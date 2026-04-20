package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/fsc/telepath-core/internal/daemon"
	"github.com/fsc/telepath-core/internal/dashboard"
	"github.com/fsc/telepath-core/pkg/schema"
)

// defaultDaemonLogPath returns ~/.telepath/logs/daemon.log, the canonical
// location for detached-daemon output. The operator tails it with
// `tail -f` when they want to watch; telepath itself no longer wraps
// that.
func defaultDaemonLogPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "/tmp/telepath-daemon.log"
	}
	return filepath.Join(home, ".telepath", "logs", "daemon.log")
}

func newDaemonCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "daemon",
		Short: "Control the telepath daemon",
	}
	c.AddCommand(newDaemonRunCmd(), newDaemonStatusCmd(), newDaemonStopCmd())
	return c
}

// daemonRunFlags bundles the daemon-run flag values so the detach path
// can re-exec the same configuration without re-enumerating them.
type daemonRunFlags struct {
	socket        string
	root          string
	pid           string
	log           string
	withDashboard bool
	dashboardBind string
}

func newDaemonRunCmd() *cobra.Command {
	var f daemonRunFlags
	var detach bool
	c := &cobra.Command{
		Use:   "run",
		Short: "Run the daemon (foreground by default; use --detach to fork)",
		Long: `Run the daemon. By default runs in the foreground until Ctrl+C. Pass
--detach to fork to the background with logs going to
~/.telepath/logs/daemon.log (Unix only; Windows should schedule as a
service).

Pass --with-dashboard to spawn the operator dashboard alongside the
daemon in the same process — one gesture, one terminal, both up. The
dashboard listens on --dashboard-bind (default 0.0.0.0:0, ephemeral
port) and prints a tokenized URL on stderr. Closing the daemon
(SIGINT/SIGTERM) shuts the dashboard down too.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if detach {
				return detachAndExit(cmd, f)
			}
			return runDaemonForeground(cmd, f)
		},
	}
	c.Flags().StringVar(&f.socket, "socket", "", "override socket path")
	c.Flags().StringVar(&f.root, "root", "", "override ~/.telepath root")
	c.Flags().StringVar(&f.pid, "pid-file", "", "override daemon.pid path")
	c.Flags().BoolVar(&detach, "detach", false, "fork to background; log to ~/.telepath/logs/daemon.log (Unix only)")
	c.Flags().StringVar(&f.log, "log-file", "", "override detach log-file path")
	c.Flags().BoolVar(&f.withDashboard, "with-dashboard", false, "also start the operator dashboard in this process")
	c.Flags().StringVar(&f.dashboardBind, "dashboard-bind", dashboard.DefaultBindAddr, "dashboard bind address (when --with-dashboard)")
	return c
}

func runDaemonForeground(cmd *cobra.Command, f daemonRunFlags) error {
	d, err := daemon.New(daemon.Config{
		RootDir:     f.root,
		SocketPath:  f.socket,
		PIDFilePath: f.pid,
	})
	if err != nil {
		return err
	}
	if err := d.Start(); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "telepath daemon listening on %s\n", d.SocketPath())

	var dashSrv *dashboard.Server
	if f.withDashboard {
		dashSrv, err = startEmbeddedDashboard(cmd, d.SocketPath(), f.dashboardBind)
		if err != nil {
			// Daemon is up but dashboard failed; surface both states
			// clearly so the operator can decide (keep daemon running
			// + fix bind, or Ctrl+C and retry). We don't auto-shutdown
			// the daemon on dashboard-only failure.
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: dashboard did not start: %v (daemon still running)\n", err)
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	sig := <-sigCh
	fmt.Fprintf(cmd.ErrOrStderr(), "received %s, shutting down...\n", sig)

	if dashSrv != nil {
		_ = dashSrv.Shutdown(context.Background())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return d.Shutdown(ctx)
}

// startEmbeddedDashboard spawns a dashboard server in the same process
// as the daemon. It talks back to the daemon over the same Unix socket
// the daemon just opened — no special in-process transport, so the
// code path matches an external `telepath dashboard` invocation.
//
// A brief wait-for-socket loop handles the edge case where dashboard
// fires before the IPC listener is accepting connections; in practice
// d.Start() blocks until listen succeeds so the first ping usually
// works, but the loop is cheap insurance.
func startEmbeddedDashboard(cmd *cobra.Command, socketPath, bindAddr string) (*dashboard.Server, error) {
	fetcher := &dashboard.IPCFetcher{SocketPath: socketPath, Timeout: 3 * time.Second}
	srv, err := dashboard.Start(dashboard.Config{
		BindAddr:   bindAddr,
		Fetcher:    fetcher,
		CLIVersion: daemon.Version,
	})
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "telepath dashboard listening on %s\n", srv.URL())
	fmt.Fprintln(cmd.ErrOrStderr(), "(token rotates on restart; anyone with the URL can read engagement state)")
	return srv, nil
}

// detachAndExit re-execs the current binary with the same daemon-run
// flags but NO --detach, redirects its stdio to a log file, and exits
// the parent. On Unix we put the child in its own session so the parent
// shell closing won't kill it. --with-dashboard / --dashboard-bind
// propagate through so `telepath daemon run --detach --with-dashboard`
// lights up both components in the background.
func detachAndExit(cmd *cobra.Command, f daemonRunFlags) error {
	if runtime.GOOS == "windows" {
		return errors.New("`daemon run --detach` is not supported on Windows yet — run in foreground or schedule as a service")
	}
	logFlag := f.log
	if logFlag == "" {
		logFlag = defaultDaemonLogPath()
	}
	if err := os.MkdirAll(filepath.Dir(logFlag), 0o700); err != nil {
		return fmt.Errorf("daemon: mkdir log dir: %w", err)
	}
	logF, err := os.OpenFile(logFlag, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("daemon: open log: %w", err)
	}
	defer logF.Close()

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"daemon", "run"}
	if f.socket != "" {
		args = append(args, "--socket", f.socket)
	}
	if f.root != "" {
		args = append(args, "--root", f.root)
	}
	if f.pid != "" {
		args = append(args, "--pid-file", f.pid)
	}
	if f.withDashboard {
		args = append(args, "--with-dashboard")
		if f.dashboardBind != "" && f.dashboardBind != dashboard.DefaultBindAddr {
			args = append(args, "--dashboard-bind", f.dashboardBind)
		}
	}

	child := exec.Command(exe, args...)
	child.Stdin = nil
	child.Stdout = logF
	child.Stderr = logF
	applyDetachedSysProcAttr(child)
	if err := child.Start(); err != nil {
		return fmt.Errorf("daemon: detach start: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "daemon detached (pid %d, log %s)\n", child.Process.Pid, logFlag)
	// Parent returns immediately; the child continues under its own
	// session until the daemon shuts down (SIGTERM from `telepath daemon
	// stop` or system shutdown).
	return nil
}

// pidFilePath resolves the active PID file path in precedence order:
//
//	1. --pid-file flag (if provided on this command)
//	2. TELEPATH_PID_FILE environment variable
//	3. daemon.DefaultPIDFilePath() (~/.telepath/daemon.pid)
func pidFilePath(flag string) string {
	if flag != "" {
		return flag
	}
	if v := os.Getenv("TELEPATH_PID_FILE"); v != "" {
		return v
	}
	return daemon.DefaultPIDFilePath()
}

func newDaemonStatusCmd() *cobra.Command {
	var pidFlag string
	c := &cobra.Command{
		Use:   "status",
		Short: "Report daemon status",
		RunE: func(cmd *cobra.Command, args []string) error {
			pidPath := pidFilePath(pidFlag)
			pid, err := daemon.ReadPIDFile(pidPath)
			if err != nil {
				fmt.Printf("daemon: not running (no pidfile at %s)\n", pidPath)
				return nil
			}
			if !daemon.PIDAlive(pid) {
				fmt.Printf("daemon: stale pidfile %s (pid %d not alive); run `telepath daemon run` to start a fresh daemon\n", pidPath, pid)
				return nil
			}
			var p schema.PingResult
			if err := rpc(schema.MethodPing, nil, &p); err != nil {
				fmt.Printf("daemon: pidfile shows pid %d but ping failed: %v\n", pid, err)
				return nil
			}
			fmt.Printf("daemon: running (pid %d, version %s, socket %s)\n", pid, p.Version, socketPath())
			return nil
		},
	}
	c.Flags().StringVar(&pidFlag, "pid-file", "", "override ~/.telepath/daemon.pid for this call")
	return c
}

func newDaemonStopCmd() *cobra.Command {
	var pidFlag string
	c := &cobra.Command{
		Use:   "stop",
		Short: "Send SIGTERM to the running daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			pidPath := pidFilePath(pidFlag)
			pid, err := daemon.ReadPIDFile(pidPath)
			if err != nil {
				return fmt.Errorf("no pidfile at %s: %w", pidPath, err)
			}
			p, err := os.FindProcess(pid)
			if err != nil {
				return err
			}
			if err := p.Signal(syscall.SIGTERM); err != nil {
				return fmt.Errorf("signal pid %d: %w", pid, err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "sent SIGTERM to pid %d\n", pid)
			return nil
		},
	}
	c.Flags().StringVar(&pidFlag, "pid-file", "", "override ~/.telepath/daemon.pid for this call")
	return c
}
