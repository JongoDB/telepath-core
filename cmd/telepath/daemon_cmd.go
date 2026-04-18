package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/fsc/telepath-core/internal/daemon"
	"github.com/fsc/telepath-core/pkg/schema"
)

// defaultDaemonLogPath returns ~/.telepath/logs/daemon.log, the canonical
// location for detached-daemon output. Also used by `daemon logs`.
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
	c.AddCommand(newDaemonRunCmd(), newDaemonStatusCmd(), newDaemonStopCmd(), newDaemonLogsCmd())
	return c
}

func newDaemonRunCmd() *cobra.Command {
	var socketFlag, rootFlag, pidFlag, logFlag string
	var detach bool
	c := &cobra.Command{
		Use:   "run",
		Short: "Run the daemon (foreground by default; use --detach to fork)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if detach {
				return detachAndExit(cmd, socketFlag, rootFlag, pidFlag, logFlag)
			}
			return runDaemonForeground(cmd, socketFlag, rootFlag, pidFlag)
		},
	}
	c.Flags().StringVar(&socketFlag, "socket", "", "override socket path")
	c.Flags().StringVar(&rootFlag, "root", "", "override ~/.telepath root")
	c.Flags().StringVar(&pidFlag, "pid-file", "", "override daemon.pid path")
	c.Flags().BoolVar(&detach, "detach", false, "fork to background; log to ~/.telepath/logs/daemon.log (Unix only)")
	c.Flags().StringVar(&logFlag, "log-file", "", "override detach log-file path")
	return c
}

func runDaemonForeground(cmd *cobra.Command, socketFlag, rootFlag, pidFlag string) error {
	d, err := daemon.New(daemon.Config{
		RootDir:     rootFlag,
		SocketPath:  socketFlag,
		PIDFilePath: pidFlag,
	})
	if err != nil {
		return err
	}
	if err := d.Start(); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "telepath daemon listening on %s\n", d.SocketPath())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	sig := <-sigCh
	fmt.Fprintf(cmd.ErrOrStderr(), "received %s, shutting down...\n", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return d.Shutdown(ctx)
}

// detachAndExit re-execs the current binary with the same daemon-run
// flags but NO --detach, redirects its stdio to a log file, and exits
// the parent. On Unix we put the child in its own session so the parent
// shell closing won't kill it.
func detachAndExit(cmd *cobra.Command, socketFlag, rootFlag, pidFlag, logFlag string) error {
	if runtime.GOOS == "windows" {
		return errors.New("`daemon run --detach` is not supported on Windows yet — run in foreground or schedule as a service")
	}
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
	if socketFlag != "" {
		args = append(args, "--socket", socketFlag)
	}
	if rootFlag != "" {
		args = append(args, "--root", rootFlag)
	}
	if pidFlag != "" {
		args = append(args, "--pid-file", pidFlag)
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

func newDaemonLogsCmd() *cobra.Command {
	var follow bool
	var logFlag string
	var lines int
	c := &cobra.Command{
		Use:   "logs",
		Short: "Show the detached daemon log",
		RunE: func(cmd *cobra.Command, args []string) error {
			if logFlag == "" {
				logFlag = defaultDaemonLogPath()
			}
			if _, err := os.Stat(logFlag); os.IsNotExist(err) {
				fmt.Fprintf(cmd.ErrOrStderr(), "no daemon log at %s yet\n", logFlag)
				return nil
			}
			if follow {
				return tailFollow(cmd, logFlag)
			}
			return tailLastN(cmd, logFlag, lines)
		},
	}
	c.Flags().BoolVarP(&follow, "follow", "f", false, "follow log output (like tail -f)")
	c.Flags().IntVarP(&lines, "lines", "n", 50, "number of lines to show (ignored with -f)")
	c.Flags().StringVar(&logFlag, "log-file", "", "override log-file path")
	return c
}

// tailLastN prints the last n lines of path, like `tail -n N`.
func tailLastN(cmd *cobra.Command, path string, n int) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("daemon logs: read: %w", err)
	}
	lines := splitLines(string(data))
	if n > 0 && len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	for _, l := range lines {
		fmt.Fprintln(cmd.OutOrStdout(), l)
	}
	return nil
}

// tailFollow streams new content as it's appended. Simple poller — good
// enough for daemon logs that write on the order of events per second.
func tailFollow(cmd *cobra.Command, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("daemon logs: open: %w", err)
	}
	defer f.Close()
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	buf := make([]byte, 4096)
	for {
		select {
		case <-sigCh:
			return nil
		default:
		}
		n, err := f.Read(buf)
		if n > 0 {
			_, _ = cmd.OutOrStdout().Write(buf[:n])
		}
		if err == io.EOF {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if err != nil {
			return err
		}
	}
}

// splitLines splits s on \n without dropping the trailing empty string.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
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
