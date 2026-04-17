package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/fsc/telepath-core/internal/daemon"
	"github.com/fsc/telepath-core/pkg/schema"
)

func newDaemonCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "daemon",
		Short: "Control the telepath daemon",
	}
	c.AddCommand(newDaemonRunCmd(), newDaemonStatusCmd(), newDaemonStopCmd())
	return c
}

func newDaemonRunCmd() *cobra.Command {
	var socketFlag, rootFlag, pidFlag string
	c := &cobra.Command{
		Use:   "run",
		Short: "Run the daemon in the foreground (blocks until SIGINT/SIGTERM)",
		RunE: func(cmd *cobra.Command, args []string) error {
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
		},
	}
	c.Flags().StringVar(&socketFlag, "socket", "", "override socket path")
	c.Flags().StringVar(&rootFlag, "root", "", "override ~/.telepath root")
	c.Flags().StringVar(&pidFlag, "pid-file", "", "override daemon.pid path")
	return c
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
