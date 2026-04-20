package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/fsc/telepath-core/internal/daemon"
)

// newStopCmd is `telepath stop` — the symmetric partner to
// `telepath start`. Sends SIGTERM to the running daemon, which also
// shuts down an embedded dashboard started with --with-dashboard.
// Equivalent to `telepath daemon stop`, kept as a top-level verb so
// the happy-path vocabulary is `telepath start / stop`.
func newStopCmd() *cobra.Command {
	var pidFlag string
	c := &cobra.Command{
		Use:   "stop",
		Short: "Stop telepath (gracefully SIGTERMs the daemon + embedded dashboard)",
		Long: `Send SIGTERM to the running telepath daemon. If the daemon was
started with --with-dashboard (or via 'telepath start'), the
dashboard shuts down with it.

An external 'telepath dashboard' process pointed at the same daemon
survives this call — stop that one with Ctrl+C in its own terminal.

This is equivalent to 'telepath daemon stop'.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			pidPath := pidFilePath(pidFlag)
			pid, err := daemon.ReadPIDFile(pidPath)
			if err != nil {
				return fmt.Errorf("no pidfile at %s: %w (telepath doesn't appear to be running)", pidPath, err)
			}
			p, err := os.FindProcess(pid)
			if err != nil {
				return err
			}
			if err := p.Signal(syscall.SIGTERM); err != nil {
				return fmt.Errorf("signal pid %d: %w", pid, err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "sent SIGTERM to telepath (pid %d)\n", pid)
			return nil
		},
	}
	c.Flags().StringVar(&pidFlag, "pid-file", "", "override ~/.telepath/daemon.pid")
	return c
}
