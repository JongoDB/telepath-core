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
	"github.com/fsc/telepath-core/internal/dashboard"
)

// newStartCmd is `telepath start` — the recommended one-gesture entry
// point. Spins up the daemon + dashboard in the same process and
// auto-opens the browser. Power users who want finer control can
// still use `telepath daemon run` or `telepath dashboard`
// independently (and this command takes the same knobs as flags).
func newStartCmd() *cobra.Command {
	var f startFlags
	c := &cobra.Command{
		Use:   "start",
		Short: "Start telepath (daemon + dashboard + browser) — the recommended way to run",
		Long: `Start the telepath daemon + dashboard in one command. The dashboard
binds to 0.0.0.0 by default (token-gated; anyone with the URL can
read state, nobody without can) and auto-opens in your default
browser. Use Ctrl+C to stop both.

Useful tweaks:
  --no-dashboard       Daemon only; equivalent to 'telepath daemon run'
  --no-browser         Start dashboard but don't auto-launch the browser
                       (headless servers, SSH sessions)
  --dashboard-bind     Narrow dashboard to a specific interface
                       (e.g. 127.0.0.1:0 for loopback-only)
  --detach             Fork to background, log to ~/.telepath/logs/daemon.log
                       (implies --no-browser)
  --socket/--root/--pid-file/--log-file   Advanced overrides; rarely needed

Nothing has moved: 'telepath daemon run' + 'telepath dashboard' still
work independently for granular control.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStart(cmd, f)
		},
	}
	c.Flags().StringVar(&f.socket, "socket", "", "override daemon socket path")
	c.Flags().StringVar(&f.root, "root", "", "override ~/.telepath root")
	c.Flags().StringVar(&f.pid, "pid-file", "", "override daemon.pid path")
	c.Flags().BoolVar(&f.detach, "detach", false, "fork to background; log to ~/.telepath/logs/daemon.log (Unix only; implies --no-browser)")
	c.Flags().StringVar(&f.log, "log-file", "", "override detach log-file path")
	c.Flags().BoolVar(&f.noDashboard, "no-dashboard", false, "run only the daemon (skip dashboard + browser)")
	c.Flags().StringVar(&f.dashboardBind, "dashboard-bind", dashboard.DefaultBindAddr, "dashboard bind address (0.0.0.0:0 default; use 127.0.0.1:0 for loopback)")
	c.Flags().BoolVar(&f.noBrowser, "no-browser", false, "don't auto-open the dashboard in a browser")
	return c
}

type startFlags struct {
	socket, root, pid, log, dashboardBind string
	detach, noDashboard, noBrowser        bool
}

// runStart dispatches to the foreground or detach path. The dashboard
// defaults to ON (opposite of `daemon run`, where it's opt-in via
// --with-dashboard) — `start`'s intent is "turn everything on."
func runStart(cmd *cobra.Command, f startFlags) error {
	combo := daemonRunFlags{
		socket:        f.socket,
		root:          f.root,
		pid:           f.pid,
		log:           f.log,
		withDashboard: !f.noDashboard,
		dashboardBind: f.dashboardBind,
	}
	if f.detach {
		// Detached mode has no terminal to print to and no browser to
		// open, so --no-browser is implied. detachAndExit already
		// handles propagating --with-dashboard to the re-exec'd child.
		return detachAndExit(cmd, combo)
	}
	return runStartForeground(cmd, combo, !f.noDashboard && !f.noBrowser)
}

// runStartForeground is the foreground flavor of `telepath start`.
// Mirrors runDaemonForeground's shutdown discipline but additionally
// opens the browser when asked. Extracted here (rather than plumbed
// into runDaemonForeground) so `daemon run --with-dashboard` stays
// headless by default — only the high-level `start` verb is
// opinionated about launching a browser.
func runStartForeground(cmd *cobra.Command, f daemonRunFlags, autoOpenBrowser bool) error {
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
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: dashboard did not start: %v (daemon still running)\n", err)
		} else if autoOpenBrowser {
			if berr := openBrowser(dashSrv.URL()); berr != nil {
				fmt.Fprintln(cmd.ErrOrStderr(), "(no browser launcher available — open the URL above manually)")
			}
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
