package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/fsc/telepath-core/internal/daemon"
	"github.com/fsc/telepath-core/internal/dashboard"
)

// newDashboardCmd is the operator-facing "telepath dashboard" launcher.
// Starts an HTTP server that renders the daemon's state (engagement,
// transport, OAuth, findings, notes, evidence). Sits in the Operation
// group — it's an operational surface, not setup/config.
func newDashboardCmd() *cobra.Command {
	var bindAddr string
	var noBrowser bool
	c := &cobra.Command{
		Use:   "dashboard",
		Short: "Launch the operator dashboard (authenticated HTTP)",
		Long: `Start a web dashboard that polls the running daemon and renders
engagement + transport + OAuth + findings + notes + evidence state.

Binds to 0.0.0.0:0 by default so the headless use case works out of
the box — run 'telepath daemon run' on a remote host, hit the
dashboard URL from a laptop browser. The listen URL includes a
one-time bearer token (?t=...) that the dashboard stores in an
HttpOnly session cookie on first load; requests without the token
get 401 regardless of origin interface. Token lives in memory only
and rotates on every restart.

Pass --bind 127.0.0.1:0 to scope to loopback for a local-only
desktop flow.

Opens the URL in the default browser unless --no-browser is set.
Ctrl+C stops the dashboard; the daemon continues running.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fetcher := &dashboard.IPCFetcher{
				SocketPath: socketPath(),
				Timeout:    3 * time.Second,
			}
			srv, err := dashboard.Start(dashboard.Config{
				BindAddr:   bindAddr,
				Fetcher:    fetcher,
				CLIVersion: daemon.Version,
			})
			if err != nil {
				return fmt.Errorf("dashboard: %w", err)
			}

			url := srv.URL()
			fmt.Fprintln(cmd.OutOrStdout(), "telepath dashboard listening on", url)
			fmt.Fprintln(cmd.OutOrStdout(), "(token rotates on restart; anyone with the URL can read engagement state)")
			fmt.Fprintln(cmd.OutOrStdout(), "Ctrl+C to stop (daemon keeps running).")

			if !noBrowser {
				if err := openBrowser(url); err != nil {
					// Silent when no browser-opener is present — the
					// URL already printed above is the actionable output.
					// Surface the detail on stderr for debugging.
					fmt.Fprintln(cmd.ErrOrStderr(), "(no browser launcher available:", err.Error(), "— open the URL above manually)")
				}
			}

			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()
			sigs := make(chan os.Signal, 1)
			signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
			select {
			case <-sigs:
			case <-ctx.Done():
			}
			fmt.Fprintln(cmd.OutOrStdout(), "\nshutting down dashboard…")
			return srv.Shutdown(context.Background())
		},
	}
	c.Flags().StringVar(&bindAddr, "bind", dashboard.DefaultBindAddr,
		"address:port to bind (default 0.0.0.0:0 — all interfaces, ephemeral port; use 127.0.0.1:0 for loopback-only)")
	c.Flags().BoolVar(&noBrowser, "no-browser", false, "skip auto-opening the default browser")
	return c
}

// openBrowser tries to open URL in the operator's default browser.
// Best-effort: failure is surfaced to the caller, which prints a
// "open manually" hint. Mirrors the pattern used by `go tool cover
// -html` and similar Go CLIs.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", url)
	default:
		// Linux/BSD + headless servers — try xdg-open first.
		cmd = exec.Command("xdg-open", url)
	}
	// Detach stdin/stdout so the child doesn't inherit the terminal.
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Start()
}
