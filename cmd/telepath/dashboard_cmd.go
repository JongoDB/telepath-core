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

	"github.com/fsc/telepath-core/internal/dashboard"
)

// newDashboardCmd is the operator-facing "telepath dashboard" launcher.
// Starts a localhost-only HTTP server that renders the daemon's state
// (engagement, transport, OAuth, findings, notes, evidence). Sits in the
// Operation group — it's an operational surface, not setup/config.
func newDashboardCmd() *cobra.Command {
	var bindAddr string
	var noBrowser bool
	c := &cobra.Command{
		Use:   "dashboard",
		Short: "Launch the operator dashboard (localhost HTTP)",
		Long: `Start a localhost-only web dashboard that polls the running daemon and
renders engagement + transport + OAuth + findings + notes + evidence
state. Binds to 127.0.0.1 only — the dashboard is never exposed to the
network. Opens the URL in your default browser unless --no-browser is
passed.

Run Ctrl+C to stop the dashboard; the daemon continues running.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fetcher := &dashboard.IPCFetcher{
				SocketPath: socketPath(),
				Timeout:    3 * time.Second,
			}
			srv, err := dashboard.Start(dashboard.Config{
				BindAddr: bindAddr,
				Fetcher:  fetcher,
			})
			if err != nil {
				return fmt.Errorf("dashboard: %w", err)
			}

			url := srv.URL()
			fmt.Fprintln(cmd.OutOrStdout(), "telepath dashboard listening on", url)
			fmt.Fprintln(cmd.OutOrStdout(), "Ctrl+C to stop (daemon keeps running).")

			if !noBrowser {
				if err := openBrowser(url); err != nil {
					fmt.Fprintln(cmd.ErrOrStderr(), "could not open browser:", err)
					fmt.Fprintln(cmd.ErrOrStderr(), "open", url, "manually.")
				}
			}

			// Block on SIGINT/SIGTERM and shutdown cleanly.
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
	c.Flags().StringVar(&bindAddr, "bind", "127.0.0.1:0",
		"address:port to bind (always 127.0.0.1-scoped; port 0 picks a free one)")
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
