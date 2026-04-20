package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/fsc/telepath-core/internal/dashboard"
	"github.com/fsc/telepath-core/internal/service"
)

// newServiceCmd is `telepath service` — installs telepath as a per-user
// OS service (systemd user on Linux, launchd on macOS). Setup/config
// class: permanent CLI, survives the v0.4 GUI because "install as a
// service" is something every operator does once and then forgets.
func newServiceCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "service",
		Short: "Install telepath as a per-user OS service (systemd / launchd)",
		Long: `Install telepath as a per-user service so it starts at login and
restarts on failure — removes the "run telepath start every time"
ceremony. Per-OS driver:

  Linux:  systemd user unit at ~/.config/systemd/user/telepath.service
  macOS:  launchd LaunchAgent at ~/Library/LaunchAgents/io.telepath.daemon.plist
  Windows: not supported in v0.1 (Task Scheduler work lands in v0.2)

Subcommands:
  install    Write the unit file and enable it (use --print-only to preview)
  uninstall  Stop, disable, and remove the unit file
  status     Report whether the service is installed + running`,
	}
	c.AddCommand(newServiceInstallCmd(), newServiceUninstallCmd(), newServiceStatusCmd())
	return c
}

func newServiceInstallCmd() *cobra.Command {
	var (
		withDashboard bool
		dashboardBind string
		execPath      string
		logPath       string
		noEnable      bool
		printOnly     bool
	)
	c := &cobra.Command{
		Use:   "install",
		Short: "Write the service unit file and enable it at login",
		Long: `Write the per-OS service unit for telepath and (unless --no-enable)
activate it via the host's service manager.

Flags:
  --with-dashboard           Keep the operator dashboard live alongside the
                             daemon. Off by default — service-managed
                             daemons are usually headless, and operators
                             run 'telepath dashboard' from a laptop when
                             they need the UI.
  --dashboard-bind <addr>    Dashboard bind address (when --with-dashboard)
  --no-enable                Write the unit but skip the systemctl/launchctl
                             activation step — useful when wiring into a
                             dotfiles repo.
  --print-only               Print the unit content to stdout; no filesystem
                             writes, no activation. Review before committing.
  --exec-path <path>         Override the binary path baked into the unit
                             (default: the currently-running telepath).
  --log-file <path>          Override the stdout/stderr destination.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := service.New()
			if err != nil {
				return fmt.Errorf("service: %w (run `telepath daemon run` by hand or schedule via your OS's task runner)", err)
			}
			opts, err := collectInstallOpts(withDashboard, dashboardBind, execPath, logPath)
			if err != nil {
				return err
			}
			if printOnly {
				u, err := svc.Generate(opts)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "# %s — would be written to %s\n\n%s", svc.Name(), u.Path, u.Content)
				return nil
			}
			u, err := svc.Install(opts, !noEnable)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Installed %s unit: %s\n", svc.Name(), u.Path)
			if noEnable {
				fmt.Fprintln(cmd.OutOrStdout())
				fmt.Fprintln(cmd.OutOrStdout(), "Not enabled. Run the activator yourself:")
				fmt.Fprintln(cmd.OutOrStdout(), "  "+manualActivateHint())
			} else {
				fmt.Fprintln(cmd.OutOrStdout())
				fmt.Fprintln(cmd.OutOrStdout(), "telepath is now managed by", svc.Name()+" — it will start at login and restart on failure.")
				fmt.Fprintln(cmd.OutOrStdout(), "Check status with:", "  telepath service status")
			}
			return nil
		},
	}
	c.Flags().BoolVar(&withDashboard, "with-dashboard", false, "keep the dashboard live alongside the daemon (off by default — services are usually headless)")
	c.Flags().StringVar(&dashboardBind, "dashboard-bind", "", "dashboard bind address (when --with-dashboard)")
	c.Flags().StringVar(&execPath, "exec-path", "", "override the telepath binary path baked into the unit (default: this binary)")
	c.Flags().StringVar(&logPath, "log-file", "", "override stdout/stderr log path (default: ~/.telepath/logs/daemon.log)")
	c.Flags().BoolVar(&noEnable, "no-enable", false, "write the unit but don't activate it (no systemctl/launchctl call)")
	c.Flags().BoolVar(&printOnly, "print-only", false, "print the rendered unit to stdout and exit; no filesystem writes")
	return c
}

func newServiceUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Stop, disable, and remove the telepath service unit",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := service.New()
			if err != nil {
				return err
			}
			u, err := svc.Uninstall()
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed %s unit (%s).\n", svc.Name(), u.Path)
			fmt.Fprintln(cmd.OutOrStdout(), "Any running `telepath start` process outside the service is untouched — stop it separately if desired.")
			return nil
		},
	}
}

func newServiceStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report whether the telepath service unit is installed + running",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := service.New()
			if err != nil {
				return err
			}
			st, err := svc.Status()
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "driver:    %s\n", svc.Name())
			fmt.Fprintf(cmd.OutOrStdout(), "unit path: %s\n", st.Path)
			fmt.Fprintf(cmd.OutOrStdout(), "installed: %t\n", st.Installed)
			fmt.Fprintf(cmd.OutOrStdout(), "running:   %t\n", st.Running)
			if st.Detail != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "detail:    %s\n", st.Detail)
			}
			return nil
		},
	}
}

// collectInstallOpts assembles the InstallOpts an OS driver needs.
// Resolves HomeDir + ExecPath from the runtime when the operator
// didn't supply overrides.
func collectInstallOpts(withDashboard bool, dashboardBind, execPath, logPath string) (service.InstallOpts, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return service.InstallOpts{}, fmt.Errorf("service: resolve home: %w", err)
	}
	if execPath == "" {
		self, err := os.Executable()
		if err != nil {
			return service.InstallOpts{}, fmt.Errorf("service: resolve self: %w", err)
		}
		// Prefer the resolved symlink target so service units survive
		// a telepath update that swaps the bin.
		if resolved, err := filepath.EvalSymlinks(self); err == nil {
			self = resolved
		}
		execPath = self
	}
	if dashboardBind == "" {
		dashboardBind = dashboard.DefaultBindAddr
	}
	return service.InstallOpts{
		ExecPath:      execPath,
		WithDashboard: withDashboard,
		DashboardBind: dashboardBind,
		LogPath:       logPath,
		HomeDir:       home,
	}, nil
}

// manualActivateHint returns the OS-specific command line the operator
// should run when they passed --no-enable. Kept here (rather than in
// the service drivers) because it's a pure UI concern.
func manualActivateHint() string {
	switch runtime.GOOS {
	case "linux":
		return "systemctl --user daemon-reload && systemctl --user enable --now telepath.service"
	case "darwin":
		return fmt.Sprintf("launchctl bootstrap gui/%d ~/Library/LaunchAgents/io.telepath.daemon.plist", os.Getuid())
	}
	return "(no default activator for this OS)"
}
