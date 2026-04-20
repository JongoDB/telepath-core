// Package service installs + manages the telepath daemon as a per-user
// OS service. systemd user on Linux, launchd on macOS. The goal is to
// remove the "you have to run `telepath start` every time" friction from
// the operator flow — the service unit starts telepath at login and
// keeps it alive across restarts.
//
// v0.1 scope: write + enable the unit, remove + disable it, report
// whether it's installed/running. Windows support is deferred (sc.exe
// or scheduled tasks aren't adjacent in the way systemd/launchd are).
package service

import (
	"errors"
	"fmt"
	"runtime"
)

// ErrUnsupportedOS is returned for platforms we don't have a driver
// for. Wraps with a specific OS name where relevant.
var ErrUnsupportedOS = errors.New("service: no unit driver for this OS")

// InstallOpts bundles everything a driver's Generate + Install need.
type InstallOpts struct {
	// ExecPath is the absolute path to the telepath binary the service
	// should start. Resolved from os.Executable() by the CLI when the
	// operator doesn't supply one.
	ExecPath string
	// WithDashboard tells the service to also start the dashboard. Off
	// by default because a typical service-managed daemon is headless;
	// enable it when you want the web UI live whenever telepath is.
	WithDashboard bool
	// DashboardBind is passed through to `telepath start`. Empty uses
	// the binary's built-in default (0.0.0.0:0).
	DashboardBind string
	// LogPath overrides the default log file
	// (<HomeDir>/.telepath/logs/daemon.log). The service unit redirects
	// the daemon's stderr/stdout here.
	LogPath string
	// HomeDir is the operator's home directory. Used for unit-file
	// placement (~/.config/systemd/user/…, ~/Library/LaunchAgents/…)
	// and to resolve the default log path.
	HomeDir string
}

// Unit is the render result: what the unit file says + where it lives.
// Used both by Install (write then enable) and by the CLI's --print-only
// flow (render, print, no filesystem touch).
type Unit struct {
	Content string
	Path    string
}

// Status is what a driver reports from Status().
type Status struct {
	Installed bool
	Running   bool
	Path      string
	Detail    string
}

// Service is the per-OS driver contract. The CLI calls one of these;
// New returns the right implementation for runtime.GOOS.
type Service interface {
	// Generate builds the unit file content + its target path from
	// opts. Pure function — no filesystem side effects. Use this for
	// CLI --print-only and for tests.
	Generate(opts InstallOpts) (Unit, error)
	// Install writes the unit file and, if enable is true, runs the
	// OS's activation command (systemctl --user enable --now /
	// launchctl bootstrap). Returns the Unit actually written.
	Install(opts InstallOpts, enable bool) (Unit, error)
	// Uninstall stops + disables the service (best effort) and removes
	// the unit file. Returns the unit path whether or not the file was
	// actually present.
	Uninstall() (Unit, error)
	// Status inspects the unit file + asks the OS whether it's running.
	Status() (Status, error)
	// Name returns the driver's human-readable label — "systemd user",
	// "launchd", etc. Used in CLI output.
	Name() string
}

// New returns the driver for the host OS.
func New() (Service, error) { return NewFor(runtime.GOOS) }

// NewFor returns the driver for the given platform. Used by tests to
// render + assert output for an OS that isn't the test host.
func NewFor(platform string) (Service, error) {
	switch platform {
	case "linux":
		return newSystemdUser(), nil
	case "darwin":
		return newLaunchd(), nil
	case "windows":
		return nil, fmt.Errorf("%w: windows (use Task Scheduler or a user-scope service; v0.2+)", ErrUnsupportedOS)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedOS, platform)
	}
}

// buildExecArgs assembles the `telepath start …` argv the service
// should exec. Shared between systemd's ExecStart= line and launchd's
// ProgramArguments array so both drivers agree on flag shape.
//
// --no-browser is always included: a service has no terminal to open a
// browser from, and auto-open would confusingly pop a browser at login.
// Operators who want the dashboard on-by-default enable it with
// --with-dashboard (translated from opts.WithDashboard).
func buildExecArgs(opts InstallOpts) []string {
	args := []string{opts.ExecPath, "start", "--no-browser"}
	if !opts.WithDashboard {
		args = append(args, "--no-dashboard")
	} else if opts.DashboardBind != "" {
		// The default ("0.0.0.0:0") is already telepath start's
		// default; only write the flag when overridden, to keep the
		// unit file minimal and easier to diff.
		args = append(args, "--dashboard-bind", opts.DashboardBind)
	}
	return args
}
