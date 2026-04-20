package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// launchd is the macOS driver. User-scope LaunchAgent under
// ~/Library/LaunchAgents/ — per-user, no sudo, starts at login.
type launchd struct{}

func newLaunchd() *launchd { return &launchd{} }

// Name satisfies Service.
func (l *launchd) Name() string { return "launchd" }

// launchdLabel is the plist Label key + what launchctl refers to the
// service by. Reverse-DNS convention per Apple's docs.
const launchdLabel = "io.telepath.daemon"

// plistPath resolves the install location.
func (l *launchd) plistPath(home string) string {
	return filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist")
}

// Generate renders the launchd plist. Hand-formatted XML rather than
// encoding/xml: plists want a specific DOCTYPE + ordering, and Go's
// encoding/xml doesn't emit plist-shaped output without a dep on one
// of the plist-specific libraries. The string is small, auditable,
// and easy to diff.
func (l *launchd) Generate(opts InstallOpts) (Unit, error) {
	if opts.ExecPath == "" {
		return Unit{}, errors.New("service: ExecPath required")
	}
	if opts.HomeDir == "" {
		return Unit{}, errors.New("service: HomeDir required")
	}
	args := buildExecArgs(opts)
	var programArgs strings.Builder
	for _, a := range args {
		programArgs.WriteString("    <string>")
		programArgs.WriteString(xmlEscape(a))
		programArgs.WriteString("</string>\n")
	}

	logPath := opts.LogPath
	if logPath == "" {
		logPath = filepath.Join(opts.HomeDir, ".telepath", "logs", "daemon.log")
	}

	content := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>%s</string>
  <key>ProgramArguments</key>
  <array>
%s  </array>
  <key>KeepAlive</key>
  <true/>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>%s</string>
  <key>StandardErrorPath</key>
  <string>%s</string>
</dict>
</plist>
`, launchdLabel, programArgs.String(), xmlEscape(logPath), xmlEscape(logPath))

	return Unit{Content: content, Path: l.plistPath(opts.HomeDir)}, nil
}

// Install writes the plist and (when enable=true) loads it via
// launchctl bootstrap. bootout-then-bootstrap ensures a clean re-install
// — bootstrap errors if the label is already loaded.
func (l *launchd) Install(opts InstallOpts, enable bool) (Unit, error) {
	u, err := l.Generate(opts)
	if err != nil {
		return u, err
	}
	if err := os.MkdirAll(filepath.Dir(u.Path), 0o755); err != nil {
		return u, fmt.Errorf("service: mkdir %s: %w", filepath.Dir(u.Path), err)
	}
	// Pre-create the log dir so StandardOutPath/StandardErrorPath
	// doesn't bounce on first load.
	logDir := filepath.Join(opts.HomeDir, ".telepath", "logs")
	if opts.LogPath != "" {
		logDir = filepath.Dir(opts.LogPath)
	}
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return u, fmt.Errorf("service: mkdir log dir %s: %w", logDir, err)
	}
	if err := os.WriteFile(u.Path, []byte(u.Content), 0o644); err != nil {
		return u, fmt.Errorf("service: write %s: %w", u.Path, err)
	}
	if !enable {
		return u, nil
	}
	target := launchdBootstrapTarget()
	// Best-effort bootout in case the label is already loaded. Ignore
	// the "not loaded" error case; a real failure will resurface on
	// the subsequent bootstrap call.
	_ = exec.Command("launchctl", "bootout", target, u.Path).Run()
	if err := runLaunchctl("bootstrap", target, u.Path); err != nil {
		return u, err
	}
	return u, nil
}

// Uninstall runs bootout then removes the plist.
func (l *launchd) Uninstall() (Unit, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Unit{}, err
	}
	path := l.plistPath(home)
	target := launchdBootstrapTarget()
	_ = exec.Command("launchctl", "bootout", target, path).Run()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return Unit{Path: path}, fmt.Errorf("service: remove %s: %w", path, err)
	}
	return Unit{Path: path}, nil
}

// Status inspects the plist + asks launchctl for the label's state.
func (l *launchd) Status() (Status, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Status{}, err
	}
	path := l.plistPath(home)
	st := Status{Path: path}
	if _, err := os.Stat(path); err == nil {
		st.Installed = true
	}
	if !st.Installed {
		return st, nil
	}
	// `launchctl list` lines look like "<pid>\t<exit-status>\t<label>".
	// A running service has a numeric pid; a stopped one has "-".
	out, _ := exec.Command("launchctl", "list").Output()
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, launchdLabel) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 1 && fields[0] != "-" {
			st.Running = true
			st.Detail = strings.TrimSpace(line)
			break
		}
		st.Detail = strings.TrimSpace(line)
	}
	return st, nil
}

// launchdBootstrapTarget returns the gui/<uid> domain string
// launchctl expects for per-user LaunchAgents.
func launchdBootstrapTarget() string {
	return fmt.Sprintf("gui/%d", os.Getuid())
}

// runLaunchctl surfaces stderr on failure — launchctl's exit codes
// alone aren't actionable.
func runLaunchctl(args ...string) error {
	cmd := exec.Command("launchctl", args...)
	combined, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(combined))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("launchctl %s: %s", strings.Join(args, " "), msg)
	}
	return nil
}

// xmlEscape is a minimal plist-safe escape. plist values are XML, so
// the same & < > escape rules apply. We don't emit user-controlled
// XML attributes so quote/apos escaping is unnecessary.
func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
