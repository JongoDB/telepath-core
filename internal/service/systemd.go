package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// systemdUser is the Linux driver. User-scope (~/.config/systemd/user/)
// so there's no sudo and nothing to clean up on a shared host —
// matches the operator-personal model the rest of telepath uses.
type systemdUser struct{}

func newSystemdUser() *systemdUser { return &systemdUser{} }

// Name satisfies Service.
func (s *systemdUser) Name() string { return "systemd (user)" }

// unitName is the service file name. systemctl references it with this
// string (`systemctl --user enable telepath.service`).
const systemdUnitName = "telepath.service"

// unitPath resolves the install location for the given home dir.
// XDG_CONFIG_HOME override is intentionally skipped — systemd itself
// reads from ~/.config/systemd/user/ regardless of $XDG_CONFIG_HOME for
// consistency with how every distro's tooling documents this.
func (s *systemdUser) unitPath(home string) string {
	return filepath.Join(home, ".config", "systemd", "user", systemdUnitName)
}

// Generate renders the systemd unit file content.
func (s *systemdUser) Generate(opts InstallOpts) (Unit, error) {
	if opts.ExecPath == "" {
		return Unit{}, errors.New("service: ExecPath required")
	}
	if opts.HomeDir == "" {
		return Unit{}, errors.New("service: HomeDir required")
	}
	args := buildExecArgs(opts)
	// Quote each arg — paths might contain spaces, and systemd's
	// ExecStart= parses with its own word-splitting that's NOT shell.
	// Use the same trick as the `systemd-escape` tool: wrap each arg
	// in double quotes + backslash-escape embedded quotes.
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = `"` + strings.ReplaceAll(a, `"`, `\"`) + `"`
	}
	execStart := strings.Join(quoted, " ")

	logPath := opts.LogPath
	if logPath == "" {
		logPath = filepath.Join(opts.HomeDir, ".telepath", "logs", "daemon.log")
	}

	content := fmt.Sprintf(`[Unit]
Description=telepath daemon (FSC assessment harness)
Documentation=https://github.com/JongoDB/telepath-core
After=default.target

[Service]
Type=simple
ExecStart=%s
Restart=on-failure
RestartSec=5
StandardOutput=append:%s
StandardError=append:%s

[Install]
WantedBy=default.target
`, execStart, logPath, logPath)

	return Unit{Content: content, Path: s.unitPath(opts.HomeDir)}, nil
}

// Install writes the unit + optionally enables it. enable=true runs
// `systemctl --user daemon-reload` (so systemd picks up the new file)
// followed by `systemctl --user enable --now telepath.service` (which
// is idempotent — re-enabling an already-enabled unit is a no-op).
func (s *systemdUser) Install(opts InstallOpts, enable bool) (Unit, error) {
	u, err := s.Generate(opts)
	if err != nil {
		return u, err
	}
	if err := os.MkdirAll(filepath.Dir(u.Path), 0o755); err != nil {
		return u, fmt.Errorf("service: mkdir %s: %w", filepath.Dir(u.Path), err)
	}
	// Ensure the log dir exists — systemd's StandardOutput=append
	// errors at service-start time otherwise.
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
	if err := runSystemctl("--user", "daemon-reload"); err != nil {
		return u, err
	}
	if err := runSystemctl("--user", "enable", "--now", systemdUnitName); err != nil {
		return u, err
	}
	return u, nil
}

// Uninstall disables + stops + removes. Every step is best-effort: a
// stale unit that systemd doesn't know about should still be
// removable.
func (s *systemdUser) Uninstall() (Unit, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Unit{}, err
	}
	path := s.unitPath(home)
	// disable --now performs stop+disable atomically; if the unit was
	// never enabled, systemd returns 1 which we swallow.
	_ = runSystemctl("--user", "disable", "--now", systemdUnitName)
	_ = runSystemctl("--user", "daemon-reload")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return Unit{Path: path}, fmt.Errorf("service: remove %s: %w", path, err)
	}
	return Unit{Path: path}, nil
}

// Status inspects the unit file + asks systemctl whether it's active.
func (s *systemdUser) Status() (Status, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Status{}, err
	}
	path := s.unitPath(home)
	st := Status{Path: path}
	if _, err := os.Stat(path); err == nil {
		st.Installed = true
	}
	if !st.Installed {
		return st, nil
	}
	out, _ := exec.Command("systemctl", "--user", "is-active", systemdUnitName).Output()
	state := strings.TrimSpace(string(out))
	st.Running = state == "active"
	st.Detail = "state: " + state
	return st, nil
}

// runSystemctl is a thin wrapper that surfaces systemctl's stderr in
// the error message — otherwise a bare exit-code failure tells
// operators nothing actionable.
func runSystemctl(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	combined, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(combined))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("systemctl %s: %s", strings.Join(args, " "), msg)
	}
	return nil
}
