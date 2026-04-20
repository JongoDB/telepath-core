package service

import (
	"strings"
	"testing"
)

// baseOpts returns a standard InstallOpts with both required fields
// populated, used as the starting point for each test case.
func baseOpts() InstallOpts {
	return InstallOpts{
		ExecPath: "/home/alice/.local/bin/telepath",
		HomeDir:  "/home/alice",
	}
}

func TestNewFor_UnknownPlatform(t *testing.T) {
	t.Parallel()
	_, err := NewFor("plan9")
	if err == nil {
		t.Fatal("expected error for unknown platform")
	}
	if !strings.Contains(err.Error(), "plan9") {
		t.Errorf("error should name the platform: %v", err)
	}
}

func TestNewFor_Windows(t *testing.T) {
	t.Parallel()
	_, err := NewFor("windows")
	if err == nil {
		t.Fatal("expected explicit unsupported error for windows in v0.1")
	}
}

func TestSystemd_Generate_HeadlessDaemon(t *testing.T) {
	t.Parallel()
	s, err := NewFor("linux")
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.Generate(baseOpts())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Unit file path
	want := "/home/alice/.config/systemd/user/telepath.service"
	if u.Path != want {
		t.Errorf("path = %q, want %q", u.Path, want)
	}
	body := u.Content
	// Structural sections
	for _, s := range []string{"[Unit]", "[Service]", "[Install]", "WantedBy=default.target"} {
		if !strings.Contains(body, s) {
			t.Errorf("missing section/directive %q", s)
		}
	}
	// Exec line: quoted binary path + start + --no-browser +
	// --no-dashboard (default — WithDashboard is false).
	for _, arg := range []string{
		`"/home/alice/.local/bin/telepath"`,
		`"start"`,
		`"--no-browser"`,
		`"--no-dashboard"`,
	} {
		if !strings.Contains(body, arg) {
			t.Errorf("ExecStart missing %q; body was:\n%s", arg, body)
		}
	}
	// Restart policy present
	if !strings.Contains(body, "Restart=on-failure") {
		t.Errorf("missing Restart=on-failure")
	}
	// Default log path
	if !strings.Contains(body, "/home/alice/.telepath/logs/daemon.log") {
		t.Errorf("missing default log path")
	}
}

func TestSystemd_Generate_WithDashboard(t *testing.T) {
	t.Parallel()
	s, _ := NewFor("linux")
	opts := baseOpts()
	opts.WithDashboard = true
	opts.DashboardBind = "127.0.0.1:8765"
	u, err := s.Generate(opts)
	if err != nil {
		t.Fatal(err)
	}
	body := u.Content
	// No --no-dashboard when WithDashboard is on
	if strings.Contains(body, "--no-dashboard") {
		t.Errorf("--no-dashboard should NOT appear when WithDashboard=true: %s", body)
	}
	// --dashboard-bind appears with the custom value
	if !strings.Contains(body, `"--dashboard-bind"`) || !strings.Contains(body, `"127.0.0.1:8765"`) {
		t.Errorf("dashboard-bind missing: %s", body)
	}
}

func TestSystemd_Generate_RejectsMissingPaths(t *testing.T) {
	t.Parallel()
	s, _ := NewFor("linux")
	if _, err := s.Generate(InstallOpts{HomeDir: "/home/x"}); err == nil {
		t.Errorf("expected error when ExecPath is empty")
	}
	if _, err := s.Generate(InstallOpts{ExecPath: "/bin/t"}); err == nil {
		t.Errorf("expected error when HomeDir is empty")
	}
}

func TestLaunchd_Generate_HeadlessDaemon(t *testing.T) {
	t.Parallel()
	s, err := NewFor("darwin")
	if err != nil {
		t.Fatal(err)
	}
	opts := baseOpts()
	// Mac operators usually have /Users/<name>; adjust for realism.
	opts.HomeDir = "/Users/alice"
	opts.ExecPath = "/Users/alice/.local/bin/telepath"
	u, err := s.Generate(opts)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	want := "/Users/alice/Library/LaunchAgents/io.telepath.daemon.plist"
	if u.Path != want {
		t.Errorf("path = %q, want %q", u.Path, want)
	}
	body := u.Content
	// plist framing
	for _, s := range []string{
		`<?xml version="1.0" encoding="UTF-8"?>`,
		`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"`,
		`<plist version="1.0">`,
		`<key>Label</key>`,
		`<string>io.telepath.daemon</string>`,
		`<key>ProgramArguments</key>`,
		`<key>KeepAlive</key>`,
		`<key>RunAtLoad</key>`,
		`<key>StandardOutPath</key>`,
		`<key>StandardErrorPath</key>`,
	} {
		if !strings.Contains(body, s) {
			t.Errorf("plist missing %q", s)
		}
	}
	// ProgramArguments entries
	for _, arg := range []string{
		`<string>/Users/alice/.local/bin/telepath</string>`,
		`<string>start</string>`,
		`<string>--no-browser</string>`,
		`<string>--no-dashboard</string>`,
	} {
		if !strings.Contains(body, arg) {
			t.Errorf("ProgramArguments missing %q", arg)
		}
	}
	// Log paths resolved
	if !strings.Contains(body, `<string>/Users/alice/.telepath/logs/daemon.log</string>`) {
		t.Errorf("missing default log path in plist: %s", body)
	}
}

func TestLaunchd_Generate_XMLEscapesSpecialCharsInPaths(t *testing.T) {
	t.Parallel()
	s, _ := NewFor("darwin")
	// Simulated pathological home dir with XML-meta characters. This
	// shouldn't exist in practice but the escaping matters — an
	// unescaped & in LogPath would produce a malformed plist that
	// launchctl bootstrap rejects.
	opts := InstallOpts{
		ExecPath: "/bin/t",
		HomeDir:  "/Users/alice",
		LogPath:  "/tmp/tele<path>&friends.log",
	}
	u, err := s.Generate(opts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(u.Content, "<path>") && !strings.Contains(u.Content, "&lt;path&gt;") {
		t.Errorf("< > not escaped")
	}
	if strings.Contains(u.Content, "&friends") && !strings.Contains(u.Content, "&amp;friends") {
		t.Errorf("& not escaped")
	}
}

func TestBuildExecArgs_ShapeByOpts(t *testing.T) {
	t.Parallel()
	// Directly tests the shared arg builder so a future driver added
	// here (Windows service, say) inherits the same flag contract.
	cases := []struct {
		name string
		opts InstallOpts
		want []string
	}{
		{
			name: "headless default",
			opts: InstallOpts{ExecPath: "/t"},
			want: []string{"/t", "start", "--no-browser", "--no-dashboard"},
		},
		{
			name: "with-dashboard, default bind",
			opts: InstallOpts{ExecPath: "/t", WithDashboard: true},
			want: []string{"/t", "start", "--no-browser"},
		},
		{
			name: "with-dashboard + custom bind",
			opts: InstallOpts{ExecPath: "/t", WithDashboard: true, DashboardBind: "127.0.0.1:9000"},
			want: []string{"/t", "start", "--no-browser", "--dashboard-bind", "127.0.0.1:9000"},
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := buildExecArgs(c.opts)
			if strings.Join(got, " ") != strings.Join(c.want, " ") {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}
