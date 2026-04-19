package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/fsc/telepath-core/internal/config"
	"github.com/fsc/telepath-core/internal/daemon"
	"github.com/fsc/telepath-core/internal/keys"
	"github.com/fsc/telepath-core/pkg/schema"
)

// ANSI color codes for doctor output. Skipped when stdout is not a TTY
// (pipes, redirects, CI logs) so captures stay plain-text.
var (
	colorReset  = ""
	colorGreen  = ""
	colorYellow = ""
	colorRed    = ""
)

func init() {
	// Colors on when stdout is a char device and NO_COLOR isn't set.
	// Convention from https://no-color.org/.
	if _, noColor := os.LookupEnv("NO_COLOR"); noColor {
		return
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return
	}
	if fi.Mode()&os.ModeCharDevice == 0 {
		return
	}
	colorReset = "\x1b[0m"
	colorGreen = "\x1b[32m"
	colorYellow = "\x1b[33m"
	colorRed = "\x1b[31m"
}

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose common setup issues",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Non-fatal checks; we report results line-by-line and always
			// exit 0 so the command is useful in a pipe even when the
			// daemon isn't running. Order is deliberate: environment first
			// (keystore/config/claude/pandoc), then daemon-dependent checks
			// (daemon, engagement, oauth) — so operators reading top-down
			// understand whether a DOWN daemon is the cause of later warns.
			checkKeystore(cmd)
			checkConfig(cmd)
			checkClaudeBinary(cmd)
			checkPandoc(cmd)
			checkDaemon(cmd)
			checkActiveEngagement(cmd)
			checkOAuthConnections(cmd)
			return nil
		},
	}
}

func ok(cmd *cobra.Command, label, detail string) {
	fmt.Fprintf(cmd.OutOrStdout(), "%s[ OK ]%s %-20s %s\n", colorGreen, colorReset, label, detail)
}
func warn(cmd *cobra.Command, label, detail string) {
	fmt.Fprintf(cmd.OutOrStdout(), "%s[WARN]%s %-20s %s\n", colorYellow, colorReset, label, detail)
}
func fail(cmd *cobra.Command, label, detail string) {
	fmt.Fprintf(cmd.OutOrStdout(), "%s[FAIL]%s %-20s %s\n", colorRed, colorReset, label, detail)
}

func checkKeystore(cmd *cobra.Command) {
	s, err := keys.Open()
	if err != nil {
		fail(cmd, "keystore", err.Error())
		return
	}
	if _, err := keys.GetOrCreateSigningKey(s); err != nil {
		fail(cmd, "keystore", fmt.Sprintf("signing key unavailable: %v", err))
		return
	}
	ok(cmd, "keystore", fmt.Sprintf("backend=%s, signing key present", s.Backend()))
}

func checkConfig(cmd *cobra.Command) {
	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		fail(cmd, "config", err.Error())
		return
	}
	var missing []string
	if cfg.Operator.Name == "" {
		missing = append(missing, "operator.name")
	}
	if cfg.Claude.AuthMethod == "" {
		missing = append(missing, "claude.auth_method")
	}
	if len(missing) > 0 {
		warn(cmd, "config", fmt.Sprintf("unset: %v — run `telepath config init`", missing))
		return
	}
	ok(cmd, "config", fmt.Sprintf("path=%s, auth=%s", config.DefaultPath(), cfg.Claude.AuthMethod))
}

func checkClaudeBinary(cmd *cobra.Command) {
	if _, err := exec.LookPath("claude"); err != nil {
		warn(cmd, "claude binary", "`claude` not on PATH — operators need it for the actual assessment")
		return
	}
	ok(cmd, "claude binary", "on PATH")
}

func checkDaemon(cmd *cobra.Command) {
	pid, err := daemon.ReadPIDFile(daemon.DefaultPIDFilePath())
	if err != nil {
		warn(cmd, "daemon", "not running (no pidfile)")
		return
	}
	if !daemon.PIDAlive(pid) {
		warn(cmd, "daemon", fmt.Sprintf("stale pidfile (pid %d not alive)", pid))
		return
	}
	res, err := func() (*schema.PingResult, error) {
		var p schema.PingResult
		if err := rpc(schema.MethodPing, nil, &p); err != nil {
			return nil, err
		}
		return &p, nil
	}()
	if err != nil {
		warn(cmd, "daemon", fmt.Sprintf("pid %d alive but ping failed: %v", pid, err))
		return
	}
	ok(cmd, "daemon", fmt.Sprintf("pid %d, version %s", pid, res.Version))
}

// checkPandoc flags whether the optional DOCX/PDF/PPTX deliverables
// will be produced by engagement export. Pandoc absent is a WARN, not a
// FAIL — the Markdown report is always the canonical deliverable.
func checkPandoc(cmd *cobra.Command) {
	if _, err := exec.LookPath("pandoc"); err != nil {
		warn(cmd, "pandoc", "not on PATH — engagement export will skip DOCX/PDF/PPTX (Markdown still produced)")
		return
	}
	ok(cmd, "pandoc", "on PATH — DOCX/PDF/PPTX deliverables enabled")
}

// checkActiveEngagement reports whether an engagement is currently
// loaded. Not an error either way; operators on a fresh daemon see
// "none loaded" and those mid-engagement see the ID + status.
func checkActiveEngagement(cmd *cobra.Command) {
	var res schema.EngagementGetResult
	if err := rpc(schema.MethodEngagementGet, nil, &res); err != nil {
		// Daemon unreachable — already flagged by checkDaemon. Skip.
		return
	}
	if res.Engagement == nil {
		warn(cmd, "active engagement", "none loaded — run `telepath engagement load <id>` before starting Claude Code")
		return
	}
	e := res.Engagement
	ok(cmd, "active engagement", fmt.Sprintf("%s (client=%s, status=%s)", e.ID, e.ClientName, e.Status))
}

// checkOAuthConnections lists SaaS connections the operator has made,
// flagging expired ones. An empty list is INFO-level (not every
// engagement needs SaaS access).
func checkOAuthConnections(cmd *cobra.Command) {
	var res schema.OAuthStatusResult
	if err := rpc(schema.MethodOAuthStatus, schema.OAuthStatusParams{}, &res); err != nil {
		// Same as above — daemon down already flagged.
		return
	}
	if len(res.Connections) == 0 {
		ok(cmd, "oauth connections", "none — run `telepath oauth begin <provider>` if a SaaS-backed engagement")
		return
	}
	for _, c := range res.Connections {
		label := fmt.Sprintf("oauth.%s/%s", c.Provider, c.Tenant)
		if c.Expired {
			warn(cmd, label, fmt.Sprintf("EXPIRED at %s — re-run `telepath oauth begin %s --tenant %s`", c.ExpiresAt, c.Provider, c.Tenant))
			continue
		}
		ok(cmd, label, fmt.Sprintf("live, expires %s", c.ExpiresAt))
	}
}

// silence unused import warnings if json drops out of checks later.
var _ = json.RawMessage{}
