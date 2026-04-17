// Package rendering turns engagement metadata into the CLAUDE.md the
// operator's Claude Code session reads at SessionStart. The canonical
// template lives in the plugin repo at templates/CLAUDE.md; telepath-core
// ships a minimal embedded fallback used when no override is configured.
package rendering

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsc/telepath-core/pkg/schema"
)

// defaultClaudeMD is the embedded fallback rendered when the operator has
// not pointed telepath-core at a richer plugin template.
//
//go:embed default_claude.md
var defaultClaudeMD string

// PlaceholderPair maps a {{TOKEN}} spelling to the engagement accessor that
// supplies its value. Keep in sync with the template.
var placeholders = []struct {
	token string
	fn    func(schema.Engagement) string
}{
	{"{{ENGAGEMENT_ID}}", func(e schema.Engagement) string { return e.ID }},
	{"{{CLIENT_NAME}}", func(e schema.Engagement) string { return e.ClientName }},
	{"{{ASSESSMENT_TYPE}}", func(e schema.Engagement) string { return e.AssessmentType }},
	{"{{START_DATE}}", func(e schema.Engagement) string { return fmtDate(e.StartDate) }},
	{"{{END_DATE}}", func(e schema.Engagement) string { return fmtDate(e.EndDate) }},
	{"{{OPERATOR_NAME}}", func(e schema.Engagement) string { return fallback(e.OperatorID, "(unset)") }},
	{"{{TRANSPORT_MODE}}", func(e schema.Engagement) string { return fallback(e.TransportMode, "(not up)") }},
	{"{{PRIMARY_SKILL}}", func(e schema.Engagement) string { return fallback(e.PrimarySkill, "(none)") }},
}

// Render returns the CLAUDE.md content for e. If templatePath is empty or
// the file is missing, the embedded default is used. Placeholder tokens that
// don't appear in the chosen template are ignored silently — this tolerates
// operator-customized templates.
func Render(e schema.Engagement, templatePath string) (string, error) {
	src := defaultClaudeMD
	if templatePath != "" {
		if data, err := os.ReadFile(templatePath); err == nil {
			src = string(data)
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("rendering: read %s: %w", templatePath, err)
		}
	}
	out := src
	for _, p := range placeholders {
		out = strings.ReplaceAll(out, p.token, p.fn(e))
	}
	return out, nil
}

// WriteForEngagement renders and writes <engagementDir>/.claude/CLAUDE.md.
// templatePath is optional (empty string = embedded default). Parent
// directories are created as needed.
func WriteForEngagement(e schema.Engagement, engagementDir, templatePath string) (string, error) {
	content, err := Render(e, templatePath)
	if err != nil {
		return "", err
	}
	outDir := filepath.Join(engagementDir, ".claude")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return "", fmt.Errorf("rendering: mkdir %s: %w", outDir, err)
	}
	outPath := filepath.Join(outDir, "CLAUDE.md")
	if err := os.WriteFile(outPath, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("rendering: write %s: %w", outPath, err)
	}
	return outPath, nil
}

// TemplatePathFromEnv returns TELEPATH_TEMPLATES_DIR/CLAUDE.md if the env
// var is set, or "" to signal "use embedded default." Extracted so tests
// can construct paths without depending on real env state.
func TemplatePathFromEnv() string {
	dir := os.Getenv("TELEPATH_TEMPLATES_DIR")
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "CLAUDE.md")
}

// WriteRules copies plugin-provided rules files into the engagement's
// .claude/rules/ directory. Rules are plain markdown and are loaded with
// high priority by Claude Code at session start. Per-engagement copies let
// operators tailor rules (e.g., injecting the specific ROE's blackout
// window) without editing the plugin.
//
// Source lookup: <pluginRulesDir> (typically <plugin>/templates/rules).
// When pluginRulesDir is empty, this function is a no-op and returns nil —
// bootstrap environments without a plugin dir still get a working engagement,
// just with no rules files.
func WriteRules(engagementDir, pluginRulesDir string) (int, error) {
	if pluginRulesDir == "" {
		return 0, nil
	}
	src, err := os.Stat(pluginRulesDir)
	if err != nil || !src.IsDir() {
		return 0, nil
	}
	dst := filepath.Join(engagementDir, ".claude", "rules")
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return 0, fmt.Errorf("rendering: mkdir %s: %w", dst, err)
	}
	entries, err := os.ReadDir(pluginRulesDir)
	if err != nil {
		return 0, fmt.Errorf("rendering: read %s: %w", pluginRulesDir, err)
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".md" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(pluginRulesDir, e.Name()))
		if err != nil {
			return n, fmt.Errorf("rendering: read rule %s: %w", e.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), data, 0o600); err != nil {
			return n, fmt.Errorf("rendering: write rule %s: %w", e.Name(), err)
		}
		n++
	}
	return n, nil
}

// WriteMCPConfig writes the engagement's .claude/mcp.json. This is what
// Claude Code reads when launched from the engagement directory — it
// spawns `telepath mcp-adapter` as an MCP server, with TELEPATH_SOCKET set
// to point at the running daemon.
func WriteMCPConfig(engagementDir, daemonSocket, telepathBin string) (string, error) {
	if telepathBin == "" {
		telepathBin = "telepath"
	}
	body := map[string]any{
		"mcpServers": map[string]any{
			"telepath": map[string]any{
				"command": telepathBin,
				"args":    []string{"mcp-adapter"},
				"env": map[string]string{
					"TELEPATH_SOCKET": daemonSocket,
				},
			},
		},
	}
	data, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return "", fmt.Errorf("rendering: marshal mcp.json: %w", err)
	}
	outDir := filepath.Join(engagementDir, ".claude")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return "", fmt.Errorf("rendering: mkdir %s: %w", outDir, err)
	}
	outPath := filepath.Join(outDir, "mcp.json")
	if err := os.WriteFile(outPath, data, 0o600); err != nil {
		return "", fmt.Errorf("rendering: write mcp.json: %w", err)
	}
	return outPath, nil
}

// PluginRulesDirFromEnv returns TELEPATH_TEMPLATES_DIR/rules if set, else "".
func PluginRulesDirFromEnv() string {
	dir := os.Getenv("TELEPATH_TEMPLATES_DIR")
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "rules")
}

func fmtDate(t time.Time) string {
	if t.IsZero() {
		return "(unset)"
	}
	return t.Format("2006-01-02")
}

func fallback(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}
