package rendering

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fsc/telepath-core/pkg/schema"
)

func sampleEngagement() schema.Engagement {
	return schema.Engagement{
		ID:             "acme-01",
		ClientName:     "Acme Corp",
		AssessmentType: "ai-opportunity-roadmap",
		StartDate:      time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC),
		EndDate:        time.Date(2026, 5, 3, 0, 0, 0, 0, time.UTC),
		OperatorID:     "alex",
		PrimarySkill:   "ai-opportunity-discovery",
		TransportMode:  "cloudflare-tunnel",
	}
}

func TestRender_DefaultTemplate(t *testing.T) {
	t.Parallel()
	out, err := Render(sampleEngagement(), "")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{"acme-01", "Acme Corp", "ai-opportunity-roadmap", "2026-04-20", "alex", "cloudflare-tunnel", "ai-opportunity-discovery"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
	if strings.Contains(out, "{{") {
		t.Errorf("unreplaced placeholder in output:\n%s", out)
	}
}

func TestRender_OverrideTemplate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "CLAUDE.md")
	body := "engagement: {{ENGAGEMENT_ID}} for {{CLIENT_NAME}}"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := Render(sampleEngagement(), path)
	if err != nil {
		t.Fatal(err)
	}
	if out != "engagement: acme-01 for Acme Corp" {
		t.Errorf("override body: %q", out)
	}
}

func TestRender_MissingTemplateFallsBackToDefault(t *testing.T) {
	t.Parallel()
	out, err := Render(sampleEngagement(), filepath.Join(t.TempDir(), "does-not-exist.md"))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "acme-01") {
		t.Errorf("expected fallback to default, got no ID substitution")
	}
}

func TestRender_ZeroDatesFormattedAsUnset(t *testing.T) {
	t.Parallel()
	e := sampleEngagement()
	e.StartDate = time.Time{}
	e.EndDate = time.Time{}
	out, _ := Render(e, "")
	if !strings.Contains(out, "(unset)") {
		t.Errorf("zero-date formatting missing %q: %s", "(unset)", out)
	}
}

func TestWriteForEngagement(t *testing.T) {
	t.Parallel()
	engagementDir := t.TempDir()
	outPath, err := WriteForEngagement(sampleEngagement(), engagementDir, "")
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if outPath != filepath.Join(engagementDir, ".claude", "CLAUDE.md") {
		t.Errorf("outPath = %q", outPath)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "acme-01") {
		t.Errorf("file missing expected content")
	}
}

func TestTemplatePathFromEnv(t *testing.T) {
	t.Setenv("TELEPATH_TEMPLATES_DIR", "")
	if p := TemplatePathFromEnv(); p != "" {
		t.Errorf("unset env -> empty path; got %q", p)
	}
	t.Setenv("TELEPATH_TEMPLATES_DIR", "/plugin/templates")
	if p := TemplatePathFromEnv(); p != "/plugin/templates/CLAUDE.md" {
		t.Errorf("env path: %q", p)
	}
}

func TestWriteRules(t *testing.T) {
	t.Parallel()
	// Build a fake plugin rules dir with two markdown files and one non-md
	// file that should be ignored.
	plugin := t.TempDir()
	if err := os.WriteFile(filepath.Join(plugin, "01-engagement.md"), []byte("# ROE rule"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plugin, "02-scope.md"), []byte("# Scope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plugin, "not-a-rule.txt"), []byte("ignore me"), 0o600); err != nil {
		t.Fatal(err)
	}
	engagement := t.TempDir()
	n, err := WriteRules(engagement, plugin)
	if err != nil {
		t.Fatalf("WriteRules: %v", err)
	}
	if n != 2 {
		t.Errorf("count = %d, want 2", n)
	}
	if _, err := os.Stat(filepath.Join(engagement, ".claude", "rules", "01-engagement.md")); err != nil {
		t.Errorf("rule 1 missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(engagement, ".claude", "rules", "not-a-rule.txt")); err == nil {
		t.Errorf("non-md file shouldn't have been copied")
	}
}

func TestWriteRules_EmptyPluginDirIsNoOp(t *testing.T) {
	t.Parallel()
	engagement := t.TempDir()
	n, err := WriteRules(engagement, "")
	if err != nil || n != 0 {
		t.Errorf("empty plugin dir: got n=%d err=%v", n, err)
	}
	if _, err := os.Stat(filepath.Join(engagement, ".claude", "rules")); err == nil {
		t.Errorf("no-op should not create rules dir")
	}
}

func TestWriteMCPConfig(t *testing.T) {
	t.Parallel()
	engagement := t.TempDir()
	path, err := WriteMCPConfig(engagement, "/tmp/x.sock", "")
	if err != nil {
		t.Fatalf("WriteMCPConfig: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	for _, want := range []string{`"mcpServers"`, `"telepath"`, `"mcp-adapter"`, `/tmp/x.sock`, `"telepath"`} {
		if !strings.Contains(body, want) {
			t.Errorf("mcp.json missing %q: %s", want, body)
		}
	}
}
