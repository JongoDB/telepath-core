package hooks

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/fsc/telepath-core/pkg/schema"
)

// Classify evaluates a tool call and returns a class + approval-required
// flag per ARCHITECTURE.md §9.1. The goal is conservative: false positives
// (classifying a read as a write) cost an extra approval prompt, which the
// operator dismisses; false negatives (classifying a write as a read) are
// the failure mode we protect against.
func Classify(toolName string, toolInput json.RawMessage) schema.ClassifyResult {
	tool := strings.TrimSpace(toolName)
	switch {
	case isMCPTelepath(tool):
		return classifyMCP(tool, toolInput)
	case tool == "Bash":
		return classifyBash(toolInput)
	case tool == "Write" || tool == "Edit" || tool == "NotebookEdit":
		return schema.ClassifyResult{
			OK:               true,
			Class:            schema.ClassWriteIrreversibl,
			RequiresApproval: true,
			Reason:           "built-in filesystem write",
		}
	case tool == "Read" || tool == "Glob" || tool == "Grep":
		return schema.ClassifyResult{
			OK:    true,
			Class: schema.ClassReadEnumeration,
		}
	case tool == "WebFetch" || tool == "WebSearch":
		return schema.ClassifyResult{
			OK:     true,
			Class:  schema.ClassReadEnumeration,
			Reason: "agent-tooling fetch; no client-system touch",
		}
	default:
		return schema.ClassifyResult{
			OK:     true,
			Class:  schema.ClassUnknown,
			Reason: "no classifier pattern for tool " + tool,
		}
	}
}

func isMCPTelepath(tool string) bool {
	return strings.HasPrefix(tool, "mcp__telepath__") ||
		// Direct daemon methods when dispatched over Unix socket use
		// dotted names; classify by the dotted prefix too for consistency.
		strings.HasPrefix(tool, "telepath-") ||
		strings.Contains(tool, ".exec") ||
		strings.Contains(tool, ".powershell") ||
		strings.Contains(tool, ".request") ||
		strings.Contains(tool, ".store_synthesized") ||
		strings.Contains(tool, ".sftp_")
}

// classifyMCP handles telepath MCP tools. The tool name encodes protocol +
// action; this function fans out on that.
func classifyMCP(tool string, toolInput json.RawMessage) schema.ClassifyResult {
	low := strings.ToLower(tool)
	switch {
	case strings.HasSuffix(low, "ssh.exec"), strings.Contains(low, "ssh_exec"), strings.HasSuffix(low, "winrm.powershell"), strings.Contains(low, "winrm_powershell"):
		return classifyShell(toolInput)
	case strings.HasSuffix(low, "http.request"), strings.Contains(low, "http_request"),
		strings.HasSuffix(low, "saas.request"), strings.Contains(low, "saas_request"):
		// SaaS request follows the same read-vs-write heuristic as plain
		// HTTP — GET/HEAD/OPTIONS are reads, POST/PUT/PATCH/DELETE need
		// approval. The daemon's write-actions policy still overrides
		// per ROE.
		return classifyHTTP(toolInput)
	case strings.HasSuffix(low, "saas.refresh"), strings.Contains(low, "saas_refresh"):
		return schema.ClassifyResult{OK: true, Class: schema.ClassReadEnumeration, Reason: "operator-side token refresh"}
	case strings.Contains(low, "files_collect"), strings.Contains(low, "sftp_get"), strings.HasSuffix(low, "files.collect"):
		return schema.ClassifyResult{OK: true, Class: schema.ClassReadBulk, Reason: "file collection"}
	case strings.Contains(low, "sftp_list"), strings.Contains(low, "evidence.search"), strings.Contains(low, "evidence_search"), strings.Contains(low, "files_list_remote"), strings.HasSuffix(low, "files.list_remote"):
		return schema.ClassifyResult{OK: true, Class: schema.ClassReadEnumeration}
	case strings.Contains(low, "findings.create"), strings.Contains(low, "notes.create"), strings.Contains(low, "findings_create"), strings.Contains(low, "notes_create"):
		return schema.ClassifyResult{OK: true, Class: schema.ClassReadEnumeration, Reason: "operator-side artifact; no client-system write"}
	case strings.Contains(low, "store_synthesized"):
		return schema.ClassifyResult{OK: true, Class: schema.ClassReadEnumeration, Reason: "synthesized artifact stored locally"}
	case strings.Contains(low, "oauth_begin"), strings.Contains(low, "oauth_status"), strings.Contains(low, "oauth_complete"),
		strings.HasSuffix(low, "oauth.begin"), strings.HasSuffix(low, "oauth.status"), strings.HasSuffix(low, "oauth.complete"):
		return schema.ClassifyResult{OK: true, Class: schema.ClassReadEnumeration}
	}
	return schema.ClassifyResult{OK: true, Class: schema.ClassUnknown, Reason: "unrecognized MCP tool"}
}

// shellWritePattern matches commands that mutate state on the target host.
// Ordered roughly by risk; the first matching pattern wins.
var shellWritePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?m)\brm\s+-[rfRf]*\s`),
	regexp.MustCompile(`(?m)\bdd\s+if=`),
	regexp.MustCompile(`(?m)\bmkfs\b`),
	regexp.MustCompile(`(?m)>\s*/`),
	regexp.MustCompile(`(?m)>>\s*/`),
	regexp.MustCompile(`(?m)\bchmod\s+\d`),
	regexp.MustCompile(`(?m)\bchown\s+\S+`),
	regexp.MustCompile(`(?m)\bmv\s+\S+\s+\S+`),
	regexp.MustCompile(`(?m)\bcp\s+\S+\s+\S+`),
	regexp.MustCompile(`(?m)\bkill(?:\s+|all\b)`),
	regexp.MustCompile(`(?m)\breboot\b`),
	regexp.MustCompile(`(?m)\bshutdown\b`),
	regexp.MustCompile(`(?m)\bpasswd\s+\S+`),
	regexp.MustCompile(`(?m)\b(useradd|userdel|groupadd|groupdel|gpasswd)\s`),
	regexp.MustCompile(`(?m)\bsystemctl\s+(start|stop|enable|disable|restart|mask)`),
	regexp.MustCompile(`(?i)\bNew-[A-Za-z]+`), // PowerShell New-*
	regexp.MustCompile(`(?i)\bSet-[A-Za-z]+`),
	regexp.MustCompile(`(?i)\bRemove-[A-Za-z]+`),
	regexp.MustCompile(`(?i)\bAdd-[A-Za-z]+`),
	regexp.MustCompile(`(?i)\bDisable-[A-Za-z]+`),
}

func classifyShell(toolInput json.RawMessage) schema.ClassifyResult {
	cmd := extractField(toolInput, "command", "script")
	for _, p := range shellWritePatterns {
		if p.FindStringIndex(cmd) != nil {
			return schema.ClassifyResult{
				OK:               true,
				Class:            schema.ClassWriteIrreversibl,
				RequiresApproval: true,
				Reason:           "shell command matches write pattern: " + p.String(),
			}
		}
	}
	return schema.ClassifyResult{
		OK:    true,
		Class: schema.ClassReadEnumeration,
	}
}

func classifyHTTP(toolInput json.RawMessage) schema.ClassifyResult {
	method := strings.ToUpper(extractField(toolInput, "method"))
	switch method {
	case "", "GET", "HEAD", "OPTIONS":
		return schema.ClassifyResult{OK: true, Class: schema.ClassReadEnumeration}
	case "POST", "PUT", "PATCH", "DELETE":
		return schema.ClassifyResult{
			OK:               true,
			Class:            schema.ClassWriteReversible,
			RequiresApproval: true,
			Reason:           "HTTP " + method + " request",
		}
	}
	return schema.ClassifyResult{OK: true, Class: schema.ClassUnknown}
}

func classifyBash(toolInput json.RawMessage) schema.ClassifyResult {
	return classifyShell(toolInput)
}

// extractField pulls the first present string field from a json.RawMessage.
// Avoids a full unmarshal when only one key is needed.
func extractField(raw json.RawMessage, keys ...string) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}
