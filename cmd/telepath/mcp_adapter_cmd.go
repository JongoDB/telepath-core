package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/fsc/telepath-core/internal/daemon"
	"github.com/fsc/telepath-core/internal/ipc"
	"github.com/fsc/telepath-core/pkg/schema"
)

// newMCPAdapterCmd is `telepath mcp-adapter`. Reads MCP JSON-RPC on stdin,
// writes responses on stdout, translates each tools/call into a telepath
// socket RPC. Runs until stdin closes (matching Claude Code's lifecycle).
func newMCPAdapterCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp-adapter",
		Short: "MCP stdio server; forwards tool calls to the telepath daemon over Unix socket",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMCPAdapter(os.Stdin, os.Stdout)
		},
	}
}

// --- MCP protocol framing (JSON-RPC 2.0 over stdio) ---

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *mcpError       `json:"error,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const mcpProtocolVersion = "2024-11-05"

type mcpServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type mcpCapabilities struct {
	Tools struct{} `json:"tools"`
}

type mcpInitializeResult struct {
	ProtocolVersion string          `json:"protocolVersion"`
	Capabilities    mcpCapabilities `json:"capabilities"`
	ServerInfo      mcpServerInfo   `json:"serverInfo"`
}

type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type mcpToolsListResult struct {
	Tools []mcpTool `json:"tools"`
}

type mcpContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type mcpToolCallResult struct {
	Content []mcpContentBlock `json:"content"`
	IsError bool              `json:"isError,omitempty"`
}

// toolSpec links an MCP-visible tool name to its description, input schema,
// and the daemon method it forwards to. Keep alphabetical by MCP name for
// discoverability.
type toolSpec struct {
	MCPName      string
	DaemonMethod string
	Description  string
	InputSchema  map[string]any
}

var toolCatalog = []toolSpec{
	{
		MCPName:      "telepath_engagement_get",
		DaemonMethod: schema.MethodEngagementGet,
		Description:  "Return metadata of the currently active engagement.",
		InputSchema:  jsonSchemaObject(nil, nil),
	},
	{
		MCPName:      "telepath_engagement_get_roe",
		DaemonMethod: schema.MethodROESummary,
		Description:  "Return a human-readable summary of the currently loaded ROE.",
		InputSchema:  jsonSchemaObject(nil, nil),
	},
	{
		MCPName:      "telepath_scope_check",
		DaemonMethod: schema.MethodScopeCheck,
		Description:  "Test whether a target (host, URL, tenant) is in scope before attempting an action.",
		InputSchema: jsonSchemaObject(map[string]any{
			"target":   jsonSchemaString("hostname, IP, or URL"),
			"protocol": jsonSchemaString("optional: ssh|winrm|https|sftp|smb"),
		}, []string{"target"}),
	},
	{
		MCPName:      "telepath_ssh_exec",
		DaemonMethod: schema.MethodSSHExec,
		Description:  "Execute a single shell command on a remote host over SSH.",
		InputSchema: jsonSchemaObject(map[string]any{
			"host":             jsonSchemaString("target hostname or IP"),
			"port":             jsonSchemaInt("SSH port; 22 if omitted"),
			"username":         jsonSchemaString("SSH user"),
			"password":         jsonSchemaString("optional: password auth"),
			"private_key_pem":  jsonSchemaString("optional: PEM-encoded key"),
			"passphrase":       jsonSchemaString("optional: passphrase for key"),
			"command":          jsonSchemaString("command to run"),
			"timeout_seconds":  jsonSchemaInt("command timeout"),
		}, []string{"host", "username", "command"}),
	},
	{
		MCPName:      "telepath_winrm_powershell",
		DaemonMethod: schema.MethodWinRMPowerShell,
		Description:  "Execute a PowerShell command on a remote Windows host via WinRM.",
		InputSchema: jsonSchemaObject(map[string]any{
			"host":            jsonSchemaString("target hostname or IP"),
			"port":            jsonSchemaInt("WinRM port; 5986 (HTTPS) or 5985 (HTTP) per https flag"),
			"https":           jsonSchemaString("use HTTPS; defaults false"),
			"insecure":        jsonSchemaString("skip TLS verification (sharp knife; ROE approval required)"),
			"username":        jsonSchemaString("Windows account"),
			"password":        jsonSchemaString("password (basic auth; NTLM/Kerberos in v0.2)"),
			"command":         jsonSchemaString("PowerShell script to run"),
			"timeout_seconds": jsonSchemaInt("command timeout"),
		}, []string{"host", "username", "command"}),
	},
	{
		MCPName:      "telepath_winrm_cmd",
		DaemonMethod: schema.MethodWinRMCmd,
		Description:  "Execute a cmd.exe command on a remote Windows host via WinRM.",
		InputSchema: jsonSchemaObject(map[string]any{
			"host":            jsonSchemaString("target hostname or IP"),
			"port":            jsonSchemaInt("WinRM port; 5986 (HTTPS) or 5985 (HTTP) per https flag"),
			"https":           jsonSchemaString("use HTTPS; defaults false"),
			"insecure":        jsonSchemaString("skip TLS verification (sharp knife; ROE approval required)"),
			"username":        jsonSchemaString("Windows account"),
			"password":        jsonSchemaString("password"),
			"command":         jsonSchemaString("cmd.exe command"),
			"stdin":           jsonSchemaString("optional stdin"),
			"timeout_seconds": jsonSchemaInt("command timeout"),
		}, []string{"host", "username", "command"}),
	},
	{
		MCPName:      "telepath_http_request",
		DaemonMethod: schema.MethodHTTPRequest,
		Description:  "Make an authenticated or anonymous HTTP request and return status, headers, and body.",
		InputSchema: jsonSchemaObject(map[string]any{
			"method":          jsonSchemaString("GET|POST|PUT|DELETE|..."),
			"url":             jsonSchemaString("full URL"),
			"headers":         jsonSchemaObject(map[string]any{}, nil),
			"body":            jsonSchemaString("request body (base64 for binary)"),
			"timeout_seconds": jsonSchemaInt("request timeout"),
		}, []string{"url"}),
	},
	{
		MCPName:      "telepath_files_store_synthesized",
		DaemonMethod: schema.MethodFilesStore,
		Description:  "Store a Claude-produced artifact (interview summary, observation write-up) as content-addressed evidence.",
		InputSchema: jsonSchemaObject(map[string]any{
			"content":      jsonSchemaString("artifact content"),
			"content_type": jsonSchemaString("MIME type"),
			"tags":         jsonSchemaStringArray("evidence tags"),
			"description":  jsonSchemaString("short human-readable provenance"),
			"skill":        jsonSchemaString("originating skill"),
			"target":       jsonSchemaString("target system or stakeholder"),
		}, []string{"content"}),
	},
	{
		MCPName:      "telepath_files_get_evidence",
		DaemonMethod: schema.MethodFilesGet,
		Description:  "Retrieve evidence content + metadata by evidence ID (sha256).",
		InputSchema: jsonSchemaObject(map[string]any{
			"evidence_id": jsonSchemaString("evidence SHA-256 hash"),
		}, []string{"evidence_id"}),
	},
	{
		MCPName:      "telepath_files_collect",
		DaemonMethod: schema.MethodFilesCollect,
		Description:  "Fetch a remote file via SFTP into the engagement's evidence vault. Requires sftp in ROE allowed_protocols.",
		InputSchema: jsonSchemaObject(map[string]any{
			"host":            jsonSchemaString("target hostname or IP"),
			"port":            jsonSchemaInt("SSH port; 22 if omitted"),
			"username":        jsonSchemaString("SSH user"),
			"password":        jsonSchemaString("optional: password auth"),
			"private_key_pem": jsonSchemaString("optional: PEM-encoded key"),
			"passphrase":      jsonSchemaString("optional: passphrase for key"),
			"path":            jsonSchemaString("remote file path"),
			"skill":           jsonSchemaString("originating skill (metadata)"),
			"tags":            jsonSchemaStringArray("evidence tags"),
		}, []string{"host", "username", "path"}),
	},
	{
		MCPName:      "telepath_files_list_remote",
		DaemonMethod: schema.MethodFilesListRemote,
		Description:  "List entries in a remote directory over SFTP. Non-recursive.",
		InputSchema: jsonSchemaObject(map[string]any{
			"host":            jsonSchemaString("target hostname or IP"),
			"port":            jsonSchemaInt("SSH port; 22 if omitted"),
			"username":        jsonSchemaString("SSH user"),
			"password":        jsonSchemaString("optional: password auth"),
			"private_key_pem": jsonSchemaString("optional: PEM-encoded key"),
			"passphrase":      jsonSchemaString("optional: passphrase for key"),
			"path":            jsonSchemaString("remote directory path"),
		}, []string{"host", "username", "path"}),
	},
	{
		MCPName:      "telepath_evidence_search",
		DaemonMethod: schema.MethodEvidenceSearch,
		Description:  "Search evidence metadata by tag, skill, target, or time.",
		InputSchema: jsonSchemaObject(map[string]any{
			"tag":        jsonSchemaString(""),
			"skill":      jsonSchemaString(""),
			"target":     jsonSchemaString(""),
			"session_id": jsonSchemaString(""),
			"since":      jsonSchemaString("RFC3339 timestamp"),
		}, nil),
	},
	{
		MCPName:      "telepath_findings_create",
		DaemonMethod: schema.MethodFindingsCreate,
		Description:  "Create a structured finding (status defaults to draft).",
		InputSchema: jsonSchemaObject(map[string]any{
			"finding": jsonSchemaObject(map[string]any{
				"title":            jsonSchemaString(""),
				"category":         jsonSchemaString("workflow_opportunity|automation_opportunity|ai_readiness_gap|risk"),
				"severity":         jsonSchemaString("info|low|medium|high|critical"),
				"description":      jsonSchemaString(""),
				"recommendation":   jsonSchemaString(""),
				"effort_estimate":  jsonSchemaString("XS|S|M|L|XL"),
				"impact_estimate":  jsonSchemaString("low|medium|high|transformative"),
				"confidence_level": jsonSchemaString("low|medium|high"),
			}, []string{"title", "category"}),
		}, []string{"finding"}),
	},
	{
		MCPName:      "telepath_findings_update",
		DaemonMethod: schema.MethodFindingsUpdate,
		Description:  "Update fields on an existing finding.",
		InputSchema: jsonSchemaObject(map[string]any{
			"id":      jsonSchemaString("f_NNNNNN"),
			"updates": jsonSchemaObject(map[string]any{}, nil),
			"reason":  jsonSchemaString(""),
		}, []string{"id", "updates"}),
	},
	{
		MCPName:      "telepath_findings_get",
		DaemonMethod: schema.MethodFindingsGet,
		Description:  "Retrieve a finding by ID.",
		InputSchema: jsonSchemaObject(map[string]any{
			"id": jsonSchemaString("f_NNNNNN"),
		}, []string{"id"}),
	},
	{
		MCPName:      "telepath_findings_list",
		DaemonMethod: schema.MethodFindingsList,
		Description:  "List findings, optionally filtered.",
		InputSchema: jsonSchemaObject(map[string]any{
			"category": jsonSchemaString(""),
			"severity": jsonSchemaString(""),
			"status":   jsonSchemaString("draft|confirmed|dismissed"),
		}, nil),
	},
	{
		MCPName:      "telepath_findings_set_status",
		DaemonMethod: schema.MethodFindingsSetStatus,
		Description:  "Transition a finding to draft|confirmed|dismissed.",
		InputSchema: jsonSchemaObject(map[string]any{
			"id":     jsonSchemaString("f_NNNNNN"),
			"status": jsonSchemaString("draft|confirmed|dismissed"),
			"reason": jsonSchemaString(""),
		}, []string{"id", "status"}),
	},
	{
		MCPName:      "telepath_notes_create",
		DaemonMethod: schema.MethodNotesCreate,
		Description:  "Create a freeform engagement note (markdown content + tags).",
		InputSchema: jsonSchemaObject(map[string]any{
			"note": jsonSchemaObject(map[string]any{
				"content":           jsonSchemaString("markdown"),
				"tags":              jsonSchemaStringArray("classification tags"),
				"related_evidence":  jsonSchemaStringArray("evidence IDs"),
				"related_findings":  jsonSchemaStringArray("finding IDs"),
			}, []string{"content"}),
		}, []string{"note"}),
	},
	{
		MCPName:      "telepath_notes_list",
		DaemonMethod: schema.MethodNotesList,
		Description:  "List notes, optionally filtered.",
		InputSchema: jsonSchemaObject(map[string]any{
			"tag":         jsonSchemaString(""),
			"since":       jsonSchemaString("RFC3339 timestamp"),
			"text_search": jsonSchemaString(""),
		}, nil),
	},
	{
		MCPName:      "telepath_notes_get",
		DaemonMethod: schema.MethodNotesGet,
		Description:  "Retrieve a note by ID.",
		InputSchema: jsonSchemaObject(map[string]any{
			"id": jsonSchemaString("n_NNNNNN"),
		}, []string{"id"}),
	},
}

// specByMCPName allows O(1) tool lookup in tools/call.
var specByMCPName = func() map[string]toolSpec {
	m := make(map[string]toolSpec, len(toolCatalog))
	for _, s := range toolCatalog {
		m[s.MCPName] = s
	}
	return m
}()

func runMCPAdapter(stdin io.Reader, stdout io.Writer) error {
	br := bufio.NewReader(stdin)
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			if errors.Is(err, io.EOF) && len(strings.TrimSpace(string(line))) == 0 {
				return nil
			}
			if errors.Is(err, io.EOF) {
				// Fall through to process the last line without newline.
			} else {
				return err
			}
		}
		line = []byte(strings.TrimRight(string(line), "\r\n"))
		if len(line) == 0 {
			if err != nil {
				return nil
			}
			continue
		}
		var req mcpRequest
		if perr := json.Unmarshal(line, &req); perr != nil {
			writeMCPLine(stdout, mcpResponse{
				JSONRPC: "2.0",
				ID:      nil,
				Error:   &mcpError{Code: -32700, Message: fmt.Sprintf("parse error: %v", perr)},
			})
			if errors.Is(err, io.EOF) {
				return nil
			}
			continue
		}
		resp := dispatchMCP(&req)
		// Notifications (no id) receive no response.
		if req.ID != nil {
			writeMCPLine(stdout, resp)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}

func dispatchMCP(req *mcpRequest) mcpResponse {
	switch req.Method {
	case "initialize":
		return mcpResponse{
			JSONRPC: "2.0", ID: req.ID,
			Result: mcpInitializeResult{
				ProtocolVersion: mcpProtocolVersion,
				ServerInfo:      mcpServerInfo{Name: "telepath-mcp-adapter", Version: daemon.Version},
			},
		}
	case "initialized":
		return mcpResponse{JSONRPC: "2.0", ID: req.ID}
	case "ping":
		return mcpResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}}
	case "tools/list":
		tools := make([]mcpTool, 0, len(toolCatalog))
		for _, s := range toolCatalog {
			tools = append(tools, mcpTool{Name: s.MCPName, Description: s.Description, InputSchema: s.InputSchema})
		}
		return mcpResponse{JSONRPC: "2.0", ID: req.ID, Result: mcpToolsListResult{Tools: tools}}
	case "tools/call":
		return dispatchToolsCall(req)
	default:
		return mcpResponse{JSONRPC: "2.0", ID: req.ID, Error: &mcpError{Code: -32601, Message: "method not found: " + req.Method}}
	}
}

type toolsCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func dispatchToolsCall(req *mcpRequest) mcpResponse {
	var p toolsCallParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return errorResult(req.ID, "invalid params: "+err.Error())
	}
	spec, ok := specByMCPName[p.Name]
	if !ok {
		return errorResult(req.ID, "unknown tool: "+p.Name)
	}
	var params any
	if len(p.Arguments) > 0 {
		var raw any
		if err := json.Unmarshal(p.Arguments, &raw); err != nil {
			return errorResult(req.ID, "arguments parse error: "+err.Error())
		}
		params = raw
	}
	res, err := ipc.Call(socketPath(), spec.DaemonMethod, params)
	if err != nil {
		return errorResult(req.ID, err.Error())
	}
	// Pretty-print the response JSON for the content block so Claude sees a
	// readable payload; callers can still parse it as JSON.
	pretty, _ := json.MarshalIndent(json.RawMessage(res), "", "  ")
	return mcpResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  mcpToolCallResult{Content: []mcpContentBlock{{Type: "text", Text: string(pretty)}}},
	}
}

func errorResult(id json.RawMessage, msg string) mcpResponse {
	return mcpResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  mcpToolCallResult{IsError: true, Content: []mcpContentBlock{{Type: "text", Text: msg}}},
	}
}

func writeMCPLine(w io.Writer, r mcpResponse) {
	data, err := json.Marshal(r)
	if err != nil {
		data = []byte(`{"jsonrpc":"2.0","error":{"code":-32603,"message":"marshal"}}`)
	}
	data = append(data, '\n')
	_, _ = w.Write(data)
}

// --- tiny JSON Schema helpers ---

func jsonSchemaObject(props map[string]any, required []string) map[string]any {
	out := map[string]any{"type": "object"}
	if len(props) > 0 {
		out["properties"] = props
	}
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}

func jsonSchemaString(desc string) map[string]any {
	out := map[string]any{"type": "string"}
	if desc != "" {
		out["description"] = desc
	}
	return out
}

func jsonSchemaInt(desc string) map[string]any {
	out := map[string]any{"type": "integer"}
	if desc != "" {
		out["description"] = desc
	}
	return out
}

func jsonSchemaStringArray(desc string) map[string]any {
	out := map[string]any{
		"type":  "array",
		"items": map[string]any{"type": "string"},
	}
	if desc != "" {
		out["description"] = desc
	}
	return out
}
