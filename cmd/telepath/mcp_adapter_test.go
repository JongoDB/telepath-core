package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// MCP adapter is primarily a transport, but we can test its dispatch logic
// without a real daemon by checking initialize, tools/list, and the error
// path for tools/call when the socket isn't reachable (tests don't spin up
// a daemon — they just validate the adapter's side of the protocol).

func TestMCPAdapter_Initialize(t *testing.T) {
	t.Parallel()
	in := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n"
	var out bytes.Buffer
	if err := runMCPAdapter(strings.NewReader(in), &out); err != nil {
		t.Fatalf("runMCPAdapter: %v", err)
	}
	var resp mcpResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (raw=%q)", err, out.String())
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
	bodyJSON, _ := json.Marshal(resp.Result)
	if !strings.Contains(string(bodyJSON), `"protocolVersion"`) {
		t.Errorf("initialize result missing protocolVersion: %s", bodyJSON)
	}
	if !strings.Contains(string(bodyJSON), `"telepath-mcp-adapter"`) {
		t.Errorf("initialize result missing server name: %s", bodyJSON)
	}
}

func TestMCPAdapter_ToolsList_ContainsKeyTools(t *testing.T) {
	t.Parallel()
	in := `{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}` + "\n"
	var out bytes.Buffer
	if err := runMCPAdapter(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	body := out.String()
	// Tools the plugin's hook lib + subagents call during every
	// engagement. Don't remove one without also updating the plugin —
	// the MCP surface is the stable-contract boundary.
	for _, required := range []string{
		"telepath_engagement_get",
		"telepath_scope_check",
		"telepath_ssh_exec",
		"telepath_winrm_powershell",
		"telepath_winrm_cmd",
		"telepath_http_request",
		"telepath_saas_request",
		"telepath_saas_refresh",
		"telepath_files_collect",
		"telepath_files_list_remote",
		"telepath_files_store_synthesized",
		"telepath_files_get_evidence",
		"telepath_evidence_search",
		"telepath_findings_create",
		"telepath_findings_update",
		"telepath_findings_get",
		"telepath_findings_list",
		"telepath_findings_set_status",
		"telepath_notes_create",
		"telepath_notes_list",
		"telepath_notes_get",
	} {
		if !strings.Contains(body, required) {
			t.Errorf("tools/list missing %q", required)
		}
	}
}

func TestMCPAdapter_UnknownTool(t *testing.T) {
	t.Parallel()
	in := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"telepath_bogus","arguments":{}}}` + "\n"
	var out bytes.Buffer
	if err := runMCPAdapter(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	// An unknown tool returns isError=true via tool result, not via
	// JSON-RPC error — matches the MCP convention.
	if !strings.Contains(out.String(), `"isError":true`) {
		t.Errorf("expected isError=true, got %s", out.String())
	}
}

func TestMCPAdapter_NotificationHasNoResponse(t *testing.T) {
	t.Parallel()
	// `initialized` is a notification (no id) — the adapter must not write
	// a response line.
	in := `{"jsonrpc":"2.0","method":"initialized","params":{}}` + "\n"
	var out bytes.Buffer
	if err := runMCPAdapter(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Errorf("notification should produce no output; got %q", out.String())
	}
}

func TestMCPAdapter_ParseError(t *testing.T) {
	t.Parallel()
	in := "not json at all\n"
	var out bytes.Buffer
	if err := runMCPAdapter(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"code":-32700`) {
		t.Errorf("expected parse error code; got %s", out.String())
	}
}
