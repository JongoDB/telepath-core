package hooks

import (
	"encoding/json"
	"testing"

	"github.com/fsc/telepath-core/pkg/schema"
)

func inputWith(key, value string) json.RawMessage {
	b, _ := json.Marshal(map[string]string{key: value})
	return b
}

func TestClassify_BashRead(t *testing.T) {
	t.Parallel()
	r := Classify("Bash", inputWith("command", "ls -la /etc"))
	if r.RequiresApproval {
		t.Errorf("`ls` should not require approval")
	}
	if r.Class != schema.ClassReadEnumeration {
		t.Errorf("class = %q", r.Class)
	}
}

func TestClassify_BashWriteRm(t *testing.T) {
	t.Parallel()
	r := Classify("Bash", inputWith("command", "rm -rf /var/tmp/stuff"))
	if !r.RequiresApproval {
		t.Errorf("`rm -rf` must require approval")
	}
}

func TestClassify_SSHExec_Write(t *testing.T) {
	t.Parallel()
	r := Classify("mcp__telepath__ssh_exec", inputWith("command", "systemctl restart sshd"))
	if !r.RequiresApproval {
		t.Errorf("systemctl restart must require approval")
	}
}

func TestClassify_SSHExec_Read(t *testing.T) {
	t.Parallel()
	r := Classify("mcp__telepath__ssh_exec", inputWith("command", "uname -a"))
	if r.RequiresApproval {
		t.Errorf("`uname -a` must not require approval")
	}
}

func TestClassify_PowerShell_Write(t *testing.T) {
	t.Parallel()
	r := Classify("mcp__telepath__winrm_powershell", inputWith("script", "New-ADUser -Name bob"))
	if !r.RequiresApproval {
		t.Errorf("New-ADUser must require approval")
	}
}

func TestClassify_HTTP_GET(t *testing.T) {
	t.Parallel()
	r := Classify("mcp__telepath__http_request", inputWith("method", "GET"))
	if r.RequiresApproval {
		t.Errorf("HTTP GET must not require approval")
	}
}

func TestClassify_HTTP_POST(t *testing.T) {
	t.Parallel()
	r := Classify("mcp__telepath__http_request", inputWith("method", "POST"))
	if !r.RequiresApproval {
		t.Errorf("HTTP POST must require approval")
	}
}

func TestClassify_FindingsCreateIsLocal(t *testing.T) {
	t.Parallel()
	r := Classify("mcp__telepath__findings_create", json.RawMessage(`{}`))
	if r.RequiresApproval {
		t.Errorf("findings.create is a local artifact; should not gate approval")
	}
}

func TestClassify_WriteToolAlwaysApproves(t *testing.T) {
	t.Parallel()
	r := Classify("Write", inputWith("file_path", "/tmp/x"))
	if !r.RequiresApproval {
		t.Errorf("Write must require approval")
	}
}

func TestClassify_ReadTool(t *testing.T) {
	t.Parallel()
	r := Classify("Read", inputWith("file_path", "/tmp/x"))
	if r.RequiresApproval {
		t.Errorf("Read must not require approval")
	}
}

func TestClassify_Unknown(t *testing.T) {
	t.Parallel()
	r := Classify("SomeUnknownTool", nil)
	if r.Class != schema.ClassUnknown {
		t.Errorf("class = %q", r.Class)
	}
}
