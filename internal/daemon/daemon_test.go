package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fsc/telepath-core/internal/engagement"
	"github.com/fsc/telepath-core/internal/ipc"
	"github.com/fsc/telepath-core/internal/keys"
	"github.com/fsc/telepath-core/internal/vault"
	"github.com/fsc/telepath-core/pkg/schema"
)

// newTestDaemon spins up a fully wired daemon on a temp dir. Returns the
// daemon, the engagement Manager, and a cleanup function that drains
// shutdown.
func newTestDaemon(t *testing.T) (*Daemon, *engagement.Manager) {
	t.Helper()
	dir := t.TempDir()
	store, err := keys.NewFileStore(filepath.Join(dir, "keystore"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	sock := filepath.Join(dir, "daemon.sock")
	d, err := New(Config{
		RootDir:     dir,
		SocketPath:  sock,
		PIDFilePath: filepath.Join(dir, "daemon.pid"),
		KeyStore:    store,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := d.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = d.Shutdown(ctx)
	})
	return d, d.Manager()
}

func TestDaemon_PingOverSocket(t *testing.T) {
	t.Parallel()
	d, _ := newTestDaemon(t)
	res, err := ipc.Call(d.SocketPath(), schema.MethodPing, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	var p schema.PingResult
	if err := json.Unmarshal(res, &p); err != nil {
		t.Fatal(err)
	}
	if !p.OK || p.Version == "" {
		t.Errorf("ping result: %+v", p)
	}
}

func TestDaemon_EngagementGet_NoActive(t *testing.T) {
	t.Parallel()
	d, _ := newTestDaemon(t)
	res, err := ipc.Call(d.SocketPath(), schema.MethodEngagementGet, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out schema.EngagementGetResult
	_ = json.Unmarshal(res, &out)
	if !out.OK {
		t.Errorf("expected OK=true")
	}
	if out.Engagement != nil {
		t.Errorf("expected nil engagement, got %+v", out.Engagement)
	}
}

func TestDaemon_EngagementGet_WithActive(t *testing.T) {
	t.Parallel()
	d, mgr := newTestDaemon(t)
	_, err := mgr.Create(engagement.CreateParams{ID: "d1", ClientName: "C", AssessmentType: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Load("d1"); err != nil {
		t.Fatal(err)
	}
	res, err := ipc.Call(d.SocketPath(), schema.MethodEngagementGet, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out schema.EngagementGetResult
	_ = json.Unmarshal(res, &out)
	if out.Engagement == nil || out.Engagement.ID != "d1" {
		t.Errorf("engagement not reflected: %+v", out)
	}
}

func TestDaemon_AuditEmit_NoEngagement(t *testing.T) {
	t.Parallel()
	d, _ := newTestDaemon(t)
	params := schema.AuditEmitParams{Type: schema.AuditTypeMCPCall}
	_, err := ipc.Call(d.SocketPath(), schema.MethodAuditEmit, params)
	var re *ipc.RemoteError
	if !errors.As(err, &re) || re.Code != schema.ErrCodeNoActiveEngagement {
		t.Fatalf("expected NoActiveEngagement, got %v", err)
	}
}

func TestDaemon_AuditEmit_IntoActiveLog(t *testing.T) {
	t.Parallel()
	d, mgr := newTestDaemon(t)
	_, err := mgr.Create(engagement.CreateParams{ID: "d2", ClientName: "C", AssessmentType: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Load("d2"); err != nil {
		t.Fatal(err)
	}
	params := schema.AuditEmitParams{
		Type:    schema.AuditTypeMCPCall,
		Actor:   schema.ActorClaudeCode,
		Payload: json.RawMessage(`{"tool":"ssh","cmd":"uname"}`),
	}
	res, err := ipc.Call(d.SocketPath(), schema.MethodAuditEmit, params)
	if err != nil {
		t.Fatal(err)
	}
	var out schema.AuditEmitResult
	_ = json.Unmarshal(res, &out)
	if !out.OK {
		t.Errorf("expected OK")
	}
	if out.Sequence == 0 || out.Hash == "" {
		t.Errorf("missing seq/hash: %+v", out)
	}
}

func TestDaemon_Checkpoint(t *testing.T) {
	t.Parallel()
	d, mgr := newTestDaemon(t)
	_, _ = mgr.Create(engagement.CreateParams{ID: "d3", ClientName: "C", AssessmentType: "t"})
	_, _ = mgr.Load("d3")
	// Append one event so the checkpoint has something to sign.
	_, err := ipc.Call(d.SocketPath(), schema.MethodAuditEmit, schema.AuditEmitParams{Type: schema.AuditTypeMCPCall})
	if err != nil {
		t.Fatal(err)
	}
	res, err := ipc.Call(d.SocketPath(), schema.MethodAuditCheckpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out schema.CheckpointResult
	_ = json.Unmarshal(res, &out)
	if !out.OK || out.SignedThrough == 0 {
		t.Errorf("checkpoint result: %+v", out)
	}
}

func TestDaemon_SessionSummary(t *testing.T) {
	t.Parallel()
	d, mgr := newTestDaemon(t)
	_, _ = mgr.Create(engagement.CreateParams{ID: "d4", ClientName: "C", AssessmentType: "t"})
	_, _ = mgr.Load("d4")
	res, err := ipc.Call(d.SocketPath(), schema.MethodSessionWriteSummary, schema.SessionSummaryParams{
		Content: "# Today\n\nInterviewed Sarah.\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	var out schema.SessionSummaryResult
	_ = json.Unmarshal(res, &out)
	if !out.OK || !strings.HasSuffix(out.Path, ".md") {
		t.Errorf("summary result: %+v", out)
	}
	// File exists and has content.
	data, err := os.ReadFile(out.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Interviewed Sarah") {
		t.Errorf("summary file content: %q", string(data))
	}
}

func TestDaemon_CredentialsRedact(t *testing.T) {
	t.Parallel()
	d, _ := newTestDaemon(t)
	res, err := ipc.Call(d.SocketPath(), schema.MethodCredentialsRedact, schema.CredentialsRedactParams{
		Text: "my key is AKIAABCDEFGHIJKLMNOP here",
	})
	if err != nil {
		t.Fatal(err)
	}
	var out schema.CredentialsRedactResult
	_ = json.Unmarshal(res, &out)
	if !out.OK || strings.Contains(out.Redacted, "AKIA") {
		t.Errorf("redact result: %+v", out)
	}
}

func TestDaemon_UnknownMethod(t *testing.T) {
	t.Parallel()
	d, _ := newTestDaemon(t)
	_, err := ipc.Call(d.SocketPath(), "bogus.method", nil)
	var re *ipc.RemoteError
	if !errors.As(err, &re) || re.Code != schema.ErrCodeMethodNotFound {
		t.Fatalf("expected MethodNotFound, got %v", err)
	}
}

func TestDaemon_RefusesSecondStart(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store, _ := keys.NewFileStore(filepath.Join(dir, "ks"))
	d, err := New(Config{
		RootDir:     dir,
		SocketPath:  filepath.Join(dir, "s.sock"),
		PIDFilePath: filepath.Join(dir, "d.pid"),
		KeyStore:    store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, c := context.WithTimeout(context.Background(), time.Second)
		defer c()
		_ = d.Shutdown(ctx)
	}()
	if err := d.Start(); err == nil {
		t.Fatalf("expected second Start to fail")
	}
}

func TestDaemon_ShutdownRemovesFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store, _ := keys.NewFileStore(filepath.Join(dir, "ks"))
	sock := filepath.Join(dir, "s.sock")
	pid := filepath.Join(dir, "d.pid")
	d, err := New(Config{RootDir: dir, SocketPath: sock, PIDFilePath: pid, KeyStore: store})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := d.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	for _, path := range []string{sock, pid} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("path %s should be gone: err=%v", path, err)
		}
	}
}

func TestDaemon_ScopeCheck_DeniesWithoutROE(t *testing.T) {
	t.Parallel()
	d, mgr := newTestDaemon(t)
	if _, err := mgr.Create(engagement.CreateParams{ID: "sc1", ClientName: "C", AssessmentType: "t"}); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Load("sc1"); err != nil {
		t.Fatal(err)
	}
	res, err := ipc.Call(d.SocketPath(), schema.MethodScopeCheck, schema.ScopeCheckParams{Target: "anything", Protocol: "ssh"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	var out schema.ScopeCheckResult
	_ = json.Unmarshal(res, &out)
	if out.InScope {
		t.Errorf("without ROE loaded, scope.check must deny; got %+v", out)
	}
}

func TestDaemon_ScopeCheck_WithROE(t *testing.T) {
	t.Parallel()
	d, mgr := newTestDaemon(t)
	if _, err := mgr.Create(engagement.CreateParams{ID: "sc2", ClientName: "C", AssessmentType: "t"}); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Load("sc2"); err != nil {
		t.Fatal(err)
	}
	roeYAML := `
engagement_id: sc2
version: 1
in_scope:
  hosts: ["10.0.0.0/8", "jumphost.acme"]
allowed_protocols: [ssh, https]
`
	_, err := ipc.Call(d.SocketPath(), schema.MethodEngagementSetROE, schema.EngagementSetROEParams{ID: "sc2", YAML: roeYAML})
	if err != nil {
		t.Fatal(err)
	}
	// In-scope
	res, _ := ipc.Call(d.SocketPath(), schema.MethodScopeCheck, schema.ScopeCheckParams{Target: "10.1.2.3", Protocol: "ssh"})
	var out schema.ScopeCheckResult
	_ = json.Unmarshal(res, &out)
	if !out.InScope {
		t.Errorf("expected allow: %+v", out)
	}
	// Disallowed protocol
	res2, _ := ipc.Call(d.SocketPath(), schema.MethodScopeCheck, schema.ScopeCheckParams{Target: "jumphost.acme", Protocol: "rdp"})
	var out2 schema.ScopeCheckResult
	_ = json.Unmarshal(res2, &out2)
	if out2.InScope {
		t.Errorf("rdp should be denied: %+v", out2)
	}
	// Out-of-scope host
	res3, _ := ipc.Call(d.SocketPath(), schema.MethodScopeCheck, schema.ScopeCheckParams{Target: "8.8.8.8", Protocol: "ssh"})
	var out3 schema.ScopeCheckResult
	_ = json.Unmarshal(res3, &out3)
	if out3.InScope {
		t.Errorf("8.8.8.8 should be out-of-scope: %+v", out3)
	}
}

// setupClassifyROE creates + loads an engagement and applies an ROE with
// the given write_actions policy. Returns the daemon for subsequent calls.
func setupClassifyROE(t *testing.T, policy string) *Daemon {
	t.Helper()
	d, mgr := newTestDaemon(t)
	id := "cl-" + policy
	if policy == "" {
		id = "cl-default"
	}
	if _, err := mgr.Create(engagement.CreateParams{ID: id, ClientName: "C", AssessmentType: "t"}); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Load(id); err != nil {
		t.Fatal(err)
	}
	roeYAML := fmt.Sprintf(`engagement_id: %s
version: 1
in_scope:
  hosts: ["127.0.0.0/8"]
allowed_protocols: [ssh, https]
write_actions:
  policy: %q
`, id, policy)
	if _, err := ipc.Call(d.SocketPath(), schema.MethodEngagementSetROE, schema.EngagementSetROEParams{ID: id, YAML: roeYAML}); err != nil {
		t.Fatal(err)
	}
	return d
}

func classify(t *testing.T, d *Daemon, tool string, toolInput string) schema.ClassifyResult {
	t.Helper()
	res, err := ipc.Call(d.SocketPath(), schema.MethodApprovalClassify, schema.ClassifyParams{
		ToolName:  tool,
		ToolInput: json.RawMessage(toolInput),
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	var out schema.ClassifyResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDaemon_ApprovalClassify_WritePolicyAlwaysApproves(t *testing.T) {
	t.Parallel()
	d := setupClassifyROE(t, schema.WritePolicyAlwaysApprove)
	// Bash "rm -rf" would normally RequiresApproval=true; policy=always flips it.
	out := classify(t, d, "Bash", `{"command":"rm -rf /tmp/x"}`)
	if out.Class != schema.ClassWriteIrreversibl {
		t.Errorf("class = %q, want write_irreversible", out.Class)
	}
	if out.RequiresApproval {
		t.Errorf("RequiresApproval=true despite policy=always: %+v", out)
	}
	if out.Blocked {
		t.Errorf("Blocked=true despite policy=always: %+v", out)
	}
}

func TestDaemon_ApprovalClassify_WritePolicyRequireApproval(t *testing.T) {
	t.Parallel()
	d := setupClassifyROE(t, schema.WritePolicyRequireApproval)
	out := classify(t, d, "Bash", `{"command":"rm -rf /tmp/x"}`)
	if !out.RequiresApproval {
		t.Errorf("expected require_approval, got %+v", out)
	}
	if out.Blocked {
		t.Errorf("Blocked=true despite policy=require_approval: %+v", out)
	}
}

func TestDaemon_ApprovalClassify_WritePolicyNeverBlocks(t *testing.T) {
	t.Parallel()
	d := setupClassifyROE(t, schema.WritePolicyNever)
	out := classify(t, d, "Bash", `{"command":"rm -rf /tmp/x"}`)
	if !out.Blocked {
		t.Errorf("expected Blocked=true for policy=never, got %+v", out)
	}
	// RequiresApproval should also be true — fail-closed for hook libs that
	// don't yet read the Blocked flag.
	if !out.RequiresApproval {
		t.Errorf("expected RequiresApproval=true alongside Blocked: %+v", out)
	}
}

func TestDaemon_ApprovalClassify_ReadsUnaffectedByPolicy(t *testing.T) {
	t.Parallel()
	// A read-class action must never require approval regardless of policy.
	for _, policy := range []string{schema.WritePolicyAlwaysApprove, schema.WritePolicyRequireApproval, schema.WritePolicyNever} {
		policy := policy
		t.Run(policy, func(t *testing.T) {
			t.Parallel()
			d := setupClassifyROE(t, policy)
			out := classify(t, d, "Read", `{"file_path":"/tmp/x"}`)
			if out.RequiresApproval || out.Blocked {
				t.Errorf("policy=%s: read should be free, got %+v", policy, out)
			}
		})
	}
}

func TestDaemon_ApprovalClassify_NoROE_UsesClassifierDefault(t *testing.T) {
	t.Parallel()
	// Without an ROE, there's no policy to apply — the classifier's own
	// RequiresApproval wins.
	d, mgr := newTestDaemon(t)
	if _, err := mgr.Create(engagement.CreateParams{ID: "cl-noroe", ClientName: "C", AssessmentType: "t"}); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Load("cl-noroe"); err != nil {
		t.Fatal(err)
	}
	out := classify(t, d, "Bash", `{"command":"rm -rf /tmp/x"}`)
	if !out.RequiresApproval {
		t.Errorf("expected classifier default RequiresApproval=true, got %+v", out)
	}
	if out.Blocked {
		t.Errorf("no ROE, no block: %+v", out)
	}
}

func TestDaemon_TransportLifecycle(t *testing.T) {
	t.Parallel()
	d, _ := newTestDaemon(t)

	// Initially no transport.
	res, _ := ipc.Call(d.SocketPath(), schema.MethodTransportStatus, nil)
	var out schema.TransportStatusResult
	_ = json.Unmarshal(res, &out)
	if out.Status.State != "down" {
		t.Errorf("initial state = %s, want down", out.Status.State)
	}

	// Bring direct up.
	res2, err := ipc.Call(d.SocketPath(), schema.MethodTransportUp, schema.TransportUpParams{Kind: "direct"})
	if err != nil {
		t.Fatal(err)
	}
	var out2 schema.TransportStatusResult
	_ = json.Unmarshal(res2, &out2)
	if out2.Status.Kind != "direct" || out2.Status.State != "up" {
		t.Errorf("up result: %+v", out2.Status)
	}

	// Bring it back down.
	res3, err := ipc.Call(d.SocketPath(), schema.MethodTransportDown, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out3 schema.TransportStatusResult
	_ = json.Unmarshal(res3, &out3)
	if out3.Status.State != "down" {
		t.Errorf("down result: %+v", out3.Status)
	}
}

func TestDaemon_EvidenceTag_MergesAndPersists(t *testing.T) {
	t.Parallel()
	d, mgr := newTestDaemon(t)
	if _, err := mgr.Create(engagement.CreateParams{ID: "e1", ClientName: "C", AssessmentType: "t"}); err != nil {
		t.Fatal(err)
	}
	active, err := mgr.Load("e1")
	if err != nil {
		t.Fatal(err)
	}
	// Seed one evidence item through the vault directly — shortcut to avoid
	// routing through files.store_synthesized, which is tested elsewhere.
	hash, err := active.Vault.Put([]byte("raw evidence"), vault.Metadata{
		ContentType: "text/plain",
		Tags:        []string{"interview"},
	})
	if err != nil {
		t.Fatalf("seed put: %v", err)
	}

	res, err := ipc.Call(d.SocketPath(), schema.MethodEvidenceTag, schema.EvidenceTagParams{
		EvidenceID: hash,
		Tags:       []string{"critical", "interview"}, // "interview" already present → dedup
	})
	if err != nil {
		t.Fatalf("evidence.tag: %v", err)
	}
	var out schema.EvidenceTagResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatal(err)
	}
	if !out.OK {
		t.Errorf("OK=false")
	}
	if len(out.Tags) != 2 || out.Tags[0] != "interview" || out.Tags[1] != "critical" {
		t.Errorf("tags = %v, want [interview critical]", out.Tags)
	}

	// Verify persistence via evidence.search on the new tag.
	sres, err := ipc.Call(d.SocketPath(), schema.MethodEvidenceSearch, schema.EvidenceSearchParams{Tag: "critical"})
	if err != nil {
		t.Fatalf("evidence.search: %v", err)
	}
	var sout schema.EvidenceSearchResult
	_ = json.Unmarshal(sres, &sout)
	if len(sout.Items) != 1 || sout.Items[0].EvidenceID != hash {
		t.Errorf("search did not return tagged item: %+v", sout.Items)
	}
}

func TestDaemon_EvidenceTag_NotFound(t *testing.T) {
	t.Parallel()
	d, mgr := newTestDaemon(t)
	if _, err := mgr.Create(engagement.CreateParams{ID: "e2", ClientName: "C", AssessmentType: "t"}); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Load("e2"); err != nil {
		t.Fatal(err)
	}
	bogus := strings.Repeat("0", 64)
	_, err := ipc.Call(d.SocketPath(), schema.MethodEvidenceTag, schema.EvidenceTagParams{
		EvidenceID: bogus,
		Tags:       []string{"x"},
	})
	if err == nil {
		t.Fatalf("expected error for missing evidence")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention not-found: %v", err)
	}
}

// Satisfy imports we want to keep even if compilation trims unused references
// in future refactors.
var _ io.Reader = (*os.File)(nil)
var _ = fmt.Sprintf
