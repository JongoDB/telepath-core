package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsc/telepath-core/pkg/schema"
)

func makeSigner(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv
}

func openFreshLog(t *testing.T, dir string, signer ed25519.PrivateKey, every uint64) *Log {
	t.Helper()
	l, err := Open(filepath.Join(dir, "audit.jsonl"), "eng-test", signer, Options{
		CheckpointEvery: every,
		Clock:           func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return l
}

func TestLog_AppendAndVerify(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	signer := makeSigner(t)

	l := openFreshLog(t, dir, signer, 1000) // no auto-checkpoint
	for i := 0; i < 5; i++ {
		payload, _ := json.Marshal(map[string]any{"step": i})
		if _, err := l.Append(schema.AuditEvent{
			Type:    schema.AuditTypeMCPCall,
			Actor:   schema.ActorClaudeCode,
			Payload: payload,
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	f, err := os.Open(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	res, err := Verify(f, "eng-test", signer.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	// 5 mcp_call events + 1 final checkpoint from Close()
	if res.TotalEvents != 6 {
		t.Errorf("events = %d, want 6", res.TotalEvents)
	}
	if res.CheckpointCount != 1 {
		t.Errorf("checkpoints = %d, want 1", res.CheckpointCount)
	}
	if !res.OK() {
		t.Errorf("verify failed: %+v", res.Issues)
	}
}

func TestLog_AutoCheckpoint(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	signer := makeSigner(t)

	l := openFreshLog(t, dir, signer, 3) // checkpoint every 3 events
	for i := 0; i < 7; i++ {
		if _, err := l.Append(schema.AuditEvent{
			Type:  schema.AuditTypeHookFired,
			Actor: schema.ActorHookHandler,
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	f, err := os.Open(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	res, err := Verify(f, "eng-test", signer.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK() {
		t.Errorf("verify issues: %+v", res.Issues)
	}
	// 7 user events + 2 auto (after 3rd and 6th) + 1 final = 10 total events; 3 checkpoints.
	if res.TotalEvents != 10 {
		t.Errorf("events = %d, want 10", res.TotalEvents)
	}
	if res.CheckpointCount != 3 {
		t.Errorf("checkpoints = %d, want 3", res.CheckpointCount)
	}
}

func TestLog_ResumeAcrossOpen(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	signer := makeSigner(t)

	l1 := openFreshLog(t, dir, signer, 1000)
	for i := 0; i < 3; i++ {
		if _, err := l1.Append(schema.AuditEvent{Type: schema.AuditTypeMCPCall}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l1.Close(); err != nil {
		t.Fatal(err)
	}

	l2 := openFreshLog(t, dir, signer, 1000)
	if got := l2.LastSequence(); got != 4 {
		// 3 events + 1 final checkpoint from l1.Close()
		t.Fatalf("resume LastSequence = %d, want 4", got)
	}
	if _, err := l2.Append(schema.AuditEvent{Type: schema.AuditTypeMCPCall}); err != nil {
		t.Fatal(err)
	}
	if err := l2.Close(); err != nil {
		t.Fatal(err)
	}

	f, _ := os.Open(filepath.Join(dir, "audit.jsonl"))
	defer f.Close()
	res, err := Verify(f, "eng-test", signer.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Errorf("verify issues: %+v", res.Issues)
	}
}

func TestVerify_DetectsTamperedHash(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	signer := makeSigner(t)

	l := openFreshLog(t, dir, signer, 1000)
	for i := 0; i < 3; i++ {
		if _, err := l.Append(schema.AuditEvent{
			Type:    schema.AuditTypeMCPCall,
			Payload: json.RawMessage(fmt.Sprintf(`{"i":%d}`, i)),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "audit.jsonl")
	raw, _ := os.ReadFile(path)

	// Swap one byte in the middle of an event's payload section; the stored
	// hash won't match the recomputed one, AND prev_hash on the next event
	// won't match the mutated hash either.
	mutated := bytes.Replace(raw, []byte(schema.AuditTypeMCPCall), []byte("Xcp_call_tampered"), 1)
	tmp := path + ".tamp"
	if err := os.WriteFile(tmp, mutated, 0o600); err != nil {
		t.Fatal(err)
	}

	f, _ := os.Open(tmp)
	defer f.Close()
	res, err := Verify(f, "eng-test", signer.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Errorf("expected tamper to produce issues, got clean verify")
	}
}

func TestVerify_DetectsBadSignature(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	signer := makeSigner(t)

	l := openFreshLog(t, dir, signer, 1000)
	for i := 0; i < 3; i++ {
		if _, err := l.Append(schema.AuditEvent{Type: schema.AuditTypeMCPCall}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	// Verify against a different public key; the checkpoint signature must fail.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	f, _ := os.Open(filepath.Join(dir, "audit.jsonl"))
	defer f.Close()
	res, err := Verify(f, "eng-test", other.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	sigIssues := 0
	for _, iss := range res.Issues {
		if iss.Kind == "signature" {
			sigIssues++
		}
	}
	if sigIssues == 0 {
		t.Fatalf("expected signature issue with wrong key, got: %+v", res.Issues)
	}
}

func TestLog_CloseEmptyNoError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	signer := makeSigner(t)
	l := openFreshLog(t, dir, signer, 1000)
	if err := l.Close(); err != nil {
		t.Fatalf("close empty: %v", err)
	}
	// Second close is a no-op.
	if err := l.Close(); err != nil {
		t.Fatalf("close twice: %v", err)
	}
}
