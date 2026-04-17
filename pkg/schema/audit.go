package schema

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

// Audit event type constants. Keep in sync with docs/ARCHITECTURE.md §10.
const (
	AuditTypeEngagementLifecycle = "engagement_lifecycle"
	AuditTypeSessionIO           = "session_io"
	AuditTypeMCPCall             = "mcp_call"
	AuditTypeScopeCheck          = "scope_check"
	AuditTypeApproval            = "approval"
	AuditTypeHookFired           = "hook_fired"
	AuditTypeCheckpoint          = "audit_checkpoint"
	AuditTypeSessionSummary      = "session_summary"
)

// Actor constants for the Actor field of AuditEvent.
const (
	ActorOperator    = "operator"
	ActorClaudeCode  = "claude-code"
	ActorTelepath    = "telepath-core"
	ActorHookHandler = "hook-handler"
)

// AuditEvent is one entry in the append-only, hash-chained audit log.
//
// Persistence format: one JSON object per line in audit.jsonl. The Hash field
// chains each event to its predecessor; signed checkpoints (see
// CheckpointPayload) are themselves events with Type == AuditTypeCheckpoint
// whose payload carries the Ed25519 signature over a prior event's hash.
type AuditEvent struct {
	Sequence     uint64          `json:"seq"`
	Timestamp    time.Time       `json:"ts"`
	Type         string          `json:"type"`
	EngagementID string          `json:"engagement_id,omitempty"`
	SessionID    string          `json:"session_id,omitempty"`
	Actor        string          `json:"actor,omitempty"`
	Payload      json.RawMessage `json:"payload,omitempty"`
	PreviousHash HexBytes        `json:"prev_hash"`
	Hash         HexBytes        `json:"hash"`
}

// CheckpointPayload is the structured payload of an AuditTypeCheckpoint event.
// The signature is Ed25519 over the hash of the event at sequence SignedThrough.
type CheckpointPayload struct {
	SignedThrough uint64   `json:"signed_through"`
	Signature     HexBytes `json:"signature"`
}

// GenesisPrevHash returns the deterministic prev_hash for event 1 of an
// engagement. Using the engagement ID means two engagements can't share a
// genesis, which would otherwise allow splicing audit logs between them.
func GenesisPrevHash(engagementID string) HexBytes {
	h := sha256.New()
	h.Write([]byte("telepath-audit-v1:"))
	h.Write([]byte(engagementID))
	return h.Sum(nil)
}

// ComputeHash derives the event's Hash from its body and PreviousHash. Callers
// must set PreviousHash before calling; the returned bytes should then be
// stored in Hash. Signature fields and the Hash field itself are excluded
// from the hash input so verification can reconstruct the result.
func (e *AuditEvent) ComputeHash() (HexBytes, error) {
	body, err := canonicalBody(e)
	if err != nil {
		return nil, fmt.Errorf("audit event: canonical body: %w", err)
	}
	sum := sha256.New()
	sum.Write(body)
	sum.Write(e.PreviousHash)
	return sum.Sum(nil), nil
}

// canonicalBody produces the bytes used as hash input. It is the JSON encoding
// of the event with Hash cleared. Go's json encoder emits struct fields in
// declaration order and sorts map keys lexicographically, so the output is
// deterministic for a given event.
func canonicalBody(e *AuditEvent) ([]byte, error) {
	dup := *e
	dup.Hash = nil
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&dup); err != nil {
		return nil, err
	}
	// json.Encoder.Encode appends a trailing newline; trim it so the hash
	// input matches what a verifier reads from the JSONL file (also minus
	// trailing newline, stripped before parsing).
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
