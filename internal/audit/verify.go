package audit

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"

	"github.com/fsc/telepath-core/pkg/schema"
)

// VerifyResult summarizes what Verify found.
type VerifyResult struct {
	TotalEvents     uint64
	CheckpointCount uint64
	Issues          []Issue // empty when the log is intact
}

// Issue is one problem detected during verification.
type Issue struct {
	Sequence uint64
	Kind     string // parse | sequence_gap | prev_hash | hash | signature | payload
	Detail   string
}

// OK reports whether no issues were found.
func (r *VerifyResult) OK() bool { return len(r.Issues) == 0 }

// Verify re-computes the hash chain over r and validates checkpoint
// signatures against pubKey. It never stops at the first problem — a full
// report of issues is collected so operators can see the whole picture.
//
// If the stream itself becomes unreadable (I/O error), a non-nil error is
// returned along with any partial result.
func Verify(r io.Reader, engagementID string, pubKey ed25519.PublicKey) (*VerifyResult, error) {
	res := &VerifyResult{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	expectedSeq := uint64(0)
	expectedPrev := schema.GenesisPrevHash(engagementID)
	hashBySeq := map[uint64]schema.HexBytes{}

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e schema.AuditEvent
		if err := json.Unmarshal(line, &e); err != nil {
			res.Issues = append(res.Issues, Issue{
				Sequence: expectedSeq + 1,
				Kind:     "parse",
				Detail:   err.Error(),
			})
			// Can't verify further from here.
			return res, nil
		}
		expectedSeq++
		if e.Sequence != expectedSeq {
			res.Issues = append(res.Issues, Issue{
				Sequence: e.Sequence,
				Kind:     "sequence_gap",
				Detail:   fmt.Sprintf("expected %d, got %d", expectedSeq, e.Sequence),
			})
			// Continue with the observed sequence so we can still check hash
			// linkage for subsequent events.
			expectedSeq = e.Sequence
		}
		if !bytes.Equal(e.PreviousHash, expectedPrev) {
			res.Issues = append(res.Issues, Issue{
				Sequence: e.Sequence,
				Kind:     "prev_hash",
				Detail:   fmt.Sprintf("expected %s, got %s", expectedPrev, e.PreviousHash),
			})
		}
		hash, err := e.ComputeHash()
		if err != nil {
			res.Issues = append(res.Issues, Issue{
				Sequence: e.Sequence,
				Kind:     "hash",
				Detail:   err.Error(),
			})
			continue
		}
		if !bytes.Equal(hash, e.Hash) {
			res.Issues = append(res.Issues, Issue{
				Sequence: e.Sequence,
				Kind:     "hash",
				Detail:   fmt.Sprintf("expected %s, got %s", hash, e.Hash),
			})
		}
		hashBySeq[e.Sequence] = e.Hash
		expectedPrev = e.Hash
		res.TotalEvents++

		if e.Type == schema.AuditTypeCheckpoint {
			res.CheckpointCount++
			var cp schema.CheckpointPayload
			if err := json.Unmarshal(e.Payload, &cp); err != nil {
				res.Issues = append(res.Issues, Issue{
					Sequence: e.Sequence,
					Kind:     "payload",
					Detail:   fmt.Sprintf("checkpoint: %v", err),
				})
				continue
			}
			target, ok := hashBySeq[cp.SignedThrough]
			if !ok {
				res.Issues = append(res.Issues, Issue{
					Sequence: e.Sequence,
					Kind:     "signature",
					Detail:   fmt.Sprintf("checkpoint references missing event %d", cp.SignedThrough),
				})
				continue
			}
			if !ed25519.Verify(pubKey, target, cp.Signature) {
				res.Issues = append(res.Issues, Issue{
					Sequence: e.Sequence,
					Kind:     "signature",
					Detail:   fmt.Sprintf("signature over event %d invalid", cp.SignedThrough),
				})
			}
		}
	}
	if err := sc.Err(); err != nil {
		return res, fmt.Errorf("audit: verify scan: %w", err)
	}
	return res, nil
}
