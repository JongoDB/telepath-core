// Package audit implements the append-only, hash-chained, Ed25519-checkpointed
// audit log described in docs/ARCHITECTURE.md §10.
//
// One Log instance per engagement. All appends for an engagement MUST go
// through the same Log; the hash chain depends on a single writer keeping the
// lastHash invariant.
package audit

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsc/telepath-core/pkg/schema"
)

// Default checkpoint thresholds per ARCHITECTURE.md §10.3. Both are
// adjustable via Options for tests and tuning.
const (
	DefaultCheckpointEvery    = uint64(100)
	DefaultCheckpointInterval = 60 * time.Second
)

// Options tune a Log's behavior; all fields are optional.
type Options struct {
	// CheckpointEvery is the event count between auto-inserted checkpoints.
	CheckpointEvery uint64
	// CheckpointInterval is the time-based threshold; a checkpoint is
	// inserted on the next Append after this much time has elapsed since
	// the last checkpoint, provided at least one event was appended in
	// that window (so an idle daemon doesn't churn checkpoints).
	CheckpointInterval time.Duration
	// Clock is an injectable time source for tests. Defaults to time.Now.
	Clock func() time.Time
}

// Log is a handle to an audit JSONL file plus the state needed to append new
// events consistent with the chain.
type Log struct {
	mu sync.Mutex

	path         string
	file         *os.File
	engagementID string
	signer       ed25519.PrivateKey

	lastSeq           uint64
	lastHash          schema.HexBytes
	lastCheckpointSeq uint64
	lastCheckpointAt  time.Time

	checkpointEvery    uint64
	checkpointInterval time.Duration
	now                func() time.Time

	closed bool
}

// Open opens or creates the audit log at path. If the file already contains
// events, they are scanned once to recover sequence and chain state. The
// signer is the operator's Ed25519 key used to sign checkpoint events.
func Open(path, engagementID string, signer ed25519.PrivateKey, opts Options) (*Log, error) {
	if engagementID == "" {
		return nil, errors.New("audit: engagement ID required")
	}
	if len(signer) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("audit: signer must be %d bytes, got %d", ed25519.PrivateKeySize, len(signer))
	}
	if opts.CheckpointEvery == 0 {
		opts.CheckpointEvery = DefaultCheckpointEvery
	}
	if opts.CheckpointInterval == 0 {
		opts.CheckpointInterval = DefaultCheckpointInterval
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit: mkdir: %w", err)
	}

	l := &Log{
		path:               path,
		engagementID:       engagementID,
		signer:             signer,
		checkpointEvery:    opts.CheckpointEvery,
		checkpointInterval: opts.CheckpointInterval,
		now:                opts.Clock,
	}
	if err := l.scan(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open for append: %w", err)
	}
	l.file = f
	return l, nil
}

// scan replays the existing file to recover lastSeq, lastHash, and the last
// checkpoint marker. A missing file means a fresh chain. Returns an error if
// an existing file is malformed.
func (l *Log) scan() error {
	f, err := os.Open(l.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("audit: scan open: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e schema.AuditEvent
		if err := json.Unmarshal(line, &e); err != nil {
			return fmt.Errorf("audit: scan parse at seq=%d: %w", l.lastSeq+1, err)
		}
		if e.Sequence != l.lastSeq+1 {
			return fmt.Errorf("audit: scan sequence gap at %d: saw %d", l.lastSeq+1, e.Sequence)
		}
		l.lastSeq = e.Sequence
		l.lastHash = e.Hash
		if e.Type == schema.AuditTypeCheckpoint {
			l.lastCheckpointSeq = e.Sequence
			l.lastCheckpointAt = e.Timestamp
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("audit: scan: %w", err)
	}
	return nil
}

// Append writes one event and returns it with seq, timestamp, prev_hash, and
// hash filled in. If the append crosses a checkpoint threshold, a checkpoint
// event is appended immediately after and its error is returned as a wrap of
// the originally-appended event — i.e., the caller sees the user-supplied
// event as successfully logged but is told the checkpoint failed.
func (l *Log) Append(e schema.AuditEvent) (schema.AuditEvent, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return schema.AuditEvent{}, errors.New("audit: log closed")
	}
	filled, err := l.appendLocked(e)
	if err != nil {
		return schema.AuditEvent{}, err
	}
	if l.shouldCheckpointLocked(filled) {
		if _, cerr := l.insertCheckpointLocked(); cerr != nil {
			return filled, fmt.Errorf("audit: auto-checkpoint after seq=%d: %w", filled.Sequence, cerr)
		}
	}
	return filled, nil
}

// Checkpoint forces a checkpoint now. Returns the checkpoint event. Returns
// an error if the log has no events to cover.
func (l *Log) Checkpoint() (schema.AuditEvent, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return schema.AuditEvent{}, errors.New("audit: log closed")
	}
	return l.insertCheckpointLocked()
}

// Close flushes, inserts a final checkpoint if uncovered events exist, and
// closes the file. Idempotent.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	if l.lastSeq > 0 && l.lastSeq > l.lastCheckpointSeq {
		if _, err := l.insertCheckpointLocked(); err != nil {
			return fmt.Errorf("audit: final checkpoint: %w", err)
		}
	}
	if l.file != nil {
		if err := l.file.Sync(); err != nil {
			return fmt.Errorf("audit: sync: %w", err)
		}
		if err := l.file.Close(); err != nil {
			return fmt.Errorf("audit: close: %w", err)
		}
	}
	l.closed = true
	return nil
}

// Path returns the log's filesystem path.
func (l *Log) Path() string { return l.path }

// LastSequence returns the sequence number of the most recently appended
// event. Used by tests and diagnostics.
func (l *Log) LastSequence() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastSeq
}

// appendLocked is the shared path for Append and checkpoint insertion. It
// assigns seq, timestamp, prev_hash, computes hash, marshals, and writes.
// Caller holds l.mu.
func (l *Log) appendLocked(e schema.AuditEvent) (schema.AuditEvent, error) {
	l.lastSeq++
	e.Sequence = l.lastSeq
	if e.Timestamp.IsZero() {
		e.Timestamp = l.now().UTC()
	} else {
		e.Timestamp = e.Timestamp.UTC()
	}
	e.EngagementID = l.engagementID
	if l.lastHash == nil {
		e.PreviousHash = schema.GenesisPrevHash(l.engagementID)
	} else {
		e.PreviousHash = l.lastHash
	}
	hash, err := e.ComputeHash()
	if err != nil {
		l.lastSeq--
		return schema.AuditEvent{}, fmt.Errorf("audit: compute hash: %w", err)
	}
	e.Hash = hash
	line, err := json.Marshal(&e)
	if err != nil {
		l.lastSeq--
		return schema.AuditEvent{}, fmt.Errorf("audit: marshal: %w", err)
	}
	line = append(line, '\n')
	if _, err := l.file.Write(line); err != nil {
		l.lastSeq--
		return schema.AuditEvent{}, fmt.Errorf("audit: write: %w", err)
	}
	l.lastHash = e.Hash
	return e, nil
}

// shouldCheckpointLocked returns true if the just-appended event crossed a
// checkpoint threshold. Never fires for checkpoint events themselves (avoids
// recursion).
func (l *Log) shouldCheckpointLocked(last schema.AuditEvent) bool {
	if last.Type == schema.AuditTypeCheckpoint {
		return false
	}
	since := last.Sequence - l.lastCheckpointSeq
	if since >= l.checkpointEvery {
		return true
	}
	if !l.lastCheckpointAt.IsZero() && since >= 1 {
		if l.now().Sub(l.lastCheckpointAt) >= l.checkpointInterval {
			return true
		}
	}
	return false
}

// insertCheckpointLocked appends a checkpoint event that signs the hash of
// the most recent event. Caller holds l.mu.
func (l *Log) insertCheckpointLocked() (schema.AuditEvent, error) {
	if l.lastSeq == 0 {
		return schema.AuditEvent{}, errors.New("audit: cannot checkpoint empty log")
	}
	sig := ed25519.Sign(l.signer, l.lastHash)
	payload, err := json.Marshal(schema.CheckpointPayload{
		SignedThrough: l.lastSeq,
		Signature:     sig,
	})
	if err != nil {
		return schema.AuditEvent{}, fmt.Errorf("audit: marshal checkpoint payload: %w", err)
	}
	cp := schema.AuditEvent{
		Type:    schema.AuditTypeCheckpoint,
		Actor:   schema.ActorTelepath,
		Payload: payload,
	}
	filled, err := l.appendLocked(cp)
	if err != nil {
		return schema.AuditEvent{}, err
	}
	l.lastCheckpointSeq = filled.Sequence
	l.lastCheckpointAt = filled.Timestamp
	return filled, nil
}
