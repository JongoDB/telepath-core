// Package vault is the content-addressed, AES-256-GCM encrypted evidence
// store. One Vault per engagement, rooted at <engagement>/vault/. File
// layout matches ARCHITECTURE.md §11 — <sha[:2]>/<sha>.enc holds the
// ciphertext, <sha[:2]>/<sha>.meta.json holds the metadata.
//
// The encryption key is the engagement's symmetric key retrieved from the
// keystore. Losing the key loses the evidence, by design; that's the basis
// of engagement sealing in later milestones.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Metadata describes one piece of evidence. Mirrors EvidenceItem in
// docs/ARCHITECTURE.md §4.3; we keep it JSON-serializable for the side-car
// .meta.json files.
type Metadata struct {
	SHA256      string    `json:"sha256"`
	ContentType string    `json:"content_type"`
	Size        int64     `json:"size"`
	CollectedAt time.Time `json:"collected_at"`
	SessionID   string    `json:"session_id,omitempty"`
	Target      string    `json:"target,omitempty"`
	Command     string    `json:"command,omitempty"`
	Skill       string    `json:"skill,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	// CollectionContext is a free-form string (e.g., "workflow-observation
	// interview with Sarah") — useful for dedup-aware provenance when the
	// same file is collected multiple times.
	CollectionContext string `json:"collection_context,omitempty"`
}

// Vault is the handle.
type Vault struct {
	mu  sync.Mutex
	dir string
	key []byte // 32-byte AES-256 key
	now func() time.Time
}

// Open returns a Vault rooted at dir, using key for AES-256-GCM encryption.
// The directory is created if absent.
func Open(dir string, key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("vault: key must be 32 bytes, got %d", len(key))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("vault: mkdir %s: %w", dir, err)
	}
	return &Vault{dir: dir, key: key, now: func() time.Time { return time.Now().UTC() }}, nil
}

// Put writes content + metadata and returns the content hash. Metadata
// Size and SHA256 fields are overwritten; CollectedAt defaults to now
// when zero. Idempotent: writing the same content twice updates metadata
// but the ciphertext stays intact.
func (v *Vault) Put(content []byte, meta Metadata) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	sum := sha256.Sum256(content)
	hashStr := hex.EncodeToString(sum[:])
	meta.SHA256 = hashStr
	meta.Size = int64(len(content))
	if meta.CollectedAt.IsZero() {
		meta.CollectedAt = v.now()
	}

	encPath := v.encPath(hashStr)
	metaPath := v.metaPath(hashStr)
	if err := os.MkdirAll(filepath.Dir(encPath), 0o700); err != nil {
		return "", fmt.Errorf("vault: mkdir shard: %w", err)
	}

	// Encrypt.
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return "", fmt.Errorf("vault: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("vault: gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("vault: nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, content, []byte(hashStr))
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)

	// Atomic writes.
	if err := writeAtomic(encPath, out, 0o600); err != nil {
		return "", err
	}
	mBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return "", fmt.Errorf("vault: marshal meta: %w", err)
	}
	if err := writeAtomic(metaPath, mBytes, 0o600); err != nil {
		return "", err
	}
	return hashStr, nil
}

// Get returns the content and metadata for a hash. Returns ErrNotFound if
// no item exists.
func (v *Vault) Get(hash string) ([]byte, Metadata, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	encPath := v.encPath(hash)
	raw, err := os.ReadFile(encPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, Metadata{}, ErrNotFound
		}
		return nil, Metadata{}, fmt.Errorf("vault: read ct: %w", err)
	}
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, Metadata{}, fmt.Errorf("vault: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, Metadata{}, fmt.Errorf("vault: gcm: %w", err)
	}
	ns := gcm.NonceSize()
	if len(raw) < ns+gcm.Overhead() {
		return nil, Metadata{}, fmt.Errorf("vault: ciphertext too short")
	}
	pt, err := gcm.Open(nil, raw[:ns], raw[ns:], []byte(hash))
	if err != nil {
		return nil, Metadata{}, fmt.Errorf("vault: decrypt: %w", err)
	}

	meta, err := v.readMeta(hash)
	if err != nil {
		return nil, Metadata{}, err
	}
	return pt, meta, nil
}

// List returns metadata for every item in the vault. Order is lexicographic
// by hash to keep test assertions deterministic.
func (v *Vault) List() ([]Metadata, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	var out []Metadata
	err := filepath.WalkDir(v.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".meta.json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var m Metadata
		if err := json.Unmarshal(data, &m); err != nil {
			// Skip corrupt metadata silently; the .enc is still intact.
			return nil
		}
		out = append(out, m)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SHA256 < out[j].SHA256 })
	return out, nil
}

// Filter narrows a list by tag/skill/session/time. Empty fields match all.
type Filter struct {
	Tag       string
	Skill     string
	SessionID string
	Since     time.Time
	Target    string
}

// Search lists metadata that matches the filter. Currently linear; a SQLite
// index comes with the findings store in week 4.
func (v *Vault) Search(f Filter) ([]Metadata, error) {
	all, err := v.List()
	if err != nil {
		return nil, err
	}
	var out []Metadata
	for _, m := range all {
		if f.Tag != "" && !contains(m.Tags, f.Tag) {
			continue
		}
		if f.Skill != "" && m.Skill != f.Skill {
			continue
		}
		if f.SessionID != "" && m.SessionID != f.SessionID {
			continue
		}
		if !f.Since.IsZero() && m.CollectedAt.Before(f.Since) {
			continue
		}
		if f.Target != "" && !strings.Contains(m.Target, f.Target) {
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

// AddTags merges tags into the metadata for the given hash and returns the
// resulting tag set. Existing tags are preserved; new tags are appended in
// order and deduplicated. Returns ErrNotFound when no item exists.
//
// The ciphertext is untouched — only the side-car .meta.json is rewritten.
// Atomic via the same temp-file + rename pattern as Put.
func (v *Vault) AddTags(hash string, tags []string) ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	meta, err := v.readMeta(hash)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(meta.Tags)+len(tags))
	merged := make([]string, 0, len(meta.Tags)+len(tags))
	for _, t := range meta.Tags {
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		merged = append(merged, t)
	}
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		merged = append(merged, t)
	}
	meta.Tags = merged

	mBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("vault: marshal meta: %w", err)
	}
	if err := writeAtomic(v.metaPath(hash), mBytes, 0o600); err != nil {
		return nil, err
	}
	return merged, nil
}

// ErrNotFound is returned by Get when the hash is absent.
var ErrNotFound = errors.New("vault: not found")

// --- helpers ---

func (v *Vault) encPath(hash string) string {
	return filepath.Join(v.dir, hash[:2], hash+".enc")
}
func (v *Vault) metaPath(hash string) string {
	return filepath.Join(v.dir, hash[:2], hash+".meta.json")
}

func (v *Vault) readMeta(hash string) (Metadata, error) {
	data, err := os.ReadFile(v.metaPath(hash))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Metadata{}, ErrNotFound
		}
		return Metadata{}, err
	}
	var m Metadata
	if err := json.Unmarshal(data, &m); err != nil {
		return Metadata{}, fmt.Errorf("vault: parse meta %s: %w", hash, err)
	}
	return m, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return fmt.Errorf("vault: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("vault: rename %s: %w", path, err)
	}
	return nil
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
