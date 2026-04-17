package keys

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
)

func TestFileStore_RoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, err := newFileStore(dir)
	if err != nil {
		t.Fatalf("newFileStore: %v", err)
	}
	if s.Backend() != "file" {
		t.Fatalf("Backend = %q, want file", s.Backend())
	}

	// Missing key returns ErrNotFound.
	if _, err := s.Get("absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get absent: got %v, want ErrNotFound", err)
	}

	// Set then Get returns the same bytes.
	want := []byte{0xde, 0xad, 0xbe, 0xef}
	if err := s.Set("k1", want); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.Get("k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Get: %x, want %x", got, want)
	}

	// Reopen the store from disk, same key readable.
	s2, err := newFileStore(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got2, err := s2.Get("k1")
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if !bytes.Equal(got2, want) {
		t.Fatalf("Get after reopen: %x, want %x", got2, want)
	}

	// Delete removes it.
	if err := s.Delete("k1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get("k1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after delete: got %v, want ErrNotFound", err)
	}
	if err := s.Delete("k1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete twice: got %v, want ErrNotFound", err)
	}
}

func TestFileStore_TamperDetection(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, err := newFileStore(dir)
	if err != nil {
		t.Fatalf("newFileStore: %v", err)
	}
	if err := s.Set("k", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	// Corrupt the store file and expect Get to fail with a decrypt error.
	encPath := filepath.Join(dir, "keystore.enc")
	data := []byte("not a valid encrypted blob")
	if err := writeFileBytes(encPath, data); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	if _, err := s.Get("k"); err == nil {
		t.Fatalf("expected decrypt error, got nil")
	}
}

func TestFileStore_DifferentKeysDoNotDecrypt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, err := newFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Set("a", []byte{1}); err != nil {
		t.Fatal(err)
	}
	// Rotate the master key underneath the store, simulating tamper/loss.
	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(i)
	}
	if err := writeFileBytes(filepath.Join(dir, "keystore.key"), newKey); err != nil {
		t.Fatal(err)
	}
	s2, err := newFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Get("a"); err == nil {
		t.Fatalf("reading with rotated master key must fail")
	}
}

func TestSigningKey_StableAcrossCalls(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, err := newFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	k1, err := GetOrCreateSigningKey(s)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	k2, err := GetOrCreateSigningKey(s)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatalf("signing key changed between calls")
	}
	// Exercise sign/verify.
	msg := []byte("hello telepath")
	sig := ed25519.Sign(k1, msg)
	if !ed25519.Verify(PublicKey(k1), msg, sig) {
		t.Fatalf("verify failed with own public key")
	}
}

func TestEngagementKey_LifeCycle(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, err := newFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	k1, err := NewEngagementKey(s, "eng-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(k1) != 32 {
		t.Fatalf("engagement key len = %d, want 32", len(k1))
	}
	k2, err := GetEngagementKey(s, "eng-1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatalf("engagement key round-trip mismatch")
	}
	if err := DeleteEngagementKey(s, "eng-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := GetEngagementKey(s, "eng-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: got %v, want ErrNotFound", err)
	}
}

// writeFileBytes writes data to path with 0600 perms, replacing any existing
// file. Used by tests that need to corrupt the store.
func writeFileBytes(path string, data []byte) error {
	return writeFile(path, data)
}
