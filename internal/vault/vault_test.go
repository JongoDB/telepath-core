package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makeKey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

func TestVault_AddTags_MergesAndDedups(t *testing.T) {
	t.Parallel()
	v, err := Open(t.TempDir(), makeKey(7))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := v.Put([]byte("payload"), Metadata{Tags: []string{"interview", "config"}})
	if err != nil {
		t.Fatal(err)
	}

	got, err := v.AddTags(hash, []string{"critical", "interview", "  ", "escalation"})
	if err != nil {
		t.Fatalf("AddTags: %v", err)
	}
	want := []string{"interview", "config", "critical", "escalation"}
	if len(got) != len(want) {
		t.Fatalf("tags = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("tags[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// Second call is a no-op when all tags already present.
	again, err := v.AddTags(hash, []string{"interview"})
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != len(want) {
		t.Errorf("duplicate-only call changed tag count: %v", again)
	}

	// Persistence check via Get.
	_, meta, err := v.Get(hash)
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.Tags) != len(want) {
		t.Errorf("persisted tags = %v, want %v", meta.Tags, want)
	}
}

func TestVault_AddTags_NotFound(t *testing.T) {
	t.Parallel()
	v, err := Open(t.TempDir(), makeKey(8))
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.AddTags("0000000000000000000000000000000000000000000000000000000000000000", []string{"x"})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestVault_PutGet(t *testing.T) {
	t.Parallel()
	v, err := Open(t.TempDir(), makeKey(1))
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("the quick brown fox")
	hash, err := v.Put(content, Metadata{
		ContentType: "text/plain",
		Skill:       "ai-opportunity-discovery",
		Target:      "jumphost.acme",
	})
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(content)
	if hash != hex.EncodeToString(expected[:]) {
		t.Errorf("hash mismatch: %s", hash)
	}

	got, meta, err := v.Get(hash)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("content mismatch")
	}
	if meta.Size != int64(len(content)) {
		t.Errorf("meta size = %d", meta.Size)
	}
	if meta.ContentType != "text/plain" {
		t.Errorf("content_type = %q", meta.ContentType)
	}
}

func TestVault_Idempotent(t *testing.T) {
	t.Parallel()
	v, _ := Open(t.TempDir(), makeKey(2))
	h1, _ := v.Put([]byte("x"), Metadata{Target: "h1"})
	h2, _ := v.Put([]byte("x"), Metadata{Target: "h2"})
	if h1 != h2 {
		t.Errorf("same content must map to same hash")
	}
	// Meta reflects the last write.
	_, meta, _ := v.Get(h1)
	if meta.Target != "h2" {
		t.Errorf("meta = %q, want h2 (last write)", meta.Target)
	}
}

func TestVault_GetMissing(t *testing.T) {
	t.Parallel()
	v, _ := Open(t.TempDir(), makeKey(3))
	_, _, err := v.Get("0000000000000000000000000000000000000000000000000000000000000000")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestVault_WrongKeyCannotDecrypt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	v1, _ := Open(dir, makeKey(4))
	hash, _ := v1.Put([]byte("secret stuff"), Metadata{})
	// Reopen with a different key.
	v2, _ := Open(dir, makeKey(5))
	_, _, err := v2.Get(hash)
	if err == nil {
		t.Fatalf("decrypt with wrong key must fail")
	}
}

func TestVault_List(t *testing.T) {
	t.Parallel()
	v, _ := Open(t.TempDir(), makeKey(6))
	for i := 0; i < 3; i++ {
		_, err := v.Put([]byte{byte(i)}, Metadata{Tags: []string{"t1"}})
		if err != nil {
			t.Fatal(err)
		}
	}
	list, err := v.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Errorf("got %d items, want 3", len(list))
	}
}

func TestVault_SearchByTag(t *testing.T) {
	t.Parallel()
	v, _ := Open(t.TempDir(), makeKey(7))
	_, _ = v.Put([]byte("a"), Metadata{Tags: []string{"interview"}})
	_, _ = v.Put([]byte("b"), Metadata{Tags: []string{"config"}})
	_, _ = v.Put([]byte("c"), Metadata{Tags: []string{"interview", "critical"}})

	res, err := v.Search(Filter{Tag: "interview"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Errorf("expected 2 interview items, got %d", len(res))
	}
}

func TestVault_SearchByTime(t *testing.T) {
	t.Parallel()
	v, _ := Open(t.TempDir(), makeKey(8))
	past := time.Now().Add(-1 * time.Hour)
	future := time.Now().Add(1 * time.Hour)
	_, _ = v.Put([]byte("old"), Metadata{CollectedAt: past})
	_, _ = v.Put([]byte("new"), Metadata{})
	res, _ := v.Search(Filter{Since: future})
	if len(res) != 0 {
		t.Errorf("Since-in-future should match 0, got %d", len(res))
	}
	res2, _ := v.Search(Filter{Since: past.Add(-1 * time.Second)})
	if len(res2) != 2 {
		t.Errorf("expected both items when Since is before all, got %d", len(res2))
	}
}

func TestVault_KeyWrongSize(t *testing.T) {
	t.Parallel()
	if _, err := Open(t.TempDir(), []byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for wrong key size")
	}
}

func TestVault_FilesystemLayout(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	v, _ := Open(dir, makeKey(9))
	hash, _ := v.Put([]byte("probe"), Metadata{})
	for _, suffix := range []string{".enc", ".meta.json"} {
		p := filepath.Join(dir, hash[:2], hash+suffix)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("missing %s: %v", p, err)
		}
	}
}

func TestVault_TamperAAD(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	v, _ := Open(dir, makeKey(10))
	hash, _ := v.Put([]byte("payload"), Metadata{})
	// Corrupt one byte of the ciphertext. AEAD should fail.
	path := filepath.Join(dir, hash[:2], hash+".enc")
	data, _ := os.ReadFile(path)
	data[len(data)-1] ^= 0x01
	_ = os.WriteFile(path, data, 0o600)
	_, _, err := v.Get(hash)
	if err == nil {
		t.Fatal("AEAD should reject tampered ciphertext")
	}
}
