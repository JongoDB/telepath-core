package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// fileStore keeps secrets in a single AES-256-GCM-encrypted JSON file. The
// master key is either a random 32-byte file at <dir>/keystore.key or
// derived by SHA-256 from TELEPATH_KEYSTORE_PASSPHRASE when set.
//
// Concurrency: all operations take a process-local mutex. The on-disk write
// is atomic via write-then-rename, so a crash mid-save leaves either the old
// or new file intact but never a torn blob.
type fileStore struct {
	mu      sync.Mutex
	encPath string
	key     []byte
}

func newFileStore(baseDir string) (*fileStore, error) {
	if baseDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("keys: resolve HOME: %w", err)
		}
		baseDir = filepath.Join(home, ".telepath")
	}
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return nil, fmt.Errorf("keys: mkdir %s: %w", baseDir, err)
	}
	keyPath := filepath.Join(baseDir, "keystore.key")
	encPath := filepath.Join(baseDir, "keystore.enc")
	key, err := loadOrCreateMasterKey(keyPath)
	if err != nil {
		return nil, err
	}
	return &fileStore{encPath: encPath, key: key}, nil
}

// loadOrCreateMasterKey resolves the AES-256 key used to seal the store. If
// TELEPATH_KEYSTORE_PASSPHRASE is set it takes priority — SHA-256 of the
// passphrase is the key. Otherwise a random 32-byte file is created on first
// use at keyPath (mode 0600) and re-read on subsequent calls.
func loadOrCreateMasterKey(keyPath string) ([]byte, error) {
	if pass := os.Getenv("TELEPATH_KEYSTORE_PASSPHRASE"); pass != "" {
		sum := sha256.Sum256([]byte(pass))
		out := make([]byte, len(sum))
		copy(out, sum[:])
		return out, nil
	}
	data, err := os.ReadFile(keyPath)
	if err == nil {
		if len(data) != 32 {
			return nil, fmt.Errorf("keys: master key %s is %d bytes, want 32", keyPath, len(data))
		}
		return data, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("keys: read master key: %w", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("keys: generate master key: %w", err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		return nil, fmt.Errorf("keys: write master key: %w", err)
	}
	return key, nil
}

func (s *fileStore) Backend() string { return "file" }

func (s *fileStore) Get(name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.loadLocked()
	if err != nil {
		return nil, err
	}
	enc, ok := m[name]
	if !ok {
		return nil, ErrNotFound
	}
	out, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, fmt.Errorf("keys: decode %q: %w", name, err)
	}
	return out, nil
}

func (s *fileStore) Set(name string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.loadLocked()
	if err != nil {
		return err
	}
	m[name] = base64.StdEncoding.EncodeToString(value)
	return s.saveLocked(m)
}

func (s *fileStore) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.loadLocked()
	if err != nil {
		return err
	}
	if _, ok := m[name]; !ok {
		return ErrNotFound
	}
	delete(m, name)
	return s.saveLocked(m)
}

// loadLocked decrypts and parses the on-disk blob. Missing file returns an
// empty map. Caller holds s.mu.
func (s *fileStore) loadLocked() (map[string]string, error) {
	data, err := os.ReadFile(s.encPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("keys: read store: %w", err)
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, fmt.Errorf("keys: cipher init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("keys: gcm init: %w", err)
	}
	ns := gcm.NonceSize()
	if len(data) < ns+gcm.Overhead() {
		return nil, fmt.Errorf("keys: store file too short")
	}
	nonce := data[:ns]
	ct := data[ns:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("keys: decrypt store: %w", err)
	}
	var m map[string]string
	if err := json.Unmarshal(pt, &m); err != nil {
		return nil, fmt.Errorf("keys: parse store: %w", err)
	}
	return m, nil
}

// saveLocked encrypts m and atomically writes it to s.encPath. Caller holds
// s.mu.
func (s *fileStore) saveLocked(m map[string]string) error {
	pt, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("keys: marshal store: %w", err)
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return fmt.Errorf("keys: cipher init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("keys: gcm init: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("keys: nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, pt, nil)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)

	tmp := s.encPath + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return fmt.Errorf("keys: write temp store: %w", err)
	}
	if err := os.Rename(tmp, s.encPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("keys: rename store: %w", err)
	}
	return nil
}
