// Package keys is telepath-core's secret-storage layer. Secrets live in one
// of two places: the OS keychain (macOS Keychain, Windows Credential Manager,
// Linux Secret Service) or a local AES-256-GCM encrypted file. Callers work
// only with the Store interface; selection is handled by Open.
//
// Backend selection:
//
//	TELEPATH_KEYSTORE_BACKEND=os    — force OS keychain (error if unavailable)
//	TELEPATH_KEYSTORE_BACKEND=file  — force file backend
//	unset (default)                  — try OS keychain; fall back to file if
//	                                   a probe fails (headless Linux, CI)
//
// The file backend reads its base directory from TELEPATH_KEYSTORE_DIR and
// defaults to ~/.telepath. Its master key is kept at <dir>/keystore.key
// (mode 0600) unless TELEPATH_KEYSTORE_PASSPHRASE is set, in which case the
// passphrase is SHA-256'd to derive a master key deterministically.
package keys

import (
	"errors"
	"fmt"
	"os"
)

// ErrNotFound is returned by Store.Get and Store.Delete when a key is absent.
var ErrNotFound = errors.New("keys: not found")

// Store is the minimal secret-storage contract.
type Store interface {
	// Get returns the bytes stored under name. Returns ErrNotFound if the
	// key does not exist. Backends that store strings base64-decode before
	// returning.
	Get(name string) ([]byte, error)

	// Set writes bytes under name, overwriting any existing value. Backends
	// that store strings base64-encode the value first.
	Set(name string, value []byte) error

	// Delete removes the key under name. Returns ErrNotFound if the key
	// does not exist (callers that treat "already gone" as success should
	// check with errors.Is).
	Delete(name string) error

	// Backend reports which implementation is in use ("os" or "file"). Used
	// by doctor and verify-config to explain the environment.
	Backend() string
}

// NewFileStore returns a file-backed Store rooted at dir. Intended for tests
// and for environments where the OS keychain is unavailable (headless Linux,
// CI). Production callers should prefer Open, which picks a backend per
// env vars.
func NewFileStore(dir string) (Store, error) { return newFileStore(dir) }

// Open returns a Store selected per the documented env vars. The returned
// Store is safe for concurrent use.
func Open() (Store, error) {
	backend := os.Getenv("TELEPATH_KEYSTORE_BACKEND")
	switch backend {
	case "os":
		s, err := newKeyringStore()
		if err != nil {
			return nil, fmt.Errorf("keys: OS keychain unavailable: %w", err)
		}
		return s, nil
	case "file":
		return newFileStore(os.Getenv("TELEPATH_KEYSTORE_DIR"))
	case "":
		// Auto: prefer OS; on probe failure, fall back to file.
		if s, err := newKeyringStore(); err == nil {
			return s, nil
		}
		return newFileStore(os.Getenv("TELEPATH_KEYSTORE_DIR"))
	default:
		return nil, fmt.Errorf("keys: unknown TELEPATH_KEYSTORE_BACKEND %q (want os|file)", backend)
	}
}
