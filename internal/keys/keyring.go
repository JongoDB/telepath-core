package keys

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
)

const (
	// Service namespace used with the OS keychain. Per-OS semantics:
	//   - macOS: Keychain service attribute
	//   - Windows: Credential target prefix
	//   - Linux (Secret Service): collection attribute
	keyringService = "telepath"

	// Separate service for the backend-liveness probe so real keys never
	// collide with probe entries.
	keyringProbeService = "telepath-probe"
)

type keyringStore struct{}

// newKeyringStore returns a keyringStore if and only if the OS keychain is
// actually reachable. We verify this by writing and deleting a probe entry;
// many Linux containers present a keyring API that fails at call time rather
// than at init, so a probe is the only reliable way to know.
func newKeyringStore() (*keyringStore, error) {
	if err := keyring.Set(keyringProbeService, "probe", "ok"); err != nil {
		return nil, fmt.Errorf("keyring probe: %w", err)
	}
	_ = keyring.Delete(keyringProbeService, "probe")
	return &keyringStore{}, nil
}

func (s *keyringStore) Backend() string { return "os" }

func (s *keyringStore) Get(name string) ([]byte, error) {
	v, err := keyring.Get(keyringService, name)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("keyring get %q: %w", name, err)
	}
	out, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("keyring get %q: value not base64: %w", name, err)
	}
	return out, nil
}

func (s *keyringStore) Set(name string, value []byte) error {
	enc := base64.StdEncoding.EncodeToString(value)
	if err := keyring.Set(keyringService, name, enc); err != nil {
		return fmt.Errorf("keyring set %q: %w", name, err)
	}
	return nil
}

func (s *keyringStore) Delete(name string) error {
	if err := keyring.Delete(keyringService, name); err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("keyring delete %q: %w", name, err)
	}
	return nil
}
