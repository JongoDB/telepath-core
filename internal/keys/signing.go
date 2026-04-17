package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
)

// Store name for the operator's long-lived Ed25519 signing key. This key
// signs audit-checkpoint events for every engagement the operator runs.
const operatorSigningKeyName = "operator.signing-key"

// GetOrCreateSigningKey returns the operator's Ed25519 private key from the
// Store, generating and persisting a new seed if none exists. Only the 32-byte
// seed is stored; the full 64-byte private key is derived on each load.
func GetOrCreateSigningKey(s Store) (ed25519.PrivateKey, error) {
	seed, err := s.Get(operatorSigningKeyName)
	switch {
	case err == nil:
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("keys: stored signing seed is %d bytes, want %d", len(seed), ed25519.SeedSize)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	case errors.Is(err, ErrNotFound):
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, fmt.Errorf("keys: generate signing seed: %w", err)
		}
		if err := s.Set(operatorSigningKeyName, seed); err != nil {
			return nil, fmt.Errorf("keys: persist signing seed: %w", err)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	default:
		return nil, fmt.Errorf("keys: read signing seed: %w", err)
	}
}

// PublicKey returns the public half of the operator's signing key.
func PublicKey(priv ed25519.PrivateKey) ed25519.PublicKey {
	return priv.Public().(ed25519.PublicKey)
}

// EngagementKeyName returns the Store name for an engagement's symmetric key.
// Keys are 32 bytes, used as AES-256-GCM keys for the evidence vault and the
// credential vault.
func EngagementKeyName(engagementID string) string {
	return "engagement." + engagementID + ".key"
}

// NewEngagementKey generates a fresh 32-byte key, persists it under the
// engagement's slot, and returns it.
func NewEngagementKey(s Store, engagementID string) ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("keys: generate engagement key: %w", err)
	}
	if err := s.Set(EngagementKeyName(engagementID), key); err != nil {
		return nil, fmt.Errorf("keys: persist engagement key: %w", err)
	}
	return key, nil
}

// GetEngagementKey fetches the stored key for an engagement.
func GetEngagementKey(s Store, engagementID string) ([]byte, error) {
	return s.Get(EngagementKeyName(engagementID))
}

// DeleteEngagementKey removes an engagement's key. Evidence encrypted with it
// becomes permanently unreadable — this is the basis of engagement sealing.
func DeleteEngagementKey(s Store, engagementID string) error {
	return s.Delete(EngagementKeyName(engagementID))
}
