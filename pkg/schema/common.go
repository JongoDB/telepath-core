// Package schema holds the public data types telepath-core exposes over its
// socket, in files it writes to disk, and in the audit log. Types here are the
// wire contract; changes are visible to the plugin, the Python hook library,
// and standalone verifiers.
package schema

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// HexBytes is a raw byte slice that marshals to and from a hex string in JSON.
// Used for hashes and signatures so the audit log stays human-inspectable.
type HexBytes []byte

// MarshalJSON encodes the bytes as a lowercase hex string. A nil or empty
// value becomes JSON null.
func (h HexBytes) MarshalJSON() ([]byte, error) {
	if len(h) == 0 {
		return []byte("null"), nil
	}
	dst := make([]byte, hex.EncodedLen(len(h))+2)
	dst[0] = '"'
	hex.Encode(dst[1:], h)
	dst[len(dst)-1] = '"'
	return dst, nil
}

// UnmarshalJSON accepts a hex string or JSON null. Empty string decodes to nil.
func (h *HexBytes) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*h = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("hex bytes: %w", err)
	}
	if s == "" {
		*h = nil
		return nil
	}
	dst := make([]byte, hex.DecodedLen(len(s)))
	n, err := hex.Decode(dst, []byte(s))
	if err != nil {
		return fmt.Errorf("hex bytes: invalid encoding: %w", err)
	}
	*h = dst[:n]
	return nil
}

// String returns the hex encoding. Never panics.
func (h HexBytes) String() string {
	return hex.EncodeToString(h)
}
