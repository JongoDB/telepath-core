package keys

import (
	"errors"
	"fmt"
	"io"
)

// PurgeTelepathEntries removes every telepath-owned entry from the active
// keystore. Called by `telepath uninstall --purge`. Returns the count of
// entries removed so the caller can tell the operator what happened.
//
// For the file backend, the actual file lives under ~/.telepath and is
// removed by the filesystem wipe step — so PurgeTelepathEntries on the
// file backend is effectively a no-op. For the OS keychain backend, we
// need to enumerate known slot names and Delete each one.
//
// This enumerates the slots we KNOW about (operator signing key, Claude
// auth slots, and engagement keys for the engagement IDs the caller
// supplies). We can't iterate the keychain generically, so entries that
// existed for engagements whose directories are already gone will be
// orphaned — that's a v0.2 hardening item.
func PurgeTelepathEntries(out io.Writer, store Store, engagementIDs []string) int {
	if store.Backend() != "os" {
		return 0
	}
	removed := 0
	candidates := []string{
		operatorSigningKeyName,
		"claude.oauth_token",
		"claude.api_key",
		"claude.subscription_access_token",
		"claude.subscription_refresh_token",
	}
	for _, id := range engagementIDs {
		candidates = append(candidates, EngagementKeyName(id))
	}
	for _, name := range candidates {
		if err := store.Delete(name); err == nil {
			removed++
			if out != nil {
				fmt.Fprintf(out, "removed keystore entry: %s\n", name)
			}
		} else if !errors.Is(err, ErrNotFound) && out != nil {
			fmt.Fprintf(out, "warning: could not remove %s: %v\n", name, err)
		}
	}
	return removed
}
