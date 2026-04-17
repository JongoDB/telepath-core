package keys

import "os"

// writeFile is a tiny test helper: write bytes with 0600 perms.
func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
