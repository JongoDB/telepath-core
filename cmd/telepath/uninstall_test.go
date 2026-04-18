package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestPurgeDoesNotResurrectStateDir is the regression test for the
// purgeState re-creation bug: keys.Open() used to re-run os.MkdirAll on
// ~/.telepath via the file backend AFTER RemoveAll, leaving an empty
// directory behind. The fix is to probe the backend before removing state
// and skip Open() for the file backend entirely. This test drives
// runUninstall(purge=true) against a fake HOME and asserts the state dir
// is gone at the end.
func TestPurgeDoesNotResurrectStateDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uninstall binary-removal path is different on Windows; state-purge behavior is shared but test fixture uses Unix removal")
	}

	// Redirect HOME so the test writes under its own temp dir.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("TELEPATH_KEYSTORE_BACKEND", "file")
	// Keystore dir defaults to $HOME/.telepath when TELEPATH_KEYSTORE_DIR is
	// unset; make sure it IS unset so file-backend opens at ~/.telepath.
	t.Setenv("TELEPATH_KEYSTORE_DIR", "")

	stateDir := filepath.Join(home, ".telepath")
	if err := os.MkdirAll(filepath.Join(stateDir, "engagements", "eng-x"), 0o700); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "config.yaml"), []byte("operator:\n  name: test\n"), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	// The uninstall command discovers the running binary and tries to
	// remove it. We don't actually want to nuke the test process binary,
	// so copy the current executable to a throwaway path and re-exec the
	// runUninstall logic with that as os.Executable would see.
	// Simpler: just invoke runUninstall directly and tolerate the
	// removeBinary step operating on an already-absent file.
	//
	// To keep removeBinary harmless, point the test at a sacrificial
	// binary file under the home.
	fakeBin := filepath.Join(home, "telepath-fake")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Make os.Executable() return our fakeBin. We can't actually rewrite
	// os.Executable() output — but we can invoke the state-purge helpers
	// directly via the split API (purgeState) rather than the full
	// runUninstall. This keeps the test tight and scoped to the bug.

	var buf bytes.Buffer
	if err := purgeState(&buf, stateDir); err != nil {
		t.Fatalf("purgeState: %v", err)
	}

	// The directory must be gone. If the file-backend's Open() re-creates
	// it (the regressed behavior), this fails.
	if _, err := os.Stat(stateDir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s still exists after purge: err=%v", stateDir, err)
	}
	if !strings.Contains(buf.String(), "removed "+stateDir) {
		t.Errorf("purge output missing 'removed %s': %s", stateDir, buf.String())
	}
	// For completeness: no resurrected telepath files anywhere under home.
	_ = filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Name() == "keystore.key" || d.Name() == "keystore.enc" {
			t.Errorf("leftover keystore artifact at %s", p)
		}
		return nil
	})
	_ = fakeBin // keeps the variable alive; removeBinary is covered separately
}
