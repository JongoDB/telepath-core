package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/fsc/telepath-core/internal/keys"
)

// newUninstallCmd wires `telepath uninstall`. Two modes:
//
//   telepath uninstall           — removes the binary; leaves state alone
//   telepath uninstall --purge   — also removes ~/.telepath (config,
//                                   engagements, audit, vault, findings,
//                                   notes, logs) AND any keystore entries
//                                   the daemon had written
//
// --yes skips the "are you sure" prompt. Useful in scripts, dangerous
// interactively; we still summarize what will be removed before acting.
func newUninstallCmd() *cobra.Command {
	var purge bool
	var yes bool
	c := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the telepath binary (use --purge to also delete state)",
		Long: `Remove the installed telepath binary. By default only the
binary is removed — your engagements, audit logs, keystore, and config survive.

Use --purge to additionally remove every telepath-produced file on the host:
  ~/.telepath         (engagements, audit, vault, findings, notes, logs, config)
  keystore entries    (operator signing key, engagement keys, Claude auth)

Pass --yes to skip the interactive confirmation (scripts, CI).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUninstall(cmd.OutOrStdout(), os.Stdin, purge, yes)
		},
	}
	c.Flags().BoolVar(&purge, "purge", false, "also remove ~/.telepath and all keystore entries")
	c.Flags().BoolVar(&yes, "yes", false, "skip interactive confirmation")
	return c
}

// runUninstall is the logic. Separated from cobra wiring so tests/scripts
// can exercise it with in-process readers.
func runUninstall(out io.Writer, in io.Reader, purge, yes bool) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("uninstall: resolve self: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}

	home, _ := os.UserHomeDir()
	stateDir := filepath.Join(home, ".telepath")

	// Build a plan first — nothing destructive until the user confirms.
	var plan []string
	plan = append(plan, fmt.Sprintf("remove binary: %s", self))
	stateSummary := ""
	if purge {
		if summary, exists := inspectStateDir(stateDir); exists {
			plan = append(plan, "remove state: "+stateDir)
			stateSummary = summary
			plan = append(plan, "remove keystore entries for operator signing key, engagement keys, Claude auth")
		} else {
			plan = append(plan, fmt.Sprintf("(no state to remove: %s does not exist)", stateDir))
		}
	}

	fmt.Fprintln(out, "telepath uninstall plan:")
	for _, step := range plan {
		fmt.Fprintf(out, "  - %s\n", step)
	}
	if stateSummary != "" {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "state inventory:")
		fmt.Fprint(out, stateSummary)
	}

	if !yes {
		fmt.Fprintln(out)
		fmt.Fprint(out, "Proceed? Type 'yes' to continue: ")
		reader := bufio.NewReader(in)
		line, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(line)) != "yes" {
			fmt.Fprintln(out, "aborted")
			return nil
		}
	}

	// Execute: state first, then binary. If state removal fails halfway,
	// at least the binary is still there to retry with.
	if purge {
		if err := purgeState(out, stateDir); err != nil {
			// Best-effort: tell the user what failed and keep going.
			fmt.Fprintf(out, "warning: %v\n", err)
		}
	}

	if err := removeBinary(out, self); err != nil {
		return err
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "telepath uninstalled.")
	if !purge {
		fmt.Fprintln(out, "(state preserved; re-run with --purge to remove ~/.telepath and keystore entries.)")
	}
	return nil
}

// inspectStateDir returns a human-readable summary of what's in statePath
// plus whether the directory exists. Empty summary + false when absent.
func inspectStateDir(statePath string) (string, bool) {
	info, err := os.Stat(statePath)
	if err != nil {
		return "", false
	}
	if !info.IsDir() {
		return fmt.Sprintf("  %s is not a directory — refusing to remove\n", statePath), true
	}
	var b strings.Builder
	engs := 0
	events := 0
	evidence := 0
	_ = filepath.WalkDir(filepath.Join(statePath, "engagements"), func(p string, d fs.DirEntry, _ error) error {
		if d == nil {
			return nil
		}
		if d.IsDir() && filepath.Dir(p) == filepath.Join(statePath, "engagements") {
			engs++
		}
		if !d.IsDir() && filepath.Base(p) == "audit.jsonl" {
			if f, err := os.Open(p); err == nil {
				sc := bufio.NewScanner(f)
				for sc.Scan() {
					events++
				}
				f.Close()
			}
		}
		if !d.IsDir() && strings.HasSuffix(p, ".enc") && strings.Contains(p, "/vault/") {
			evidence++
		}
		return nil
	})
	fmt.Fprintf(&b, "  engagements: %d\n", engs)
	fmt.Fprintf(&b, "  audit events: %d\n", events)
	fmt.Fprintf(&b, "  evidence items: %d\n", evidence)
	return b.String(), true
}

// purgeState deletes ~/.telepath and any telepath-* entries in the OS
// keychain (best-effort; keys not owned by us stay).
func purgeState(out io.Writer, stateDir string) error {
	// For engagement keys we need to know the IDs — read them from the
	// engagements dir BEFORE we nuke it.
	engs := listEngagementIDs(stateDir)

	if err := os.RemoveAll(stateDir); err != nil {
		return fmt.Errorf("remove %s: %w", stateDir, err)
	}
	fmt.Fprintf(out, "removed %s\n", stateDir)

	// Keystore cleanup: only the OS-keychain backend needs explicit
	// deletion. The file backend lives under ~/.telepath which we just
	// removed.
	if store, err := keys.Open(); err == nil {
		n := keys.PurgeTelepathEntries(out, store, engs)
		if n == 0 && store.Backend() == "file" {
			// File backend: already wiped by the ~/.telepath removal.
			fmt.Fprintln(out, "(file keystore removed alongside ~/.telepath)")
		}
	} else {
		fmt.Fprintf(out, "warning: keystore unreachable for cleanup: %v\n", err)
	}
	return nil
}

func listEngagementIDs(stateDir string) []string {
	engDir := filepath.Join(stateDir, "engagements")
	entries, err := os.ReadDir(engDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

// removeBinary deletes the running binary. On Unix this works because the
// kernel keeps the inode alive via the open file descriptor. On Windows a
// running .exe can't be deleted — we print a delete command instead.
func removeBinary(out io.Writer, path string) error {
	if runtime.GOOS == "windows" {
		fmt.Fprintln(out)
		fmt.Fprintf(out, "telepath.exe is still running; delete it manually with:\n  del %q\n", path)
		return nil
	}
	if err := os.Remove(path); err != nil {
		fmt.Fprintf(out, "could not delete %s automatically (%v); run: rm %q\n", path, err, path)
		return nil
	}
	fmt.Fprintf(out, "removed %s\n", path)
	return nil
}

// sumFile returns the SHA-256 hex digest of a file (used by install's
// same-content detection, not uninstall). Placed here because it's small
// and both commands consume it.
func sumFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
