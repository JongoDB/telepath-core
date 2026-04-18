package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
)

// newInstallCmd wires the "telepath install" subcommand. The binary copies
// itself to a canonical per-user install dir, prints the PATH-adding line for
// the user's shell, and hints at the next commands to run. Single binary,
// single install path — no bash / PowerShell script to keep in sync.
func newInstallCmd() *cobra.Command {
	var dir string
	var force bool
	c := &cobra.Command{
		Use:   "install",
		Short: "Copy this binary to a canonical location and print PATH setup",
		Long: `Install the currently-running telepath binary to a per-user install
directory (default: ~/.local/bin on Unix, %LOCALAPPDATA%\telepath\bin on Windows)
and print the shell-specific PATH-update line for you to paste.

Typical first-run workflow:
  1. Download telepath-<version>-<os>-<arch>.tar.gz (or .zip on Windows)
  2. Extract it
  3. ./telepath install     — this command
  4. Paste the PATH line into your shell rc
  5. telepath config init   — open the TUI`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if dir == "" {
				dir = defaultInstallDir()
			}
			return runInstall(cmd.OutOrStdout(), dir, force)
		},
	}
	c.Flags().StringVar(&dir, "dir", "", "install directory (defaults per-OS)")
	c.Flags().BoolVar(&force, "force", false, "overwrite an existing telepath at the destination")
	return c
}

// defaultInstallDir returns the per-user install path appropriate for the
// current OS. Keeping it user-scoped (no sudo) is deliberate — telepath is
// operator-personal state and doesn't belong in /usr/local/bin on shared hosts.
func defaultInstallDir() string {
	if runtime.GOOS == "windows" {
		if v := os.Getenv("LOCALAPPDATA"); v != "" {
			return filepath.Join(v, "telepath", "bin")
		}
		return filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "telepath", "bin")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "/usr/local/bin"
	}
	return filepath.Join(home, ".local", "bin")
}

// runInstall copies the running binary to targetDir/telepath(.exe), making
// parent dirs as needed. Idempotent in three cases:
//  1. src and target are the same file (running `install` from installed loc)
//  2. target exists with identical content (same binary, different path)
//  3. target does not exist
//
// Only case (4) — target exists with different content — requires --force.
func runInstall(out io.Writer, targetDir string, force bool) error {
	src, err := os.Executable()
	if err != nil {
		return fmt.Errorf("install: resolve self: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(src); err == nil {
		src = resolved
	}

	name := "telepath"
	if runtime.GOOS == "windows" {
		name = "telepath.exe"
	}
	target := filepath.Join(targetDir, name)

	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return fmt.Errorf("install: mkdir %s: %w", targetDir, err)
	}

	// Case 1: same path.
	if samePath(src, target) {
		fmt.Fprintf(out, "telepath is already installed at %s.\n", target)
		printPathAdvice(out, targetDir)
		printNextSteps(out)
		return nil
	}

	// Cases 2 & 4: target exists. Check content.
	if _, err := os.Stat(target); err == nil {
		// Compare content hashes. Same content -> idempotent no-op.
		srcSum, serr := sumFile(src)
		tgtSum, terr := sumFile(target)
		if serr == nil && terr == nil && srcSum == tgtSum {
			fmt.Fprintf(out, "telepath is already installed at %s (identical binary).\n", target)
			printPathAdvice(out, targetDir)
			printNextSteps(out)
			return nil
		}
		if !force {
			return fmt.Errorf("install: %s already exists with different content; pass --force to overwrite", target)
		}
	}

	if err := copyExecutable(src, target); err != nil {
		return fmt.Errorf("install: copy: %w", err)
	}
	fmt.Fprintf(out, "Installed telepath to %s\n", target)
	printPathAdvice(out, targetDir)
	printNextSteps(out)
	return nil
}

// samePath normalizes a and b and compares them. Used to detect idempotent
// reinstalls (same source and target).
func samePath(a, b string) bool {
	aa, err := filepath.Abs(a)
	if err != nil {
		return false
	}
	bb, err := filepath.Abs(b)
	if err != nil {
		return false
	}
	return aa == bb
}

// copyExecutable writes src to dst with an atomic write-then-rename. Fails
// loudly on Windows if dst is currently being executed (the typical upgrade
// path there is to delete the old binary first or run from a different
// location during install).
func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// printPathAdvice prints PATH setup guidance appropriate to the situation.
// Two paths:
//  1. targetDir is already on PATH → short "already on PATH" note.
//  2. Not on PATH → emit the shell-specific export command for the
//     operator to paste into their rc file.
//
// Ubuntu/Debian's default ~/.profile auto-adds ~/.local/bin to PATH for
// login shells; we note that when relevant so operators don't paste a
// redundant line into ~/.bashrc.
func printPathAdvice(out io.Writer, targetDir string) {
	onPath := dirOnPath(targetDir)

	if runtime.GOOS == "windows" {
		fmt.Fprintln(out)
		if onPath {
			fmt.Fprintln(out, "telepath is on your current PATH.")
			fmt.Fprintln(out, "Verify with:  telepath --version")
			return
		}
		fmt.Fprintln(out, "Add telepath to your user PATH by pasting this into PowerShell:")
		fmt.Fprintln(out)
		fmt.Fprintf(out, "  [Environment]::SetEnvironmentVariable('PATH', '%s;' + [Environment]::GetEnvironmentVariable('PATH', 'User'), 'User')\n", targetDir)
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Open a new PowerShell window, then verify:")
		fmt.Fprintln(out, "  telepath --version")
		return
	}

	if onPath {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "telepath is on your current PATH.")
		fmt.Fprintln(out, "Verify with:  telepath --version")
		return
	}

	// On Debian/Ubuntu the default ~/.profile already adds ~/.local/bin
	// to PATH for login shells. A new terminal will pick it up without
	// any rc edit. Detect the default-location case and give the lighter
	// advice.
	home, _ := os.UserHomeDir()
	defaultLocalBin := home != "" && targetDir == filepath.Join(home, ".local", "bin")

	shellBase := filepath.Base(os.Getenv("SHELL"))
	var rc, line string
	switch shellBase {
	case "zsh":
		rc = "~/.zshrc"
		line = fmt.Sprintf(`export PATH="%s:$PATH"`, targetDir)
	case "bash":
		rc = "~/.bashrc"
		line = fmt.Sprintf(`export PATH="%s:$PATH"`, targetDir)
	case "fish":
		rc = "~/.config/fish/config.fish"
		line = fmt.Sprintf(`set -gx PATH %s $PATH`, targetDir)
	default:
		rc = "~/.profile"
		line = fmt.Sprintf(`export PATH="%s:$PATH"`, targetDir)
	}

	fmt.Fprintln(out)
	if defaultLocalBin {
		fmt.Fprintf(out, "%s is telepath's default install location.\n", targetDir)
		fmt.Fprintln(out, "On Debian/Ubuntu the default ~/.profile auto-adds it to PATH for new login shells —")
		fmt.Fprintln(out, "open a new terminal and `telepath --version` should just work.")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "If your shell doesn't auto-pick-up this directory, paste:")
	} else {
		fmt.Fprintf(out, "To add %s to your PATH, paste this into your shell:\n", targetDir)
	}
	fmt.Fprintln(out)
	fmt.Fprintf(out, "  echo '%s' >> %s && source %s\n", line, rc, rc)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Verify with:  telepath --version")
}

// dirOnPath returns true when targetDir appears in the current PATH. Uses
// exact match on the cleaned path, so ~/.local/bin vs /home/alice/.local/bin
// still resolves correctly.
func dirOnPath(targetDir string) bool {
	clean, err := filepath.Abs(targetDir)
	if err != nil {
		return false
	}
	sep := ":"
	if runtime.GOOS == "windows" {
		sep = ";"
	}
	for _, p := range filepath.SplitList(os.Getenv("PATH")) {
		if p == "" {
			continue
		}
		if a, err := filepath.Abs(p); err == nil && a == clean {
			return true
		}
	}
	_ = sep
	return false
}

// printNextSteps tells the operator what to do immediately after install.
// Lightweight — the real guidance lives in `telepath config init`.
func printNextSteps(out io.Writer) {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Next:")
	fmt.Fprintln(out, "  telepath config init          # interactive setup (TUI)")
	fmt.Fprintln(out, "  telepath daemon run           # start the daemon (foreground)")
	fmt.Fprintln(out, "  telepath engagement new …     # create your first engagement")
}
