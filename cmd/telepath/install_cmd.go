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
// parent dirs as needed. Returns a descriptive error if a binary already
// lives there and --force wasn't passed.
func runInstall(out io.Writer, targetDir string, force bool) error {
	src, err := os.Executable()
	if err != nil {
		return fmt.Errorf("install: resolve self: %w", err)
	}
	// Resolve symlinks so installs from an extracted tarball work even when
	// the extracted path is itself a symlink.
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

	// Detect the "already installed to the target" case so running
	// `telepath install` after it's already on PATH is a helpful no-op
	// instead of an error.
	if samePath(src, target) {
		fmt.Fprintf(out, "telepath is already installed at %s.\n", target)
		printPathHint(out, targetDir)
		printNextSteps(out)
		return nil
	}

	if !force {
		if _, err := os.Stat(target); err == nil {
			return fmt.Errorf("install: %s already exists; pass --force to overwrite", target)
		}
	}

	if err := copyExecutable(src, target); err != nil {
		return fmt.Errorf("install: copy: %w", err)
	}

	fmt.Fprintf(out, "Installed telepath to %s\n", target)
	printPathHint(out, targetDir)
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

// printPathHint emits the one-liner the operator pastes to add targetDir to
// their PATH. Dispatches on platform + $SHELL so zsh/bash/fish each get the
// right syntax; Windows gets the PowerShell [Environment]::SetEnvironmentVariable
// invocation.
func printPathHint(out io.Writer, targetDir string) {
	if runtime.GOOS == "windows" {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Add telepath to your user PATH by pasting this into PowerShell:")
		fmt.Fprintln(out)
		fmt.Fprintf(out, "  [Environment]::SetEnvironmentVariable('PATH', '%s;' + [Environment]::GetEnvironmentVariable('PATH', 'User'), 'User')\n", targetDir)
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Open a new PowerShell window, then verify:")
		fmt.Fprintln(out, "  telepath --version")
		return
	}

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
	fmt.Fprintf(out, "To add %s to your PATH, paste this into your shell:\n", targetDir)
	fmt.Fprintln(out)
	fmt.Fprintf(out, "  echo '%s' >> %s && source %s\n", line, rc, rc)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Verify with:  telepath --version")
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
