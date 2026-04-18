package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/fsc/telepath-core/internal/daemon"
)

// BootstrapInstallURL is the raw URL to the curl-able install script.
// Kept in a var so `telepath update` and the release workflow both read
// from the same place; pointing at a fork during testing is a one-line
// override.
var BootstrapInstallURL = "https://raw.githubusercontent.com/JongoDB/telepath-core/main/scripts/install.sh"

// newUpdateCmd is `telepath update` — re-runs the bootstrap install
// script, which downloads the latest release tarball for the current
// OS/arch and hands off to `telepath install`. Windows prints a note
// pointing at the download page (the bootstrap script is Unix-only).
func newUpdateCmd() *cobra.Command {
	var version string
	c := &cobra.Command{
		Use:   "update",
		Short: "Upgrade telepath to the latest release (re-runs the bootstrap installer)",
		Long: `Upgrade telepath by re-running the bootstrap installer against this
machine. Fetches scripts/install.sh from the main branch, which
downloads the matching release tarball and runs the embedded install.

Use VERSION=vX.Y.Z to pin a specific release:
  telepath update --version v0.1.5

Unix (macOS + Linux) only. Windows upgrades by downloading the new
telepath-<version>-windows-amd64.zip from the Releases page and running
the extracted ./telepath install.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate(cmd, version)
		},
	}
	c.Flags().StringVar(&version, "version", "", "pin an explicit version (e.g. v0.1.5); default: latest")
	return c
}

func runUpdate(cmd *cobra.Command, pinVersion string) error {
	if runtime.GOOS == "windows" {
		fmt.Fprintln(cmd.OutOrStdout(),
			"Windows upgrade: download the latest telepath-<version>-windows-amd64.zip from")
		fmt.Fprintln(cmd.OutOrStdout(),
			"  https://github.com/JongoDB/telepath-core/releases/latest")
		fmt.Fprintln(cmd.OutOrStdout(),
			"Extract the zip and run `./telepath.exe install` from the extracted directory.")
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Current version: %s\n", daemon.Version)
	fmt.Fprintln(cmd.OutOrStdout(), "Fetching bootstrap installer:", BootstrapInstallURL)
	fmt.Fprintln(cmd.OutOrStdout())

	// Assemble: curl -sSL <url> | VERSION=<pin> sh
	// Any sh works — /bin/sh is universal on Unix; the install script
	// uses only POSIX features.
	shellCmd := "curl -sSL " + BootstrapInstallURL + " | "
	if pinVersion != "" {
		shellCmd += "VERSION=" + shEscape(pinVersion) + " "
	}
	shellCmd += "sh"

	sh := exec.Command("sh", "-c", shellCmd)
	sh.Stdin = os.Stdin
	sh.Stdout = cmd.OutOrStdout()
	sh.Stderr = cmd.ErrOrStderr()
	if err := sh.Run(); err != nil {
		return fmt.Errorf("update: bootstrap installer failed: %w", err)
	}
	return nil
}

// shEscape is a minimal single-quote escape for the VERSION value.
// Only called on user-supplied pin strings; belt-and-suspenders against
// weird characters in a tag name.
func shEscape(s string) string {
	// Wrap in single quotes and escape any embedded single quotes.
	out := []byte{'\''}
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			out = append(out, '\'', '\\', '\'', '\'')
		} else {
			out = append(out, s[i])
		}
	}
	out = append(out, '\'')
	return string(out)
}
