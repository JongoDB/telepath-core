// Command telepath is the operator-facing binary: daemon, CLI, and MCP
// adapter all dispatched by subcommand. "telepath daemon run" launches the
// long-lived process; every other subcommand is a thin client that talks to
// it over a Unix socket.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/fsc/telepath-core/internal/daemon"
)

func main() {
	root := &cobra.Command{
		Use:           "telepath",
		Short:         "FSC assessment harness — CLI + daemon",
		SilenceUsage:  true,
		SilenceErrors: false,
		Version:       daemon.Version,
		// Root invocation with no subcommand: if the binary is running
		// from outside PATH (freshly-extracted tarball), lead with a
		// "Next step" banner so users don't hit `telepath install` →
		// "command not found" by forgetting the leading ./. After
		// `telepath install`, the binary IS on PATH and the banner
		// suppresses itself — the help-only output remains.
		Run: func(cmd *cobra.Command, args []string) {
			if !runningFromPATH() {
				fmt.Fprintln(cmd.OutOrStdout(), freshExtractBanner())
			}
			_ = cmd.Help()
		},
	}
	// Cobra groups organize `telepath --help` output into three
	// functional buckets so new operators see the setup commands at the
	// top of the list instead of alphabetical noise.
	root.AddGroup(
		&cobra.Group{ID: "setup", Title: "Setup:"},
		&cobra.Group{ID: "ops", Title: "Operation:"},
		&cobra.Group{ID: "integration", Title: "Integration:"},
	)
	// Cobra's built-in completion command is unhidden by default; most
	// operators won't invoke it directly. Don't surface it in top-level
	// help — advanced users can still run `telepath completion --help`.
	root.CompletionOptions.HiddenDefaultCmd = true

	addToGroup := func(c *cobra.Command, id string) *cobra.Command {
		c.GroupID = id
		return c
	}
	root.AddCommand(
		addToGroup(newInstallCmd(), "setup"),
		addToGroup(newUpdateCmd(), "setup"),
		addToGroup(newUninstallCmd(), "setup"),
		addToGroup(newConfigCmd(), "setup"),
		addToGroup(newOAuthCmd(), "setup"),
		addToGroup(newDoctorCmd(), "setup"),
		addToGroup(newVerifyConfigCmd(), "setup"),
		addToGroup(newDaemonCmd(), "ops"),
		addToGroup(newEngagementCmd(), "ops"),
		addToGroup(newTransportCmd(), "ops"),
		addToGroup(newClaudeCmd(), "integration"),
		addToGroup(newMCPAdapterCmd(), "integration"),
	)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// runningFromPATH reports whether the executing binary lives in a
// directory that appears on $PATH. A tarball extraction to $HOME returns
// false and triggers the getting-started banner; a post-`install`
// invocation returns true and skips it.
func runningFromPATH() bool {
	self, err := os.Executable()
	if err != nil {
		// Fail-open: don't nag users in weird embedded environments.
		return true
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	selfAbs, err := filepath.Abs(self)
	if err != nil {
		return true
	}
	name := filepath.Base(self)
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		candidate := filepath.Join(dir, name)
		if candAbs, err := filepath.Abs(candidate); err == nil && candAbs == selfAbs {
			return true
		}
	}
	return false
}

// freshExtractBanner is the preamble printed before cobra's help when
// telepath is run with no subcommand and the binary isn't on PATH yet.
func freshExtractBanner() string {
	return `Looks like you've extracted telepath but haven't installed it yet.

Next step:

  ./telepath install

That copies the binary to ~/.local/bin (or %LOCALAPPDATA%\telepath\bin on
Windows) and prints the PATH-setup line for your shell. After that, plain
` + "`telepath`" + ` works from any directory.

Full command reference below:
`
}
