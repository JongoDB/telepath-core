// Command telepath is the operator-facing binary: daemon, CLI, and MCP
// adapter all dispatched by subcommand. "telepath daemon run" launches the
// long-lived process; every other subcommand is a thin client that talks to
// it over a Unix socket.
package main

import (
	"fmt"
	"os"

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
		addToGroup(newUninstallCmd(), "setup"),
		addToGroup(newConfigCmd(), "setup"),
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
