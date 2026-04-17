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
	root.AddCommand(
		newDaemonCmd(),
		newEngagementCmd(),
		newTransportCmd(),
		newConfigCmd(),
		newDoctorCmd(),
		newVerifyConfigCmd(),
		newClaudeCmd(),
		newMCPAdapterCmd(),
	)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
