package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

func newVerifyConfigCmd() *cobra.Command {
	var pluginDir string
	c := &cobra.Command{
		Use:   "verify-config",
		Short: "Validate the telepath plugin manifest (runs tests/manifests/validate.py)",
		Long: `Invokes the plugin's own Python validator at tests/manifests/validate.py
against the given plugin directory. Intended as a pre-engagement sanity check;
the richer runtime validation (FR-V-2) lands alongside the engagement-load
flow in v0.1 week 7.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if pluginDir == "" {
				pluginDir = os.Getenv("TELEPATH_PLUGIN_DIR")
			}
			if pluginDir == "" {
				return fmt.Errorf("--plugin-dir or TELEPATH_PLUGIN_DIR required")
			}
			script := filepath.Join(pluginDir, "tests", "manifests", "validate.py")
			if _, err := os.Stat(script); err != nil {
				return fmt.Errorf("validator script not found at %s: %w", script, err)
			}
			out, err := exec.Command("python3", script).CombinedOutput()
			cmd.OutOrStdout().Write(out)
			if err != nil {
				return fmt.Errorf("validator failed: %w", err)
			}
			return nil
		},
	}
	c.Flags().StringVar(&pluginDir, "plugin-dir", "", "path to plugin repo (defaults to $TELEPATH_PLUGIN_DIR)")
	return c
}
