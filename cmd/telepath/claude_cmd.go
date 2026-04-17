package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/fsc/telepath-core/internal/config"
	"github.com/fsc/telepath-core/internal/keys"
)

func newClaudeCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "claude [args...]",
		Short:              "Launch Claude Code with the configured auth credential injected",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(config.DefaultPath())
			if err != nil {
				return err
			}
			if cfg.Claude.AuthMethod == "" {
				return errors.New("claude auth not configured; run `telepath config init`")
			}
			slot := config.KeystoreSlotForMethod(cfg.Claude.AuthMethod)
			envVar := config.EnvVarForMethod(cfg.Claude.AuthMethod)
			if slot == "" || envVar == "" {
				return fmt.Errorf("unsupported auth method %q", cfg.Claude.AuthMethod)
			}

			store, err := keys.Open()
			if err != nil {
				return err
			}
			secret, err := store.Get(slot)
			if err != nil {
				return fmt.Errorf("auth secret %q unavailable: %w (re-run `telepath config init`)", slot, err)
			}

			bin, err := exec.LookPath("claude")
			if err != nil {
				return fmt.Errorf("`claude` not on PATH: %w", err)
			}

			// Build env with the credential set. We inherit the existing
			// env so other configuration (PATH, HOME, editor prefs) carries
			// through to Claude Code.
			env := append(os.Environ(), fmt.Sprintf("%s=%s", envVar, string(secret)))

			// Use syscall.Exec so we become the claude process; that way
			// signals, TTY, and exit code propagate naturally.
			argv := append([]string{bin}, args...)
			return syscall.Exec(bin, argv, env)
		},
	}
}
