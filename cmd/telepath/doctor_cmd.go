package main

import (
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/fsc/telepath-core/internal/config"
	"github.com/fsc/telepath-core/internal/daemon"
	"github.com/fsc/telepath-core/internal/keys"
	"github.com/fsc/telepath-core/pkg/schema"
)

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose common setup issues",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Non-fatal checks; we report results line-by-line and always
			// exit 0 so the command is useful in a pipe even when the
			// daemon isn't running.
			checkKeystore(cmd)
			checkConfig(cmd)
			checkClaudeBinary(cmd)
			checkDaemon(cmd)
			return nil
		},
	}
}

func ok(cmd *cobra.Command, label, detail string) {
	fmt.Fprintf(cmd.OutOrStdout(), "[ OK ] %-20s %s\n", label, detail)
}
func warn(cmd *cobra.Command, label, detail string) {
	fmt.Fprintf(cmd.OutOrStdout(), "[WARN] %-20s %s\n", label, detail)
}
func fail(cmd *cobra.Command, label, detail string) {
	fmt.Fprintf(cmd.OutOrStdout(), "[FAIL] %-20s %s\n", label, detail)
}

func checkKeystore(cmd *cobra.Command) {
	s, err := keys.Open()
	if err != nil {
		fail(cmd, "keystore", err.Error())
		return
	}
	if _, err := keys.GetOrCreateSigningKey(s); err != nil {
		fail(cmd, "keystore", fmt.Sprintf("signing key unavailable: %v", err))
		return
	}
	ok(cmd, "keystore", fmt.Sprintf("backend=%s, signing key present", s.Backend()))
}

func checkConfig(cmd *cobra.Command) {
	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		fail(cmd, "config", err.Error())
		return
	}
	var missing []string
	if cfg.Operator.Name == "" {
		missing = append(missing, "operator.name")
	}
	if cfg.Claude.AuthMethod == "" {
		missing = append(missing, "claude.auth_method")
	}
	if len(missing) > 0 {
		warn(cmd, "config", fmt.Sprintf("unset: %v — run `telepath config init`", missing))
		return
	}
	ok(cmd, "config", fmt.Sprintf("path=%s, auth=%s", config.DefaultPath(), cfg.Claude.AuthMethod))
}

func checkClaudeBinary(cmd *cobra.Command) {
	if _, err := exec.LookPath("claude"); err != nil {
		warn(cmd, "claude binary", "`claude` not on PATH — operators need it for the actual assessment")
		return
	}
	ok(cmd, "claude binary", "on PATH")
}

func checkDaemon(cmd *cobra.Command) {
	pid, err := daemon.ReadPIDFile(daemon.DefaultPIDFilePath())
	if err != nil {
		warn(cmd, "daemon", "not running (no pidfile)")
		return
	}
	if !daemon.PIDAlive(pid) {
		warn(cmd, "daemon", fmt.Sprintf("stale pidfile (pid %d not alive)", pid))
		return
	}
	res, err := func() (*schema.PingResult, error) {
		var p schema.PingResult
		if err := rpc(schema.MethodPing, nil, &p); err != nil {
			return nil, err
		}
		return &p, nil
	}()
	if err != nil {
		warn(cmd, "daemon", fmt.Sprintf("pid %d alive but ping failed: %v", pid, err))
		return
	}
	ok(cmd, "daemon", fmt.Sprintf("pid %d, version %s", pid, res.Version))
}

// silence unused import warnings if json drops out of checks later.
var _ = json.RawMessage{}
