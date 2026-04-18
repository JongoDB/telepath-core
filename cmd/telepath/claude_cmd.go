package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/fsc/telepath-core/internal/config"
	"github.com/fsc/telepath-core/internal/keys"
	claudeoauth "github.com/fsc/telepath-core/internal/oauth/claude"
)

// preExpiryWindow is how close to expiry subscription-OAuth access tokens
// are refreshed. 5 minutes is enough that a slow `telepath claude` start
// never hands an already-expired token to the `claude` binary, and small
// enough that the refresh HTTP call amortizes over many invocations.
const preExpiryWindow = 5 * time.Minute

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
			store, err := keys.Open()
			if err != nil {
				return err
			}

			token, envVar, err := resolveClaudeCredential(cmd.Context(), cfg.Claude.AuthMethod, store, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			bin, err := exec.LookPath("claude")
			if err != nil {
				return fmt.Errorf("`claude` not on PATH: %w", err)
			}

			// Build env with the credential set. We inherit the existing
			// env so other configuration (PATH, HOME, editor prefs) carries
			// through to Claude Code.
			env := append(os.Environ(), fmt.Sprintf("%s=%s", envVar, token))

			// Use syscall.Exec so we become the claude process; that way
			// signals, TTY, and exit code propagate naturally.
			argv := append([]string{bin}, args...)
			return syscall.Exec(bin, argv, env)
		},
	}
}

// resolveClaudeCredential returns the credential string to export as the
// Claude Code env var, plus the env var name itself. For oauth-token and
// api-key it's a straight keystore read. For subscription-oauth it also
// enforces the 5-minute pre-expiry refresh window — if the stored access
// token is within that window (or already expired), it trades the
// refresh token for a fresh pair and persists the result before
// returning.
//
// warnOut receives non-fatal diagnostics (e.g., keystore write failures
// after a successful refresh — the current run still gets a valid token,
// but the next one won't see the fresh pair). stderr in production.
func resolveClaudeCredential(ctx context.Context, method config.AuthMethod, store keys.Store, warnOut io.Writer) (token, envVar string, err error) {
	envVar = config.EnvVarForMethod(method)
	if envVar == "" {
		return "", "", fmt.Errorf("unsupported auth method %q", method)
	}

	if method != config.AuthMethodSubscriptionOAuth {
		slot := config.KeystoreSlotForMethod(method)
		secret, err := store.Get(slot)
		if err != nil {
			return "", "", fmt.Errorf("auth secret %q unavailable: %w (re-run `telepath config init`)", slot, err)
		}
		return string(secret), envVar, nil
	}

	access, err := store.Get(config.KeystoreClaudeSubAccessToken)
	if err != nil {
		return "", "", fmt.Errorf("subscription access token unavailable: %w (re-run `telepath config init`)", err)
	}

	expiresAt, err := readSubscriptionExpiresAt(store)
	if err != nil {
		return "", "", err
	}
	if time.Now().Add(preExpiryWindow).Before(expiresAt) {
		return string(access), envVar, nil
	}

	// Pre-expiry refresh: trade the refresh token for a new pair.
	refresh, err := store.Get(config.KeystoreClaudeSubRefreshToken)
	if err != nil {
		return "", "", fmt.Errorf("subscription refresh token unavailable: %w (re-run `telepath config init`)", err)
	}
	fmt.Fprintln(warnOut, "telepath: subscription access token near expiry — refreshing…")
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	fresh, err := claudeoauth.Refresh(rctx, string(refresh))
	if err != nil {
		return "", "", fmt.Errorf("subscription token refresh: %w (re-run `telepath config init` if this persists)", err)
	}

	// Persist — failure here is non-fatal for this run (we already have
	// the fresh token in hand) but flagged so the operator can fix the
	// keystore before the next refresh window.
	if err := store.Set(config.KeystoreClaudeSubAccessToken, []byte(fresh.AccessToken)); err != nil {
		fmt.Fprintf(warnOut, "telepath: warning: persist refreshed access token: %v\n", err)
	}
	if fresh.RefreshToken != "" {
		if err := store.Set(config.KeystoreClaudeSubRefreshToken, []byte(fresh.RefreshToken)); err != nil {
			fmt.Fprintf(warnOut, "telepath: warning: persist refreshed refresh token: %v\n", err)
		}
	}
	if err := store.Set(config.KeystoreClaudeSubExpiresAt, []byte(fresh.ExpiresAt.Format(time.RFC3339))); err != nil {
		fmt.Fprintf(warnOut, "telepath: warning: persist refreshed expires_at: %v\n", err)
	}
	return fresh.AccessToken, envVar, nil
}

// readSubscriptionExpiresAt parses the RFC3339 timestamp stored next to
// the subscription access token. A missing slot is treated as "expired
// now" so a fresh install without the field still triggers a refresh
// instead of handing over an already-expired token.
func readSubscriptionExpiresAt(store keys.Store) (time.Time, error) {
	raw, err := store.Get(config.KeystoreClaudeSubExpiresAt)
	if err != nil {
		return time.Now().UTC(), nil
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(raw)))
	if err != nil {
		return time.Time{}, fmt.Errorf("parse subscription expires_at: %w", err)
	}
	return t, nil
}
