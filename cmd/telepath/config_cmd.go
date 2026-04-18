package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/fsc/telepath-core/internal/config"
	"github.com/fsc/telepath-core/internal/keys"
	claudeoauth "github.com/fsc/telepath-core/internal/oauth/claude"
)

func newConfigCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Inspect or update telepath's operator-level config",
	}
	c.AddCommand(newConfigInitCmd(), newConfigSetCmd(), newConfigGetCmd(), newConfigShowCmd())
	return c
}

func newConfigShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print the current config (without secrets)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(config.DefaultPath())
			if err != nil {
				return err
			}
			fmt.Printf("operator.name      = %s\n", cfg.Operator.Name)
			fmt.Printf("operator.email     = %s\n", cfg.Operator.Email)
			fmt.Printf("claude.auth_method = %s\n", cfg.Claude.AuthMethod)
			fmt.Printf("config_path        = %s\n", config.DefaultPath())
			// Surface the keystore backend so operators can see whether
			// secrets live in the OS keychain or the file fallback.
			if store, err := keys.Open(); err == nil {
				fmt.Printf("keystore_backend   = %s\n", store.Backend())
			} else {
				fmt.Printf("keystore_backend   = (unreachable: %v)\n", err)
			}
			return nil
		},
	}
}

func newConfigGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <key>",
		Short: "Read a single dotted config key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(config.DefaultPath())
			if err != nil {
				return err
			}
			fmt.Println(config.Get(cfg, args[0]))
			return nil
		},
	}
}

func newConfigSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Write a single dotted config key",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := config.DefaultPath()
			cfg, err := config.Load(path)
			if err != nil {
				return err
			}
			if err := config.Set(cfg, args[0], args[1]); err != nil {
				return err
			}
			return config.Save(path, cfg)
		},
	}
}

func newConfigInitCmd() *cobra.Command {
	var nonInteractive bool
	c := &cobra.Command{
		Use:   "init",
		Short: "Interactive setup: operator identity + Claude Code auth method",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Three-way dispatch:
			//   - --non-interactive set OR stdin is not a TTY: line-by-line
			//     prompts, no subprocess calls (skipping `claude setup-token`
			//     entirely so automation never hangs on a hidden subprompt)
			//   - otherwise: huh/Bubble Tea TUI
			//   - if the TUI renderer can't start, fall through to prompts
			interactive := stdinIsTerminal() && !nonInteractive
			if !interactive {
				return runConfigInit(os.Stdin, cmd.OutOrStdout(), cmd.ErrOrStderr(), configInitOpts{interactive: false})
			}
			if err := runConfigInitTUI(cmd.OutOrStdout()); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "TUI unavailable (%v); falling back to stdin prompts\n", err)
				return runConfigInit(os.Stdin, cmd.OutOrStdout(), cmd.ErrOrStderr(), configInitOpts{interactive: true})
			}
			return nil
		},
	}
	c.Flags().BoolVar(&nonInteractive, "non-interactive", false, "use line-by-line stdin prompts instead of the TUI")
	return c
}

// configInitOpts carries the small bit of context the stdin wizard needs
// from the cobra command layer. Today just whether the runtime is
// interactive (TTY stdin + user-invoked), which gates subprocess prompts
// like `claude setup-token`.
type configInitOpts struct {
	interactive bool
}

// stdinIsTerminal reports whether stdin is attached to a terminal. No new
// dependency: os.Stdin.Stat() is sufficient to check the char-device bit.
func stdinIsTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// runConfigInitTUI is the Bubble Tea / huh-based interactive wizard. Mirrors
// the steps in runConfigInit: operator identity, auth method choice, credential
// capture — but rendered with a form instead of line-by-line prompts.
func runConfigInitTUI(out io.Writer) error {
	path := config.DefaultPath()
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}

	// Form state. huh binds Value(&ptr) to each field and mutates in place.
	name := cfg.Operator.Name
	email := cfg.Operator.Email
	method := cfg.Claude.AuthMethod
	if method == "" {
		method = config.AuthMethodOAuthToken
	}
	var token string

	var confirm bool
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("telepath — operator configuration").
				Description("Set up who you are and how Claude Code will authenticate to Anthropic.\nTokens are stored in the OS keychain (or the file backend when the keychain is unavailable)."),
			huh.NewInput().
				Title("Operator name").
				Placeholder("Alex Thompson").
				Value(&name),
			huh.NewInput().
				Title("Operator email").
				Placeholder("alex@fsc.example").
				Value(&email),
		),
		huh.NewGroup(
			huh.NewSelect[config.AuthMethod]().
				Title("Claude Code auth method").
				Description("The credential Claude Code will use for model calls.").
				Options(
					huh.NewOption("CLAUDE_CODE_OAUTH_TOKEN (recommended for Max/Team/Enterprise)", config.AuthMethodOAuthToken),
					huh.NewOption("ANTHROPIC_API_KEY (FSC API account)", config.AuthMethodAPIKey),
					huh.NewOption("Subscription OAuth (personal Claude Pro/Max)", config.AuthMethodSubscriptionOAuth),
				).
				Value(&method),
		),
		// Token input shows ONLY for api-key. oauth-token drops out of the
		// TUI after Save and hands off to `claude setup-token` (interactive
		// subprocess — matches `claude code cli` auth UX). subscription-
		// oauth runs the PKCE flow. Hiding the field for both methods
		// avoids a misleading "paste a token here" prompt for flows where
		// the token comes from a handoff, not paste-in.
		huh.NewGroup(
			huh.NewInput().
				Title("ANTHROPIC_API_KEY (input hidden)").
				Description("Your FSC API-account key. Leave empty to skip and capture later with `telepath config set`.").
				EchoMode(huh.EchoModePassword).
				Value(&token),
		).WithHideFunc(func() bool {
			return method != config.AuthMethodAPIKey
		}),
		// Confirmation step. The operator can Shift+Tab back through the
		// groups to review/change values before saying "Save".
		huh.NewGroup(
			huh.NewNote().
				Title("Review").
				Description("Shift+Tab to go back and change any value. Confirm below to write the config."),
			huh.NewConfirm().
				Title("Save configuration?").
				Affirmative("Save").
				Negative("Cancel").
				Value(&confirm),
		),
	)

	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return errors.New("cancelled")
		}
		return err
	}
	if !confirm {
		fmt.Fprintln(out, "cancelled; config not saved.")
		return nil
	}

	cfg.Operator.Name = strings.TrimSpace(name)
	cfg.Operator.Email = strings.TrimSpace(email)
	cfg.Claude.AuthMethod = method
	if err := config.Save(path, cfg); err != nil {
		return err
	}

	// After the TUI form ends, each auth method takes its method-specific
	// capture path. The TUI form is OVER by this point (huh has returned);
	// terminal is back to normal so subprocess handoffs work cleanly.
	store, err := keys.Open()
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}

	switch method {
	case config.AuthMethodAPIKey:
		// API key: came from the TUI input field. Store if non-empty.
		if token != "" {
			if err := store.Set(config.KeystoreClaudeAPIKey, []byte(strings.TrimSpace(token))); err != nil {
				return err
			}
			fmt.Fprintf(out, "Stored ANTHROPIC_API_KEY in keystore (backend=%s).\n", store.Backend())
		} else {
			fmt.Fprintln(out, "No API key captured; set later with `telepath config set` or the keystore tool of your choice.")
		}
	case config.AuthMethodOAuthToken:
		// oauth-token: drop out of the TUI and run `claude setup-token`
		// under the hood. Claude's own CLI takes over the terminal, shows
		// the URL, completes the browser handoff, and prints the token —
		// identical UX to running `claude setup-token` directly. We then
		// prompt the operator to paste the token back.
		reader := bufio.NewReader(os.Stdin)
		capturedToken, err := captureClaudeOAuthToken(reader, out, out, configInitOpts{interactive: true}, true)
		if err != nil {
			return err
		}
		if err := store.Set(config.KeystoreClaudeOAuthToken, []byte(capturedToken)); err != nil {
			return err
		}
		fmt.Fprintf(out, "Stored CLAUDE_CODE_OAUTH_TOKEN in keystore (backend=%s).\n", store.Backend())
	case config.AuthMethodSubscriptionOAuth:
		reader := bufio.NewReader(os.Stdin)
		if err := runClaudeSubscriptionOAuth(reader, out, store, true); err != nil {
			return err
		}
	}

	fmt.Fprintf(out, "Config saved to %s.\n", path)
	return nil
}

// runConfigInit is the wizard. Split out of the cobra RunE so it can be
// exercised with in-process readers/writers in tests.
func runConfigInit(in io.Reader, out, errOut io.Writer, opts configInitOpts) error {
	reader := bufio.NewReader(in)
	// Piped stdin does not echo the user's newline the way a TTY does.
	// The prompt helper emits a synthetic newline in that case so each
	// prompt lands on its own line when transcripted.
	promptEchoesNewline := !stdinIsTerminal()

	path := config.DefaultPath()
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "telepath config init — operator identity + Claude Code auth")
	fmt.Fprintln(out, "Press enter to keep the existing value shown in [brackets].")

	cfg.Operator.Name = prompt(reader, out, "Operator name", cfg.Operator.Name, promptEchoesNewline)
	cfg.Operator.Email = prompt(reader, out, "Operator email", cfg.Operator.Email, promptEchoesNewline)

	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Claude Code auth method:")
	fmt.Fprintln(out, "  1) oauth-token         — `claude setup-token` one-year token (recommended for Claude Max/Team)")
	fmt.Fprintln(out, "  2) api-key             — ANTHROPIC_API_KEY from FSC's API account")
	fmt.Fprintln(out, "  3) subscription-oauth  — PKCE flow against your personal Claude Pro/Max subscription")

	def := "1"
	if cfg.Claude.AuthMethod != "" {
		def = string(cfg.Claude.AuthMethod)
	}
	choice := prompt(reader, out, "Choose [1-3 or name]", def, promptEchoesNewline)
	method, err := config.NormalizeSelectedMethod(choice)
	if err != nil {
		return err
	}
	cfg.Claude.AuthMethod = method

	store, err := keys.Open()
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}

	switch method {
	case config.AuthMethodOAuthToken:
		token, err := captureClaudeOAuthToken(reader, out, errOut, opts, promptEchoesNewline)
		if err != nil {
			return err
		}
		if err := store.Set(config.KeystoreClaudeOAuthToken, []byte(token)); err != nil {
			return err
		}
		fmt.Fprintln(out, "stored CLAUDE_CODE_OAUTH_TOKEN in keystore")
	case config.AuthMethodAPIKey:
		key := prompt(reader, out, "ANTHROPIC_API_KEY (input hidden)", "", promptEchoesNewline)
		if key == "" {
			return fmt.Errorf("API key required")
		}
		if err := store.Set(config.KeystoreClaudeAPIKey, []byte(key)); err != nil {
			return err
		}
		fmt.Fprintln(out, "stored ANTHROPIC_API_KEY in keystore")
	case config.AuthMethodSubscriptionOAuth:
		if err := runClaudeSubscriptionOAuth(reader, out, store, promptEchoesNewline); err != nil {
			return err
		}
	}

	if err := config.Save(path, cfg); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s (backend=%s)\n", path, store.Backend())
	return nil
}

// runClaudeSubscriptionOAuth executes the headless PKCE flow documented in
// docs/CLAUDE_OAUTH.md (plugin repo): generate a session, print the
// authorize URL for the operator to open in their browser, read back the
// code+state Anthropic's callback page displays, exchange for access +
// refresh tokens, and persist all three (access, refresh, expires_at)
// into the keystore.
//
// Shared between the TUI wizard (after form.Run) and the stdin wizard so
// the PKCE handoff looks identical in either mode. Keeping the terminal
// I/O here and the HTTP/crypto in internal/oauth/claude lets the oauth
// package stay stdlib-only and unit-testable without terminal mocks.
func runClaudeSubscriptionOAuth(reader *bufio.Reader, out io.Writer, store keys.Store, echoNewline bool) error {
	session, err := claudeoauth.NewSession()
	if err != nil {
		return err
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Open this URL in your browser to authorize telepath against your Claude subscription:")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  "+session.AuthURL)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "After signing in, Anthropic will show a page containing your authorization code.")
	fmt.Fprintln(out, "Paste the full `code#state` string (or the whole callback URL) below.")
	fmt.Fprintln(out)

	raw := prompt(reader, out, "Authorization code", "", echoNewline)
	code, stateFromInput, err := claudeoauth.ParseCallbackInput(raw)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tokens, err := claudeoauth.ExchangeCode(ctx, session, code, stateFromInput)
	if err != nil {
		return fmt.Errorf("subscription OAuth exchange: %w", err)
	}

	if err := store.Set(config.KeystoreClaudeSubAccessToken, []byte(tokens.AccessToken)); err != nil {
		return err
	}
	if tokens.RefreshToken != "" {
		if err := store.Set(config.KeystoreClaudeSubRefreshToken, []byte(tokens.RefreshToken)); err != nil {
			return err
		}
	}
	if err := store.Set(config.KeystoreClaudeSubExpiresAt, []byte(tokens.ExpiresAt.Format(time.RFC3339))); err != nil {
		return err
	}

	if email := claudeoauth.LookupEmail(ctx, tokens.AccessToken); email != "" {
		fmt.Fprintf(out, "Connected as %s.\n", email)
	}
	fmt.Fprintf(out, "Stored subscription OAuth tokens in keystore (backend=%s).\n", store.Backend())
	fmt.Fprintf(out, "Access token expires at %s; `telepath claude` will refresh before expiry.\n",
		tokens.ExpiresAt.Format(time.RFC3339))
	return nil
}

// captureClaudeOAuthToken delegates to Claude Code's own `claude
// setup-token` flow when available. claude takes over the terminal,
// prints an auth URL, waits for the browser handoff, and emits the
// one-year OAuth token on stdout — same UX as running
// `claude setup-token` directly on the CLI. We then prompt the
// operator to paste the token back into telepath.
//
// When claude is NOT on PATH, we point the operator at the one-liner
// to install it. They re-run `telepath config init` once it's
// available. Automation (non-interactive) skips the subprocess
// entirely and requires the token on stdin.
func captureClaudeOAuthToken(r *bufio.Reader, out, errOut io.Writer, opts configInitOpts, echoNewline bool) (string, error) {
	if opts.interactive {
		if _, err := exec.LookPath("claude"); err != nil {
			fmt.Fprintln(out)
			fmt.Fprintln(out, "Claude Code (the `claude` CLI) isn't on your PATH. Install it first, then re-run:")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "  curl -fsSL https://claude.ai/install.sh | bash")
			fmt.Fprintln(out, "  telepath config init")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "Or paste an existing CLAUDE_CODE_OAUTH_TOKEN below to skip the handoff.")
		} else {
			fmt.Fprintln(out)
			fmt.Fprintln(out, "Launching `claude setup-token` — sign in when the browser opens, and claude will print your token when done.")
			fmt.Fprintln(out)
			cmd := exec.Command("claude", "setup-token")
			cmd.Stdin = os.Stdin
			cmd.Stdout = out
			cmd.Stderr = errOut
			if err := cmd.Run(); err != nil {
				return "", fmt.Errorf("claude setup-token: %w", err)
			}
			fmt.Fprintln(out)
			fmt.Fprintln(out, "Paste the token claude just printed into the prompt below.")
		}
	}
	token := strings.TrimSpace(prompt(r, out, "CLAUDE_CODE_OAUTH_TOKEN", "", echoNewline))
	if token == "" {
		return "", fmt.Errorf("token required")
	}
	return token, nil
}

// prompt asks the user for a single line of input. Default value returned
// when the user presses enter without typing. echoNewline=true emits a
// trailing newline when the input was empty — compensates for piped stdin
// not echoing the user's enter key (TTYs always do, so they pass false).
func prompt(r *bufio.Reader, out io.Writer, label, def string, echoNewline bool) string {
	if def == "" {
		fmt.Fprintf(out, "%s: ", label)
	} else {
		fmt.Fprintf(out, "%s [%s]: ", label, def)
	}
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		if echoNewline {
			fmt.Fprintln(out)
		}
		return def
	}
	line = strings.TrimRight(line, "\r\n")
	if echoNewline {
		fmt.Fprintln(out)
	}
	if line == "" {
		return def
	}
	return line
}
