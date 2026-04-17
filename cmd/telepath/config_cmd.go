package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/fsc/telepath-core/internal/config"
	"github.com/fsc/telepath-core/internal/keys"
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
			fmt.Printf("operator.name     = %s\n", cfg.Operator.Name)
			fmt.Printf("operator.email    = %s\n", cfg.Operator.Email)
			fmt.Printf("claude.auth_method = %s\n", cfg.Claude.AuthMethod)
			fmt.Printf("config_path        = %s\n", config.DefaultPath())
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
			// Choose TUI vs stdin-wizard. Operators usually want the TUI;
			// pipelines, CI jobs, and automation want non-interactive.
			if nonInteractive || !stdinIsTerminal() {
				return runConfigInit(os.Stdin, cmd.OutOrStdout(), cmd.ErrOrStderr())
			}
			if err := runConfigInitTUI(cmd.OutOrStdout()); err != nil {
				// huh returns an error if the terminal can't start the
				// renderer for any reason. Fall back to the stdin path so
				// the user is never stuck.
				fmt.Fprintf(cmd.ErrOrStderr(), "TUI unavailable (%v); falling back to stdin prompts\n", err)
				return runConfigInit(os.Stdin, cmd.OutOrStdout(), cmd.ErrOrStderr())
			}
			return nil
		},
	}
	c.Flags().BoolVar(&nonInteractive, "non-interactive", false, "use line-by-line stdin prompts instead of the TUI")
	return c
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
		huh.NewGroup(
			huh.NewInput().
				Title("Token / API key (input hidden)").
				Description("For OAuth token: paste from `claude setup-token`. For API key: your Anthropic key. Leave empty to skip and capture later with `telepath config set`.").
				EchoMode(huh.EchoModePassword).
				Value(&token),
		).WithHideFunc(func() bool {
			// Subscription OAuth runs a PKCE flow that captures the token
			// itself in a later step (v0.2); v0.1 just records the choice.
			return method == config.AuthMethodSubscriptionOAuth
		}),
	)

	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return errors.New("cancelled")
		}
		return err
	}

	cfg.Operator.Name = strings.TrimSpace(name)
	cfg.Operator.Email = strings.TrimSpace(email)
	cfg.Claude.AuthMethod = method
	if err := config.Save(path, cfg); err != nil {
		return err
	}

	if token != "" && method != config.AuthMethodSubscriptionOAuth {
		store, err := keys.Open()
		if err != nil {
			return fmt.Errorf("keystore: %w", err)
		}
		slot := config.KeystoreSlotForMethod(method)
		if err := store.Set(slot, []byte(strings.TrimSpace(token))); err != nil {
			return err
		}
		fmt.Fprintf(out, "Stored %s in keystore (backend=%s).\n", slot, store.Backend())
	}

	fmt.Fprintf(out, "Config saved to %s.\n", path)
	if method == config.AuthMethodSubscriptionOAuth {
		fmt.Fprintln(out, "Subscription OAuth: the PKCE capture flow is designed in docs/CLAUDE_OAUTH.md; v0.1 records the method but does not yet open the browser. Re-run when v0.2 ships or use API key as a stopgap.")
	}
	return nil
}

// runConfigInit is the wizard. Split out of the cobra RunE so it can be
// exercised with in-process readers/writers in tests.
func runConfigInit(in io.Reader, out, errOut io.Writer) error {
	reader := bufio.NewReader(in)
	path := config.DefaultPath()

	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "telepath config init — operator identity + Claude Code auth")
	fmt.Fprintln(out, "Press enter to keep the existing value shown in [brackets].")

	cfg.Operator.Name = prompt(reader, out, "Operator name", cfg.Operator.Name)
	cfg.Operator.Email = prompt(reader, out, "Operator email", cfg.Operator.Email)

	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Claude Code auth method:")
	fmt.Fprintln(out, "  1) oauth-token         — `claude setup-token` one-year token (recommended for Claude Max/Team)")
	fmt.Fprintln(out, "  2) api-key             — ANTHROPIC_API_KEY from FSC's API account")
	fmt.Fprintln(out, "  3) subscription-oauth  — PKCE flow against your personal Claude Pro/Max subscription")

	def := "1"
	if cfg.Claude.AuthMethod != "" {
		def = string(cfg.Claude.AuthMethod)
	}
	choice := prompt(reader, out, "Choose [1-3 or name]", def)
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
		token, err := captureClaudeOAuthToken(reader, out, errOut)
		if err != nil {
			return err
		}
		if err := store.Set(config.KeystoreClaudeOAuthToken, []byte(token)); err != nil {
			return err
		}
		fmt.Fprintln(out, "stored CLAUDE_CODE_OAUTH_TOKEN in keystore")
	case config.AuthMethodAPIKey:
		key := prompt(reader, out, "ANTHROPIC_API_KEY (input hidden)", "")
		if key == "" {
			return fmt.Errorf("API key required")
		}
		if err := store.Set(config.KeystoreClaudeAPIKey, []byte(key)); err != nil {
			return err
		}
		fmt.Fprintln(out, "stored ANTHROPIC_API_KEY in keystore")
	case config.AuthMethodSubscriptionOAuth:
		fmt.Fprintln(out, "subscription OAuth setup not wired in v0.1 week 1-2; see docs/CLAUDE_OAUTH.md.")
		fmt.Fprintln(out, "for now, the auth method is recorded but no token was captured. Re-run `telepath config init`")
		fmt.Fprintln(out, "once the PKCE flow lands, or use --method api-key as a stopgap.")
	}

	if err := config.Save(path, cfg); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s (backend=%s)\n", path, store.Backend())
	return nil
}

// captureClaudeOAuthToken offers two paths: (1) invoke `claude setup-token`
// if the binary is on PATH; (2) prompt the operator to paste a token.
func captureClaudeOAuthToken(r *bufio.Reader, out, errOut io.Writer) (string, error) {
	if _, err := exec.LookPath("claude"); err == nil {
		choice := strings.ToLower(strings.TrimSpace(prompt(r, out, "Run `claude setup-token` for you? [Y/n]", "y")))
		if choice == "" || choice == "y" || choice == "yes" {
			cmd := exec.Command("claude", "setup-token")
			cmd.Stdin = os.Stdin
			cmd.Stdout = out
			cmd.Stderr = errOut
			if err := cmd.Run(); err != nil {
				return "", fmt.Errorf("claude setup-token: %w", err)
			}
			fmt.Fprintln(out, "(paste the token below)")
		}
	}
	token := strings.TrimSpace(prompt(r, out, "CLAUDE_CODE_OAUTH_TOKEN", ""))
	if token == "" {
		return "", fmt.Errorf("token required")
	}
	return token, nil
}

// prompt asks the user for a single line of input. If the user presses Enter
// without typing anything and def is non-empty, def is returned.
func prompt(r *bufio.Reader, out io.Writer, label, def string) string {
	if def == "" {
		fmt.Fprintf(out, "%s: ", label)
	} else {
		fmt.Fprintf(out, "%s [%s]: ", label, def)
	}
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return def
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return def
	}
	return line
}
