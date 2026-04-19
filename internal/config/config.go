// Package config manages telepath-core's operator-level configuration
// (~/.telepath/config.yaml). Sensitive values (OAuth tokens, API keys,
// engagement symmetric keys) live in the keystore, NOT this file; the config
// only records identity-ish metadata and the auth method the operator chose.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// AuthMethod is the kind of Claude Code authentication the operator uses.
type AuthMethod string

// Supported auth methods. Subscription OAuth is accepted as a value even in
// v0.1 week 1-2; the full PKCE flow lands in week 4 per docs/CLAUDE_OAUTH.md.
const (
	AuthMethodOAuthToken       AuthMethod = "oauth-token"
	AuthMethodAPIKey           AuthMethod = "api-key"
	AuthMethodSubscriptionOAuth AuthMethod = "subscription-oauth"
)

// Config is the shape of ~/.telepath/config.yaml.
type Config struct {
	Operator OperatorConfig `yaml:"operator"`
	Claude   ClaudeConfig   `yaml:"claude"`
	OAuth    OAuthConfig    `yaml:"oauth,omitempty"`
}

// OperatorConfig holds operator identity metadata.
type OperatorConfig struct {
	Name  string `yaml:"name,omitempty"`
	Email string `yaml:"email,omitempty"`
}

// ClaudeConfig holds metadata about the chosen Claude Code auth method.
// The actual secret lives in the keystore.
type ClaudeConfig struct {
	AuthMethod AuthMethod `yaml:"auth_method,omitempty"`
}

// OAuthConfig holds per-provider OAuth 2.0 client registrations. The
// ClientID is public information (lives safely in the yaml file); any
// confidential client_secret belongs in the keystore under the
// oauth.<provider>.client_secret slot and is loaded from there at token
// exchange time. v0.1 is public-client-only — PKCE authenticates without
// a secret; add secret-loading if we need confidential clients in v0.2.
type OAuthConfig struct {
	M365       ProviderConfig `yaml:"m365,omitempty"`
	Google     ProviderConfig `yaml:"google,omitempty"`
	Salesforce ProviderConfig `yaml:"salesforce,omitempty"`
}

// ProviderConfig is the per-provider client registration. An operator
// registers an app in each SaaS tenant, copies the client_id here, and
// (optionally) overrides the default redirect_uri if their app doesn't
// accept the default http://localhost:0/callback.
type ProviderConfig struct {
	ClientID    string `yaml:"client_id,omitempty"`
	RedirectURI string `yaml:"redirect_uri,omitempty"`
}

// DefaultPath returns ~/.telepath/config.yaml.
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", "telepath-config.yaml")
	}
	return filepath.Join(home, ".telepath", "config.yaml")
}

// Load reads config from path. A missing file returns an empty Config with
// no error — that's the "not initialized yet" state.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	return &c, nil
}

// Save atomically writes config to path.
func Save(path string, c *Config) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("config: mkdir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("config: write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("config: rename: %w", err)
	}
	return nil
}

// Get returns the string value at a dotted key ("operator.name",
// "claude.auth_method"). Returns empty string if the key does not exist.
func Get(c *Config, dotted string) string {
	switch dotted {
	case "operator.name":
		return c.Operator.Name
	case "operator.email":
		return c.Operator.Email
	case "claude.auth_method":
		return string(c.Claude.AuthMethod)
	default:
		return ""
	}
}

// Set mutates c in place for a dotted key. Unknown keys return an error so
// typos don't silently disappear into the abyss.
func Set(c *Config, dotted, value string) error {
	switch dotted {
	case "operator.name":
		c.Operator.Name = value
	case "operator.email":
		c.Operator.Email = value
	case "claude.auth_method":
		m := AuthMethod(value)
		switch m {
		case AuthMethodOAuthToken, AuthMethodAPIKey, AuthMethodSubscriptionOAuth:
			c.Claude.AuthMethod = m
		default:
			return fmt.Errorf("config: unknown auth method %q (want oauth-token|api-key|subscription-oauth)", value)
		}
	default:
		return fmt.Errorf("config: unknown key %q", dotted)
	}
	return nil
}

// KnownKeys returns the dotted keys callers can pass to Get/Set.
func KnownKeys() []string {
	return []string{"operator.name", "operator.email", "claude.auth_method"}
}

// Keystore slot names used by the wizard and by `telepath claude`.
const (
	KeystoreClaudeOAuthToken      = "claude.oauth_token"
	KeystoreClaudeAPIKey          = "claude.api_key"
	KeystoreClaudeSubAccessToken  = "claude.subscription_access_token"
	KeystoreClaudeSubRefreshToken = "claude.subscription_refresh_token"
	// RFC3339 timestamp stored next to the subscription tokens; the claude
	// subcommand reads this before picking a token and refreshes when it
	// falls within a 5-minute pre-expiry window.
	KeystoreClaudeSubExpiresAt = "claude.subscription_expires_at"
)

// Default tenant label used when a caller doesn't supply one on an
// OAuth begin/complete call. Operators working against a single SaaS
// tenant per provider never need to set this; operators with multiple
// tenants supply distinct labels so the slots don't collide.
const OAuthDefaultTenant = "default"

// OAuthKeystorePrefix returns the keystore slot prefix for the given
// provider + tenant. Actual slot names append `.access_token`,
// `.refresh_token`, `.expires_at`, `.scope` to this prefix. Callers
// treat empty tenant as the default label — single source of truth.
func OAuthKeystorePrefix(provider, tenant string) string {
	if tenant == "" {
		tenant = OAuthDefaultTenant
	}
	return "oauth." + provider + "." + tenant
}

// Suffixes used under the OAuthKeystorePrefix. Kept here as constants so
// the daemon, the status handler, and future refresh-on-use paths all
// read from the same names.
const (
	OAuthKeystoreSuffixAccessToken  = ".access_token"
	OAuthKeystoreSuffixRefreshToken = ".refresh_token"
	OAuthKeystoreSuffixExpiresAt    = ".expires_at"
	OAuthKeystoreSuffixScope        = ".scope"
)

// KeystoreSlotForMethod returns the primary keystore slot name for the
// token associated with the given method, or "" for unknown methods.
func KeystoreSlotForMethod(m AuthMethod) string {
	switch m {
	case AuthMethodOAuthToken:
		return KeystoreClaudeOAuthToken
	case AuthMethodAPIKey:
		return KeystoreClaudeAPIKey
	case AuthMethodSubscriptionOAuth:
		return KeystoreClaudeSubAccessToken
	default:
		return ""
	}
}

// EnvVarForMethod returns the environment variable that Claude Code expects
// to hold the credential of the given method. Subscription OAuth currently
// uses CLAUDE_CODE_OAUTH_TOKEN per everest-ai's implementation of the same
// token type. If Claude Code ships a separate variable in the future, update
// here.
func EnvVarForMethod(m AuthMethod) string {
	switch m {
	case AuthMethodOAuthToken, AuthMethodSubscriptionOAuth:
		return "CLAUDE_CODE_OAUTH_TOKEN"
	case AuthMethodAPIKey:
		return "ANTHROPIC_API_KEY"
	default:
		return ""
	}
}

// NormalizeSelectedMethod makes Set a bit friendlier for the wizard.
func NormalizeSelectedMethod(choice string) (AuthMethod, error) {
	s := strings.TrimSpace(strings.ToLower(choice))
	switch s {
	case "1", "oauth", "oauth-token", "oauth_token":
		return AuthMethodOAuthToken, nil
	case "2", "api", "api-key", "api_key":
		return AuthMethodAPIKey, nil
	case "3", "sub", "subscription", "subscription-oauth":
		return AuthMethodSubscriptionOAuth, nil
	default:
		return "", fmt.Errorf("unknown choice %q", choice)
	}
}
