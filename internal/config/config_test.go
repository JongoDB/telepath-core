package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSave_RoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	// Missing file -> empty Config, no error.
	c, err := Load(path)
	if err != nil {
		t.Fatalf("load missing: %v", err)
	}
	if c.Operator.Name != "" {
		t.Errorf("expected empty, got %+v", c)
	}

	c.Operator.Name = "alex"
	c.Operator.Email = "a@fsc.example"
	c.Claude.AuthMethod = AuthMethodOAuthToken
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}

	c2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Operator.Name != "alex" || c2.Operator.Email != "a@fsc.example" || c2.Claude.AuthMethod != AuthMethodOAuthToken {
		t.Errorf("round trip mismatch: %+v", c2)
	}
}

func TestGetSet(t *testing.T) {
	t.Parallel()
	c := &Config{}
	if err := Set(c, "operator.name", "Alex"); err != nil {
		t.Fatal(err)
	}
	if got := Get(c, "operator.name"); got != "Alex" {
		t.Errorf("got %q", got)
	}
	if err := Set(c, "bogus.key", "x"); err == nil {
		t.Errorf("expected error for unknown key")
	}
	if err := Set(c, "claude.auth_method", "bad"); err == nil {
		t.Errorf("expected error for bad auth method")
	}
	if err := Set(c, "claude.auth_method", "api-key"); err != nil {
		t.Fatal(err)
	}
	if Get(c, "claude.auth_method") != "api-key" {
		t.Errorf("auth method not set")
	}
}

func TestNormalizeSelectedMethod(t *testing.T) {
	t.Parallel()
	cases := map[string]AuthMethod{
		"1":                  AuthMethodOAuthToken,
		"OAUTH":              AuthMethodOAuthToken,
		" oauth-token ":      AuthMethodOAuthToken,
		"2":                  AuthMethodAPIKey,
		"api-key":            AuthMethodAPIKey,
		"3":                  AuthMethodSubscriptionOAuth,
		"subscription":       AuthMethodSubscriptionOAuth,
		"subscription-oauth": AuthMethodSubscriptionOAuth,
	}
	for in, want := range cases {
		got, err := NormalizeSelectedMethod(in)
		if err != nil {
			t.Errorf("input %q: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("input %q: got %q, want %q", in, got, want)
		}
	}
	if _, err := NormalizeSelectedMethod("zzz"); err == nil {
		t.Errorf("expected error for unknown input")
	}
}

func TestKeystoreSlotForMethod(t *testing.T) {
	t.Parallel()
	if KeystoreSlotForMethod(AuthMethodOAuthToken) != KeystoreClaudeOAuthToken {
		t.Errorf("oauth-token slot wrong")
	}
	if KeystoreSlotForMethod(AuthMethodAPIKey) != KeystoreClaudeAPIKey {
		t.Errorf("api-key slot wrong")
	}
	if KeystoreSlotForMethod(AuthMethodSubscriptionOAuth) != KeystoreClaudeSubAccessToken {
		t.Errorf("subscription slot wrong")
	}
	if KeystoreSlotForMethod("unknown") != "" {
		t.Errorf("unknown should return empty")
	}
}

func TestSave_WritesMode600(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	c := &Config{Operator: OperatorConfig{Name: "x"}}
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 0600", fi.Mode().Perm())
	}
}
