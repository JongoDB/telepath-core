package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fsc/telepath-core/internal/config"
	"github.com/fsc/telepath-core/internal/keys"
	claudeoauth "github.com/fsc/telepath-core/internal/oauth/claude"
)

// seed primes a file-backed keystore with a subscription-OAuth token
// set where ExpiresAt is offset from now by the given duration (negative
// for already-expired). Returns the Store so the test can inspect
// post-resolve state.
func seedSubscriptionStore(t *testing.T, expiresOffset time.Duration) keys.Store {
	t.Helper()
	store, err := keys.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if err := store.Set(config.KeystoreClaudeSubAccessToken, []byte("stored-access")); err != nil {
		t.Fatalf("seed access: %v", err)
	}
	if err := store.Set(config.KeystoreClaudeSubRefreshToken, []byte("stored-refresh")); err != nil {
		t.Fatalf("seed refresh: %v", err)
	}
	expires := time.Now().UTC().Add(expiresOffset).Format(time.RFC3339)
	if err := store.Set(config.KeystoreClaudeSubExpiresAt, []byte(expires)); err != nil {
		t.Fatalf("seed expires_at: %v", err)
	}
	return store
}

// mockTokenEndpoint spins up an httptest.Server that impersonates the
// Anthropic token endpoint for refresh requests. Captures the received
// refresh_token for assertion.
func mockTokenEndpoint(t *testing.T, access, refresh string, expiresIn int) (url string, received *map[string]string) {
	t.Helper()
	got := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Header().Set("Content-Type", "application/json")
		body := map[string]any{
			"access_token": access,
			"expires_in":   expiresIn,
		}
		if refresh != "" {
			body["refresh_token"] = refresh
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &got
}

func TestResolveClaudeCredential_APIKey(t *testing.T) {
	store, err := keys.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(config.KeystoreClaudeAPIKey, []byte("sk-ant-example")); err != nil {
		t.Fatal(err)
	}
	tok, env, err := resolveClaudeCredential(context.Background(), config.AuthMethodAPIKey, store, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if tok != "sk-ant-example" || env != "ANTHROPIC_API_KEY" {
		t.Errorf("got token=%q env=%q", tok, env)
	}
}

func TestResolveClaudeCredential_OAuthToken(t *testing.T) {
	store, err := keys.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(config.KeystoreClaudeOAuthToken, []byte("year-long-token")); err != nil {
		t.Fatal(err)
	}
	tok, env, err := resolveClaudeCredential(context.Background(), config.AuthMethodOAuthToken, store, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if tok != "year-long-token" || env != "CLAUDE_CODE_OAUTH_TOKEN" {
		t.Errorf("got token=%q env=%q", tok, env)
	}
}

func TestResolveClaudeCredential_SubscriptionFresh_NoRefresh(t *testing.T) {
	store := seedSubscriptionStore(t, 30*time.Minute) // well outside 5-min window
	warn := &bytes.Buffer{}
	tok, env, err := resolveClaudeCredential(context.Background(), config.AuthMethodSubscriptionOAuth, store, warn)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if tok != "stored-access" {
		t.Errorf("expected existing access token, got %q", tok)
	}
	if env != "CLAUDE_CODE_OAUTH_TOKEN" {
		t.Errorf("env = %q", env)
	}
	if warn.Len() != 0 {
		t.Errorf("expected no warnings, got %q", warn.String())
	}
}

func TestResolveClaudeCredential_SubscriptionNearExpiry_Refreshes(t *testing.T) {
	store := seedSubscriptionStore(t, 1*time.Minute) // inside 5-min window
	warn := &bytes.Buffer{}

	srvURL, received := mockTokenEndpoint(t, "fresh-access", "rotated-refresh", 3600)
	orig := claudeoauth.TokenURL
	claudeoauth.TokenURL = srvURL
	defer func() { claudeoauth.TokenURL = orig }()

	tok, _, err := resolveClaudeCredential(context.Background(), config.AuthMethodSubscriptionOAuth, store, warn)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if tok != "fresh-access" {
		t.Errorf("expected refreshed token, got %q", tok)
	}
	if (*received)["refresh_token"] != "stored-refresh" {
		t.Errorf("refresh endpoint received wrong refresh token: %v", *received)
	}
	// Persistence check: next call (still inside window? no — new ExpiresAt is
	// an hour out) should see the rotated refresh token and fresh access.
	got, _ := store.Get(config.KeystoreClaudeSubAccessToken)
	if string(got) != "fresh-access" {
		t.Errorf("access token not persisted: %q", got)
	}
	got, _ = store.Get(config.KeystoreClaudeSubRefreshToken)
	if string(got) != "rotated-refresh" {
		t.Errorf("rotated refresh token not persisted: %q", got)
	}
	if !strings.Contains(warn.String(), "refreshing") {
		t.Errorf("expected refreshing notice on stderr, got %q", warn.String())
	}
}

func TestResolveClaudeCredential_SubscriptionExpired_Refreshes(t *testing.T) {
	store := seedSubscriptionStore(t, -10*time.Minute) // already expired
	srvURL, _ := mockTokenEndpoint(t, "fresh-access", "", 3600)
	orig := claudeoauth.TokenURL
	claudeoauth.TokenURL = srvURL
	defer func() { claudeoauth.TokenURL = orig }()

	tok, _, err := resolveClaudeCredential(context.Background(), config.AuthMethodSubscriptionOAuth, store, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if tok != "fresh-access" {
		t.Errorf("expected refreshed token, got %q", tok)
	}
	// Endpoint omitted refresh_token → old one must be preserved on disk.
	got, _ := store.Get(config.KeystoreClaudeSubRefreshToken)
	if string(got) != "stored-refresh" {
		t.Errorf("expected preserved refresh, got %q", got)
	}
}

func TestResolveClaudeCredential_SubscriptionRefreshFailure_Surfaces(t *testing.T) {
	store := seedSubscriptionStore(t, -1*time.Minute)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()
	orig := claudeoauth.TokenURL
	claudeoauth.TokenURL = srv.URL
	defer func() { claudeoauth.TokenURL = orig }()

	_, _, err := resolveClaudeCredential(context.Background(), config.AuthMethodSubscriptionOAuth, store, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error on refresh failure")
	}
	if !strings.Contains(err.Error(), "refresh") {
		t.Errorf("error should mention refresh: %v", err)
	}
}
