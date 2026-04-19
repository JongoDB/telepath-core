package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsc/telepath-core/internal/config"
	"github.com/fsc/telepath-core/internal/engagement"
	"github.com/fsc/telepath-core/internal/ipc"
	"github.com/fsc/telepath-core/internal/keys"
	"github.com/fsc/telepath-core/internal/oauth/saas"
	"github.com/fsc/telepath-core/pkg/schema"
)

// setupSaaSDaemon spins a daemon with an active engagement whose ROE
// allows HTTPS against the hosts used in the tests. Tokens are seeded
// directly into the keystore so the tests don't have to run begin+complete
// first. Returns the daemon and the keystore (for inspection).
func setupSaaSDaemon(t *testing.T, apiHost string, tokenExpiresOffset time.Duration) (*Daemon, keys.Store) {
	t.Helper()
	root := t.TempDir()
	cfgPath := filepath.Join(root, "config.yaml")
	cfgYAML := `operator:
  name: test
oauth:
  m365:
    client_id: m365-test-client
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := keys.NewFileStore(filepath.Join(root, "keystore"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := New(Config{
		RootDir:     root,
		SocketPath:  filepath.Join(root, "daemon.sock"),
		PIDFilePath: filepath.Join(root, "daemon.pid"),
		KeyStore:    store,
		ConfigPath:  cfgPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = d.Shutdown(ctx)
	})

	// Create + load an engagement with a permissive ROE for the test API host.
	if _, err := d.manager.Create(engagement.CreateParams{ID: "eng-saas", ClientName: "C", AssessmentType: "t"}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.manager.Load("eng-saas"); err != nil {
		t.Fatal(err)
	}
	// hosts matches SSH/WinRM-style bare hostname targets; domains matches
	// URL targets after scheme/path/port are stripped. Including both so
	// the scope check passes for both a literal host and a full URL of
	// the same host.
	roeYAML := fmt.Sprintf(`engagement_id: eng-saas
version: 1
in_scope:
  hosts: ["%s"]
  domains: ["%s"]
allowed_protocols: [https]
`, apiHost, apiHost)
	if _, err := ipc.Call(d.SocketPath(), schema.MethodEngagementSetROE, schema.EngagementSetROEParams{ID: "eng-saas", YAML: roeYAML}); err != nil {
		t.Fatal(err)
	}

	// Seed tokens.
	prefix := config.OAuthKeystorePrefix("m365", "default")
	_ = store.Set(prefix+config.OAuthKeystoreSuffixAccessToken, []byte("seeded-access"))
	_ = store.Set(prefix+config.OAuthKeystoreSuffixRefreshToken, []byte("seeded-refresh"))
	_ = store.Set(prefix+config.OAuthKeystoreSuffixExpiresAt, []byte(time.Now().Add(tokenExpiresOffset).UTC().Format(time.RFC3339)))
	return d, store
}

func TestDaemon_SaaSRequest_FreshToken_InjectsAuthHeader(t *testing.T) {
	var receivedAuth atomic.Value
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth.Store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[{"id":"1"}]}`))
	}))
	defer apiSrv.Close()
	apiURL, _ := url.Parse(apiSrv.URL)

	d, _ := setupSaaSDaemon(t, apiURL.Hostname(), 30*time.Minute)

	res, err := ipc.Call(d.SocketPath(), schema.MethodSaaSRequest, schema.SaaSRequestParams{
		Provider: "m365",
		Method:   "GET",
		URL:      apiSrv.URL + "/v1.0/me/drive/root/children",
	})
	if err != nil {
		t.Fatalf("saas.request: %v", err)
	}
	var out schema.SaaSRequestResult
	_ = json.Unmarshal(res, &out)
	if out.Status != 200 {
		t.Errorf("status = %d", out.Status)
	}
	if out.TokenRefreshed {
		t.Errorf("fresh token should not trigger refresh")
	}
	if got := receivedAuth.Load(); got != "Bearer seeded-access" {
		t.Errorf("auth header = %q, want %q", got, "Bearer seeded-access")
	}
}

func TestDaemon_SaaSRequest_NearExpiry_AutoRefreshes(t *testing.T) {
	// Mock token endpoint: saas.M365.TokenURL gets pointed here.
	var tokenCalls atomic.Int64
	tokSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		tokenCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"fresh-access","refresh_token":"rotated-refresh","expires_in":3600}`))
	}))
	defer tokSrv.Close()
	origTok := saas.M365.TokenURL
	saas.M365.TokenURL = tokSrv.URL
	t.Cleanup(func() { saas.M365.TokenURL = origTok })

	// API server should receive the FRESH access token, not the seeded one.
	var receivedAuth atomic.Value
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth.Store(r.Header.Get("Authorization"))
		_, _ = w.Write([]byte("ok"))
	}))
	defer apiSrv.Close()
	apiURL, _ := url.Parse(apiSrv.URL)

	// Token expires in 1 minute — inside the 5-minute pre-expiry window.
	d, store := setupSaaSDaemon(t, apiURL.Hostname(), 1*time.Minute)

	res, err := ipc.Call(d.SocketPath(), schema.MethodSaaSRequest, schema.SaaSRequestParams{
		Provider: "m365",
		Method:   "GET",
		URL:      apiSrv.URL + "/",
	})
	if err != nil {
		t.Fatalf("saas.request: %v", err)
	}
	var out schema.SaaSRequestResult
	_ = json.Unmarshal(res, &out)
	if !out.TokenRefreshed {
		t.Errorf("expected TokenRefreshed=true for near-expiry token")
	}
	if got := receivedAuth.Load(); got != "Bearer fresh-access" {
		t.Errorf("auth header = %q, want Bearer fresh-access", got)
	}
	if tokenCalls.Load() != 1 {
		t.Errorf("expected exactly one token endpoint call, got %d", tokenCalls.Load())
	}

	// Keystore should now hold the rotated refresh + fresh access.
	got, _ := store.Get(config.OAuthKeystorePrefix("m365", "default") + config.OAuthKeystoreSuffixAccessToken)
	if string(got) != "fresh-access" {
		t.Errorf("access not persisted: %q", got)
	}
	got, _ = store.Get(config.OAuthKeystorePrefix("m365", "default") + config.OAuthKeystoreSuffixRefreshToken)
	if string(got) != "rotated-refresh" {
		t.Errorf("rotated refresh not persisted: %q", got)
	}
}

func TestDaemon_SaaSRequest_Expired_NoRefresh_Errors(t *testing.T) {
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer apiSrv.Close()
	apiURL, _ := url.Parse(apiSrv.URL)
	d, store := setupSaaSDaemon(t, apiURL.Hostname(), -10*time.Minute)
	// Remove the seeded refresh token to simulate "operator never got
	// a refresh token from the original grant" (Google's quirk when
	// the re-consent prompt isn't forced).
	_ = store.Delete(config.OAuthKeystorePrefix("m365", "default") + config.OAuthKeystoreSuffixRefreshToken)

	_, err := ipc.Call(d.SocketPath(), schema.MethodSaaSRequest, schema.SaaSRequestParams{
		Provider: "m365",
		Method:   "GET",
		URL:      apiSrv.URL + "/",
	})
	if err == nil {
		t.Fatal("expected error when refresh token missing and access expired")
	}
	if !strings.Contains(err.Error(), "refresh") {
		t.Errorf("error should mention refresh: %v", err)
	}
}

func TestDaemon_SaaSRequest_NotConnected_Errors(t *testing.T) {
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer apiSrv.Close()
	apiURL, _ := url.Parse(apiSrv.URL)

	d, store := setupSaaSDaemon(t, apiURL.Hostname(), time.Hour)
	// Remove the access token so the handler hits the "not connected"
	// branch.
	_ = store.Delete(config.OAuthKeystorePrefix("m365", "default") + config.OAuthKeystoreSuffixAccessToken)

	_, err := ipc.Call(d.SocketPath(), schema.MethodSaaSRequest, schema.SaaSRequestParams{
		Provider: "m365",
		Method:   "GET",
		URL:      apiSrv.URL + "/",
	})
	if err == nil || !strings.Contains(err.Error(), "no access token") {
		t.Errorf("expected no-access-token error, got %v", err)
	}
}

func TestDaemon_SaaSRequest_ScopeDenied(t *testing.T) {
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer apiSrv.Close()
	// ROE is populated for "api.in-scope.example" but we call the
	// httptest server which lives at 127.0.0.1 — should be denied.
	d, _ := setupSaaSDaemon(t, "api.in-scope.example", time.Hour)
	_, err := ipc.Call(d.SocketPath(), schema.MethodSaaSRequest, schema.SaaSRequestParams{
		Provider: "m365",
		Method:   "GET",
		URL:      apiSrv.URL + "/",
	})
	if err == nil || !strings.Contains(err.Error(), "scope") {
		t.Errorf("expected scope-denied error, got %v", err)
	}
}

func TestDaemon_SaaSRefresh_HappyPath(t *testing.T) {
	tokSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"rf-access","refresh_token":"rf-rt","expires_in":7200}`))
	}))
	defer tokSrv.Close()
	origTok := saas.M365.TokenURL
	saas.M365.TokenURL = tokSrv.URL
	t.Cleanup(func() { saas.M365.TokenURL = origTok })

	d, store := setupSaaSDaemon(t, "unused.example", time.Hour)

	res, err := ipc.Call(d.SocketPath(), schema.MethodSaaSRefresh, schema.SaaSRefreshParams{
		Provider: "m365",
	})
	if err != nil {
		t.Fatalf("saas.refresh: %v", err)
	}
	var out schema.SaaSRefreshResult
	_ = json.Unmarshal(res, &out)
	if !out.OK || out.ExpiresAt == "" {
		t.Errorf("unexpected result: %+v", out)
	}
	// Verify keystore now has the fresh access.
	got, _ := store.Get(config.OAuthKeystorePrefix("m365", "default") + config.OAuthKeystoreSuffixAccessToken)
	if string(got) != "rf-access" {
		t.Errorf("access = %q", got)
	}
}

func TestDaemon_SaaSRefresh_MissingRefreshToken(t *testing.T) {
	d, store := setupSaaSDaemon(t, "x.example", time.Hour)
	_ = store.Delete(config.OAuthKeystorePrefix("m365", "default") + config.OAuthKeystoreSuffixRefreshToken)

	_, err := ipc.Call(d.SocketPath(), schema.MethodSaaSRefresh, schema.SaaSRefreshParams{Provider: "m365"})
	if err == nil || !strings.Contains(err.Error(), "refresh token") {
		t.Errorf("expected missing-refresh-token error, got %v", err)
	}
}

func TestDaemon_SaaSRefresh_UnknownProvider(t *testing.T) {
	d, _ := setupSaaSDaemon(t, "x.example", time.Hour)
	_, err := ipc.Call(d.SocketPath(), schema.MethodSaaSRefresh, schema.SaaSRefreshParams{Provider: "nope"})
	if err == nil || !strings.Contains(err.Error(), "unknown provider") {
		t.Errorf("expected unknown-provider error, got %v", err)
	}
}
