package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fsc/telepath-core/internal/config"
	"github.com/fsc/telepath-core/internal/ipc"
	"github.com/fsc/telepath-core/internal/keys"
	"github.com/fsc/telepath-core/internal/oauth/saas"
	"github.com/fsc/telepath-core/pkg/schema"
)

// newOAuthTestDaemon spins up a daemon whose config.yaml lives in the
// test's tmpdir with m365.client_id pre-populated. Returns the daemon
// and the tmp root so tests can inspect keystore state on disk.
func newOAuthTestDaemon(t *testing.T) (*Daemon, string) {
	t.Helper()
	root := t.TempDir()
	cfgPath := filepath.Join(root, "config.yaml")
	cfgYAML := `operator:
  name: "Test Operator"
  email: "test@example.com"
claude:
  auth_method: api-key
oauth:
  m365:
    client_id: "m365-test-client"
  google:
    client_id: "google-test-client"
  salesforce:
    client_id: "sfdc-test-client"
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	store, err := keys.NewFileStore(filepath.Join(root, "keystore"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	sock := filepath.Join(root, "daemon.sock")
	d, err := New(Config{
		RootDir:     root,
		SocketPath:  sock,
		PIDFilePath: filepath.Join(root, "daemon.pid"),
		KeyStore:    store,
		ConfigPath:  cfgPath,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := d.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = d.Shutdown(ctx)
	})
	return d, root
}

// mockTokenServer spins up an httptest.Server that returns a canned
// token response. Captures the form-encoded payload for assertion.
func mockTokenServer(t *testing.T, access, refresh string, expiresIn int) (serverURL string, capturedForm func() url.Values) {
	t.Helper()
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		body := `{"access_token":"` + access + `","expires_in":` + itoa(expiresIn)
		if refresh != "" {
			body += `,"refresh_token":"` + refresh + `"`
		}
		body += `,"scope":"Mail.Read Files.Read.All"}`
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() url.Values { return got }
}

func itoa(n int) string {
	// stdlib strconv would do, but keeping test deps minimal.
	if n == 0 {
		return "0"
	}
	neg := ""
	if n < 0 {
		neg = "-"
		n = -n
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return neg + string(digits)
}

// rpcCall is a thin wrapper that returns (result bytes, rpc error or nil).
// ipc.Call returns the raw result on success and the error on failure; we
// just surface both so tests can assert error paths cleanly.
func rpcCall(t *testing.T, d *Daemon, method string, params any) (json.RawMessage, error) {
	t.Helper()
	return ipc.Call(d.SocketPath(), method, params)
}

func TestDaemon_OAuthBegin_UnknownProvider(t *testing.T) {
	d, _ := newOAuthTestDaemon(t)
	_, err := rpcCall(t, d, schema.MethodOAuthBegin, schema.OAuthBeginParams{Provider: "does-not-exist"})
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
	if !strings.Contains(err.Error(), "unknown provider") {
		t.Errorf("error = %v", err)
	}
}

func TestDaemon_OAuthBegin_MissingClientID(t *testing.T) {
	// Use a daemon whose config has no client_id at all.
	root := t.TempDir()
	cfgPath := filepath.Join(root, "config.yaml")
	// Empty oauth config → no client_id anywhere.
	if err := os.WriteFile(cfgPath, []byte("operator:\n  name: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, _ := keys.NewFileStore(filepath.Join(root, "ks"))
	d, err := New(Config{RootDir: root, SocketPath: filepath.Join(root, "s"), PIDFilePath: filepath.Join(root, "p"), KeyStore: store, ConfigPath: cfgPath})
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
	_, err = rpcCall(t, d, schema.MethodOAuthBegin, schema.OAuthBeginParams{Provider: "m365"})
	if err == nil {
		t.Fatal("expected missing-client-id error")
	}
	if !strings.Contains(err.Error(), "client_id") {
		t.Errorf("error should mention client_id: %v", err)
	}
}

func TestDaemon_OAuthBegin_HappyPath(t *testing.T) {
	d, _ := newOAuthTestDaemon(t)
	res, err := rpcCall(t, d, schema.MethodOAuthBegin, schema.OAuthBeginParams{Provider: "m365"})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	var out schema.OAuthBeginResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatal(err)
	}
	if !out.OK || out.SessionID == "" || out.AuthURL == "" {
		t.Fatalf("unexpected result: %+v", out)
	}
	u, err := url.Parse(out.AuthURL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("client_id") != "m365-test-client" {
		t.Errorf("client_id on auth URL = %q", u.Query().Get("client_id"))
	}
	if u.Query().Get("code_challenge_method") != "S256" {
		t.Errorf("challenge method = %q", u.Query().Get("code_challenge_method"))
	}
}

func TestDaemon_OAuthComplete_HappyPath(t *testing.T) {
	d, root := newOAuthTestDaemon(t)
	// Point the M365 TokenURL at our mock. saas.M365 is a package var; the
	// test saves/restores to avoid leaking the override to parallel tests.
	tokURL, captured := mockTokenServer(t, "fresh-access-token", "fresh-refresh-token", 3600)
	origTokenURL := saas.M365.TokenURL
	saas.M365.TokenURL = tokURL
	t.Cleanup(func() { saas.M365.TokenURL = origTokenURL })

	beginRes, err := rpcCall(t, d, schema.MethodOAuthBegin, schema.OAuthBeginParams{Provider: "m365", Tenant: "acme-prod"})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	var begin schema.OAuthBeginResult
	_ = json.Unmarshal(beginRes, &begin)

	// Pull the state from the auth URL so our paste-back has the right value.
	u, _ := url.Parse(begin.AuthURL)
	state := u.Query().Get("state")

	compRes, err := rpcCall(t, d, schema.MethodOAuthComplete, schema.OAuthCompleteParams{
		SessionID: begin.SessionID,
		Input:     "auth-code-from-browser#" + state,
	})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	var comp schema.OAuthCompleteResult
	if err := json.Unmarshal(compRes, &comp); err != nil {
		t.Fatal(err)
	}
	if comp.CredentialID != "oauth.m365.acme-prod" {
		t.Errorf("credential_id = %q", comp.CredentialID)
	}
	if comp.Provider != "m365" || comp.Tenant != "acme-prod" {
		t.Errorf("provider/tenant = %q/%q", comp.Provider, comp.Tenant)
	}
	if comp.Scope == "" {
		t.Errorf("scope should echo back from provider response")
	}

	// Form sent to token endpoint should carry the verifier + grant type.
	form := captured()
	if form.Get("grant_type") != "authorization_code" || form.Get("code") != "auth-code-from-browser" {
		t.Errorf("unexpected form: %v", form)
	}
	if form.Get("code_verifier") == "" {
		t.Errorf("verifier missing from token exchange form")
	}

	// Keystore should hold the four slot entries.
	ks, _ := keys.NewFileStore(filepath.Join(root, "keystore"))
	for suffix, want := range map[string]string{
		config.OAuthKeystoreSuffixAccessToken:  "fresh-access-token",
		config.OAuthKeystoreSuffixRefreshToken: "fresh-refresh-token",
	} {
		got, err := ks.Get("oauth.m365.acme-prod" + suffix)
		if err != nil {
			t.Errorf("keystore read %s: %v", suffix, err)
			continue
		}
		if string(got) != want {
			t.Errorf("keystore %s = %q want %q", suffix, got, want)
		}
	}
	if _, err := ks.Get("oauth.m365.acme-prod" + config.OAuthKeystoreSuffixExpiresAt); err != nil {
		t.Errorf("expires_at slot missing: %v", err)
	}
}

func TestDaemon_OAuthComplete_UnknownSession(t *testing.T) {
	d, _ := newOAuthTestDaemon(t)
	_, err := rpcCall(t, d, schema.MethodOAuthComplete, schema.OAuthCompleteParams{
		SessionID: "bogus-session-id",
		Input:     "abc123",
	})
	if err == nil || !strings.Contains(err.Error(), "unknown or expired") {
		t.Errorf("expected unknown-session error, got %v", err)
	}
}

func TestDaemon_OAuthComplete_ConsumesSessionOnSuccess(t *testing.T) {
	d, _ := newOAuthTestDaemon(t)
	tokURL, _ := mockTokenServer(t, "access", "refresh", 3600)
	origTokenURL := saas.M365.TokenURL
	saas.M365.TokenURL = tokURL
	t.Cleanup(func() { saas.M365.TokenURL = origTokenURL })

	begin, _ := rpcCall(t, d, schema.MethodOAuthBegin, schema.OAuthBeginParams{Provider: "m365"})
	var b schema.OAuthBeginResult
	_ = json.Unmarshal(begin, &b)
	u, _ := url.Parse(b.AuthURL)
	state := u.Query().Get("state")
	// First complete succeeds.
	if _, err := rpcCall(t, d, schema.MethodOAuthComplete, schema.OAuthCompleteParams{
		SessionID: b.SessionID, Input: "code#" + state,
	}); err != nil {
		t.Fatal(err)
	}
	// Second complete with same session must fail — code is single-use.
	if _, err := rpcCall(t, d, schema.MethodOAuthComplete, schema.OAuthCompleteParams{
		SessionID: b.SessionID, Input: "code#" + state,
	}); err == nil {
		t.Errorf("expected second complete to fail (session consumed)")
	}
}

func TestDaemon_OAuthComplete_ExpiredSession(t *testing.T) {
	d, _ := newOAuthTestDaemon(t)
	// Pre-populate a session with an expired createdAt.
	d.oauthMu.Lock()
	d.oauthSessions["old-session"] = &oauthPendingSession{
		sess:      &saas.Session{Verifier: "v", State: "s"},
		provider:  "m365",
		tenant:    "default",
		createdAt: time.Now().Add(-30 * time.Minute),
	}
	d.oauthMu.Unlock()
	_, err := rpcCall(t, d, schema.MethodOAuthComplete, schema.OAuthCompleteParams{
		SessionID: "old-session",
		Input:     "code",
	})
	if err == nil || !strings.Contains(err.Error(), "unknown or expired") {
		t.Errorf("expected expired-session error, got %v", err)
	}
}

func TestDaemon_OAuthStatus_NoConnections(t *testing.T) {
	d, _ := newOAuthTestDaemon(t)
	res, err := rpcCall(t, d, schema.MethodOAuthStatus, schema.OAuthStatusParams{})
	if err != nil {
		t.Fatal(err)
	}
	var out schema.OAuthStatusResult
	_ = json.Unmarshal(res, &out)
	if !out.OK {
		t.Errorf("OK=false")
	}
	if len(out.Connections) != 0 {
		t.Errorf("expected no connections, got %+v", out.Connections)
	}
}

func TestDaemon_OAuthStatus_ReportsConnectedAndExpired(t *testing.T) {
	d, _ := newOAuthTestDaemon(t)
	// Write a connection directly to the keystore so we don't need the
	// full begin/complete dance for this test.
	prefix := config.OAuthKeystorePrefix("m365", "") // default tenant
	_ = d.keys.Set(prefix+config.OAuthKeystoreSuffixAccessToken, []byte("at"))
	_ = d.keys.Set(prefix+config.OAuthKeystoreSuffixRefreshToken, []byte("rt"))
	future := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	_ = d.keys.Set(prefix+config.OAuthKeystoreSuffixExpiresAt, []byte(future))

	// Also one that is already expired.
	expPrefix := config.OAuthKeystorePrefix("google", "")
	_ = d.keys.Set(expPrefix+config.OAuthKeystoreSuffixAccessToken, []byte("old-at"))
	past := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	_ = d.keys.Set(expPrefix+config.OAuthKeystoreSuffixExpiresAt, []byte(past))

	res, err := rpcCall(t, d, schema.MethodOAuthStatus, schema.OAuthStatusParams{})
	if err != nil {
		t.Fatal(err)
	}
	var out schema.OAuthStatusResult
	_ = json.Unmarshal(res, &out)
	if len(out.Connections) != 2 {
		t.Fatalf("expected 2 connections, got %d: %+v", len(out.Connections), out.Connections)
	}
	byProvider := map[string]schema.OAuthConnection{}
	for _, c := range out.Connections {
		byProvider[c.Provider] = c
	}
	if m := byProvider["m365"]; m.Expired {
		t.Errorf("m365 should be live: %+v", m)
	}
	if g := byProvider["google"]; !g.Expired {
		t.Errorf("google should be expired: %+v", g)
	}
}

func TestDaemon_OAuthStatus_FiltersByProvider(t *testing.T) {
	d, _ := newOAuthTestDaemon(t)
	prefix := config.OAuthKeystorePrefix("m365", "")
	_ = d.keys.Set(prefix+config.OAuthKeystoreSuffixExpiresAt,
		[]byte(time.Now().Add(time.Hour).Format(time.RFC3339)))
	prefix2 := config.OAuthKeystorePrefix("google", "")
	_ = d.keys.Set(prefix2+config.OAuthKeystoreSuffixExpiresAt,
		[]byte(time.Now().Add(time.Hour).Format(time.RFC3339)))

	res, err := rpcCall(t, d, schema.MethodOAuthStatus, schema.OAuthStatusParams{Provider: "m365"})
	if err != nil {
		t.Fatal(err)
	}
	var out schema.OAuthStatusResult
	_ = json.Unmarshal(res, &out)
	if len(out.Connections) != 1 || out.Connections[0].Provider != "m365" {
		t.Errorf("filter failed: %+v", out.Connections)
	}
}

func TestDaemon_OAuthStatus_RejectsUnknownProvider(t *testing.T) {
	d, _ := newOAuthTestDaemon(t)
	_, err := rpcCall(t, d, schema.MethodOAuthStatus, schema.OAuthStatusParams{Provider: "nope"})
	if err == nil || !strings.Contains(err.Error(), "unknown provider") {
		t.Errorf("expected unknown-provider error, got %v", err)
	}
}
