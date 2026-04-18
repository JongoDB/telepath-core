package saas

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// stubProvider yields a Provider whose URLs are a hypothetical vendor —
// rewritten per-test to point at an httptest.Server for the token endpoint.
func stubProvider() Provider {
	return Provider{
		Name:         "stub",
		AuthorizeURL: "https://auth.example.com/oauth/authorize",
		TokenURL:     "https://auth.example.com/oauth/token",
		RedirectURI:  "http://localhost:0/cb",
		Scopes:       []string{"read", "offline_access"},
		ExtraAuthParams: map[string]string{
			"prompt": "consent",
		},
	}
}

func TestNewSession_AuthURLShape(t *testing.T) {
	t.Parallel()
	s, err := NewSession(stubProvider(), "client-123")
	if err != nil {
		t.Fatal(err)
	}
	if s.Verifier == "" || s.State == "" {
		t.Fatalf("empty verifier/state: %+v", s)
	}
	u, err := url.Parse(s.AuthURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("client_id") != "client-123" {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("challenge method = %q", q.Get("code_challenge_method"))
	}
	if q.Get("scope") != "read offline_access" {
		t.Errorf("scope = %q", q.Get("scope"))
	}
	if q.Get("prompt") != "consent" {
		t.Errorf("extra auth param 'prompt' not set: %q", q.Get("prompt"))
	}
	if q.Get("state") != s.State {
		t.Errorf("state URL mismatch")
	}
}

func TestNewSession_ValidatesInputs(t *testing.T) {
	t.Parallel()
	if _, err := NewSession(stubProvider(), ""); err == nil {
		t.Errorf("expected empty client_id error")
	}
	p := Provider{Name: "broken"}
	if _, err := NewSession(p, "c"); err == nil {
		t.Errorf("expected provider-endpoint error")
	}
}

func TestParseCallbackInput(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, wantCode, wantState string }{
		{"abc123", "abc123", ""},
		{"abc123#state-xyz", "abc123", "state-xyz"},
		{"https://example.com/cb?code=abc123&state=xyz", "abc123", "xyz"},
		{"  abc123#xyz  ", "abc123", "xyz"},
	}
	for _, c := range cases {
		code, state, err := ParseCallbackInput(c.in)
		if err != nil {
			t.Errorf("input %q unexpected error: %v", c.in, err)
			continue
		}
		if code != c.wantCode || state != c.wantState {
			t.Errorf("input %q: got (%q,%q) want (%q,%q)", c.in, code, state, c.wantCode, c.wantState)
		}
	}
	if _, _, err := ParseCallbackInput(""); err == nil {
		t.Errorf("expected error for empty input")
	}
}

func TestExchangeCode_HappyPath(t *testing.T) {
	t.Parallel()
	p := stubProvider()
	var captured url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		captured = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","refresh_token":"rt","expires_in":3600}`))
	}))
	defer srv.Close()
	p.TokenURL = srv.URL

	s, _ := NewSession(p, "client-123")
	tok, err := ExchangeCode(context.Background(), s, "the-code", s.State, "")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if tok.AccessToken != "at" || tok.RefreshToken != "rt" {
		t.Errorf("tokens = %+v", tok)
	}
	if tok.ExpiresAt.Before(time.Now()) {
		t.Errorf("expires_at should be in the future")
	}
	if captured.Get("code_verifier") != s.Verifier {
		t.Errorf("verifier not sent: %q", captured.Get("code_verifier"))
	}
	if captured.Get("grant_type") != "authorization_code" {
		t.Errorf("grant_type = %q", captured.Get("grant_type"))
	}
}

func TestExchangeCode_StateMismatch(t *testing.T) {
	t.Parallel()
	s, _ := NewSession(stubProvider(), "c")
	_, err := ExchangeCode(context.Background(), s, "code", "not-the-real-state", "")
	if err == nil || !strings.Contains(err.Error(), "state mismatch") {
		t.Errorf("expected state mismatch, got %v", err)
	}
}

func TestRefresh_RotatesTokenWhenProviderIssuesOne(t *testing.T) {
	t.Parallel()
	p := stubProvider()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-at","refresh_token":"rotated","expires_in":1800}`))
	}))
	defer srv.Close()
	p.TokenURL = srv.URL

	tok, err := Refresh(context.Background(), p, "client-123", "old-rt", "")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if tok.AccessToken != "new-at" {
		t.Errorf("access = %q", tok.AccessToken)
	}
	if tok.RefreshToken != "rotated" {
		t.Errorf("expected rotated refresh token, got %q", tok.RefreshToken)
	}
}

func TestRefresh_PreservesOldTokenWhenProviderOmits(t *testing.T) {
	t.Parallel()
	p := stubProvider()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-at","expires_in":1800}`))
	}))
	defer srv.Close()
	p.TokenURL = srv.URL

	tok, err := Refresh(context.Background(), p, "client-123", "old-rt", "")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if tok.RefreshToken != "old-rt" {
		t.Errorf("expected old refresh preserved, got %q", tok.RefreshToken)
	}
}

func TestRefresh_ServerError(t *testing.T) {
	t.Parallel()
	p := stubProvider()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()
	p.TokenURL = srv.URL

	_, err := Refresh(context.Background(), p, "c", "rt", "")
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("expected 401 error, got %v", err)
	}
}

func TestProviders_CatalogURLs(t *testing.T) {
	t.Parallel()
	// Sanity check the hardcoded templates so a careless edit that blanks
	// a URL can't ship silently. These are bit-patterned vendor endpoints;
	// if the vendor changes them, operators will notice via refresh errors
	// and we'll pin the new URL here.
	for _, p := range []Provider{M365, Google, Salesforce} {
		if p.AuthorizeURL == "" || p.TokenURL == "" {
			t.Errorf("provider %s has empty endpoint(s)", p.Name)
		}
		if len(p.Scopes) == 0 {
			t.Errorf("provider %s has no default scopes", p.Name)
		}
	}
	if !strings.Contains(Google.ExtraAuthParams["access_type"], "offline") {
		t.Errorf("Google provider must request offline access for refresh tokens")
	}
}
