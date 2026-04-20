package claude

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestNewSession_AuthURLShape(t *testing.T) {
	t.Parallel()
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if s.Verifier == "" || s.State == "" {
		t.Fatalf("empty verifier/state: %+v", s)
	}
	u, err := url.Parse(s.AuthURL)
	if err != nil {
		t.Fatalf("auth URL invalid: %v", err)
	}
	q := u.Query()
	if q.Get("client_id") != ClientID {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("wrong challenge method")
	}
	if q.Get("redirect_uri") != RedirectURI {
		t.Errorf("redirect_uri = %q", q.Get("redirect_uri"))
	}
	if q.Get("scope") != Scope {
		t.Errorf("scope = %q", q.Get("scope"))
	}
	if q.Get("state") != s.State {
		t.Errorf("state missing from URL")
	}
	if q.Get("code_challenge") == "" {
		t.Errorf("missing code_challenge")
	}
}

func TestParseCallbackInput(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in             string
		wantCode       string
		wantState      string
		wantErr        bool
	}{
		{"abc123", "abc123", "", false},
		{"abc123#state-xyz", "abc123", "state-xyz", false},
		{"https://platform.claude.com/oauth/code/callback?code=abc123&state=state-xyz", "abc123", "state-xyz", false},
		{"  abc123#state-xyz  ", "abc123", "state-xyz", false},
		{"", "", "", true},
	}
	for _, c := range cases {
		code, state, err := ParseCallbackInput(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("input %q: err=%v, wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if !c.wantErr {
			if code != c.wantCode {
				t.Errorf("input %q: code = %q want %q", c.in, code, c.wantCode)
			}
			if state != c.wantState {
				t.Errorf("input %q: state = %q want %q", c.in, state, c.wantState)
			}
		}
	}
}

func TestExchangeCode_HappyPath(t *testing.T) {
	// Intentionally serial: mutates the package-global TokenURL.
	// t.Parallel with TestRefresh_HappyPath + TestExchangeCode_ServerError
	// raced and flaked ~80% of runs before this change.
	s, _ := NewSession()
	mockCode := "testcode"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var got map[string]string
		_ = json.Unmarshal(body, &got)
		if got["grant_type"] != "authorization_code" || got["code"] != mockCode || got["code_verifier"] != s.Verifier {
			t.Errorf("token request body mismatch: %v", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "at-" + mockCode,
			"refresh_token": "rt-" + mockCode,
			"expires_in":    3600,
		})
	}))
	defer srv.Close()

	// Override TokenURL via the exchange with a mock-aware client path;
	// here we patch the URL via an internal override by directly calling
	// the mock via an httptest.Server-hosted client. Simpler: temporarily
	// replace TokenURL.
	orig := TokenURL
	setTokenURL(srv.URL)
	defer setTokenURL(orig)

	tok, err := ExchangeCode(context.Background(), s, mockCode, s.State)
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if tok.AccessToken != "at-"+mockCode {
		t.Errorf("access = %q", tok.AccessToken)
	}
	if tok.RefreshToken != "rt-"+mockCode {
		t.Errorf("refresh = %q", tok.RefreshToken)
	}
	if tok.ExpiresAt.Before(time.Now()) {
		t.Errorf("expires_at should be in the future")
	}
}

func TestExchangeCode_StateMismatch(t *testing.T) {
	t.Parallel()
	s, _ := NewSession()
	// Don't hit the mock server; ExchangeCode rejects the state mismatch
	// before issuing an HTTP request.
	_, err := ExchangeCode(context.Background(), s, "code", "wrong-state")
	if err == nil || !strings.Contains(err.Error(), "state mismatch") {
		t.Errorf("expected state mismatch error, got %v", err)
	}
}

func TestRefresh_HappyPath(t *testing.T) {
	// Serial — mutates package-global TokenURL.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fresh-access",
			// Refresh token omitted — caller should re-use the old one.
			"expires_in": 3600,
		})
	}))
	defer srv.Close()
	orig := TokenURL
	setTokenURL(srv.URL)
	defer setTokenURL(orig)

	tok, err := Refresh(context.Background(), "old-refresh")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if tok.AccessToken != "fresh-access" {
		t.Errorf("access = %q", tok.AccessToken)
	}
	if tok.RefreshToken != "old-refresh" {
		t.Errorf("expected old refresh preserved, got %q", tok.RefreshToken)
	}
}

func TestExchangeCode_ServerError(t *testing.T) {
	// Serial — mutates package-global TokenURL.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()
	orig := TokenURL
	setTokenURL(srv.URL)
	defer setTokenURL(orig)

	s, _ := NewSession()
	_, err := ExchangeCode(context.Background(), s, "code", s.State)
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Errorf("expected 400 error, got %v", err)
	}
}
