// Package saas is the generic OAuth 2.0 + PKCE client for third-party
// SaaS providers (Microsoft 365, Google Workspace, Salesforce) used by
// telepath's read-class adapters (email, files, SOQL). Shape mirrors
// internal/oauth/claude but is provider-agnostic — each provider's
// specifics live in a Provider struct the caller passes in.
//
// v0.1 scope: PKCE-S256 authorize-URL generation, code exchange, and
// refresh. No loopback HTTP listener (headless operator flow) —
// operators paste the authorization code back into the CLI / TUI the
// same way the claude subscription OAuth flow works.
//
// CredentialID is the keystore slot where the token bundle lives. Pick
// deterministic slot names per provider + tenant so "operator has two
// M365 engagements against different tenants" doesn't collide.
package saas

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Provider describes one SaaS identity provider (M365, Google, Salesforce,
// etc.). Fields mirror the standard OAuth 2.0 authorize/token endpoint
// shape; per-provider oddities go in ExtraAuthParams (e.g., Salesforce's
// "response_type=code&prompt=login"). Scopes is a space-separated list on
// the wire per RFC 6749 §3.3.
type Provider struct {
	Name             string
	AuthorizeURL     string
	TokenURL         string
	Scopes           []string
	RedirectURI      string
	ExtraAuthParams  map[string]string
	ExtraTokenParams map[string]string
}

// Session bundles the PKCE state that survives between AuthURL generation
// and ExchangeCode. Callers hold it in memory only; nothing touches disk.
type Session struct {
	Provider  Provider
	ClientID  string
	Verifier  string
	State     string
	AuthURL   string
}

// Tokens is the parsed token endpoint response. ExpiresAt is computed
// client-side from expires_in + time.Now so callers can compare without
// needing the server's clock.
type Tokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type,omitempty"`
	Scope        string    `json:"scope,omitempty"`
}

// NewSession builds a fresh PKCE Session for clientID against provider.
// Returns the authorize URL the operator should open in a browser.
func NewSession(provider Provider, clientID string) (*Session, error) {
	if clientID == "" {
		return nil, errors.New("saas: client_id required")
	}
	if provider.AuthorizeURL == "" || provider.TokenURL == "" {
		return nil, errors.New("saas: provider endpoints incomplete")
	}
	verifier, err := randomBase64URL(32)
	if err != nil {
		return nil, fmt.Errorf("saas: generate verifier: %w", err)
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return nil, fmt.Errorf("saas: generate state: %w", err)
	}
	state := hex.EncodeToString(stateBytes)

	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", provider.RedirectURI)
	q.Set("scope", strings.Join(provider.Scopes, " "))
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	for k, v := range provider.ExtraAuthParams {
		q.Set(k, v)
	}

	return &Session{
		Provider: provider,
		ClientID: clientID,
		Verifier: verifier,
		State:    state,
		AuthURL:  provider.AuthorizeURL + "?" + q.Encode(),
	}, nil
}

// ParseCallbackInput accepts any of the three shapes the callback display
// produces: a full URL (code + state as query params), "code#state", or
// a bare authorization code. Returns (code, stateFromInput). Empty
// stateFromInput means the caller supplied a bare code — skip the state
// match check in that case.
func ParseCallbackInput(raw string) (code, stateFromInput string, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", "", errors.New("saas: empty input")
	}
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		u, perr := url.Parse(trimmed)
		if perr != nil {
			return "", "", fmt.Errorf("saas: parse URL: %w", perr)
		}
		return u.Query().Get("code"), u.Query().Get("state"), nil
	}
	if idx := strings.Index(trimmed, "#"); idx >= 0 {
		return trimmed[:idx], trimmed[idx+1:], nil
	}
	return trimmed, "", nil
}

// ExchangeCode POSTs the authorization code + verifier to the token
// endpoint and returns access + refresh tokens.
func ExchangeCode(ctx context.Context, s *Session, code, stateFromInput, clientSecret string) (*Tokens, error) {
	if s == nil {
		return nil, errors.New("saas: nil session")
	}
	if code == "" {
		return nil, errors.New("saas: empty code")
	}
	if stateFromInput != "" && stateFromInput != s.State {
		return nil, errors.New("saas: state mismatch (possible CSRF; start over)")
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", s.Provider.RedirectURI)
	form.Set("client_id", s.ClientID)
	form.Set("code_verifier", s.Verifier)
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	for k, v := range s.Provider.ExtraTokenParams {
		form.Set(k, v)
	}
	return postToken(ctx, s.Provider.TokenURL, form)
}

// Refresh exchanges a refresh_token for a new access + refresh pair.
// Anthropic-style providers may rotate the refresh_token; if absent in
// the response, the caller's old refresh token is preserved. clientSecret
// is optional (confidential clients only).
func Refresh(ctx context.Context, provider Provider, clientID, refreshToken, clientSecret string) (*Tokens, error) {
	if refreshToken == "" {
		return nil, errors.New("saas: empty refresh_token")
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", clientID)
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	for k, v := range provider.ExtraTokenParams {
		form.Set(k, v)
	}
	tok, err := postToken(ctx, provider.TokenURL, form)
	if err != nil {
		return nil, err
	}
	if tok.RefreshToken == "" {
		tok.RefreshToken = refreshToken
	}
	return tok, nil
}

// postToken issues the form-encoded POST the OAuth token endpoint
// expects and decodes the response. Accept both RFC-standard JSON
// (content-type application/json) and providers that still use
// application/x-www-form-urlencoded for the response (rare but Salesforce
// historically did it).
func postToken(ctx context.Context, tokenURL string, form url.Values) (*Tokens, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("saas: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("saas: token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("saas: token exchange failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	var parsed struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("saas: decode token response: %w", err)
	}
	if parsed.AccessToken == "" {
		return nil, errors.New("saas: token response contained no access_token")
	}
	expires := parsed.ExpiresIn
	if expires <= 0 {
		expires = 3600
	}
	return &Tokens{
		AccessToken:  parsed.AccessToken,
		RefreshToken: parsed.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(expires) * time.Second).UTC(),
		TokenType:    parsed.TokenType,
		Scope:        parsed.Scope,
	}, nil
}

func randomBase64URL(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
