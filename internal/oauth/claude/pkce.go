// Package claude implements the PKCE OAuth handoff for Anthropic
// subscription-OAuth tokens (Claude Pro/Max personal subscriptions). Port
// of the flow documented in ~/telepath-v2/docs/CLAUDE_OAUTH.md, derived
// from the production Next.js implementation in JongoDB/everest-ai at
// src/features/settings/actions/claude-oauth.ts.
//
// Flow shape (headless — no localhost callback):
//
//  1. telepath generates a PKCE code_verifier + code_challenge (S256) and
//     a random state. Verifier stays in memory; challenge + state go in
//     the authorize URL.
//  2. Operator opens the authorize URL in any browser, signs in with
//     their Claude account, and Anthropic redirects to
//     platform.claude.com/oauth/code/callback which renders the
//     authorization code as "<code>#<state>" on-page.
//  3. Operator pastes that back into telepath. We accept three formats:
//     full URL (code + state as query params), "code#state", or a bare
//     code.
//  4. telepath POSTs to the token endpoint with grant_type=
//     authorization_code, the verifier, and the state, receiving
//     access_token + refresh_token + expires_in.
//  5. Tokens are stored encrypted in the keystore; refresh is done
//     pre-emptively on use (5-minute pre-expiry window).
package claude

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

// These values match the everest-ai production implementation. Changing
// client_id or the URLs will break auth against Anthropic — update only
// when Anthropic publishes new endpoints.
//
// AuthorizeURL / TokenURL / RolesURL are vars (not consts) so test code
// can point them at an httptest.Server; production code never mutates.
const (
	ClientID    = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	RedirectURI = "https://platform.claude.com/oauth/code/callback"
	Scope       = "user:inference user:profile"
)

var (
	AuthorizeURL = "https://claude.com/cai/oauth/authorize"
	TokenURL     = "https://platform.claude.com/v1/oauth/token"
	RolesURL     = "https://api.anthropic.com/api/oauth/claude_cli/roles"
)

// Session bundles the PKCE state that survives between AuthURL() and
// ExchangeCode(). Callers hold it in memory only; nothing touches disk.
type Session struct {
	Verifier string
	State    string
	AuthURL  string
}

// NewSession generates a fresh PKCE session and returns the URL the
// operator should open in their browser plus the verifier/state the
// caller must pass back to ExchangeCode.
func NewSession() (*Session, error) {
	verifier, err := randomBase64URL(32)
	if err != nil {
		return nil, fmt.Errorf("claude oauth: generate verifier: %w", err)
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return nil, fmt.Errorf("claude oauth: generate state: %w", err)
	}
	state := hex.EncodeToString(stateBytes)

	q := url.Values{}
	q.Set("code", "true")
	q.Set("client_id", ClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", RedirectURI)
	q.Set("scope", Scope)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)

	return &Session{
		Verifier: verifier,
		State:    state,
		AuthURL:  AuthorizeURL + "?" + q.Encode(),
	}, nil
}

// Tokens is the parsed token endpoint response.
type Tokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// ParseCallbackInput accepts any of the three shapes the callback display
// produces: a full URL (contains `?code=...&state=...`), "code#state", or
// a bare authorization code. Returns (code, stateFromInput).
// stateFromInput is empty when the user supplies a bare code — the caller
// then skips the state-match check.
func ParseCallbackInput(raw string) (code, stateFromInput string, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", "", errors.New("claude oauth: empty input")
	}
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		u, perr := url.Parse(trimmed)
		if perr != nil {
			return "", "", fmt.Errorf("claude oauth: parse URL: %w", perr)
		}
		return u.Query().Get("code"), u.Query().Get("state"), nil
	}
	if idx := strings.Index(trimmed, "#"); idx >= 0 {
		return trimmed[:idx], trimmed[idx+1:], nil
	}
	return trimmed, "", nil
}

// ExchangeCode POSTs the authorization code + verifier to the token
// endpoint and returns the access + refresh tokens. Context timeout is
// honored.
func ExchangeCode(ctx context.Context, s *Session, code, stateFromInput string) (*Tokens, error) {
	if s == nil {
		return nil, errors.New("claude oauth: nil session")
	}
	if code == "" {
		return nil, errors.New("claude oauth: empty code")
	}
	// If the callback gave us a state, verify it matches.
	if stateFromInput != "" && stateFromInput != s.State {
		return nil, errors.New("claude oauth: state mismatch (possible CSRF; start over)")
	}

	body, err := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  RedirectURI,
		"client_id":     ClientID,
		"code_verifier": s.Verifier,
		"state":         s.State,
	})
	if err != nil {
		return nil, fmt.Errorf("claude oauth: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, TokenURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("claude oauth: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("claude oauth: token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("claude oauth: token exchange failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	var parsed struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("claude oauth: decode token response: %w", err)
	}
	if parsed.AccessToken == "" {
		return nil, errors.New("claude oauth: token response contained no access_token")
	}

	expires := parsed.ExpiresIn
	if expires <= 0 {
		expires = 3600
	}
	return &Tokens{
		AccessToken:  parsed.AccessToken,
		RefreshToken: parsed.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(expires) * time.Second).UTC(),
	}, nil
}

// LookupEmail calls the roles endpoint with the access token and parses
// the user-friendly email out of the organization_name field. Best-effort
// — a failure here just means we can't display the connected-as line.
// Matches everest's regex: the tenant name is usually
// "<email>'s Organization" for personal subs.
func LookupEmail(ctx context.Context, accessToken string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, RolesURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var payload struct {
		OrganizationName string `json:"organization_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return ""
	}
	name := strings.TrimSpace(strings.TrimSuffix(payload.OrganizationName, "'s Organization"))
	if strings.Contains(name, "@") {
		return name
	}
	return ""
}

// Refresh exchanges a refresh_token for a new access + refresh pair. On
// success, the returned Tokens has ExpiresAt computed from
// expires_in. Callers should atomically overwrite the stored credentials
// with the result.
func Refresh(ctx context.Context, refreshToken string) (*Tokens, error) {
	body, err := json.Marshal(map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     ClientID,
	})
	if err != nil {
		return nil, fmt.Errorf("claude oauth: marshal refresh: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, TokenURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("claude oauth: refresh request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("claude oauth: refresh failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	var parsed struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("claude oauth: decode refresh response: %w", err)
	}
	if parsed.AccessToken == "" {
		return nil, errors.New("claude oauth: refresh response contained no access_token")
	}
	// Anthropic may rotate the refresh token; if absent, reuse the old one.
	out := &Tokens{
		AccessToken:  parsed.AccessToken,
		RefreshToken: parsed.RefreshToken,
	}
	if out.RefreshToken == "" {
		out.RefreshToken = refreshToken
	}
	expires := parsed.ExpiresIn
	if expires <= 0 {
		expires = 3600
	}
	out.ExpiresAt = time.Now().Add(time.Duration(expires) * time.Second).UTC()
	return out, nil
}

// randomBase64URL returns n random bytes encoded as RawURL base64.
func randomBase64URL(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
