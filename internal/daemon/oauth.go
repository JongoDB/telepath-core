package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fsc/telepath-core/internal/config"
	"github.com/fsc/telepath-core/internal/keys"
	"github.com/fsc/telepath-core/internal/oauth/saas"
	"github.com/fsc/telepath-core/internal/proxy/httpproxy"
	"github.com/fsc/telepath-core/pkg/schema"
)

// providerForName resolves the provider name ("m365" | "google" |
// "salesforce") to the matching saas.Provider template. Unknown
// providers are rejected at the handler boundary so typos don't silently
// construct a broken authorize URL.
func providerForName(name string) (saas.Provider, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "m365", "microsoft365", "microsoft", "azuread":
		return saas.M365, true
	case "google", "gworkspace", "google-workspace":
		return saas.Google, true
	case "salesforce", "sfdc":
		return saas.Salesforce, true
	}
	return saas.Provider{}, false
}

// resolveClientID returns the operator's ClientID for the given
// provider from config (or the override supplied directly on the RPC).
// Empty means "operator hasn't registered this provider" — handler
// returns a structured error that tells them where to add it.
func resolveClientID(cfg *config.Config, providerName, override string) string {
	if override != "" {
		return override
	}
	if cfg == nil {
		return ""
	}
	switch strings.ToLower(providerName) {
	case "m365":
		return cfg.OAuth.M365.ClientID
	case "google":
		return cfg.OAuth.Google.ClientID
	case "salesforce":
		return cfg.OAuth.Salesforce.ClientID
	}
	return ""
}

// resolveRedirectURI mirrors resolveClientID for the redirect_uri —
// operators may need to override the default when their registered app
// has a specific URI.
func resolveRedirectURI(cfg *config.Config, providerName string) string {
	if cfg == nil {
		return ""
	}
	switch strings.ToLower(providerName) {
	case "m365":
		return cfg.OAuth.M365.RedirectURI
	case "google":
		return cfg.OAuth.Google.RedirectURI
	case "salesforce":
		return cfg.OAuth.Salesforce.RedirectURI
	}
	return ""
}

// newSessionID returns a random hex identifier used to tag pending
// OAuth PKCE sessions. 16 bytes = 128 bits of entropy — plenty for a
// session that lives at most 15 minutes.
func newSessionID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("oauth: session id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// handleOAuthBegin starts a PKCE session. Requires the operator to have
// registered the provider's client_id in config. Returns the URL the
// operator should open in a browser plus a session_id they'll pass back
// to oauth.complete after signing in.
func (d *Daemon) handleOAuthBegin(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.OAuthBeginParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	provider, ok := providerForName(p.Provider)
	if !ok {
		return nil, rpcErr(schema.ErrCodeInvalidParams, "unknown provider: "+p.Provider)
	}
	// Load the operator config fresh on each call so a just-edited
	// config.yaml is picked up without restarting the daemon.
	cfgPath := d.cfg.ConfigPath
	if cfgPath == "" {
		cfgPath = config.DefaultPath()
	}
	cfg, _ := config.Load(cfgPath)
	clientID := resolveClientID(cfg, provider.Name, p.ClientID)
	if clientID == "" {
		return nil, rpcErr(schema.ErrCodeInvalidParams,
			"no client_id configured for provider "+provider.Name+
				"; set oauth."+provider.Name+".client_id in ~/.telepath/config.yaml")
	}
	if uri := resolveRedirectURI(cfg, provider.Name); uri != "" {
		provider.RedirectURI = uri
	}

	sess, err := saas.NewSession(provider, clientID)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	sid, err := newSessionID()
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}

	tenant := p.Tenant
	if tenant == "" {
		tenant = config.OAuthDefaultTenant
	}

	d.oauthMu.Lock()
	d.cleanExpiredOAuthSessionsLocked()
	d.oauthSessions[sid] = &oauthPendingSession{
		sess:      sess,
		provider:  provider.Name,
		tenant:    tenant,
		clientID:  clientID,
		createdAt: time.Now(),
	}
	d.oauthMu.Unlock()

	return encodeResult(schema.OAuthBeginResult{
		OK:        true,
		SessionID: sid,
		AuthURL:   sess.AuthURL,
		ExpiresAt: time.Now().Add(oauthSessionTTL).UTC().Format(time.RFC3339),
	})
}

// handleOAuthComplete trades the authorization code for tokens and
// writes them to the keystore under the provider+tenant prefix. The
// session is consumed — a successful complete deletes the in-memory
// entry so the one-time code can't be replayed.
func (d *Daemon) handleOAuthComplete(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.OAuthCompleteParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	if p.SessionID == "" || p.Input == "" {
		return nil, rpcErr(schema.ErrCodeInvalidParams, "session_id and input required")
	}
	d.oauthMu.Lock()
	d.cleanExpiredOAuthSessionsLocked()
	pending := d.oauthSessions[p.SessionID]
	// Delete up front — the code is single-use either way, and hanging
	// on to a pending session after a failure only encourages replays.
	delete(d.oauthSessions, p.SessionID)
	d.oauthMu.Unlock()
	if pending == nil {
		return nil, rpcErr(schema.ErrCodeInvalidParams, "unknown or expired session_id; run oauth.begin again")
	}

	code, state, err := saas.ParseCallbackInput(p.Input)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInvalidParams, err.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tok, err := saas.ExchangeCode(ctx, pending.sess, code, state, "")
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}

	prefix := config.OAuthKeystorePrefix(pending.provider, pending.tenant)
	if err := writeOAuthTokens(d.keys, prefix, tok); err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, "persist tokens: "+err.Error())
	}

	return encodeResult(schema.OAuthCompleteResult{
		OK:           true,
		CredentialID: prefix,
		Provider:     pending.provider,
		Tenant:       pending.tenant,
		ExpiresAt:    tok.ExpiresAt.UTC().Format(time.RFC3339),
		Scope:        tok.Scope,
	})
}

// handleOAuthStatus lists the connections recorded in the keystore,
// optionally filtered to a specific provider + tenant. Does not include
// any token material in the response — only identity + expiry.
func (d *Daemon) handleOAuthStatus(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.OAuthStatusParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	targets := []string{"m365", "google", "salesforce"}
	if p.Provider != "" {
		if _, ok := providerForName(p.Provider); !ok {
			return nil, rpcErr(schema.ErrCodeInvalidParams, "unknown provider: "+p.Provider)
		}
		targets = []string{strings.ToLower(p.Provider)}
	}
	// Initialize to an empty (not nil) slice so the JSON wire shape is
	// always `"connections":[]` rather than `null`. Hook libs + smoke
	// tests grep on the empty-array shape.
	conns := make([]schema.OAuthConnection, 0)
	for _, prov := range targets {
		// The keystore doesn't expose listing; we enumerate the tenants
		// the caller cares about. Either the caller named a tenant, or we
		// look for the default tenant. Multi-tenant operators who used
		// custom labels pass Tenant explicitly.
		tenants := []string{config.OAuthDefaultTenant}
		if p.Tenant != "" {
			tenants = []string{p.Tenant}
		}
		for _, t := range tenants {
			prefix := config.OAuthKeystorePrefix(prov, t)
			expRaw, err := d.keys.Get(prefix + config.OAuthKeystoreSuffixExpiresAt)
			if err != nil {
				continue // no connection for this provider+tenant
			}
			exp, perr := time.Parse(time.RFC3339, strings.TrimSpace(string(expRaw)))
			expired := false
			if perr != nil {
				// Malformed timestamp: treat as expired so the operator
				// re-authorizes rather than thinks the connection is live.
				expired = true
			} else {
				expired = time.Now().After(exp)
			}
			conns = append(conns, schema.OAuthConnection{
				Provider:  prov,
				Tenant:    t,
				ExpiresAt: strings.TrimSpace(string(expRaw)),
				Expired:   expired,
			})
		}
	}
	return encodeResult(schema.OAuthStatusResult{OK: true, Connections: conns})
}

// writeOAuthTokens persists the four slot entries atomically-enough for
// v0.1 (three separate keystore writes; an interruption leaves partial
// state that the status call flags as expired). Keeping the slots flat
// mirrors the claude subscription OAuth layout.
func writeOAuthTokens(store keys.Store, prefix string, tok *saas.Tokens) error {
	if err := store.Set(prefix+config.OAuthKeystoreSuffixAccessToken, []byte(tok.AccessToken)); err != nil {
		return err
	}
	if tok.RefreshToken != "" {
		if err := store.Set(prefix+config.OAuthKeystoreSuffixRefreshToken, []byte(tok.RefreshToken)); err != nil {
			return err
		}
	}
	if err := store.Set(prefix+config.OAuthKeystoreSuffixExpiresAt, []byte(tok.ExpiresAt.UTC().Format(time.RFC3339))); err != nil {
		return err
	}
	if tok.Scope != "" {
		if err := store.Set(prefix+config.OAuthKeystoreSuffixScope, []byte(tok.Scope)); err != nil {
			return err
		}
	}
	return nil
}

// cleanExpiredOAuthSessionsLocked evicts pending sessions older than
// oauthSessionTTL. Called at the top of every oauth handler so expiry
// is enforced lazily — no background goroutine, no allocations in the
// steady state. Caller must hold d.oauthMu.
func (d *Daemon) cleanExpiredOAuthSessionsLocked() {
	cutoff := time.Now().Add(-oauthSessionTTL)
	for id, s := range d.oauthSessions {
		if s.createdAt.Before(cutoff) {
			delete(d.oauthSessions, id)
		}
	}
}

// saasPreExpiryWindow mirrors the claude subscription window — 5 minutes
// is short enough that a slow daemon never hands out an already-expired
// token, long enough that the refresh HTTP call amortizes across many
// SaaS calls.
const saasPreExpiryWindow = 5 * time.Minute

// ensureFreshSaaSToken returns a non-expired access token for the
// provider+tenant pair, refreshing transparently when the stored token
// is within the pre-expiry window. Returns refreshed=true when a
// refresh happened so callers can surface that fact in audit events.
// Mirrors the claude subscription logic in cmd/telepath/claude_cmd.go;
// keeping them separate is deliberate (different keystore layout).
func (d *Daemon) ensureFreshSaaSToken(ctx context.Context, providerName, tenant string) (accessToken string, refreshed bool, err error) {
	provider, ok := providerForName(providerName)
	if !ok {
		return "", false, fmt.Errorf("saas: unknown provider %q", providerName)
	}
	prefix := config.OAuthKeystorePrefix(providerName, tenant)

	access, err := d.keys.Get(prefix + config.OAuthKeystoreSuffixAccessToken)
	if err != nil {
		return "", false, fmt.Errorf("saas: no access token for %s/%s; run `telepath oauth begin %s --tenant %s`",
			providerName, tenant, providerName, tenant)
	}
	expRaw, err := d.keys.Get(prefix + config.OAuthKeystoreSuffixExpiresAt)
	if err != nil {
		// Missing expires_at → treat as expired, refresh to be safe.
		expRaw = []byte(time.Now().UTC().Format(time.RFC3339))
	}
	expiresAt, perr := time.Parse(time.RFC3339, strings.TrimSpace(string(expRaw)))
	if perr != nil {
		return "", false, fmt.Errorf("saas: parse expires_at for %s/%s: %w", providerName, tenant, perr)
	}
	if time.Now().Add(saasPreExpiryWindow).Before(expiresAt) {
		return string(access), false, nil
	}

	// Pre-expiry or expired — refresh.
	refresh, err := d.keys.Get(prefix + config.OAuthKeystoreSuffixRefreshToken)
	if err != nil {
		return "", false, fmt.Errorf("saas: refresh token missing for %s/%s; re-run `telepath oauth begin %s --tenant %s`",
			providerName, tenant, providerName, tenant)
	}
	cfg, _ := config.Load(d.configPath())
	clientID := resolveClientID(cfg, providerName, "")
	if clientID == "" {
		return "", false, fmt.Errorf("saas: client_id not configured for %s; set oauth.%s.client_id in config.yaml",
			providerName, providerName)
	}
	if uri := resolveRedirectURI(cfg, providerName); uri != "" {
		provider.RedirectURI = uri
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	fresh, err := saas.Refresh(rctx, provider, clientID, string(refresh), "")
	if err != nil {
		return "", false, fmt.Errorf("saas: refresh %s/%s: %w", providerName, tenant, err)
	}
	if err := writeOAuthTokens(d.keys, prefix, fresh); err != nil {
		// Non-fatal: we have a valid access token in hand. Next call's
		// expiry read will re-trigger refresh which is costly but safe.
		d.logger.Warn("saas: persist refreshed tokens", "provider", providerName, "tenant", tenant, "err", err)
	}
	return fresh.AccessToken, true, nil
}

// configPath returns the daemon's config path — flag override when set
// on daemon.Config, else the canonical ~/.telepath/config.yaml.
func (d *Daemon) configPath() string {
	if d.cfg.ConfigPath != "" {
		return d.cfg.ConfigPath
	}
	return config.DefaultPath()
}

// handleSaaSRequest executes an authenticated HTTPS call against a
// SaaS provider. Token refresh is transparent. Scope is checked with
// protocol "https" against the URL host — operators list
// graph.microsoft.com / www.googleapis.com / etc. in their ROE
// allowed_hosts (same as http.request).
func (d *Daemon) handleSaaSRequest(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.SaaSRequestParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	if p.Provider == "" || p.URL == "" {
		return nil, rpcErr(schema.ErrCodeInvalidParams, "provider and url are required")
	}
	tenant := p.Tenant
	if tenant == "" {
		tenant = config.OAuthDefaultTenant
	}

	active, rpcE := d.requireActive()
	if rpcE != nil {
		return nil, rpcE
	}
	if rpcE := d.checkScope(active, p.URL, "https"); rpcE != nil {
		return nil, rpcE
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutFromSec(p.TimeoutSec, 30*time.Second))
	defer cancel()

	token, refreshed, err := d.ensureFreshSaaSToken(ctx, p.Provider, tenant)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}

	headers := map[string]string{}
	for k, v := range p.Headers {
		headers[k] = v
	}
	headers["Authorization"] = "Bearer " + token

	h := httpproxy.New(d.Transport())
	r, err := h.Do(ctx, httpproxy.Request{
		Method:  p.Method,
		URL:     p.URL,
		Headers: headers,
		Body:    p.Body,
		Timeout: timeoutFromSec(p.TimeoutSec, 30*time.Second),
	})
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	out := schema.SaaSRequestResult{
		OK:             true,
		Status:         r.Status,
		Headers:        r.Headers,
		Body:           r.Body,
		Truncated:      r.Truncated,
		DurationMs:     r.DurationMs,
		TokenRefreshed: refreshed,
	}
	d.auditMCPCall(active, "saas.request", map[string]any{
		"provider":        p.Provider,
		"tenant":          tenant,
		"method":          p.Method,
		"url":             p.URL,
		"status":          r.Status,
		"token_refreshed": refreshed,
	})
	return encodeResult(out)
}

// handleSaaSRefresh forces a refresh now. Useful for operators who want
// to guarantee a long session starts with a fresh token, or for the
// post-hoc "my last call failed, let me retry after explicit refresh"
// recovery path.
func (d *Daemon) handleSaaSRefresh(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.SaaSRefreshParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	if p.Provider == "" {
		return nil, rpcErr(schema.ErrCodeInvalidParams, "provider is required")
	}
	tenant := p.Tenant
	if tenant == "" {
		tenant = config.OAuthDefaultTenant
	}
	provider, ok := providerForName(p.Provider)
	if !ok {
		return nil, rpcErr(schema.ErrCodeInvalidParams, "unknown provider: "+p.Provider)
	}
	prefix := config.OAuthKeystorePrefix(p.Provider, tenant)
	refresh, err := d.keys.Get(prefix + config.OAuthKeystoreSuffixRefreshToken)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInvalidParams, "no refresh token for "+p.Provider+"/"+tenant)
	}
	cfg, _ := config.Load(d.configPath())
	clientID := resolveClientID(cfg, p.Provider, "")
	if clientID == "" {
		return nil, rpcErr(schema.ErrCodeInvalidParams, "client_id not configured for "+p.Provider)
	}
	if uri := resolveRedirectURI(cfg, p.Provider); uri != "" {
		provider.RedirectURI = uri
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fresh, err := saas.Refresh(ctx, provider, clientID, string(refresh), "")
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	if err := writeOAuthTokens(d.keys, prefix, fresh); err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, "persist refreshed tokens: "+err.Error())
	}
	return encodeResult(schema.SaaSRefreshResult{
		OK:          true,
		ExpiresAt:   fresh.ExpiresAt.UTC().Format(time.RFC3339),
		RefreshedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

// Satisfy go vet when no OAuth handler actually references saas directly
// beyond the ones in this file (keeps the import alive during refactors).
var _ = errors.New
