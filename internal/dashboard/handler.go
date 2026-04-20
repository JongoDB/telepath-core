package dashboard

import (
	"encoding/json"
	"net/http"
)

// cookieName is the session cookie the dashboard sets once an operator
// opens the tokenized URL. All subsequent requests from the same tab
// carry the cookie so the token doesn't stay in the address bar.
const cookieName = "telepath_dash"

// Handler is the HTTP handler group the dashboard server exposes. Split
// out of Server so tests can hit individual endpoints via httptest.
//
// Token is the bearer credential required on every endpoint except
// /healthz. Empty Token disables auth (test-only mode — production
// Server.Start always populates it). Clients can supply the token
// three ways: `?t=<token>` query param (bootstraps the cookie on the
// first hit), `Cookie: telepath_dash=<token>`, or
// `Authorization: Bearer <token>` header for scripted clients.
type Handler struct {
	Fetcher Fetcher
	Token   string
}

// ServeHTTP routes the small number of dashboard endpoints. Keeps paths
// hand-registered so there's no framework opacity — operators who pop
// curl at the port see exactly what's there.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// /healthz stays unauthenticated so ops probes work without the
	// token. It reveals nothing operational.
	if r.URL.Path == "/healthz" {
		h.healthz(w, r)
		return
	}
	if !h.authorize(w, r) {
		return
	}
	switch r.URL.Path {
	case "/api/state":
		h.apiState(w, r)
	case "/", "/index.html", "/app.css", "/app.js":
		h.staticHandler(w, r)
	default:
		http.NotFound(w, r)
	}
}

// authorize verifies the caller presented the bearer token. Returns
// true when authorized (and, if the token came from ?t=, refreshes the
// session cookie so subsequent requests don't need the query param).
// Writes a 401 response on failure.
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) bool {
	if h.Token == "" {
		// No token configured — test mode. Caller opted out.
		return true
	}
	if t := r.URL.Query().Get("t"); t == h.Token {
		setSessionCookie(w, h.Token)
		return true
	}
	if c, err := r.Cookie(cookieName); err == nil && c.Value == h.Token {
		return true
	}
	if got := r.Header.Get("Authorization"); got == "Bearer "+h.Token {
		return true
	}
	// Keep the message actionable: an operator who lost the URL
	// should know restarting the dashboard prints a fresh one.
	http.Error(w, "unauthorized — restart `telepath dashboard` and open the tokenized URL it prints\n", http.StatusUnauthorized)
	return false
}

// setSessionCookie writes the telepath_dash cookie after a successful
// token match. Session-scoped (no Expires) so the cookie is cleared
// when the browser closes. HttpOnly + SameSite=Strict close the easy
// exfil paths. Secure is left off because we serve plain HTTP on
// localhost — when v0.4 adds HTTPS for remote dashboards the flag
// gets set based on the request's scheme.
func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// healthz is the liveness endpoint. Returns 200 unconditionally so
// orchestration / browser auto-reload logic can probe without
// disturbing daemon state.
func (h *Handler) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

// apiState returns the aggregated State as JSON. Always HTTP 200 — a
// unreachable daemon surfaces as State.Daemon == nil + a warning, not
// an HTTP error, so the browser's polling loop can keep rendering.
func (h *Handler) apiState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	s := Aggregate(h.Fetcher)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Cache-Control: no-store makes Firefox / Safari / Chrome treat
	// the polling response as fresh on every hit. Without it, some
	// proxies or local dev caches can freeze the dashboard on stale
	// state between refreshes.
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(s)
}
