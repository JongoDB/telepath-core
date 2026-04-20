package dashboard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fsc/telepath-core/pkg/schema"
)

func TestHandler_Healthz(t *testing.T) {
	t.Parallel()
	h := &Handler{Fetcher: &fakeFetcher{}}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Errorf("status = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "ok") {
		t.Errorf("body = %q", rr.Body.String())
	}
}

func TestHandler_APIState_ReturnsJSON(t *testing.T) {
	t.Parallel()
	f := &fakeFetcher{
		responses: map[string]json.RawMessage{
			schema.MethodPing:            rawJSON(schema.PingResult{OK: true, Version: "0.1.22"}),
			schema.MethodEngagementGet:   rawJSON(schema.EngagementGetResult{OK: true}),
			schema.MethodTransportStatus: rawJSON(schema.TransportStatusResult{OK: true, Status: schema.TransportStatus{State: "down"}}),
			schema.MethodOAuthStatus:     rawJSON(schema.OAuthStatusResult{OK: true}),
		},
	}
	h := &Handler{Fetcher: f}
	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Errorf("status = %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type = %q", ct)
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("cache-control = %q", cc)
	}
	var out State
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Daemon == nil || out.Daemon.Version != "0.1.22" {
		t.Errorf("daemon = %+v", out.Daemon)
	}
}

func TestHandler_APIState_DaemonDownStillReturns200(t *testing.T) {
	t.Parallel()
	// Unreachable daemon → Aggregate returns an empty State with a
	// warning, but the HTTP layer still responds 200 so the browser's
	// polling loop keeps trying. This test is the contract guardrail.
	h := &Handler{Fetcher: &fakeFetcher{}}
	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Errorf("status = %d", rr.Code)
	}
	var out State
	_ = json.NewDecoder(rr.Body).Decode(&out)
	if len(out.Warnings) == 0 {
		t.Errorf("expected warning about daemon unreachable")
	}
}

func TestHandler_APIState_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := &Handler{Fetcher: &fakeFetcher{}}
	req := httptest.NewRequest(http.MethodPost, "/api/state", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHandler_UnknownPath_Returns404(t *testing.T) {
	t.Parallel()
	h := &Handler{Fetcher: &fakeFetcher{}}
	req := httptest.NewRequest(http.MethodGet, "/nope", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 404 {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// TestServer_StartShutdown wires the full Server lifecycle against a
// fake Fetcher and proves /api/state is reachable via an actual HTTP
// client. Exercises the production auth path — Start generates a
// token, URL() bakes it in, first request sets the session cookie,
// subsequent requests ride the cookie.
func TestServer_StartShutdown(t *testing.T) {
	t.Parallel()
	f := &fakeFetcher{
		responses: map[string]json.RawMessage{
			schema.MethodPing:            rawJSON(schema.PingResult{OK: true, Version: "v-test"}),
			schema.MethodEngagementGet:   rawJSON(schema.EngagementGetResult{OK: true}),
			schema.MethodTransportStatus: rawJSON(schema.TransportStatusResult{OK: true, Status: schema.TransportStatus{State: "down"}}),
			schema.MethodOAuthStatus:     rawJSON(schema.OAuthStatusResult{OK: true}),
		},
	}
	srv, err := Start(Config{Fetcher: f})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Shutdown(testCtx(t))

	if srv.Token == "" {
		t.Fatal("Server.Token should be populated without DisableAuth")
	}

	// /api/state via the tokenized URL (?t=...) — proves the bootstrap
	// query-param path works end-to-end through the real handler chain.
	resp, err := http.Get("http://" + srv.Addr + "/api/state?t=" + srv.Token)
	if err != nil {
		t.Fatalf("GET /api/state?t=: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "v-test") {
		t.Errorf("body missing daemon version: %s", body)
	}

	// Unauthenticated caller gets 401 regardless of which interface
	// the dashboard's listening on.
	unauth, err := http.Get("http://" + srv.Addr + "/api/state")
	if err != nil {
		t.Fatalf("unauthed GET: %v", err)
	}
	defer unauth.Body.Close()
	if unauth.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthed status = %d, want 401", unauth.StatusCode)
	}
}

// TestServer_DisableAuth_SkipsTokenCheck pins the test-only escape
// hatch so the DisableAuth flag keeps working for handler/state tests.
func TestServer_DisableAuth_SkipsTokenCheck(t *testing.T) {
	t.Parallel()
	f := &fakeFetcher{
		responses: map[string]json.RawMessage{
			schema.MethodPing:            rawJSON(schema.PingResult{OK: true, Version: "v-noauth"}),
			schema.MethodEngagementGet:   rawJSON(schema.EngagementGetResult{OK: true}),
			schema.MethodTransportStatus: rawJSON(schema.TransportStatusResult{OK: true, Status: schema.TransportStatus{State: "down"}}),
			schema.MethodOAuthStatus:     rawJSON(schema.OAuthStatusResult{OK: true}),
		},
	}
	srv, err := Start(Config{Fetcher: f, DisableAuth: true})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Shutdown(testCtx(t))
	if srv.Token != "" {
		t.Errorf("Token should be empty when DisableAuth: %q", srv.Token)
	}
	resp, err := http.Get(srv.URL() + "/api/state")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestHandler_StaticAssets_Root_ReturnsHTML(t *testing.T) {
	t.Parallel()
	h := &Handler{Fetcher: &fakeFetcher{}}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Errorf("status = %d", rr.Code)
	}
	if !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/html") {
		t.Errorf("content-type = %q", rr.Header().Get("Content-Type"))
	}
	body := rr.Body.String()
	// Sanity: the index.html must reference the CSS + JS assets so
	// the browser loads them. A regression that strips those links
	// would break the dashboard silently.
	if !strings.Contains(body, "/app.css") || !strings.Contains(body, "/app.js") {
		t.Errorf("index.html missing asset references: %s", body)
	}
	if !strings.Contains(body, "engagement-bar") {
		t.Errorf("index.html missing engagement-bar element (UI would be blank)")
	}
}

func TestHandler_StaticAssets_CSS(t *testing.T) {
	t.Parallel()
	h := &Handler{Fetcher: &fakeFetcher{}}
	req := httptest.NewRequest(http.MethodGet, "/app.css", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Errorf("status = %d", rr.Code)
	}
	if !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/css") {
		t.Errorf("content-type = %q", rr.Header().Get("Content-Type"))
	}
	if !strings.Contains(rr.Body.String(), ".card") {
		t.Errorf("app.css missing .card rule")
	}
}

func TestHandler_StaticAssets_JS(t *testing.T) {
	t.Parallel()
	h := &Handler{Fetcher: &fakeFetcher{}}
	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Errorf("status = %d", rr.Code)
	}
	if !strings.HasPrefix(rr.Header().Get("Content-Type"), "application/javascript") {
		t.Errorf("content-type = %q", rr.Header().Get("Content-Type"))
	}
	body := rr.Body.String()
	if !strings.Contains(body, "/api/state") {
		t.Errorf("app.js missing polling endpoint reference")
	}
	// Regression guard: the app uses DOM-building helpers rather
	// than innerHTML for user-controlled values. If someone
	// "simplifies" back to innerHTML, catch it here.
	if strings.Contains(body, ".innerHTML") {
		t.Errorf("app.js uses innerHTML — XSS risk; use el() + setContent() instead")
	}
}

// --- Bearer token / cookie auth --------------------------------------

// authedHandler returns a Handler with the given Token configured.
// Keeps the auth tests readable — test-only constructor.
func authedHandler(tok string) *Handler {
	f := &fakeFetcher{
		responses: map[string]json.RawMessage{
			schema.MethodPing:            rawJSON(schema.PingResult{OK: true, Version: "v-auth"}),
			schema.MethodEngagementGet:   rawJSON(schema.EngagementGetResult{OK: true}),
			schema.MethodTransportStatus: rawJSON(schema.TransportStatusResult{OK: true, Status: schema.TransportStatus{State: "down"}}),
			schema.MethodOAuthStatus:     rawJSON(schema.OAuthStatusResult{OK: true}),
		},
	}
	return &Handler{Fetcher: f, Token: tok}
}

func TestHandler_Auth_Rejects_Unauthenticated(t *testing.T) {
	t.Parallel()
	h := authedHandler("the-right-token")
	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "restart") {
		t.Errorf("401 body should be actionable: %q", rr.Body.String())
	}
}

func TestHandler_Auth_Rejects_WrongToken(t *testing.T) {
	t.Parallel()
	h := authedHandler("the-right-token")
	req := httptest.NewRequest(http.MethodGet, "/api/state?t=wrong-token", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestHandler_Auth_Accepts_QueryParam_AndSetsCookie(t *testing.T) {
	t.Parallel()
	h := authedHandler("the-right-token")
	req := httptest.NewRequest(http.MethodGet, "/api/state?t=the-right-token", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Errorf("status = %d", rr.Code)
	}
	// The response must Set-Cookie so the next request doesn't need
	// ?t=; the cookie is HttpOnly + SameSite=Strict.
	sc := rr.Header().Get("Set-Cookie")
	if !strings.Contains(sc, cookieName+"=the-right-token") {
		t.Errorf("Set-Cookie missing token: %q", sc)
	}
	if !strings.Contains(sc, "HttpOnly") {
		t.Errorf("Set-Cookie must be HttpOnly: %q", sc)
	}
	if !strings.Contains(sc, "SameSite=Strict") {
		t.Errorf("Set-Cookie must be SameSite=Strict: %q", sc)
	}
}

func TestHandler_Auth_Accepts_Cookie(t *testing.T) {
	t.Parallel()
	h := authedHandler("the-right-token")
	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: "the-right-token"})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Errorf("status = %d", rr.Code)
	}
}

func TestHandler_Auth_Accepts_BearerHeader(t *testing.T) {
	t.Parallel()
	h := authedHandler("the-right-token")
	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	req.Header.Set("Authorization", "Bearer the-right-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Errorf("status = %d", rr.Code)
	}
}

func TestHandler_Auth_HealthzAlwaysOpen(t *testing.T) {
	t.Parallel()
	// /healthz must work without auth so orchestrators / probes don't
	// need to know the token. It reveals nothing operational.
	h := authedHandler("the-right-token")
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Errorf("/healthz should be open; got %d", rr.Code)
	}
}

func TestHandler_Auth_StaticAssets_RequireAuth(t *testing.T) {
	t.Parallel()
	// /, /app.css, /app.js all require auth — otherwise a rogue
	// visitor could pull the JS source to reverse-engineer endpoints
	// or confirm telepath is running on the port.
	h := authedHandler("t")
	for _, p := range []string{"/", "/app.css", "/app.js"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("unauth GET %s = %d, want 401", p, rr.Code)
		}
	}
}

func TestServer_URL_EmbedsToken(t *testing.T) {
	t.Parallel()
	f := &fakeFetcher{}
	srv, err := Start(Config{Fetcher: f})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Shutdown(testCtx(t))
	u := srv.URL()
	if !strings.Contains(u, "?t="+srv.Token) {
		t.Errorf("URL should include tokenized query param: %q", u)
	}
}

// testCtx returns a short-lived context for Shutdown. Avoids pulling
// context/time into the top of every test.
func testCtx(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}
