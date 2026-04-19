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
// client. Ensures listen/serve/shutdown plumbing works together before
// we rely on it from the CLI command in the next release.
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

	resp, err := http.Get(srv.URL() + "/api/state")
	if err != nil {
		t.Fatalf("GET /api/state: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "v-test") {
		t.Errorf("body missing daemon version: %s", body)
	}
}

// testCtx returns a short-lived context for Shutdown. Avoids pulling
// context/time into the top of every test.
func testCtx(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}
