package dashboard

import (
	"encoding/json"
	"net/http"
)

// Handler is the HTTP handler group the dashboard server exposes. Split
// out of Server so tests can hit individual endpoints via httptest.
type Handler struct {
	Fetcher Fetcher
}

// ServeHTTP routes the small number of dashboard endpoints. Keeps paths
// hand-registered so there's no framework opacity — operators who pop
// curl at the port see exactly what's there.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		h.healthz(w, r)
	case "/api/state":
		h.apiState(w, r)
	default:
		http.NotFound(w, r)
	}
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
