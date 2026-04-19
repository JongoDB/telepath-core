// Package dashboard is the operator-facing web dashboard that ships with
// telepath-core as a first-class operator surface. Background / motivation
// lives in docs/V1_VISION.md §3.3 — the CLI is the automation + scripting
// surface, the TUI handles setup/config, and this package is the
// day-to-day operation view.
//
// The dashboard process is a localhost-only HTTP server started by
// `telepath dashboard`. It reaches back to the running daemon over the
// same Unix-socket JSON-RPC every other telepath command uses, so the
// daemon stays the single source of truth — the dashboard never holds
// durable state of its own.
package dashboard

import (
	"encoding/json"
	"os"
	"time"

	"github.com/fsc/telepath-core/internal/ipc"
	"github.com/fsc/telepath-core/pkg/schema"
)

// Fetcher is the RPC seam. Production wires it to ipc.Call against the
// daemon socket; tests inject a fake that returns canned responses so
// state aggregation is exercised without a running daemon.
type Fetcher interface {
	Call(method string, params any) (json.RawMessage, error)
}

// IPCFetcher is the production Fetcher.
type IPCFetcher struct {
	SocketPath string
	Timeout    time.Duration
}

// Call satisfies Fetcher by dispatching through the IPC client. Each
// call spins up a fresh connection — the dashboard's polling cadence
// (every 2s) is not hot enough to warrant connection pooling.
func (f *IPCFetcher) Call(method string, params any) (json.RawMessage, error) {
	if f.Timeout > 0 {
		return ipc.CallWithTimeout(f.SocketPath, method, params, f.Timeout)
	}
	return ipc.Call(f.SocketPath, method, params)
}

// State is the aggregated view the /api/state endpoint returns. Shape is
// deliberately flat + JSON-friendly so the browser JS can render each
// field with minimal transforms. Fields are populated best-effort: a
// failing RPC contributes an entry to Warnings but doesn't fail the
// whole fetch, so a degraded daemon still produces a useful page.
type State struct {
	// GeneratedAt is the client-side timestamp of this snapshot; the
	// dashboard renders it in the header so operators know the page is
	// live vs. stale.
	GeneratedAt string `json:"generated_at"`

	// Daemon carries identity + liveness info. Null when the daemon
	// RPC was unreachable — UI renders a "daemon down" banner.
	Daemon *DaemonInfo `json:"daemon"`

	// ActiveEngagement is nil when no engagement is loaded.
	ActiveEngagement *schema.Engagement `json:"active_engagement"`

	// Transport is nil when no transport is up.
	Transport *schema.TransportStatus `json:"transport"`

	// OAuth lists every connection currently in the keystore across
	// m365/google/salesforce/default-tenant. Empty when the operator
	// hasn't connected anything.
	OAuth []schema.OAuthConnection `json:"oauth"`

	// FindingsCount + NotesCount + EvidenceCount are totals for the
	// active engagement. Zero when there's no active engagement (the
	// list RPCs return no items in that case).
	FindingsCount int `json:"findings_count"`
	NotesCount    int `json:"notes_count"`
	EvidenceCount int `json:"evidence_count"`

	// Recent{Findings,Notes} are the most recent entries — enough for
	// the operator to spot-check what Claude just created. Capped at
	// recentLimit items.
	RecentFindings []schema.Finding `json:"recent_findings"`
	RecentNotes    []schema.Note    `json:"recent_notes"`

	// Warnings surfaces any non-fatal issues discovered during
	// aggregation (e.g., oauth token expired, audit log missing). UI
	// renders these as a banner at the top of the page.
	Warnings []string `json:"warnings"`
}

// DaemonInfo is the nested daemon status block.
type DaemonInfo struct {
	Version  string `json:"version"`
	PID      int    `json:"pid"`
	Socket   string `json:"socket"`
	Keystore string `json:"keystore,omitempty"`
}

// recentLimit caps how many recent findings/notes we return. 5 fits
// a single dashboard card without overflow; operators who need more
// drill into the full findings list (v0.1.24+ adds a findings page).
const recentLimit = 5

// Aggregate builds a State snapshot via Fetcher. Every RPC is
// best-effort: failures turn into Warnings rather than aborting the
// whole refresh, so the browser sees partial state even when the
// daemon is mid-restart or a single subsystem is flaky.
func Aggregate(f Fetcher) State {
	s := State{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		OAuth:       []schema.OAuthConnection{},
	}

	// ping → daemon version + PID from the caller's pid file if
	// available. We don't hit the pidfile from here (dashboard isn't
	// necessarily on the same host as the daemon in v0.x, though v0.1
	// is local-only). Version comes from the ping response.
	if raw, err := f.Call(schema.MethodPing, nil); err == nil {
		var p schema.PingResult
		if json.Unmarshal(raw, &p) == nil && p.OK {
			s.Daemon = &DaemonInfo{Version: p.Version}
			if os.Getenv("TELEPATH_SOCKET") != "" {
				s.Daemon.Socket = os.Getenv("TELEPATH_SOCKET")
			}
		}
	} else {
		s.Warnings = append(s.Warnings, "daemon unreachable: "+err.Error())
		// All subsequent RPCs will also fail; return early so the UI
		// sees a coherent "daemon down" state rather than a cascade.
		return s
	}

	// engagement.get → ActiveEngagement
	if raw, err := f.Call(schema.MethodEngagementGet, nil); err == nil {
		var r schema.EngagementGetResult
		if json.Unmarshal(raw, &r) == nil {
			s.ActiveEngagement = r.Engagement
		}
	} else {
		s.Warnings = append(s.Warnings, "engagement.get failed: "+err.Error())
	}

	// transport.status → Transport (nil-coerced when state is "down")
	if raw, err := f.Call(schema.MethodTransportStatus, nil); err == nil {
		var r schema.TransportStatusResult
		if json.Unmarshal(raw, &r) == nil && r.Status.State != "down" && r.Status.Kind != "" {
			status := r.Status
			s.Transport = &status
		}
	}

	// oauth.status → connections (always a slice, never nil — UI greps
	// on array-ness for the "no connections" messaging).
	if raw, err := f.Call(schema.MethodOAuthStatus, schema.OAuthStatusParams{}); err == nil {
		var r schema.OAuthStatusResult
		if json.Unmarshal(raw, &r) == nil && r.Connections != nil {
			s.OAuth = r.Connections
			for _, c := range r.Connections {
				if c.Expired {
					s.Warnings = append(s.Warnings,
						"oauth expired: "+c.Provider+"/"+c.Tenant+" — run `telepath oauth begin` to refresh")
				}
			}
		}
	}

	// findings.list + notes.list + evidence.search (no filter = all)
	// run only when an engagement is active — otherwise these RPCs
	// return ErrCodeNoActiveEngagement and the empty Warnings entry
	// would clutter the UI without helping.
	if s.ActiveEngagement != nil {
		if raw, err := f.Call(schema.MethodFindingsList, map[string]any{}); err == nil {
			var r schema.FindingListResult
			if json.Unmarshal(raw, &r) == nil {
				s.FindingsCount = len(r.Findings)
				s.RecentFindings = takeLastN(r.Findings, recentLimit)
			}
		}
		if raw, err := f.Call(schema.MethodNotesList, map[string]any{}); err == nil {
			var r schema.NoteListResult
			if json.Unmarshal(raw, &r) == nil {
				s.NotesCount = len(r.Notes)
				s.RecentNotes = takeLastNotes(r.Notes, recentLimit)
			}
		}
		if raw, err := f.Call(schema.MethodEvidenceSearch, map[string]any{}); err == nil {
			var r schema.EvidenceSearchResult
			if json.Unmarshal(raw, &r) == nil {
				s.EvidenceCount = len(r.Items)
			}
		}
	}
	return s
}

// takeLastN returns the last n findings (or all if the slice is shorter).
// Findings are stored in creation order — the last entries are the most
// recently-created, which is what the dashboard's "Recent" card wants.
func takeLastN(list []schema.Finding, n int) []schema.Finding {
	if len(list) <= n {
		// Return a copy so later mutation of the underlying store
		// doesn't race with a rendered snapshot.
		out := make([]schema.Finding, len(list))
		copy(out, list)
		return out
	}
	out := make([]schema.Finding, n)
	copy(out, list[len(list)-n:])
	return out
}

// takeLastNotes is a note-shaped version of takeLastN. Generics would
// trim this but keeping both explicit is clearer in a small package.
func takeLastNotes(list []schema.Note, n int) []schema.Note {
	if len(list) <= n {
		out := make([]schema.Note, len(list))
		copy(out, list)
		return out
	}
	out := make([]schema.Note, n)
	copy(out, list[len(list)-n:])
	return out
}
