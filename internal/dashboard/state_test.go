package dashboard

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/fsc/telepath-core/pkg/schema"
)

// fakeFetcher is a per-test Fetcher. Keyed on method name; values are
// either a function (computed response) or a canned RawMessage. Missing
// entries return a (nil, error) pair so tests can assert the
// "unreachable daemon" branch without spinning up a real IPC server.
type fakeFetcher struct {
	responses map[string]json.RawMessage
	errors    map[string]error
	calls     []fakeCall
}

type fakeCall struct {
	Method string
	Params any
}

func (f *fakeFetcher) Call(method string, params any) (json.RawMessage, error) {
	f.calls = append(f.calls, fakeCall{Method: method, Params: params})
	if err, ok := f.errors[method]; ok {
		return nil, err
	}
	if r, ok := f.responses[method]; ok {
		return r, nil
	}
	return nil, errors.New("no canned response for " + method)
}

func rawJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func TestAggregate_DaemonUnreachable_ReturnsEarlyWithWarning(t *testing.T) {
	t.Parallel()
	f := &fakeFetcher{
		errors: map[string]error{schema.MethodPing: errors.New("dial unix: no such file")},
	}
	s := Aggregate(f, "")
	if s.Daemon != nil {
		t.Errorf("daemon should be nil when ping fails: %+v", s.Daemon)
	}
	if len(s.Warnings) == 0 || !strings.Contains(s.Warnings[0], "unreachable") {
		t.Errorf("expected unreachable warning, got %v", s.Warnings)
	}
	// No downstream RPCs should fire once ping fails — the aggregator
	// short-circuits so the UI sees a coherent "daemon down" state.
	for _, c := range f.calls {
		if c.Method != schema.MethodPing {
			t.Errorf("unexpected downstream call after ping failure: %s", c.Method)
		}
	}
}

func TestAggregate_DaemonAlivePopulatesVersion(t *testing.T) {
	t.Parallel()
	f := &fakeFetcher{
		responses: map[string]json.RawMessage{
			schema.MethodPing:            rawJSON(schema.PingResult{OK: true, Version: "0.1.22"}),
			schema.MethodEngagementGet:   rawJSON(schema.EngagementGetResult{OK: true, Engagement: nil}),
			schema.MethodTransportStatus: rawJSON(schema.TransportStatusResult{OK: true, Status: schema.TransportStatus{State: "down"}}),
			schema.MethodOAuthStatus:     rawJSON(schema.OAuthStatusResult{OK: true, Connections: []schema.OAuthConnection{}}),
		},
	}
	s := Aggregate(f, "")
	if s.Daemon == nil || s.Daemon.Version != "0.1.22" {
		t.Errorf("daemon = %+v", s.Daemon)
	}
	if s.GeneratedAt == "" {
		t.Errorf("GeneratedAt should be set")
	}
	if s.ActiveEngagement != nil {
		t.Errorf("no active engagement expected")
	}
	if s.Transport != nil {
		t.Errorf("transport should be nil when state=down: %+v", s.Transport)
	}
	if len(s.OAuth) != 0 {
		t.Errorf("oauth should be empty: %v", s.OAuth)
	}
	if len(s.Warnings) != 0 {
		t.Errorf("no warnings expected: %v", s.Warnings)
	}
}

func TestAggregate_ActiveEngagement_PopulatesCountsAndRecents(t *testing.T) {
	t.Parallel()
	findings := []schema.Finding{
		{ID: "f_000001", Title: "first"},
		{ID: "f_000002", Title: "second"},
		{ID: "f_000003", Title: "third"},
		{ID: "f_000004", Title: "fourth"},
		{ID: "f_000005", Title: "fifth"},
		{ID: "f_000006", Title: "sixth"},
		{ID: "f_000007", Title: "seventh"},
	}
	notes := []schema.Note{
		{ID: "n_000001", Content: "a"},
		{ID: "n_000002", Content: "b"},
	}
	f := &fakeFetcher{
		responses: map[string]json.RawMessage{
			schema.MethodPing:            rawJSON(schema.PingResult{OK: true, Version: "0.1.22"}),
			schema.MethodEngagementGet:   rawJSON(schema.EngagementGetResult{OK: true, Engagement: &schema.Engagement{ID: "acme-01", ClientName: "Acme", Status: "active"}}),
			schema.MethodTransportStatus: rawJSON(schema.TransportStatusResult{OK: true, Status: schema.TransportStatus{Kind: "direct", State: "up"}}),
			schema.MethodOAuthStatus:     rawJSON(schema.OAuthStatusResult{OK: true, Connections: nil}),
			schema.MethodFindingsList:    rawJSON(schema.FindingListResult{OK: true, Findings: findings}),
			schema.MethodNotesList:       rawJSON(schema.NoteListResult{OK: true, Notes: notes}),
			schema.MethodEvidenceSearch:  rawJSON(schema.EvidenceSearchResult{OK: true, Items: []schema.EvidenceSummary{{EvidenceID: "x"}, {EvidenceID: "y"}}}),
		},
	}
	s := Aggregate(f, "")
	if s.ActiveEngagement == nil || s.ActiveEngagement.ID != "acme-01" {
		t.Errorf("engagement = %+v", s.ActiveEngagement)
	}
	if s.Transport == nil || s.Transport.Kind != "direct" {
		t.Errorf("transport = %+v", s.Transport)
	}
	if s.FindingsCount != 7 || s.NotesCount != 2 || s.EvidenceCount != 2 {
		t.Errorf("counts wrong: f=%d n=%d e=%d", s.FindingsCount, s.NotesCount, s.EvidenceCount)
	}
	// Recent should be capped at recentLimit = 5, and the last 5
	// entries in creation order.
	if len(s.RecentFindings) != 5 {
		t.Fatalf("recent findings = %d, want 5", len(s.RecentFindings))
	}
	if s.RecentFindings[0].ID != "f_000003" || s.RecentFindings[4].ID != "f_000007" {
		t.Errorf("recent findings order wrong: %+v", s.RecentFindings)
	}
	if len(s.RecentNotes) != 2 {
		t.Errorf("recent notes = %d, want 2", len(s.RecentNotes))
	}
}

func TestAggregate_ExpiredOAuth_SurfacesAsWarning(t *testing.T) {
	t.Parallel()
	f := &fakeFetcher{
		responses: map[string]json.RawMessage{
			schema.MethodPing:            rawJSON(schema.PingResult{OK: true, Version: "x"}),
			schema.MethodEngagementGet:   rawJSON(schema.EngagementGetResult{OK: true}),
			schema.MethodTransportStatus: rawJSON(schema.TransportStatusResult{OK: true, Status: schema.TransportStatus{State: "down"}}),
			schema.MethodOAuthStatus: rawJSON(schema.OAuthStatusResult{OK: true, Connections: []schema.OAuthConnection{
				{Provider: "m365", Tenant: "acme-prod", ExpiresAt: time.Now().Add(-time.Hour).Format(time.RFC3339), Expired: true},
				{Provider: "google", Tenant: "default", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339), Expired: false},
			}}),
		},
	}
	s := Aggregate(f, "")
	if len(s.OAuth) != 2 {
		t.Fatalf("expected 2 connections: %+v", s.OAuth)
	}
	foundExpired := false
	for _, w := range s.Warnings {
		if strings.Contains(w, "oauth expired") && strings.Contains(w, "m365/acme-prod") {
			foundExpired = true
		}
	}
	if !foundExpired {
		t.Errorf("expected expired-oauth warning in %v", s.Warnings)
	}
}

func TestAggregate_VersionMismatch_EmitsWarning(t *testing.T) {
	t.Parallel()
	// CLIVersion = 0.1.26, daemon reports 0.1.20 → the operator ran
	// telepath update but didn't restart the daemon. The warning
	// tells them exactly what to do.
	f := &fakeFetcher{
		responses: map[string]json.RawMessage{
			schema.MethodPing:            rawJSON(schema.PingResult{OK: true, Version: "0.1.20"}),
			schema.MethodEngagementGet:   rawJSON(schema.EngagementGetResult{OK: true}),
			schema.MethodTransportStatus: rawJSON(schema.TransportStatusResult{OK: true, Status: schema.TransportStatus{State: "down"}}),
			schema.MethodOAuthStatus:     rawJSON(schema.OAuthStatusResult{OK: true}),
		},
	}
	s := Aggregate(f, "0.1.26")
	if s.CLIVersion != "0.1.26" {
		t.Errorf("CLIVersion = %q", s.CLIVersion)
	}
	found := false
	for _, w := range s.Warnings {
		if strings.Contains(w, "0.1.20") && strings.Contains(w, "0.1.26") && strings.Contains(w, "daemon stop") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected mismatch warning with both versions + restart hint, got: %v", s.Warnings)
	}
}

func TestAggregate_VersionMatch_NoWarning(t *testing.T) {
	t.Parallel()
	f := &fakeFetcher{
		responses: map[string]json.RawMessage{
			schema.MethodPing:            rawJSON(schema.PingResult{OK: true, Version: "0.1.26"}),
			schema.MethodEngagementGet:   rawJSON(schema.EngagementGetResult{OK: true}),
			schema.MethodTransportStatus: rawJSON(schema.TransportStatusResult{OK: true, Status: schema.TransportStatus{State: "down"}}),
			schema.MethodOAuthStatus:     rawJSON(schema.OAuthStatusResult{OK: true}),
		},
	}
	s := Aggregate(f, "0.1.26")
	for _, w := range s.Warnings {
		if strings.Contains(w, "older build") {
			t.Errorf("version-match run should not warn: %v", s.Warnings)
		}
	}
}

func TestAggregate_EmptyCLIVersion_SkipsMismatchCheck(t *testing.T) {
	t.Parallel()
	// CLIVersion="" (SDK embed without a version) should not warn
	// regardless of what the daemon reports.
	f := &fakeFetcher{
		responses: map[string]json.RawMessage{
			schema.MethodPing:            rawJSON(schema.PingResult{OK: true, Version: "anything"}),
			schema.MethodEngagementGet:   rawJSON(schema.EngagementGetResult{OK: true}),
			schema.MethodTransportStatus: rawJSON(schema.TransportStatusResult{OK: true, Status: schema.TransportStatus{State: "down"}}),
			schema.MethodOAuthStatus:     rawJSON(schema.OAuthStatusResult{OK: true}),
		},
	}
	s := Aggregate(f, "")
	for _, w := range s.Warnings {
		if strings.Contains(w, "older build") {
			t.Errorf("empty CLIVersion should not warn: %v", s.Warnings)
		}
	}
}

func TestAggregate_EmptySlicesAreArraysNotNull(t *testing.T) {
	t.Parallel()
	// Wire contract: the frontend renders oauth/recent/warnings as
	// arrays; null would make JS code paths (reverse(), length) crash.
	// This test asserts the aggregator initializes them as empty
	// slices even when nothing ever populates them.
	f := &fakeFetcher{
		responses: map[string]json.RawMessage{
			schema.MethodPing:            rawJSON(schema.PingResult{OK: true, Version: "v"}),
			schema.MethodEngagementGet:   rawJSON(schema.EngagementGetResult{OK: true}),
			schema.MethodTransportStatus: rawJSON(schema.TransportStatusResult{OK: true, Status: schema.TransportStatus{State: "down"}}),
			schema.MethodOAuthStatus:     rawJSON(schema.OAuthStatusResult{OK: true}),
		},
	}
	s := Aggregate(f, "")
	raw, _ := json.Marshal(s)
	out := string(raw)
	for _, want := range []string{`"oauth":[]`, `"recent_findings":[]`, `"recent_notes":[]`, `"warnings":[]`} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %s in JSON, got: %s", want, out)
		}
	}
}

func TestAggregate_NoActiveEngagement_SkipsListRPCs(t *testing.T) {
	t.Parallel()
	f := &fakeFetcher{
		responses: map[string]json.RawMessage{
			schema.MethodPing:            rawJSON(schema.PingResult{OK: true, Version: "x"}),
			schema.MethodEngagementGet:   rawJSON(schema.EngagementGetResult{OK: true, Engagement: nil}),
			schema.MethodTransportStatus: rawJSON(schema.TransportStatusResult{OK: true, Status: schema.TransportStatus{State: "down"}}),
			schema.MethodOAuthStatus:     rawJSON(schema.OAuthStatusResult{OK: true}),
		},
	}
	s := Aggregate(f, "")
	if s.FindingsCount != 0 || s.NotesCount != 0 || s.EvidenceCount != 0 {
		t.Errorf("counts should be zero: %+v", s)
	}
	// Assert list RPCs were skipped — only 4 calls (ping + engagement
	// + transport + oauth) expected.
	for _, c := range f.calls {
		if c.Method == schema.MethodFindingsList || c.Method == schema.MethodNotesList || c.Method == schema.MethodEvidenceSearch {
			t.Errorf("unexpected list RPC without active engagement: %s", c.Method)
		}
	}
}
