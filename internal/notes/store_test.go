package notes

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fsc/telepath-core/pkg/schema"
)

func TestNotes_CreateGet(t *testing.T) {
	t.Parallel()
	s, err := Open(filepath.Join(t.TempDir(), "n"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.Create(schema.Note{
		Content:         "Interviewed Sarah. Main complaint: ticketing churn.",
		Tags:            []string{"interview", "ops"},
		RelatedEvidence: []string{"ev_abc"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if n.ID != "n_000001" {
		t.Errorf("ID = %q", n.ID)
	}
	got, err := s.Get(n.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.Content, "Sarah") {
		t.Errorf("content round trip failed: %q", got.Content)
	}
	if got.Tags[0] != "interview" {
		t.Errorf("tags = %v", got.Tags)
	}
}

func TestNotes_List_Filters(t *testing.T) {
	t.Parallel()
	s, _ := Open(filepath.Join(t.TempDir(), "n"))
	_, _ = s.Create(schema.Note{Content: "alpha", Tags: []string{"a"}})
	_, _ = s.Create(schema.Note{Content: "beta bravo", Tags: []string{"a", "b"}})
	_, _ = s.Create(schema.Note{Content: "gamma", Tags: []string{"b"}})
	all, _ := s.List(ListFilter{})
	if len(all) != 3 {
		t.Errorf("all = %d", len(all))
	}
	tagged, _ := s.List(ListFilter{Tag: "a"})
	if len(tagged) != 2 {
		t.Errorf("tag a = %d", len(tagged))
	}
	search, _ := s.List(ListFilter{TextSearch: "bravo"})
	if len(search) != 1 {
		t.Errorf("text search = %d", len(search))
	}
}

func TestNotes_ReopenPreservesIDs(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "n")
	s1, _ := Open(dir)
	n, _ := s1.Create(schema.Note{Content: "first"})
	if n.ID != "n_000001" {
		t.Fatal()
	}
	s2, _ := Open(dir)
	m, _ := s2.Create(schema.Note{Content: "second"})
	if m.ID != "n_000002" {
		t.Errorf("after reopen id = %s", m.ID)
	}
}

func TestNotes_EmptyContentErrors(t *testing.T) {
	t.Parallel()
	s, _ := Open(filepath.Join(t.TempDir(), "n"))
	if _, err := s.Create(schema.Note{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestNotes_FrontmatterRoundTrip(t *testing.T) {
	t.Parallel()
	s, _ := Open(filepath.Join(t.TempDir(), "n"))
	orig := schema.Note{
		Content:         "body text\nacross lines",
		Tags:            []string{"one", "two"},
		RelatedFindings: []string{"f_000001"},
		CreatedBy:       "alex",
		CreatedAt:       time.Date(2026, 4, 20, 9, 0, 0, 0, time.UTC),
	}
	created, _ := s.Create(orig)
	got, _ := s.Get(created.ID)
	if got.Content != orig.Content {
		t.Errorf("content body changed through round trip: %q vs %q", got.Content, orig.Content)
	}
	if len(got.RelatedFindings) != 1 || got.RelatedFindings[0] != "f_000001" {
		t.Errorf("related findings lost: %v", got.RelatedFindings)
	}
}
