package findings

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/fsc/telepath-core/pkg/schema"
)

func TestFindings_CreateGetList(t *testing.T) {
	t.Parallel()
	s, err := Open(filepath.Join(t.TempDir(), "findings"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := s.Create(schema.Finding{
		Title:    "Shared CS inbox not triaged",
		Category: "workflow_opportunity",
		Severity: schema.SeverityMedium,
		Description: "First-response times are inconsistent.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.ID != "f_000001" {
		t.Errorf("ID = %q", f.ID)
	}
	if f.Status != schema.FindingStatusDraft {
		t.Errorf("default status = %q", f.Status)
	}
	got, err := s.Get(f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Title != f.Title {
		t.Errorf("round trip mismatch")
	}

	// Create another, list them.
	if _, err := s.Create(schema.Finding{Title: "Another", Category: "risk"}); err != nil {
		t.Fatal(err)
	}
	list, err := s.List(ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Errorf("list len = %d, want 2", len(list))
	}
	// Filter.
	med, _ := s.List(ListFilter{Severity: schema.SeverityMedium})
	if len(med) != 1 {
		t.Errorf("severity filter: got %d", len(med))
	}
}

func TestFindings_Update(t *testing.T) {
	t.Parallel()
	s, _ := Open(filepath.Join(t.TempDir(), "f"))
	f, _ := s.Create(schema.Finding{Title: "t", Category: "c"})
	updated, err := s.Update(f.ID, map[string]string{"title": "new title", "severity": "high"}, "operator edit")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Title != "new title" || updated.Severity != "high" {
		t.Errorf("update not applied: %+v", updated)
	}
}

func TestFindings_SetStatus(t *testing.T) {
	t.Parallel()
	s, _ := Open(filepath.Join(t.TempDir(), "f"))
	f, _ := s.Create(schema.Finding{Title: "t", Category: "c"})
	if _, err := s.SetStatus(f.ID, "bogus", "x"); err == nil {
		t.Fatal("expected invalid status error")
	}
	ok, err := s.SetStatus(f.ID, schema.FindingStatusConfirmed, "reviewed")
	if err != nil {
		t.Fatal(err)
	}
	if ok.Status != schema.FindingStatusConfirmed {
		t.Errorf("status = %q", ok.Status)
	}
}

func TestFindings_IDsStableAcrossReopen(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "f")
	s1, _ := Open(dir)
	f, _ := s1.Create(schema.Finding{Title: "a", Category: "c"})
	if f.ID != "f_000001" {
		t.Errorf("first = %s", f.ID)
	}
	s2, _ := Open(dir)
	g, _ := s2.Create(schema.Finding{Title: "b", Category: "c"})
	if g.ID != "f_000002" {
		t.Errorf("after reopen first = %s", g.ID)
	}
}

func TestFindings_Validation(t *testing.T) {
	t.Parallel()
	s, _ := Open(filepath.Join(t.TempDir(), "f"))
	if _, err := s.Create(schema.Finding{Category: "c"}); err == nil {
		t.Error("missing title: expected error")
	}
	if _, err := s.Create(schema.Finding{Title: "t"}); err == nil {
		t.Error("missing category: expected error")
	}
	if _, err := s.Create(schema.Finding{Title: "t", Category: "c", Severity: "urgent"}); err == nil {
		t.Error("invalid severity: expected error")
	}
}

func TestFindings_GetMissing(t *testing.T) {
	t.Parallel()
	s, _ := Open(filepath.Join(t.TempDir(), "f"))
	_, err := s.Get("f_999999")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}
