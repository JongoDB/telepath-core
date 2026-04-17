// Package findings is the structured-findings store. Each finding is one
// JSON file under engagement/findings/f_NNNNNN.json so the directory stays
// human-readable and Git-diff-friendly; writes are atomic. An in-memory
// sequence counter is derived from the highest existing ID on open so
// creates don't collide across daemon restarts.
package findings

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsc/telepath-core/pkg/schema"
)

// Store manages findings for one engagement.
type Store struct {
	mu   sync.Mutex
	dir  string
	next int64 // next ID suffix
	now  func() time.Time
}

// ErrNotFound is returned when an ID does not exist.
var ErrNotFound = errors.New("findings: not found")

// Open returns a Store rooted at dir (typically <engagement>/findings).
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("findings: mkdir: %w", err)
	}
	s := &Store{dir: dir, now: func() time.Time { return time.Now().UTC() }}
	if err := s.loadCounter(); err != nil {
		return nil, err
	}
	return s, nil
}

// Create validates, assigns an ID, timestamps, and writes the finding.
// Overwrites any client-supplied ID.
func (s *Store) Create(f schema.Finding) (schema.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := validate(f, true); err != nil {
		return schema.Finding{}, err
	}
	s.next++
	f.ID = fmt.Sprintf("f_%06d", s.next)
	now := s.now()
	f.CreatedAt = now
	f.UpdatedAt = now
	if f.Status == "" {
		f.Status = schema.FindingStatusDraft
	}
	if err := s.saveLocked(f); err != nil {
		s.next-- // reclaim on failure
		return schema.Finding{}, err
	}
	return f, nil
}

// Update applies partial changes to a finding. Keys mirror the JSON field
// names (title, category, severity, description, recommendation,
// effort_estimate, impact_estimate, confidence_level). Unknown keys are
// ignored rather than erroring, so clients can send a union-of-updates map.
func (s *Store) Update(id string, updates map[string]string, reason string) (schema.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.readLocked(id)
	if err != nil {
		return schema.Finding{}, err
	}
	applyUpdates(&f, updates)
	f.UpdatedAt = s.now()
	if err := s.saveLocked(f); err != nil {
		return schema.Finding{}, err
	}
	_ = reason // reserved for audit payload by caller
	return f, nil
}

// Get returns a finding by ID.
func (s *Store) Get(id string) (schema.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readLocked(id)
}

// List returns all findings matching the filter (empty filter = all).
func (s *Store) List(f ListFilter) ([]schema.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("findings: read dir: %w", err)
	}
	var out []schema.Finding
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, ent.Name()))
		if err != nil {
			continue
		}
		var finding schema.Finding
		if err := json.Unmarshal(data, &finding); err != nil {
			continue
		}
		if !f.matches(finding) {
			continue
		}
		out = append(out, finding)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ListFilter narrows a List call.
type ListFilter struct {
	Category string
	Severity string
	Status   string
}

func (f ListFilter) matches(x schema.Finding) bool {
	if f.Category != "" && x.Category != f.Category {
		return false
	}
	if f.Severity != "" && x.Severity != f.Severity {
		return false
	}
	if f.Status != "" && x.Status != f.Status {
		return false
	}
	return true
}

// SetStatus transitions a finding to a new status. The reason field is the
// caller's responsibility to log in audit.
func (s *Store) SetStatus(id, status, reason string) (schema.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.readLocked(id)
	if err != nil {
		return schema.Finding{}, err
	}
	if !validStatus(status) {
		return schema.Finding{}, fmt.Errorf("findings: invalid status %q", status)
	}
	f.Status = status
	f.UpdatedAt = s.now()
	if err := s.saveLocked(f); err != nil {
		return schema.Finding{}, err
	}
	_ = reason
	return f, nil
}

// --- helpers ---

func (s *Store) path(id string) string {
	return filepath.Join(s.dir, id+".json")
}

func (s *Store) readLocked(id string) (schema.Finding, error) {
	data, err := os.ReadFile(s.path(id))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return schema.Finding{}, ErrNotFound
		}
		return schema.Finding{}, fmt.Errorf("findings: read %s: %w", id, err)
	}
	var f schema.Finding
	if err := json.Unmarshal(data, &f); err != nil {
		return schema.Finding{}, fmt.Errorf("findings: parse %s: %w", id, err)
	}
	return f, nil
}

func (s *Store) saveLocked(f schema.Finding) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("findings: marshal: %w", err)
	}
	path := s.path(f.ID)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("findings: write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("findings: rename: %w", err)
	}
	return nil
}

func (s *Store) loadCounter() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "f_") {
			continue
		}
		numPart := strings.TrimPrefix(strings.TrimSuffix(e.Name(), ".json"), "f_")
		n, err := strconv.ParseInt(numPart, 10, 64)
		if err != nil {
			continue
		}
		if n > s.next {
			s.next = n
		}
	}
	return nil
}

func validate(f schema.Finding, creating bool) error {
	if f.Title == "" {
		return errors.New("findings: title required")
	}
	if f.Category == "" {
		return errors.New("findings: category required")
	}
	if creating && f.ID != "" && !strings.HasPrefix(f.ID, "f_") {
		return errors.New("findings: ID must be auto-assigned (omit on create)")
	}
	if f.Severity != "" && !validSeverity(f.Severity) {
		return fmt.Errorf("findings: invalid severity %q", f.Severity)
	}
	if f.Status != "" && !validStatus(f.Status) {
		return fmt.Errorf("findings: invalid status %q", f.Status)
	}
	return nil
}

func validSeverity(s string) bool {
	switch s {
	case schema.SeverityInfo, schema.SeverityLow, schema.SeverityMedium, schema.SeverityHigh, schema.SeverityCritical:
		return true
	}
	return false
}

func validStatus(s string) bool {
	switch s {
	case schema.FindingStatusDraft, schema.FindingStatusConfirmed, schema.FindingStatusDismissed:
		return true
	}
	return false
}

func applyUpdates(f *schema.Finding, updates map[string]string) {
	for k, v := range updates {
		switch k {
		case "title":
			f.Title = v
		case "category":
			f.Category = v
		case "severity":
			if validSeverity(v) {
				f.Severity = v
			}
		case "description":
			f.Description = v
		case "recommendation":
			f.Recommendation = v
		case "effort_estimate":
			f.EffortEstimate = v
		case "impact_estimate":
			f.ImpactEstimate = v
		case "confidence_level":
			f.ConfidenceLevel = v
		}
	}
}
