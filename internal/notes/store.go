// Package notes is the freeform-notes store. Each note is one markdown
// file under engagement/notes/n_NNNNNN.md with YAML frontmatter for
// metadata and the markdown body for content. Kept intentionally primitive
// so the operator can grep/edit notes directly with any editor.
package notes

import (
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

	"gopkg.in/yaml.v3"

	"github.com/fsc/telepath-core/pkg/schema"
)

// Store manages notes for one engagement.
type Store struct {
	mu   sync.Mutex
	dir  string
	next int64
	now  func() time.Time
}

// ErrNotFound is returned when an ID does not exist.
var ErrNotFound = errors.New("notes: not found")

// Open returns a Store rooted at dir (typically <engagement>/notes).
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("notes: mkdir: %w", err)
	}
	s := &Store{dir: dir, now: func() time.Time { return time.Now().UTC() }}
	if err := s.loadCounter(); err != nil {
		return nil, err
	}
	return s, nil
}

// Create writes a new note, assigning an ID and timestamp. Returns the
// populated note record.
func (s *Store) Create(n schema.Note) (schema.Note, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n.Content == "" {
		return schema.Note{}, errors.New("notes: content required")
	}
	s.next++
	n.ID = fmt.Sprintf("n_%06d", s.next)
	n.CreatedAt = s.now()
	if err := s.saveLocked(n); err != nil {
		s.next--
		return schema.Note{}, err
	}
	return n, nil
}

// Get retrieves a note by ID.
func (s *Store) Get(id string) (schema.Note, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readLocked(id)
}

// ListFilter narrows a List call.
type ListFilter struct {
	Tag        string
	Since      time.Time
	TextSearch string
}

// List returns notes matching filter. Results sorted by ID ascending
// (equivalent to CreatedAt ascending since IDs are monotonic).
func (s *Store) List(f ListFilter) ([]schema.Note, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("notes: read dir: %w", err)
	}
	var out []schema.Note
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".md")
		n, err := s.readLocked(id)
		if err != nil {
			continue
		}
		if f.Tag != "" && !contains(n.Tags, f.Tag) {
			continue
		}
		if !f.Since.IsZero() && n.CreatedAt.Before(f.Since) {
			continue
		}
		if f.TextSearch != "" && !strings.Contains(strings.ToLower(n.Content), strings.ToLower(f.TextSearch)) {
			continue
		}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// --- helpers ---

func (s *Store) path(id string) string { return filepath.Join(s.dir, id+".md") }

type noteFrontmatter struct {
	ID              string    `yaml:"id"`
	Tags            []string  `yaml:"tags,omitempty"`
	RelatedEvidence []string  `yaml:"related_evidence,omitempty"`
	RelatedFindings []string  `yaml:"related_findings,omitempty"`
	CreatedAt       time.Time `yaml:"created_at"`
	CreatedBy       string    `yaml:"created_by,omitempty"`
}

func (s *Store) saveLocked(n schema.Note) error {
	fm := noteFrontmatter{
		ID:              n.ID,
		Tags:            n.Tags,
		RelatedEvidence: n.RelatedEvidence,
		RelatedFindings: n.RelatedFindings,
		CreatedAt:       n.CreatedAt,
		CreatedBy:       n.CreatedBy,
	}
	fmBytes, err := yaml.Marshal(fm)
	if err != nil {
		return fmt.Errorf("notes: marshal frontmatter: %w", err)
	}
	// Normalize: exactly one trailing newline on disk, regardless of input.
	// Read-side trims one trailing newline so round-trip preserves the
	// original content for inputs with 0 or 1 trailing newlines.
	body := strings.TrimRight(n.Content, "\n") + "\n"
	var b strings.Builder
	b.WriteString("---\n")
	b.Write(fmBytes)
	b.WriteString("---\n\n")
	b.WriteString(body)
	path := s.path(n.ID)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("notes: write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("notes: rename: %w", err)
	}
	return nil
}

func (s *Store) readLocked(id string) (schema.Note, error) {
	data, err := os.ReadFile(s.path(id))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return schema.Note{}, ErrNotFound
		}
		return schema.Note{}, fmt.Errorf("notes: read: %w", err)
	}
	return parseNote(id, data)
}

// parseNote extracts frontmatter + body from a note file.
func parseNote(id string, data []byte) (schema.Note, error) {
	s := string(data)
	if !strings.HasPrefix(s, "---\n") {
		return schema.Note{}, fmt.Errorf("notes: %s missing frontmatter", id)
	}
	rest := s[4:]
	end := strings.Index(rest, "\n---")
	if end < 0 {
		return schema.Note{}, fmt.Errorf("notes: %s frontmatter unterminated", id)
	}
	var fm noteFrontmatter
	if err := yaml.Unmarshal([]byte(rest[:end]), &fm); err != nil {
		return schema.Note{}, fmt.Errorf("notes: %s parse frontmatter: %w", id, err)
	}
	body := rest[end+4:]
	body = strings.TrimLeft(body, "\n")
	body = strings.TrimSuffix(body, "\n") // undo the save-side normalization
	return schema.Note{
		ID:              fm.ID,
		Content:         body,
		Tags:            fm.Tags,
		RelatedEvidence: fm.RelatedEvidence,
		RelatedFindings: fm.RelatedFindings,
		CreatedAt:       fm.CreatedAt,
		CreatedBy:       fm.CreatedBy,
	}, nil
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
		if !strings.HasPrefix(e.Name(), "n_") {
			continue
		}
		numPart := strings.TrimPrefix(strings.TrimSuffix(e.Name(), ".md"), "n_")
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

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
