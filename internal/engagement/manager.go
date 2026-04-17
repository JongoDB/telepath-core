// Package engagement manages the per-engagement directory layout, metadata,
// and lifecycle. One Manager per daemon; at most one Active engagement at a
// time (v0.1 constraint; v1.0 relaxes this).
package engagement

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/fsc/telepath-core/internal/audit"
	"github.com/fsc/telepath-core/internal/findings"
	"github.com/fsc/telepath-core/internal/keys"
	"github.com/fsc/telepath-core/internal/notes"
	"github.com/fsc/telepath-core/internal/roe"
	"github.com/fsc/telepath-core/internal/vault"
	"github.com/fsc/telepath-core/pkg/schema"
)

// idPattern constrains engagement IDs so they're safe filesystem path
// components: alphanumerics, underscores, dashes, up to 64 chars.
var idPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// Manager owns the engagements directory and tracks the currently-loaded
// engagement (if any). Safe for concurrent use; all mutations take the write
// lock, reads use the read lock.
type Manager struct {
	mu sync.RWMutex

	rootDir string
	store   keys.Store
	signer  ed25519.PrivateKey

	active *Active

	// now is injectable for tests.
	now func() time.Time
}

// Active bundles the state held while an engagement is loaded. The AuditLog
// stays open for the duration of the load; callers append through it rather
// than opening the file themselves.
type Active struct {
	Engagement schema.Engagement
	AuditLog   *audit.Log
	Dir        string          // absolute path to <rootDir>/<id>
	ROE        *roe.ROE        // nil until operator uploads roe.yaml
	Vault      *vault.Vault    // opened with engagement key at load
	Findings   *findings.Store // structured findings (SQL-free, file-per-record)
	Notes      *notes.Store    // freeform notes with YAML frontmatter
}

// CreateParams is the input to Manager.Create. Only ID, ClientName, and
// AssessmentType are strictly required; the rest default to zero values.
type CreateParams struct {
	ID             string
	ClientName     string
	AssessmentType string
	StartDate      time.Time
	EndDate        time.Time
	SOWReference   string
	OperatorID     string
	PrimarySkill   string
	TransportMode  string
}

// NewManager wires a Manager to its dependencies. rootDir is the parent of
// per-engagement directories (typically ~/.telepath/engagements).
func NewManager(rootDir string, store keys.Store, signer ed25519.PrivateKey) *Manager {
	return &Manager{
		rootDir: rootDir,
		store:   store,
		signer:  signer,
		now:     func() time.Time { return time.Now().UTC() },
	}
}

// RootDir returns the configured engagements root.
func (m *Manager) RootDir() string { return m.rootDir }

// Active returns the currently loaded engagement, or nil.
func (m *Manager) Active() *Active {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active
}

// Create initializes a fresh engagement on disk: engagement.yaml,
// per-engagement symmetric key in the keystore, an empty audit log, and a
// "created" engagement-lifecycle audit event. Returns ErrExists if an
// engagement with the same ID already exists.
func (m *Manager) Create(p CreateParams) (schema.Engagement, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !idPattern.MatchString(p.ID) {
		return schema.Engagement{}, fmt.Errorf("engagement: invalid ID %q (allowed: A-Z a-z 0-9 _ -, up to 64 chars)", p.ID)
	}
	if p.ClientName == "" {
		return schema.Engagement{}, errors.New("engagement: client_name required")
	}
	if p.AssessmentType == "" {
		return schema.Engagement{}, errors.New("engagement: assessment_type required")
	}

	dir := engagementDir(m.rootDir, p.ID)
	switch _, err := os.Stat(dir); {
	case err == nil:
		return schema.Engagement{}, fmt.Errorf("engagement: %q already exists at %s", p.ID, dir)
	case errors.Is(err, fs.ErrNotExist):
		// OK
	default:
		return schema.Engagement{}, fmt.Errorf("engagement: stat %s: %w", dir, err)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return schema.Engagement{}, fmt.Errorf("engagement: mkdir %s: %w", dir, err)
	}
	if err := os.MkdirAll(claudeSessionsDir(m.rootDir, p.ID), 0o700); err != nil {
		return schema.Engagement{}, fmt.Errorf("engagement: mkdir .claude/sessions: %w", err)
	}
	// Reserve sessions/ at engagement root for non-Claude session artifacts
	// (operator notes, day-of summaries in docs-format). It's cheap to create
	// up front and avoids surprise mkdir errors later.
	if err := os.MkdirAll(dir+"/sessions", 0o700); err != nil {
		return schema.Engagement{}, fmt.Errorf("engagement: mkdir sessions: %w", err)
	}

	if _, err := keys.NewEngagementKey(m.store, p.ID); err != nil {
		return schema.Engagement{}, err
	}

	e := schema.Engagement{
		ID:             p.ID,
		ClientName:     p.ClientName,
		AssessmentType: p.AssessmentType,
		StartDate:      p.StartDate.UTC(),
		EndDate:        p.EndDate.UTC(),
		Status:         schema.StatusDraft,
		SOWReference:   p.SOWReference,
		OperatorID:     p.OperatorID,
		PrimarySkill:   p.PrimarySkill,
		TransportMode:  p.TransportMode,
		CreatedAt:      m.now(),
	}
	if err := writeEngagementYAML(engagementYAMLPath(m.rootDir, p.ID), e); err != nil {
		return schema.Engagement{}, err
	}

	log, err := audit.Open(auditLogPath(m.rootDir, p.ID), p.ID, m.signer, audit.Options{})
	if err != nil {
		return schema.Engagement{}, err
	}
	payload, err := json.Marshal(map[string]string{
		"event":      "created",
		"client":     p.ClientName,
		"assessment": p.AssessmentType,
		"operator":   p.OperatorID,
	})
	if err != nil {
		_ = log.Close()
		return schema.Engagement{}, fmt.Errorf("engagement: marshal created payload: %w", err)
	}
	if _, err := log.Append(schema.AuditEvent{
		Type:    schema.AuditTypeEngagementLifecycle,
		Actor:   schema.ActorTelepath,
		Payload: payload,
	}); err != nil {
		_ = log.Close()
		return schema.Engagement{}, err
	}
	if err := log.Close(); err != nil {
		return schema.Engagement{}, err
	}
	return e, nil
}

// List returns all engagements under rootDir, sorted by CreatedAt ascending.
// Directories without a parseable engagement.yaml are ignored.
func (m *Manager) List() ([]schema.Engagement, error) {
	entries, err := os.ReadDir(m.rootDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("engagement: list: %w", err)
	}
	var out []schema.Engagement
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		e, err := readEngagementYAML(engagementYAMLPath(m.rootDir, ent.Name()))
		if err != nil {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// Load marks an engagement active: opens its audit log, emits a "loaded"
// lifecycle event, and transitions status from draft→active on first load.
// Errors if another engagement is already active.
func (m *Manager) Load(id string) (*Active, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.active != nil {
		if m.active.Engagement.ID == id {
			return m.active, nil
		}
		return nil, fmt.Errorf("engagement: %q already active; unload it first", m.active.Engagement.ID)
	}

	path := engagementYAMLPath(m.rootDir, id)
	e, err := readEngagementYAML(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("engagement: %q not found", id)
		}
		return nil, err
	}
	if e.Status == schema.StatusSealed || e.Status == schema.StatusArchived {
		return nil, fmt.Errorf("engagement: %q is %s; cannot load", id, e.Status)
	}
	engKey, err := keys.GetEngagementKey(m.store, id)
	if err != nil {
		return nil, fmt.Errorf("engagement: key unavailable: %w", err)
	}

	log, err := audit.Open(auditLogPath(m.rootDir, id), id, m.signer, audit.Options{})
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(map[string]string{"event": "loaded"})
	if err != nil {
		_ = log.Close()
		return nil, fmt.Errorf("engagement: marshal loaded payload: %w", err)
	}
	if _, err := log.Append(schema.AuditEvent{
		Type:    schema.AuditTypeEngagementLifecycle,
		Actor:   schema.ActorTelepath,
		Payload: payload,
	}); err != nil {
		_ = log.Close()
		return nil, err
	}

	if e.Status == schema.StatusDraft {
		e.Status = schema.StatusActive
		if err := writeEngagementYAML(path, e); err != nil {
			_ = log.Close()
			return nil, err
		}
	}

	active := &Active{
		Engagement: e,
		AuditLog:   log,
		Dir:        engagementDir(m.rootDir, id),
	}

	// Open vault (never fatal at load — if the engagement has no vault dir
	// yet it's created by Open).
	v, err := vault.Open(filepath.Join(active.Dir, "vault"), engKey)
	if err != nil {
		_ = log.Close()
		return nil, fmt.Errorf("engagement: open vault: %w", err)
	}
	active.Vault = v

	fs, err := findings.Open(filepath.Join(active.Dir, "findings"))
	if err != nil {
		_ = log.Close()
		return nil, fmt.Errorf("engagement: open findings: %w", err)
	}
	active.Findings = fs

	ns, err := notes.Open(filepath.Join(active.Dir, "notes"))
	if err != nil {
		_ = log.Close()
		return nil, fmt.Errorf("engagement: open notes: %w", err)
	}
	active.Notes = ns

	// Load ROE if present. Missing ROE is non-fatal at load — the operator
	// may set it via `telepath engagement set-roe` after creation. Scope
	// enforcement defaults to deny-everything when ROE is nil (stricter
	// than the v0.1 week-1-2 pass-through stub).
	loaded, err := roe.Load(filepath.Join(active.Dir, "roe.yaml"))
	switch {
	case err == nil:
		active.ROE = loaded
	case errors.Is(err, roe.ErrROEMissing):
		// fine; operator will set it later
	default:
		_ = log.Close()
		return nil, fmt.Errorf("engagement: load ROE: %w", err)
	}

	m.active = active
	return m.active, nil
}

// SetROE writes an ROE document for the given engagement and, if the
// engagement is currently active, hot-swaps the in-memory evaluator.
// Emits an engagement_lifecycle event recording the update.
func (m *Manager) SetROE(id string, yamlBytes []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Parse first — never persist broken ROE.
	parsed, err := roe.Parse(yamlBytes)
	if err != nil {
		return err
	}
	if parsed.EngagementID() != id {
		return fmt.Errorf("engagement: ROE engagement_id %q does not match target %q", parsed.EngagementID(), id)
	}
	path := filepath.Join(engagementDir(m.rootDir, id), "roe.yaml")
	if err := writeAtomic(path, yamlBytes); err != nil {
		return err
	}
	if m.active != nil && m.active.Engagement.ID == id {
		m.active.ROE = parsed
		payload, _ := json.Marshal(map[string]any{
			"event":   "roe_updated",
			"version": parsed.Raw().Version,
		})
		_, _ = m.active.AuditLog.Append(schema.AuditEvent{
			Type:    schema.AuditTypeEngagementLifecycle,
			Actor:   schema.ActorOperator,
			Payload: payload,
		})
	}
	return nil
}

// writeAtomic writes to tmp then renames. Duplicated here to avoid exporting
// engagement's metadata helper.
func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Unload releases the active engagement: emits an "unloaded" lifecycle event,
// triggers a final checkpoint via audit.Log.Close, and clears the active
// slot. Idempotent — no-op when nothing is active.
func (m *Manager) Unload() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		return nil
	}
	payload, _ := json.Marshal(map[string]string{"event": "unloaded"})
	_, _ = m.active.AuditLog.Append(schema.AuditEvent{
		Type:    schema.AuditTypeEngagementLifecycle,
		Actor:   schema.ActorTelepath,
		Payload: payload,
	})
	err := m.active.AuditLog.Close()
	m.active = nil
	return err
}

// Close (seal) finalizes an engagement. Works whether or not the engagement
// is the currently active one. After sealing, the engagement cannot be
// loaded. The engagement key is retained so historical audits remain
// verifiable; a future `engagement purge` command will remove it.
func (m *Manager) Close(id string) (schema.Engagement, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var (
		e        schema.Engagement
		log      *audit.Log
		isActive bool
		err      error
	)

	if m.active != nil && m.active.Engagement.ID == id {
		isActive = true
		e = m.active.Engagement
		log = m.active.AuditLog
	} else {
		e, err = readEngagementYAML(engagementYAMLPath(m.rootDir, id))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return schema.Engagement{}, fmt.Errorf("engagement: %q not found", id)
			}
			return schema.Engagement{}, err
		}
		if e.Status == schema.StatusSealed {
			return schema.Engagement{}, fmt.Errorf("engagement: %q already sealed", id)
		}
		log, err = audit.Open(auditLogPath(m.rootDir, id), id, m.signer, audit.Options{})
		if err != nil {
			return schema.Engagement{}, err
		}
	}

	payload, _ := json.Marshal(map[string]string{"event": "sealed"})
	if _, err := log.Append(schema.AuditEvent{
		Type:    schema.AuditTypeEngagementLifecycle,
		Actor:   schema.ActorTelepath,
		Payload: payload,
	}); err != nil {
		_ = log.Close()
		return schema.Engagement{}, err
	}
	if err := log.Close(); err != nil {
		return schema.Engagement{}, err
	}

	now := m.now()
	e.Status = schema.StatusSealed
	e.SealedAt = &now
	if err := writeEngagementYAML(engagementYAMLPath(m.rootDir, id), e); err != nil {
		return schema.Engagement{}, err
	}
	if isActive {
		m.active = nil
	}
	return e, nil
}

// Get returns a stored engagement by ID without loading it.
func (m *Manager) Get(id string) (schema.Engagement, error) {
	e, err := readEngagementYAML(engagementYAMLPath(m.rootDir, id))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return schema.Engagement{}, fmt.Errorf("engagement: %q not found", id)
		}
		return schema.Engagement{}, err
	}
	return e, nil
}
