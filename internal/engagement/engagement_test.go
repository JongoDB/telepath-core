package engagement

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsc/telepath-core/internal/audit"
	"github.com/fsc/telepath-core/internal/keys"
	"github.com/fsc/telepath-core/pkg/schema"
)

func setupManager(t *testing.T) (*Manager, keys.Store, ed25519.PrivateKey) {
	t.Helper()
	dir := t.TempDir()
	store, err := keys.NewFileStore(filepath.Join(dir, "keystore"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	signer, err := keys.GetOrCreateSigningKey(store)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	m := NewManager(filepath.Join(dir, "engagements"), store, signer)
	return m, store, signer
}

func TestManager_CreateAndLoad(t *testing.T) {
	t.Parallel()
	m, store, signer := setupManager(t)

	e, err := m.Create(CreateParams{
		ID:             "acme-01",
		ClientName:     "Acme",
		AssessmentType: "ai-opportunity-roadmap",
		OperatorID:     "alex",
		StartDate:      time.Now(),
		EndDate:        time.Now().Add(14 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if e.Status != schema.StatusDraft {
		t.Errorf("status = %q, want draft", e.Status)
	}

	// Engagement key exists in keystore.
	if _, err := keys.GetEngagementKey(store, "acme-01"); err != nil {
		t.Errorf("engagement key missing: %v", err)
	}

	// Load transitions to active.
	a, err := m.Load("acme-01")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if a.Engagement.Status != schema.StatusActive {
		t.Errorf("loaded status = %q, want active", a.Engagement.Status)
	}

	// Second Load returns the same Active.
	a2, err := m.Load("acme-01")
	if err != nil {
		t.Fatalf("Load twice: %v", err)
	}
	if a2 != a {
		t.Errorf("Load should be idempotent and return same pointer")
	}

	// Close the engagement through the Manager (seals + unloads).
	sealed, err := m.Close("acme-01")
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	if sealed.Status != schema.StatusSealed {
		t.Errorf("sealed status = %q", sealed.Status)
	}
	if sealed.SealedAt == nil {
		t.Errorf("SealedAt not set")
	}
	if m.Active() != nil {
		t.Errorf("Active() should be nil after close")
	}

	// Verify the audit log end-to-end.
	f, err := os.Open(filepath.Join(m.RootDir(), "acme-01", "audit.jsonl"))
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer f.Close()
	res, err := audit.Verify(f, "acme-01", signer.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK() {
		t.Errorf("audit verify issues: %+v", res.Issues)
	}
	// created + loaded + sealed lifecycle events, plus a final checkpoint from Close.
	if res.TotalEvents < 4 {
		t.Errorf("total events = %d, want >=4", res.TotalEvents)
	}
}

func TestManager_Create_RejectsDuplicate(t *testing.T) {
	t.Parallel()
	m, _, _ := setupManager(t)
	p := CreateParams{ID: "dup", ClientName: "C", AssessmentType: "a"}
	if _, err := m.Create(p); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := m.Create(p); err == nil {
		t.Fatalf("expected duplicate create to fail")
	}
}

func TestManager_Create_ValidatesID(t *testing.T) {
	t.Parallel()
	m, _, _ := setupManager(t)
	bad := []string{"", "has space", "has/slash", "..", "A" + string(make([]byte, 100))}
	for _, id := range bad {
		if _, err := m.Create(CreateParams{ID: id, ClientName: "C", AssessmentType: "a"}); err == nil {
			t.Errorf("ID %q: expected error", id)
		}
	}
}

func TestManager_Load_UnknownEngagement(t *testing.T) {
	t.Parallel()
	m, _, _ := setupManager(t)
	if _, err := m.Load("nope"); err == nil {
		t.Fatalf("expected load of missing engagement to fail")
	}
}

func TestManager_Load_CannotSwitchWhileActive(t *testing.T) {
	t.Parallel()
	m, _, _ := setupManager(t)
	for _, id := range []string{"a", "b"} {
		if _, err := m.Create(CreateParams{ID: id, ClientName: "C", AssessmentType: "t"}); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	if _, err := m.Load("a"); err != nil {
		t.Fatalf("load a: %v", err)
	}
	if _, err := m.Load("b"); err == nil {
		t.Fatalf("expected load b to fail while a active")
	}
	if err := m.Unload(); err != nil {
		t.Fatalf("unload: %v", err)
	}
	if _, err := m.Load("b"); err != nil {
		t.Fatalf("load b after unload: %v", err)
	}
}

func TestManager_Close_OnInactiveEngagement(t *testing.T) {
	t.Parallel()
	m, _, signer := setupManager(t)
	if _, err := m.Create(CreateParams{ID: "x", ClientName: "C", AssessmentType: "t"}); err != nil {
		t.Fatal(err)
	}
	// Do not load. Close directly.
	if _, err := m.Close("x"); err != nil {
		t.Fatalf("Close inactive: %v", err)
	}
	// A second Close should fail (already sealed).
	if _, err := m.Close("x"); err == nil {
		t.Fatalf("second Close should fail")
	}
	// Audit log still verifies.
	f, _ := os.Open(filepath.Join(m.RootDir(), "x", "audit.jsonl"))
	defer f.Close()
	res, err := audit.Verify(f, "x", signer.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Errorf("verify issues: %+v", res.Issues)
	}
}

func TestManager_List(t *testing.T) {
	t.Parallel()
	m, _, _ := setupManager(t)
	// Empty list OK.
	list, err := m.List()
	if err != nil || len(list) != 0 {
		t.Fatalf("empty List: %v %v", list, err)
	}
	for _, id := range []string{"alpha", "beta", "gamma"} {
		if _, err := m.Create(CreateParams{ID: id, ClientName: "C", AssessmentType: "t"}); err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
	}
	list, err = m.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("List: got %d, want 3", len(list))
	}

	// Stray directory without engagement.yaml is ignored.
	_ = os.MkdirAll(filepath.Join(m.RootDir(), "not-an-engagement"), 0o700)
	list2, err := m.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list2) != 3 {
		t.Errorf("stray dir polluted List: got %d, want 3", len(list2))
	}
}

func TestManager_LoadSealed_Fails(t *testing.T) {
	t.Parallel()
	m, _, _ := setupManager(t)
	if _, err := m.Create(CreateParams{ID: "s", ClientName: "C", AssessmentType: "t"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Close("s"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Load("s"); err == nil {
		t.Fatalf("expected load of sealed engagement to fail")
	}
}

func TestManager_DirectoryLayout(t *testing.T) {
	t.Parallel()
	m, _, _ := setupManager(t)
	if _, err := m.Create(CreateParams{ID: "layout", ClientName: "C", AssessmentType: "t"}); err != nil {
		t.Fatal(err)
	}
	root := m.RootDir()
	for _, path := range []string{
		filepath.Join(root, "layout", "engagement.yaml"),
		filepath.Join(root, "layout", "audit.jsonl"),
		filepath.Join(root, "layout", ".claude", "sessions"),
		filepath.Join(root, "layout", "sessions"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("missing %s: %v", path, err)
		}
	}
}

func TestManager_Unload_Idempotent(t *testing.T) {
	t.Parallel()
	m, _, _ := setupManager(t)
	if err := m.Unload(); err != nil {
		t.Fatalf("Unload on nothing: %v", err)
	}
	if _, err := m.Create(CreateParams{ID: "u", ClientName: "C", AssessmentType: "t"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Load("u"); err != nil {
		t.Fatal(err)
	}
	if err := m.Unload(); err != nil {
		t.Fatal(err)
	}
	if err := m.Unload(); err != nil {
		t.Fatal(err)
	}
}

// Sanity: ensure the IsPathError wrapping plays nice with errors.Is in
// places the CLI will use.
func TestManager_Load_MissingIsWrappedCleanly(t *testing.T) {
	t.Parallel()
	m, _, _ := setupManager(t)
	_, err := m.Load("missing")
	if err == nil {
		t.Fatalf("expected error")
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		t.Errorf("os.PathError leaked into Load error: %v", err)
	}
}
