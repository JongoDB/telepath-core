package export

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fsc/telepath-core/internal/vault"
	"github.com/fsc/telepath-core/pkg/schema"
)

func setupFixture(t *testing.T) Inputs {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// Fake audit log.
	audit := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(audit, []byte(`{"seq":1,"type":"engagement_lifecycle"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Vault with one item.
	v, err := vault.Open(filepath.Join(dir, "vault"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	h, err := v.Put([]byte("this is some collected evidence"), vault.Metadata{
		ContentType: "text/plain",
		Target:      "jumphost.acme",
		Skill:       "ai-opportunity-discovery",
		Tags:        []string{"ssh_exec"},
	})
	if err != nil {
		t.Fatal(err)
	}
	meta := vault.Metadata{
		SHA256:      h,
		ContentType: "text/plain",
		Size:        int64(len("this is some collected evidence")),
		Target:      "jumphost.acme",
		Skill:       "ai-opportunity-discovery",
		Tags:        []string{"ssh_exec"},
		CollectedAt: time.Now().UTC(),
	}
	return Inputs{
		Engagement: schema.Engagement{
			ID:             "acme-01",
			ClientName:     "Acme",
			AssessmentType: "ai-opportunity-roadmap",
			OperatorID:     "alex",
			StartDate:      time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC),
			EndDate:        time.Date(2026, 5, 3, 0, 0, 0, 0, time.UTC),
		},
		Findings: []schema.Finding{
			{ID: "f_000001", Title: "Triage inbox", Category: "workflow_opportunity", Severity: schema.SeverityMedium, Description: "Ops drops tickets", Status: schema.FindingStatusConfirmed},
			{ID: "f_000002", Title: "Missing MFA", Category: "risk", Severity: schema.SeverityHigh, Status: schema.FindingStatusDraft},
		},
		Notes: []schema.Note{
			{ID: "n_000001", Content: "Sarah mentioned volume spikes on Fridays.", Tags: []string{"interview"}, CreatedAt: time.Now()},
		},
		Vault:        v,
		VaultMeta:    []vault.Metadata{meta},
		AuditLogPath: audit,
		Signer:       priv,
		Now:          time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC),
	}
}

func TestExport_AllArtifactsPresent(t *testing.T) {
	t.Parallel()
	in := setupFixture(t)
	outDir := filepath.Join(t.TempDir(), "bundle")
	out, err := Run(in, outDir)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, p := range []string{out.FindingsJSON, out.ReportMarkdown, out.EvidenceTarball, out.EvidenceManifest, out.AuditCopy, out.Verify} {
		if p == "" {
			t.Errorf("expected non-empty path, got empty")
			continue
		}
		if _, err := os.Stat(p); err != nil {
			t.Errorf("missing %s: %v", p, err)
		}
	}
}

func TestExport_ReportContainsFindingTitles(t *testing.T) {
	t.Parallel()
	in := setupFixture(t)
	outDir := t.TempDir()
	out, err := Run(in, outDir)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out.ReportMarkdown)
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	for _, want := range []string{"Acme", "Triage inbox", "Missing MFA", "n_000001"} {
		if !strings.Contains(body, want) {
			t.Errorf("report missing %q", want)
		}
	}
}

func TestExport_ManifestSignatureVerifies(t *testing.T) {
	t.Parallel()
	in := setupFixture(t)
	outDir := t.TempDir()
	out, err := Run(in, outDir)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out.EvidenceManifest)
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Signature == "" {
		t.Fatal("signature empty")
	}
	// Recompute: strip signature, hash, verify.
	sig, err := hex.DecodeString(m.Signature)
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = ""
	body, err := json.Marshal(&m)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	pub := in.Signer.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, digest[:], sig) {
		t.Error("signature did not verify")
	}
}

func TestExport_TarballContainsEvidence(t *testing.T) {
	t.Parallel()
	in := setupFixture(t)
	outDir := t.TempDir()
	out, err := Run(in, outDir)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(out.EvidenceTarball)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gzr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gzr)
	found := 0
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if strings.HasPrefix(hdr.Name, "evidence/") {
			found++
		}
	}
	if found != 1 {
		t.Errorf("expected 1 evidence file in tarball, got %d", found)
	}
}

func TestExport_VerifyMDReferencesPubKey(t *testing.T) {
	t.Parallel()
	in := setupFixture(t)
	outDir := t.TempDir()
	out, err := Run(in, outDir)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(out.Verify)
	if !strings.Contains(string(data), out.OperatorPublicKey) {
		t.Errorf("VERIFY.md must embed the public key")
	}
}

func TestExport_EmptyFindingsStillWorks(t *testing.T) {
	t.Parallel()
	in := setupFixture(t)
	in.Findings = nil
	in.Notes = nil
	in.VaultMeta = nil
	outDir := t.TempDir()
	out, err := Run(in, outDir)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(out.ReportMarkdown)
	if !strings.Contains(string(data), "No findings recorded") {
		t.Errorf("empty report should state no findings; body=%q", data)
	}
}
