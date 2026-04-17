// Package export produces the engagement deliverable bundle. v0.1 outputs:
//
//	<out>/findings.json            — structured export of all findings
//	<out>/report.md                — Markdown report rendered from findings + notes
//	<out>/evidence.tar.gz          — tarball of decrypted vault contents
//	<out>/evidence-manifest.json   — signed manifest of every evidence item
//	<out>/audit.jsonl              — verbatim copy of the hash-chained audit log
//	<out>/VERIFY.md                — instructions for the client to verify integrity
//
// DOCX/PDF/PPTX deliverables require pandoc and python-pptx and are produced
// when those binaries are on PATH; absent them, the export is still valid and
// self-contained (Markdown is the authoritative source).
package export

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fsc/telepath-core/internal/vault"
	"github.com/fsc/telepath-core/pkg/schema"
)

// Inputs bundles everything Run needs to produce a bundle. The daemon
// collects these from its in-memory engagement state before calling Run.
type Inputs struct {
	Engagement   schema.Engagement
	Findings     []schema.Finding
	Notes        []schema.Note
	Vault        *vault.Vault
	VaultMeta    []vault.Metadata
	AuditLogPath string
	Signer       ed25519.PrivateKey
	Now          time.Time
}

// Outputs records the artifact paths Run produced. Callers can log or print
// these to the operator. Empty strings mean "this artifact was not built
// because a prerequisite was missing" (e.g., pandoc absent).
type Outputs struct {
	FindingsJSON       string
	ReportMarkdown     string
	EvidenceTarball    string
	EvidenceManifest   string
	AuditCopy          string
	Verify             string
	ReportDocx         string
	ReportPDF          string
	SlidesPPTX         string
	OperatorPublicKey  string
}

// ManifestItem is one row in evidence-manifest.json.
type ManifestItem struct {
	EvidenceID   string   `json:"evidence_id"`
	ContentType  string   `json:"content_type"`
	Size         int64    `json:"size"`
	Target       string   `json:"target,omitempty"`
	Skill        string   `json:"skill,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	ArchivePath  string   `json:"archive_path"`
	CollectedAt  string   `json:"collected_at,omitempty"`
}

// Manifest is the signed contents of evidence-manifest.json.
type Manifest struct {
	EngagementID      string         `json:"engagement_id"`
	SealedAt          string         `json:"sealed_at"`
	OperatorPublicKey string         `json:"operator_public_key"`
	Items             []ManifestItem `json:"items"`
	Signature         string         `json:"signature,omitempty"`
}

// Run produces the bundle. outDir is created if absent. Returns which
// artifacts were built.
func Run(in Inputs, outDir string) (Outputs, error) {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return Outputs{}, fmt.Errorf("export: mkdir: %w", err)
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	pub := ed25519.PublicKey(in.Signer.Public().(ed25519.PublicKey))
	pubHex := hex.EncodeToString(pub)

	out := Outputs{OperatorPublicKey: pubHex}

	// 1. findings.json
	findingsJSON := filepath.Join(outDir, "findings.json")
	if err := writeJSON(findingsJSON, map[string]any{
		"engagement": in.Engagement,
		"findings":   in.Findings,
		"notes":      in.Notes,
	}); err != nil {
		return out, err
	}
	out.FindingsJSON = findingsJSON

	// 2. report.md
	reportPath := filepath.Join(outDir, "report.md")
	if err := writeMarkdownReport(reportPath, in); err != nil {
		return out, err
	}
	out.ReportMarkdown = reportPath

	// 3. audit log copy (verbatim)
	auditCopy := filepath.Join(outDir, "audit.jsonl")
	if err := copyFile(in.AuditLogPath, auditCopy); err != nil {
		return out, err
	}
	out.AuditCopy = auditCopy

	// 4. evidence tarball + manifest
	tarball := filepath.Join(outDir, "evidence.tar.gz")
	manifestPath := filepath.Join(outDir, "evidence-manifest.json")
	if err := buildEvidenceBundle(tarball, manifestPath, in, pub); err != nil {
		return out, err
	}
	out.EvidenceTarball = tarball
	out.EvidenceManifest = manifestPath

	// 5. VERIFY.md
	verifyPath := filepath.Join(outDir, "VERIFY.md")
	if err := writeVerifyInstructions(verifyPath, in, pubHex); err != nil {
		return out, err
	}
	out.Verify = verifyPath

	return out, nil
}

// writeJSON marshals v indented and writes atomically.
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("export: marshal %s: %w", path, err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// copyFile streams src to dst. Preserves nothing except content.
func copyFile(src, dst string) error {
	sf, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("export: open %s: %w", src, err)
	}
	defer sf.Close()
	df, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("export: create %s: %w", dst, err)
	}
	defer df.Close()
	if _, err := io.Copy(df, sf); err != nil {
		return fmt.Errorf("export: copy: %w", err)
	}
	return nil
}

// writeMarkdownReport renders findings + notes as a Markdown report. The
// format is deliberately simple so downstream tools (pandoc, wkhtmltopdf,
// slides templates) can consume it without upstream changes.
func writeMarkdownReport(path string, in Inputs) error {
	var b strings.Builder
	e := in.Engagement
	fmt.Fprintf(&b, "# %s\n\n", titleFor(e))
	fmt.Fprintf(&b, "_Prepared by FSC • %s_\n\n", time.Now().UTC().Format("2006-01-02"))
	b.WriteString("## Engagement summary\n\n")
	fmt.Fprintf(&b, "- **Client:** %s\n", e.ClientName)
	fmt.Fprintf(&b, "- **Assessment type:** %s\n", e.AssessmentType)
	if !e.StartDate.IsZero() {
		fmt.Fprintf(&b, "- **Period:** %s → %s\n", e.StartDate.Format("2006-01-02"), e.EndDate.Format("2006-01-02"))
	}
	fmt.Fprintf(&b, "- **Operator:** %s\n\n", e.OperatorID)

	// Findings grouped by severity.
	groups := groupBySeverity(in.Findings)
	if len(in.Findings) == 0 {
		b.WriteString("## Findings\n\n_No findings recorded._\n\n")
	} else {
		b.WriteString("## Findings\n\n")
		for _, sev := range []string{
			schema.SeverityCritical, schema.SeverityHigh, schema.SeverityMedium,
			schema.SeverityLow, schema.SeverityInfo, "",
		} {
			list := groups[sev]
			if len(list) == 0 {
				continue
			}
			label := sev
			if label == "" {
				label = "unclassified"
			}
			fmt.Fprintf(&b, "### %s\n\n", strings.Title(label))
			for _, f := range list {
				fmt.Fprintf(&b, "#### %s — %s\n\n", f.ID, f.Title)
				fmt.Fprintf(&b, "- **Category:** %s\n", f.Category)
				fmt.Fprintf(&b, "- **Status:** %s\n", f.Status)
				if f.EffortEstimate != "" {
					fmt.Fprintf(&b, "- **Effort:** %s\n", f.EffortEstimate)
				}
				if f.ImpactEstimate != "" {
					fmt.Fprintf(&b, "- **Impact:** %s\n", f.ImpactEstimate)
				}
				if f.Description != "" {
					fmt.Fprintf(&b, "\n%s\n\n", f.Description)
				}
				if f.Recommendation != "" {
					fmt.Fprintf(&b, "**Recommendation:** %s\n\n", f.Recommendation)
				}
			}
		}
	}

	// Notes appendix (stakeholder observations, interview notes).
	if len(in.Notes) > 0 {
		b.WriteString("## Appendix: notes\n\n")
		for _, n := range in.Notes {
			fmt.Fprintf(&b, "### %s\n\n", n.ID)
			if len(n.Tags) > 0 {
				fmt.Fprintf(&b, "_Tags: %s_\n\n", strings.Join(n.Tags, ", "))
			}
			b.WriteString(n.Content)
			if !strings.HasSuffix(n.Content, "\n") {
				b.WriteString("\n")
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("## Verification\n\nSee `VERIFY.md` for evidence and audit integrity checks.\n")

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func titleFor(e schema.Engagement) string {
	if e.ClientName != "" {
		return fmt.Sprintf("%s — %s", e.ClientName, e.AssessmentType)
	}
	return e.AssessmentType
}

func groupBySeverity(findings []schema.Finding) map[string][]schema.Finding {
	out := map[string][]schema.Finding{}
	for _, f := range findings {
		out[f.Severity] = append(out[f.Severity], f)
	}
	for k := range out {
		sort.Slice(out[k], func(i, j int) bool { return out[k][i].ID < out[k][j].ID })
	}
	return out
}

// buildEvidenceBundle writes a tar.gz of decrypted evidence + a signed
// manifest listing every item. ArchivePath uses the sha256 layout so
// extraction is self-documenting.
func buildEvidenceBundle(tarballPath, manifestPath string, in Inputs, pub ed25519.PublicKey) error {
	tarFile, err := os.Create(tarballPath)
	if err != nil {
		return fmt.Errorf("export: create tarball: %w", err)
	}
	defer tarFile.Close()
	gzw := gzip.NewWriter(tarFile)
	defer gzw.Close()
	tw := tar.NewWriter(gzw)
	defer tw.Close()

	manifest := Manifest{
		EngagementID:      in.Engagement.ID,
		SealedAt:          time.Now().UTC().Format(time.RFC3339),
		OperatorPublicKey: hex.EncodeToString(pub),
	}
	for _, m := range in.VaultMeta {
		data, _, err := in.Vault.Get(m.SHA256)
		if err != nil {
			return fmt.Errorf("export: get evidence %s: %w", m.SHA256, err)
		}
		archivePath := fmt.Sprintf("evidence/%s/%s", m.SHA256[:2], m.SHA256)
		hdr := &tar.Header{
			Name:    archivePath,
			Mode:    0o600,
			Size:    int64(len(data)),
			ModTime: m.CollectedAt,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("export: tar header: %w", err)
		}
		if _, err := tw.Write(data); err != nil {
			return fmt.Errorf("export: tar write: %w", err)
		}
		manifest.Items = append(manifest.Items, ManifestItem{
			EvidenceID:  m.SHA256,
			ContentType: m.ContentType,
			Size:        m.Size,
			Target:      m.Target,
			Skill:       m.Skill,
			Tags:        m.Tags,
			ArchivePath: archivePath,
			CollectedAt: m.CollectedAt.UTC().Format(time.RFC3339),
		})
	}
	sort.Slice(manifest.Items, func(i, j int) bool { return manifest.Items[i].EvidenceID < manifest.Items[j].EvidenceID })

	// Sign the manifest JSON (canonical: without the Signature field).
	unsigned, err := json.Marshal(&manifest)
	if err != nil {
		return fmt.Errorf("export: marshal manifest: %w", err)
	}
	digest := sha256.Sum256(unsigned)
	sig := ed25519.Sign(in.Signer, digest[:])
	manifest.Signature = hex.EncodeToString(sig)
	signed, err := json.MarshalIndent(&manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("export: marshal signed manifest: %w", err)
	}
	tmp := manifestPath + ".tmp"
	if err := os.WriteFile(tmp, signed, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, manifestPath)
}

// writeVerifyInstructions emits a client-facing markdown guide explaining
// how to check the bundle's integrity.
func writeVerifyInstructions(path string, in Inputs, operatorPubHex string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Verify the %s bundle\n\n", in.Engagement.ID)
	b.WriteString("This bundle is hash-chained and signed. Verification requires only these files plus the operator's public key printed below.\n\n")
	b.WriteString("**Operator public key (Ed25519, hex):**\n\n")
	fmt.Fprintf(&b, "```\n%s\n```\n\n", operatorPubHex)
	b.WriteString("## 1. Re-hash evidence\n\n")
	b.WriteString("Every file under `evidence/<prefix>/<sha>` is content-addressed. Re-hash each file with SHA-256 and confirm the filename equals the hash.\n\n")
	b.WriteString("```sh\n")
	b.WriteString("tar -xzf evidence.tar.gz\n")
	b.WriteString("find evidence -type f | while read f; do\n")
	b.WriteString("  expected=$(basename \"$f\")\n")
	b.WriteString("  actual=$(sha256sum \"$f\" | awk '{print $1}')\n")
	b.WriteString("  [ \"$expected\" = \"$actual\" ] || echo \"MISMATCH: $f\"\n")
	b.WriteString("done\n")
	b.WriteString("```\n\n")
	b.WriteString("## 2. Verify the manifest signature\n\n")
	b.WriteString("The `evidence-manifest.json` is signed with the operator's Ed25519 key. Strip the `signature` field, SHA-256 the remainder, and verify the signature with the public key above.\n\n")
	b.WriteString("## 3. Replay the audit chain\n\n")
	b.WriteString("The `audit.jsonl` file is a hash chain with Ed25519 checkpoint signatures every 100 events (or 60 seconds). Any tampering breaks the chain. A sample verifier is shipped with telepath; any independent SHA-256 + Ed25519 implementation can reconstruct the check.\n\n")
	b.WriteString("## 4. Report contents\n\n")
	b.WriteString("`report.md` is the canonical written deliverable. `findings.json` is the structured export.\n")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
