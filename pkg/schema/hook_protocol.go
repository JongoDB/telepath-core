package schema

import (
	"encoding/json"
	"time"
)

// JSON-RPC 2.0 framing for the daemon's Unix-socket protocol. The Python hook
// library (hooks/telepath_hook_lib.py in the plugin repo) sends one request
// per connection terminated by a newline and reads one response terminated by
// a newline; this struct shape matches that contract exactly.

// JSONRPCRequest is a client-to-daemon request.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      uint64          `json:"id,omitempty"`
}

// JSONRPCResponse is a daemon-to-client response. Exactly one of Result or
// Error is populated on success/failure.
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
	ID      uint64          `json:"id,omitempty"`
}

// JSONRPCError is a structured error per the spec.
type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Standard JSON-RPC error codes.
const (
	ErrCodeParseError     = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternalError  = -32603
)

// telepath-specific error codes in the reserved range -32000..-32099 is not
// large enough long-term; we allocate -33000..-33999 for product-level errors.
const (
	ErrCodeNoActiveEngagement = -33001
	ErrCodeEngagementNotFound = -33002
	ErrCodeScopeDenied        = -33003
	ErrCodeApprovalDenied     = -33004
	ErrCodeDaemonShuttingDown = -33005
	ErrCodeEvidenceNotFound   = -33006
)

// Method names — mirrored in hooks/telepath_hook_lib.py. Changing a name
// breaks the plugin; add new ones instead.
const (
	MethodPing                 = "ping"
	MethodEngagementGet        = "engagement.get"
	MethodROESummary           = "roe.summary"
	MethodScopeCheck           = "scope.check"
	MethodApprovalClassify     = "approval.classify"
	MethodAuditEmit            = "audit.emit"
	MethodAuditCheckpoint      = "audit.checkpoint"
	MethodAuditUnresolvedWrite = "audit.unresolved_writes"
	MethodSessionWriteSummary  = "session.write_summary"
	MethodCredentialsRedact    = "credentials.redact"
)

// --- Method parameter and result shapes ---

// PingResult is returned by the Ping method.
type PingResult struct {
	OK      bool   `json:"ok"`
	Version string `json:"version"`
}

// ScopeCheckParams is the input for MethodScopeCheck.
type ScopeCheckParams struct {
	Target   string `json:"target"`
	Protocol string `json:"protocol,omitempty"`
}

// ScopeCheckResult is the output for MethodScopeCheck.
type ScopeCheckResult struct {
	OK      bool   `json:"ok"`
	InScope bool   `json:"in_scope"`
	Reason  string `json:"reason"`
}

// ClassifyParams is the input for MethodApprovalClassify.
type ClassifyParams struct {
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input,omitempty"`
}

// ClassifyResult is the output for MethodApprovalClassify.
//
// Blocked means the ROE's write_actions.policy forbids this action
// outright — the hook lib should deny without prompting. RequiresApproval
// covers the "ask operator" case; the two are independent (a Blocked
// result may also set RequiresApproval=true so hook libs that don't
// understand Blocked yet still default to the safer "prompt" behavior).
type ClassifyResult struct {
	OK               bool   `json:"ok"`
	Class            string `json:"class"`
	RequiresApproval bool   `json:"requires_approval"`
	Blocked          bool   `json:"blocked,omitempty"`
	Reason           string `json:"reason,omitempty"`
	BlackoutAdjacent bool   `json:"blackout_adjacent,omitempty"`
	NovelHost        bool   `json:"novel_host,omitempty"`
}

// Action classification values for ClassifyResult.Class.
const (
	ClassReadEnumeration  = "read_enumeration"
	ClassReadBulk         = "read_bulk"
	ClassWriteReversible  = "write_reversible"
	ClassWriteIrreversibl = "write_irreversible"
	ClassNovelHost        = "novel_host"
	ClassBlackoutAdjacent = "blackout_adjacent"
	ClassUnknown          = "unknown"
)

// AuditEmitParams is the input for MethodAuditEmit.
type AuditEmitParams struct {
	Type      string          `json:"type"`
	SessionID string          `json:"session_id,omitempty"`
	Actor     string          `json:"actor,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

// AuditEmitResult is the output for MethodAuditEmit.
type AuditEmitResult struct {
	OK       bool   `json:"ok"`
	Sequence uint64 `json:"seq"`
	Hash     string `json:"hash"`
}

// CheckpointResult is the output for MethodAuditCheckpoint.
type CheckpointResult struct {
	OK            bool   `json:"ok"`
	Sequence      uint64 `json:"seq"`
	SignedThrough uint64 `json:"signed_through"`
}

// UnresolvedWritesParams is the input for MethodAuditUnresolvedWrite.
type UnresolvedWritesParams struct {
	SessionID string `json:"session_id"`
}

// UnresolvedWritesResult is the output for MethodAuditUnresolvedWrite.
type UnresolvedWritesResult struct {
	OK     bool            `json:"ok"`
	Writes []UnresolvedRef `json:"writes"`
}

// UnresolvedRef is a single write action still missing approval.
type UnresolvedRef struct {
	AuditEventID string `json:"audit_event_id"`
	ToolName     string `json:"tool_name"`
	Target       string `json:"target"`
	Timestamp    string `json:"timestamp"`
}

// SessionSummaryParams is the input for MethodSessionWriteSummary.
type SessionSummaryParams struct {
	Content string `json:"content"`
}

// SessionSummaryResult is the output for MethodSessionWriteSummary.
type SessionSummaryResult struct {
	OK   bool   `json:"ok"`
	Path string `json:"path"`
}

// CredentialsRedactParams is the input for MethodCredentialsRedact.
type CredentialsRedactParams struct {
	Text string `json:"text"`
}

// CredentialsRedactResult is the output for MethodCredentialsRedact.
type CredentialsRedactResult struct {
	OK       bool              `json:"ok"`
	Redacted string            `json:"redacted"`
	Mapping  map[string]string `json:"mapping,omitempty"`
}

// ROESummaryResult is the output for MethodROESummary.
type ROESummaryResult struct {
	OK      bool   `json:"ok"`
	Summary string `json:"summary"`
}

// EngagementGetResult wraps an Engagement value in a response. A nil engagement
// marshals to JSON null with OK=true when no engagement is active.
type EngagementGetResult struct {
	OK         bool        `json:"ok"`
	Engagement *Engagement `json:"engagement,omitempty"`
}

// --- Engagement admin methods (CLI → daemon) ---

const (
	MethodEngagementCreate = "engagement.create"
	MethodEngagementLoad   = "engagement.load"
	MethodEngagementUnload = "engagement.unload"
	MethodEngagementList   = "engagement.list"
	MethodEngagementClose  = "engagement.close"
)

// EngagementCreateParams is the input for MethodEngagementCreate.
type EngagementCreateParams struct {
	ID             string `json:"id"`
	ClientName     string `json:"client_name"`
	AssessmentType string `json:"assessment_type"`
	// Dates are RFC3339 strings on the wire; empty means "unset."
	StartDate     string `json:"start_date,omitempty"`
	EndDate       string `json:"end_date,omitempty"`
	SOWReference  string `json:"sow_reference,omitempty"`
	OperatorID    string `json:"operator_id,omitempty"`
	PrimarySkill  string `json:"primary_skill,omitempty"`
	TransportMode string `json:"transport_mode,omitempty"`
}

// EngagementLoadParams is the input for MethodEngagementLoad.
type EngagementLoadParams struct {
	ID string `json:"id"`
}

// EngagementCloseParams is the input for MethodEngagementClose.
type EngagementCloseParams struct {
	ID string `json:"id"`
}

// EngagementCreateResult is the output for MethodEngagementCreate.
type EngagementCreateResult struct {
	OK         bool       `json:"ok"`
	Engagement Engagement `json:"engagement"`
}

// EngagementLoadResult is the output for MethodEngagementLoad.
type EngagementLoadResult struct {
	OK          bool       `json:"ok"`
	Engagement  Engagement `json:"engagement"`
	Dir         string     `json:"dir"`
	ClaudeMDPath string    `json:"claude_md_path,omitempty"`
}

// EngagementListResult is the output for MethodEngagementList.
type EngagementListResult struct {
	OK          bool         `json:"ok"`
	Engagements []Engagement `json:"engagements"`
}

// EngagementCloseResult is the output for MethodEngagementClose.
type EngagementCloseResult struct {
	OK         bool       `json:"ok"`
	Engagement Engagement `json:"engagement"`
}

// MethodEngagementSetROE uploads a new roe.yaml document.
const MethodEngagementSetROE = "engagement.set_roe"

// EngagementSetROEParams is the input. YAML is the literal roe.yaml bytes.
type EngagementSetROEParams struct {
	ID   string `json:"id"`
	YAML string `json:"yaml"`
}

// EngagementSetROEResult is the output.
type EngagementSetROEResult struct {
	OK bool `json:"ok"`
}

// --- Transport admin ---

const (
	MethodTransportUp     = "transport.up"
	MethodTransportDown   = "transport.down"
	MethodTransportStatus = "transport.status"
)

// TransportUpParams is the input for MethodTransportUp.
type TransportUpParams struct {
	Kind string `json:"kind"`

	// Cloudflare Tunnel
	CloudflareAPIToken   string `json:"cloudflare_api_token,omitempty"`
	CloudflareAccountID  string `json:"cloudflare_account_id,omitempty"`
	CloudflareHostname   string `json:"cloudflare_hostname,omitempty"`

	// OpenVPN
	OpenVPNConfigPath string `json:"openvpn_config_path,omitempty"`

	// Shared
	StartupTimeoutSeconds int `json:"startup_timeout_seconds,omitempty"`
}

// TransportStatus mirrors internal/transport.Status on the wire to avoid
// importing daemon-internal types from the schema.
type TransportStatus struct {
	Kind   string `json:"kind"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
	Hint   string `json:"hint,omitempty"`
}

// TransportStatusResult is the output for MethodTransportStatus and
// MethodTransportUp.
type TransportStatusResult struct {
	OK     bool            `json:"ok"`
	Status TransportStatus `json:"status"`
}

// --- Protocol proxy RPCs (called by the MCP adapter) ---

const (
	MethodSSHExec         = "ssh.exec"
	MethodWinRMPowerShell = "winrm.powershell"
	MethodWinRMCmd        = "winrm.cmd"
	MethodHTTPRequest     = "http.request"
	MethodFilesStore      = "files.store_synthesized"
	MethodFilesGet        = "files.get_evidence"
	MethodFilesCollect    = "files.collect"      // SFTP fetch into vault
	MethodFilesListRemote = "files.list_remote"  // SFTP directory listing
	MethodEvidenceSearch  = "evidence.search"
	MethodEvidenceTag     = "evidence.tag"
)

// SSHExecParams is the input for MethodSSHExec.
type SSHExecParams struct {
	Host       string `json:"host"`
	Port       int    `json:"port,omitempty"`
	Username   string `json:"username"`
	// One of Password or PrivateKeyPEM must be supplied. Values are never
	// written to audit (credentials are redacted to references in the
	// PostToolUse hook).
	Password      string `json:"password,omitempty"`
	PrivateKeyPEM string `json:"private_key_pem,omitempty"`
	Passphrase    string `json:"passphrase,omitempty"`
	Command       string `json:"command"`
	TimeoutSec    int    `json:"timeout_seconds,omitempty"`
}

// SSHExecResult is the output for MethodSSHExec.
type SSHExecResult struct {
	OK          bool   `json:"ok"`
	Stdout      []byte `json:"stdout,omitempty"`
	Stderr      []byte `json:"stderr,omitempty"`
	ExitCode    int    `json:"exit_code"`
	DurationMs  int64  `json:"duration_ms"`
	EvidenceID  string `json:"evidence_id,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
}

// WinRMExecParams is the input for MethodWinRMPowerShell and MethodWinRMCmd.
// Default Port: 5985 (HTTP) or 5986 (HTTPS) per the HTTPS flag. Basic
// username+password auth is the v0.1 shape; NTLM/Kerberos follow in v0.2.
type WinRMExecParams struct {
	Host       string `json:"host"`
	Port       int    `json:"port,omitempty"`
	HTTPS      bool   `json:"https,omitempty"`
	Insecure   bool   `json:"insecure,omitempty"` // skip TLS verify
	Username   string `json:"username"`
	Password   string `json:"password,omitempty"`
	Command    string `json:"command"`
	Stdin      string `json:"stdin,omitempty"` // for cmd variant
	TimeoutSec int    `json:"timeout_seconds,omitempty"`
}

// WinRMExecResult is the output. Identical shape to SSHExecResult so hook
// libs can share code for remote-command return handling.
type WinRMExecResult struct {
	OK         bool   `json:"ok"`
	Stdout     []byte `json:"stdout,omitempty"`
	Stderr     []byte `json:"stderr,omitempty"`
	ExitCode   int    `json:"exit_code"`
	DurationMs int64  `json:"duration_ms"`
	EvidenceID string `json:"evidence_id,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
}

// HTTPRequestParams is the input for MethodHTTPRequest.
type HTTPRequestParams struct {
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       []byte            `json:"body,omitempty"`
	TimeoutSec int               `json:"timeout_seconds,omitempty"`
}

// HTTPRequestResult is the output for MethodHTTPRequest.
type HTTPRequestResult struct {
	OK         bool                `json:"ok"`
	Status     int                 `json:"status"`
	Headers    map[string][]string `json:"headers,omitempty"`
	Body       []byte              `json:"body,omitempty"`
	Truncated  bool                `json:"truncated,omitempty"`
	DurationMs int64               `json:"duration_ms"`
	EvidenceID string              `json:"evidence_id,omitempty"`
}

// FilesCollectParams is the input for MethodFilesCollect — a one-shot SFTP
// fetch of a remote file straight into the engagement's vault. Credential
// fields mirror SSHExecParams and carry the same redaction contract.
// Scope is checked against protocol "sftp"; operators who want to allow
// SFTP file collection must list "sftp" in the ROE's allowed_protocols
// (listing "ssh" alone covers ssh.exec only).
type FilesCollectParams struct {
	Host          string   `json:"host"`
	Port          int      `json:"port,omitempty"`
	Username      string   `json:"username"`
	Password      string   `json:"password,omitempty"`
	PrivateKeyPEM string   `json:"private_key_pem,omitempty"`
	Passphrase    string   `json:"passphrase,omitempty"`
	Path          string   `json:"path"`
	Skill         string   `json:"skill,omitempty"`
	Tags          []string `json:"tags,omitempty"`
}

// FilesCollectResult is the output for MethodFilesCollect.
type FilesCollectResult struct {
	OK         bool   `json:"ok"`
	EvidenceID string `json:"evidence_id"`
	Size       int64  `json:"size"`
	Path       string `json:"path"`
}

// FilesListRemoteParams is the input for MethodFilesListRemote — SFTP
// directory listing. Non-recursive by design; one SFTP call per invocation.
type FilesListRemoteParams struct {
	Host          string `json:"host"`
	Port          int    `json:"port,omitempty"`
	Username      string `json:"username"`
	Password      string `json:"password,omitempty"`
	PrivateKeyPEM string `json:"private_key_pem,omitempty"`
	Passphrase    string `json:"passphrase,omitempty"`
	Path          string `json:"path"`
}

// FilesListRemoteResult is the output for MethodFilesListRemote.
type FilesListRemoteResult struct {
	OK      bool              `json:"ok"`
	Entries []RemoteFileEntry `json:"entries"`
}

// RemoteFileEntry is one row in a remote directory listing.
type RemoteFileEntry struct {
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	Mode  string `json:"mode"`
	IsDir bool   `json:"is_dir"`
}

// FilesStoreParams stores Claude-synthesized content (notes, summaries) as
// evidence.
type FilesStoreParams struct {
	Content     string            `json:"content"`
	ContentType string            `json:"content_type,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Description string            `json:"description,omitempty"`
	SessionID   string            `json:"session_id,omitempty"`
	Skill       string            `json:"skill,omitempty"`
	Target      string            `json:"target,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// FilesStoreResult is the output.
type FilesStoreResult struct {
	OK         bool   `json:"ok"`
	EvidenceID string `json:"evidence_id"`
	Size       int64  `json:"size"`
}

// FilesGetParams retrieves evidence content + metadata by ID.
type FilesGetParams struct {
	EvidenceID string `json:"evidence_id"`
}

// FilesGetResult returns the content and metadata.
type FilesGetResult struct {
	OK          bool              `json:"ok"`
	Content     []byte            `json:"content"`
	ContentType string            `json:"content_type"`
	Tags        []string          `json:"tags,omitempty"`
	CollectedAt string            `json:"collected_at,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// EvidenceSearchParams filters evidence by facet.
type EvidenceSearchParams struct {
	Tag       string `json:"tag,omitempty"`
	Skill     string `json:"skill,omitempty"`
	Target    string `json:"target,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Since     string `json:"since,omitempty"` // RFC3339
}

// EvidenceSearchResult returns matching items.
type EvidenceSearchResult struct {
	OK    bool              `json:"ok"`
	Items []EvidenceSummary `json:"items"`
}

// EvidenceSummary is a terse evidence list entry (no content).
type EvidenceSummary struct {
	EvidenceID  string   `json:"evidence_id"`
	ContentType string   `json:"content_type"`
	Size        int64    `json:"size"`
	Skill       string   `json:"skill,omitempty"`
	Target      string   `json:"target,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	CollectedAt string   `json:"collected_at,omitempty"`
}

// EvidenceTagParams adds tags to existing evidence.
type EvidenceTagParams struct {
	EvidenceID string   `json:"evidence_id"`
	Tags       []string `json:"tags"`
}

// EvidenceTagResult is the output.
type EvidenceTagResult struct {
	OK   bool     `json:"ok"`
	Tags []string `json:"tags"`
}

// --- Findings ---

const (
	MethodFindingsCreate   = "findings.create"
	MethodFindingsUpdate   = "findings.update"
	MethodFindingsGet      = "findings.get"
	MethodFindingsList     = "findings.list"
	MethodFindingsSetStatus = "findings.set_status"
)

// Finding is the structured record per ARCHITECTURE.md §4.4.
type Finding struct {
	ID              string    `json:"id" yaml:"id"`
	Title           string    `json:"title" yaml:"title"`
	Category        string    `json:"category" yaml:"category"`
	Severity        string    `json:"severity" yaml:"severity"`
	Status          string    `json:"status" yaml:"status"`
	Description     string    `json:"description" yaml:"description"`
	Evidence        []string  `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Recommendation  string    `json:"recommendation,omitempty" yaml:"recommendation,omitempty"`
	EffortEstimate  string    `json:"effort_estimate,omitempty" yaml:"effort_estimate,omitempty"`
	ImpactEstimate  string    `json:"impact_estimate,omitempty" yaml:"impact_estimate,omitempty"`
	ConfidenceLevel string    `json:"confidence_level,omitempty" yaml:"confidence_level,omitempty"`
	CreatedAt       time.Time `json:"created_at" yaml:"created_at"`
	UpdatedAt       time.Time `json:"updated_at" yaml:"updated_at"`
	CreatedBy       string    `json:"created_by,omitempty" yaml:"created_by,omitempty"`
}

// Finding status and severity constants.
const (
	FindingStatusDraft     = "draft"
	FindingStatusConfirmed = "confirmed"
	FindingStatusDismissed = "dismissed"

	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// FindingCreateParams is the input. ID is auto-assigned.
type FindingCreateParams struct {
	Finding Finding `json:"finding"`
}

// FindingCreateResult is the output.
type FindingCreateResult struct {
	OK      bool    `json:"ok"`
	Finding Finding `json:"finding"`
}

// FindingUpdateParams updates fields on an existing finding.
type FindingUpdateParams struct {
	ID      string            `json:"id"`
	Updates map[string]string `json:"updates"`
	Reason  string            `json:"reason,omitempty"`
}

// FindingUpdateResult is the output.
type FindingUpdateResult struct {
	OK      bool    `json:"ok"`
	Finding Finding `json:"finding"`
}

// FindingGetParams fetches a finding by ID.
type FindingGetParams struct {
	ID string `json:"id"`
}

// FindingGetResult is the output.
type FindingGetResult struct {
	OK      bool    `json:"ok"`
	Finding Finding `json:"finding"`
}

// FindingListParams filters by facet.
type FindingListParams struct {
	Category string `json:"category,omitempty"`
	Severity string `json:"severity,omitempty"`
	Status   string `json:"status,omitempty"`
}

// FindingListResult is the output.
type FindingListResult struct {
	OK       bool      `json:"ok"`
	Findings []Finding `json:"findings"`
}

// FindingSetStatusParams transitions status.
type FindingSetStatusParams struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// FindingSetStatusResult is the output.
type FindingSetStatusResult struct {
	OK      bool    `json:"ok"`
	Finding Finding `json:"finding"`
}

// --- Notes ---

const (
	MethodNotesCreate = "notes.create"
	MethodNotesList   = "notes.list"
	MethodNotesGet    = "notes.get"
)

// Note is a freeform engagement observation.
type Note struct {
	ID               string    `json:"id" yaml:"id"`
	Content          string    `json:"content" yaml:"-"` // stored in body, not frontmatter
	Tags             []string  `json:"tags,omitempty" yaml:"tags,omitempty"`
	RelatedEvidence  []string  `json:"related_evidence,omitempty" yaml:"related_evidence,omitempty"`
	RelatedFindings  []string  `json:"related_findings,omitempty" yaml:"related_findings,omitempty"`
	CreatedAt        time.Time `json:"created_at" yaml:"created_at"`
	CreatedBy        string    `json:"created_by,omitempty" yaml:"created_by,omitempty"`
}

// NoteCreateParams is the input.
type NoteCreateParams struct {
	Note Note `json:"note"`
}

// NoteCreateResult is the output.
type NoteCreateResult struct {
	OK   bool `json:"ok"`
	Note Note `json:"note"`
}

// NoteListParams filters notes.
type NoteListParams struct {
	Tag        string `json:"tag,omitempty"`
	Since      string `json:"since,omitempty"` // RFC3339
	TextSearch string `json:"text_search,omitempty"`
}

// NoteListResult is the output.
type NoteListResult struct {
	OK    bool   `json:"ok"`
	Notes []Note `json:"notes"`
}

// NoteGetParams fetches a note by ID.
type NoteGetParams struct {
	ID string `json:"id"`
}

// NoteGetResult is the output.
type NoteGetResult struct {
	OK   bool `json:"ok"`
	Note Note `json:"note"`
}

// --- Engagement export ---

const MethodEngagementExport = "engagement.export"

// EngagementExportParams is the input.
type EngagementExportParams struct {
	ID     string `json:"id"`
	OutDir string `json:"out_dir"`
}

// EngagementExportResult reports which artifacts were produced.
type EngagementExportResult struct {
	OK                bool     `json:"ok"`
	OutDir            string   `json:"out_dir"`
	Artifacts         []string `json:"artifacts"`
	OperatorPublicKey string   `json:"operator_public_key"`
}
