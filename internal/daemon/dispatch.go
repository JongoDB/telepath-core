package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/fsc/telepath-core/internal/engagement"
	"github.com/fsc/telepath-core/internal/export"
	"github.com/fsc/telepath-core/internal/findings"
	"github.com/fsc/telepath-core/internal/hooks"
	"github.com/fsc/telepath-core/internal/keys"
	"github.com/fsc/telepath-core/internal/notes"
	"github.com/fsc/telepath-core/internal/proxy"
	"github.com/fsc/telepath-core/internal/proxy/httpproxy"
	"github.com/fsc/telepath-core/internal/proxy/sftpproxy"
	"github.com/fsc/telepath-core/internal/proxy/sshproxy"
	"github.com/fsc/telepath-core/internal/proxy/winrmproxy"
	"github.com/fsc/telepath-core/internal/rendering"
	"github.com/fsc/telepath-core/internal/transport"
	"github.com/fsc/telepath-core/internal/vault"
	"github.com/fsc/telepath-core/pkg/schema"
)

// dispatch is the single entry point for all JSON-RPC methods served by the
// daemon. Unknown methods get a structured MethodNotFound error so the
// client (Python hook lib or CLI) can distinguish "daemon is not aware of
// this method" from "method ran and errored out."
func (d *Daemon) dispatch(ctx context.Context, req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	switch req.Method {
	case schema.MethodPing:
		return d.handlePing(req)
	case schema.MethodEngagementGet:
		return d.handleEngagementGet(req)
	case schema.MethodROESummary:
		return d.handleROESummary(req)
	case schema.MethodScopeCheck:
		return d.handleScopeCheck(req)
	case schema.MethodApprovalClassify:
		return d.handleApprovalClassify(req)
	case schema.MethodAuditEmit:
		return d.handleAuditEmit(req)
	case schema.MethodAuditCheckpoint:
		return d.handleAuditCheckpoint(req)
	case schema.MethodAuditUnresolvedWrite:
		return d.handleUnresolvedWrites(req)
	case schema.MethodSessionWriteSummary:
		return d.handleSessionWriteSummary(req)
	case schema.MethodCredentialsRedact:
		return d.handleCredentialsRedact(req)
	case schema.MethodEngagementCreate:
		return d.handleEngagementCreate(req)
	case schema.MethodEngagementLoad:
		return d.handleEngagementLoad(req)
	case schema.MethodEngagementUnload:
		return d.handleEngagementUnload(req)
	case schema.MethodEngagementList:
		return d.handleEngagementList(req)
	case schema.MethodEngagementClose:
		return d.handleEngagementClose(req)
	case schema.MethodEngagementSetROE:
		return d.handleEngagementSetROE(req)
	case schema.MethodTransportUp:
		return d.handleTransportUp(req)
	case schema.MethodTransportDown:
		return d.handleTransportDown(req)
	case schema.MethodTransportStatus:
		return d.handleTransportStatus(req)
	case schema.MethodSSHExec:
		return d.handleSSHExec(req)
	case schema.MethodWinRMPowerShell:
		return d.handleWinRMExec(req, true)
	case schema.MethodWinRMCmd:
		return d.handleWinRMExec(req, false)
	case schema.MethodHTTPRequest:
		return d.handleHTTPRequest(req)
	case schema.MethodFilesStore:
		return d.handleFilesStore(req)
	case schema.MethodFilesGet:
		return d.handleFilesGet(req)
	case schema.MethodFilesCollect:
		return d.handleFilesCollect(req)
	case schema.MethodFilesListRemote:
		return d.handleFilesListRemote(req)
	case schema.MethodEvidenceSearch:
		return d.handleEvidenceSearch(req)
	case schema.MethodEvidenceTag:
		return d.handleEvidenceTag(req)
	case schema.MethodOAuthBegin:
		return d.handleOAuthBegin(req)
	case schema.MethodOAuthComplete:
		return d.handleOAuthComplete(req)
	case schema.MethodOAuthStatus:
		return d.handleOAuthStatus(req)
	case schema.MethodSaaSRequest:
		return d.handleSaaSRequest(req)
	case schema.MethodSaaSRefresh:
		return d.handleSaaSRefresh(req)
	case schema.MethodFindingsCreate:
		return d.handleFindingsCreate(req)
	case schema.MethodFindingsUpdate:
		return d.handleFindingsUpdate(req)
	case schema.MethodFindingsGet:
		return d.handleFindingsGet(req)
	case schema.MethodFindingsList:
		return d.handleFindingsList(req)
	case schema.MethodFindingsSetStatus:
		return d.handleFindingsSetStatus(req)
	case schema.MethodNotesCreate:
		return d.handleNotesCreate(req)
	case schema.MethodNotesList:
		return d.handleNotesList(req)
	case schema.MethodNotesGet:
		return d.handleNotesGet(req)
	case schema.MethodEngagementExport:
		return d.handleEngagementExport(req)
	default:
		return nil, rpcErr(schema.ErrCodeMethodNotFound, fmt.Sprintf("method %q not implemented", req.Method))
	}
}

func (d *Daemon) handlePing(_ *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	return encodeResult(schema.PingResult{OK: true, Version: Version})
}

func (d *Daemon) handleEngagementGet(_ *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	active := d.manager.Active()
	res := schema.EngagementGetResult{OK: true}
	if active != nil {
		e := active.Engagement
		res.Engagement = &e
	}
	return encodeResult(res)
}

func (d *Daemon) handleROESummary(_ *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	active := d.manager.Active()
	if active == nil || active.ROE == nil {
		return encodeResult(hooks.ROESummary())
	}
	return encodeResult(schema.ROESummaryResult{OK: true, Summary: active.ROE.Summary()})
}

func (d *Daemon) handleScopeCheck(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.ScopeCheckParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	active := d.manager.Active()
	// Stricter than the week-1-2 stub: with no ROE we DENY rather than
	// pass-through. Operator-visible error message makes the reason
	// actionable ("set ROE first"). The old stub still lives in hooks.ScopeCheck
	// so tests that exercise the pre-ROE state can reference it directly.
	if active == nil {
		return nil, rpcErr(schema.ErrCodeNoActiveEngagement, "scope.check: no active engagement")
	}
	if active.ROE == nil {
		return encodeResult(schema.ScopeCheckResult{
			OK:      true,
			InScope: false,
			Reason:  "no ROE loaded; set one via `telepath engagement set-roe`",
		})
	}
	dec := active.ROE.Check(p.Target, p.Protocol, time.Now().UTC())
	return encodeResult(schema.ScopeCheckResult{OK: true, InScope: dec.Allow, Reason: dec.Reason})
}

func (d *Daemon) handleApprovalClassify(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.ClassifyParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	c := hooks.Classify(p.ToolName, p.ToolInput)
	// With an active engagement + ROE, the write_actions.policy supersedes
	// the classifier's default RequiresApproval for write-class actions.
	// The policy has three shapes:
	//   - "always" (alias: WritePolicyAlwaysApprove): approve writes without
	//     prompting — useful for engagements with an already-signed SOW
	//     covering write-class ops.
	//   - "require_approval": prompt the operator on every write (default
	//     when the field is unset or empty).
	//   - "never": deny writes outright; surface via Blocked=true so hook
	//     libs that understand the flag short-circuit without prompting.
	// Read classifications never take the policy branch — there is nothing
	// to approve or block about a read.
	if active := d.manager.Active(); active != nil && active.ROE != nil && isWriteClass(c.Class) {
		switch active.ROE.WriteActions().Policy {
		case schema.WritePolicyAlwaysApprove:
			c.RequiresApproval = false
			c.Reason = "ROE write_actions.policy=always; auto-approved"
		case schema.WritePolicyNever:
			c.Blocked = true
			c.RequiresApproval = true
			c.Reason = "ROE write_actions.policy=never; blocked"
		case schema.WritePolicyRequireApproval, "":
			// Keep the classifier's default (RequiresApproval=true for writes).
			// Empty policy intentionally falls through — conservative default.
		}
	}
	return encodeResult(c)
}

// isWriteClass reports whether a classification class is a write variant.
// Keeping it here (not in the hooks package) avoids circular knowledge
// about ROE policy in the classifier itself — the classifier stays pure,
// the daemon layers policy on top.
func isWriteClass(class string) bool {
	return class == schema.ClassWriteReversible || class == schema.ClassWriteIrreversibl
}

func (d *Daemon) handleAuditEmit(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.AuditEmitParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	if p.Type == "" {
		return nil, rpcErr(schema.ErrCodeInvalidParams, "audit.emit: type required")
	}
	active := d.manager.Active()
	if active == nil {
		return nil, rpcErr(schema.ErrCodeNoActiveEngagement, "audit.emit: no active engagement")
	}
	ev, err := active.AuditLog.Append(schema.AuditEvent{
		Type:      p.Type,
		SessionID: p.SessionID,
		Actor:     p.Actor,
		Payload:   p.Payload,
	})
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	return encodeResult(schema.AuditEmitResult{
		OK:       true,
		Sequence: ev.Sequence,
		Hash:     ev.Hash.String(),
	})
}

func (d *Daemon) handleAuditCheckpoint(_ *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	active := d.manager.Active()
	if active == nil {
		return nil, rpcErr(schema.ErrCodeNoActiveEngagement, "audit.checkpoint: no active engagement")
	}
	ev, err := active.AuditLog.Checkpoint()
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	var cp schema.CheckpointPayload
	_ = json.Unmarshal(ev.Payload, &cp)
	return encodeResult(schema.CheckpointResult{
		OK:            true,
		Sequence:      ev.Sequence,
		SignedThrough: cp.SignedThrough,
	})
}

func (d *Daemon) handleUnresolvedWrites(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	// v0.1 pass-through. Classification (approval.classify) is fully wired
	// as of v0.1.12, but correlating "classified as write" with "approval
	// audited later" requires a contract with the telepath-v2 hook lib —
	// payload keys, sequence references — that we haven't coordinated
	// across repos yet. v0.2 plan: introduce AuditTypeWriteAction +
	// AuditTypeApprovalDecision; unresolved = write_actions in this
	// session without a matching approval_decision keyed by sequence. The
	// schema + handler land here; the hook lib emits the events from
	// pre/post_tool_use on the plugin side.
	//
	// Returning an empty list is safe: Stop-hook callers treat an empty
	// result as "no pending writes" which is the correct answer until the
	// tracking machinery is in place. A runaway write-class tool that
	// bypasses the hook flow would still show up in the audit log for
	// manual review via `telepath engagement export` + post-hoc scan.
	var p schema.UnresolvedWritesParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	return encodeResult(schema.UnresolvedWritesResult{OK: true, Writes: []schema.UnresolvedRef{}})
}

func (d *Daemon) handleSessionWriteSummary(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.SessionSummaryParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	active := d.manager.Active()
	if active == nil {
		return nil, rpcErr(schema.ErrCodeNoActiveEngagement, "session.write_summary: no active engagement")
	}
	dir := filepath.Join(active.Dir, ".claude", "sessions")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	fname := time.Now().UTC().Format("2006-01-02") + ".md"
	path := filepath.Join(dir, fname)
	if err := os.WriteFile(path, []byte(p.Content), 0o600); err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	// Best-effort audit. If this fails, the content is still saved; we
	// don't want to lose the summary because the chain hiccuped.
	meta, _ := json.Marshal(map[string]any{
		"path":  path,
		"bytes": len(p.Content),
	})
	_, _ = active.AuditLog.Append(schema.AuditEvent{
		Type:    schema.AuditTypeSessionSummary,
		Actor:   schema.ActorTelepath,
		Payload: meta,
	})
	return encodeResult(schema.SessionSummaryResult{OK: true, Path: path})
}

func (d *Daemon) handleCredentialsRedact(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.CredentialsRedactParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	redacted, mapping := hooks.RedactCredentials(p.Text)
	return encodeResult(schema.CredentialsRedactResult{
		OK:       true,
		Redacted: redacted,
		Mapping:  mapping,
	})
}

// --- helpers ---

func encodeResult(v any) (json.RawMessage, *schema.JSONRPCError) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	return data, nil
}

func unmarshalParams(params json.RawMessage, dst any) *schema.JSONRPCError {
	if len(params) == 0 {
		return nil
	}
	if err := json.Unmarshal(params, dst); err != nil {
		return rpcErr(schema.ErrCodeInvalidParams, fmt.Sprintf("params: %v", err))
	}
	return nil
}

func rpcErr(code int, msg string) *schema.JSONRPCError {
	return &schema.JSONRPCError{Code: code, Message: msg}
}

// --- Engagement admin handlers ---

func (d *Daemon) handleEngagementCreate(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.EngagementCreateParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	start, err := parseDateMaybe(p.StartDate)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInvalidParams, fmt.Sprintf("start_date: %v", err))
	}
	end, err := parseDateMaybe(p.EndDate)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInvalidParams, fmt.Sprintf("end_date: %v", err))
	}
	created, err := d.manager.Create(engagement.CreateParams{
		ID:             p.ID,
		ClientName:     p.ClientName,
		AssessmentType: p.AssessmentType,
		StartDate:      start,
		EndDate:        end,
		SOWReference:   p.SOWReference,
		OperatorID:     p.OperatorID,
		PrimarySkill:   p.PrimarySkill,
		TransportMode:  p.TransportMode,
	})
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	return encodeResult(schema.EngagementCreateResult{OK: true, Engagement: created})
}

func (d *Daemon) handleEngagementLoad(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.EngagementLoadParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	active, err := d.manager.Load(p.ID)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	claudeMDPath, err := rendering.WriteForEngagement(active.Engagement, active.Dir, rendering.TemplatePathFromEnv())
	if err != nil {
		// Rendering failure does not invalidate the load — the engagement
		// is active, the audit log has the "loaded" event, and the operator
		// can retry render. Surface the error in a log message but don't
		// bail.
		d.logger.Warn("engagement.load: render CLAUDE.md failed", "err", err, "id", p.ID)
		claudeMDPath = ""
	}
	if n, rerr := rendering.WriteRules(active.Dir, rendering.PluginRulesDirFromEnv()); rerr != nil {
		d.logger.Warn("engagement.load: write rules failed", "err", rerr, "id", p.ID)
	} else if n > 0 {
		d.logger.Info("engagement.load: rules copied", "count", n)
	}
	if _, rerr := rendering.WriteMCPConfig(active.Dir, d.cfg.SocketPath, ""); rerr != nil {
		d.logger.Warn("engagement.load: write mcp.json failed", "err", rerr, "id", p.ID)
	}
	return encodeResult(schema.EngagementLoadResult{
		OK:           true,
		Engagement:   active.Engagement,
		Dir:          active.Dir,
		ClaudeMDPath: claudeMDPath,
	})
}

func (d *Daemon) handleEngagementUnload(_ *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	if err := d.manager.Unload(); err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	return encodeResult(map[string]any{"ok": true})
}

func (d *Daemon) handleEngagementList(_ *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	list, err := d.manager.List()
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	if list == nil {
		list = []schema.Engagement{}
	}
	return encodeResult(schema.EngagementListResult{OK: true, Engagements: list})
}

func (d *Daemon) handleEngagementClose(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.EngagementCloseParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	sealed, err := d.manager.Close(p.ID)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	return encodeResult(schema.EngagementCloseResult{OK: true, Engagement: sealed})
}

func (d *Daemon) handleEngagementSetROE(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.EngagementSetROEParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	if p.ID == "" || p.YAML == "" {
		return nil, rpcErr(schema.ErrCodeInvalidParams, "engagement.set_roe: id and yaml required")
	}
	if err := d.manager.SetROE(p.ID, []byte(p.YAML)); err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	return encodeResult(schema.EngagementSetROEResult{OK: true})
}

// --- Transport handlers ---

func (d *Daemon) handleTransportUp(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.TransportUpParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	if p.Kind == "" {
		return nil, rpcErr(schema.ErrCodeInvalidParams, "transport.up: kind required")
	}
	// Tear down any current transport before bringing a new one up.
	if cur := d.Transport(); cur != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = cur.Down(ctx)
		cancel()
	}
	tr, err := transport.New(transport.Kind(p.Kind))
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInvalidParams, err.Error())
	}
	cfg := transport.Config{
		CloudflareAPIToken:    p.CloudflareAPIToken,
		CloudflareAccountID:   p.CloudflareAccountID,
		CloudflareHostname:    p.CloudflareHostname,
		OpenVPNConfigPath:     p.OpenVPNConfigPath,
		StartupTimeoutSeconds: p.StartupTimeoutSeconds,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := tr.Up(ctx, cfg); err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	d.SetTransport(tr)
	if active := d.manager.Active(); active != nil {
		payload, _ := json.Marshal(map[string]any{"event": "transport_up", "kind": p.Kind})
		_, _ = active.AuditLog.Append(schema.AuditEvent{
			Type:    schema.AuditTypeEngagementLifecycle,
			Actor:   schema.ActorOperator,
			Payload: payload,
		})
	}
	return encodeResult(schema.TransportStatusResult{OK: true, Status: transportStatusToWire(tr.Status())})
}

func (d *Daemon) handleTransportDown(_ *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	cur := d.Transport()
	if cur == nil {
		return encodeResult(schema.TransportStatusResult{
			OK:     true,
			Status: schema.TransportStatus{State: "down"},
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := cur.Down(ctx); err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	d.SetTransport(nil)
	if active := d.manager.Active(); active != nil {
		payload, _ := json.Marshal(map[string]any{"event": "transport_down"})
		_, _ = active.AuditLog.Append(schema.AuditEvent{
			Type:    schema.AuditTypeEngagementLifecycle,
			Actor:   schema.ActorOperator,
			Payload: payload,
		})
	}
	return encodeResult(schema.TransportStatusResult{OK: true, Status: schema.TransportStatus{State: "down"}})
}

func (d *Daemon) handleTransportStatus(_ *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	cur := d.Transport()
	if cur == nil {
		return encodeResult(schema.TransportStatusResult{
			OK:     true,
			Status: schema.TransportStatus{State: "down"},
		})
	}
	return encodeResult(schema.TransportStatusResult{OK: true, Status: transportStatusToWire(cur.Status())})
}

func transportStatusToWire(s transport.Status) schema.TransportStatus {
	return schema.TransportStatus{
		Kind:   string(s.Kind),
		State:  string(s.State),
		Detail: s.Detail,
		Hint:   s.Hint,
	}
}

// --- Protocol / findings / notes / evidence handlers ---

// requireActive returns the current active engagement or an ErrCodeNoActiveEngagement
// JSON-RPC error. Used at the top of every handler that needs an engagement.
func (d *Daemon) requireActive() (*engagement.Active, *schema.JSONRPCError) {
	a := d.manager.Active()
	if a == nil {
		return nil, rpcErr(schema.ErrCodeNoActiveEngagement, "no active engagement")
	}
	return a, nil
}

// checkScope enforces ROE on a target before an action touches client
// systems. Returns a ScopeDenied JSON-RPC error when blocked. When no ROE
// is loaded, the daemon denies by default (safer than the week-1-2 stub).
func (d *Daemon) checkScope(active *engagement.Active, target, protocol string) *schema.JSONRPCError {
	if active.ROE == nil {
		return rpcErr(schema.ErrCodeScopeDenied, "no ROE loaded; run `telepath engagement set-roe` before running tool calls")
	}
	dec := active.ROE.Check(target, protocol, time.Now().UTC())
	if !dec.Allow {
		return rpcErr(schema.ErrCodeScopeDenied, dec.Reason)
	}
	return nil
}

func (d *Daemon) handleSSHExec(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.SSHExecParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	active, rpcE := d.requireActive()
	if rpcE != nil {
		return nil, rpcE
	}
	if rpcE := d.checkScope(active, p.Host, "ssh"); rpcE != nil {
		return nil, rpcE
	}
	tr := d.Transport()
	// Allow direct-without-configured-transport for local testing so the
	// smoke test can exercise SSH against loopback without bringing up a
	// real tunnel first.
	h := sshproxy.New(tr, nil)
	ctx, cancel := context.WithTimeout(context.Background(), timeoutFromSec(p.TimeoutSec, 30*time.Second))
	defer cancel()
	res, err := h.Exec(ctx, p.Host, p.Port, sshproxy.Credentials{
		Username:   p.Username,
		Password:   p.Password,
		KeyData:    []byte(p.PrivateKeyPEM),
		Passphrase: p.Passphrase,
	}, p.Command)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}

	out := schema.SSHExecResult{
		OK:         true,
		Stdout:     res.Stdout,
		Stderr:     res.Stderr,
		ExitCode:   res.ExitCode,
		DurationMs: res.DurationMs,
	}
	// Redact + store big outputs in the vault.
	redacted, _ := hooks.RedactCredentials(string(res.Stdout))
	if len(redacted) > 1<<20 && active.Vault != nil {
		id, verr := active.Vault.Put([]byte(redacted), vault.Metadata{
			ContentType: "text/plain",
			Target:      p.Host,
			Command:     p.Command,
			SessionID:   "", // filled by MCP adapter when known
			Tags:        []string{"ssh_exec"},
		})
		if verr == nil {
			out.EvidenceID = id
			out.Stdout = nil
			out.Truncated = true
		}
	}
	d.auditMCPCall(active, "ssh.exec", map[string]any{
		"host":      p.Host,
		"command":   p.Command,
		"exit_code": res.ExitCode,
	})
	return encodeResult(out)
}

// handleWinRMExec dispatches both PowerShell and cmd.exe variants. The
// isPowerShell flag is the only difference at the protocol seam. Scope is
// checked with protocol "winrm" — operators list it in allowed_protocols
// to opt into Windows remote command execution, same opt-in shape as ssh.
func (d *Daemon) handleWinRMExec(req *schema.JSONRPCRequest, isPowerShell bool) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.WinRMExecParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	active, rpcE := d.requireActive()
	if rpcE != nil {
		return nil, rpcE
	}
	if rpcE := d.checkScope(active, p.Host, "winrm"); rpcE != nil {
		return nil, rpcE
	}
	h := winrmproxy.New(d.Transport())
	ctx, cancel := context.WithTimeout(context.Background(), timeoutFromSec(p.TimeoutSec, 60*time.Second))
	defer cancel()
	cfg := winrmproxy.Config{
		Host:       p.Host,
		Port:       p.Port,
		HTTPS:      p.HTTPS,
		Insecure:   p.Insecure,
		Username:   p.Username,
		Password:   p.Password,
		TimeoutSec: p.TimeoutSec,
	}
	var res proxy.ExecResult
	var err error
	if isPowerShell {
		res, err = h.PowerShell(ctx, cfg, p.Command)
	} else {
		res, err = h.Cmd(ctx, cfg, p.Command, p.Stdin)
	}
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	out := schema.WinRMExecResult{
		OK:         true,
		Stdout:     res.Stdout,
		Stderr:     res.Stderr,
		ExitCode:   res.ExitCode,
		DurationMs: res.DurationMs,
	}
	// Redact + vault large outputs, mirroring ssh.exec.
	redacted, _ := hooks.RedactCredentials(string(res.Stdout))
	if len(redacted) > 1<<20 && active.Vault != nil {
		kind := "winrm_cmd"
		if isPowerShell {
			kind = "winrm_powershell"
		}
		id, verr := active.Vault.Put([]byte(redacted), vault.Metadata{
			ContentType: "text/plain",
			Target:      p.Host,
			Command:     p.Command,
			SessionID:   "",
			Tags:        []string{kind},
		})
		if verr == nil {
			out.EvidenceID = id
			out.Stdout = nil
			out.Truncated = true
		}
	}
	method := "winrm.cmd"
	if isPowerShell {
		method = "winrm.powershell"
	}
	d.auditMCPCall(active, method, map[string]any{
		"host":      p.Host,
		"command":   p.Command,
		"exit_code": res.ExitCode,
	})
	return encodeResult(out)
}

func (d *Daemon) handleHTTPRequest(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.HTTPRequestParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	active, rpcE := d.requireActive()
	if rpcE != nil {
		return nil, rpcE
	}
	if rpcE := d.checkScope(active, p.URL, "https"); rpcE != nil {
		return nil, rpcE
	}
	h := httpproxy.New(d.Transport())
	ctx, cancel := context.WithTimeout(context.Background(), timeoutFromSec(p.TimeoutSec, 30*time.Second))
	defer cancel()
	r, err := h.Do(ctx, httpproxy.Request{
		Method:  p.Method,
		URL:     p.URL,
		Headers: p.Headers,
		Body:    p.Body,
		Timeout: timeoutFromSec(p.TimeoutSec, 30*time.Second),
	})
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	out := schema.HTTPRequestResult{
		OK:         true,
		Status:     r.Status,
		Headers:    r.Headers,
		Body:       r.Body,
		Truncated:  r.Truncated,
		DurationMs: r.DurationMs,
	}
	d.auditMCPCall(active, "http.request", map[string]any{
		"method": p.Method,
		"url":    p.URL,
		"status": r.Status,
	})
	return encodeResult(out)
}

func (d *Daemon) handleFilesStore(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.FilesStoreParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	active, rpcE := d.requireActive()
	if rpcE != nil {
		return nil, rpcE
	}
	ct := p.ContentType
	if ct == "" {
		ct = "text/plain; charset=utf-8"
	}
	id, err := active.Vault.Put([]byte(p.Content), vault.Metadata{
		ContentType:       ct,
		Tags:              p.Tags,
		SessionID:         p.SessionID,
		Skill:             p.Skill,
		Target:            p.Target,
		CollectionContext: p.Description,
	})
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	d.auditMCPCall(active, "files.store_synthesized", map[string]any{
		"evidence_id": id,
		"size":        len(p.Content),
		"skill":       p.Skill,
	})
	return encodeResult(schema.FilesStoreResult{OK: true, EvidenceID: id, Size: int64(len(p.Content))})
}

func (d *Daemon) handleFilesGet(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.FilesGetParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	active, rpcE := d.requireActive()
	if rpcE != nil {
		return nil, rpcE
	}
	content, meta, err := active.Vault.Get(p.EvidenceID)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	return encodeResult(schema.FilesGetResult{
		OK:          true,
		Content:     content,
		ContentType: meta.ContentType,
		Tags:        meta.Tags,
		CollectedAt: meta.CollectedAt.UTC().Format(time.RFC3339),
	})
}

func (d *Daemon) handleEvidenceSearch(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.EvidenceSearchParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	active, rpcE := d.requireActive()
	if rpcE != nil {
		return nil, rpcE
	}
	filter := vault.Filter{
		Tag:       p.Tag,
		Skill:     p.Skill,
		Target:    p.Target,
		SessionID: p.SessionID,
	}
	if p.Since != "" {
		t, err := time.Parse(time.RFC3339, p.Since)
		if err == nil {
			filter.Since = t
		}
	}
	list, err := active.Vault.Search(filter)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	items := make([]schema.EvidenceSummary, 0, len(list))
	for _, m := range list {
		items = append(items, schema.EvidenceSummary{
			EvidenceID:  m.SHA256,
			ContentType: m.ContentType,
			Size:        m.Size,
			Skill:       m.Skill,
			Target:      m.Target,
			Tags:        m.Tags,
			CollectedAt: m.CollectedAt.UTC().Format(time.RFC3339),
		})
	}
	return encodeResult(schema.EvidenceSearchResult{OK: true, Items: items})
}

// handleFilesCollect fetches a remote file via SFTP into the engagement's
// vault. Scope is checked against protocol "sftp" — operators must list it
// in the ROE's allowed_protocols list explicitly (we intentionally do not
// treat "ssh" as implying "sftp" since exec and file exfil are different
// risk tiers).
func (d *Daemon) handleFilesCollect(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.FilesCollectParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	if p.Host == "" || p.Path == "" {
		return nil, rpcErr(schema.ErrCodeInvalidParams, "host and path are required")
	}
	active, rpcE := d.requireActive()
	if rpcE != nil {
		return nil, rpcE
	}
	if rpcE := d.checkScope(active, p.Host, "sftp"); rpcE != nil {
		return nil, rpcE
	}
	tr := d.Transport()
	h := sftpproxy.New(tr, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	data, err := h.Get(ctx, p.Host, p.Port, sshproxy.Credentials{
		Username:   p.Username,
		Password:   p.Password,
		KeyData:    []byte(p.PrivateKeyPEM),
		Passphrase: p.Passphrase,
	}, p.Path)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	id, err := active.Vault.Put(data, vault.Metadata{
		ContentType: "application/octet-stream",
		Target:      p.Host,
		Skill:       p.Skill,
		Tags:        p.Tags,
		CollectionContext: fmt.Sprintf("sftp %s:%s", p.Host, p.Path),
	})
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	d.auditMCPCall(active, "files.collect", map[string]any{
		"host":        p.Host,
		"path":        p.Path,
		"size":        len(data),
		"evidence_id": id,
	})
	return encodeResult(schema.FilesCollectResult{
		OK:         true,
		EvidenceID: id,
		Size:       int64(len(data)),
		Path:       p.Path,
	})
}

// handleFilesListRemote returns an SFTP directory listing. Read-class
// operation (no vault write); scope-checked with protocol "sftp".
func (d *Daemon) handleFilesListRemote(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.FilesListRemoteParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	if p.Host == "" || p.Path == "" {
		return nil, rpcErr(schema.ErrCodeInvalidParams, "host and path are required")
	}
	active, rpcE := d.requireActive()
	if rpcE != nil {
		return nil, rpcE
	}
	if rpcE := d.checkScope(active, p.Host, "sftp"); rpcE != nil {
		return nil, rpcE
	}
	tr := d.Transport()
	h := sftpproxy.New(tr, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	entries, err := h.List(ctx, p.Host, p.Port, sshproxy.Credentials{
		Username:   p.Username,
		Password:   p.Password,
		KeyData:    []byte(p.PrivateKeyPEM),
		Passphrase: p.Passphrase,
	}, p.Path)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	out := make([]schema.RemoteFileEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, schema.RemoteFileEntry{
			Name:  e.Name,
			Size:  e.Size,
			Mode:  e.Mode,
			IsDir: e.IsDir,
		})
	}
	d.auditMCPCall(active, "files.list_remote", map[string]any{
		"host":  p.Host,
		"path":  p.Path,
		"count": len(entries),
	})
	return encodeResult(schema.FilesListRemoteResult{OK: true, Entries: out})
}

// handleEvidenceTag merges tags into an existing evidence item's metadata.
// The ciphertext is never touched — only the side-car .meta.json — so this
// is safe to call repeatedly without reencrypting the payload.
func (d *Daemon) handleEvidenceTag(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.EvidenceTagParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	if p.EvidenceID == "" {
		return nil, rpcErr(schema.ErrCodeInvalidParams, "evidence_id required")
	}
	active, rpcE := d.requireActive()
	if rpcE != nil {
		return nil, rpcE
	}
	merged, err := active.Vault.AddTags(p.EvidenceID, p.Tags)
	if err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			return nil, rpcErr(schema.ErrCodeEvidenceNotFound, fmt.Sprintf("evidence %s not found", p.EvidenceID))
		}
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	return encodeResult(schema.EvidenceTagResult{OK: true, Tags: merged})
}

func (d *Daemon) handleFindingsCreate(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.FindingCreateParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	active, rpcE := d.requireActive()
	if rpcE != nil {
		return nil, rpcE
	}
	f, err := active.Findings.Create(p.Finding)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	d.auditMCPCall(active, "findings.create", map[string]any{"id": f.ID, "title": f.Title})
	return encodeResult(schema.FindingCreateResult{OK: true, Finding: f})
}

func (d *Daemon) handleFindingsUpdate(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.FindingUpdateParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	active, rpcE := d.requireActive()
	if rpcE != nil {
		return nil, rpcE
	}
	f, err := active.Findings.Update(p.ID, p.Updates, p.Reason)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	d.auditMCPCall(active, "findings.update", map[string]any{"id": p.ID, "reason": p.Reason})
	return encodeResult(schema.FindingUpdateResult{OK: true, Finding: f})
}

func (d *Daemon) handleFindingsGet(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.FindingGetParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	active, rpcE := d.requireActive()
	if rpcE != nil {
		return nil, rpcE
	}
	f, err := active.Findings.Get(p.ID)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	return encodeResult(schema.FindingGetResult{OK: true, Finding: f})
}

func (d *Daemon) handleFindingsList(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.FindingListParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	active, rpcE := d.requireActive()
	if rpcE != nil {
		return nil, rpcE
	}
	list, err := active.Findings.List(findings.ListFilter{
		Category: p.Category,
		Severity: p.Severity,
		Status:   p.Status,
	})
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	if list == nil {
		list = []schema.Finding{}
	}
	return encodeResult(schema.FindingListResult{OK: true, Findings: list})
}

func (d *Daemon) handleFindingsSetStatus(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.FindingSetStatusParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	active, rpcE := d.requireActive()
	if rpcE != nil {
		return nil, rpcE
	}
	f, err := active.Findings.SetStatus(p.ID, p.Status, p.Reason)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	d.auditMCPCall(active, "findings.set_status", map[string]any{"id": p.ID, "status": p.Status})
	return encodeResult(schema.FindingSetStatusResult{OK: true, Finding: f})
}

func (d *Daemon) handleNotesCreate(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.NoteCreateParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	active, rpcE := d.requireActive()
	if rpcE != nil {
		return nil, rpcE
	}
	n, err := active.Notes.Create(p.Note)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	d.auditMCPCall(active, "notes.create", map[string]any{"id": n.ID})
	return encodeResult(schema.NoteCreateResult{OK: true, Note: n})
}

func (d *Daemon) handleNotesList(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.NoteListParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	active, rpcE := d.requireActive()
	if rpcE != nil {
		return nil, rpcE
	}
	filter := notes.ListFilter{Tag: p.Tag, TextSearch: p.TextSearch}
	if p.Since != "" {
		t, err := time.Parse(time.RFC3339, p.Since)
		if err == nil {
			filter.Since = t
		}
	}
	list, err := active.Notes.List(filter)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	if list == nil {
		list = []schema.Note{}
	}
	return encodeResult(schema.NoteListResult{OK: true, Notes: list})
}

func (d *Daemon) handleNotesGet(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.NoteGetParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	active, rpcE := d.requireActive()
	if rpcE != nil {
		return nil, rpcE
	}
	n, err := active.Notes.Get(p.ID)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	return encodeResult(schema.NoteGetResult{OK: true, Note: n})
}

func (d *Daemon) handleEngagementExport(req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	var p schema.EngagementExportParams
	if err := unmarshalParams(req.Params, &p); err != nil {
		return nil, err
	}
	if p.ID == "" || p.OutDir == "" {
		return nil, rpcErr(schema.ErrCodeInvalidParams, "engagement.export: id and out_dir required")
	}
	e, err := d.manager.Get(p.ID)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeEngagementNotFound, err.Error())
	}
	engDir := filepath.Join(d.manager.RootDir(), p.ID)

	engKey, err := keys.GetEngagementKey(d.keys, p.ID)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, "engagement key unavailable: "+err.Error())
	}
	v, err := vault.Open(filepath.Join(engDir, "vault"), engKey)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	fs, err := findings.Open(filepath.Join(engDir, "findings"))
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	ns, err := notes.Open(filepath.Join(engDir, "notes"))
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	fList, err := fs.List(findings.ListFilter{})
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	nList, err := ns.List(notes.ListFilter{})
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	meta, err := v.List()
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	outs, err := export.Run(export.Inputs{
		Engagement:   e,
		Findings:     fList,
		Notes:        nList,
		Vault:        v,
		VaultMeta:    meta,
		AuditLogPath: filepath.Join(engDir, "audit.jsonl"),
		Signer:       d.signer,
	}, p.OutDir)
	if err != nil {
		return nil, rpcErr(schema.ErrCodeInternalError, err.Error())
	}
	// Collect non-empty artifact paths for the response.
	artifacts := []string{}
	for _, p := range []string{outs.FindingsJSON, outs.ReportMarkdown, outs.EvidenceTarball, outs.EvidenceManifest, outs.AuditCopy, outs.Verify, outs.ReportDocx, outs.ReportPDF, outs.SlidesPPTX} {
		if p != "" {
			artifacts = append(artifacts, p)
		}
	}
	return encodeResult(schema.EngagementExportResult{
		OK:                true,
		OutDir:            p.OutDir,
		Artifacts:         artifacts,
		OperatorPublicKey: outs.OperatorPublicKey,
	})
}

// auditMCPCall records an MCP-level tool invocation in the audit log.
// Best-effort — never fails a handler because audit logging hit an error.
func (d *Daemon) auditMCPCall(active *engagement.Active, tool string, payload map[string]any) {
	body, err := json.Marshal(map[string]any{
		"tool":    tool,
		"payload": payload,
	})
	if err != nil {
		return
	}
	_, _ = active.AuditLog.Append(schema.AuditEvent{
		Type:    schema.AuditTypeMCPCall,
		Actor:   schema.ActorClaudeCode,
		Payload: body,
	})
}

// timeoutFromSec converts a seconds-valued config field to a time.Duration,
// using fallback when unset.
func timeoutFromSec(sec int, fallback time.Duration) time.Duration {
	if sec <= 0 {
		return fallback
	}
	return time.Duration(sec) * time.Second
}

// parseDateMaybe parses RFC3339 or a bare YYYY-MM-DD. Empty input returns
// the zero time and no error.
func parseDateMaybe(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02", s)
}

// Ensures the fs.ErrNotExist and os imports survive future simplifications.
// Remove if/when a real use lands.
var (
	_ = fs.ErrNotExist
	_ = filepath.Join
	_ = os.O_RDONLY
)
