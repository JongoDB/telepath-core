// Package proxy is the "protocol proxy" layer: protocol-specific handlers
// (SSH, HTTP, later WinRM/browser/files) that dial through a configured
// transport, execute operations against client systems, and return results.
//
// Each handler has a specific API matching its protocol — there is no
// unifying Session interface because the operations don't usefully
// generalize (SSH exec returns stdout+stderr+exit; HTTP returns status+body;
// browser returns screenshots; WinRM is PowerShell). Callers dispatch by
// protocol name.
package proxy

// ExecResult is the shape returned by command-oriented handlers (SSH, WinRM).
// HTTP has its own Response type in the httpproxy subpackage.
type ExecResult struct {
	Stdout     []byte `json:"stdout,omitempty"`
	Stderr     []byte `json:"stderr,omitempty"`
	ExitCode   int    `json:"exit_code"`
	DurationMs int64  `json:"duration_ms"`
}
