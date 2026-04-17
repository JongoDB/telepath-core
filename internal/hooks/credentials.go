// Package hooks holds the logic invoked by JSON-RPC hook-protocol methods:
// credential redaction, scope checking, and action classification. The
// patterns here mirror hooks/telepath_hook_lib.py in the plugin repo so the
// Python client and Go daemon agree on what counts as a credential.
package hooks

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
)

// credentialPattern associates a regex with the credential type label used
// in audit references. Order matters: earlier patterns win when two match the
// same text (e.g. a bearer token that also looks like a generic secret).
type credentialPattern struct {
	re   *regexp.Regexp
	kind string
}

// credentialPatterns ports hooks/telepath_hook_lib.py CRED_PATTERNS. Keep in
// sync; drift here is the kind of thing that silently weakens redaction.
var credentialPatterns = []credentialPattern{
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "aws_access_key"},
	{regexp.MustCompile(`\baws_secret_access_key\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?`), "aws_secret"},
	{regexp.MustCompile(`\bBearer\s+[A-Za-z0-9._\-~+/=]{20,}\b`), "bearer_token"},
	{regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`), "private_key"},
	{regexp.MustCompile(`://[^:/]+:[^@/]+@`), "password_in_url"},
	{regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`), "github_pat"},
	{regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]+\b`), "slack_token"},
	{regexp.MustCompile(`(?i)(?:password|passwd|apikey|api_key|secret)\s*[=:]\s*["']?([^\s"'&]{8,})["']?`), "generic_secret"},
}

// RedactCredentials replaces credential-like substrings in text with
// reference tokens of the form "<redacted:cred_ref_XXXXXXXX>" and returns
// both the redacted text and a mapping from ref-id to credential kind.
//
// The ref ID is the first 8 hex chars of the SHA-256 of the original match;
// the same credential always maps to the same ref, so callers can correlate
// appearances across logs without storing the credential itself.
func RedactCredentials(text string) (string, map[string]string) {
	mapping := map[string]string{}
	out := text
	for _, p := range credentialPatterns {
		out = p.re.ReplaceAllStringFunc(out, func(match string) string {
			sum := sha256.Sum256([]byte(match))
			ref := "cred_ref_" + hex.EncodeToString(sum[:4])
			mapping[ref] = p.kind
			return "<redacted:" + ref + ">"
		})
	}
	return out, mapping
}
