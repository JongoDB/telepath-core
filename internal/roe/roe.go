// Package roe owns parsing, validating, and evaluating the rules-of-engagement
// document for an engagement. "Scope" in telepath is not "does Claude think
// it's in scope" — it's this package's Decision over a target.
//
// The evaluator is the authority. hooks.ScopeCheck in v0.1 week 1-2 was a
// pass-through stub; with this package loaded into the daemon, real scope
// enforcement kicks in.
package roe

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/fsc/telepath-core/pkg/schema"
)

// Decision is the result of evaluating a target against an ROE.
type Decision struct {
	Allow  bool
	Reason string
}

// ROE is an in-memory, pre-parsed rules-of-engagement document. Host, domain,
// and SaaS-tenant entries are split into typed matchers at parse time so
// per-call evaluation is cheap.
type ROE struct {
	raw schema.RulesOfEngagement

	inHosts     []hostMatcher
	outHosts    []hostMatcher
	inDomains   []string
	outDomains  []string
	saasTenants map[string]string // provider -> tenant id
}

// Parse builds an ROE from a yaml.v3-decoded document body. Returns an error
// if required fields are missing or the structure is malformed.
func Parse(data []byte) (*ROE, error) {
	var raw schema.RulesOfEngagement
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("roe: parse: %w", err)
	}
	return fromRaw(raw)
}

// Load reads path and returns an ROE. Missing file returns the special error
// ErrROEMissing so callers can distinguish "no ROE loaded yet" from "ROE is
// broken."
func Load(path string) (*ROE, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrROEMissing
		}
		return nil, fmt.Errorf("roe: read %s: %w", path, err)
	}
	return Parse(data)
}

// ErrROEMissing is returned by Load when roe.yaml does not exist.
var ErrROEMissing = errors.New("roe: document not found")

func fromRaw(raw schema.RulesOfEngagement) (*ROE, error) {
	if raw.EngagementID == "" {
		return nil, errors.New("roe: engagement_id required")
	}
	if raw.Version == 0 {
		raw.Version = 1
	}
	r := &ROE{
		raw:         raw,
		saasTenants: map[string]string{},
	}

	var err error
	r.inHosts, err = compileHostMatchers(raw.InScope.Hosts, "in_scope.hosts")
	if err != nil {
		return nil, err
	}
	r.outHosts, err = compileHostMatchers(raw.OutOfScope.Hosts, "out_of_scope.hosts")
	if err != nil {
		return nil, err
	}
	r.inDomains = normalizeDomains(raw.InScope.Domains)
	r.outDomains = normalizeDomains(raw.OutOfScope.Domains)
	for _, entry := range raw.InScope.SaaSTenants {
		for provider, tenant := range entry {
			r.saasTenants[strings.ToLower(provider)] = tenant
		}
	}
	return r, nil
}

// Raw returns the underlying schema struct for serialization.
func (r *ROE) Raw() schema.RulesOfEngagement { return r.raw }

// EngagementID returns the owning engagement ID.
func (r *ROE) EngagementID() string { return r.raw.EngagementID }

// Summary returns a human-readable one-liner used for SessionStart context.
func (r *ROE) Summary() string {
	parts := []string{}
	if n := len(r.raw.InScope.Hosts); n > 0 {
		parts = append(parts, fmt.Sprintf("%d in-scope hosts", n))
	}
	if n := len(r.raw.InScope.Domains); n > 0 {
		parts = append(parts, fmt.Sprintf("%d domains", n))
	}
	if n := len(r.saasTenants); n > 0 {
		parts = append(parts, fmt.Sprintf("%d SaaS tenants", n))
	}
	if n := len(r.raw.OutOfScope.Hosts) + len(r.raw.OutOfScope.Domains); n > 0 {
		parts = append(parts, fmt.Sprintf("%d out-of-scope entries", n))
	}
	if len(parts) == 0 {
		return "ROE loaded (no scope entries)"
	}
	return "ROE: " + strings.Join(parts, ", ")
}

// Check evaluates whether a target is allowed under this ROE at the given
// wall-clock time. Ordering matches ARCHITECTURE §8.2: out-of-scope beats
// in-scope, protocol allow-list is enforced, blackout windows block all
// targets regardless of scope.
func (r *ROE) Check(target, protocol string, now time.Time) Decision {
	t := strings.TrimSpace(target)
	if t == "" {
		return Decision{Allow: false, Reason: "empty target"}
	}

	if r.matchesOutOfScope(t) {
		return Decision{Allow: false, Reason: "target is out of scope"}
	}
	if !r.matchesInScope(t) {
		return Decision{Allow: false, Reason: "target is not in scope"}
	}
	if protocol != "" && !r.protocolAllowed(protocol) {
		return Decision{Allow: false, Reason: fmt.Sprintf("protocol %q not allowed by ROE", protocol)}
	}
	if win := r.inBlackout(now); win != nil {
		return Decision{Allow: false, Reason: fmt.Sprintf("within blackout window (%s)", win.Reason)}
	}
	return Decision{Allow: true, Reason: "allowed by ROE"}
}

func (r *ROE) matchesInScope(target string) bool {
	if hostMatcherList(r.inHosts).matches(target) {
		return true
	}
	if domainListMatches(r.inDomains, target) {
		return true
	}
	if saasMatches(r.saasTenants, target) {
		return true
	}
	return false
}

func (r *ROE) matchesOutOfScope(target string) bool {
	if hostMatcherList(r.outHosts).matches(target) {
		return true
	}
	if domainListMatches(r.outDomains, target) {
		return true
	}
	return false
}

func (r *ROE) protocolAllowed(protocol string) bool {
	if len(r.raw.AllowedProtocols) == 0 {
		// Unset means "no restriction" for v0.1; real deployments should
		// set this explicitly to avoid accidental allow-all.
		return true
	}
	for _, p := range r.raw.AllowedProtocols {
		if strings.EqualFold(p, protocol) {
			return true
		}
	}
	return false
}

func (r *ROE) inBlackout(now time.Time) *schema.BlackoutWindow {
	for i := range r.raw.BlackoutWindows {
		w := &r.raw.BlackoutWindows[i]
		if w.Start == nil || w.End == nil {
			continue
		}
		if (now.Equal(*w.Start) || now.After(*w.Start)) && now.Before(*w.End) {
			return w
		}
	}
	return nil
}

// --- matcher internals ---

// hostMatcher represents one compiled entry from in_scope.hosts or
// out_of_scope.hosts. Entries are one of:
//   - CIDR (contains "/")
//   - IP literal (parseable as net.IP)
//   - hostname (anything else; matched exactly, case-insensitive)
type hostMatcher struct {
	kind    string // "cidr" | "ip" | "hostname"
	cidr    *net.IPNet
	ip      net.IP
	host    string
}

type hostMatcherList []hostMatcher

func (l hostMatcherList) matches(target string) bool {
	// Target may be an IP literal or a hostname. Resolve once.
	ip := net.ParseIP(target)
	lowered := strings.ToLower(strings.TrimSpace(target))
	for _, m := range l {
		switch m.kind {
		case "cidr":
			if ip != nil && m.cidr.Contains(ip) {
				return true
			}
		case "ip":
			if ip != nil && m.ip.Equal(ip) {
				return true
			}
		case "hostname":
			if lowered == m.host {
				return true
			}
		}
	}
	return false
}

func compileHostMatchers(entries []string, label string) ([]hostMatcher, error) {
	out := make([]hostMatcher, 0, len(entries))
	for _, raw := range entries {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			_, cidr, err := net.ParseCIDR(s)
			if err != nil {
				return nil, fmt.Errorf("roe: %s: invalid CIDR %q: %w", label, s, err)
			}
			out = append(out, hostMatcher{kind: "cidr", cidr: cidr})
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			out = append(out, hostMatcher{kind: "ip", ip: ip})
			continue
		}
		out = append(out, hostMatcher{kind: "hostname", host: strings.ToLower(s)})
	}
	return out, nil
}

// normalizeDomains lowercases and strips any leading "*." or "." prefixes;
// matching always treats entries as "match target.suffix" or "target equals."
func normalizeDomains(entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, raw := range entries {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" {
			continue
		}
		s = strings.TrimPrefix(s, "*.")
		s = strings.TrimPrefix(s, ".")
		out = append(out, s)
	}
	return out
}

func domainListMatches(domains []string, target string) bool {
	lowered := strings.ToLower(strings.TrimSpace(target))
	// Strip URL prefixes so URLs match against their host.
	if i := strings.Index(lowered, "://"); i >= 0 {
		lowered = lowered[i+3:]
	}
	if j := strings.IndexAny(lowered, "/?#"); j >= 0 {
		lowered = lowered[:j]
	}
	// Strip port.
	if k := strings.LastIndex(lowered, ":"); k > 0 && !strings.Contains(lowered[k:], "]") {
		lowered = lowered[:k]
	}
	for _, d := range domains {
		if lowered == d {
			return true
		}
		if strings.HasSuffix(lowered, "."+d) {
			return true
		}
	}
	return false
}

// saasMatches returns true when the target looks like one of the configured
// SaaS tenant identifiers. Heuristic: case-insensitive substring presence of
// the tenant ID in the target, OR equality. Defensive — SaaS checks are
// mostly for display; real enforcement uses domain+hostname.
func saasMatches(tenants map[string]string, target string) bool {
	if len(tenants) == 0 {
		return false
	}
	lowered := strings.ToLower(target)
	for _, tenant := range tenants {
		t := strings.ToLower(strings.TrimSpace(tenant))
		if t == "" {
			continue
		}
		if lowered == t || strings.Contains(lowered, t) {
			return true
		}
	}
	return false
}
