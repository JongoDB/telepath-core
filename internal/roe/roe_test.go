package roe

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const sampleROE = `
engagement_id: acme-01
version: 1
in_scope:
  hosts:
    - 10.20.0.0/16
    - jumphost.acme.internal
    - 192.168.1.5
  domains:
    - acme.com
    - "*.acme.onmicrosoft.com"
  saas_tenants:
    - microsoft_365: acme.onmicrosoft.com
    - google_workspace: acme.com
out_of_scope:
  hosts:
    - 10.20.99.0/24
    - hr-sql-01.acme.internal
  domains:
    - legal.acme.com
allowed_protocols:
  - ssh
  - winrm
  - https
blackout_windows:
  - start: 2026-05-01T00:00:00Z
    end:   2026-05-01T04:00:00Z
    reason: maintenance
data_handling:
  retention_days: 90
  require_redaction: true
rate_limits:
  per_host_per_minute: 10
  bulk_data_mb: 100
write_actions:
  policy: require_approval
`

func mustROE(t *testing.T) *ROE {
	t.Helper()
	r, err := Parse([]byte(sampleROE))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return r
}

func TestROE_InScope(t *testing.T) {
	t.Parallel()
	r := mustROE(t)
	cases := []struct {
		target, protocol string
		want             bool
	}{
		{"10.20.5.7", "ssh", true},                       // CIDR match
		{"jumphost.acme.internal", "ssh", true},          // exact host
		{"192.168.1.5", "ssh", true},                     // ip literal
		{"foo.acme.com", "https", true},                  // domain suffix
		{"acme.com", "https", true},                      // exact domain
		{"deep.nested.acme.com", "https", true},          // deeper suffix
		{"acme.onmicrosoft.com", "https", true},          // SaaS tenant
		{"admin.acme.onmicrosoft.com", "https", true},    // suffix of SaaS-domain
		{"https://graph.microsoft.com/v1.0/users", "https", false}, // not in scope
	}
	for _, c := range cases {
		got := r.Check(c.target, c.protocol, time.Unix(0, 0).UTC())
		if got.Allow != c.want {
			t.Errorf("Check(%q, %q) = %v reason=%q; want allow=%v", c.target, c.protocol, got.Allow, got.Reason, c.want)
		}
	}
}

func TestROE_OutOfScopeBeatsInScope(t *testing.T) {
	t.Parallel()
	r := mustROE(t)
	// 10.20.99.5 is inside in-scope 10.20.0.0/16 AND inside out-of-scope 10.20.99.0/24.
	d := r.Check("10.20.99.5", "ssh", time.Unix(0, 0).UTC())
	if d.Allow {
		t.Fatalf("out-of-scope must win; got allow=true reason=%q", d.Reason)
	}
	// hr-sql-01.acme.internal is explicitly out; also not in-scope so we'd
	// deny anyway. Ensure the reason reflects the out-of-scope decision
	// rather than "not in scope."
	d2 := r.Check("hr-sql-01.acme.internal", "ssh", time.Unix(0, 0).UTC())
	if d2.Allow {
		t.Fatalf("explicit out-of-scope must deny")
	}
	if d2.Reason != "target is out of scope" {
		t.Errorf("reason = %q; expected out-of-scope", d2.Reason)
	}
	d3 := r.Check("legal.acme.com", "https", time.Unix(0, 0).UTC())
	if d3.Allow {
		t.Errorf("domain out-of-scope failed: %q", d3.Reason)
	}
}

func TestROE_ProtocolAllowList(t *testing.T) {
	t.Parallel()
	r := mustROE(t)
	d := r.Check("jumphost.acme.internal", "rdp", time.Unix(0, 0).UTC())
	if d.Allow {
		t.Fatalf("rdp must be denied; allowed protocols = [ssh winrm https]")
	}
	if !containsSubstr(d.Reason, "rdp") {
		t.Errorf("reason lacks protocol name: %q", d.Reason)
	}
}

func TestROE_BlackoutWindow(t *testing.T) {
	t.Parallel()
	r := mustROE(t)
	inWindow := time.Date(2026, 5, 1, 2, 0, 0, 0, time.UTC)
	outWindow := time.Date(2026, 5, 1, 5, 0, 0, 0, time.UTC)
	if d := r.Check("jumphost.acme.internal", "ssh", inWindow); d.Allow {
		t.Errorf("blackout window must deny: %q", d.Reason)
	}
	if d := r.Check("jumphost.acme.internal", "ssh", outWindow); !d.Allow {
		t.Errorf("outside window must allow: %q", d.Reason)
	}
}

func TestROE_UnsetProtocolAllowsAnything(t *testing.T) {
	t.Parallel()
	r, err := Parse([]byte(`
engagement_id: x
in_scope:
  hosts: ["1.2.3.4"]
`))
	if err != nil {
		t.Fatal(err)
	}
	d := r.Check("1.2.3.4", "novel_proto", time.Unix(0, 0).UTC())
	if !d.Allow {
		t.Errorf("unset allowed_protocols should permit any; got %q", d.Reason)
	}
}

func TestROE_LoadMissing(t *testing.T) {
	t.Parallel()
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != ErrROEMissing {
		t.Fatalf("got %v, want ErrROEMissing", err)
	}
}

func TestROE_LoadFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "roe.yaml")
	if err := os.WriteFile(path, []byte(sampleROE), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if r.EngagementID() != "acme-01" {
		t.Errorf("id = %q", r.EngagementID())
	}
}

func TestROE_Summary(t *testing.T) {
	t.Parallel()
	r := mustROE(t)
	s := r.Summary()
	if !containsSubstr(s, "in-scope hosts") || !containsSubstr(s, "out-of-scope") {
		t.Errorf("summary unexpected: %q", s)
	}
}

func TestROE_InvalidCIDRFails(t *testing.T) {
	t.Parallel()
	_, err := Parse([]byte(`
engagement_id: x
in_scope:
  hosts: ["not-a-cidr/weird"]
`))
	if err == nil {
		t.Fatal("expected error for bad CIDR")
	}
}

func TestROE_URLStrippedToHostForDomainCheck(t *testing.T) {
	t.Parallel()
	r := mustROE(t)
	// A URL targeting an in-scope domain should allow.
	d := r.Check("https://some-host.acme.com:443/api/v1", "https", time.Unix(0, 0).UTC())
	if !d.Allow {
		t.Errorf("URL under in-scope domain must allow: %q", d.Reason)
	}
}

func containsSubstr(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
