package hooks

import (
	"strings"
	"testing"
)

func TestRedactCredentials_AWSAccessKey(t *testing.T) {
	t.Parallel()
	in := "sent to AKIA1234567890ABCDEF for processing"
	out, mapping := RedactCredentials(in)
	if strings.Contains(out, "AKIA1234567890ABCDEF") {
		t.Errorf("AWS key not redacted: %q", out)
	}
	if !strings.Contains(out, "<redacted:cred_ref_") {
		t.Errorf("expected ref token in %q", out)
	}
	if len(mapping) != 1 {
		t.Errorf("expected one entry, got %+v", mapping)
	}
	for _, v := range mapping {
		if v != "aws_access_key" {
			t.Errorf("kind = %q, want aws_access_key", v)
		}
	}
}

func TestRedactCredentials_DeterministicRefs(t *testing.T) {
	t.Parallel()
	in := "AKIAABCDEFGHIJKLMNOP and AKIAABCDEFGHIJKLMNOP again"
	out, mapping := RedactCredentials(in)
	count := strings.Count(out, "<redacted:")
	if count != 2 {
		t.Fatalf("expected 2 redactions, got %d (%q)", count, out)
	}
	if len(mapping) != 1 {
		t.Errorf("same credential should map to one ref, got %+v", mapping)
	}
}

func TestRedactCredentials_PrivateKey(t *testing.T) {
	t.Parallel()
	in := "-----BEGIN RSA PRIVATE KEY-----\nMIICetc\n-----END"
	out, mapping := RedactCredentials(in)
	if strings.Contains(out, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Errorf("PEM header not redacted: %q", out)
	}
	if len(mapping) == 0 {
		t.Errorf("no redaction mapping")
	}
}

func TestRedactCredentials_GenericSecret(t *testing.T) {
	t.Parallel()
	in := `config: password="hunter2hunter2" more`
	out, mapping := RedactCredentials(in)
	if strings.Contains(out, "hunter2hunter2") {
		t.Errorf("generic secret leaked: %q", out)
	}
	if len(mapping) == 0 {
		t.Errorf("no redaction mapping")
	}
}

func TestRedactCredentials_PassThroughSafeText(t *testing.T) {
	t.Parallel()
	in := "this is a benign string with no secrets"
	out, mapping := RedactCredentials(in)
	if out != in {
		t.Errorf("benign text was modified: %q -> %q", in, out)
	}
	if len(mapping) != 0 {
		t.Errorf("unexpected mapping: %+v", mapping)
	}
}

func TestRedactCredentials_URLPassword(t *testing.T) {
	t.Parallel()
	in := "https://admin:p%40ss@server.internal/path"
	out, _ := RedactCredentials(in)
	if strings.Contains(out, "admin:p%40ss") {
		t.Errorf("URL password leaked: %q", out)
	}
}
