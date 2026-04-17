package schema

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestHexBytes_RoundTrip(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   HexBytes
		want string
	}{
		{"nil", nil, "null"},
		{"empty", HexBytes{}, "null"},
		{"one byte", HexBytes{0xab}, `"ab"`},
		{"multi", HexBytes{0xde, 0xad, 0xbe, 0xef}, `"deadbeef"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := json.Marshal(tc.in)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("marshal: got %s, want %s", got, tc.want)
			}
			var back HexBytes
			if err := json.Unmarshal(got, &back); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if !bytes.Equal(back, tc.in) && !(len(back) == 0 && len(tc.in) == 0) {
				t.Errorf("round trip: got %x, want %x", back, tc.in)
			}
		})
	}
}

func TestHexBytes_UnmarshalInvalid(t *testing.T) {
	t.Parallel()
	var h HexBytes
	if err := json.Unmarshal([]byte(`"zzzz"`), &h); err == nil {
		t.Fatalf("expected error for invalid hex, got nil")
	}
}

func TestAuditEvent_ComputeHashDeterministic(t *testing.T) {
	t.Parallel()
	ts := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)
	prev := GenesisPrevHash("eng-1")
	e1 := AuditEvent{
		Sequence:     1,
		Timestamp:    ts,
		Type:         AuditTypeEngagementLifecycle,
		EngagementID: "eng-1",
		Actor:        ActorTelepath,
		Payload:      json.RawMessage(`{"event":"created"}`),
		PreviousHash: prev,
	}
	h1, err := e1.ComputeHash()
	if err != nil {
		t.Fatalf("compute 1: %v", err)
	}

	// Same struct values, fresh instance -> same hash.
	e2 := e1
	h2, err := e2.ComputeHash()
	if err != nil {
		t.Fatalf("compute 2: %v", err)
	}
	if !bytes.Equal(h1, h2) {
		t.Fatalf("non-deterministic hash: %x vs %x", h1, h2)
	}

	// A different payload produces a different hash.
	e3 := e1
	e3.Payload = json.RawMessage(`{"event":"closed"}`)
	h3, err := e3.ComputeHash()
	if err != nil {
		t.Fatalf("compute 3: %v", err)
	}
	if bytes.Equal(h1, h3) {
		t.Fatalf("payload change did not affect hash")
	}
}

func TestAuditEvent_HashFieldIgnoredInHash(t *testing.T) {
	t.Parallel()
	e := AuditEvent{
		Sequence:     2,
		Timestamp:    time.Unix(0, 0).UTC(),
		Type:         AuditTypeMCPCall,
		EngagementID: "eng-x",
		PreviousHash: HexBytes{0x00},
	}
	h1, err := e.ComputeHash()
	if err != nil {
		t.Fatal(err)
	}
	e.Hash = HexBytes{0xff, 0xfe}
	h2, err := e.ComputeHash()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(h1, h2) {
		t.Fatalf("Hash field must not influence computed hash: %x vs %x", h1, h2)
	}
}

func TestAuditEvent_GenesisPrevHashUnique(t *testing.T) {
	t.Parallel()
	a := GenesisPrevHash("eng-a")
	b := GenesisPrevHash("eng-b")
	if bytes.Equal(a, b) {
		t.Fatalf("genesis prev_hash collided across engagements")
	}
}
