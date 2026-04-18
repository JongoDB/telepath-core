package winrmproxy

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/masterzen/winrm"

	"github.com/fsc/telepath-core/internal/transport"
)

// fakeWinRMClient is a stand-in for *winrm.Client. We control what Run*
// returns so tests focus on Handler behavior, not masterzen internals
// (which themselves require a live Windows endpoint).
type fakeWinRMClient struct {
	lastPSCommand  string
	lastCmdCommand string
	stdout, stderr string
	exit           int
	err            error
}

func (f *fakeWinRMClient) RunPSWithContext(ctx context.Context, command string) (string, string, int, error) {
	f.lastPSCommand = command
	return f.stdout, f.stderr, f.exit, f.err
}
func (f *fakeWinRMClient) RunWithContextWithString(ctx context.Context, command string, _ string) (string, string, int, error) {
	f.lastCmdCommand = command
	return f.stdout, f.stderr, f.exit, f.err
}

func withFake(h *Handler, fake *fakeWinRMClient) {
	h.newClient = func(_ *winrm.Endpoint, _ string, _ string, _ *winrm.Parameters) (winrmClient, error) {
		return fake, nil
	}
}

func TestWinRM_PowerShell_HappyPath(t *testing.T) {
	t.Parallel()
	h := New(nil)
	fake := &fakeWinRMClient{stdout: "OK", stderr: "", exit: 0}
	withFake(h, fake)

	res, err := h.PowerShell(context.Background(), Config{
		Host: "dc.example.corp", Username: "svc-telepath", Password: "pw",
	}, "Get-Host")
	if err != nil {
		t.Fatalf("PowerShell: %v", err)
	}
	if string(res.Stdout) != "OK" || res.ExitCode != 0 {
		t.Errorf("unexpected result: %+v", res)
	}
	if fake.lastPSCommand != "Get-Host" {
		t.Errorf("command not forwarded: %q", fake.lastPSCommand)
	}
}

func TestWinRM_Cmd_HappyPath(t *testing.T) {
	t.Parallel()
	h := New(nil)
	fake := &fakeWinRMClient{stdout: "hello", exit: 0}
	withFake(h, fake)

	res, err := h.Cmd(context.Background(), Config{
		Host: "dc.example.corp", Username: "svc-telepath", Password: "pw",
	}, "echo hello", "")
	if err != nil {
		t.Fatalf("Cmd: %v", err)
	}
	if string(res.Stdout) != "hello" {
		t.Errorf("stdout = %q", res.Stdout)
	}
	if fake.lastCmdCommand != "echo hello" {
		t.Errorf("command = %q", fake.lastCmdCommand)
	}
}

func TestWinRM_RequiresHost(t *testing.T) {
	t.Parallel()
	h := New(nil)
	_, err := h.PowerShell(context.Background(), Config{Username: "u", Password: "p"}, "Get-Host")
	if err == nil || err.Error() != "winrmproxy: host required" {
		t.Errorf("expected host required error, got %v", err)
	}
}

func TestWinRM_RequiresUsername(t *testing.T) {
	t.Parallel()
	h := New(nil)
	_, err := h.PowerShell(context.Background(), Config{Host: "h"}, "Get-Host")
	if err == nil || err.Error() != "winrmproxy: username required" {
		t.Errorf("expected username required error, got %v", err)
	}
}

func TestWinRM_DefaultPort(t *testing.T) {
	t.Parallel()
	if DefaultPort(true) != 5986 {
		t.Errorf("https default = %d", DefaultPort(true))
	}
	if DefaultPort(false) != 5985 {
		t.Errorf("http default = %d", DefaultPort(false))
	}
}

// countingTransport is the same shape as httpproxy/sshproxy's integration
// tests — verifies Handler wires Parameters.Dial to the transport when
// one is configured.
type countingTransport struct{ dials atomic.Int64 }

func (c *countingTransport) Kind() transport.Kind                       { return transport.KindDirect }
func (c *countingTransport) Up(context.Context, transport.Config) error { return nil }
func (c *countingTransport) Down(context.Context) error                 { return nil }
func (c *countingTransport) Status() transport.Status {
	return transport.Status{Kind: transport.KindDirect, State: transport.StateUp}
}
func (c *countingTransport) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	c.dials.Add(1)
	return nil, errors.New("countingTransport: not a real dialer")
}

// TestWinRM_TransportDialerIsWired reaches into the run path just far
// enough to verify Parameters.Dial was populated from the transport.
// We call newClient directly, capturing the *winrm.Parameters passed in,
// then invoke its Dial hook and assert the counting transport counted.
func TestWinRM_TransportDialerIsWired(t *testing.T) {
	t.Parallel()
	tr := &countingTransport{}
	h := New(tr)

	var capturedParams *winrm.Parameters
	h.newClient = func(_ *winrm.Endpoint, _ string, _ string, p *winrm.Parameters) (winrmClient, error) {
		capturedParams = p
		return &fakeWinRMClient{exit: 0}, nil
	}

	_, _ = h.PowerShell(context.Background(), Config{
		Host: "winbox", Username: "u", Password: "p",
	}, "Get-Host")

	if capturedParams == nil {
		t.Fatal("newClient was not called")
	}
	if capturedParams.Dial == nil {
		t.Fatal("Parameters.Dial was not wired when transport present")
	}
	// Fire the wired Dial hook; the counting transport should record it.
	_, _ = capturedParams.Dial("tcp", "winbox:5986")
	if got := tr.dials.Load(); got != 1 {
		t.Errorf("expected 1 dial through transport, got %d", got)
	}
}
