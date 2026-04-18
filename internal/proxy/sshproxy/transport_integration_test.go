package sshproxy

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsc/telepath-core/internal/transport"
)

// countingTransport is a transport.Transport that delegates to the stdlib
// Dialer but counts Dial invocations. Proves sshproxy.New(tr, hostKey)
// actually routes through the transport — the test would catch a
// regression where the handler fell back to stdlib net.Dial.
type countingTransport struct {
	dials atomic.Int64
}

func (c *countingTransport) Kind() transport.Kind                       { return transport.KindDirect }
func (c *countingTransport) Up(context.Context, transport.Config) error { return nil }
func (c *countingTransport) Down(context.Context) error                 { return nil }
func (c *countingTransport) Status() transport.Status {
	return transport.Status{Kind: transport.KindDirect, State: transport.StateUp}
}
func (c *countingTransport) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	c.dials.Add(1)
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

func TestSSH_RoutesThroughTransport(t *testing.T) {
	t.Parallel()
	srv := startTestServer(t)
	tr := &countingTransport{}
	h := New(tr, srv.signer.PublicKey())
	host, port := splitHostPort(t, srv.addr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := h.Exec(ctx, host, port, Credentials{
		Username: "alex",
		Password: "correct horse battery staple",
	}, "uname")
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit = %d", res.ExitCode)
	}
	if got := tr.dials.Load(); got != 1 {
		t.Errorf("expected 1 dial through transport, got %d", got)
	}
}
