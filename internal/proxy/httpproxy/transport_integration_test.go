package httpproxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/fsc/telepath-core/internal/transport"
)

// countingTransport is a transport.Transport that delegates to the stdlib
// Dialer but records how many Dial calls came through it. Used to prove the
// httpproxy routes requests through the configured transport instead of
// bypassing it via http.Client's default DialContext.
type countingTransport struct {
	dials atomic.Int64
}

func (c *countingTransport) Kind() transport.Kind                      { return transport.KindDirect }
func (c *countingTransport) Up(context.Context, transport.Config) error { return nil }
func (c *countingTransport) Down(context.Context) error                 { return nil }
func (c *countingTransport) Status() transport.Status {
	return transport.Status{Kind: transport.KindDirect, State: transport.StateUp}
}
func (c *countingTransport) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	c.dials.Add(1)
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

func TestHTTP_RoutesThroughTransport(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("routed"))
	}))
	defer srv.Close()

	tr := &countingTransport{}
	h := New(tr)
	res, err := h.Do(context.Background(), Request{URL: srv.URL})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if res.Status != 200 || string(res.Body) != "routed" {
		t.Errorf("unexpected response: status=%d body=%q", res.Status, res.Body)
	}
	// A single request should produce exactly one dial through the transport.
	// If http.Client's internal connection reuse ever lets it skip our
	// DialContext hook, this test will see zero and fail loudly.
	if got := tr.dials.Load(); got != 1 {
		t.Errorf("expected 1 dial through transport, got %d", got)
	}
}

func TestHTTP_NilTransport_StillWorks(t *testing.T) {
	t.Parallel()
	// Sanity check for the New(nil) compatibility path — must still function.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	h := New(nil)
	res, err := h.Do(context.Background(), Request{URL: srv.URL})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if res.Status != 200 {
		t.Errorf("status = %d", res.Status)
	}
}
