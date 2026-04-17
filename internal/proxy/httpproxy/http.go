// Package httpproxy implements the HTTP protocol handler. Used for SaaS
// APIs, generic HTTPS fetches, and as the backbone for OAuth flows (added
// in week 5). Dials through a transport.Transport so traffic follows the
// same routing policy as other protocols.
package httpproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fsc/telepath-core/internal/transport"
)

// InlineBodyLimit bounds the response body kept inline. Larger bodies are
// truncated with Truncated=true; callers that want the full payload should
// use the streaming API once we add it (week 5 for large collections).
const InlineBodyLimit = 1 << 20 // 1 MiB

// Request is the input shape.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
	Timeout time.Duration // 0 = 30s default
}

// Response is the output shape. Headers uses net/http's canonical map for
// convenience (case-insensitive Get via .Get).
type Response struct {
	Status     int         `json:"status"`
	Headers    http.Header `json:"headers"`
	Body       []byte      `json:"body"`
	Truncated  bool        `json:"truncated"`
	DurationMs int64       `json:"duration_ms"`
}

// Handler makes HTTP requests through a Transport.
type Handler struct {
	tr transport.Transport
	// insecureSkipVerify is kept false by default; operators can flip it
	// via config for targets with self-signed certs under ROE approval.
	insecureSkipVerify bool
}

// New constructs a Handler dialing through tr. A nil tr uses default routing
// (equivalent to the direct transport).
func New(tr transport.Transport) *Handler {
	return &Handler{tr: tr}
}

// SetInsecureSkipVerify is a sharp knife. Only call when the operator has
// explicitly approved bypassing TLS verification for a specific target
// under ROE; most production engagements should leave it off.
func (h *Handler) SetInsecureSkipVerify(v bool) { h.insecureSkipVerify = v }

// Do executes req and returns the response. Body is clipped to
// InlineBodyLimit with Truncated=true when it overflows.
func (h *Handler) Do(ctx context.Context, req Request) (Response, error) {
	if req.URL == "" {
		return Response{}, errors.New("httpproxy: URL required")
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	u, err := url.Parse(req.URL)
	if err != nil {
		return Response{}, fmt.Errorf("httpproxy: parse URL: %w", err)
	}

	timeout := req.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	transportClient := &http.Transport{
		// Route every dial through the Transport layer when configured.
		DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
			if h.tr == nil {
				return (&net.Dialer{}).DialContext(dctx, network, addr)
			}
			return h.tr.Dial(dctx, network, addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: h.insecureSkipVerify},
	}
	client := &http.Client{Transport: transportClient}

	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	hreq, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return Response{}, fmt.Errorf("httpproxy: build request: %w", err)
	}
	for k, v := range req.Headers {
		hreq.Header.Set(k, v)
	}

	start := time.Now()
	hresp, err := client.Do(hreq)
	if err != nil {
		return Response{}, fmt.Errorf("httpproxy: request %s: %w", req.URL, err)
	}
	defer hresp.Body.Close()

	lr := io.LimitReader(hresp.Body, InlineBodyLimit+1)
	bodyBytes, err := io.ReadAll(lr)
	if err != nil {
		return Response{}, fmt.Errorf("httpproxy: read body: %w", err)
	}
	truncated := false
	if int64(len(bodyBytes)) > InlineBodyLimit {
		bodyBytes = bodyBytes[:InlineBodyLimit]
		truncated = true
	}

	return Response{
		Status:     hresp.StatusCode,
		Headers:    hresp.Header,
		Body:       bodyBytes,
		Truncated:  truncated,
		DurationMs: time.Since(start).Milliseconds(),
	}, nil
}
