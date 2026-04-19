package dashboard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Server is the localhost HTTP server that renders the dashboard. It
// binds only to 127.0.0.1 — we never listen on a routable interface —
// so the security posture is "if you can run processes as this user you
// can already read the keystore anyway."
type Server struct {
	// Addr is the bind address after Start returns. Zero-port requests
	// ("127.0.0.1:0") are resolved here so callers can print the real
	// URL for the operator.
	Addr    string
	httpSrv *http.Server
	listen  net.Listener
}

// Config bundles dashboard server options. Zero values take sane
// defaults.
type Config struct {
	// BindAddr is the TCP address to listen on. Defaults to
	// "127.0.0.1:0" (localhost + ephemeral port).
	BindAddr string
	// Fetcher is the backend RPC client. Required.
	Fetcher Fetcher
}

// Start binds the listener, begins serving, and returns the running
// Server. The server runs until Shutdown is called; errors from
// Serve are logged (v0.2 will pipe them back to the caller — v0.1
// keeps the surface minimal).
func Start(cfg Config) (*Server, error) {
	if cfg.Fetcher == nil {
		return nil, errors.New("dashboard: Fetcher required")
	}
	addr := cfg.BindAddr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dashboard: listen %s: %w", addr, err)
	}
	h := &Handler{Fetcher: cfg.Fetcher}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		// Write / idle are generous — this is operator-facing polling.
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	return &Server{
		Addr:    ln.Addr().String(),
		httpSrv: srv,
		listen:  ln,
	}, nil
}

// URL returns a ready-to-paste http:// URL for the browser.
func (s *Server) URL() string { return "http://" + s.Addr }

// Shutdown stops the server gracefully, waiting up to 5 seconds for
// in-flight requests to drain.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpSrv == nil {
		return nil
	}
	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.httpSrv.Shutdown(sctx)
}
