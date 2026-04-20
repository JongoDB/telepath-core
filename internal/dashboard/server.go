package dashboard

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// DefaultBindAddr is "0.0.0.0:0" — all interfaces, ephemeral port.
// The headless-operator flow (`telepath daemon run` on a cloud box,
// browser on the laptop) is the primary deployment, and locking the
// dashboard to loopback would force SSH tunneling for every session.
// Network exposure is gated by the auto-generated bearer token — the
// URL that gets printed carries the credential, and requests without
// it get a 401 regardless of which interface they came in on.
const DefaultBindAddr = "0.0.0.0:0"

// Server is the HTTP server that renders the dashboard. Listens on
// whatever interface Config.BindAddr resolves to; the bearer token in
// Server.Token is the only thing between the port and an unauth'd
// caller.
type Server struct {
	// Addr is the bind address after Start returns. Zero-port requests
	// resolve here so callers can print the real URL for the operator.
	Addr string
	// Token is the auto-generated bearer credential every HTTP request
	// (except /healthz) must present. Prints in the listen URL as the
	// `?t=` query param.
	Token   string
	httpSrv *http.Server
	listen  net.Listener
}

// Config bundles dashboard server options. Zero values take sane
// defaults.
type Config struct {
	// BindAddr is the TCP address to listen on. Defaults to
	// DefaultBindAddr ("0.0.0.0:0"). Supply "127.0.0.1:0" (or any
	// specific address) to narrow it.
	BindAddr string
	// Fetcher is the backend RPC client. Required.
	Fetcher Fetcher
	// CLIVersion is the version of the telepath binary running the
	// dashboard. Used to detect + warn about stale daemons (daemon
	// built from an older binary that hasn't been restarted after an
	// update). Zero-value disables the check.
	CLIVersion string
	// DisableAuth bypasses the bearer-token requirement. Test-only —
	// do NOT set this in production code paths. The field exists so
	// handler/state tests that use httptest.NewRequest don't have to
	// thread a token through every call.
	DisableAuth bool
}

// Start binds the listener, begins serving, and returns the running
// Server. The server runs until Shutdown is called.
func Start(cfg Config) (*Server, error) {
	if cfg.Fetcher == nil {
		return nil, errors.New("dashboard: Fetcher required")
	}
	addr := cfg.BindAddr
	if addr == "" {
		addr = DefaultBindAddr
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dashboard: listen %s: %w", addr, err)
	}
	var token string
	if !cfg.DisableAuth {
		token, err = randomToken()
		if err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("dashboard: token: %w", err)
		}
	}
	h := &Handler{Fetcher: cfg.Fetcher, Token: token, CLIVersion: cfg.CLIVersion}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	return &Server{
		Addr:    ln.Addr().String(),
		Token:   token,
		httpSrv: srv,
		listen:  ln,
	}, nil
}

// URL returns a ready-to-paste http:// URL including the tokenized
// query param. When the dashboard has no token (DisableAuth), the URL
// is returned without the ?t= suffix.
func (s *Server) URL() string {
	base := "http://" + s.Addr
	if s.Token == "" {
		return base
	}
	return base + "/?t=" + s.Token
}

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

// randomToken returns 32 bytes of crypto/rand base64-URL-encoded — ~43
// chars, 256 bits of entropy. Plenty for a session credential that
// dies when the process exits.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
