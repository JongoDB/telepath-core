// Package winrmproxy is the WinRM protocol handler for telepath's Protocol
// Proxy layer. Wraps masterzen/winrm and routes every TCP dial through a
// transport.Transport so WinRM traffic honors the same tunnel routing as
// SSH and HTTP.
//
// v0.1 scope:
//   - PowerShell + cmd.exe one-shot execution
//   - HTTP (5985) and HTTPS (5986, optional -k) endpoints
//   - Basic auth (username + password) — NTLM/Kerberos follow in v0.2
//
// Test strategy: masterzen/winrm has no mock server; integration tests
// need a real Windows host. Unit tests here validate argument handling
// and prove the transport.Dial hook fires before any WinRM handshake.
package winrmproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/masterzen/winrm"

	"github.com/fsc/telepath-core/internal/proxy"
	"github.com/fsc/telepath-core/internal/transport"
)

// DefaultPort returns the canonical port for WinRM over HTTPS (5986) or
// plain HTTP (5985). Most enterprise deployments use HTTPS by default.
func DefaultPort(https bool) int {
	if https {
		return 5986
	}
	return 5985
}

// Handler runs WinRM commands over the given transport. Safe to reuse
// across requests; each call opens a fresh client.
type Handler struct {
	tr transport.Transport
	// newClient is overrideable in tests so we can assert behavior
	// without a live WinRM endpoint. Production use always goes through
	// winrm.NewClientWithParameters.
	newClient func(endpoint *winrm.Endpoint, user, pass string, params *winrm.Parameters) (winrmClient, error)
}

// winrmClient is the subset of *winrm.Client we use. Keeping it small
// limits the fake's surface and makes the tests readable.
type winrmClient interface {
	RunPSWithContext(ctx context.Context, command string) (stdout, stderr string, exitCode int, err error)
	RunWithContextWithString(ctx context.Context, command string, stdin string) (stdout, stderr string, exitCode int, err error)
}

// New constructs a Handler that dials through tr. A nil tr uses stdlib
// net.Dial — matches the httpproxy/sshproxy defaults.
func New(tr transport.Transport) *Handler {
	return &Handler{
		tr:        tr,
		newClient: realNewClient,
	}
}

// Config bundles WinRM endpoint parameters.
type Config struct {
	Host       string
	Port       int
	HTTPS      bool
	Insecure   bool // skip TLS verification
	Username   string
	Password   string
	TimeoutSec int // default 60
}

// PowerShell runs a PowerShell command and returns stdout/stderr/exit.
func (h *Handler) PowerShell(ctx context.Context, cfg Config, command string) (proxy.ExecResult, error) {
	return h.run(ctx, cfg, command, "", true)
}

// Cmd runs a cmd.exe command with optional stdin. Useful for tooling
// that already formats shell one-liners.
func (h *Handler) Cmd(ctx context.Context, cfg Config, command, stdin string) (proxy.ExecResult, error) {
	return h.run(ctx, cfg, command, stdin, false)
}

func (h *Handler) run(ctx context.Context, cfg Config, command, stdin string, ps bool) (proxy.ExecResult, error) {
	if cfg.Host == "" {
		return proxy.ExecResult{}, errors.New("winrmproxy: host required")
	}
	if cfg.Username == "" {
		return proxy.ExecResult{}, errors.New("winrmproxy: username required")
	}
	if cfg.Port <= 0 {
		cfg.Port = DefaultPort(cfg.HTTPS)
	}
	timeout := cfg.TimeoutSec
	if timeout <= 0 {
		timeout = 60
	}
	endpoint := &winrm.Endpoint{
		Host:     cfg.Host,
		Port:     cfg.Port,
		HTTPS:    cfg.HTTPS,
		Insecure: cfg.Insecure,
		Timeout:  time.Duration(timeout) * time.Second,
	}
	params := winrm.NewParameters(strconv.Itoa(timeout)+"s", "en-US", 153600)
	// Route every TCP dial through our transport when configured. This is
	// the single seam that makes WinRM honor cloudflare-tunnel / openvpn.
	if h.tr != nil {
		tr := h.tr
		params.Dial = func(network, addr string) (net.Conn, error) {
			dctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
			defer cancel()
			return tr.Dial(dctx, network, addr)
		}
	}
	client, err := h.newClient(endpoint, cfg.Username, cfg.Password, params)
	if err != nil {
		return proxy.ExecResult{}, fmt.Errorf("winrmproxy: client: %w", err)
	}

	start := time.Now()
	var stdout, stderr string
	var exit int
	if ps {
		stdout, stderr, exit, err = client.RunPSWithContext(ctx, command)
	} else {
		stdout, stderr, exit, err = client.RunWithContextWithString(ctx, command, stdin)
	}
	dur := time.Since(start)
	if err != nil {
		return proxy.ExecResult{
			Stdout:     []byte(stdout),
			Stderr:     []byte(stderr),
			ExitCode:   exit,
			DurationMs: dur.Milliseconds(),
		}, fmt.Errorf("winrmproxy: run: %w", err)
	}
	return proxy.ExecResult{
		Stdout:     []byte(stdout),
		Stderr:     []byte(stderr),
		ExitCode:   exit,
		DurationMs: dur.Milliseconds(),
	}, nil
}

// realNewClient is the production factory that wires masterzen/winrm's
// concrete client into our interface.
func realNewClient(endpoint *winrm.Endpoint, user, pass string, params *winrm.Parameters) (winrmClient, error) {
	c, err := winrm.NewClientWithParameters(endpoint, user, pass, params)
	if err != nil {
		return nil, err
	}
	return c, nil
}
