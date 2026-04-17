// Package sshproxy implements the SSH protocol handler for telepath's
// Protocol Proxy layer. Backed by golang.org/x/crypto/ssh; dials through a
// transport.Transport so the same code works over direct, openvpn, or any
// future driver that exposes a net.Conn via DialContext.
package sshproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/fsc/telepath-core/internal/proxy"
	"github.com/fsc/telepath-core/internal/transport"
)

// Credentials for SSH auth. Exactly one of Password, KeyData, or Agent must
// be set. If more than one is provided, KeyData wins, then Password, then
// Agent — matching typical operator expectations.
type Credentials struct {
	Username string
	Password string
	KeyData  []byte // PEM-encoded private key
	Passphrase string // optional passphrase for KeyData
}

// Handler opens SSH sessions over the given transport. Safe to share
// across goroutines; each Exec call opens a fresh TCP + SSH connection.
type Handler struct {
	tr      transport.Transport
	dialer  Dialer
	// hostKey is optional. When set, sessions require the server's host key
	// to match. When nil, InsecureIgnoreHostKey is used (documented caveat
	// below). Production engagements should pin host keys via ROE.
	hostKey ssh.PublicKey
}

// Dialer is the net-level hook Exec uses. Pluggable for tests so we can
// inject a direct net.Conn pair without a real socket listener.
type Dialer interface {
	Dial(ctx context.Context, network, addr string) (net.Conn, error)
}

// New returns a Handler that dials through tr. A nil hostKey means "trust
// any host key" — acceptable for v0.1 internal/test usage; production ROE
// should pin the key (TODO v0.2: ROE host_keys section).
func New(tr transport.Transport, hostKey ssh.PublicKey) *Handler {
	return &Handler{tr: tr, dialer: transportDialer{tr}, hostKey: hostKey}
}

// NewWithDialer is the test constructor: injects a Dialer so we can wire
// the handler to an in-process ssh.Server without going through a transport.
func NewWithDialer(d Dialer, hostKey ssh.PublicKey) *Handler {
	return &Handler{dialer: d, hostKey: hostKey}
}

// Exec runs a command on host:port as user with the given credentials and
// returns the completed result. Default port is 22 when port<=0.
func (h *Handler) Exec(ctx context.Context, host string, port int, creds Credentials, command string) (proxy.ExecResult, error) {
	if host == "" {
		return proxy.ExecResult{}, errors.New("sshproxy: host required")
	}
	if port <= 0 {
		port = 22
	}
	if creds.Username == "" {
		return proxy.ExecResult{}, errors.New("sshproxy: username required")
	}
	authMethods, err := buildAuth(creds)
	if err != nil {
		return proxy.ExecResult{}, err
	}
	var hostKeyCallback ssh.HostKeyCallback
	if h.hostKey != nil {
		hostKeyCallback = ssh.FixedHostKey(h.hostKey)
	} else {
		// #nosec G106 — v0.1 allows any host key. ROE host-key pinning in v0.2.
		hostKeyCallback = ssh.InsecureIgnoreHostKey()
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := h.dialer.Dial(ctx, "tcp", addr)
	if err != nil {
		return proxy.ExecResult{}, fmt.Errorf("sshproxy: dial %s: %w", addr, err)
	}
	clientCfg := &ssh.ClientConfig{
		User:            creds.Username,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         15 * time.Second,
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, clientCfg)
	if err != nil {
		_ = conn.Close()
		return proxy.ExecResult{}, fmt.Errorf("sshproxy: handshake %s: %w", addr, err)
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return proxy.ExecResult{}, fmt.Errorf("sshproxy: new session: %w", err)
	}
	defer sess.Close()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	start := time.Now()
	execErr := sess.Run(command)
	dur := time.Since(start)

	res := proxy.ExecResult{
		Stdout:     stdout.Bytes(),
		Stderr:     stderr.Bytes(),
		DurationMs: dur.Milliseconds(),
	}
	if execErr != nil {
		var ee *ssh.ExitError
		if errors.As(execErr, &ee) {
			res.ExitCode = ee.ExitStatus()
			return res, nil
		}
		return res, fmt.Errorf("sshproxy: exec: %w", execErr)
	}
	return res, nil
}

// Stream opens a session and returns a ReadCloser over the command's stdout.
// Intended for long-running commands like `tail -f`; caller closes when done.
func (h *Handler) Stream(ctx context.Context, host string, port int, creds Credentials, command string) (io.ReadCloser, error) {
	if port <= 0 {
		port = 22
	}
	authMethods, err := buildAuth(creds)
	if err != nil {
		return nil, err
	}
	hkcb := ssh.InsecureIgnoreHostKey()
	if h.hostKey != nil {
		hkcb = ssh.FixedHostKey(h.hostKey)
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := h.dialer.Dial(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("sshproxy: dial %s: %w", addr, err)
	}
	clientCfg := &ssh.ClientConfig{
		User:            creds.Username,
		Auth:            authMethods,
		HostKeyCallback: hkcb,
		Timeout:         15 * time.Second,
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, clientCfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("sshproxy: handshake: %w", err)
	}
	client := ssh.NewClient(c, chans, reqs)
	sess, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("sshproxy: new session: %w", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		_ = sess.Close()
		_ = client.Close()
		return nil, fmt.Errorf("sshproxy: stdout pipe: %w", err)
	}
	if err := sess.Start(command); err != nil {
		_ = sess.Close()
		_ = client.Close()
		return nil, fmt.Errorf("sshproxy: start: %w", err)
	}
	return &streamCloser{r: stdout, sess: sess, client: client}, nil
}

func buildAuth(creds Credentials) ([]ssh.AuthMethod, error) {
	var out []ssh.AuthMethod
	if len(creds.KeyData) > 0 {
		var signer ssh.Signer
		var err error
		if creds.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(creds.KeyData, []byte(creds.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(creds.KeyData)
		}
		if err != nil {
			return nil, fmt.Errorf("sshproxy: parse key: %w", err)
		}
		out = append(out, ssh.PublicKeys(signer))
	}
	if creds.Password != "" {
		out = append(out, ssh.Password(creds.Password))
	}
	if len(out) == 0 {
		return nil, errors.New("sshproxy: no auth method (set Password or KeyData)")
	}
	return out, nil
}

// transportDialer adapts a Transport to the Dialer interface. When the
// transport is directDriver, Dial degrades to stdlib net.Dial.
type transportDialer struct{ tr transport.Transport }

func (d transportDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.tr == nil {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	return d.tr.Dial(ctx, network, addr)
}

// streamCloser wraps an SSH stdout pipe so Close tears down the session and
// client. Without this, callers would leak both.
type streamCloser struct {
	r      io.Reader
	sess   *ssh.Session
	client *ssh.Client
}

func (s *streamCloser) Read(b []byte) (int, error) { return s.r.Read(b) }
func (s *streamCloser) Close() error {
	_ = s.sess.Close()
	return s.client.Close()
}
