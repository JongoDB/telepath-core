package sshproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testSSHServer is an in-process SSH server for Handler tests. It accepts a
// known username+password, runs a fixed "echo" behavior for any command
// requested, and shuts down when Stop is called.
type testSSHServer struct {
	ln     net.Listener
	cfg    *ssh.ServerConfig
	done   chan struct{}
	addr   string
	tb     testing.TB
	signer ssh.Signer
}

func startTestServer(t *testing.T) *testSSHServer {
	t.Helper()
	_, privEd, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromSigner(privEd)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if string(pw) == "correct horse battery staple" {
				return nil, nil
			}
			return nil, fmt.Errorf("bad password")
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testSSHServer{
		ln:     ln,
		cfg:    cfg,
		done:   make(chan struct{}),
		addr:   ln.Addr().String(),
		tb:     t,
		signer: signer,
	}
	go s.serve()
	t.Cleanup(s.stop)
	return s
}

func (s *testSSHServer) stop() {
	select {
	case <-s.done:
		return
	default:
	}
	close(s.done)
	_ = s.ln.Close()
}

func (s *testSSHServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *testSSHServer) handleConn(c net.Conn) {
	defer c.Close()
	serverConn, chans, reqs, err := ssh.NewServerConn(c, s.cfg)
	if err != nil {
		return
	}
	defer serverConn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "unknown")
			continue
		}
		ch, rqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for req := range rqs {
				switch req.Type {
				case "exec":
					// payload: 4-byte length + command bytes
					cmd := ""
					if len(req.Payload) >= 4 {
						cmd = string(req.Payload[4:])
					}
					_ = req.Reply(true, nil)
					// Fake behavior: echo the command to stdout, write
					// "stderr-echo" to stderr. Exit code 0 for everything
					// except a command starting with "fail" which gets 7.
					_, _ = ch.Write([]byte("stdout:" + cmd))
					_, _ = ch.Stderr().Write([]byte("stderr-echo"))
					status := []byte{0, 0, 0, 0}
					if strings.HasPrefix(cmd, "fail") {
						status = []byte{0, 0, 0, 7}
					}
					_, _ = ch.SendRequest("exit-status", false, status)
					return
				default:
					_ = req.Reply(false, nil)
				}
			}
		}()
	}
}

// directDialer is a tiny Dialer that uses net.Dial directly. Avoids pulling
// in the full transport package to the test.
type directDialer struct{}

func (directDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

func TestSSH_ExecRoundTrip(t *testing.T) {
	t.Parallel()
	srv := startTestServer(t)
	h := NewWithDialer(directDialer{}, srv.signer.PublicKey())

	host, port := splitHostPort(t, srv.addr)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := h.Exec(ctx, host, port, Credentials{Username: "alex", Password: "correct horse battery staple"}, "uname -a")
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if string(res.Stdout) != "stdout:uname -a" {
		t.Errorf("stdout = %q", res.Stdout)
	}
	if string(res.Stderr) != "stderr-echo" {
		t.Errorf("stderr = %q", res.Stderr)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit = %d", res.ExitCode)
	}
}

func TestSSH_ExitCodePropagates(t *testing.T) {
	t.Parallel()
	srv := startTestServer(t)
	h := NewWithDialer(directDialer{}, srv.signer.PublicKey())
	host, port := splitHostPort(t, srv.addr)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := h.Exec(ctx, host, port, Credentials{Username: "alex", Password: "correct horse battery staple"}, "fail-on-purpose")
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if res.ExitCode != 7 {
		t.Errorf("exit = %d, want 7", res.ExitCode)
	}
}

func TestSSH_BadAuthFails(t *testing.T) {
	t.Parallel()
	srv := startTestServer(t)
	h := NewWithDialer(directDialer{}, srv.signer.PublicKey())
	host, port := splitHostPort(t, srv.addr)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := h.Exec(ctx, host, port, Credentials{Username: "alex", Password: "wrong"}, "uname")
	if err == nil {
		t.Fatalf("expected auth failure")
	}
}

func TestSSH_HostKeyMismatchFails(t *testing.T) {
	t.Parallel()
	srv := startTestServer(t)
	// Build a different host key — the mismatch should cause FixedHostKey to fail.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := ssh.NewSignerFromSigner(priv)
	h := NewWithDialer(directDialer{}, other.PublicKey())
	host, port := splitHostPort(t, srv.addr)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := h.Exec(ctx, host, port, Credentials{Username: "alex", Password: "correct horse battery staple"}, "uname")
	if err == nil {
		t.Fatalf("expected host-key mismatch to fail")
	}
}

func TestSSH_RequiresCredential(t *testing.T) {
	t.Parallel()
	h := NewWithDialer(directDialer{}, nil)
	_, err := h.Exec(context.Background(), "localhost", 22, Credentials{Username: "x"}, "uname")
	if err == nil {
		t.Fatalf("expected missing-auth error")
	}
}

func TestSSH_Stream(t *testing.T) {
	t.Parallel()
	srv := startTestServer(t)
	h := NewWithDialer(directDialer{}, srv.signer.PublicKey())
	host, port := splitHostPort(t, srv.addr)
	rc, err := h.Stream(context.Background(), host, port, Credentials{Username: "alex", Password: "correct horse battery staple"}, "tail-fake")
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	_ = rc.Close()
	if !strings.HasPrefix(string(data), "stdout:tail-fake") {
		t.Errorf("stream body = %q", data)
	}
}

func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	_, err = fmt.Sscanf(portStr, "%d", &port)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}
