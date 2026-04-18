package sftpproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/fsc/telepath-core/internal/proxy/sshproxy"
)

// testSFTPServer is an in-process SSH server with a working SFTP subsystem
// rooted at the given directory. Used to exercise the full sftp.NewClient
// path without shelling out to a system sshd.
type testSFTPServer struct {
	signer ssh.Signer
	addr   string
	root   string
	ln     net.Listener
}

func startTestServer(t *testing.T, root string) *testSFTPServer {
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
			if string(pw) == "hunter2" {
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
	srv := &testSFTPServer{signer: signer, addr: ln.Addr().String(), root: root, ln: ln}
	go srv.serve(cfg)
	t.Cleanup(func() { _ = ln.Close() })
	return srv
}

func (s *testSFTPServer) serve(cfg *ssh.ServerConfig) {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn, cfg)
	}
}

func (s *testSFTPServer) handleConn(c net.Conn, cfg *ssh.ServerConfig) {
	defer c.Close()
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
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
		go func(ch ssh.Channel, rqs <-chan *ssh.Request) {
			defer ch.Close()
			for req := range rqs {
				if req.Type == "subsystem" && len(req.Payload) >= 4 && string(req.Payload[4:]) == "sftp" {
					_ = req.Reply(true, nil)
					// Root the SFTP server at our test directory by chdir — pkg/sftp
					// itself honors absolute paths; we rely on the test passing paths
					// inside the chrooted tmpdir.
					cwd, _ := os.Getwd()
					_ = os.Chdir(s.root)
					srv, _ := sftp.NewServer(ch)
					_ = srv.Serve()
					_ = os.Chdir(cwd)
					return
				}
				_ = req.Reply(false, nil)
			}
		}(ch, rqs)
	}
}

// directDialer is the minimal Dialer used to bypass the transport in tests;
// sftpproxy.New wires through sshproxy.New which accepts a transport.Transport,
// so for tests we reuse sshproxy.NewWithDialer to keep the handler wired to
// a direct net.Dial.
type directDialer struct{}

func (directDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, addr)
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

func TestSFTP_GetRoundTrip(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	payload := []byte("interview transcript\nline two\n")
	if err := os.WriteFile(filepath.Join(root, "notes.txt"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	srv := startTestServer(t, root)

	// Use sshproxy.NewWithDialer so we bypass the transport wiring (covered
	// by the sshproxy integration test) and focus on the SFTP semantics.
	ssh := sshproxy.NewWithDialer(directDialer{}, srv.signer.PublicKey())
	h := NewFromSSH(ssh)
	host, port := splitHostPort(t, srv.addr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := h.Get(ctx, host, port, sshproxy.Credentials{
		Username: "alex",
		Password: "hunter2",
	}, "notes.txt")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("content mismatch: got %q", got)
	}
}

func TestSFTP_ListReturnsEntries(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for _, name := range []string{"one.txt", "two.txt", "three.md"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	srv := startTestServer(t, root)
	ssh := sshproxy.NewWithDialer(directDialer{}, srv.signer.PublicKey())
	h := NewFromSSH(ssh)
	host, port := splitHostPort(t, srv.addr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entries, err := h.List(ctx, host, port, sshproxy.Credentials{Username: "alex", Password: "hunter2"}, ".")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d: %+v", len(entries), entries)
	}
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name] = true
		if e.IsDir {
			t.Errorf("unexpected dir entry: %s", e.Name)
		}
	}
	for _, want := range []string{"one.txt", "two.txt", "three.md"} {
		if !names[want] {
			t.Errorf("missing %s in entries", want)
		}
	}
}

func TestSFTP_FileSizeCapRejects(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	// Write a file 1 byte over the cap — MaxFileBytes+1 is enough to trigger
	// the cap check in Get.
	big := make([]byte, MaxFileBytes+1)
	for i := range big {
		big[i] = 'z'
	}
	if err := os.WriteFile(filepath.Join(root, "big.bin"), big, 0o600); err != nil {
		t.Fatal(err)
	}
	srv := startTestServer(t, root)
	ssh := sshproxy.NewWithDialer(directDialer{}, srv.signer.PublicKey())
	h := NewFromSSH(ssh)
	host, port := splitHostPort(t, srv.addr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := h.Get(ctx, host, port, sshproxy.Credentials{Username: "alex", Password: "hunter2"}, "big.bin")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("expected size-cap error, got %v", err)
	}
}
