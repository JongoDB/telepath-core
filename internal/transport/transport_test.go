package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestDirect_DialAgainstLoopback(t *testing.T) {
	t.Parallel()
	// Spin up a local TCP listener, then Dial it via the direct transport.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("hi"))
	}()

	tr, err := New(KindDirect)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := tr.Dial(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf) != "hi" {
		t.Errorf("got %q", buf)
	}
}

func TestDirect_Lifecycle(t *testing.T) {
	t.Parallel()
	tr, _ := New(KindDirect)
	if tr.Status().State != StateUp {
		t.Errorf("direct starts up; got %s", tr.Status().State)
	}
	if err := tr.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	if tr.Status().State != StateDown {
		t.Errorf("after Down state = %s", tr.Status().State)
	}
	if _, err := tr.Dial(context.Background(), "tcp", "127.0.0.1:1"); !errors.Is(err, ErrNotSupported) {
		t.Errorf("expected ErrNotSupported, got %v", err)
	}
	if err := tr.Up(context.Background(), Config{}); err != nil {
		t.Fatal(err)
	}
	if tr.Status().State != StateUp {
		t.Errorf("after Up state = %s", tr.Status().State)
	}
}

func TestUnknownKind(t *testing.T) {
	t.Parallel()
	_, err := New("bogus")
	if err == nil {
		t.Fatal("expected error for unknown kind")
	}
}

func TestCloudflareTunnel_RequiresHostname(t *testing.T) {
	t.Parallel()
	tr, _ := New(KindCloudflareTunnel)
	err := tr.Up(context.Background(), Config{})
	if err == nil {
		t.Fatalf("expected error without hostname")
	}
}

func TestCloudflareTunnel_StatusHintFormat(t *testing.T) {
	t.Parallel()
	tr, _ := New(KindCloudflareTunnel)
	// We can't actually bring it up without cloudflared on PATH in this
	// environment, but we can validate that Up rejects missing PATH cleanly.
	err := tr.Up(context.Background(), Config{CloudflareHostname: "acme.example"})
	if err == nil {
		t.Fatalf("expected error without cloudflared binary")
	}
}

func TestOpenVPN_MissingConfigPath(t *testing.T) {
	t.Parallel()
	tr, _ := New(KindOpenVPN)
	if err := tr.Up(context.Background(), Config{}); err == nil {
		t.Fatalf("expected error without config path")
	}
}

func TestOpenVPN_ConfigMustExist(t *testing.T) {
	t.Parallel()
	tr, _ := New(KindOpenVPN)
	bogus := filepath.Join(t.TempDir(), "nope.ovpn")
	if err := tr.Up(context.Background(), Config{OpenVPNConfigPath: bogus}); err == nil {
		t.Fatalf("expected error for missing config file")
	}
}
