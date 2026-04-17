package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsc/telepath-core/pkg/schema"
)

func startServer(t *testing.T, h Handler) (*Server, string) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "daemon.sock")
	srv, err := Listen(sock, h, ListenOptions{ConnDeadline: 2 * time.Second})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return srv, sock
}

func ctxWith(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func TestIPC_RoundTrip_Result(t *testing.T) {
	t.Parallel()
	h := HandlerFunc(func(ctx context.Context, req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
		if req.Method != "ping" {
			return nil, &schema.JSONRPCError{Code: schema.ErrCodeMethodNotFound, Message: "unknown"}
		}
		return json.RawMessage(`{"ok":true,"version":"test"}`), nil
	})
	_, sock := startServer(t, h)

	res, err := Call(sock, "ping", nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	var out schema.PingResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.OK || out.Version != "test" {
		t.Errorf("got %+v", out)
	}
}

func TestIPC_RoundTrip_Error(t *testing.T) {
	t.Parallel()
	h := HandlerFunc(func(ctx context.Context, req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
		return nil, &schema.JSONRPCError{Code: schema.ErrCodeNoActiveEngagement, Message: "none"}
	})
	_, sock := startServer(t, h)

	_, err := Call(sock, "x", nil)
	var re *RemoteError
	if !errors.As(err, &re) {
		t.Fatalf("expected RemoteError, got %T (%v)", err, err)
	}
	if re.Code != schema.ErrCodeNoActiveEngagement {
		t.Errorf("code = %d, want %d", re.Code, schema.ErrCodeNoActiveEngagement)
	}
}

func TestIPC_BadJSONRPCVersionRejected(t *testing.T) {
	t.Parallel()
	h := HandlerFunc(func(ctx context.Context, req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
		t.Fatalf("handler should not run for bad version")
		return nil, nil
	})
	_, sock := startServer(t, h)

	// Send a request with jsonrpc != "2.0" via raw conn.
	conn, err := dialUnix(sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte(`{"jsonrpc":"1.0","method":"ping","id":1}` + "\n"))

	var resp schema.JSONRPCResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != schema.ErrCodeInvalidRequest {
		t.Errorf("expected InvalidRequest, got %+v", resp)
	}
}

func TestIPC_ParseErrorOnBadJSON(t *testing.T) {
	t.Parallel()
	h := HandlerFunc(func(ctx context.Context, req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
		t.Fatalf("handler should not run on parse error")
		return nil, nil
	})
	_, sock := startServer(t, h)

	conn, err := dialUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("not json at all\n"))
	var resp schema.JSONRPCResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != schema.ErrCodeParseError {
		t.Errorf("expected ParseError, got %+v", resp)
	}
}

func TestIPC_ShutdownDrains(t *testing.T) {
	t.Parallel()
	h := HandlerFunc(func(ctx context.Context, req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
		time.Sleep(50 * time.Millisecond)
		return json.RawMessage(`{"ok":true}`), nil
	})
	srv, sock := startServer(t, h)

	// Kick off an in-flight call.
	done := make(chan error, 1)
	go func() {
		_, err := Call(sock, "slow", nil)
		done <- err
	}()
	time.Sleep(10 * time.Millisecond)
	if err := srv.Shutdown(ctxWith(t, 2*time.Second)); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("in-flight call failed during shutdown: %v", err)
	}
	// Socket file should be gone.
	if _, err := dialUnix(sock); err == nil {
		t.Errorf("socket still accepting after shutdown")
	}
}
