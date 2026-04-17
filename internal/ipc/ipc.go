// Package ipc implements the daemon's Unix-socket JSON-RPC transport. Each
// client connection carries exactly one request followed by exactly one
// response, both newline-terminated JSON objects. This matches the contract
// in the plugin's hooks/telepath_hook_lib.py so the Python hook library can
// talk to the daemon without any framing negotiation.
package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"sync"
	"time"

	"github.com/fsc/telepath-core/pkg/schema"
)

// DefaultSocketPath returns /tmp/telepath-<uid>.sock, matching the Python
// hook library's hard-coded default. On Windows, UID is not meaningful and
// callers should supply an explicit named-pipe path via configuration once
// v0.2 adds Windows support.
func DefaultSocketPath() string {
	return fmt.Sprintf("/tmp/telepath-%d.sock", os.Getuid())
}

// Handler processes one parsed JSON-RPC request. Returning a non-nil
// *schema.JSONRPCError sends that error to the client; returning a nil error
// with a result marshals the result as the Result field.
type Handler interface {
	Handle(ctx context.Context, req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError)
}

// HandlerFunc adapts a function to the Handler interface.
type HandlerFunc func(ctx context.Context, req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError)

// Handle satisfies Handler.
func (f HandlerFunc) Handle(ctx context.Context, req *schema.JSONRPCRequest) (json.RawMessage, *schema.JSONRPCError) {
	return f(ctx, req)
}

// Server is a listening Unix-socket JSON-RPC server.
type Server struct {
	path    string
	handler Handler
	ln      net.Listener

	wg       sync.WaitGroup
	stopOnce sync.Once
	done     chan struct{}

	connDeadline time.Duration
}

// ListenOptions tunes server behavior.
type ListenOptions struct {
	// ConnDeadline bounds the per-connection read+write window. Defaults
	// to 30 seconds if zero.
	ConnDeadline time.Duration
}

// Listen starts accepting connections on path. If a file already exists at
// path and is a stale socket (not owned by a live process), the caller
// should remove it before calling Listen — this function does not remove
// existing files to avoid clobbering an active daemon.
func Listen(path string, h Handler, opts ListenOptions) (*Server, error) {
	if opts.ConnDeadline == 0 {
		opts.ConnDeadline = 30 * time.Second
	}
	if err := os.MkdirAll(parentDir(path), 0o700); err != nil {
		return nil, fmt.Errorf("ipc: mkdir: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("ipc: listen %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("ipc: chmod %s: %w", path, err)
	}
	s := &Server{
		path:         path,
		handler:      h,
		ln:           ln,
		done:         make(chan struct{}),
		connDeadline: opts.ConnDeadline,
	}
	s.wg.Add(1)
	go s.serve()
	return s, nil
}

// Addr returns the listening socket path.
func (s *Server) Addr() string { return s.path }

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			// Accept errors after the listener is active and not shutting
			// down usually indicate a permanent fault (socket removed).
			// We bail rather than spin.
			return
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer c.Close()
			s.handleConn(c)
		}(conn)
	}
}

func (s *Server) handleConn(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(s.connDeadline))

	dec := json.NewDecoder(c)
	var req schema.JSONRPCRequest
	if err := dec.Decode(&req); err != nil {
		writeResponse(c, schema.JSONRPCResponse{
			JSONRPC: "2.0",
			Error: &schema.JSONRPCError{
				Code:    schema.ErrCodeParseError,
				Message: fmt.Sprintf("parse error: %v", err),
			},
		})
		return
	}
	if req.JSONRPC != "" && req.JSONRPC != "2.0" {
		writeResponse(c, schema.JSONRPCResponse{
			JSONRPC: "2.0", ID: req.ID,
			Error: &schema.JSONRPCError{
				Code:    schema.ErrCodeInvalidRequest,
				Message: fmt.Sprintf("unsupported jsonrpc version %q", req.JSONRPC),
			},
		})
		return
	}
	result, rpcErr := s.handler.Handle(context.Background(), &req)
	resp := schema.JSONRPCResponse{JSONRPC: "2.0", ID: req.ID}
	if rpcErr != nil {
		resp.Error = rpcErr
	} else {
		resp.Result = result
	}
	writeResponse(c, resp)
}

// Shutdown closes the listener, waits for in-flight handlers to drain (up to
// ctx deadline), and removes the socket file. Safe to call more than once.
func (s *Server) Shutdown(ctx context.Context) error {
	var closeErr error
	s.stopOnce.Do(func() {
		close(s.done)
		closeErr = s.ln.Close()
	})
	if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
		return fmt.Errorf("ipc: close listener: %w", closeErr)
	}
	waited := make(chan struct{})
	go func() { s.wg.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-ctx.Done():
		return fmt.Errorf("ipc: shutdown deadline: %w", ctx.Err())
	}
	if err := os.Remove(s.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("ipc: remove socket: %w", err)
	}
	return nil
}

func writeResponse(c net.Conn, r schema.JSONRPCResponse) {
	data, err := json.Marshal(r)
	if err != nil {
		// Last-ditch: write a minimal error message. Realistically, this
		// doesn't happen for any type we define.
		data = []byte(`{"jsonrpc":"2.0","error":{"code":-32603,"message":"internal marshal error"}}`)
	}
	data = append(data, '\n')
	_, _ = c.Write(data)
}

func parentDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			if i == 0 {
				return "/"
			}
			return path[:i]
		}
	}
	return "."
}
