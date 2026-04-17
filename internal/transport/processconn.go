package transport

import (
	"errors"
	"io"
	"net"
	"os/exec"
	"sync"
	"time"
)

// processConn adapts a subprocess's stdio to a net.Conn. Used by the
// cloudflared-based driver; could also back a netcat-style OpenVPN proxy in
// the future.
type processConn struct {
	cmd *exec.Cmd

	reader io.ReadCloser
	writer io.WriteCloser

	mu     sync.Mutex
	closed bool
}

// Read delegates to the subprocess's stdout.
func (p *processConn) Read(b []byte) (int, error) {
	n, err := p.reader.Read(b)
	if err == io.EOF {
		return n, io.EOF
	}
	return n, err
}

// Write delegates to the subprocess's stdin.
func (p *processConn) Write(b []byte) (int, error) {
	return p.writer.Write(b)
}

// Close terminates the subprocess and closes both pipes. Idempotent.
func (p *processConn) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	_ = p.reader.Close()
	_ = p.writer.Close()
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
	}
	return nil
}

// LocalAddr returns a synthetic address for diagnostics.
func (p *processConn) LocalAddr() net.Addr { return &namedAddr{"telepath-subprocess", "local"} }

// RemoteAddr returns a synthetic address for diagnostics.
func (p *processConn) RemoteAddr() net.Addr { return &namedAddr{"telepath-subprocess", "remote"} }

// SetDeadline is a no-op for subprocess-backed connections. A future
// enhancement can wrap the reader/writer in context-cancellable wrappers.
func (p *processConn) SetDeadline(t time.Time) error { return errDeadlineUnsupported }

// SetReadDeadline see SetDeadline.
func (p *processConn) SetReadDeadline(t time.Time) error { return errDeadlineUnsupported }

// SetWriteDeadline see SetDeadline.
func (p *processConn) SetWriteDeadline(t time.Time) error { return errDeadlineUnsupported }

var errDeadlineUnsupported = errors.New("transport: deadline not supported on subprocess-backed connection")

type namedAddr struct {
	network, name string
}

func (a *namedAddr) Network() string { return a.network }
func (a *namedAddr) String() string  { return a.name }
