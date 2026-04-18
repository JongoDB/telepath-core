// Package sftpproxy is the SFTP file-collection handler. Rides on top of
// the SSH protocol adapter — every SFTP session is an SSH connection + an
// sftp subsystem request — so transport routing and credential handling
// come for free from sshproxy.
//
// v0.1 scope: one-shot Get + List against a single remote path. Bulk
// downloads, recursive transfers, and resume are v0.2 territory.
package sftpproxy

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/fsc/telepath-core/internal/proxy/sshproxy"
	"github.com/fsc/telepath-core/internal/transport"
)

// MaxFileBytes caps the content pulled in a single Get call. Files larger
// than this are rejected with an explicit error rather than silently
// truncated — callers who want partial pulls explicitly pass a byte range
// in a future version.
const MaxFileBytes = 32 << 20 // 32 MiB

// FileInfo is the subset of os.FileInfo we expose on the wire.
type FileInfo struct {
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	Mode  string `json:"mode"`
	IsDir bool   `json:"is_dir"`
}

// Handler wraps an SSH handler + adds SFTP semantics on top.
type Handler struct {
	ssh *sshproxy.Handler
}

// New constructs a Handler that dials through tr and pins hostKey. A nil
// hostKey defers to sshproxy's InsecureIgnoreHostKey default — same
// security posture as Exec, documented there.
func New(tr transport.Transport, hostKey ssh.PublicKey) *Handler {
	return &Handler{ssh: sshproxy.New(tr, hostKey)}
}

// NewFromSSH lets tests (or operators) reuse an existing sshproxy.Handler
// instead of constructing a second one — relevant when both exec + file
// fetch operations share credentials for a single engagement session.
func NewFromSSH(h *sshproxy.Handler) *Handler { return &Handler{ssh: h} }

// Get fetches a single remote file into memory. Returns an error if the
// file exceeds MaxFileBytes.
func (h *Handler) Get(ctx context.Context, host string, port int, creds sshproxy.Credentials, remotePath string) ([]byte, error) {
	if remotePath == "" {
		return nil, errors.New("sftpproxy: remote path required")
	}
	client, err := h.ssh.OpenClient(ctx, host, port, creds)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	sc, err := sftp.NewClient(client)
	if err != nil {
		return nil, fmt.Errorf("sftpproxy: subsystem: %w", err)
	}
	defer sc.Close()

	f, err := sc.Open(remotePath)
	if err != nil {
		return nil, fmt.Errorf("sftpproxy: open %s: %w", remotePath, err)
	}
	defer f.Close()

	// Use LimitReader so we can detect overflow cleanly: read MaxFileBytes+1
	// and error if the result exceeds the cap.
	lr := io.LimitReader(f, MaxFileBytes+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("sftpproxy: read %s: %w", remotePath, err)
	}
	if int64(len(data)) > MaxFileBytes {
		return nil, fmt.Errorf("sftpproxy: %s exceeds %d byte cap", remotePath, MaxFileBytes)
	}
	return data, nil
}

// List returns the directory entries at remotePath. Non-recursive; one
// SFTP call, no fan-out.
func (h *Handler) List(ctx context.Context, host string, port int, creds sshproxy.Credentials, remotePath string) ([]FileInfo, error) {
	if remotePath == "" {
		return nil, errors.New("sftpproxy: remote path required")
	}
	client, err := h.ssh.OpenClient(ctx, host, port, creds)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	sc, err := sftp.NewClient(client)
	if err != nil {
		return nil, fmt.Errorf("sftpproxy: subsystem: %w", err)
	}
	defer sc.Close()

	entries, err := sc.ReadDir(remotePath)
	if err != nil {
		return nil, fmt.Errorf("sftpproxy: readdir %s: %w", remotePath, err)
	}
	out := make([]FileInfo, 0, len(entries))
	for _, e := range entries {
		out = append(out, FileInfo{
			Name:  e.Name(),
			Size:  e.Size(),
			Mode:  e.Mode().String(),
			IsDir: e.IsDir(),
		})
	}
	return out, nil
}
