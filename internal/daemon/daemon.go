// Package daemon is the long-lived process at the heart of telepath-core.
// It owns the engagement Manager, the audit log of the active engagement,
// and the JSON-RPC IPC surface that the Claude Code hooks and the telepath
// CLI both call into. All scope, approval, and audit decisions flow through
// this layer; lower packages are library code.
package daemon

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsc/telepath-core/internal/engagement"
	"github.com/fsc/telepath-core/internal/ipc"
	"github.com/fsc/telepath-core/internal/keys"
	"github.com/fsc/telepath-core/internal/oauth/saas"
	"github.com/fsc/telepath-core/internal/transport"
)

// Version is the telepath-core build version string reported by the ping
// method. Declared as var (not const) so release builds can override it
// via `-ldflags "-X github.com/fsc/telepath-core/internal/daemon.Version=..."`.
var Version = "0.1.0-dev"

// Config bundles daemon-wide settings. Zero-valued fields take documented
// defaults (see individual comments).
type Config struct {
	// RootDir is the per-operator telepath state root. Defaults to
	// ~/.telepath.
	RootDir string
	// SocketPath is the Unix-domain socket the daemon listens on. Defaults
	// to ipc.DefaultSocketPath (/tmp/telepath-<uid>.sock) to match the
	// Python hook library.
	SocketPath string
	// PIDFilePath is where the daemon records its PID for CLI status
	// checks. Defaults to <RootDir>/daemon.pid.
	PIDFilePath string
	// KeyStore overrides the keystore backend. When nil, keys.Open is
	// called (env-var-driven selection).
	KeyStore keys.Store
	// ConfigPath overrides ~/.telepath/config.yaml. Used by tests so
	// they don't reach into the developer's real HOME; production leaves
	// this empty and handlers fall back to config.DefaultPath().
	ConfigPath string
	// Logger overrides the logger. When nil, a text handler writing to
	// stderr is used.
	Logger *slog.Logger
}

// Daemon is a running telepath-core process.
type Daemon struct {
	cfg     Config
	logger  *slog.Logger
	keys    keys.Store
	signer  ed25519.PrivateKey
	manager *engagement.Manager
	server  *ipc.Server

	// transport is the currently-active network transport (nil when no
	// tunnel is up). Mutated through Transport()/SetTransport under a
	// dedicated mutex; protocol handlers read it via Transport() on each
	// call so operators can tear down/bring up transports without
	// restarting the daemon.
	transportMu sync.RWMutex
	transport   transport.Transport

	// oauthSessions holds in-flight SaaS OAuth PKCE sessions between the
	// oauth.begin call (returns auth URL) and oauth.complete (takes the
	// paste-back code). Keyed by session_id; entries live in memory only
	// and expire after oauthSessionTTL — reboot or missed paste means the
	// operator restarts the flow.
	oauthMu       sync.Mutex
	oauthSessions map[string]*oauthPendingSession

	started bool
}

// oauthSessionTTL is how long a pending PKCE session remains valid.
// Long enough for an operator to open a browser, sign in with MFA, and
// paste back; short enough that a forgotten session doesn't linger
// forever.
const oauthSessionTTL = 15 * time.Minute

// oauthPendingSession is one in-flight PKCE flow.
type oauthPendingSession struct {
	sess      *saas.Session
	provider  string
	tenant    string
	clientID  string
	createdAt time.Time
}

// New constructs a Daemon, resolving defaults and loading the operator's
// signing key from the keystore. The daemon is not yet listening; call
// Start.
func New(cfg Config) (*Daemon, error) {
	if cfg.RootDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("daemon: resolve $HOME: %w", err)
		}
		cfg.RootDir = filepath.Join(home, ".telepath")
	}
	if cfg.SocketPath == "" {
		cfg.SocketPath = ipc.DefaultSocketPath()
	}
	if cfg.PIDFilePath == "" {
		cfg.PIDFilePath = filepath.Join(cfg.RootDir, "daemon.pid")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	store := cfg.KeyStore
	if store == nil {
		opened, err := keys.Open()
		if err != nil {
			return nil, err
		}
		store = opened
	}
	signer, err := keys.GetOrCreateSigningKey(store)
	if err != nil {
		return nil, err
	}

	mgr := engagement.NewManager(filepath.Join(cfg.RootDir, "engagements"), store, signer)

	return &Daemon{
		cfg:           cfg,
		logger:        cfg.Logger,
		keys:          store,
		signer:        signer,
		manager:       mgr,
		oauthSessions: map[string]*oauthPendingSession{},
	}, nil
}

// Start writes the PID file, binds the IPC socket, and begins serving
// requests. Idempotent: calling Start twice is an error.
func (d *Daemon) Start() error {
	if d.started {
		return errors.New("daemon: already started")
	}
	if err := os.MkdirAll(d.cfg.RootDir, 0o700); err != nil {
		return fmt.Errorf("daemon: mkdir %s: %w", d.cfg.RootDir, err)
	}

	if existing, err := readPIDFile(d.cfg.PIDFilePath); err == nil && pidAlive(existing) {
		return fmt.Errorf("daemon: already running (pid %d)", existing)
	}
	if err := writePIDFile(d.cfg.PIDFilePath, os.Getpid()); err != nil {
		return fmt.Errorf("daemon: write pid: %w", err)
	}

	if err := removeStaleSocket(d.cfg.SocketPath); err != nil {
		_ = os.Remove(d.cfg.PIDFilePath)
		return err
	}

	srv, err := ipc.Listen(d.cfg.SocketPath, ipc.HandlerFunc(d.dispatch), ipc.ListenOptions{
		ConnDeadline: 30 * time.Second,
	})
	if err != nil {
		_ = os.Remove(d.cfg.PIDFilePath)
		return err
	}
	d.server = srv
	d.started = true
	d.logger.Info("daemon started", "socket", d.cfg.SocketPath, "pid", os.Getpid(), "keystore", d.keys.Backend())
	return nil
}

// Transport returns the currently-active network transport, or nil. Used by
// protocol-handler call sites (SSH exec, HTTP request) inside RPC handlers.
func (d *Daemon) Transport() transport.Transport {
	d.transportMu.RLock()
	defer d.transportMu.RUnlock()
	return d.transport
}

// SetTransport swaps the daemon's active transport. Callers that need to
// close an old transport before bringing a new one up should do so before
// calling this; SetTransport does not Down the replaced driver.
func (d *Daemon) SetTransport(t transport.Transport) {
	d.transportMu.Lock()
	d.transport = t
	d.transportMu.Unlock()
}

// Shutdown drains in-flight RPCs (up to ctx deadline), unloads any active
// engagement (closes its audit log), removes the socket file and PID file,
// and marks the daemon stopped. Safe to call more than once.
func (d *Daemon) Shutdown(ctx context.Context) error {
	if !d.started {
		return nil
	}
	d.started = false

	var firstErr error
	if d.server != nil {
		if err := d.server.Shutdown(ctx); err != nil {
			firstErr = err
		}
	}
	if err := d.manager.Unload(); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("daemon: unload: %w", err)
	}
	if err := os.Remove(d.cfg.PIDFilePath); err != nil && !errors.Is(err, fs.ErrNotExist) && firstErr == nil {
		firstErr = fmt.Errorf("daemon: remove pid: %w", err)
	}
	d.logger.Info("daemon stopped")
	return firstErr
}

// Manager exposes the engagement manager so in-process callers (daemon
// command in cmd/telepath) can perform lifecycle actions directly instead
// of going through the socket.
func (d *Daemon) Manager() *engagement.Manager { return d.manager }

// SocketPath returns the path of the daemon's IPC socket.
func (d *Daemon) SocketPath() string { return d.cfg.SocketPath }

// PublicKey returns the operator's signing public key for external verifiers.
func (d *Daemon) PublicKey() ed25519.PublicKey { return keys.PublicKey(d.signer) }

// KeystoreBackend reports the active key storage backend ("os" or "file").
// Used by the doctor subcommand.
func (d *Daemon) KeystoreBackend() string { return d.keys.Backend() }

// removeStaleSocket tolerates an existing socket file if it is not currently
// bound to a live server. A stale file is a common outcome of un-graceful
// shutdown; removing it is safe. A live file is not — that means a daemon
// is already running.
func removeStaleSocket(path string) error {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err == nil {
		conn.Close()
		return fmt.Errorf("daemon: socket %s is already in use", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("daemon: remove stale socket %s: %w", path, err)
	}
	return nil
}
