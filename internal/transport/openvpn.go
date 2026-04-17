package transport

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"
)

// openVPNDriver manages an openvpn client subprocess. Up validates the .ovpn
// config and launches openvpn; Down terminates it. Dial is net.Dial because
// OpenVPN sets up kernel routing once the tunnel is up.
//
// In production this requires the `openvpn` binary on PATH and usually root
// privileges for the TUN interface. That NFR-3 caveat is documented in the
// PRD; this package does not elevate itself.
type openVPNDriver struct {
	mu     sync.Mutex
	state  State
	cmd    *exec.Cmd
	detail string
}

func newOpenVPN() *openVPNDriver {
	return &openVPNDriver{state: StateDown}
}

func (o *openVPNDriver) Kind() Kind { return KindOpenVPN }

func (o *openVPNDriver) Up(ctx context.Context, cfg Config) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.state == StateUp {
		return nil
	}
	if cfg.OpenVPNConfigPath == "" {
		return errors.New("transport/openvpn: openvpn_config_path required")
	}
	if _, err := os.Stat(cfg.OpenVPNConfigPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("transport/openvpn: %s does not exist", cfg.OpenVPNConfigPath)
		}
		return fmt.Errorf("transport/openvpn: stat %s: %w", cfg.OpenVPNConfigPath, err)
	}
	if _, err := exec.LookPath("openvpn"); err != nil {
		return fmt.Errorf("transport/openvpn: openvpn binary not on PATH: %w", err)
	}

	cmd := exec.CommandContext(ctx, "openvpn", "--config", cfg.OpenVPNConfigPath)
	// Let openvpn write its status to whatever stdio it inherits; callers
	// are expected to attach a log handler. Not capturing here keeps the
	// subprocess output available for troubleshooting.
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("transport/openvpn: start: %w", err)
	}
	o.cmd = cmd
	o.state = StateStarting
	o.detail = fmt.Sprintf("openvpn starting (config=%s)", cfg.OpenVPNConfigPath)

	// Wait a short moment for the process to initialize. In production a
	// readiness probe (reading status log, pinging a known-reachable host)
	// is more robust; that's a v0.2 upgrade.
	timeout := 5 * time.Second
	if cfg.StartupTimeoutSeconds > 0 {
		timeout = time.Duration(cfg.StartupTimeoutSeconds) * time.Second
	}
	time.Sleep(timeout)
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		o.state = StateError
		o.detail = "openvpn exited during startup"
		return fmt.Errorf("transport/openvpn: process exited during startup")
	}
	o.state = StateUp
	o.detail = "openvpn up"
	return nil
}

func (o *openVPNDriver) Down(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.cmd == nil || o.cmd.Process == nil {
		o.state = StateDown
		return nil
	}
	_ = o.cmd.Process.Signal(os.Interrupt)
	// Give it a beat to close gracefully; otherwise kill.
	done := make(chan error, 1)
	go func() { done <- o.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = o.cmd.Process.Kill()
	}
	o.cmd = nil
	o.state = StateDown
	o.detail = ""
	return nil
}

func (o *openVPNDriver) Status() Status {
	o.mu.Lock()
	defer o.mu.Unlock()
	return Status{Kind: KindOpenVPN, State: o.state, Detail: o.detail}
}

func (o *openVPNDriver) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	o.mu.Lock()
	if o.state != StateUp {
		o.mu.Unlock()
		return nil, ErrNotSupported
	}
	o.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}
