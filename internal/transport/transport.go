// Package transport abstracts the network-reachability layer. Drivers bring
// the operator's laptop into a client network (direct, cloudflare-tunnel,
// openvpn, and later tailscale/ipsec). Protocol handlers (SSH, HTTP, etc.)
// dial through the active transport.
package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
)

// Kind identifies a transport driver.
type Kind string

const (
	KindDirect           Kind = "direct"
	KindCloudflareTunnel Kind = "cloudflare-tunnel"
	KindOpenVPN          Kind = "openvpn"
)

// State of a transport's connection.
type State string

const (
	StateDown    State = "down"
	StateStarting State = "starting"
	StateUp      State = "up"
	StateError   State = "error"
)

// Status reports the current connection state and any diagnostic detail.
type Status struct {
	Kind    Kind   `json:"kind"`
	State   State  `json:"state"`
	Detail  string `json:"detail,omitempty"`
	Hint    string `json:"hint,omitempty"` // operator-facing instruction (e.g., tunnel one-liner)
}

// Config carries driver-specific knobs. Fields that don't apply to a given
// driver are ignored.
type Config struct {
	// Cloudflare Tunnel fields
	CloudflareAPIToken   string `yaml:"cloudflare_api_token,omitempty" json:"cloudflare_api_token,omitempty"`
	CloudflareAccountID  string `yaml:"cloudflare_account_id,omitempty" json:"cloudflare_account_id,omitempty"`
	CloudflareHostname   string `yaml:"cloudflare_hostname,omitempty" json:"cloudflare_hostname,omitempty"`

	// OpenVPN fields
	OpenVPNConfigPath string `yaml:"openvpn_config_path,omitempty" json:"openvpn_config_path,omitempty"`

	// Timeouts and tweakables common to all drivers
	StartupTimeoutSeconds int `yaml:"startup_timeout_seconds,omitempty" json:"startup_timeout_seconds,omitempty"`
}

// Transport is the contract every driver implements.
type Transport interface {
	Kind() Kind
	Up(ctx context.Context, cfg Config) error
	Down(ctx context.Context) error
	Status() Status
	// Dial returns a net.Conn routed through the active transport. For
	// `direct` this is net.Dial; for tunnels it routes through the tunnel.
	Dial(ctx context.Context, network, addr string) (net.Conn, error)
}

// ErrNotSupported is returned by drivers for calls that don't apply in the
// current state (e.g., Dial on a down transport).
var ErrNotSupported = errors.New("transport: operation not supported in current state")

// New constructs a driver by Kind. Returns an error for unknown Kind; the
// caller is expected to validate against the ROE's allowed transports before
// instantiating.
func New(k Kind) (Transport, error) {
	switch k {
	case KindDirect:
		return newDirect(), nil
	case KindCloudflareTunnel:
		return newCloudflareTunnel(), nil
	case KindOpenVPN:
		return newOpenVPN(), nil
	default:
		return nil, fmt.Errorf("transport: unknown kind %q", k)
	}
}

// --- Direct driver ---

type directDriver struct {
	mu    sync.Mutex
	state State
}

func newDirect() *directDriver {
	return &directDriver{state: StateUp} // direct is always "up"; no setup needed
}

func (d *directDriver) Kind() Kind { return KindDirect }

func (d *directDriver) Up(ctx context.Context, cfg Config) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.state = StateUp
	return nil
}

func (d *directDriver) Down(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.state = StateDown
	return nil
}

func (d *directDriver) Status() Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	return Status{Kind: KindDirect, State: d.state, Detail: "uses the operator laptop's default routing"}
}

func (d *directDriver) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	if d.state != StateUp {
		d.mu.Unlock()
		return nil, ErrNotSupported
	}
	d.mu.Unlock()
	dialer := &net.Dialer{}
	return dialer.DialContext(ctx, network, addr)
}
