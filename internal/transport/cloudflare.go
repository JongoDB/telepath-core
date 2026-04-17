package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sync"
	"time"
)

// cloudflareTunnelDriver wraps cloudflared's `access tcp` command. Up validates
// that a tunnel hostname is configured and that cloudflared is on PATH; the
// actual tunnel creation (via Cloudflare API) is out of scope for v0.1 and is
// assumed to be operator-provisioned. Dial execs `cloudflared access tcp
// --hostname <h>` and pipes through stdio.
//
// For v0.1 this is an honest minimum: the structure is correct, the config
// generation is testable, and production testing requires cloudflared on the
// operator's laptop.
type cloudflareTunnelDriver struct {
	mu     sync.Mutex
	state  State
	cfg    Config
	hint   string
	detail string
}

func newCloudflareTunnel() *cloudflareTunnelDriver {
	return &cloudflareTunnelDriver{state: StateDown}
}

func (c *cloudflareTunnelDriver) Kind() Kind { return KindCloudflareTunnel }

func (c *cloudflareTunnelDriver) Up(ctx context.Context, cfg Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cfg.CloudflareHostname == "" {
		return errors.New("transport/cloudflare: cloudflare_hostname required")
	}
	if _, err := exec.LookPath("cloudflared"); err != nil {
		return fmt.Errorf("transport/cloudflare: cloudflared binary not on PATH: %w", err)
	}
	c.cfg = cfg
	c.state = StateUp
	c.detail = fmt.Sprintf("routing via cloudflared hostname %s", cfg.CloudflareHostname)
	c.hint = fmt.Sprintf("client jumphost should run: cloudflared tunnel run --token <client-side token for %s>", cfg.CloudflareHostname)
	return nil
}

func (c *cloudflareTunnelDriver) Down(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = StateDown
	return nil
}

func (c *cloudflareTunnelDriver) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Status{Kind: KindCloudflareTunnel, State: c.state, Detail: c.detail, Hint: c.hint}
}

// Dial invokes `cloudflared access tcp --hostname <h>` as a subprocess and
// returns a net.Conn whose reads/writes are plumbed through the subprocess's
// stdio. On subprocess exit the connection errors cleanly.
func (c *cloudflareTunnelDriver) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	c.mu.Lock()
	if c.state != StateUp {
		c.mu.Unlock()
		return nil, ErrNotSupported
	}
	hostname := c.cfg.CloudflareHostname
	c.mu.Unlock()

	cmd := exec.CommandContext(ctx, "cloudflared", "access", "tcp", "--hostname", hostname, "--url", addr)
	return stdioConn(cmd, 5*time.Second)
}

// stdioConn starts cmd, returning a net.Conn implementation backed by
// cmd.Stdin/Stdout. Caller is responsible for eventual Close which terminates
// the subprocess. The startupDelay gives the child a moment to initialize
// before we treat connection errors as fatal; in practice tunnels can take
// a second or two to attach.
func stdioConn(cmd *exec.Cmd, startupDelay time.Duration) (net.Conn, error) {
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("transport: stdin pipe: %w", err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("transport: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("transport: start %s: %w", cmd.Path, err)
	}
	time.Sleep(startupDelay)
	return &processConn{
		cmd:    cmd,
		writer: in,
		reader: out,
	}, nil
}
