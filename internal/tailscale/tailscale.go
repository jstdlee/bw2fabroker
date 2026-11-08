// Package tailscale checks that tailscaled is installed, logged in, and connected, through its local
// API socket, and returns this node's tailnet addresses.
package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"
)

// Status is what the broker needs from tailscaled.
type Status struct {
	BackendState string
	IPs          []netip.Addr
	DNSName      string
}

// IPv4 returns the node's tailnet IPv4 address.
func (s Status) IPv4() (netip.Addr, bool) {
	for _, ip := range s.IPs {
		if ip.Is4() {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

// Has reports whether ip belongs to this node.
func (s Status) Has(ip netip.Addr) bool {
	for _, a := range s.IPs {
		if a == ip.Unmap() {
			return true
		}
	}
	return false
}

// Checker returns tailscaled's status.
type Checker interface {
	Status(ctx context.Context) (Status, error)
}

// Errors returned by Preflight.
var (
	ErrNotRunning   = errors.New("Tailscale is not installed or not running (tailscaled local API not reachable)")
	ErrNotConnected = errors.New("Tailscale is not connected; run `tailscale up`")
	ErrNoAddress    = errors.New("Tailscale is connected but this node has no tailnet IPv4 address")
)

// LocalAPI talks to tailscaled over its unix socket.
type LocalAPI struct {
	Socket string
	client *http.Client
}

// NewLocalAPI returns a checker for the socket path.
func NewLocalAPI(socket string) *LocalAPI {
	return &LocalAPI{
		Socket: socket,
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				Proxy: nil,
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socket)
				},
			},
		},
	}
}

type statusJSON struct {
	BackendState string `json:"BackendState"`
	Self         *struct {
		DNSName      string   `json:"DNSName"`
		TailscaleIPs []string `json:"TailscaleIPs"`
	} `json:"Self"`
}

// Status calls /localapi/v0/status?peers=false.
func (l *LocalAPI) Status(ctx context.Context) (Status, error) {
	if _, err := os.Stat(l.Socket); err != nil {
		return Status{}, fmt.Errorf("%w: %s", ErrNotRunning, l.Socket)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://local-tailscaled.sock/localapi/v0/status?peers=false", nil)
	if err != nil {
		return Status{}, err
	}
	req.Host = "local-tailscaled.sock"
	resp, err := l.client.Do(req)
	if err != nil {
		return Status{}, fmt.Errorf("%w: %v", ErrNotRunning, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Status{}, fmt.Errorf("%w: local API answered %d", ErrNotRunning, resp.StatusCode)
	}
	var sj statusJSON
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&sj); err != nil {
		return Status{}, fmt.Errorf("tailscaled status: %w", err)
	}
	st := Status{BackendState: sj.BackendState}
	if sj.Self != nil {
		st.DNSName = strings.TrimSuffix(sj.Self.DNSName, ".")
		for _, s := range sj.Self.TailscaleIPs {
			if ip, err := netip.ParseAddr(s); err == nil {
				st.IPs = append(st.IPs, ip)
			}
		}
	}
	return st, nil
}

// Preflight checks that Tailscale is running and connected and returns the status.
func Preflight(ctx context.Context, c Checker) (Status, error) {
	st, err := c.Status(ctx)
	if err != nil {
		return Status{}, err
	}
	if st.BackendState != "Running" {
		return st, fmt.Errorf("%w (state %q)", ErrNotConnected, st.BackendState)
	}
	if _, ok := st.IPv4(); !ok {
		return st, ErrNoAddress
	}
	return st, nil
}
