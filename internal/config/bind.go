package config

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Exposure is where the approval page and admin panel listen.
type Exposure struct {
	Addr netip.AddrPort
	Mode string // "tailscale" or "lan"
}

// Classify reports whether ip may hold the broker listener.
// Tailscale CGNAT is "tailscale". RFC1918 and IPv6 ULA are "lan". Anything else is refused.
func Classify(ip netip.Addr) (mode string, ok bool) {
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() {
		return "", false
	}
	if IsTailnetIP(ip) {
		return "tailscale", true
	}
	if ip.IsPrivate() {
		return "lan", true
	}
	return "", false
}

// LookupHost resolves a hostname. Tests replace it.
var LookupHost = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// ValidHostname reports whether s is a DNS name with no scheme, port, or path.
func ValidHostname(s string) bool {
	if s == "" || len(s) > 253 || strings.ContainsAny(s, " /\\:@") {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// ResolveBind picks the approver address.
// An empty bind uses this node's tailnet IPv4. A hostname may resolve to that tailnet address,
// or to exactly one private LAN address. A public address is refused.
func ResolveBind(ctx context.Context, c *Config, node []netip.Addr) (Exposure, error) {
	if c.Approver.Port < 1 || c.Approver.Port > 65535 {
		return Exposure{}, errors.New("approver.port out of range")
	}
	port := uint16(c.Approver.Port)
	if c.Approver.BindHost != "" {
		ips, err := LookupHost(ctx, c.Approver.BindHost)
		if err != nil {
			return Exposure{}, fmt.Errorf("approver.bind_host %s: %w", c.Approver.BindHost, err)
		}
		return pickHost(c.Approver.BindHost, ips, node, port)
	}
	if c.Approver.BindIP != "" {
		ip, err := netip.ParseAddr(c.Approver.BindIP)
		if err != nil {
			return Exposure{}, fmt.Errorf("approver.bind_ip: %w", err)
		}
		mode, ok := Classify(ip)
		if !ok {
			return Exposure{}, fmt.Errorf("approver.bind_ip %s is not a tailnet or private LAN address", ip)
		}
		if mode == "tailscale" && !hasAddr(node, ip) {
			return Exposure{}, fmt.Errorf("approver.bind_ip %s is not a tailnet address of this node", ip)
		}
		return Exposure{Addr: netip.AddrPortFrom(ip, port), Mode: mode}, nil
	}
	for _, ip := range node {
		if ip.Is4() && IsTailnetIP(ip) {
			return Exposure{Addr: netip.AddrPortFrom(ip, port), Mode: "tailscale"}, nil
		}
	}
	return Exposure{}, errors.New("no tailnet IPv4 address; set approver.bind_host to a LAN hostname or connect Tailscale")
}

func pickHost(host string, ips, node []netip.Addr, port uint16) (Exposure, error) {
	var lan []netip.Addr
	for _, ip := range ips {
		mode, ok := Classify(ip)
		if !ok {
			return Exposure{}, fmt.Errorf("approver.bind_host %s resolves to %s, which is not a tailnet or private LAN address", host, ip)
		}
		if mode == "tailscale" {
			if !hasAddr(node, ip) {
				return Exposure{}, fmt.Errorf("approver.bind_host %s resolves to tailnet address %s, which is not this node", host, ip)
			}
			return Exposure{Addr: netip.AddrPortFrom(ip, port), Mode: "tailscale"}, nil
		}
		lan = append(lan, ip)
	}
	if len(lan) != 1 {
		return Exposure{}, fmt.Errorf("approver.bind_host %s must resolve to one LAN address", host)
	}
	return Exposure{Addr: netip.AddrPortFrom(lan[0], port), Mode: "lan"}, nil
}

func hasAddr(ips []netip.Addr, ip netip.Addr) bool {
	for _, o := range ips {
		if o == ip {
			return true
		}
	}
	return false
}
