package config

import (
	"errors"
	"net/netip"
	"net/url"
	"strings"
)

// ValidVaultServer checks a Bitwarden or Vaultwarden base URL.
// An empty string means "leave bw's current server alone".
// HTTPS is always accepted. HTTP is accepted only for localhost, a loopback
// address, a private address, or a tailnet address, so a vault on the same
// machine or tailnet can be used without pretending a public HTTP server is safe.
func ValidVaultServer(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return errors.New("vault server must be an http(s) URL with a host")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("vault server URL must not contain a user, a query, or a fragment")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if httpVaultAllowed(u.Hostname()) {
			return nil
		}
		return errors.New("plain HTTP is only allowed for localhost, a loopback address, a private address, or a tailnet address")
	default:
		return errors.New("vault server must be https, or http on a local or tailnet host")
	}
}

func httpVaultAllowed(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || IsTailnetIP(ip)
}
