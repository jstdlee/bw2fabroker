// Package config loads and saves the broker's TOML config. The file must be mode 0600.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// DefaultPath is used when BROKER_CONFIG is not set.
const DefaultPath = "/etc/bw2fabroker/config.toml"

// Path returns the config path from BROKER_CONFIG or the default.
func Path() string {
	if p := os.Getenv("BROKER_CONFIG"); p != "" {
		return p
	}
	return DefaultPath
}

// Config is the whole file.
type Config struct {
	HMACKey          string `toml:"hmac_key"`
	ApprovalPassword string `toml:"approval_password"` // argon2id hash

	Approver  Approver         `toml:"approver"`
	Agent     AgentAPI         `toml:"agent"`
	Ntfy      Ntfy             `toml:"ntfy"`
	Tailscale Tailscale        `toml:"tailscale"`
	Vault     Vault            `toml:"vault"`
	Admin     Admin            `toml:"admin"`
	Agents    map[string]Agent `toml:"agents"`
	Auto      []AutoRule       `toml:"auto"`
}

// Approver is the tailnet listener for the approval page.
type Approver struct {
	Port       int    `toml:"port"`        // default 8787
	BindIP     string `toml:"bind_ip"`     // optional override; must be this node's tailnet IP
	PublicHost string `toml:"public_host"` // optional host for links (e.g. MagicDNS name)
}

// AgentAPI is where agents connect: "unix:/path", "127.0.0.1:8786", or "100.x.y.z:8786".
type AgentAPI struct {
	Listen    string `toml:"listen"`
	SocketGID int    `toml:"socket_gid"` // unix socket: group allowed to connect (mode 0660); 0 = group broker-clients if present
}

// Ntfy is the push target. URL must be https on OwnDomain.
type Ntfy struct {
	OwnDomain string `toml:"own_domain"`
	URL       string `toml:"url"`
	Topic     string `toml:"topic"`
	Token     string `toml:"token"`
}

// Tailscale settings.
type Tailscale struct {
	Socket string `toml:"socket"` // default /var/run/tailscale/tailscaled.sock or $TS_SOCKET
}

// Vault settings.
type Vault struct {
	BWPath  string `toml:"bw_path"`  // default "bw"
	AppData string `toml:"app_data"` // BITWARDENCLI_APPDATA_DIR, optional
}

// Admin socket for unlock and resume commands.
type Admin struct {
	Socket string `toml:"socket"` // default /run/bw2fabroker/admin.sock
}

// Agent is one registered agent; only the token hash is stored.
type Agent struct {
	TokenSHA256 string    `toml:"token_sha256"`
	Created     time.Time `toml:"created"`
}

// AutoRule marks an item (optionally one field) as approved without asking. Never totp.
type AutoRule struct {
	ItemID string `toml:"item_id"`
	Field  string `toml:"field"` // empty = any field except totp
}

// Defaults fills empty settings.
func (c *Config) Defaults() {
	if c.Approver.Port == 0 {
		c.Approver.Port = 8787
	}
	if c.Agent.Listen == "" {
		c.Agent.Listen = envOr("BROKER_AGENT_LISTEN", "unix:/run/bw2fabroker/agent.sock")
	}
	if c.Tailscale.Socket == "" {
		if s := os.Getenv("TS_SOCKET"); s != "" {
			c.Tailscale.Socket = s
		} else {
			c.Tailscale.Socket = "/var/run/tailscale/tailscaled.sock"
		}
	}
	if c.Vault.BWPath == "" {
		c.Vault.BWPath = "bw"
	}
	if c.Admin.Socket == "" {
		c.Admin.Socket = envOr("BROKER_ADMIN_SOCKET", "/run/bw2fabroker/admin.sock")
	}
	if c.Vault.AppData == "" {
		c.Vault.AppData = os.Getenv("BITWARDENCLI_APPDATA_DIR")
	}
	if c.Agents == nil {
		c.Agents = map[string]Agent{}
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// Validate checks values that do not need the network.
func (c *Config) Validate() error {
	if len(c.HMACKey) < 64 {
		return errors.New("hmac_key missing or too short; run `broker init`")
	}
	if !strings.HasPrefix(c.ApprovalPassword, "$argon2id$") {
		return errors.New("approval_password missing; run `broker init`")
	}
	if c.Approver.Port < 1 || c.Approver.Port > 65535 {
		return errors.New("approver.port out of range")
	}
	if c.Approver.BindIP != "" {
		if _, err := netip.ParseAddr(c.Approver.BindIP); err != nil {
			return fmt.Errorf("approver.bind_ip: %w", err)
		}
	}
	if err := checkListen(c.Agent.Listen); err != nil {
		return err
	}
	for _, r := range c.Auto {
		if r.Field == "totp" {
			return errors.New("auto rule for totp is not allowed")
		}
	}
	return nil
}

func checkListen(l string) error {
	if p, ok := strings.CutPrefix(l, "unix:"); ok {
		if !filepath.IsAbs(p) {
			return errors.New("agent.listen unix path must be absolute")
		}
		return nil
	}
	ap, err := netip.ParseAddrPort(l)
	if err != nil {
		return fmt.Errorf("agent.listen must be unix:/path or ip:port: %w", err)
	}
	if ap.Addr().IsUnspecified() {
		return errors.New("agent.listen must not bind all interfaces")
	}
	return nil
}

// AgentListenIsTailnet reports whether the agent API listens on a tailnet address.
func (c *Config) AgentListenIsTailnet() bool {
	ap, err := netip.ParseAddrPort(c.Agent.Listen)
	return err == nil && IsTailnetIP(ap.Addr())
}

// IsTailnetIP reports whether ip is in Tailscale's ranges (100.64.0.0/10, fd7a:115c:a1e0::/48).
func IsTailnetIP(ip netip.Addr) bool {
	return netip.MustParsePrefix("100.64.0.0/10").Contains(ip.Unmap()) ||
		netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(ip)
}

// IsAuto reports whether an item field is on the auto list. totp never is.
func (c *Config) IsAuto(itemID, field string) bool {
	if field == "totp" {
		return false
	}
	for _, r := range c.Auto {
		if r.ItemID == itemID && (r.Field == "" || r.Field == field) {
			return true
		}
	}
	return false
}

// AgentNames returns agent names in order.
func (c *Config) AgentNames() []string {
	names := make([]string, 0, len(c.Agents))
	for n := range c.Agents {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Load reads the config and refuses a file that others can read or write.
func Load(path string) (*Config, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s has mode %v; it must be 0600 (chmod 600 %s)", path, st.Mode().Perm(), path)
	}
	var c Config
	if _, err := toml.DecodeFile(path, &c); err != nil {
		return nil, err
	}
	c.Defaults()
	return &c, nil
}

// Save writes the config atomically with mode 0600.
func Save(path string, c *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.toml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString("# bw2fabroker config. Keep mode 0600. Edit with `broker` commands.\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := toml.NewEncoder(tmp).Encode(c); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Exists reports whether a config file is present.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, fs.ErrNotExist)
}
