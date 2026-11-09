package config

import (
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/jstdlee/bw2fabroker/internal/auth"
	"github.com/jstdlee/bw2fabroker/internal/notify"
)

// firstEnv returns the value of the first name that is set and not empty.
func firstEnv(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

// ApplyEnv copies credentials and bind settings from the environment when they are set.
// A password is re-hashed only when it does not match the stored hash. Tokens are stored
// only as hashes, except the ntfy bearer token, which has to be sent to ntfy.
func ApplyEnv(c *Config) (bool, error) {
	changed := false
	set := func() { changed = true }
	if pw := os.Getenv("BROKER_APPROVAL_PASSWORD"); pw != "" {
		if !auth.VerifyPassword(c.ApprovalPassword, pw) {
			h, err := auth.HashPassword(pw)
			if err != nil {
				return false, err
			}
			c.ApprovalPassword = h
			set()
		}
	}
	if tok := strings.TrimSpace(os.Getenv("BROKER_ADMIN_TOKEN")); tok != "" {
		h := auth.HashToken(tok)
		if c.AgentHasHash(h) {
			return false, errors.New("BROKER_ADMIN_TOKEN must not match an agent access token")
		}
		if c.Admin.TokenSHA256 != h {
			c.Admin.TokenSHA256 = h
			set()
		}
	}
	if d := os.Getenv("BROKER_NTFY_DOMAIN"); d != "" && c.Ntfy.OwnDomain != d {
		if err := notify.CheckOwnDomain(d); err != nil {
			return false, err
		}
		c.Ntfy.OwnDomain = d
		set()
	}
	u := firstEnv("BROKER_NTFY_URL", "NTFY_URL")
	if u != "" && c.Ntfy.URL != u {
		c.Ntfy.URL = u
		set()
		if c.Ntfy.OwnDomain == "" {
			if parsed, err := url.Parse(u); err == nil {
				c.Ntfy.OwnDomain = parsed.Hostname()
			}
		}
	}
	if t := firstEnv("BROKER_NTFY_TOPIC", "NTFY_TOPIC"); t != "" && c.Ntfy.Topic != t {
		c.Ntfy.Topic = t
		set()
	}
	tok := strings.TrimSpace(firstEnv("BROKER_NTFY_TOKEN", "NTFY_TOKEN"))
	if tok == "" {
		if p := os.Getenv("BROKER_NTFY_TOKEN_FILE"); p != "" {
			b, err := os.ReadFile(p)
			if err != nil {
				return false, err
			}
			tok = strings.TrimSpace(string(b))
		}
	}
	if tok != "" && c.Ntfy.Token != tok {
		c.Ntfy.Token = tok
		set()
	}
	if h := os.Getenv("BROKER_BIND_HOST"); h != "" && c.Approver.BindHost != h {
		c.Approver.BindHost = h
		set()
	}
	if h := os.Getenv("BROKER_PUBLIC_HOST"); h != "" && c.Approver.PublicHost != h {
		c.Approver.PublicHost = h
		set()
	}
	if p := os.Getenv("BROKER_BIND_PORT"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return false, err
		}
		if c.Approver.Port != n {
			c.Approver.Port = n
			set()
		}
	}
	if s := os.Getenv("BW_SERVER"); s != "" && c.Vault.Server != s {
		c.Vault.Server = s
		set()
	}
	if d := os.Getenv("BROKER_VAULT_APPDATA"); d != "" && c.Vault.AppData != d {
		c.Vault.AppData = d
		set()
	}
	if p := os.Getenv("BROKER_VAULT_BW_PATH"); p != "" && c.Vault.BWPath != p {
		c.Vault.BWPath = p
		set()
	}
	if a := os.Getenv("BROKER_ADMIN_LISTEN"); a != "" && c.Admin.Server != a {
		c.Admin.Server = a
		set()
	}
	return changed, nil
}
