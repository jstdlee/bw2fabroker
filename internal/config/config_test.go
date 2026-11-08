package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jstdlee/bw2fabroker/internal/auth"
)

func TestSaveLoadMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.toml")
	c := &Config{HMACKey: strings.Repeat("ab", 32), ApprovalPassword: "$argon2id$x", Ntfy: Ntfy{OwnDomain: "ntfy.example.com"}}
	c.Defaults()
	if err := Save(p, c); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	got, err := Load(p)
	if err != nil || got.Ntfy.OwnDomain != "ntfy.example.com" {
		t.Fatalf("load: %v %+v", err, got)
	}
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(p, 0o644)
	if _, err := Load(p); err == nil {
		t.Fatal("world-readable config accepted")
	}
}

func TestValidateAndAuto(t *testing.T) {
	c := &Config{HMACKey: strings.Repeat("ab", 32), ApprovalPassword: "$argon2id$x"}
	c.Defaults()
	for _, l := range []string{"0.0.0.0:8786", "relative/sock", "unix:rel", "nonsense"} {
		c.Agent.Listen = l
		if c.Validate() == nil {
			t.Errorf("listen %q accepted", l)
		}
	}
	c.Agent.Listen = "100.70.1.2:8786"
	if c.Validate() != nil || !c.AgentListenIsTailnet() {
		t.Fatal("tailnet agent listen")
	}
	c.Auto = []AutoRule{{ItemID: "a"}, {ItemID: "b", Field: "password"}}
	if !c.IsAuto("a", "username") || c.IsAuto("a", "totp") || !c.IsAuto("b", "password") || c.IsAuto("b", "username") {
		t.Fatal("IsAuto")
	}
	c.Auto = []AutoRule{{ItemID: "a", Field: "totp"}}
	if c.Validate() == nil {
		t.Fatal("totp auto accepted")
	}
}

func TestAdminTokenIsNotAgentToken(t *testing.T) {
	c := &Config{HMACKey: strings.Repeat("ab", 32), ApprovalPassword: "$argon2id$x"}
	c.Defaults()
	c.Admin.Server = "100.64.0.1:8788"
	if c.Validate() == nil {
		t.Fatal("tailnet admin server accepted")
	}
	c.Admin.Server = "127.0.0.1:8788"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Admin.TokenSHA256 = "abc"
	c.Agents["claude"] = Agent{TokenSHA256: "abc"}
	if c.Validate() == nil {
		t.Fatal("shared admin and agent token accepted")
	}
	c.Agents["claude"] = Agent{TokenSHA256: "def"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	const shared = "bwb_same-token"
	c.Agents["claude"] = Agent{TokenSHA256: auth.HashToken(shared)}
	t.Setenv("BROKER_ADMIN_TOKEN", shared)
	if _, err := ApplyEnv(c); err == nil {
		t.Fatal("BROKER_ADMIN_TOKEN matching an agent accepted")
	}
}
