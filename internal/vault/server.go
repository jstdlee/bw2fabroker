package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jstdlee/bw2fabroker/internal/config"
)

// ServerURL returns the server the bw profile is pointed at, or "" when bw knows none.
func (b *BW) ServerURL(ctx context.Context) (string, error) {
	out, err := b.run(ctx, false, nil, "status")
	if err != nil {
		return "", err
	}
	var s struct {
		ServerURL string `json:"serverUrl"`
	}
	if err := json.Unmarshal(out, &s); err != nil {
		return "", err
	}
	return s.ServerURL, nil
}

func sameServer(a, b string) bool {
	return strings.EqualFold(strings.TrimRight(a, "/"), strings.TrimRight(b, "/"))
}

// SetServer points the bw CLI at a Bitwarden or Vaultwarden server.
// It does not need the vault to be unlocked. An empty URL is refused here;
// "leave the current server" is the caller's choice, not a bw command.
//
// bw refuses to change the server while an account is logged in ("Logout required
// before server config update"), so a server the profile is already on is left alone:
// startup would otherwise fail every time on an already configured, logged-in profile.
func (b *BW) SetServer(ctx context.Context, rawURL string) error {
	if err := config.ValidVaultServer(rawURL); err != nil {
		return err
	}
	if rawURL == "" {
		return fmt.Errorf("vault server URL is empty")
	}
	if cur, err := b.ServerURL(ctx); err == nil && sameServer(cur, rawURL) {
		return nil
	}
	if _, err := b.run(ctx, false, nil, "config", "server", rawURL); err != nil {
		if strings.Contains(err.Error(), "Logout required") {
			return fmt.Errorf("bw config server: %w (run `bw logout`, then `broker login` for the new server)", err)
		}
		return fmt.Errorf("bw config server: %w", err)
	}
	return nil
}
