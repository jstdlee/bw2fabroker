package vault

import (
	"context"
	"fmt"

	"github.com/jstdlee/bw2fabroker/internal/config"
)

// SetServer points the bw CLI at a Bitwarden or Vaultwarden server.
// It does not need the vault to be unlocked. An empty URL is refused here;
// "leave the current server" is the caller's choice, not a bw command.
func (b *BW) SetServer(ctx context.Context, rawURL string) error {
	if err := config.ValidVaultServer(rawURL); err != nil {
		return err
	}
	if rawURL == "" {
		return fmt.Errorf("vault server URL is empty")
	}
	if _, err := b.run(ctx, false, nil, "config", "server", rawURL); err != nil {
		return fmt.Errorf("bw config server: %w", err)
	}
	return nil
}
