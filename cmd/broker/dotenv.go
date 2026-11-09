package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// dotEnvTemplate is the credential file the broker reads at startup. It is written by
// `broker init` and never holds a value the broker cannot get another way.
const dotEnvTemplate = `# bw2fabroker credentials.
# Keep this file mode 0600. Do not commit it.
# The broker reads this file when it starts. A variable that is already set in the
# environment wins over the value here.

# The password you type on the phone to approve a request. Not the Bitwarden master password.
BROKER_APPROVAL_PASSWORD=

# The key for the loopback admin panel.
BROKER_ADMIN_TOKEN=

# Your self-hosted ntfy server. The broker refuses ntfy.sh and plain http.
BROKER_NTFY_DOMAIN=ntfy.example.com
BROKER_NTFY_URL=https://ntfy.example.com
BROKER_NTFY_TOPIC=bw-approvals
BROKER_NTFY_TOKEN=

# Bitwarden server: Bitwarden cloud, Vaultwarden, or your own self-hosted server.
BW_SERVER=https://vault.bitwarden.com

# The master password of the agents account. It unlocks the vault at startup.
# Leave it empty to unlock with "broker unlock" instead.
BW_MASTER_PASSWORD=

# Where the phone and the agents connect. Uncomment and set what you need.
# BROKER_BIND_HOST=100.x.y.z
# BROKER_BIND_PORT=8787
# BROKER_PUBLIC_HOST=bw2fabroker.example.ts.net
# BROKER_AGENT_LISTEN=100.x.y.z:8786
# BROKER_ADMIN_LISTEN=127.0.0.1:8788
`

// writeDotEnv writes the credential template into dir when the file is not there yet.
// It returns the path and whether it created the file.
func writeDotEnv(dir string) (string, bool, error) {
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", false, err
	}
	path := filepath.Join(dir, ".env")
	if _, err := os.Stat(path); err == nil {
		return path, false, nil
	}
	if err := os.WriteFile(path, []byte(dotEnvTemplate), 0o600); err != nil {
		return "", false, fmt.Errorf("write %s: %w", path, err)
	}
	return path, true, nil
}
