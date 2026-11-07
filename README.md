# bw2fabroker

A local access broker for Bitwarden and 1Password CLIs. Agents and scripts ask the broker for one
secret. A human approves the request on a second factor (phone passkey, TOTP, or a security key).
The broker then releases only that value, for a limited time, and logs the event.

Status: planning. See [docs/DEV_PLAN.md](docs/DEV_PLAN.md).
