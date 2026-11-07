# bw2fabroker

A small Go broker in front of the Bitwarden CLI. An agent asks for **one field of one item**. You
approve it on your phone: a push from **your own ntfy domain** opens an approval page on **your
tailnet**, and you type your **approval password**. The broker then returns that one value to the
agent once, in a fixed JSON shape. Nothing else passes between the broker and the agent.

```
agent ──broker-get──▶ broker ──push──▶ your ntfy server ──▶ iPhone
                        ▲                                      │
                        └──── approval page on the tailnet ◀───┘ (approval password)
```

- Only the broker holds the Bitwarden session key. The agent never runs `bw`.
- The broker logs in as a **separate agents account** that sees only one collection.
- No database. Pending requests live in memory; a restart cancels them.
- Design and review: [docs/DEV_PLAN.md](docs/DEV_PLAN.md). Agent instructions:
  [skills/bw-broker/SKILL.md](skills/bw-broker/SKILL.md).

## What you need

- Tailscale on the broker host (required; the broker checks it is installed and connected) and on
  your phone.
- A self-hosted ntfy server on your own domain, with HTTPS. The broker refuses `ntfy.sh`, any other
  domain, plain HTTP, and redirects.
- A Bitwarden server: self-hosted Vaultwarden / Bitwarden, or Bitwarden cloud.
- A separate Bitwarden account for agents, with agent-safe items in one organization collection
  shared with it.

## Install (app mode, Linux + systemd)

```sh
make install                    # binaries to /usr/local/bin, systemd unit, user "broker", group "broker-clients"
npm install -g @bitwarden/cli   # bw must be on PATH for the broker user

sudo -u broker -H env BROKER_CONFIG=/etc/bw2fabroker/config.toml HOME=/var/lib/bw2fabroker sh -c '
  broker init --ntfy-domain ntfy.example.com            # asks for a new approval password
  broker ntfy set --url https://ntfy.example.com --topic approvals --token tk_...   # sends a test push
  BITWARDENCLI_APPDATA_DIR=/var/lib/bw2fabroker/bw bw config server https://vault.example.com
  BITWARDENCLI_APPDATA_DIR=/var/lib/bw2fabroker/bw bw login --apikey   # agents account API key
  broker agent add claude                               # prints the agent token once
'
sudo systemctl enable --now bw2fabroker
sudo -u broker env BROKER_CONFIG=/etc/bw2fabroker/config.toml broker unlock   # agents account master password
sudo -u broker env BROKER_CONFIG=/etc/bw2fabroker/config.toml broker doctor
sudo usermod -aG broker-clients <agent user>            # may use /run/bw2fabroker/agent.sock
```

Docker mode (with a Tailscale sidecar): see [deploy/docker/README.md](deploy/docker/README.md).

## Use from an agent

```sh
export BROKER_TOKEN=bwb_...                          # or BROKER_TOKEN_FILE
export BROKER_URL=unix:/run/bw2fabroker/agent.sock   # or http://100.x.y.z:8786 for a remote broker

# Preferred: the value goes only into the command's environment.
broker-get --env PGPASSWORD staging-db password --reason "run migrations on staging" -- psql -h db -c 'select 1'

# Print the value (it lands in the agent's transcript).
broker-get staging-db password --reason "set OPENAI_API_KEY for a local test"
```

Every answer is exactly one JSON line:

```json
{"request_id":"r_…","status":"approved","code":null,"value":"…"}
```

`status` is `pending`, `approved`, `denied`, or `rejected`; `code` comes from a fixed list (see
[the contract](docs/DEV_PLAN.md#4-response-gating-the-agent-contract-r19)). Fields: `username`,
`password`, `totp`, `uri`, `custom:<name>`. Notes and attachments are never available.

`broker-get` exits 0 (approved), 1 (denied), or 2 (rejected). With `--env`, the JSON line goes to
stderr and the exit status is the command's own.

## Admin

| Command | Does |
|---|---|
| `broker init` | Config, HMAC key, approval password (argon2id), ntfy own domain |
| `broker passwd` | Change the approval password |
| `broker ntfy set --url --topic [--token]` | ntfy target, own domain only; sends a test push |
| `broker net set [--ip] [--port] [--public-host] [--agent-listen] [--agent-socket-gid]` | Listeners |
| `broker agent add/rm/resume NAME`, `broker agent list` | Agent tokens (only hashes are stored) |
| `broker auto add/rm ITEM_ID [--field F]`, `broker auto list` | Items returned without asking (never `totp`) |
| `broker start` / `broker unlock` | Serve / unlock `bw` in a running broker |
| `broker unlock-approvals` | Clear the lockout after 10 wrong passwords in an hour |
| `broker status`, `broker doctor` | State of the running broker / setup checks |

The audit log is one JSON line per event on stderr (journald under systemd). It never holds a value
or a password.

## Limits that protect you

- One approval = one secret, delivered once. Requests expire after 120 s.
- 3 wrong passwords deny the request; 10 in an hour lock all approvals.
- 3 denials in 10 minutes suspend the agent until `broker agent resume`.
- At most 5 pending and 20 new requests per agent per 10 minutes.
- If Tailscale goes down, the approval page closes and pending requests expire.

## Develop

```sh
make vet test     # go vet, gofmt, tests with the race detector
make fuzz         # fuzz the request parser
make docker       # build the image
```
