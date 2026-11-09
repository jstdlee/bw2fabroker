# bw2fabroker on gpd

State as deployed: container `bw2fabroker`, image `bw2fabroker:local` (repo `cf429c3`),
host network, volume `bw2fabroker_broker-data`.

## Why host networking

The broker binds gpd's own tailnet address and reuses the host `tailscaled`:

| Surface | Address |
|---|---|
| Agent API | `http://100.122.160.125:8786` |
| Approval page | `http://100.122.160.125:8797/<hmac link>` |
| Admin panel | `http://127.0.0.1:8788/admin` (loopback only) |
| State | volume `bw2fabroker_broker-data` → `/data` |

No second tailnet node, no `TS_AUTHKEY`. The shipped `deploy/docker/compose.yml` assumes a
Tailscale sidecar; this directory replaces it. Port 8797 is used because 8787 on gpd is taken
by `bun .../.noop/app/src/cli.ts daemon`.

## Files

| File | Mode | Holds |
|---|---|---|
| `deploy/gpd/.env` | 0600 | approval password, admin token, ntfy URL/topic/token, `BW_SERVER` |
| `deploy/gpd/agents.env` | 0600 | per-agent bearer tokens (`name<TAB>token`) |
| volume `/data/config/config.toml` | 0600 | config; secrets hashed or already in `.env` |
| volume `/data/config/audit.jsonl` | 0600 | decisions, no values, 7 days |
| volume `/data/bw` | 0700 | `bw` data dir and its session |

The approval password is generated. Read it with
`grep BROKER_APPROVAL_PASSWORD deploy/gpd/.env` and save it in the phone's password manager;
change it later in the panel (`/admin`, section "Approval password").

## Remaining, needs the agents Bitwarden account

```sh
cd /home/fxyz/apps/bw2fabroker/deploy/gpd

# 1. server (skip for Bitwarden cloud US; use https://vault.bitwarden.eu or your own URL)
docker exec bw2fabroker bw config server https://vault.bitwarden.com

# 2. log in as the agents account (create that account and its one collection first)
#    the login lives in the container's /data/bw; a session from another machine cannot be used
docker exec -e BW_CLIENTID='user.xxxx' -e BW_CLIENTSECRET='yyyy' bw2fabroker broker login --apikey
#    or: BW_CLIENTID=... BW_CLIENTSECRET=... deploy/gpd/login.sh

# 3. unlock (master password of the agents account, not the approval password)
docker exec -it bw2fabroker broker unlock

# 4. check — doctor prints the account it is logged in as; it must be the agents account,
#    never a personal one, because the account is what limits which items exist at all
docker exec bw2fabroker broker doctor
```

Until step 3, every request returns `503 rejected/locked`.

## Phone

Subscribe the ntfy app to topic `bw2fabroker` on `https://ntfy.ohmyai.xyz`.

The topic is restricted to one publisher and one reader:

| User | ntfy permission on `bw2fabroker` |
|---|---|
| `bw2fabroker` | write-only (the broker's token; it cannot read its own topic) |
| `kid` | read-only (the phone; the wider `*` read-write does not apply to this topic) |
| `*` (anonymous) | denied |

ntfy applies the most specific rule, so `kid`'s `*` grant does not re-open the topic. Confirm with
`docker exec ntfy ntfy access`, then `broker doctor`; the panel's **Send a test notification**
runs the same probes and delivers one push. Re-apply the whole set with
`NTFY_URL=https://ntfy.ohmyai.xyz NTFY_READER=kid deploy/ntfy/provision.sh` (it mints a new token
and prints `BROKER_NTFY_*`; restart the broker to pick it up).

## Agents

`opencode` and `claude` tokens exist in `agents.env`. Add more in the panel; a token is shown once.
Each agent needs `BROKER_URL` and its own token, never a shared one.

```json
{
  "mcpServers": {
    "bw2fabroker": {
      "command": "broker-mcp",
      "env": {
        "BROKER_URL": "http://100.122.160.125:8786",
        "BROKER_TOKEN_FILE": "/home/fxyz/.config/bw2fabroker/opencode.token"
      }
    }
  }
}
```

`broker-mcp`, `broker-get`, `broker` are installed in `/home/fxyz/.local/bin`. The MCP server is
stdio only: each agent host runs its own copy.

## Ops

```sh
docker compose -f deploy/gpd/compose.yml ps
docker logs bw2fabroker
cd /home/fxyz/apps/bw2fabroker && docker build -t bw2fabroker:local .   # after a repo change
docker compose -f deploy/gpd/compose.yml up -d                          # then unlock again
```

After a host reboot, the container can start before `tailscaled` is up; `restart: unless-stopped`
retries it, and the vault is locked until `broker unlock`.

## Notes

- Notifications are optional. Clearing the four `[ntfy]` values (or the `BROKER_NTFY_*` keys) keeps
  the broker running; approval links then go to `docker logs bw2fabroker` and to the panel section
  "Waiting for approval". A partly filled set is refused at startup.
- `broker init` needs a TTY for the approval password and ignores
  `BROKER_APPROVAL_PASSWORD`; this config was generated with a throwaway helper instead.
