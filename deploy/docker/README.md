# Docker mode

The `tailscale` container is the broker's own node on your tailnet. The broker container shares its
network, so the approval page listens on that node's tailnet IP only.

Anyone who can run Docker commands on this host is root and can read the broker. The agent's user
must not be in the `docker` group.

## First run

```sh
cd deploy/docker
echo "TS_AUTHKEY=tskey-auth-..." > .env      # a Tailscale auth key for this node
mkdir -p agent
docker compose build
docker compose up -d tailscale

# One-time setup inside the broker container (data lives in the broker-data volume).
# Notifications are optional: without --ntfy-domain the broker runs, and approval links
# go to the log and the admin panel.
docker compose run --rm -it broker init --ntfy-domain ntfy.example.com
# The init command prints an admin token once. Open http://127.0.0.1:8788/admin
# from the host (publish that loopback port, or use the panel on the broker host)
# and set ntfy, the agent listen address, and an agent.
docker compose run --rm -it --entrypoint bw broker config server https://vault.example.com
#   (Bitwarden cloud: https://vault.bitwarden.com or https://vault.bitwarden.eu)
docker compose run --rm -it -e BW_CLIENTID=user.xxx -e BW_CLIENTSECRET=yyy --entrypoint bw broker login --apikey

docker compose up -d broker
docker compose exec -it broker broker unlock                 # master password of the agents account
docker compose exec broker broker doctor
```

ntfy settings come from `.env` as `BROKER_NTFY_URL`, `BROKER_NTFY_DOMAIN`, `BROKER_NTFY_TOPIC`, and
`BROKER_NTFY_TOKEN` (or `BROKER_NTFY_TOKEN_FILE`). Leave all four empty to run without
notifications. The server must be `https` on that domain, and the topic must reject requests with
no bearer token; `broker start` and `broker doctor` probe both before serving.

Create the broker's ntfy user, its topic permissions, and its token with
[deploy/ntfy/provision.sh](../ntfy/provision.sh): the broker is write-only, the phone's user
read-only, anonymous clients denied. ntfy has no HTTP user API, so the script uses `docker exec`
(default), `NTFY_SSH`, or `NTFY_LOCAL`. Its last step verifies the permissions with real requests,
and the panel's **Send a test notification** re-runs the check plus one delivery.

The Bitwarden server can be cloud, Vaultwarden, or Bitwarden's own self-hosted install.
Set it in the admin panel (Bitwarden server) or with `BW_SERVER`. See
[deploy/vaultwarden](../vaultwarden/README.md). Plain HTTP is accepted only for localhost,
a private address, or a tailnet address.

The broker starts **locked** after every restart. Until you run `broker unlock`, agents get
`rejected` / `locked`, and your phone gets one "bw2fabroker is locked" push.

## Agents

Set the agent listen address in the admin panel to this node's tailnet IP, for example
`100.x.y.z:8786`, then restart the broker and unlock again. Agents use
`BROKER_URL=http://100.x.y.z:8786` and the bearer token the panel showed once. There is no Unix
socket for agents. The broker CLI cannot add an agent or print a token.
