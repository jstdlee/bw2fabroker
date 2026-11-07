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

# One-time setup inside the broker container (data lives in the broker-data volume):
docker compose run --rm -it broker init --ntfy-domain ntfy.example.com
docker compose run --rm -it broker ntfy set --url https://ntfy.example.com --topic approvals --token tk_...
docker compose run --rm -it --entrypoint bw broker config server https://vault.example.com
#   (Bitwarden cloud: https://vault.bitwarden.com or https://vault.bitwarden.eu)
docker compose run --rm -it -e BW_CLIENTID=user.xxx -e BW_CLIENTSECRET=yyy --entrypoint bw broker login --apikey
docker compose run --rm -it broker agent add claude          # prints the agent token once

docker compose up -d broker
docker compose exec -it broker broker unlock                 # master password of the agents account
docker compose exec broker broker doctor
```

The broker starts **locked** after every restart. Until you run `broker unlock`, agents get
`rejected` / `locked`, and your phone gets one "bw2fabroker is locked" push.

## Agents on this host

The agent socket is `deploy/docker/agent/agent.sock`. It is mode 0600 for the container user
(uid 10001) unless you set `agent.socket_gid` in the config to a host group id; then members of that
group can connect (mode 0660):

```sh
docker compose exec broker broker net set --agent-socket-gid "$(getent group agents | cut -d: -f3)"
docker compose restart broker
docker compose exec -it broker broker unlock
```

Agents use `BROKER_URL=unix:/path/to/deploy/docker/agent/agent.sock` and their token.

## Remote agents

For agents on other machines, listen on the broker node's tailnet IP:

```sh
docker compose exec broker broker net set --agent-listen 100.x.y.z:8786
docker compose restart broker
docker compose exec -it broker broker unlock
```

Agents then use `BROKER_URL=http://100.x.y.z:8786` and their token. Remote agents are protected by
their token only.
