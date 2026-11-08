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

The broker starts **locked** after every restart. Until you run `broker unlock`, agents get
`rejected` / `locked`, and your phone gets one "bw2fabroker is locked" push.

## Agents

Set the agent listen address in the admin panel to this node's tailnet IP, for example
`100.x.y.z:8786`, then restart the broker and unlock again. Agents use
`BROKER_URL=http://100.x.y.z:8786` and the bearer token the panel showed once. There is no Unix
socket for agents. The broker CLI cannot add an agent or print a token.
