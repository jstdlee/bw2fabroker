#!/bin/sh
# Log the agents account in, then unlock the vault, inside the running container.
#
# The login lives in the container's own bw profile (/data/bw). Nothing is copied from the host:
# a session from another machine or profile cannot authenticate this one, and the broker never
# reads BW_SESSION from its environment — it runs `bw unlock --raw` itself and keeps the session
# in memory.
#
#   deploy/gpd/login.sh                     # API key from BW_CLIENTID/BW_CLIENTSECRET, or prompts
#   deploy/gpd/login.sh --email you@x.test  # email + master password; bw asks for the rest
#
# Log in once; unlock again after every container start. CONTAINER=bw2fabroker by default.
set -eu
container=${CONTAINER:-bw2fabroker}
[ -t 0 ] || { echo "a terminal is needed: bw asks for the master password" >&2; exit 1; }
docker exec -it "$container" broker login "$@"
docker exec -it "$container" broker unlock
docker exec "$container" broker doctor
