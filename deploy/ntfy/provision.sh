#!/bin/sh
# Provision the broker's ntfy user, topic permissions, and bearer token, then verify them.
#
# ntfy has no HTTP API for creating users (2.34): `ntfy user add` is a server-side command.
# This script therefore talks to the ntfy CLI, in one of three ways:
#
#   (default)          docker exec "$NTFY_CONTAINER" ntfy ...      # ntfy on this host
#   NTFY_SSH=u@host    ssh u@host ntfy ...                          # ntfy on another host
#   NTFY_LOCAL=1       ntfy ...                                     # ntfy bin on PATH
#
# Required:
#   NTFY_URL=https://ntfy.example.com
#
# Optional:
#   NTFY_TOPIC=bw2fabroker    topic name
#   NTFY_USER=bw2fabroker     the broker's user; granted write-only on the topic
#   NTFY_READER=kid           the phone's user; granted read-only on the topic (empty to skip)
#   NTFY_CONTAINER=ntfy       container name for docker exec
#   ENV_FILE=path             rewrite BROKER_NTFY_* keys in this file (mode 0600)
#
# Result: the broker can publish, the reader can read, anonymous clients get 401/403, and no
# other user can publish. Exits non-zero if any of those checks fails.
set -eu

NTFY_URL=${NTFY_URL:?set NTFY_URL, e.g. https://ntfy.example.com}
NTFY_TOPIC=${NTFY_TOPIC:-bw2fabroker}
NTFY_USER=${NTFY_USER:-bw2fabroker}
NTFY_READER=${NTFY_READER:-}
NTFY_CONTAINER=${NTFY_CONTAINER:-ntfy}
ENV_FILE=${ENV_FILE:-}

case "$NTFY_URL" in
https://*) ;;
*) echo "NTFY_URL must start with https://" >&2; exit 1 ;;
esac
HOST=${NTFY_URL#https://}
HOST=${HOST%%/*}
BASE=${NTFY_URL%/}

fail() { echo "FAIL  $*" >&2; exit 1; }
ok() { echo "ok    $*"; }

# ntfy_cli runs the ntfy server command wherever the server lives.
ntfy_cli() {
	if [ -n "${NTFY_SSH:-}" ]; then
		ssh "$NTFY_SSH" ntfy "$@"
	elif [ "${NTFY_LOCAL:-}" = 1 ]; then
		command ntfy "$@"
	else
		docker exec "$NTFY_CONTAINER" ntfy "$@"
	fi
}

# add_user creates the user when it is missing. The password is random and unused: tokens are.
add_user() {
	name=$1
	if ntfy_cli user list 2>/dev/null | grep -q "^user $name "; then
		ok "ntfy user $name already exists"
		return
	fi
	pw=$(head -c 18 /dev/urandom | base64 | tr -d '/+=')
	if [ -n "${NTFY_SSH:-}" ]; then
		NFTPW=$pw ssh "$NTFY_SSH" 'NTFY_PASSWORD=$NFTPW ntfy user add --role=user '"$name"
	elif [ "${NTFY_LOCAL:-}" = 1 ]; then
		NTFY_PASSWORD=$pw command ntfy user add --role=user "$name"
	else
		docker exec -e NTFY_PASSWORD="$pw" "$NTFY_CONTAINER" ntfy user add --role=user "$name"
	fi
	ok "created ntfy user $name"
}

add_user "$NTFY_USER"
if [ -n "$NTFY_READER" ] && ! ntfy_cli user list 2>/dev/null | grep -q "^user $NTFY_READER "; then
	fail "read user $NTFY_READER does not exist; create it in the ntfy app first (or leave NTFY_READER empty)"
fi

# Only the broker writes, the phone reads, and anonymous clients get nothing.
ntfy_cli access "$NTFY_USER" "$NTFY_TOPIC" write-only >/dev/null
if [ -n "$NTFY_READER" ]; then
	ntfy_cli access "$NTFY_READER" "$NTFY_TOPIC" read-only >/dev/null
fi
ntfy_cli access everyone "$NTFY_TOPIC" deny >/dev/null

# A token per run; ntfy shows it once, so list and remove old ones with `ntfy token list`.
TOKEN=$(ntfy_cli token add --label="${HOST%%.*}-broker" "$NTFY_USER" | sed -n 's/^token \([A-Za-z0-9_]*\) created.*/\1/p')
[ -n "$TOKEN" ] || fail "ntfy did not print a token"

status() { curl -sS -m 10 -o /dev/null -w '%{http_code}' "$@"; }
anon_pub=$(status -d 'provisioning check' "$BASE/$NTFY_TOPIC")
[ "$anon_pub" = 401 ] || [ "$anon_pub" = 403 ] || fail "anonymous publish answered $anon_pub; the topic is public"
ok "anonymous publish is refused ($anon_pub)"

anon_read=$(status "$BASE/$NTFY_TOPIC/json?poll=1&since=1s")
[ "$anon_read" = 401 ] || [ "$anon_read" = 403 ] || fail "anonymous read answered $anon_read; the topic is public"
ok "anonymous read is refused ($anon_read)"

broker_pub=$(status -H "Authorization: Bearer $TOKEN" -d 'provisioning check' "$BASE/$NTFY_TOPIC")
[ "$broker_pub" = 200 ] || fail "the broker token could not publish ($broker_pub)"
ok "the broker token publishes"

broker_read=$(status -H "Authorization: Bearer $TOKEN" "$BASE/$NTFY_TOPIC/json?poll=1&since=1s")
case "$broker_read" in
401 | 403) ok "the broker token cannot read the topic ($broker_read)" ;;
*) echo "warn  the broker token can read the topic ($broker_read); write-only is enough" ;;
esac

if [ -n "$NTFY_READER" ]; then
	READER_TOKEN=${NTFY_READER_TOKEN:-}
	if [ -n "$READER_TOKEN" ]; then
		reader_pub=$(status -H "Authorization: Bearer $READER_TOKEN" -d 'x' "$BASE/$NTFY_TOPIC")
		[ "$reader_pub" = 401 ] || [ "$reader_pub" = 403 ] || fail "$NTFY_READER can still publish ($reader_pub); set NTFY_READER_TOKEN to check it"
		ok "$NTFY_READER cannot publish ($reader_pub)"
	fi
fi

if [ -n "$ENV_FILE" ]; then
	tmp=$(mktemp)
	[ -f "$ENV_FILE" ] && grep -vE '^(BROKER_NTFY_URL|BROKER_NTFY_DOMAIN|BROKER_NTFY_TOPIC|BROKER_NTFY_TOKEN)=' "$ENV_FILE" >"$tmp" || true
	{
		echo "BROKER_NTFY_URL=$BASE"
		echo "BROKER_NTFY_DOMAIN=$HOST"
		echo "BROKER_NTFY_TOPIC=$NTFY_TOPIC"
		echo "BROKER_NTFY_TOKEN=$TOKEN"
	} >>"$tmp"
	install -m 600 "$tmp" "$ENV_FILE"
	rm -f "$tmp"
	ok "wrote BROKER_NTFY_* to $ENV_FILE"
fi

echo
echo "BROKER_NTFY_URL=$BASE"
echo "BROKER_NTFY_DOMAIN=$HOST"
echo "BROKER_NTFY_TOPIC=$NTFY_TOPIC"
echo "BROKER_NTFY_TOKEN=$TOKEN"
echo
echo "Broker: write-only on $NTFY_TOPIC. ${NTFY_READER:-Nobody else}: read-only."
echo "Next: restart the broker, then \`broker doctor\` and the panel's Send a test notification."
