# bw2fabroker: development plan

Status: v3, the simplified plan, reviewed. It replaces v2 (in git history: grants, policy file,
relay, passkeys, 1Password). Part 2 lists what the review found. Part 1 already includes the fixes,
marked **[R#]**. §0 checks the plan against the original idea.
Date: 2026-11-07

## Part 0: The original idea, and where this plan differs

The idea that started the project:

- Do not change `bw`. Bitwarden encrypts on the client; the server cannot gate access, and
  "master password reprompt" is client-side only, so an agent can skip it. **The approval must
  control who holds the decryption key.** This plan keeps that principle: only the broker holds
  `BW_SESSION`.
- Self-hosted server (Vaultwarden or official Bitwarden). → Kept as an option. The broker works with
  any server `bw` can log in to (§7).
- Broker runs `bw serve` on localhost. → **Changed.** `bw serve` has no authentication; any local
  process could read the whole vault without approval. The broker runs `bw get` per request instead
  (§7).
- Per-item policy "auto" or "ask". → **Kept, in the broker config by item id**, not as a vault tag
  (§5, R4).
- Push via ntfy, Pushover, or Telegram; passkey or TOTP for stronger proof. → v1 uses ntfy plus the
  approval password, typed on the phone over the tailnet. Passkeys are later (§13).
- Short expiry and a log of every request. → 120 s expiry, one secret per approval, JSON audit log
  (§8).
- **Separate Bitwarden account for the agent**, seeing only one collection. → **Added as a
  required setup step** (§7, R15). It was missing from the simplified plan.
- **`bw get totp` is critical.** → **Added** (§5, R16). It was missing from the simplified plan.
- Python + FastAPI starter. → Go was chosen in the simplified plan: one static binary, no runtime
  for the separate service user to keep up to date.
- Alternative: Bitwarden Secrets Manager machine accounts. → Not used. Vaultwarden does not support
  it, the official server needs a licence, and it has no per-request human approval. Noted in §14.


## Part 1: The plan

### 1. Summary

A small Go service. An agent asks for one Bitwarden item field. The broker sends a push to your phone.
You open a link on the phone over the tailnet, see the request, and type your approval password.
The broker reads the field with `bw` and gives it to the agent once.

The broker keeps no database. Pending requests live in memory only.

### 2. Rules

- One approval = one secret. No grants. No deny rules.
- Two factors: **your phone** on the tailnet (identified by its node, not just "any tailnet IP"
  **[R1]**) and **your approval password**.
- Single user. No sessions and no bearer keys on the approver side. The password is sent with each
  approve call.
- A restart cancels all pending requests. The agent gets an error.
- The broker runs as its own OS user, not as the agent's user **[R2]**.
- The approval password is separate from the Bitwarden master password. The master password is
  never typed on the page.

### 3. Agent API (unix socket, `127.0.0.1`, or tailnet for remote agents; agent token required; see §15)

HTTP long-poll. It is simpler than WebSocket and `curl` works with it. Agent tools often stop a call
after 60 s or less, so there are two calls:

1. `POST /v1/requests` with `{item, field, reason}` returns `{id, expires_in: 120}` at once.
2. `GET /v1/requests/{id}/wait` holds up to 50 s. The agent repeats it until it gets an answer.

| Reply | Meaning |
|---|---|
| 200 | The secret. Sent once, then erased from memory. |
| 202 | Still pending, with `expires_in`. |
| 403 | Denied. Final. |
| 404 | Unknown id: the broker restarted, or the secret was already delivered. Final. **[R9]** |
| 408 | Timeout. Final. |
| 409 | Item name matches more than one item. Use the item id. Final. **[R5]** |

- The agent must not make a new request before it sees a final reply. The final reply always comes
  within 120 s.
- One token per agent (`Authorization: Bearer <token>`). The broker stores only its hash and finds
  the agent by token, not by any name the agent sends.
- At most 5 pending requests **per agent** **[R11]**. After 3 denials in 10 minutes, the agent's token
  is suspended until `broker agent resume NAME` **[R7]**.
- The `/v1` routes exist only on the agent listener. The `/a` routes exist only on the tailnet
  listener **[R3]**.
- Helper `broker-get ITEM FIELD` runs the poll loop and prints the value.
  `broker-get --env VAR ITEM FIELD -- CMD...` puts the value in `CMD`'s environment and does not
  print it, so it does not land in the agent's transcript **[R10]**.

### 4. Approver side (tailnet listener only)

- `GET /a/{token}`: page with agent name, item name **and item id**, field, folder, reason, and
  time left. The reason is shown as plain text, labelled "agent's own words" **[R5]**. GET never
  changes state.
- `POST /a/{token}/approve`: needs the password.
- `POST /a/{token}/deny`: no password. Deny is safe.
- The token is the request id plus an expiry, signed with HMAC-SHA256. The broker stores nothing for
  it. It checks the MAC in constant time and checks that the id is still pending.
- 3 wrong passwords deny the request. 10 wrong passwords in an hour, across all requests, lock
  approvals until `broker unlock-approvals` and send an alert **[R6]**.
- Source check **[R1]**: the broker asks tailscaled who is calling (`whois` on the remote address,
  §13) and accepts approve and deny calls only from the phone's node (stored by its stable node
  id; the IP is checked too). It refuses its own node and every node registered for a remote agent,
  so an agent cannot use the approver side.
- Response headers: `Cache-Control: no-store`, `Referrer-Policy: no-referrer`,
  `X-Frame-Options: DENY`.

### 5. Policy: `auto` and `ask` **[R4] [R16]**

- Default for every item: **ask**.
- `broker auto add <item-id> [--field F]` marks an item as **auto**: it is returned at once, with an
  audit line and an informational push ("agent X read item Y"). The list lives in the broker
  config, by item id, not as a tag in the vault. Anyone who can edit a vault item, for example a
  member of a shared collection, could add a vault tag and widen access.
- The **`totp` field is never auto**, and `broker auto add` refuses it. A TOTP code is a second
  factor; an agent that holds both the password and the code holds the whole login.
- A request for `password` and a request for `totp` of the same item within 10 minutes is marked on
  the approval page: "this agent now has both factors for this login".

### 6. Notification (ntfy)

- `broker ntfy set --url --topic --token`. The URL must be https **or** a tailnet address. It refuses
  `ntfy.sh`. `set` sends a test message.
- The message holds only: agent name, "wants a secret", and the link. The item name stays off the
  ntfy server; the page shows it **[R8]**.
- **iPhone with a self-hosted ntfy domain (chosen) [R8]**: iOS delivers pushes only through Apple's
  push service, so your ntfy server needs `upstream-base-url: "https://ntfy.sh"` in its
  `server.yml`. ntfy.sh then forwards only a "poll" signal with a hash of the message id. The ntfy
  iOS app then fetches the message text from **your** server, so the phone must reach your ntfy
  domain. The "refuse ntfy.sh" check applies to the `--url` the broker posts to, not to this
  upstream setting. `broker doctor` reminds you of this setting, because the broker cannot read the
  server's config.
- The link in the push is `http://<broker tailnet IP or MagicDNS name>:<port>/a/<token>`. Safari
  opens it; the Tailscale iOS app must be connected.

### 7. Vault

- **Separate Bitwarden account for agents [R15]** (required). Create an account such as
  `agents@...`. Put agent-safe items in one organization collection and share only that collection
  with this account. The broker logs in as this account, never as your main account. Critical items
  are then not in the broker's vault at all, even if the broker is compromised. Vaultwarden supports
  organizations and collections without a licence.
- Server (chosen: both supported): **self-hosted Vaultwarden / Bitwarden** or **Bitwarden cloud**.
  `bw config server <url>` selects it. A self-hosted server can live on the tailnet only. On
  Bitwarden cloud, a free organization (2 users, 2 collections) is enough for you plus the agents
  account. Tests run against Vaultwarden in Docker.
- Prerequisite, once: `bw config server ...` and `bw login --apikey`, as the broker user, with the
  agents account's API key.
- The master password the broker asks for is the **agents account's** master password, not yours.
- `broker start` asks for the master password through a prompt the broker owns (its own TTY, or
  `systemd-ask-password` when run as a service), runs `bw unlock --raw`, and keeps `BW_SESSION` in
  memory only **[R12]**.
- Each read runs `bw get item <id> --nointeraction` with `BW_SESSION` in that child's environment
  only, then picks the field in Go. Name lookups use `bw list items --search`, and the broker
  requires exactly one exact-name match **[R5]**.
- `bw sync` on start and every 15 minutes **[R13]**.
- No `bw serve`: it has no authentication and would expose the whole vault to every local process.

### 8. Audit log **[R14]**

No database, but one JSON line per event to stderr (journald when run under systemd): request,
notify, approve, deny, timeout, wrong password, delivered. Lines hold the agent name, item id,
field, and source IP. **Never** the value or the password.

### 9. Admin (CLI only, no web page)

| Command | Does |
|---|---|
| `broker init` | Writes config, random 32-byte HMAC key, asks for approval password (argon2id hash). |
| `broker passwd` | Changes the approval password. |
| `broker agent add NAME` | Shows the token once. Stores only its SHA-256 hash. |
| `broker agent rm NAME` / `resume NAME` | Removes or un-suspends an agent. |
| `broker approver set` | Lists tailnet peers from tailscaled; you pick the phone. Stores its node id and IP. |
| `broker net set [--ip 100.x.y.z]` | Optional override; by default the tailnet IP comes from tailscaled (§13). |
| `broker unlock` | Unlocks `bw` in a running broker (for Docker: `docker exec -it broker broker unlock`). |
| `broker ntfy set --url --topic --token` | See §6. |
| `broker start` | Unlocks `bw`, then serves. |
| `broker doctor` | Checks file modes, the OS user, listeners, and approver IP **[R2]**. |

Config: TOML, mode `0600`, owned by the broker user, in a directory the agent's user cannot read.

### 10. Go stack and layout

`net/http`, `golang.org/x/crypto/argon2`, `crypto/hmac`, `os/exec` for `bw`,
`github.com/BurntSushi/toml`. No database.

```
cmd/broker/          admin CLI + server
cmd/broker-get/      agent helper
internal/config/
internal/api/        agent listener (/v1) and approver listener (/a)
internal/vault/      bw adapter
internal/notify/     ntfy
internal/pending/    in-memory map, expiry, wake-up of waiters
internal/auth/       argon2id, HMAC links, agent tokens, lockout counters
deploy/              systemd unit, sysusers.d entry
```

### 11. Milestones

1. Tailscale preflight, vault adapter (agents account), pending map, agent API, `broker-get`,
   auto/ask with the `totp` rule. Test with `curl`.
2. Approval page, signed link, password check, `whois` approver check, lockouts.
3. ntfy, with the URL check and a short message body.
4. Admin CLI, `doctor`, app mode (systemd unit, separate user), Docker mode (Compose with the
   Tailscale sidecar), remote agents on the tailnet.
5. Tests (§12).

### 12. Tests

- Timeout reaches 408 at 120 s; a waiter that joins late still gets the final answer.
- Double approve: the second call fails, and the secret is delivered once.
- Wrong password ×3 denies; ×10 across requests locks approvals.
- Restart: pending ids return 404 to the agent.
- Approve from the broker host's own tailnet IP fails. Approve from a third tailnet node fails.
- `/a` routes are absent on the agent listener, and `/v1` routes on the tailnet listener.
- Tampered or expired link fails. A link for request A cannot approve request B.
- Two items with the same name return 409.
- `broker auto add` refuses `totp`; a `totp` request always asks.
- An item outside the agents collection is not found (the broker's account cannot see it).
- Preflight: the broker refuses to start with tailscaled stopped or logged out; the approver
  listener closes when Tailscale goes down and opens again when it is back.
- Approve from a remote agent's node fails; agent calls from an unregistered node fail.
- Docker: the container starts locked and returns 503 until `broker unlock`.
- Both vault servers: Vaultwarden in CI; Bitwarden cloud by hand before each release.
- As the agent's OS user: cannot read the config, cannot read `/proc/<broker>/environ` or memory,
  cannot run `bw` with the broker's data.
- The audit log never contains a value or a password (search the log for test values).

### 13. Tailscale (required)

The broker depends on Tailscale. There is no mode without it.

**Preflight** (on `broker start`, in `broker doctor`, and every 30 s while running):

1. tailscaled's local API is reachable (`/var/run/tailscale/tailscaled.sock`, or the path in
   `TS_SOCKET`). If not: exit with "Tailscale is not installed or not running".
2. Backend state is `Running` (logged in, connected). If not: exit with "Tailscale is not
   connected; run `tailscale up`".
3. This node has a `100.x.y.z` address. The approver listener binds to it. `broker net set --ip`
   can override it, but the address must still belong to this node.
4. The configured phone node is in the peer list. If not: warn (the phone may be off), do not exit.

While running, if Tailscale goes down or the node's IP changes, the broker closes the approver
listener (fail closed). Pending requests then cannot be approved and end with 408. When Tailscale
comes back, it opens the listener again. Every change is written to the audit log.

**Who is calling**: for each approver call, the broker asks tailscaled `whois <remote addr>` and
compares the node's stable id with the stored phone node. This is stronger than an IP check alone.

**Tailnet ACL (recommended)**: allow only the phone to reach the broker's approver port, and only
agent nodes to reach the agent port. This is a second check outside the broker.

**No `tailscale serve`**: it forwards to a local port, so every request would appear to come from
`127.0.0.1`. That breaks `whois` and the IP check, and an agent on the same host could call the
local port directly. Plain HTTP on the tailnet IP is encrypted by WireGuard. If HTTPS is needed
later (for passkeys), the broker gets a certificate with `tailscale cert` and serves TLS itself,
which keeps the caller's real address.

### 15. Deployment modes

The broker can run on the same machine as the agent or on another one. Both are supported.

**App mode** (native binary, systemd):
- Runs as a separate `broker` user **[R2]**, using the host's tailscaled.
- Agent on the same host: unix socket `/run/broker/agent.sock`, group `broker-clients`.
- Unlock prompt on `broker start` in a terminal, or `systemd-ask-password`.

**Docker mode** (Compose file in `deploy/docker/`):
- A `tailscale/tailscale` sidecar is the broker's own tailnet node (`TS_AUTHKEY`, state volume).
  The broker container uses `network_mode: service:tailscale` and shares its tailscaled socket
  through a volume, so preflight and `whois` work the same as in app mode.
- The container boundary takes the place of the separate user [R2]: non-root user, read-only root
  filesystem, volumes only for config and `bw` data, no published ports by default.
- The container starts **locked**. `/v1` returns 503 "broker locked" and the broker sends one push
  until you run `docker exec -it broker broker unlock`.
- **Anyone who can use Docker on that host is root [R17].** The agent's user must not be in the
  `docker` group or see the Docker socket. `doctor` warns when the socket is world-readable.

**Where the agent API listens**:

| Agent runs | Agent API |
|---|---|
| Same host, app mode | Unix socket, group `broker-clients` |
| Same host, broker in Docker | Unix socket in a bind-mounted directory, or a port published on `127.0.0.1` only |
| Another machine | A second port on the tailnet IP. `broker agent add NAME --node <peer>` ties the token to that agent's node (checked with `whois`) |

The agent port and the approver port are always separate listeners [R3]. An agent node can never
approve.

### 14. Out of scope for v1

1Password, multi-user, grants, policy files, passkeys, Windows, macOS service setup, Bitwarden
Secrets Manager machine accounts. All of these
are in v2 in git history if needed later.

---

## Part 2: Review of the simplified plan

### Blockers

- **R1. "Any tailnet IP" is not your phone.** If the agent's machine is on the tailnet (it is: the
  broker binds there), the agent can call the approver side from the host's own tailnet IP. So would
  any other node, or a node shared into your tailnet. The phone factor was really "any tailnet
  device". Fix: allow only the phone's IP, and refuse the host's own IP.
- **R2. Same OS user as the agent.** The plan does not say which user runs the broker. If it is the
  agent's user, the agent can read the config (HMAC key, password hash), read `BW_SESSION` from
  `/proc/<pid>/environ` of a running `bw`, attach a debugger, or use `bw`'s data dir directly. Both
  factors are then bypassed. Fix: a separate `broker` user, and `doctor` checks it.
- **R3. One listener for both APIs.** If `/a` were reachable on `127.0.0.1`, the agent could reach
  the approver side, and the IP check would see `127.0.0.1`. Fix: two listeners, two route sets.

### Major

- **R4. `agent_access=auto` is set in the vault.** A vault field is not a safe place for a security
  setting. Anyone who can edit the item can set it, and then there is no approval at all. Fix: drop
  it for v1; if needed, list item ids in the broker config.
- **R5. Name lookup and the reason text.** `bw get item NAME` returns the first match, so a
  look-alike item could be released. The reason is text the agent writes, so a prompt-injected agent
  can write a convincing one. Fix: require one exact match (409 otherwise), and show the item id and
  folder resolved by the broker.
- **R6. Password guessing.** 3 tries per request, but an attacker with access to the approver
  side can try 3 on each new request. Argon2id slows it down; a global limit stops it.
- **R7. Approval fatigue.** The 5-pending cap limits parallel requests, not a stream of them. Fix:
  suspend the agent after 3 denials in 10 minutes.
- **R15. The broker could unlock your main vault.** The simplified plan did not say which account
  the broker uses. If it is your main account, one broker bug or a careless approval exposes every
  item, including bank logins. Fix: a separate agents account that can see only one collection
  (from the original idea).
- **R16. TOTP codes were treated like any other field.** With `auto`, an agent could get a TOTP code
  with no approval at all. Fix: `totp` is always ask, and getting both factors of one login is
  flagged.
- **R17. Docker access is root access.** In Docker mode, an agent that can run `docker exec` owns
  the broker. Fix: documented requirement, `doctor` warning.
- **R18. Tailscale down.** If Tailscale stops, nothing can be approved. Fix: fail closed (408),
  preflight on start, re-check every 30 s, audit lines.
- **R8. ntfy and iOS.** Self-hosted ntfy reaches iOS only through ntfy.sh's upstream relay. The
  "refuse ntfy.sh" rule must not block that setup. Also, keep the item name out of the push text.

### Minor

- **R9. Restart and lost replies.** After a restart, the agent's next `wait` gets 404, which must be
  final. If the 200 reply is lost in transit, the secret is gone and the agent needs a new approval.
  This is accepted and documented.
- **R10. Secret in the agent transcript.** `broker-get ITEM FIELD` prints the value, so it goes into
  the agent's context and to its model provider. `--env VAR -- CMD` avoids that.
- **R11. "Maximum 5 pending" was not scoped.** Now: per agent.
- **R12. Where the master password is typed.** `broker start` in a terminal that the agent can see
  (shared tmux or herdr pane) leaks it. Use the broker's own TTY or `systemd-ask-password`.
- **R13. Stale vault.** Without `bw sync`, new or changed items are not found.
- **R14. No audit at all.** "No database" does not need to mean no log. A JSON line per event to
  journald costs almost nothing.

### Accepted risks

- Root on the broker host can read everything.
- After `--env` release, any process of the agent's user can read the child's environment while it
  runs.
- If you approve without reading the page, the broker cannot help.
- A stolen, unlocked phone plus the password approves anything. The password is the defence.

## Part 3: Decisions

| # | Question | Decision |
|---|---|---|
| 1 | Tailscale | Required. The broker checks that tailscaled exists and is connected, and refuses to start otherwise (§13). No `tailscale serve`. |
| 2 | `auto` items | Kept, from the broker config by item id only; never for `totp` (§5). |
| 3 | Phone | iPhone, with a self-hosted ntfy domain and the ntfy.sh upstream for Apple push (§6). |
| 4 | Same machine as the agent? | Either. App mode or Docker mode; local or remote agents (§15). |
| 5 | Vault server | Self-hosted Vaultwarden / Bitwarden or Bitwarden cloud, both supported (§7). |

No open questions block milestone 1.
