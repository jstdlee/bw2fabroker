# bw2fabroker: development plan

Status: draft v2 (v1 plan, then the review in [Part 2](#part-2-review-what-v1-missed), with its fixes merged back into Part 1).
Date: 2026-11-07

## Part 1: The plan

### 1. Problem

Coding agents and scripts (Claude Code, CI-like local jobs, cron tasks) need secrets that live in a
password manager: API keys, database passwords, SSH passphrases. Today there are two bad options:

- **Unlock the vault for the agent.** Export `BW_SESSION`, or run `op signin`. The agent and every
  child process can now read every item in the vault, silently, until the session ends.
- **Copy secrets into `.env` files.** The secrets leave the vault, never rotate, and end up in logs,
  shell history, and commits.

bw2fabroker is a local **access broker**. It is the only process that holds an unlocked vault. A client
asks it for one item. A human approves that request **on a second factor** (phone or security key).
Then the broker releases only that value, for a limited time, and writes the event to an audit log.

### 2. Goals and non-goals

Goals:

1. Per-request human approval on a factor that the requesting process cannot reach.
2. Least privilege: one item (or one field) per grant. No list or search of the vault by clients.
3. Short-lived grants with a TTL and a use count.
4. Policy file: auto-allow, require approval, or deny, per item/folder/collection and per client.
5. Append-only audit log of each request, decision, and release.
6. Backends: Bitwarden (`bw` CLI) first, 1Password (`op` CLI) second, behind one interface.
7. Drop-in use: `bw2fa get <ref>`, `bw2fa run -- <cmd>` (env injection), `bw2fa inject` (template).

Non-goals (v1):

- Protection against root or a compromised kernel on the same host.
- Write access to the vault (create, edit, delete items). Read only.
- A multi-user or networked server. One human, one machine, local socket only.
- Replacing Bitwarden Secrets Manager or 1Password service accounts for production workloads.

### 3. Threat model

| Actor | Can do | Must not be able to do |
|---|---|---|
| Agent / client process (same login user) | Ask for an item by reference; run commands | Read the vault, the broker's memory, its data dir, or the approval channel; approve its own request |
| Prompt-injected agent | Ask for items it should not need; ask many times; craft misleading reasons | Get a value without a human seeing the **real** item name and requester |
| Network attacker | See approval traffic on the relay | Forge or replay an approval; learn secret values (values never leave the host) |
| Lost/stolen phone | Approve requests | Do so without the phone unlock (passkey user verification) |
| Root on host | Everything | Out of scope; documented |

The key consequence: **the broker must not run as the same OS user as the agent.** A same-uid process
can `ptrace` the broker, read `/proc/<pid>/environ` and memory, and read its files. See §5.

### 4. Architecture

```
 client (agent uid)                 broker daemon (bw2fa uid)                 human
 ─────────────────                  ─────────────────────────                 ─────
 bw2fa get / run / inject
        │  Unix socket (0660, group bw2fa-clients)
        │  peer creds: uid, pid, exe, cmdline, cwd, parent chain
        ▼
   ┌────────────┐   ┌─────────┐   ┌───────────────┐   push / link    ┌──────────────┐
   │ request    │──▶│ policy  │──▶│ approval      │ ───────────────▶ │ phone:       │
   │ handler    │   │ engine  │   │ coordinator   │ ◀─────────────── │ passkey sign │
   └────────────┘   └─────────┘   └───────────────┘  signed decision │ or TOTP      │
        │                                 │                          └──────────────┘
        ▼                                 ▼
   ┌────────────┐   ┌─────────────────────────┐   ┌───────────┐
   │ grant cache│   │ backend: bw serve / op  │   │ audit log │
   │ (TTL, uses)│   │ (vault session in RAM)  │   │ (hash     │
   └────────────┘   └─────────────────────────┘   │  chained) │
                                                   └───────────┘
```

Components:

- **Daemon `bw2fad`** (Go, single static binary). Runs as a dedicated user `bw2fa` under systemd
  (Linux) or launchd (macOS). Hardening: `PR_SET_DUMPABLE=0`, `mlockall`, no core dumps,
  `NoNewPrivileges`, `ProtectHome`, private `/tmp`.
- **Client `bw2fa`** (same binary, different argv[0]/subcommand). Talks JSON over the Unix socket.
- **Backend interface**:
  ```go
  type Backend interface {
      Unlock(ctx context.Context, secret []byte) error
      Lock(ctx context.Context) error
      Status(ctx context.Context) (State, error)
      Resolve(ctx context.Context, ref Ref) (ItemMeta, error) // name→id, no value
      Read(ctx context.Context, ref Ref) (Value, error)       // one field
      Sync(ctx context.Context) error
  }
  ```
  - **Bitwarden**: the daemon runs `bw serve --hostname 127.0.0.1 --port <random>` as a child process
    in its own network namespace or bound so that only the `bw2fa` user can reach it (see §5.3).
    It does not use one `bw get` per request: each `bw` start takes about 1 s and puts
    `BW_SESSION` in a child's environment.
  - **1Password**: `op` with the desktop-app integration is tied to a GUI session and the agent's
    user, so it does not fit. Use a **1Password service account** (`OP_SERVICE_ACCOUNT_TOKEN`) scoped
    to an "agents" vault, or a 1Password Connect server. The broker adds the human approval that
    service accounts lack.
- **Approval coordinator**: sends the request to one or more approvers and waits for the first valid
  decision, with a timeout (default 120 s, then deny).
- **Policy engine**: TOML file, owned by `bw2fa`, not writable by clients.
- **Audit log**: JSON Lines, each line holds the SHA-256 of the previous line. Values are never logged.

### 5. Key decisions

#### 5.1 Secret references

`bw2fa://<backend>/<vault-or-collection>/<item>/<field>`, for example
`bw2fa://bw/Personal/openai/api_key` or `bw2fa://op/agents/Postgres prod/password`.

- Item lookup by name must be **unique**. If two items match, the request fails and asks for the id.
  This stops an attacker who can add a shared item called `openai` from receiving the grant.
- The approval prompt always shows the resolved **item id, full name, and folder**, not the string
  the client sent.

#### 5.2 Approval channels (in priority order)

1. **Passkey approval page (default).** The broker sends a push (ntfy.sh, self-hosted ntfy, or
   Pushover) that holds only a request id and a short URL. The phone opens the approval page,
   which shows the request details. The human approves with a WebAuthn assertion. The challenge
   is the SHA-256 of the canonical request (requester, item id, field, TTL, nonce). The broker
   checks the signature with the public key that was registered at enrolment.
   - Where does the page live? Options: (a) the broker serves it on the LAN over HTTPS with a
     certificate pinned at enrolment; (b) a small relay (Cloudflare Worker + Durable Object) that
     only forwards the signed request and the signed answer. The relay sees item names unless the
     request is encrypted to a key held on the phone (see §5.4). v1 ships (b) with an encrypted
     payload; (a) is the offline fallback.
2. **TOTP on a broker-owned prompt.** The human types the 6-digit code into a prompt that the
   *broker* draws (a pinentry-style GUI or `/dev/tty` of a separate terminal), **never** into the
   agent's terminal. Enrolment stores the TOTP seed in the broker data dir. Used when the phone has
   no network. Weaker: a code proves presence, not what was approved.
3. **Hardware key touch (FIDO2 / YubiKey on the host)** via `libfido2`: the human touches the key
   and the request is shown on the broker's own prompt. Good for desktops.

Not supported: approve by replying "yes" in a chat, by e-mail link without a signature, or by a
code that the agent's terminal could see.

#### 5.3 Vault unlock

- The master password is entered **once per boot** through the broker's own prompt
  (`bw2fa unlock` opens a pinentry owned by the `bw2fa` user), or comes from the OS keyring of the
  `bw2fa` user (opt-in, documented as weaker).
- For Bitwarden, log in with the API key (`BW_CLIENTID` / `BW_CLIENTSECRET`). This avoids the
  account's own 2FA at each login. Unlock still needs the master password.
- `bw serve` has no authentication. Anything that can reach its port can read the whole vault.
  Bind it only where the agent user cannot connect: a private network namespace
  (`unshare -n` / systemd `PrivateNetwork=yes` with the daemon talking to it in the same
  namespace). macOS has no network namespaces, and any local user can reach a `localhost` port,
  so on macOS the broker does **not** run `bw serve`. It runs `bw get item <id>` per request as
  the `bw2fa` user, with `BW_SESSION` in that child's environment (other users cannot read it).
  This costs about 1 s per request, but each request needs a human approval anyway.
  **This is a release blocker on every platform.**
- Auto-lock after N minutes with no grants (default 60) and on screen lock / suspend (logind /
  `NSWorkspace` notifications).

#### 5.4 Confidentiality of the request on the relay

The phone app or PWA generates an X25519 key at enrolment. The broker encrypts each request body
(item name, requester, reason) to it. The relay sees only: request id, timestamps, ciphertext. The
signed answer binds the request hash, so the relay cannot change what was approved.

#### 5.5 Release modes

| Mode | What the client gets | Notes |
|---|---|---|
| `get` | value on stdout | Simple; value can end up in agent context/logs. Warn. |
| `run -- cmd` | value in the child's env only; the client process never prints it | Preferred for agents. Still visible in `/proc/<child>/environ` to the same uid. |
| `inject -i tpl -o file` | file written 0600 | For config files. Optional delete after N s. |
| `ssh-agent` (v2) | signing only, key never released | Best for SSH keys. |

**Output masking**: in `run` mode, the client replaces released values in the child's
stdout/stderr with `****` (exact and base64 forms), so that values do not flow back into the
agent's context.

#### 5.6 Policy file (example)

```toml
default = "approve"          # approve | allow | deny
grant_ttl = "15m"
max_uses = 1

[[rule]]
match = { backend = "bw", folder = "agents/dev" }
clients = ["claude", "node", "python3"]   # matched on resolved exe path hash, not argv[0]
action = "allow"
grant_ttl = "8h"
max_uses = 100

[[rule]]
match = { folder = "banking" }
action = "deny"

[[rule]]
match = { item_id = "6f1c…" }
action = "approve"
approvers = 2               # m-of-n: two different enrolled devices
```

Rate limit for each client: default 10 requests per 10 minutes. After 3 denials in a row, refuse new
requests from that client tree for 15 minutes and send one "flood" alert. Without this, an agent
can wear the human down with many prompts ("approval fatigue").

### 6. Milestones

| # | Scope | Exit criteria |
|---|---|---|
| M0 | Spike: `bw serve` in a private netns; Go client to `/object/item/{id}`; WebAuthn signing on a phone through a static page | Spike notes in `docs/spikes/`; latency measured |
| M1 | Daemon, socket, peer creds, Bitwarden backend, TOTP approval on a broker prompt, `get`/`run`, audit log, policy allow/deny/approve | E2E test on Linux: agent user gets one item after TOTP; same-uid attack tests (§8) fail to read vault |
| M2 | Passkey approval: enrolment, relay (Worker), encrypted payload, push via ntfy, m-of-n | Approve from iPhone and Android; replay and tamper tests pass |
| M3 | 1Password backend (service account), `inject`, output masking, rate limit, auto-lock | Same E2E suite passes for both backends |
| M4 | macOS (launchd, separate user, per-request `bw get` backend), packaging (Homebrew, .deb), `bw2fa doctor` | Install-to-first-approval in under 10 minutes on a clean machine |
| M5 | Hardening and review: fuzz the socket protocol, external review, threat-model update | No open high findings |
| Later | `ssh-agent` mode, MCP server front end for agents, Windows (named pipe, separate account), Bitwarden Secrets Manager backend | — |

### 7. Repository layout

```
cmd/bw2fa/            client + daemon entry (subcommands)
internal/broker/      request handling, grants
internal/policy/
internal/approval/    totp, webauthn, fido2, relay client
internal/backend/bw/  bw serve supervisor + HTTP client
internal/backend/op/
internal/audit/
internal/peer/        SO_PEERCRED / LOCAL_PEERPID, process tree
relay/                Cloudflare Worker (TypeScript)
approve-pwa/          phone approval page (static, WebAuthn)
deploy/               systemd units, launchd plist, sysusers.d
docs/                 this plan, threat model, ADRs, spikes
test/e2e/             multi-user test harness (containers)
```

### 8. Test plan

- **Unit**: policy matching, grant TTL/uses, canonical request hashing, audit chain checks.
- **Protocol fuzzing** of the socket JSON (`go test -fuzz`).
- **Same-uid attack suite** (run as the agent user, each must fail):
  read the broker data dir; `ptrace`/`/proc/<pid>/mem` of the daemon and of `bw serve`;
  connect to the `bw serve` port; read `BW_SESSION` from any environ; replay an old approval;
  approve with a signature over a different request; substitute an item with the same name.
- **E2E** in containers with two users and a fake approver (software WebAuthn authenticator).
- **Backend contract tests** against a local Vaultwarden for Bitwarden, and a recorded fixture for
  `op`.
- **Manual**: real iPhone and Android approvals before each release.

---

## Part 2: Review (what v1 missed)

The first draft was a "daemon + TOTP + `bw get`" design. A hostile review found these gaps. Each one
is now fixed in Part 1, or is an open question in Part 3.

### Blockers (the design was insecure without them)

1. **Same-uid broker = no boundary.** v1 ran the daemon as the login user. Any agent process could
   `ptrace` it or read `BW_SESSION` from `/proc`. → Dedicated `bw2fa` user, `PR_SET_DUMPABLE=0`,
   attack suite (§3, §4, §8).
2. **`bw serve` has no auth.** v1 used it on `localhost`. Every local process could read the full
   vault, with no approval at all. → Private network namespace on Linux, per-request `bw get` on macOS; release blocker (§5.3).
3. **2FA code typed where the agent can see it.** v1 asked for the TOTP code in the agent's
   terminal. The agent can read the screen, or trick the human into typing the code into its own
   prompt. → Broker-owned prompt only; passkey is the default (§5.2).
4. **Approval did not bind to the request.** A TOTP code says "a human is here", not "the human
   approved item X for process Y". → WebAuthn challenge = hash of the canonical request (§5.2).
5. **Name-based lookup is spoofable.** `bw get item openai` returns the first match. A shared
   collection member could plant a look-alike. → Unique resolution, id shown in the prompt (§5.1).

### Major gaps

6. **Approval fatigue / prompt flooding.** No rate limit. → Rate limits, denial lockout (§5.6).
7. **Released value leaks back into agent context.** `get` prints to stdout, which the agent
   stores in its transcript (and may send to its model provider). → `run` mode as default plus
   output masking; documented warning (§5.5).
8. **Requester identity was the client's own claim.** → Peer credentials from the kernel, exe path
   and hash, parent chain shown to the approver (§4).
9. **1Password `op` desktop integration does not work for a separate daemon user.** → Service
   account / Connect (§4).
10. **Relay sees secret names and requester details.** → Encrypt payload to phone key (§5.4).
11. **No lock policy.** The vault stayed unlocked forever. → Idle, screen lock, and suspend lock (§5.3).
12. **No enrolment / recovery story.** What if the phone is lost? → See Part 3, Q3; v1 adds
    `bw2fa enroll`, `bw2fa devices revoke`, and a printed recovery code that only resets
    approvers and needs the master password.

### Minor gaps

13. Audit log could be edited by the agent user. → Owned by `bw2fa`, hash-chained; optional
    forward to syslog/journald.
14. Bitwarden data goes stale: v1 never ran `bw sync`. → Sync on unlock and every 15 min, and on
    "item not found" once.
15. Clock skew breaks TOTP and grant TTL checks. → Use monotonic time for TTL; TOTP window ±1 step.
16. Secrets in Go strings cannot be wiped. → `[]byte` with explicit zeroing in the hot path; no
    claim of perfect memory hygiene in the docs.
17. No `doctor` command: setup with a second user, groups, and namespaces is easy to get wrong.
    → `bw2fa doctor` checks each boundary from §8 and prints a fix.
18. Licence and naming: the project calls `bw` and `op`; no Bitwarden or 1Password code or
    branding is included. Pick a licence before first release (Part 3, Q6).

### Accepted risks (stated, not fixed)

- Root on the host can read everything.
- After `run` releases a value, any same-uid process can read the child's environment while it runs.
  The grant limits which value and for how long; it cannot stop this.
- A human who approves without reading the prompt defeats the system. The prompt design (item id,
  folder, requester exe, reason, "first time this client asks for this item" marker) is the only
  defence.

---

## Part 3: Open questions for the owner

1. **Platforms for v1**: Linux only, or Linux + macOS? (macOS needs the separate-user setup and a
   per-request `bw get` backend; it adds about one milestone.)
2. **Approval device**: iPhone, Android, or both? A PWA with passkeys covers both, but iOS web push
   needs the PWA installed to the home screen. A native iOS app (shared code with Heeler?) gives
   better push but costs more.
3. **Lost-phone recovery**: recovery code (proposed), a second enrolled device, or both required?
4. **Relay hosting**: Cloudflare Worker on your account (proposed), self-hosted ntfy, or LAN-only?
5. **Primary clients**: Claude Code only (then an MCP server front end moves up to M3), or any CLI?
6. **Licence**: MIT, Apache-2.0, or private?
7. **Bitwarden server**: bitwarden.com, EU cloud, or self-hosted Vaultwarden? (Affects tests and
   API-key login.)
