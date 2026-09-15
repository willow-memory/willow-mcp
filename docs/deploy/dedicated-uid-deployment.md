# Dedicated low-privilege uid deployment (B-32, issue #231)

> **Status:** this is the deployment runbook issue #231 asked for. It is
> **operator topology, not a willow-mcp code change** — same framing the issue
> opens with. The tooling it walks through (`harden-trust-root`,
> `repair-runtime-perms`, `WILLOW_MCP_STRICT_TRUST_ROOT`, the `uid_separation`
> diagnostic) already ships; what was missing was the concrete "do this, in
> this order, on this kind of host" walkthrough tying them together, plus a
> way to *verify* the separation landed rather than infer it from permission
> bits alone.
>
> **This has not been exercised end-to-end on a real multi-uid host from
> inside this repo's own dev/CI environment** — every sandbox this code has
> been developed and tested in runs as a single uid (often root), which is
> precisely the condition B-32 describes as *no boundary at all*. The
> `uid_separation` check and its tests simulate a second identity by
> monkeypatching file ownership; nothing here substitutes for an operator
> actually running these steps on a box with a second unix account. Treat
> this document as reviewed and internally consistent, not as validated in
> production.

## The three roles

| Role | Typical account | What it may touch |
|---|---|---|
| **agent** | your login uid, or (serve mode) no local account at all | Nothing under `$WILLOW_HOME` directly. It talks to the MCP server over stdio or HTTP and gets back whatever the gate allows. |
| **runtime** | the account the MCP **server process** itself runs as | Reads manifests/leases (world-readable by design — the gate is an unprivileged reader); read/writes `store/`, `dispatch/`, and other working state (`repair-runtime-perms` scopes this). Must **not** be able to write `config/`/`mcp_apps/` and must **not** be able to read the egress private key. |
| **trust owner** (`willow-operator` by convention) | a dedicated, login-disabled system account | The only identity that may write `config/`, `mcp_apps/` (manifests, leases), and read the egress private key. Reached only via an interactive operator terminal (`sudo -u willow-operator willow-mcp grant-net …`) — never via any MCP tool call, by the same design as `confirm-binding` (`docs/design/pgp-and-persona.md`). |

Two of these three roles can legitimately be the **same** account, and one
deployment shape does exactly that:

## Shape A — stdio, agent and runtime share a uid (the common case today)

This is what `docs/OPERATOR-ONBOARD.md`'s existing "Trust-root hardening"
section already documents, and what most installs run: an IDE (Cursor,
Claude Code) spawns `willow-mcp` as a stdio subprocess under *your own login
uid*. The **agent and runtime roles are necessarily the same process** here —
there is no OS boundary between "the thing driving tool calls" and "the thing
enforcing the gate", because they are the same binary invocation. This is
the residual README.md names outright: *"the agent can write the very files
that authorize its egress."*

What hardening buys you in this shape is narrower but real: it stops that
shared-uid process from being able to **write** `config/`/`mcp_apps/` or
**read** the egress key, by moving those specific paths to a third account
(`willow-operator`) that the agent/runtime process never runs as.

```bash
sudo useradd -r -s /usr/sbin/nologin willow-operator   # once per machine
willow-mcp harden-trust-root --project-root ~/github/willow
willow-mcp repair-runtime-perms          # restore store/dispatch write access to you
```

Reload the IDE. Grants and consent now require the operator identity:

```bash
sudo -u willow-operator willow-mcp grant-net hanuman --ttl 30m --reason "push branch"
sudo -u willow-operator willow-mcp consent set internet true
```

PGP-enforced manifest changes are deliberately different: run
`allow-permission` / `deny-permission` as the human whose gpg-agent holds the
configured key, **not** inside `sudo -u willow-operator`:

```bash
export WILLOW_PGP_FINGERPRINT=<40-hex operator fingerprint>
willow-mcp allow-permission hanuman task_queue
willow-mcp deny-permission hanuman task_queue
```

The command builds, signs, and verifies the candidate before touching
`mcp_apps/`, then asks sudo to run only a narrow publication helper as the
directory owner. It resolves the Python executable before sudo, so sudo's
restricted `PATH` is irrelevant; the helper receives the expected fingerprint
and an exported public key explicitly, verifies in an isolated temporary GPG
home, and never needs the human's `HOME`, gpg-agent socket, or private key.
Gate readers and the publisher lock the app directory while the manifest and
detached signature siblings change, so they are observed as one generation.

If `WILLOW_PGP_FINGERPRINT` is absent or malformed while the existing manifest
has a signature, the command refuses before mutation. If signing, verification,
sudo, or either publication rename fails, the previous manifest and signature
bytes remain in place. Do not work around that refusal by unsetting enforcement
or by running the whole command as the trust-owner uid.

**Verify, as your own (agent/runtime) login uid — not as `willow-operator`:**

```bash
willow-mcp doctor --app-id willow
```

Look for two independent lines:

```
uid separation: OK — trust root is owned by a different account than this process (you, uid 1000)
```

and, elsewhere in the same output, `trust_root` no longer listed under
`forgeable`. Both should agree. If you ran `doctor` as `sudo -u
willow-operator` instead, expect `uid separation: NOT separated` — that
readout is correct, not a bug: you *are* the trust owner in that shell, so
of course nothing is separated from you. The check that matters is what your
own everyday account sees.

**What this shape does *not* give you:** the agent/runtime process can still
*read* everything a normal MCP server needs to read (manifests, leases,
store — all working as designed), and nothing stops that same account from
running arbitrary other commands on the box outside willow-mcp entirely. It
closes the specific "self-authorize egress" and "read the signing key" holes
B-32/#182 named; it does not turn your login account into a sandbox.

## Shape B — serve mode, agent has no local account at all

The stronger posture, and the one that actually satisfies #231's literal
"agent uid: no read on `egress/private.pem`, no write on `config/`/`mcp_apps/`"
bullets without relying on file permissions alone: the MCP server runs as a
**persistent service** under a dedicated account, and the agent is a
**remote OAuth-authenticated HTTP client with no shell or filesystem access
to the host at all**. See [`HTTP serve mode (OAuth)`](../../README.md#http-serve-mode-oauth)
for how identity binding works once a caller is authenticated — this section
covers *who runs the server*, which the README's own `scripts/willow-serve`
walkthrough leaves as "your own account" (a `systemd --user` unit, meant for
local dev convenience, not uid separation).

### Two ways to assign the runtime account

**B1 — runtime = `willow-operator`.** Simplest: one dedicated account holds
both the trust root and runs the server. Matches the issue's literal
phrasing ("runtime uid — willow-operator or equivalent"). The trade-off:
because `WILLOW_MCP_STRICT_TRUST_ROOT`'s check (`self_writable_trust_paths`)
asks *"could the process asking this question also have written the
policy"*, and that process is now `willow-operator` itself, strict mode
**will always report the trust root as self-writable and deny egress** —
correctly, since the account running the gate check genuinely can rewrite
its own policy. Leave `WILLOW_MCP_STRICT_TRUST_ROOT` **off** for this
process; the separation that is actually protecting you here is that the
agent has no account on the box at all, not the file-permission check.

**B2 — runtime = a fourth, separate account (`willow-runtime`), distinct from
`willow-operator`.** More moving parts, but lets `WILLOW_MCP_STRICT_TRUST_ROOT`
mean what it says even in serve mode: `willow-runtime` can read manifests/
leases (world-readable) and read/write `store/`/`dispatch/`, but cannot write
`config/`/`mcp_apps/` or read the egress key — those stay `willow-operator`'s
alone. Turning strict mode on for the `willow-runtime` process now correctly
reports `hardened: true`, because the account asking is genuinely not the
account that could rewrite the policy.

Pick B1 for the simplest deployment that matches the issue's wording; pick B2
if you want the diagnostic's `strict_trust_root`/`hardened` fields to carry
real meaning under serve mode too, not just under Shape A.

### Runbook (B2 shown; drop the `willow-runtime` account and point
`ExecStart`'s `User=` at `willow-operator` for B1)

Account creation is scripted in [`deploy/provision-uids.sh`](../../deploy/provision-uids.sh)
(idempotent; `--shape b1` for the single-account variant) — it does the two
`useradd`s and the `WILLOW_HOME` `chown` below and nothing else, then prints the
`harden-trust-root`/`repair-runtime-perms` commands to run next:

```bash
sudo deploy/provision-uids.sh        # creates willow-operator + willow-runtime
```

or, equivalently, by hand:

```bash
sudo useradd -r -s /usr/sbin/nologin willow-operator
sudo useradd -r -s /usr/sbin/nologin willow-runtime
sudo mkdir -p /var/lib/willow-mcp
sudo chown willow-runtime:willow-runtime /var/lib/willow-mcp   # WILLOW_HOME

# Populate WILLOW_HOME as willow-runtime first (keys, manifests, layout)…
sudo -u willow-runtime env WILLOW_HOME=/var/lib/willow-mcp willow-mcp-init
sudo -u willow-runtime env WILLOW_HOME=/var/lib/willow-mcp willow-mcp setup-egress

# …then move confirm authority to willow-operator and restore willow-runtime's
# own working paths:
sudo -u willow-operator env WILLOW_HOME=/var/lib/willow-mcp \
    willow-mcp harden-trust-root --runtime-user willow-runtime
sudo -u willow-operator env WILLOW_HOME=/var/lib/willow-mcp \
    willow-mcp repair-runtime-perms --runtime-user willow-runtime
```

System-level (not `--user`) systemd unit — ship the template
[`deploy/willow-mcp-serve-system.service.template`](../../deploy/willow-mcp-serve-system.service.template),
which is the block below with `@PLACEHOLDERS@`; fill them in and install to
`/etc/systemd/system/`. (The `--user` templates in `deploy/` cannot express a
uid switch — that is exactly why this system-level one exists.)

```ini
# /etc/systemd/system/willow-mcp-serve.service
[Unit]
Description=willow-mcp OAuth HTTP serve mode (dedicated runtime uid)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=willow-runtime
Group=willow-runtime
WorkingDirectory=/opt/willow-mcp
Environment=WILLOW_HOME=/var/lib/willow-mcp
Environment=WILLOW_MCP_STRICT_TRUST_ROOT=1
ExecStart=/opt/willow-mcp/.venv/bin/python3 -m willow_mcp --serve --port 8768 --host 127.0.0.1
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/willow-mcp/store /var/lib/willow-mcp/dispatch

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now willow-mcp-serve
```

The **agent's** machine/account only ever holds an HTTP URL and an OAuth
credential in its own `.mcp.json` — no `$WILLOW_HOME`, no local `willow-mcp`
install is required on the agent side at all. That is the property #231
asks for stated as strongly as this repo can state it: not "the agent's
read/write bits are restricted" but "the agent has nothing on this host to
read or write in the first place."

**Verify**, from the `willow-runtime` account (or by calling
`diagnostic_summary` through the running serve endpoint as a bound identity):

```bash
sudo -u willow-runtime env WILLOW_HOME=/var/lib/willow-mcp willow-mcp doctor
```

Expect `uid separation: OK`, and — for B2 only — `strict_trust_root: true`
with `hardened: true` in the `net_lease`/`trust_root` sections. For B1,
expect `uid separation: NOT separated` when checked *as `willow-operator`*
(correct — you are the trust owner and the runtime account at once) and rely
on the network/account boundary, not the file-permission check, as your
actual control.

## Shape C — container image

The repo's `Dockerfile` runs the server as a dedicated non-login `willow`
system user (never root) with its own writable `HOME` — the minimum a
single-image build can enforce on its own. That closes the "container defaults
to root" hole, but note it is only the **agent/runtime** role: a single
container running one process cannot host a *separate* trust-owner uid, so it
does not by itself satisfy #231's operator/agent split. For the real
separation in a containerized deployment, run the trust owner outside the
container (own `config/`/`mcp_apps/` on a mounted volume as a host
`willow-operator` uid, mount them read-only to the container) or split the
roles across two containers/uids sharing a pre-hardened volume — the same B1
vs B2 choice as above, expressed with `user:` in your compose/orchestrator
instead of systemd `User=`. `WILLOW_MCP_STRICT_TRUST_ROOT` stays off in the
image's own shipped env for the same default-off reason as everywhere else.

## How `harden-trust-root` and `WILLOW_MCP_STRICT_TRUST_ROOT` compose

- `harden-trust-root` is an **idempotent filesystem operation**: it chowns
  `config/`, `mcp_apps/`, and the egress key directory to the trust owner,
  restores the runtime account's write access to `store/`/`dispatch/`/etc.,
  and (optionally, via `--project-root`) writes
  `WILLOW_MCP_STRICT_TRUST_ROOT=1` into your `.mcp.json`'s `env` block. It
  does **not** by itself change who runs the MCP server process — that is
  the deployment-shape decision above, made by you (spawn stdio as your own
  login, or install a systemd unit under a chosen `User=`).
- `WILLOW_MCP_STRICT_TRUST_ROOT` is read **once, at process start**, by
  whichever process is asking (see `lease.strict_trust_root()`). It is not a
  live toggle and not meaningful in the abstract — it is only ever asking
  "can *this specific running process* write the trust root", so where you
  set it (stdio env, or a specific systemd unit's `Environment=` line)
  determines what it actually enforces. Setting it globally on a host running
  multiple willow-mcp processes as different accounts enforces a different
  thing for each of them, which is by design (see B1 vs B2 above).
- Setting it **before** any separation exists denies egress on every call —
  this is why it ships off by default, and this document does not change
  that default. Nothing in this PR flips `WILLOW_MCP_STRICT_TRUST_ROOT` on
  anywhere in the repo's own shipped config.

## Verifying the split without guessing

Two independent signals, deliberately kept separate:

1. **`checks.net_lease.self_writable` / `checks.trust_root` (existing,
   B-32/B-38/B-44).** The functional truth: could *this process* actually
   write the keys that authorize egress, right now. This is what
   `strict_trust_root` enforces against, and what the verdict/`problems`
   list is built on.
2. **`checks.uid_separation` (new, #231).** The plain-ownership legibility
   check: does the account that owns the trust root on disk differ from the
   account running this process. Purely informational — **never folded into
   `problems` or the verdict** (a `False` here is every unhardened install's
   honest resting state today; making it a `warn` would degrade every
   existing single-uid install the day this shipped, the same mistake B-18
   was about). It exists so an operator following this runbook can answer
   "did the chown actually land on a different account" without inferring
   it from permission-bit output.

Both come back from `diagnostic_summary()` and from `willow-mcp doctor`'s
human-readable output. They can diverge — a path can be owned by another
account and still be group/world-writable (ownership alone proves nothing;
`apply_trust_root_hardening`'s mode bits are the other half), and a path can
be nominally self-owned while still not self-writable under an unusual
ACL — so check both, and trust (1) for anything security-relevant.

## Verification checklist — raw OS probes (not just the diagnostic)

`willow-mcp doctor`'s `uid separation:`/`hardened` readout (above) asks
willow-mcp's own code to report on itself. The commands below ask the kernel
instead — `sudo -u <account>` as the process being tested, touching the
actual paths, independent of anything this repo's own tooling claims. Run
each of the three as the **agent/runtime account under test** (your login
uid in Shape A; `willow-runtime` in Shape B2 — see the caveat below for
Shape A/B1, where some of these are *expected* to succeed):

```bash
# Adjust to your install:
WILLOW_HOME=/var/lib/willow-mcp
AGENT_UID=willow-runtime                       # or your own login user (Shape A)
EGRESS_DIR="${WILLOW_MCP_EGRESS_CONFIG_DIR:-$HOME/.config/willow-mcp/egress}"

# 1. Cannot read the egress private key (B-44/#182)
sudo -u "$AGENT_UID" cat "$EGRESS_DIR/private.pem"
# expect: cat: …/private.pem: Permission denied

# 2. Cannot write mcp_apps/ — manifests, leases, "task_net" self-grants (B-32)
sudo -u "$AGENT_UID" sh -c "echo x > '$WILLOW_HOME/mcp_apps/.probe'"
# expect: sh: …/.probe: Permission denied

# 3. Cannot write config/ — settings.global.json, consent.json
sudo -u "$AGENT_UID" sh -c "echo x > '$WILLOW_HOME/config/.probe'"
# expect: sh: …/.probe: Permission denied

# 4. Cannot read a store .db file, once `repair-runtime-perms` has applied
#    #232's owner-only 0600 (glob covers every per-collection store.db):
sudo -u "$AGENT_UID" sh -c "cat '$WILLOW_HOME'/store/*/store.db > /dev/null"
# expect: cat: …/store.db: Permission denied
```

Each command should fail with `Permission denied` — a success (the file
opens or the write lands) means the split has not actually taken hold for
that account and path; re-run `harden-trust-root`/`repair-runtime-perms` and
check ownership with `stat` before trusting the diagnostic's summary.

**Shape A / B1 caveat:** probes 2 and 3 are the only ones that mean anything
in Shape A or B1. In both, the account under test **is** the runtime account
(Shape A: agent and runtime are literally the same process; B1: runtime IS
`willow-operator`), so probe 4 (store `.db`) is *expected to succeed* — that
account legitimately owns `store/` for normal operation — and probe 1 only
denies in Shape A (B1's account is `willow-operator`, which by definition
holds the egress key). Only Shape B2, with a real `willow-runtime` account
distinct from both `willow-operator` and the agent, makes all four probes
(1, 2, 3, and 4) meaningful in the way the checklist above implies. This
mirrors the exact same caveat the "Store `.db` files (#232)" section below
states for `store_db_exposure`/`checks.store_db_perms`.

## Revisiting strict mode's default-off posture

Not done here, and not proposed here. The issue asks this be revisited
*"once documented and verifiable"* — this document is the "documented" half.
"Verifiable" means an operator (or a CI job with a real second unix account,
which this repo's own test/dev sandboxes do not have) actually running
Shape A or B end-to-end and confirming `uid_separation.separated: true` and
`hardened: true` hold steady. Until that has happened on at least one real
deployment, changing the default would deny egress on every existing
single-uid install — exactly the outcome `strict_trust_root()`'s own
docstring says the off-default exists to avoid.

## Store `.db` files (#232)

The client-side hook (`hooks/pre_tool_use.py`'s `_OWNED_DB_FILE_RE`) blocks
Write/Edit and raw `sqlite3` against `store.db`/`vault.db`/`kart.db`/
`mcp_receipt.db` — but it is a tripwire in the agent's own harness, not an
OS control, and #232 said so explicitly: the acceptance test "proves the
hook fires, not that the OS refuses the write." A process that doesn't load
the hook skips it entirely.

`willow-mcp repair-runtime-perms` now closes the OS half, the same way it
already does for `vault.key`/`mcp_token.json` (B-46): every SOIL collection's
`store.db` (under `store_root()`), `kart.db`, and `mcp_receipt.db` get
owner-only `0700`/`0600` instead of the world-readable `0755`/`0644`
ordinary runtime state gets. `vault.db` was already covered (B-46).

```bash
willow-mcp repair-runtime-perms
willow-mcp doctor --app-id willow   # look for store_db_exposure: []
```

**This is the exact same shape of gap as the rest of this document, and the
exact same fix.** Tightening mode bits changes *nothing* while the agent and
the MCP server share a uid — the runtime user IS the agent uid in Shape A
above, so a `0600` file owned by "yourself" is exactly as readable as a
`0644` one was. It only becomes a real OS boundary once Shape B (or an
equivalent multi-uid Shape A, per #231) is actually deployed. `diagnostic_summary`'s
new `checks.store_db_perms` reports `exposure` (which files are still
group/world-readable) and `enforced` (bool) — like `checks.uid_separation`,
this is purely informational and never folded into `problems`/the verdict:
a fresh, unhardened single-uid install honestly reports `enforced: false`
and stays `verdict: ok`.

## Out of scope here

- Real end-to-end verification on a genuine multi-uid host, for both #231's
  uid separation and #232's store `.db` mode hardening above. Everything in
  `checks.uid_separation`/`checks.store_db_perms`'s test coverage simulates a
  second account via monkeypatched ownership or a real chmod verified from
  the same uid that set it; no automated test here creates a real second
  unix user, because the sandboxes this suite runs in do not have the
  privilege to do so.
