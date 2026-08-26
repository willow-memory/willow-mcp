# Operator onboard — willow-mcp
> **Scope (2026-07-22):** this is the appendix for operators who **already run a
> fleet** — key ceremony, net leases, IDE wiring against existing state. A new,
> standalone install starts from README.md's **Install** section instead
> (`pip install willow-mcp`, or `bash scripts/sandbox-bootstrap.sh` for a
> contributor sandbox).

One-time setup so network tasks work without OpenSSL, hand-edited `mcp.json`, or
knowing which `willow-mcp` binary is which.

## New install (copy/paste)

Use the **venv CLI** (`wmc` or `…/venvs/willow-mcp/bin/willow-mcp`). Do **not**
use bare `willow-mcp` on PATH if the legacy Willow 2.0 `sap_mcp.py` server is
installed — it does not have these commands.

```bash
pip install -e ~/github/willow-mcp
willow-mcp-init
willow-mcp onboard --project-root ~/github/willow --enable-internet --app-id willow
```

Reload the IDE window, then (from willow-2.0 fleet installs):

```bash
cd ~/github/willow-2.0 && ./willow.sh project sync willow   # product projects → willow-mcp templates (see docs/deploy/native-startup.md)
```

Check health:

```bash
willow-mcp doctor --app-id willow --project-root ~/github/willow
```

## Run a network task (one operator command)

```bash
willow-mcp run-net willow --task-file /path/to/script.sh --ttl 30m
willow-mcp worker --lane fast --once
```

`run-net` grants a lease (if needed), signs the exact task, and queues it.
Agents still cannot mint authority — only an interactive operator terminal can.

## What gets created

| Artifact | Location |
|----------|----------|
| Egress private key | `~/.config/willow-mcp/egress/private.pem` |
| Egress public key | `~/.config/willow-mcp/egress/public.pem` |
| Manifest | `~/.config/willow-mcp/egress/manifest.json` |
| MCP env | `WILLOW_MCP_EGRESS_PUBLIC_KEY` in `.cursor/mcp.json` (via onboard or project sync) |

Keys live **outside** `WILLOW_HOME` so Kart sandboxes cannot read the signing key.

## Troubleshooting

```bash
willow-mcp doctor --app-id willow
willow-mcp gates
willow-mcp net-status
```

If `doctor` reports missing egress keys: `willow-mcp setup-egress` (idempotent).

## Trust-root hardening (B-32, B-44)

> **Full deployment runbook:** the steps below are the minimum-viable version
> (agent and MCP server still share a uid; hardening narrows what that shared
> process can write/read). For the concrete 3-role split — agent / runtime /
> trust-owner uid, including a serve-mode deployment where the agent has no
> local filesystem access at all — see
> [`docs/deploy/dedicated-uid-deployment.md`](deploy/dedicated-uid-deployment.md)
> (issue #231).

When the agent and MCP server share your uid, the agent can forge egress authority
by editing its manifest or lease files — **or simply read the egress private key**
(B-44/issue #182): a `chmod 600` file owned by your own uid is not protected
from you. Close the host lane:

```bash
sudo useradd -r -s /usr/sbin/nologin willow-operator   # once per machine
willow-mcp harden-trust-root --project-root ~/github/willow
```

This chowns the manifest/lease roots **and** the egress key directory to
`willow-operator` — the key at owner-only `0600`, stricter than the
world-readable manifests/leases (which the gate still needs to read as an
unprivileged process; the signing key does not).

Reload the IDE. Issue grants, signed tasks, and consent as the trust owner:

```bash
sudo -u willow-operator willow-mcp grant-net hanuman --ttl 30m --reason "push branch"
sudo -u willow-operator willow-mcp sign-net-task hanuman --task-file /path/to/task.sh
sudo -u willow-operator willow-mcp consent set internet true
```

Dry-run first: `willow-mcp harden-trust-root --dry-run`

Verify: `willow-mcp doctor` should report the egress key as no longer
self-readable (`private_key_readable: false` in `net_lease`); as the agent's
own uid, `cat ~/.config/willow-mcp/egress/private.pem` should now fail with
`Permission denied`. `doctor`'s output also prints a `uid separation:` line
(`checks.uid_separation` in `diagnostic_summary`, issue #231) — the plain
"whose account owns this vs. whose account is asking" fact, checked
separately from (and never a substitute for) the writability check above.

If `doctor` reports the SOIL store is not writable after hardening, restore runtime
paths (store, dispatch, sessions, …) for the MCP server user:

```bash
willow-mcp repair-runtime-perms
```

This keeps `mcp_apps/` and `config/` owned by `willow-operator` while giving the
runtime user write access to `store/` and other MCP working directories.

## PGP-enforced manifests (B-45, issue #183)

`mcp_apps/` ownership above stops the agent from *writing* a manifest, but on
an install that hasn't hardened yet — or any process that reaches the file a
different way — an unsigned manifest is still honored as-is. Set
`WILLOW_PGP_FINGERPRINT` to close that gap outright: an unsigned, tampered,
or wrong-signer manifest gets denied exactly like a missing one.

```bash
willow-mcp sign-manifest hanuman
```

Interactive operator terminal only (same as `sign-net-task`/`sign-db-task` —
`gpg-agent` is unreachable inside Kart). Re-run after any manifest edit; a
changed manifest with a stale signature is denied too.

## Keyring identity + envelope-accrual (PR1-PR12, 2026-08-25/26)

The identity-in-session + envelope-accrual thread shipped a per-verifier
ed25519 keyring as the primary operator identity substrate (PGP stays as
legacy_key). What the operator does day-to-day:

### One-time keyring setup

```bash
willow-mcp keys add rita         # your operator handle (any name; matches WILLOW_OPERATOR_VERIFIER below)
willow-mcp keys status rita      # confirm the key is active
```

Then set the env in the MCP config so every SessionStart auto-signs:

```jsonc
// .cursor/mcp.json  (willow orchestrator seat)
{
  "willow": {
    "env": {
      "WILLOW_APP_ID": "willow",
      "WILLOW_HUMAN_ORCHESTRATOR": "1",
      "WILLOW_KEYRING": "on",
      "WILLOW_OPERATOR_VERIFIER": "rita"
    }
  }
}
```

With `WILLOW_OPERATOR_VERIFIER` set, the SessionStart hook (PR8) auto-signs
each new session: it writes the `_v2` sidecar + `.sig`, warms the
attribution cache, and prints an `auto_sign_note` into the boot context.
Your first `envelope_propose`/`ratify`/`reject` works without a second
terminal.

An **unknown or compromised verifier REFUSES `session_enter` outright**
(PR8 Commit A): a compromised key that continued unattested is exactly
the fail-quiet pattern the fleet forbids. Rotate with
`willow-mcp keys add rita --rotate` and reopen the session.

### The envelope-accrual loop in one flow

```bash
# 1. Open a session (auto-signed if WILLOW_OPERATOR_VERIFIER is set)
#    Otherwise: willow-mcp sign-session <session_id> --verifier rita

# 2. See the queue at seat-open (envelope_pending_read is on the orient block)
#    N proposals waiting: shown by session_enter's orientation block.

# 3. Do work. When a specialist hits an envelope wall, a proposal appears
#    in your queue automatically (auto-propose from _enveloped_verb_gate,
#    PR6, attributed to you via the dispatch packet, PR9).

# 4. Ratify from your operator terminal:
willow-mcp envelope pending             # list open proposals with precedents inline (PR10)
willow-mcp envelope ratify <proposal_id>
#    OR reject with a reopen condition:
willow-mcp envelope reject <proposal_id> --reason "too broad" --reopen-when "after loki audit"

# 5. Rejections accrue as precedents too (PR11), so the next similar
#    proposal shows you already said no with a reopen condition — the
#    ratify UX renders it as "you said no on 2026-08-10 because ...;
#    reopen when ..." rather than a blank slate.
```

### Diagnostics

```bash
willow-mcp envelope list                          # ratified envelopes
willow-mcp envelope pending                       # proposal queue (with precedents inline)
# via MCP tool: envelope_read_discards            # residue walk: proposals swallowed on error (PR8B)
willow-mcp sessions --unverifiable                # sessions whose sidecar exists but no longer verifies (PR4)
```

### Multi-machine attribution (unchanged)

The auto-sign path (`WILLOW_OPERATOR_VERIFIER`) is same-uid only. Cross-box
operators keep using `willow-mcp sign-session <session_id> --verifier rita`
manually — the CLI signs client-side against the operator's own key and
uploads only the sig + sidecar to the server.

### Federated MCP (PR12)

Willow's manifest now holds `federation_read` + `federation_call` +
`mcp_federation`, so the orchestrator can drive downstream MCP servers
directly. The gate is still layered — the runtime call needs
`consent.federation` (per-lease) alongside the manifest grant.

```bash
willow-mcp consent set federation true            # once; then per-lease consent still applies
```

See `docs/design/permissions-matrix.md` §4 for the full ratified
permission set, and `docs/design/envelope-accrual.md` for the mechanism
overview.
