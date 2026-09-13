---
name: consent
description: Operator egress consent and leases — the three-key network gate for Kart and integration_call
---

@markdownai v1.0

# /consent — Egress consent (operator)

Use when an agent asks for network access, or when you need to flip the fleet-wide
off switch. This is **not** guardian SAFE sign-off (that stays in the charter fleet
harness). This skill covers willow-mcp's **standing egress policy** only.

See also: `kart-tasks.md` (submit path), `session-start.md` (boot).

---

## The three keys (+ signed envelope for Kart)

| Key | Question | Where | Who sets it |
|-----|----------|-------|-------------|
| `task_net` | May this app ever request Kart egress? | manifest | operator |
| `integration_net` | May this app call `integration_call`? | manifest | operator |
| `web_net` | May this app use `willow_web_search` / `willow_web_fetch`? | manifest | operator |
| `consent.internet` | Is egress permitted *right now*? | `settings.global.json` | operator |
| **egress lease** | This app, until when? | `mcp_apps/_net_leases/<app>.json` | operator CLI only |
| **signed envelope** | This exact Kart task, scope, expiry? | `tasks.network_authorization` | `willow-mcp sign-net-task` |

**No MCP tool mints a lease or changes consent.** Agents may *request*; the operator
*confirms* at their own terminal (sudo invariant, FRANK `90e52ab7`). The PreToolUse
hook blocks self-grant attempts.

---

## Operator actions (CLI only)

### Fleet-wide off switch

Edit the canonical file (not the legacy mirror alone):

```json
// $WILLOW_HOME/config/settings.global.json
{
  "consent": {
    "internet": false,
    "cloud_llm": false
  }
}
```

`consent.internet: false` denies at **submit and execution** — no manifest edit required.
Consent is read **fail-closed**: missing, malformed, or string-typed values → denied.

### Time-boxed grant for one app

```bash
willow-mcp grant-net <app_id> --ttl 30m --reason "push release branch"
willow-mcp net-status          # what's live
willow-mcp revoke-net <app_id> # early revoke
```

Ceiling TTL is 3h. Default 30m. Lease must name the same `app_id` as its file.

### Kart task with network

1. Manifest holds `task_net` (operator added — never self-granted).
2. `consent.internet` is true.
3. Live lease for that `app_id`.
4. Operator signed envelope: `willow-mcp sign-net-task …`
5. Agent calls `task_submit(..., allow_net=True)` — **not** `# allow_net` in task text.

### Kart task with local Postgres (`allow_db`)

`allow_db` needs the `task_db` capability alone by default. When the operator sets
`WILLOW_MCP_ENFORCE_DB_PERIMETER` (off by default), it **also** needs an
operator-signed per-task envelope — the same authority model as egress, so a
`task_db` holder can no longer queue arbitrary `psql`:

1. Manifest holds `task_db` (operator added — **not** granted by `full_access`).
2. Apply `docs/schema/tasks-add-db-authorization.sql` once, then reconfirm the `tasks` mapping.
3. Operator signs the exact task: `willow-mcp sign-db-task <app_id> --task "…" --ttl 30m`
4. Agent calls `task_submit(..., allow_db=True, db_authorization=<envelope>)`.

The envelope is bound to the `database` scope, so a `sign-net-task` envelope can
never authorize db work, and vice-versa.

---

## What agents should say

For egress that a hook-guarded MCP tool needs (web fetch, an integration
call, a task_net Kart run):

> This needs egress to <specific verb, e.g. `willow_web_fetch` on
> arxiv.org>. Please run:
> `willow-mcp grant-net hanuman --ttl 15m --reason "…"`

Push is **not** an egress case for a lease. `git push` is brokered via
`git_push_execute` — the broker holds the willows-bot installation token
and runs `git` on the seat's behalf. Never ask for a `grant-net` to push
a branch; ask for the push envelope instead (`docs/design/brokered-push.md`)
or, when the broker's approval seat is set up, the pending approval row.

Never: edit `settings.global.json`, run `grant-net`, or add `task_net` to a manifest
so the agent's own next call succeeds.

---

## Verify wiring

```
diagnostic_summary(app_id="willow")
```

Check `checks.consent`, `checks.net_lease`, and `checks.severance.egress`.
`self_writable` lists keys the running process could forge — deployment hardening
is `chown` + `WILLOW_MCP_STRICT_TRUST_ROOT=1` (see `kart-tasks.md` §2).

---

## integration_call (server egress)

Same three standing keys (`integration_call` permission + consent + lease). The
integration adapter runs in the MCP server process, not Kart — but the gate model
is parallel. No agent-side shortcut.

## Constraints

@constraint severity=critical
Never: edit `settings.global.json`, run `grant-net`, or add `task_net` to a manifest so the agent's own next call succeeds. No MCP tool mints a lease or changes consent — agents may only request; the operator confirms.
