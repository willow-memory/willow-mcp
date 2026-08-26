---
name: kart-tasks
description: Guided use of willow-mcp's Kart task queue — submit/poll, signed per-task egress and local-Postgres authorization, and worker liveness
---

@markdownai v1.0

# /kart-tasks

Walks through using willow-mcp's sandboxed task queue (`task_submit`,
`task_status`, `task_list`, `fleet_health`) correctly — including the two
things that most easily go wrong: **assuming a submitted task will run**, and
**mishandling the network permission**.

## When to use this

- You're about to submit shell work to Kart via `task_submit`.
- A task you submitted is stuck `pending` and you don't know why.
- You need a task to have network access and aren't sure how to grant it.

## 0. First, know this: submitting is not running

`task_submit` only inserts a `pending` row into the `tasks` table. Execution is
done by a **separate Kart worker** that polls the table and runs each task in a
bubblewrap sandbox. **If no worker is running, your task sits `pending`
forever** — `task_submit` returning `{"status": "pending"}` is *not* a signal
that anything will execute it.

Start one with:

```
willow-mcp worker --lane fast      # daemon: polls until stopped
willow-mcp worker --once           # drain whatever is queued, then exit
```

(In the Claude Code web sandbox the SessionStart hook auto-starts a fast-lane
worker after bootstrap — but heartbeats are the truth, not the hook: check
`fleet_health` before trusting a submission, same as anywhere else.)

**Before trusting a submission, ask whether anything is draining the queue.**
You no longer have to guess. `fleet_health` reports live workers directly:

```json
{"pending": 3, "running": 0, ...,
 "workers": {"alive": 0, "workers": [...]},
 "stranded": true}
```

`stranded: true` means **there is pending work and no live worker** — the task
you just submitted will not run. Say that plainly instead of polling
`task_status` in a loop. `diagnostic_summary` raises the same condition as a
named `worker` problem with the fix attached.

Each entry in `workers.workers` carries a `state`:

| state | meaning |
|---|---|
| `alive` | process up, loop ticking — your task will be claimed |
| `stale` | process up, but its loop stopped ticking (wedged) |
| `dead` | the recorded pid is gone; a leftover file, not a worker |

Only `alive` counts. Heartbeats are **advisory telemetry, never authorization** —
no permission decision reads them.

## 1. Submitting a task

```
task_submit(app_id=..., task="echo hello", agent="kart")
```

`task` is shell. Keep it a real command; the worker extracts and runs it in the
sandbox. Returns a `task_id` for polling.

## 2. The network model — three keys, and its footguns

Tasks run **network-isolated by default**. Egress is opt-in and needs **three
standing keys plus a one-use signed task envelope** (B-19, B-29, B-32, B-37):

| Key | Question it answers | Where it lives | Who turns it |
|---|---|---|---|
| `task_net` | *May this app ever request egress?* | `mcp_apps/<app>/manifest.json` | operator, granted once |
| `consent.internet` | *Is egress permitted right now?* | `$WILLOW_HOME/settings.global.json` | operator, flipped freely |
| **egress lease** | *This app, until when?* | `mcp_apps/_net_leases/<app>.json` | operator, `willow-mcp grant-net`, expires |
| **signed envelope** | *This submitter, exact task, scope, expiry, nonce?* | `tasks.network_authorization` | operator, `willow-mcp sign-net-task`, one use |

- Pass **`allow_net=True`**. Without the **`task_net`** capability you get
  `net_denied`; with `task_net` but `consent.internet: false` you get
  `consent_denied`; with both but no live lease you get `lease_denied`. None of
  them writes anything first. `task_net` is **not** included in `task_queue` or
  `full_access` — grant it explicitly (same separation as B-14/B-19).
- **The lease expires.** Ceiling is 3h (FRANK `cc553729`); the default is 30m.
  When it lapses, egress stops with no one having to remember to turn it off.
  `willow-mcp net-status` shows what is live and how long it has left.
- **Consent is read fail-closed, and so is the lease.** No policy file, an
  unparseable one, `"internet": "true"` (a string), a lease with no timezone on
  its deadline, or a lease whose record names a *different* app than the file it
  sits in — all read as **denied**. Absence is not consent. A name is not an
  identity.
- Flipping `consent.internet` to `false` denies at both submit and execution
  time, without editing a single manifest.
- **`# allow_net` is a request, never authority.** Kartikeya calls the host
  authorizer before shell launch. It rechecks all three standing keys, strict
  trust-root state, signature, exact task hash, expiry, and nonce replay. Direct
  inserts and legacy rows have no signed envelope and therefore cannot get
  network access (B-37).
- **An agent may request egress; it may never grant itself egress.** If you find
  yourself about to write `task_net` into a manifest, or to run
  `willow-mcp grant-net`, so that your own next call succeeds — **stop.** That is
  the escalation the gate exists to prevent (B-32), and the PreToolUse hook blocks
  it. Ask the operator for a lease. The correct sentence is *"this needs egress to
  push the branch — please run `willow-mcp grant-net <app> --ttl 15m`"*, not a
  file edit.
- **Do not hand-embed `# allow_net` or `# allow_localhost` lines in `task`
  text.** The server **strips any
  such caller-supplied line unconditionally** before storing the task (B-21 /
  L-NET-01). Embedding one does nothing except signal a misunderstanding of the
  gate. `# allow_net` can only enter the stored task through the
  permission-checked `allow_net=True` path; `# allow_localhost` cannot be
  self-granted at all. The PreToolUse hook warns if you try.

So: **network = `allow_net=True` + `task_net` + `consent.internet` + a live
lease + an operator-signed `network_authorization` envelope.** Never a directive
in the task string, a manifest you edited, a lease you minted, or a reusable
signature.

### What the lease does and does not buy

A lease is time-boxed and attributed, so a grant decays on its own and leaves a
record of who issued it and why. It is **not** a full fix for B-32. On a host
where the agent and the MCP server share a uid, the agent can still write the
lease file — it now has to forge a third artifact, with a clock, under audit, but
the operating system is not stopping it. `diagnostic_summary` reports exactly
which keys the current process could forge, under `checks.net_lease.self_writable`.
The real control is ownership: put the lease root and manifest under a uid the
agent does not run as, then set `WILLOW_MCP_STRICT_TRUST_ROOT=1` so egress is
refused whenever the process reading the keys could also have written them.

### Earn-first tools — a lease for building, not for running

Some tools are `EARN-FIRST` — real capabilities the fleet does not build
ahead of a consumer. The consumer is the operator, asking, on the record.
This uses the same lease shape as the egress lease above, one subject over:

| Key | Question it answers | Where it lives | Who turns it |
|---|---|---|---|
| **build lease** | *This tool, until when?* | `mcp_apps/_build_leases/<tool>.json` | operator, `willow-mcp grant-build`, expires |

- Same 3h ceiling (FRANK `cc553729`), same fail-closed reader, same
  local-only mint boundary as `grant-net`. No MCP tool can reach it.
- `--reason` is where the operator's on-record agreement lives. The CLI
  flags a grant that landed without one — the rule this lease opens is
  *"the operator asks AND agrees to what building this opens,"* and an
  empty reason has nowhere for the agreement to live.
- `willow-mcp earn-check` reads the roster + leases on disk and prints
  `ready` / `waiting` / `dry` per family. `willow-mcp gates` folds the
  same rows into its panel under **Earn-first build leases**.
- **An agent may propose the build; it may never authorize its own.** The
  PreToolUse hook refuses `Bash: willow-mcp grant-build …` and direct
  writes into `_build_leases/`, the same class as the `grant-net`
  self-grant refusal.

The roster and the doctrine it enforces live in
`docs/design/slice-backlog.md` under **Earn-first**. Integration stubs
stay on a different rule (`earn_mode: two-cite`, see
`docs/design/integrations.md §6`) — different subject, different check.

## 3. The database model — the same shape as the network model, one key shorter

Local Postgres access is opt-in too, gated the same way egress is (B2), just
without a standing lease step:

| Key | Question it answers | Where it lives | Who turns it |
|---|---|---|---|
| `task_db` | *May this app ever reach local Postgres?* | `mcp_apps/<app>/manifest.json` | operator, granted once — **not** included in `task_queue` or `full_access` |
| `WILLOW_MCP_ENFORCE_DB_PERIMETER` | *Is a signed envelope required at all?* | server env | operator; **off by default** |
| **signed envelope** | *This submitter, exact task, `db` scope, expiry, nonce?* | `tasks.db_authorization` | operator, `willow-mcp sign-db-task`, one use |

- Pass **`allow_db=True`**. Without the **`task_db`** capability you get
  `db_denied`. With `task_db` and the perimeter off (the default), that alone
  is enough — `allow_db=True` unlocks the local Postgres socket/env for the
  task.
- **When the operator turns on `WILLOW_MCP_ENFORCE_DB_PERIMETER`**, `allow_db`
  additionally needs an operator-signed per-task envelope:
  `willow-mcp sign-db-task <app_id> --task "…" --ttl 30m`. Without one you get
  `db_authorization_denied`. This closes exactly the gap `task_db` alone
  leaves open — a `task_db` holder could otherwise queue arbitrary `psql`
  forever, with no per-task limit, the same crossing B-37 closed for
  network.
- The envelope is scoped to `db`, so a `sign-net-task` envelope can never
  authorize db work and vice versa — reusing one for the other fails
  verification, not silently succeeds.
- **`# allow_db` in task text is a request, never authority** — same rule as
  `# allow_net`. The server strips any caller-supplied `# allow_db` line
  unconditionally before storing the task (B-21's rule, same code path); it
  can only enter through the permission-checked `allow_db=True` argument.
- Schema prerequisite: the confirmed `tasks` mapping needs a
  `db_authorization` column. Apply
  `docs/schema/tasks-add-db-authorization.sql` once, then reconfirm the
  mapping — without it you get `schema_unusable` even with a valid envelope.

So: **db access = `allow_db=True` + `task_db`**, and once the operator
enforces the perimeter, **+ an operator-signed `db_authorization` envelope,
scoped to `db`, one use.** Never a directive in the task string, and never a
network envelope reused for db (or vice versa).

## 4. Polling

```
task_status(app_id=..., task_id=...)
```

Returns `status`, `result`, and completion time. Poll with restraint — if
`fleet_health` reports `stranded: true` (see §0), stop and report the worker
gap rather than re-polling a task nothing will run.

## 5. Listing

`task_list` filters by status/agent; `fleet_health` gives the aggregate counts
**plus worker liveness**. Check `stranded` first: it is exactly the distinction
between "queued, a worker will get to it" and "queued, nothing is listening."

## 6. Submit-time scan and execution caps (#111)

`task_submit` runs **`kartikeya.check_kart_task`** before the row is queued —
same scanner the worker uses, including **resource_exhaustion** (fork-bomb and
infinite-spin patterns). A match returns `KART-SECURITY` and never touches Postgres.

The worker runs tasks through **`kartikeya.sandbox.run_shell`** with **memory and
PID caps on by default** (2G / 512 PIDs unless tuned via `KART_MEM_MAX` /
`KART_PIDS_MAX`; disable only with `WILLOW_KART_NO_RLIMIT=1`). Results may include
`resource_limit`: `cgroup` or `rlimit`.

## What this skill will not do

@constraint severity=critical
It will not tell you to keep polling a `pending` task when `fleet_health` reports
`stranded: true`. It will not add a `# allow_net` or `# allow_db` directive to
task text as a shortcut around the `task_net`/`task_db` permissions — that path
is closed by design (B-21/B2), and the correct move is to ask the operator to
grant the permission. And it will not edit a manifest, flip a consent file,
issue a lease, or sign a db/net envelope to make your own egress or database
call succeed: requesting access and confirming it are separate authorities,
and you hold only the first.
