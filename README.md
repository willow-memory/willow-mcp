# willow-mcp

[![PyPI](https://img.shields.io/pypi/v/willow-mcp)](https://pypi.org/project/willow-mcp/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-2.0-blue)](https://modelcontextprotocol.io)

Agent-neutral MCP server with persistent memory and task execution. Works with any MCP client: Claude Code, Claude Desktop, Cursor, or any custom agent that speaks stdio MCP.

> **Corpus memory:** the whole Willow constellation — the code, human, and collaboration corpora assembled and queryable — lives in the sovereign [`willow-compose`](https://github.com/rudi193-cmd/willow-compose) repo. The hub *calls* it; it doesn't live here (keeping the hub lean).

**Three storage backends in one server:**
- **SOIL store** — SQLite-backed local key/value store with full-text search and soft delete
- **Postgres knowledge base** — multi-keyword searchable knowledge graph
- **Kart task queue** — sandboxed task executor for shell commands and scripts

Every tool call is authorized via a filesystem-based manifest ACL — no ACL database, no external auth service. See [Authorization](#authorization).

## Install

```bash
pip install willow-mcp
```

Requires Python 3.11+. Postgres is optional — SOIL store works standalone.

```bash
willow-mcp-init    # scaffold $WILLOW_HOME (idempotent)
willow-mcp-compile --force   # compile manifests (use product venv — see below)
willow-mcp-sign-seed hanuman # ratify home seed + detach-sign (operator terminal only)
willow-mcp-compile-persona hanuman # seed → personas/hanuman.md (AS-7)
```

### Local sandbox (one command)

To take a fresh clone to a working stdio server — venv, editable install,
scaffolded `$WILLOW_HOME`, compiled manifests, and (best-effort) a local
Postgres with every table created — run:

```bash
bash scripts/sandbox-bootstrap.sh   # idempotent; ends with a live diagnostic_summary
```

On a bootstrapped sandbox the schema mappings for the tables the script itself
just created are **auto-confirmed** (so `task_*` and knowledge writes work
immediately), behind three guards: existing mapping artifacts are never
touched, every field must resolve exact, and the live columns must equal the
repo's own DDL — an adopted/foreign database always falls through to the
human `schema_confirm_mapping` path (see `src/willow_mcp/sandbox_confirm.py`).

It scaffolds a repo-local, gitignored `.willow/` so the sandbox never touches
your real fleet state. Postgres is optional and handled best-effort (the SOIL
store stands alone); pass `WILLOW_SKIP_PG=1` for a SOIL-only stand-up, or
`WILLOW_PG_BOOTSTRAP_ROLE=1` on a bare cluster where your OS user has no
Postgres role yet.

A fresh Postgres database needs willow-mcp's tables. On a shared fleet DB they
already exist; on a standalone install, apply the DDL in
[`docs/schema/`](docs/schema/) (`knowledge`, `agents`, `routing_decisions`,
`tasks` — the four `diagnostic_summary` checks for, plus `frank_ledger` for the
FRANK governance chain). The bootstrap script applies all of them for you. Each
`knowledge`/`tasks` write path stays locked behind `schema_confirm_mapping`
until you confirm the mapping once.

### The fleet (one command up)

`sandbox-bootstrap.sh` proves this server works **alone**. Two sibling packages
attach to it — [`jeles`](https://github.com/hornbook-knowledge/Jeles), the verified-corpus
organ this package already depends on for institutional search, and
[`nestor`](https://github.com/Die-Namic-Systems/Nestor), which mirrors its hash-chained
ledger into FRANK — and standing all three up together is a different claim:

```bash
bash scripts/fleet-standup.sh    # idempotent; ends with six seam checks
```

It runs the sandbox bootstrap, installs the `jeles` and `nestor` checkouts
editable into that **same venv** (across two venvs their imports silently
resolve to whatever PyPI last published), seats `nestor` in the gate, writes
`$WILLOW_HOME/fleet.env`, and then checks that the seams actually join:

| Seam | What crosses |
|------|--------------|
| co-install | one venv, all three resolving to the checkouts |
| shared SOIL store | jeles' corpus and this server's `Store` on one SQLite file |
| gap forward | a jeles corpus miss → `gap_log`, through the manifest ACL |
| institutional search | this server's `willow_institutional_search` → jeles' ~60 collections |
| FRANK mirror | a nestor ledger entry → `frank_append` → the hash chain |
| nugget bridge | a jeles nugget → nestor, as a **draft** — never a seal |

Point `JELES_REPO` / `NESTOR_REPO` at the checkouts if they are not siblings of
this one. Re-check any time with `.venv/bin/python scripts/fleet_seams.py`
(`--json` for machine output); every seam it reports as passing was exercised
by writing real data through the real path, because a seam that is only
imported is a seam that has not been tested.

> **PATH note:** `~/.local/bin/willow-mcp` is often the **fleet** shim (`sap_mcp.py`), not this
> product. Use the venv binary from wherever you ran `pip install willow-mcp` (or
> `pip install -e .` in a clone) — e.g. `.venv/bin/willow-mcp-compile --force` or
> `.venv/bin/willow-mcp compile-agents --force` — not a bare `willow-mcp` on `PATH`.

Runtime layout: [docs/design/product-layout.md](docs/design/product-layout.md) (LOCKED).

## Tools

| Tool | Description |
|------|-------------|
| `store_put` | Write record (JSON object) to SQLite store |
| `store_get` | Read record by `record_id` |
| `store_list` | List all records in a collection |
| `store_update` | Update an existing record |
| `store_search` | Multi-keyword AND search in a collection |
| `store_delete` | Soft-delete a record by `record_id` |
| `store_search_all` | Search across all collections |
| `store_collections` | List the SOIL collections you can see (narrowed to your `store_scope`) — learn the collection names without running a search |
| `store_purge_collection` | Bulk soft-delete every record in a collection (e.g. leftover test/scratch data). Reversible (archive-don't-delete — the store.db is kept); requires `confirm=<collection name>` and stays within your `store_scope` |
| `store_stats` | Per-collection live-record counts (within your `store_scope`), largest first, plus store-wide totals — the numeric companion to `store_collections` for spotting a bloated or polluted collection |
| `knowledge_ingest` | Add a knowledge atom (requires a confirmed schema mapping — see `schema_confirm_mapping`) |
| `knowledge_search` | Multi-keyword search in the Postgres knowledge base |
| `kb_at` | Fetch a single knowledge atom by ID |
| `kb_promote` | Change an atom's domain (requires a confirmed schema mapping) |
| `knowledge_flag` | Attach an integrity flag to an existing atom (`knowledge_curate`; tags-based, idempotent) |
| `knowledge_retract` | Tombstone an atom in place — hidden from default search, still readable via `kb_at` (`knowledge_curate`) |
| `kb_journal` | Add a journal-domain knowledge atom (requires a confirmed schema mapping) |
| `kb_startup_continuity` | Fetch atoms tagged/domained for startup continuity |
| `schema_confirm_mapping` | Confirm (optionally correct) a table's column mapping, unlocking its write tools. `preview=True` dry-runs it and renders a **sample row** so you can see what each field actually resolves to before trusting a name match — see [docs/design/schema-adaptation.md](docs/design/schema-adaptation.md) |
| `gap_log` | Log or bump a "we don't know this yet" entry (fleet-wide backlog, SOIL-only, no Postgres needed) — see [docs/design/gap-backlog.md](docs/design/gap-backlog.md) |
| `gap_list` | List gaps, most-asked first — filter by `topic` and/or `status` (`open`/`resolved`/`promoted`) |
| `gap_resolve` | Mark a gap as being worked or answered — bookkeeping only, does not write to the knowledge base |
| `gap_delete` | Soft-delete a single gap by id — clear junk/test entries without disturbing real gaps. Reversible (archive-don't-delete) |
| `gap_purge_topic` | Soft-delete every gap under an exact topic in one call — bulk cleanup without the per-call rate limit. Promoted gaps (they point at a landed atom) are left intact; requires `confirm=<topic>` |
| `gap_promote` | Turn a resolved gap into a knowledge atom. Requires `answer`, at least one `source`, and `confirmed_by`; writes through the same schema-confirmation gate as `knowledge_ingest` and closes the gap out |
| `nest_scan` | Walk a drop folder, extract + classify its files by meaning, and write a canonical SQLite Nest DB. Returns counts only; `dry_run=True` (default) reports without writing — see [docs/NEST.md](docs/NEST.md) |
| `nest_status` | Counts for a seeded Nest DB — sources by status, fragments by type, topical categories by size. Structure only; filename-labels are walled and counted as `uncategorised` |
| `nest_digest` | A one-page Markdown map of a Nest DB — the **walled** view (person names, the date timeline, and filenames suppressed). The full digest is a local-CLI affordance only, never returned over MCP |
| `nest_promote` | Promote a Nest's **structure** — counts, curated category names, redacted secret kinds, never content — into the knowledge base via the same core write as `knowledge_ingest`. `dry_run=True` returns the atoms that would be promoted |
| `nest_intake_scan` | Live drop-folder router: classify new files in a drop zone by filename into a track and **stage** a review queue. Non-destructive — nothing moves until `nest_intake_file` |
| `nest_intake_queue` | List the pending review queue with the track the classifier predicted for each file |
| `nest_intake_file` | File a staged item: **move** the file to its predicted track's destination, or `override_dest` to correct it. An override feeds the correction counter |
| `nest_intake_skip` | Skip a staged item — leave the file, record the decision |
| `nest_intake_flags` | List open rule-delta flags — patterns overridden often enough that the classifier proposes a rules change (a human ratifies) |
| `task_submit` | Submit task to Kart queue |
| `task_status` | Check task status |
| `task_list` | List pending tasks |
| `agent_route` | Route a task to a target agent, recording the decision |
| `agent_dispatch_result` | Record the result of a dispatched agent task |
| `dispatch_send` | Create dispatch packet (`meta.json` + `assignment.md`) |
| `dispatch_read` | Read dispatch assignment and status |
| `dispatch_list` | List dispatch packets |
| `dispatch_accept` | Specialist accepts packet (pending → working) |
| `handoff_write_v4` | Complete work — `handoff.json` + `closeout.md` |
| `handoff_read` | Read handoff for a dispatch |
| `verify_handoff` | Orchestrator verifies completion |
| `agent_clear` | Clear specialist for next packet |
| `session_read` | Read thin session state file |
| `fleet_status` | Return the canonical charter `fleet.json` roster plus Postgres drift diagnostics |
| `fleet_health` | Task queue counts by status, live worker heartbeats, and whether the queue is `stranded` |
| `frank_read` / `frank_verify` | Read and verify the existing Postgres FRANK hash chain |
| `frank_append` | Append an established-shape FRANK event (separately gated) |
| `envelope_apply` | Match an active constitutional grant and write its FRANK citation before returning authority |
| `grove_list_channels` | List active Grove channels (name, type, description) |
| `grove_get_history` | Message history from a channel, with `since_id` polling and `limit` (max 200) |
| `grove_search` | Case-insensitive substring search across Grove messages, optionally scoped to one channel |
| `grove_watch` / `grove_watch_all` | Non-blocking poll for new messages in one channel, or many at once via a `{channel: since_id}` cursor map |
| `grove_get_thread` | A message plus its flags and all its replies |
| `grove_bus_receive` | Structured bus messages addressed to an agent (or broadcast), priority-ordered |
| `grove_inbox` | Fleet inbox: @mentions, bus messages addressed to you, and your dedicated `#<agent>` channel, merged and deduped |
| `grove_flagged` | Messages carrying a given flag (`needs-reply`/`starred`/`read`/`urgent`/`resolved`), across all channels or one |
| `grove_get_identity` | Your own Grove identity — `app_id`, resolved `grove_sender`, registered role/display name |
| `grove_agents` | Fleet agents by most-recent HEARTBEAT, newest first |
| `grove_fleet_status` | Presence plus what each agent is doing — `ui_state`, a content peek, and whether it's blocked on a reply |
| `grove_human_required` | The human-required queue: work that pauses automation until a person acts, priority-first |
| `grove_send_message` | Post to a channel (creates it if missing). `sender` defaults to your resolved `grove_sender`, never a literal "Auto"; posting as a different identity requires `grove_relay` |
| `grove_reply` | Reply in a thread; clears the parent's `needs-reply` flag |
| `grove_flag` / `grove_unflag` | Set or clear a flag on a message |
| `grove_bus_send` | Post a structured, addressed, typed, prioritized bus message (`COMMAND`/`EVENT`/`HEARTBEAT`/…) |
| `grove_ack` | Acknowledge a received message; clears `needs-reply`, marks it `read` |
| `grove_heartbeat` | Broadcast "I am alive" to `#general` |
| `context_save` | Save ephemeral per-identity working state under a key, with an optional TTL (SOIL-backed, no Postgres) |
| `context_get` | Read a saved context; `expired` (and purged) once its TTL passes |
| `context_list` | List your saved context keys and expiry times (expired ones skipped) |
| `context_expire` | Delete a saved context before its TTL |
| `integration_list` | The integration ledger: every outbound adapter, live or **declared stub**, with credential *source* (never the value) |
| `integration_status` | Offline readiness readout for one adapter — live/stub, credential presence, and whether the egress gate would pass. No network call |
| `integration_call` | Call an external API through a registered adapter — behind the three-key egress gate, keyed on `integration_net` (own line, never implied by `task_net` or `full_access`) |
| `willow_web_search` | Open-web search with the results run through **external-guard** — the guarded replacement for a client's native web tool. `web_read` + `web_net` + `consent.internet` + a live lease |
| `willow_web_fetch` | Fetch one URL through the destination guard: the host is **resolved** and every address tested (not just literals), every redirect hop re-checked, body scanned by external-guard and sandwich-wrapped. Returns the `redirects` chain actually followed |
| `willow_institutional_search` | Fan a query across jeles' registered institutional/academic collections (arXiv, PubMed, Crossref, OpenAlex, …) — citable sources rather than open web. Same `web_read` line as the two above, so one grant covers all three |
| `federation_discover` | Shadow-IT scan: `.mcp.json` files not yet owned by the ratified registry. Read-only, never connects |
| `federation_list_servers` | List every operator-ratified downstream MCP server: id, launch command, the environment-variable *names* it receives (never values) |
| `federation_call` | Call one tool on one ratified downstream MCP server — behind the fourth egress class, `mcp_federation` (own line), a per-downstream-tool namespaced grant, and the operator's ratification ceiling |
| `receipts_tail` | Read your own most-recent tool-call receipts — a self-audit trail scoped to your `app_id` |
| `whoami` | Report your own identity and effective permissions — app_id, role, permission groups, the resolved set of tools you can call (minus `deny_tools`), and your `store_scope`. Ungated, like `diagnostic_summary` |
| `diagnostic_summary` | Self-check: store/Postgres/schema/manifest/bindings/worker/consent/egress-lease/env health, with a verdict and named fixes. Ungated — see below |

### Egress needs three keys

**First run:** `willow-mcp-init` then `willow-mcp onboard --project-root <repo> --enable-internet`.
See [docs/OPERATOR-ONBOARD.md](docs/OPERATOR-ONBOARD.md). Use `wmc` or the product venv
binary — not bare `willow-mcp` on PATH when the legacy `sap_mcp.py` server is installed.

**Wiring a project into the fleet:** [docs/PROJECT-WIRING.md](docs/PROJECT-WIRING.md) —
the four `project sync` behaviors whose symptom shows up nowhere near the cause
(`claude_hooks` defaulting to `generated`, `wiring.hooks` being Cursor-only,
`trusted_read`'s real-path/mode-644 rules, and manifest verification refusing
boot fleet-wide on one bad row).

A task that reaches the network requires **all three standing keys** plus a
one-use signed task envelope. Any missing element denies before shell launch:

| Key | Question | Where | Turned by |
|---|---|---|---|
| `task_net` | May this app *ever* request egress? | `mcp_apps/<app_id>/manifest.json` | operator, granted once |
| `consent.internet` | Is egress permitted *right now*? | `$WILLOW_HOME/settings.global.json` | operator, flipped freely |
| egress lease | For *this app*, until *when*? | `mcp_apps/_net_leases/<app_id>.json` | operator, `willow-mcp grant-net`, expires on its own |
| signed task envelope | This submitter, exact task, scope, expiry, and nonce? | `tasks.network_authorization` | operator, `willow-mcp sign-net-task`, one use |

```jsonc
// $WILLOW_HOME/settings.global.json — the off switch
{ "consent": { "internet": false, "cloud_llm": false } }
```

```console
$ willow-mcp onboard --project-root ~/github/willow --enable-internet
$ willow-mcp run-net myapp --task-file task.sh --ttl 30m   # grant + sign + queue
$ willow-mcp worker --lane fast --once                   # drain the queue
$ willow-mcp doctor --app-id myapp                         # copy/paste fixes
$ willow-mcp grant-net myapp --ttl 30m --reason "publish the release"
$ willow-mcp sign-net-task myapp --task-file task.sh       # keys: setup-egress / ~/.config/willow-mcp/egress/
$ willow-mcp net-status
$ willow-mcp revoke-net myapp
```

**Open-web egress** (`willow_web_search` / `willow_web_fetch` /
`willow_institutional_search`) is the same three-key gate, keyed on `web_net`
instead of `task_net` (`web_egress.egress_denial`). Standing it up
for local/dev use is the same three grants — `allow-permission myapp web_net`,
`consent set internet true`, `grant-net myapp --ttl 30m` — done separately, in
order, each its own command. `dev-net` does the same three, in one:

```console
$ willow-mcp dev-net myapp --ttl 30m --reason "local dev"
```

It is **not a new bypass path** — it calls exactly the same operator-only
admin functions `allow-permission` / `consent set` / `grant-net` already call,
so there is nothing new to audit, and it stays local-CLI-only exactly like
them: no MCP tool can reach it, and the PreToolUse self-grant guard blocks an
agent from invoking it via `Bash` the same way it blocks a bare `grant-net`.
Consent needs an interactive operator terminal only when it is not already
granted — a repeat run needs no TTY at all — and the whole command refuses
outright when `WILLOW_MCP_STRICT_TRUST_ROOT` is set (a hardened posture this
shortcut isn't for) unless you pass `--force`. It prints the lease's expiry,
the exact `grant-net` command to renew it, and the full four-key diagnostic
below.

`web_egress.egress_status(app_id)` is the read-only counterpart: all four
keys — manifest permission, operator consent, egress lease, strict trust
root — reported at once instead of stopping at the first closed lock the way
the gate itself (`web_egress.egress_denial`) does. `dev-net` prints it after
granting so you see every key's state in one place, not just the one you just
fixed.

Setting `consent.internet` to `false` stops network tasks submitted through
`task_submit`, immediately, without editing a single manifest. `task_net` is a
capability (rarely granted, deliberately excluded from `full_access`);
`consent.internet` is a switch; the lease is a **time-boxed grant** that an agent
may ask for and never issue. No MCP tool can mint one — `grant-net` is local CLI
only, exactly like `confirm-binding`. An agent may *request* egress and may never
*grant it to itself*. `sign-net-task` requires an interactive host terminal and
an Ed25519 private key outside `WILLOW_HOME`/`WILLOW_STORE_ROOT`; no MCP tool or
worker receives that key.

At execution, Kartikeya treats `# allow_net` only as a request and calls the
willow-mcp host authorizer. The authorizer rechecks capability, consent, lease,
strict trust-root state, signature, exact normalized task hash, expiry, and the
one-use nonce. Direct task-table inserts and legacy rows have no envelope, so
they remain runnable only as network-isolated work (B-37).

Deployment is deliberately explicit: apply
`docs/schema/tasks-add-network-authorization.sql`, reconfirm the `tasks` mapping,
set `WILLOW_MCP_EGRESS_PUBLIC_KEY` to an operator-owned Ed25519 public PEM that
the worker cannot write, set a worker-writable `WILLOW_MCP_EGRESS_REPLAY_ROOT`,
and enable `WILLOW_MCP_STRICT_TRUST_ROOT=1`. The matching private key must remain
outside `WILLOW_HOME` and `WILLOW_STORE_ROOT`; only the interactive
`sign-net-task` command reads it. Until those conditions hold, network tasks deny
closed while ordinary isolated tasks remain unchanged.

Consent and leases are both read **fail-closed**: a missing file, an unparseable
file, a non-boolean value (`"true"`, `1`), a lease past its deadline, a deadline
with no timezone, or a lease record naming a *different* app than the file it sits
in — all read as denied. Absence is not consent, and a name is not an identity.
Runtime tools only read consent. An operator can mutate it through the local,
interactive-only `willow-mcp consent set <key> <true|false>` command; the command
atomically writes canonical policy and mirror and appends a metadata-only audit
record. `willow-mcp consent reconcile` keeps the canonical value and repairs its
mirror. If the two disagree, `diagnostic_summary` reports both rather than
guessing intent (B-30).

### Earn-first — a lease for building

Some tools in the roadmap are `EARN-FIRST`: real capabilities the fleet
doesn't build ahead of a consumer. The consumer is the operator, asking,
on the record. `grant-build` is that record — a lease with the same 3h
ceiling as `grant-net` (FRANK `cc553729`), kept in
`mcp_apps/_build_leases/<tool>.json`, and mintable only from the local CLI,
never an MCP tool.

```console
$ willow-mcp grant-build workflow --ttl 30m \
    --reason "ship the multi-phase engine so kart tasks compose"
$ willow-mcp earn-check          # roster vs disk: ready / waiting / dry
$ willow-mcp build-status        # every lease, active + expired + malformed
$ willow-mcp revoke-build workflow
```

`willow-mcp gates` folds the roster into the same panel that shows net
leases and manifest permissions — the roster carries an `Earn-first build
leases` heading, one row per family, active leases counting down. When the
lease expires the family falls back to earn-first; further work needs a
fresh ask under the same terms. `earn-check` prints `ready` / `waiting` /
`dry` per family so the case-by-case argument becomes a lookup.

The rule this lease opens, and the roster of families it applies to, live
in [`docs/design/slice-backlog.md`](docs/design/slice-backlog.md)
under **Earn-first** — that's the doctrine; `grant-build` and `earn-check`
are its enforcement seam. Integration stubs stay on a different rule
(`earn_mode: two-cite`, see [`docs/design/integrations.md §6`](docs/design/integrations.md));
different subject, different check.

### Governance continuity

`willow-mcp roster status` compares the constitution repo's canonical
`fleet.json` with Postgres. `willow-mcp roster sync` is interactive-only and
idempotently inserts or updates charter rows; unknown database rows are reported
as contested and preserved, never silently deleted.

Constitutional envelopes are loaded read-only from
`$WILLOW_HOME/constitutional/pre-approved.json` and checked against
`syscall-table.json` in the same directory (`WILLOW_ENVELOPE_REGISTRY` /
`WILLOW_SYSCALL_TABLE` override either). `willow-mcp-init` seeds an empty
starter registry and a real syscall table there on first run — the registry
starts empty on purpose; it's the operator's own ratified grants to issue,
never shippable content. `envelope_apply` validates issuer, grantee, verb,
exact bounds shape, revocation, expiry, and FRANK-derived quota. Both grants
and faults append an `envelope_citation` to the existing `frank_ledger`
before authority is returned.

#### `gates` — every gate, on/off, egress-lease shaped

Diagnosing a denial today means knowing which of a dozen-plus gates to check
and which file or CLI command controls it. `willow-mcp gates` shows all of
them at once, each rendered the way the egress lease already renders
itself — on/off, plus how long the "on" is good for. Run it in a real
terminal and it's interactive — arrow keys / j-k to move, enter/space to
actually flip the highlighted gate, no second command to copy anywhere:

```console
$ willow-mcp gates                    # interactive TUI (every app under mcp_apps/)
$ willow-mcp gates myapp              # interactive TUI, scoped to one app
$ willow-mcp gates --serve            # live local HTML dashboard, working buttons
$ willow-mcp gates --serve --port 9000 --host 127.0.0.1
$ willow-mcp gates --static           # one-shot text printout instead of the TUI
$ willow-mcp gates --html             # writes ./willow-gates.html, a read-only snapshot
$ willow-mcp gates --json             # raw rows, for scripting
```

`--static`/`--json`/`--html` are unchanged from before and still the right
choice for scripting, CI, or a file you want to keep — `--static` is also
what runs automatically whenever stdout isn't a real terminal (piped,
redirected), so nothing here breaks existing scripts.

The interactive TUI and `--serve`'s live dashboard share one action layer
(`gates_actions.py`) with the CLI subcommands below — pressing a row (or
clicking its button) calls the exact same functions `allow-permission`/
`grant-net`/`confirm-binding` do, nothing new. `--serve` binds
`127.0.0.1`-only by default; it's a mutation-capable local admin surface
with no authentication of its own, so widening `--host` prints a warning
rather than doing it quietly. The one exception is the `worker` row's
action: it drains the queue **once** (like `worker --once`), never launches
the persistent daemon — that would block the TUI/dashboard forever.

Manifest permission groups — which had no CLI before, only hand-editing
`manifest.json` or regenerating it via `compile-agents` — get their own
pair, usable standalone or as what the TUI/dashboard call underneath:

```console
$ willow-mcp allow-permission myapp store_read
$ willow-mcp deny-permission myapp store_read
```

Both are local-CLI-only, never MCP tools, for the same reason `grant-net`
isn't: an agent must never be able to grant itself a permission it was just
denied — and that boundary holds for the TUI and `--serve` too, since
neither is reachable except by an operator running them on the host that
owns `$WILLOW_HOME`. `consent.*` rows never show a command or a working
button — willow-mcp only reads that policy (see above) — and
`strict_trust_root` / severance / human-orchestrator attestation are
environment variables read once at process start, so their rows name the
env var to set and restart with, rather than pretending a live toggle
exists.

`task_net` and `integration_net` both show up as their own capability rows
(neither is folded into `full_access`), and both are authorized by the same
per-app egress lease below them — one `grant-net`/`revoke-net` covers Kart
sandbox egress and server-process integration calls together, since a lease
is scoped to the app, not to which capability is asking.

Every row also carries a `state_label` in context instead of a bare ON/OFF —
GRANTED, ALLOWED, ACTIVE, CONFIRMED, RUNNING, ENABLED (and their opposites) —
and a `category` (egress & network / system / identity / permissions) that
the TUI and both HTML pages group by. The HTML pages open on the egress
tab — the smallest group, and the one with a clock — with a summary strip
above the tabs for at-a-glance state, and render the ~20-row permissions
group (routine, rarely touched) as a compact list rather than large cards,
instead of one flat scroll of everything at once.

#### `tree` — the integration seam for a real dashboard

`docs/design/*.html` sketches a client UI as a tree — trunk (overall
health), sap (task queue), canopy (agent fleet), roots (SOIL store), rings
(schema-mapping confirmation), leaves (knowledge atoms), litter (activity
log), and stomata (the gates above). `willow-mcp tree` is what makes that
real: one call that returns every part in that same shape, instead of a
dashboard assembling `fleet_status`/`fleet_health`/`kb_startup_continuity`/
`receipts_tail`/`gates` itself.

```console
$ willow-mcp tree myapp              # short text summary
$ willow-mcp tree myapp --json       # full data, for a real dashboard to consume
```

It's a thin CLI wrapper over `willow_mcp.tree_view.build_tree(app_id)`,
which a Python dashboard can also import and call directly. `sap`, `canopy`,
and `leaves` go through the same `@_guarded` MCP tool functions a client
would reach over the protocol — gating, rate limiting, and receipt logging
all still apply — and degrade to `{"error": "postgres_unavailable"}` with no
database configured, same as those tools already do. `roots`, `rings`,
`litter`, and `stomata` read local SQLite/filesystem state directly, so they
work with no Postgres at all.

#### The residual, stated plainly

On a host where the agent and the MCP server run as the same uid, the agent can
write the very files that authorize its egress. Leases make a self-grant *expire*
and *leave a record*, and the PreToolUse hook blocks the obvious attempts — but
the operating system is not stopping it. `diagnostic_summary` names exactly which
keys the running process could forge, under `checks.net_lease.self_writable`.

The control is ownership. Put `mcp_apps/` and `mcp_apps/_net_leases/` under a uid
the agent does not run as, then:

```console
$ export WILLOW_MCP_STRICT_TRUST_ROOT=1   # refuse egress when the keys are self-writable
```

Strict mode is **off by default** because turning it on before that separation
exists would deny egress on every current install. This is tracked as B-32 in
`docs/BUGS.md`, and as [issue #231](https://github.com/willow-memory/willow-mcp/issues/231)
(dedicated low-privilege agent uid) and [#232](https://github.com/willow-memory/willow-mcp/issues/232)
(store `.db` OS-level permission enforcement, which depends on it); requesting
egress and confirming it are separate authorities, and until the filesystem
says so, only convention does.

The concrete runbook for actually standing up the separated deployment —
including a serve-mode shape where the agent has no local account on the
host at all — is [`docs/deploy/dedicated-uid-deployment.md`](docs/deploy/dedicated-uid-deployment.md).
`diagnostic_summary`'s `checks.uid_separation` (and `doctor`'s `uid
separation:` line) report the plain ownership fact — does the trust root
belong to a different account than the one asking — next to, never instead
of, the `self_writable`/`hardened` checks strict mode actually enforces
against.

### Integrations (outbound adapters)

`integration_call` lets the **server process** call external HTTP APIs through
registered adapters — a second egress lane, beside the Kart sandbox's. It uses
the same three-key gate, but keyed on its **own** capability, `integration_net`:
the server egresses as its own uid with its own filesystem view, a strictly more
privileged lane than the network-namespaced sandbox, so `task_net` never implies
it (and vice versa). `integration_call` itself is also excluded from
`full_access` — even the attempt surface is opt-in.

Adapters are **earned, not scaffolded**. Four are live (`github`,
`huggingface`, `jeles`, `utety`); six are *declared stubs* (`gmail`, `slack`,
`notion`, `google-drive`, `datadog`, `jira`) that refuse fail-closed, each
naming what it needs and what earns its implementation. `integration_list` is
the ledger (it reports each adapter's live/stub status) — see
[`docs/design/integrations.md`](docs/design/integrations.md) for the earn rule.

Credentials resolve environment-variable-first (e.g. `WILLOW_GITHUB_TOKEN`,
then `GITHUB_TOKEN`), then the vault under `integration/<name>/token`. No tool
ever returns a credential — only its *source*.

```console
$ willow-mcp-integrations list                # the ledger, live + stubs
$ willow-mcp-integrations check github --app-id myapp   # offline: creds? keys? no network call
$ willow-mcp-integrations set-token github   # prompted + hidden, stored in the vault
```

### Federated MCP (willow-mcp as a client)

willow-mcp can call tools on *other* MCP servers spread through the fleet —
see [`docs/design/federated-mcp-gating.md`](docs/design/federated-mcp-gating.md)
for the full decision record. A stdio MCP server willow-mcp spawns itself is
`fork`/`exec` at its own uid — a fourth, strictly-more-privileged egress class
beside the Kart sandbox, integration adapters, and open-web HTTP — so it gets
its own capability, `mcp_federation`, and its own consent key,
`consent.federation`, on the same three-key shape as the other three lanes.

A federated call is authorized only where **two ceilings agree**: the
caller's manifest must grant the namespaced permission
`mcp:<server_id>:<tool>` — gated per downstream tool, never per server, so a
grant never silently widens as a downstream server grows new tools — *and*
the server must be in the **operator-ratified registry**. Neither alone is
sufficient: a `full_access` manifest gains no new surface just because a
`.mcp.json` appears on disk, and a ratified server's advertised tools do not
themselves grant anything to a caller whose manifest never named them.

```console
$ willow-mcp allow-permission myapp mcp_federation
$ willow-mcp allow-permission myapp 'mcp:<server_id>:<tool>'
$ willow-mcp consent set federation true
$ willow-mcp grant-net myapp --ttl 30m --reason "call the gazelle MCP server"
```

`federation_discover` is read-only inventory (which `.mcp.json` files exist
that the registry does not yet own — the shadow-IT question); ratifying a
discovered server into something `federation_call` can reach is an operator
act, not an MCP tool, the same way an egress lease is. Every downstream tool
listing and every call result is run through **external-guard** before it
reaches a caller — a downstream server's tool names and descriptions are
untrusted input, scanned at listing time as well as at call time.

#### Remote downstream servers (streamable HTTP)

A ratified entry with `transport: "streamable-http"` (or `http`) and a `url` is
dialled over the network instead of forked as a subprocess. `auth_token_env`
optionally names an environment variable holding a bearer token — the **name**,
never the value, exactly as `env_keys` works.

The destination is checked with the same resolve-don't-pattern-match guard the
open-web lane uses, **at ratification and again at every connect**. Once is not
enough: the registry records a URL, but DNS decides where a *name* points, so an
entry ratified against a public host can be aimed at loopback or cloud metadata
later without the registry changing at all.

```console
$ export FED_PEER_TOKEN=...          # out of band, never in the registry
$ willow-mcp ...ratify... --transport streamable-http --url https://peer.example/mcp
```

**You cannot federate to `localhost` over HTTP.** Loopback, link-local
(`169.254.0.0/16`), and private space are refused, which is the guard working —
use `stdio` for a local downstream, which is what it is for. The five egress
locks (`mcp_federation` permission, the per-downstream-tool grant, ratification,
`consent.federation`, and a live egress lease) apply to a remote peer exactly as
they do to a spawned one.

#### Signed downstream links (optional)

When the downstream is another willow-mcp running with
`WILLOW_MCP_ENFORCE_BINDING=1`, a ratified entry can carry an identity so this
server checks in and signs every outbound call — the willow-gate binding, in the
outbound direction. Three fields, attached at ratification:

| field | meaning |
|---|---|
| `signing_agent_id` | the `app_id` this server presents downstream |
| `signing_secret_env` | the **name** of an env var holding the hex secret — never the value |
| `signing_trust_level` | the tier claimed at check-in (0–4; the downstream caps it at your registered ceiling) |

The downstream operator runs `willow-mcp register-agent <signing_agent_id>` and
hands you the minted secret out of band; you export it under the name you chose
and ratify the link. The registry never holds the secret — it names the variable
and the value is read from this process at connect time, exactly as `env_keys`
works for a child's environment.

A link that asks to sign and cannot — secret unset, malformed, under 32 bytes, or
a check-in the downstream refuses — **fails closed**: it raises rather than
connecting unsigned, and the config is resolved before any child process is
spawned. An entry with no `signing_agent_id` is unsigned and behaves exactly as
it always has.

What this buys depends on who you are calling. Against a downstream this process
**spawns** it is least-privilege and audit — the downstream's tier ceiling
applies to you, its receipt log attributes your calls, and check-out reconciles
what you declared against what its log recorded. It is not *authentication* there,
because you already chose that child's binary and environment. It becomes
authentication against a peer this process did not start — which needs a
non-stdio transport this client does not yet implement.

### Repo hygiene sweep

A read-only survey of every git repo under a root — diverged and unpushed
branches, untracked *source* files, tracked-but-dirty runtime state, branch
litter, and merged worktrees that are safe to reap. It never fetches, pulls,
commits, or deletes; cleanup is offered as a report line, never performed.

```console
$ willow-mcp repo-sweep --root ~/github
[repo-sweep] 33 repos under /home/you/github, 4 with findings, 29 clean

  willow-memory/.willow (master)
    - 10 untracked source files: skills/brainstorming.md, skills/debugging.md …
  safe-app-store-public (master)
    - 22 tracked files dirty (runtime state in git?)
```

`--emit-flags` also raises one SOIL flag per repo with findings, into
`willow_flags` (inside the `willow_*` store_scope, so no manifest change).
Flag ids are stable per repo, so a weekly run updates rather than accumulates.
`--json` for machine-readable output; `--max-depth` (default 2) covers both a
flat `<root>/<repo>` tree and an org-shaped `<root>/<org>/<repo>` one.

To run it weekly — `Mon *-*-* 04:00:00`, `Persistent=true` so a sweep missed
while the machine was off still runs:

```console
$ willow-mcp repo-sweep-service install     # writes .service + .timer
$ systemctl --user enable --now willow-mcp-repo-sweep.timer
```

Like `worker-service`, the installer only manages unit files and
`daemon-reload` — it never starts, stops, enables, or disables anything. That
second line is yours.

### Running the task worker

`task_submit` only *queues* a task. A worker process executes it, sandboxed with
bubblewrap. Without one running, tasks stay `pending` forever:

```bash
willow-mcp worker --lane fast     # daemon; polls until stopped
willow-mcp worker --once          # drain what's queued, then exit
```

The engine is [`kartikeya`](https://pypi.org/project/kartikeya/), a hard
dependency — a base `pip install willow-mcp` ships a working drainer.

`--lane` is `fast` or `batch` (env fallback: `WILLOW_WORKER_LANE`, then
kartikeya's own `KART_WORKER_LANE`, then `fast`). The two aren't just
separate queues — `batch` forces `production` mode: it refuses to start on
kartikeya's generic/vendored sandbox default (unless you also pass
`--allow-generic-sandbox`) and requires a real Postgres connection. `fast`
only enters `production` mode if you pass `--require-postgres` explicitly.
Fast-lane concurrency (`--slots`) defaults from kartikeya's `KART_FAST_WORKERS`
env var, or `3` if unset.

A running worker publishes a heartbeat under `$WILLOW_HOME/worker_heartbeat/`,
which `fleet_health` reads back:

```json
{"pending": 3, "running": 0, "completed": 12, "failed": 0, "total": 15,
 "workers": {"alive": 0, "workers": [{"pid": 4242, "state": "dead", ...}]},
 "stranded": true}
```

**`stranded: true` means there is pending work and no live worker** — the
distinction between "queued, it'll run" and "queued, nothing is listening."
`diagnostic_summary` raises the same condition as a named `worker` problem. A
worker is `alive` (ticking), `stale` (process up, loop wedged), or `dead` (pid
gone). Heartbeats are advisory telemetry: no permission decision reads them, and
reads verify the recorded pid is a live local process, so a forged file naming a
dead pid reads `dead`.

`knowledge_search`/`kb_at`/`kb_startup_continuity` and `fleet_status` adapt to
whatever your host database's real columns are named — see
[docs/design/schema-adaptation.md](docs/design/schema-adaptation.md).
`knowledge_ingest`/`kb_ingest`/`kb_journal`/`kb_promote` refuse to write
(`unconfirmed_schema`) until you've reviewed and confirmed that mapping via
`schema_confirm_mapping` — the [`schema-confirm` skill](skills/schema-confirm.md)
walks through that.

Every tool requires an `app_id` param, checked against a manifest at
`$WILLOW_HOME/mcp_apps/<app_id>/manifest.json` — see [Authorization](#authorization).
The one exception is **`diagnostic_summary`**, which is intentionally ungated: it
is the tool you reach for when your manifest or database is misconfigured, so
gating it behind a permission would make the diagnostic itself undiagnosable. It
discloses only the caller's own configuration — never fleet rows or vault
secrets — and in serve mode still requires a confirmed identity and redacts
absolute filesystem paths.

## MCP config

Repo-local configs (`.cursor/mcp.json`, `.mcp.json`) wire **willow-mcp** plus
**codebase-memory-mcp** for graph-augmented code search while developing this
package. Install the CBM binary to `~/.local/bin/codebase-memory-mcp`, then
index this repo (`project: home-sean-campbell-github-willow-mcp`).

`willow-mcp`'s entry points at a repo-local venv rather than a bare `python3` —
your host interpreter may not have `pip` or the `mcp` package installed (a
missing import here crashes the stdio server before the handshake, which
shows up as a client-side reconnect failure). Set it up once per clone:

```bash
python3 -m venv .venv
.venv/bin/python3 -m pip install -e .
```

Minimal single-server config (path is relative to the repo root, so this
works unmodified on any clone once the venv above exists):

```json
{
  "mcpServers": {
    "willow-mcp": {
      "type": "stdio",
      "command": ".venv/bin/python3",
      "args": ["-m", "willow_mcp"]
    },
    "codebase-memory-mcp": {
      "type": "stdio",
      "command": "codebase-memory-mcp",
      "args": []
    }
  }
}
```

Point `WILLOW_PG_DB` / `WILLOW_STORE_ROOT` at your host fleet store when you
need Postgres knowledge or shared SOIL data.

**This config is dev-only — never point it at fleet secrets.** No `WILLOW_HOME`
override means it defaults to `~/.willow`; no `WILLOW_PGP_FINGERPRINT` means
manifests are honored unsigned (#183 is opt-in); no `WILLOW_MCP_ENFORCE_BINDING`
means stdio `app_id` is trusted as claimed. A 2026-07-31 red-team pass found
exactly this gap live (issue #235, B-47): this project-repo desk and an
operator's separately-configured, hardened `~/.cursor/mcp.json` fleet desk are
two different trust postures under the same product, and it's easy to "test
green" on the unhardened one while believing you've verified the hardened
one. If you need PGP enforcement or binding while developing this repo, set
those env vars in this file's `env` block yourself — willow-mcp intentionally
ships no default here, so an unconfigured clone fails closed on capability
grants rather than silently inheriting someone else's fleet trust.

**Version line.** willow-mcp is the **current substrate** the fleet consumes. It
sits at the head of a lineage of *distinct machines* — each its own spec, not
rebadges of one another:

- **`willow-1.7` → `willow-1.9`** — earlier production lines; `willow-1.9` is
  **archived** (April–May 2026 era).
- **`legacy fleet monolith`** — a distinct, larger-surface fleet server; now **legacy /
  migration source**, not the current stack (GitHub archive slug is historical).
- **`willow-mcp`** — the **current substrate**: a re-scoped re-implementation of
  the monolith's SOIL / knowledge / dispatch core.

willow-mcp re-implements that core as a standalone product with a redesigned,
smaller surface — **not** a drop-in copy of the archived monolith's tool API.
Many tools were renamed in the redesign (`soil_*` → `store_*`, `ledger_*` → `frank_*`,
`agent_task_*` → `task_*`), so an app is not portable between the two unchanged.
See [`docs/migrations/willow-2.0-gap-inventory.md`](docs/migrations/willow-2.0-gap-inventory.md)
for the verified tool-by-tool diff, and query `lineage_why` on the recorded atoms
(`version-willow-mcp`, `version-legacy-monolith`, `version-willow-1.9`,
`version-willow-1.7`) for the provenance.

> **Not the same "2.0".** The legacy *fleet monolith* above is the predecessor
> line. willow-mcp's own package version (e.g. "serve mode is **2.0.0+**" below)
> is this product's semver — unrelated.

## HTTP serve mode (OAuth)

> Serve mode is **2.0.0+**. Until the 2.0.0 release lands on PyPI, install from
> source (`pip install -e .` in a clone) to use it.

Beyond stdio, willow-mcp can run as an HTTP server that authenticates callers
with **OAuth 2.0 + PKCE** against Google or Apple as the upstream identity
provider. Signing in proves *who* a caller is; a separate, operator-controlled
**identity binding** step maps that identity to an `app_id` before any tool
permission applies. An authenticated-but-unbound caller is denied exactly like
an unmanifested `app_id` — fail closed, never fail open.

**1. Store provider credentials in the local vault** (secrets are prompted, so
they never land in shell history or a process listing):

```bash
willow-mcp setup --google-client-id "<client-id>"        # prompts for the secret
# or, for Apple:
willow-mcp setup --apple-team-id "<team>" --apple-client-id "<svc>" \
                 --apple-key-id "<kid>" --apple-p8-key-path ./AuthKey.p8
```

**2. Run the server:**

```bash
python3 -m willow_mcp --serve --port 8765 --host 127.0.0.1
```

`--port`/`--host` take precedence over `WILLOW_MCP_PORT`/`WILLOW_MCP_HOST`,
which take precedence over the defaults (`8765` / `127.0.0.1`). Point an HTTP
MCP client at `http://<host>:<port>/mcp`.

**3. First sign-in proposes a binding.** When a person completes the Google/Apple
approval flow, the server writes an **unconfirmed** binding to
`$WILLOW_HOME/mcp_apps/_identity_bindings/<issuer>__<subject>.json`:

```json
{ "issuer": "google", "subject_id": "…", "email": "you@example.com",
  "email_basis": "asserted", "app_id": null, "confirmed": false }
```

`email_basis` records how much downstream code should trust the email, because
IdPs differ: `asserted` (Google — present and IdP-asserted every sign-in),
`first_auth_only` (Apple — may appear only on the first authorization),
`relay` (Apple private-relay address that can stop forwarding), or
`unavailable`. If a bound identity's email later changes between sign-ins, the
binding is annotated with `email_drift` rather than silently updated.

**4. Confirm the binding (operator-only, local).** Confirmation is deliberately
*not* an MCP tool — a remote caller must never confirm its own binding. Run it
on the host that owns `$WILLOW_HOME`:

```bash
willow-mcp confirm-binding --issuer google --subject "<subject-id>" --app-id "<app_id>"
```

Only after this does the caller's session resolve to the manifest permissions
for `<app_id>` (see [Authorization](#authorization)).

### Turning serve mode on and off

Serve mode is a background process, not part of the stdio server — so it's
turned on and off on demand rather than by editing config each time.
`scripts/willow-serve` manages a systemd `--user` service for the `--serve`
process **and** toggles the matching http entry in `.mcp.json`, so an MCP
client connects to it only while it's on:

```bash
scripts/willow-serve install   # one-time: write + load the systemd user unit
scripts/willow-serve on         # start serve + add the .mcp.json entry
scripts/willow-serve off        # stop serve  + remove the .mcp.json entry
scripts/willow-serve status     # unit state + whether the entry is present
scripts/willow-serve logs        # follow the serve logs (journalctl)
```

After `on`/`off`, reconnect your MCP client (in Claude Code: `/mcp`) so it
picks up the changed `.mcp.json`. Port/host default to `8766`/`127.0.0.1`; set
`WILLOW_MCP_PORT` / `WILLOW_MCP_HOST` before `install` to change them. Claude
Code users get this as the [`willow-serve` skill](skills/willow-serve.md) —
just ask to turn serve mode on or off.

> If you already signed in once, `on` reuses your cached credential — no OAuth
> screen reappears unless it was cleared. That's expected, not a failure.

> **Serve mode does not inherit your shell environment.** The `systemd --user`
> unit is started by systemd, not by your interactive shell, so a `WILLOW_PG_DB`
> (or `WILLOW_STORE_ROOT`, `WILLOW_HOME`, …) you `export` in `.bashrc`/`.zshrc`
> **will not reach the serve process** — it falls back to the defaults in the
> [Configuration](#configuration) table. This bites env-based, non-default
> setups: the stdio server (launched from your shell) reads `willow_20`, say,
> while serve silently reads the default `willow`. Make the config reachable by
> the unit before `on`:
>
> ```bash
> # one-time: import current shell values into the systemd --user manager
> systemctl --user import-environment WILLOW_PG_DB WILLOW_STORE_ROOT WILLOW_HOME
> # …or, durably, drop them in a file systemd --user reads at login:
> #   ~/.config/environment.d/willow-mcp.conf  →  WILLOW_PG_DB=willow_20
> ```
>
> Then `scripts/willow-serve install` (regenerate) and `on`. Verify with a read
> tool over the serve endpoint: a `table_not_found` / `relation … does not
> exist` on data that stdio can see is the signature of this env gap.

### Installing standalone workers

`willow-mcp worker-service` manages separate fast and batch systemd user units.
It writes every required environment value into the units, so workers do not
inherit hidden legacy monolith paths or depend on shell exports:

```bash
willow-mcp worker-service install
willow-mcp worker-service status
willow-mcp worker-service uninstall
```

Install and uninstall never start or stop services. Uninstall refuses while a
worker is active; live state changes remain an explicit operator action. Before
starting either unit, apply `docs/schema/tasks-worker-production.sql` and
reconfirm the `tasks` mapping. The queue then isolates `fast`/`batch` claims,
records claim owner/time, recovers stale claims, applies bounded retries, and
timestamps terminal rows.

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `WILLOW_PG_DB` | `willow` | Postgres database name (serve mode won't see a shell `export` — see [serve env note](#turning-serve-mode-on-and-off)) |
| `WILLOW_PG_USER` | `$USER` | Postgres user (Unix socket auth) |
| `WILLOW_MCP_ENSURE_POSTGRES` | *(off)* | When `1`, `get_pg()` tries `pg_isready` and local `pg_ctlcluster` / `service postgresql start` before returning `postgres_unavailable` (#160) |
| `WILLOW_PG_CLUSTER` | `16/main` | Cluster passed to `pg_ctlcluster` when ensure-postgres runs (Debian-style installs) |
| `WILLOW_STORE_ROOT` | `~/.willow/store` | SQLite store directory — set to the legacy monolith's store root to share data |
| `WILLOW_MCP_FLEET_HOME` | *(unset)* | The fleet home this install claims to be **severed** from. Unset = no claim. See [Severance](#severance) |
| `WILLOW_MCP_FLEET_PG_DB` | *(unset)* | The fleet database this install claims to be severed from |
| `WILLOW_MCP_DISPATCH_MIRROR` | *(unset)* | Truthy on a **fleet host** to best-effort mirror dispatch packets into shared Postgres `dispatch_tasks` (so the fleet sees dispatches, like it already sees store/knowledge/tasks/agents). Off = filesystem-only; the filesystem packet is always canonical. See `docs/schema/dispatch_tasks.postgres.sql` |
| `WILLOW_APP_ID` | `willow-mcp` | Default app_id if not passed per-call |
| `WILLOW_HOME` | `~/.willow` | Root for manifests, vault, and identity bindings |
| `WILLOW_WORKER_LANE` | set by worker unit | Worker lane (`fast` or `batch`) |
| `WILLOW_WORKER_HEARTBEAT_ROOT` | `$WILLOW_HOME/worker_heartbeat` | Explicit worker heartbeat directory |
| `WILLOW_WORKER_STALE_SECONDS` | `1800` | Age after which an uncompleted claim is recovered |
| `WILLOW_MCP_HOST` | `127.0.0.1` | Serve-mode bind host (`--host` overrides) |
| `WILLOW_MCP_PORT` | `8765` | Serve-mode bind port (`--port` overrides) |
| `WILLOW_MCP_URL` | *(derived)* | Public base URL for OAuth issuer/callbacks in serve mode |
| `WILLOW_MCP_PYTHON` | *(searched)* | Interpreter used when wiring willow-mcp into a project (`onboard`/`project sync`) — falls back to a venv search, then `python3` |
| `WILLOW_MCP_ENFORCE_DB_PERIMETER` | *(off)* | When `1`, local Postgres access via a Kart task also needs an operator-signed envelope (`sign-db-task`), not just the `task_db` capability. See [`kart-tasks` skill](skills/kart-tasks.md) |
| `WILLOW_MCP_AUTHORITY_CHECK` | *(off)* | Enables the S1 authority-check seam for dispatch gating. Landing the module must not change live behavior until an operator opts in |
| `WILLOW_MCP_ENFORCE_MEM_RATIFY` | *(off)* | Master switch for the Article IV Canon-promotion gate on shared-KB writes. The gate's own `WILLOW_MEM_RATIFY_ENFORCE` (also off by default) must **also** be on before a denial actually blocks — either alone only logs advisory |
| `WILLOW_OWNER_SUBJECT_ID` | *(unset)* | `subject_id` treated as the consent owner (exempt from subject-consent grants). Unset = no subject is the owner — the strict, safe default |
| `WILLOW_SETTINGS_GLOBAL` | *(derived)* | Overrides the canonical fleet settings-file path — the file `consent.json` mirrors (see `docs/BUGS.md` B-30 if you're chasing a mismatch between the two) |
| `WILLOW_IN_KART` | *(unset)* | Set inside a Kart sandbox; blocks network-authorization signing and forces non-interactive CLI paths. Not meant to be set by hand |
| `WILLOW_MCP_TRUST_OWNER` | `willow-operator` | Trust-root unix user, used by `harden-trust-root` (see [Trust-root hardening](docs/OPERATOR-ONBOARD.md#trust-root-hardening-b-32)) |
| `WILLOW_MCP_RUNTIME_USER` | `$SUDO_USER` or caller | Explicit runtime-user override for trust-root setup |
| `WILLOW_MCP_EGRESS_CONFIG_DIR` | `~/.config/willow-mcp/egress` | Egress key/manifest directory |
| `WILLOW_MCP_EGRESS_SIGNING_KEY` | *(from manifest)* | Overrides the private key path used to sign egress manifests |
| `WILLOW_SEARCH_PROVIDER_ORDER` | `ddg_html` | Comma-separated web-search provider chain order |
| `WILLOW_SOIL_HEARTBEAT_INTERVAL` | *(subsystem default)* | SOIL watchman heartbeat interval, seconds. Per-watchman override: `WILLOW_SOIL_HEARTBEAT_INTERVAL_<KEY>` |
| `WILLOW_CODE_GRAPH_DB` | `$WILLOW_HOME/code_graph/graph.db` | Symbol/code-graph SQLite DB path |
| `WILLOW_ENVELOPE_REGISTRY` | `$WILLOW_HOME/constitutional/pre-approved.json` | Pre-approved envelope registry path |
| `WILLOW_SYSCALL_TABLE` | *(sibling of registry)* | `syscall-table.json` path |
| `WILLOW_FLEET_ROSTER` | *(derived)* | `fleet.json` roster path |
| `WILLOW_MCP_GROVE_RINGS` | `$WILLOW_HOME/grove/rings.json` | Grove ring-state store path |
| `WILLOW_MCP_SCHEMA_RINGS` | `$WILLOW_HOME/schema_rings.json` | Confirmed-schema-mapping cache path (see also `WILLOW_MCP_SCHEMA_RINGS_MAX`) |
| `WILLOW_SENTRY_DSN` | *(unset)* | Sentry DSN — unset means observability is fully disabled (fail-closed default); PII, breadcrumbs, and stack locals are scrubbed regardless |
| `WILLOW_SENTRY_ENV` / `WILLOW_SENTRY_RELEASE` / `WILLOW_SENTRY_TRACES` | `experiment` / `willow-mcp@experiment` / `0` | Sentry environment tag, release tag, trace sample rate — no-ops unless `WILLOW_SENTRY_DSN` is set |
| `SAP_SAFE_ROOT` | `~/.sap/Applications` | SAFE folder root |
| `SAP_PGP_FINGERPRINT` | *(empty)* | Pinned GPG fingerprint |

## Authorization

Manifest-based ACL, no external service or ACL database. Each `app_id`
needs a manifest at `$WILLOW_HOME/mcp_apps/<app_id>/manifest.json`:

```json
{"permissions": ["store_read", "knowledge_write"]}
```

`permissions` is a list of group names and/or literal tool names —
see `PERMISSION_GROUPS` in `src/willow_mcp/gate.py` for the authoritative set
(54 groups). Common ones: `store_read`, `store_write`, `knowledge_read`,
`knowledge_write`, `schema_admin`, `task_queue`, `agent_dispatch`,
`dispatch_read`, `dispatch_write`, `fleet_read`, `context`, `audit`,
`gap_read`, `gap_write`, `gap_promote`, `fork_read`, `fork_write`, `nest_read`,
`nest_write`, `integration_read`, `web_read`, `code_graph_read`,
`code_graph_write`, `grove_read`, `grove_write`, `full_access` — plus per-subsystem read/write groups for
lineage, friction, commitments, the human-loop, and MarkdownAI. Fail-closed:
no manifest, or an empty `permissions` list, denies every call for that
`app_id`. `gap_promote` is kept separate from `gap_write` — landing
something as trusted knowledge is a more consequential act than logging or
resolving a gap, the same reasoning `schema_admin` gets its own group
instead of folding into `knowledge_write`.

### PGP-enforced manifests (opt-in)

By default a manifest is trusted as whatever's on disk — anyone who can write
`mcp_apps/<app_id>/manifest.json` can grant that app any permission, or create
a new one and become any identity (issue #183). Set `WILLOW_PGP_FINGERPRINT`
to your operator key's fingerprint and this stops being true: `gate.py` denies
any manifest whose `manifest.json.sig` doesn't verify against that key —
missing, tampered, or signed by a different key are all treated exactly like
a missing manifest. Sign one with `willow-mcp sign-manifest <app_id>`
(interactive operator terminal only, same as `sign-net-task` — `gpg-agent` is
unreachable inside the Kart sandbox); re-sign after every edit, since a
changed manifest with a stale signature is denied too. See
`docs/design/pgp-and-persona.md` for the full design.

The MarkdownAI (mai) tools (registered only when `WILLOW_MCP_MARKDOWNAI=1`)
are additionally per-app gated (#153/#161): `markdownai_read` and
`markdownai_write` cover the file/render tools, and `markdownai_directives` —
deliberately outside `full_access` — unlocks the side-effectful
`@db`/`@http`/`@env` directives inside `render()`. Even with that grant:
`@db` connections must be allowlisted in the manifest's `"mai_connections"`
list and never default to the willow database; `@http` honors the operator's
`consent.internet` and reaches the network only through `web_fetch`'s guarded
path — the same destination check `willow_web_fetch` uses, which resolves names
before judging them and re-checks every redirect hop, rather than the hostname
blocklist it used to carry; and `@env` resolves only keys
named in the operator's `WILLOW_MAI_ENV_ALLOW` (comma-separated, default
deny), with credential-shaped keys never resolving at all.

### Grove — the fleet's shared messaging room

The 20 `grove_*` tools (`willow_mcp/grove_tools.py`, data layer
`willow_mcp/grove.py`) are the agent-side successor to the legacy monolith's
`sap/grove_tools.py`: they give an agent a voice in Grove, the fleet's shared
Postgres-backed chat (`grove.channels`/`grove.messages`/`grove.message_flags`
tables) — channels, threads, flags, a priority bus protocol, and
fleet-awareness reads (`grove_agents`, `grove_fleet_status`,
`grove_human_required`). Registered unconditionally, like the store/knowledge
tools, but gated per-app like every other tool here: `grove_read` (13 tools)
and `grove_write` (7 tools), or `grove_all` for both. Unlike `web_read` /
`integration_call` / `markdownai_*`, both ride `full_access`: Grove carries no
egress concern, same reasoning as `knowledge_read`/`knowledge_write`.

*Not to be confused with* `the_grove.py` / `python -m willow_mcp.the_grove`
above — that is an unrelated local SQLite rings-of-lessons store. This Grove
is the fleet's shared Postgres messaging room.

Every write tool's `sender` defaults to the calling agent's `grove_sender`,
resolved from the specialist registry (`willow_mcp.registry.specialist_row`) —
never the literal `"Auto"` the canonical legacy monolith tools defaulted to. An
agent posts as itself by default, and for free — `grove_write` alone covers
that. Posting as a *different* identity (relaying on another identity's
behalf) is a separate, sender-locked privilege: passing an explicit `sender`
that does not match the caller's own resolved identity is refused —
`{"error": "sender_forbidden", ...}`, before any DB write — unless the
caller's manifest also holds the `grove_relay` capability. `grove_relay` is
its own manifest line, deliberately excluded from `grove_write` and
`full_access` (same shape as `task_net`/`mcp_federation` below): a broad
Grove-write grant must never silently also grant impersonation. No seed seat
holds it (`bundle/config/specialists.json`) — it is reserved for a future
operator-granted bridge/relay seat.

**The DB-name trap:** Grove's tables live in the fleet's `willow_20` Postgres
database, not this server's default `willow` database (`WILLOW_PG_DB`). If
`WILLOW_PG_DB` is unset or still `willow`, every `grove_*` tool returns a
`grove_unavailable` error naming the fix rather than a raw driver traceback.
Set `WILLOW_PG_DB=willow_20` in the willow-mcp server's environment (and
restart it) to reach Grove.

There is also one **capability permission**, `task_net`, which is not a tool
name but a privilege flag: it lets an app *ask* for `task_submit(allow_net=True)`.
It is deliberately excluded from `task_queue` and `full_access` — network egress
from the sandbox must be granted explicitly, on its own line, and only host-side
(never authored from inside the sandbox). On its own it authorizes nothing: the
call also needs the operator's `consent.internet` and a live egress lease
(see [Egress needs three keys](#egress-needs-three-keys)).

### `store_scope` — confining an app to its own collections

By default, `store_*` tools are **unrestricted across collections** — and by
default the SOIL store is the wider Willow fleet's store (see
`WILLOW_STORE_ROOT` in [Configuration](#configuration) above), so an app with
`store_read`/`store_write`/`full_access` can see every collection any other
app or fleet process has written, the same way it always could. That's the
right default for a single-operator, single-trust-domain install, but it
means a `store_read` grant to one app is implicitly a grant to read every
other app's data too.

Sharing is a default, not a design commitment. An install that should be cut
off from the fleet can point `WILLOW_STORE_ROOT` at its own store and name the
fleet it is severed from — see [Severance](#severance) below, which turns the
cut into something `diagnostic_summary` checks rather than something the docs
assert.

An operator who wants an app confined to its own data adds an optional
`store_scope` array to that app's manifest:

```json
{"permissions": ["full_access"], "store_scope": ["myapp_*"]}
```

Patterns match by exact name, or by prefix if they end in `*`. With
`store_scope` set, `store_put`/`get`/`list`/`update`/`search`/`delete` reject
any collection outside it (`collection_denied`), and `store_search_all`
only searches the matching collections instead of every collection in the
store. Omit the field entirely for today's unrestricted behavior — an empty
list (`"store_scope": []`) means "no collections," not "unrestricted."

**A scope the gate cannot read denies everything.** If `store_scope` is present
but malformed — most likely `"store_scope": "myapp_*"`, a string where a list
belongs — the app is confined to *no* collections rather than granted all of
them. The same holds for an unreadable manifest or an invalid `app_id`. This is
deliberate: an operator who mistypes the field believes the app is confined, and
a policy that cannot be parsed is not consent. The app fails loudly, an `ERROR`
is logged naming the field and the type it got, and nothing leaks while the typo
is being found. Omit the field (or set it to `null`) to declare no policy.

In [HTTP serve mode](#http-serve-mode-oauth), the `app_id` is not taken from
the call — it is resolved from the caller's confirmed OAuth identity binding,
then checked against that same manifest ACL.

### `egress_secret_exempt` — letting a tool return a raw credential

Tool responses are scanned at a single funnel and any credential-shaped value
(a provider `sk-` key, an `AKIA…` id, a PEM private-key block, a GitHub/Slack/
Google/Stripe token, a JWT) is redacted to `[REDACTED:<kind>]` before it
leaves — the data-path half of "no tool ever returns a credential." A few tools
legitimately must return a raw token, the canonical case being an
`integration_call` that performs an OAuth token exchange. Name those tools in
the app's manifest:

```json
{"permissions": ["full_access"], "egress_secret_exempt": ["integration_call"]}
```

The scan still runs, so the audit trail stays complete: an exempted return is
kept raw but receipted as `credential_returned` (naming the kinds, never the
value), so the exception is loud rather than silent. Like `store_scope`, the
field **fails closed toward redaction** — a bad `app_id`, a missing/unreadable
manifest, or a malformed field (a string where a list belongs) exempts *nothing*
and an `ERROR` is logged. Because manifests are operator-side (the PreToolUse
hook blocks an app from writing its own), an app can never exempt itself. The
exemption is per named tool, never a blanket unlock.

## Severance

A willow-mcp install can share a Willow fleet's store, database, and trust root,
or it can be cut off from them. Both are legitimate. What is not legitimate is
*claiming* the cut and not having it — a server that reports `ok` while wired to
the fleet is worse than one with no check at all.

Severance is **asserted, never assumed.** Name the fleet you are severed from:

```bash
export WILLOW_MCP_FLEET_HOME=/home/you/github/.willow
export WILLOW_MCP_FLEET_PG_DB=willow_20
```

`diagnostic_summary` then reports a `severance` check over four surfaces:

| Surface | Kind | Violation |
|---|---|---|
| `store` | data | `WILLOW_STORE_ROOT` resolves inside the fleet home → `degraded` |
| `postgres` | data | `WILLOW_PG_DB` is the fleet database → `degraded` |
| `trust_root` | **authority** | `mcp_apps/` is inside the fleet home, or is writable by this process → `broken` |
| `egress` | **authority** | this process can forge the three-key network gate (strict trust root off, or the consent switch / lease root / egress verification key is self-writable) → `unknown` degrades, a forgeable key `breaks` |

The distinction is the whole design. Store and database hold **data**: someone
who writes them corrupts records. The `trust_root` and `egress` surfaces hold
**authority** — the manifest that grants `task_net`, the lease root, the consent
file, the egress verification key. Someone who writes *those* grants themselves
the egress the cut was supposed to deny. Only an authority surface can turn a
severed install into a compromised one, so only those two break the verdict; the
data surfaces merely degrade it.

Consequently the trust root must live somewhere neither this process nor the Kart
sandbox can write. A repo directory is the wrong place for it, however convenient:
repos are bound read-write into task sandboxes. Put data in the repo; put the gate
outside it, owned by a uid the agent does not run as.

Symlinks are resolved before comparison. `~/.willow` is frequently a symlink into
a fleet tree, and two names for one directory are not two directories.

Leave both variables unset and the check reports `not_asserted` and changes
nothing — a single-trust-domain install is complete without severance, and one
that never claimed to be cut off cannot be caught lying about it. Set one and not
the other and the unnamed surface reports `unknown`, which degrades: an
unverifiable claim is not a passing one.

## The companion layer

Not everything in the package is a gate. A few subsystems exist to carry the
*story* of an install — lessons, work-units, the shape of the collaboration —
and a `tools/` directory turns jobs a model was doing by hand into
deterministic scripts.

### The Grove — rings for lessons

`the_grove.py` is a rings store for lessons learned, sibling to
`schema_profile`'s vocabulary rings but unbounded on purpose: vocabulary may be
pruned cheaply; lessons are kept precisely so the deployment cannot become
something that forgets them.

```console
$ python -m willow_mcp.the_grove            # the resting display
The Grove is stable.
Current depth: 0 rings.
Soil health: Worth tending.

Next gardener: unknown.
Chapters remaining: as many as the rain requires.
$ python -m willow_mcp.the_grove --status   # pipe-friendly: stability, depth, soil health
```

`core.record_lessons()` distills any SQLite journal (the table holding the
writing is introspected, never assumed; the source is opened read-only) into
exactly one ring carrying the lesson worth keeping. A diseased rings file reads
as empty but reports the grove `unsettled` rather than silently claiming
depth 0.

### Forks — bounded work-unit tracking

The seven `fork_*` tools (`fork_create` / `fork_status` / `fork_log` /
`fork_list` / `fork_join` / `fork_merge` / `fork_delete`, under the
`fork_read`/`fork_write` permission groups) track branch + PR work-units as
durable SOIL records with an append-only change log — the same shape as gaps,
lineage, and the human-loop queue, deliberately *not* a fleet-Postgres table
(B-28's lesson: don't drag a schema migration into the shared database for a
bookkeeping record). `fork_merge`/`fork_delete` count atom/KB change-log refs
as promoted/archived bookkeeping.

### Friction floor — the mirror detector

`friction_scan` watches one thing: whether the agent has stopped being *other*
and is mirroring the user back, smoothed, **while the user is escalating**.
When a window of agent turns sits below the friction floor during escalation,
it raises a loud, human-facing flag — persisted and deduped;
`friction_flags_list` reads them back. It never blocks and never egresses: a
signal, not a verdict. It must be driven from outside the watched model — a
mirror cannot audit itself.

### `tools/` — take the job off the model

Deterministic harnesses for jobs a model was doing by hand — each turns
conversational labor into a script, so the next session runs the tool instead
of re-deriving the work. See [`tools/README.md`](tools/README.md) for the full
wiring; the cast:

| Script | Job it takes off the model |
|---|---|
| `wtool.py` | the substrate — call any of the server's tools from a shell (`--list`, JSON args), so *any* script can do what a model does through an MCP client |
| `mai_lint.py` | deterministic @markdownai format validation (also a CI step) |
| `mai_metrics.py` | record one metric per bite into SOIL; report the new-gaps-by-learnings convergence curve |
| `mai_prose_split.py` | the prose/structure pass for converting narrative docs to @markdownai — separates protected prose from directive candidates, and a `prose_ratio` verdict flags story-shaped docs "do not force" instead of mangling them |
| `provision_gate.py` | union permission groups into a gate manifest, validating every name against `gate.PERMISSION_GROUPS` — loud-fail on a typo instead of granting nothing |

## Hooks and skills (Claude Code)

`.claude-plugin/plugin.json` registers a `PreToolUse` hook and thirteen skills
for Claude Code users — install this package as a plugin to get them alongside
the MCP server itself. The hook is wired for four matchers (`Bash`,
`task_submit`, `Write|Edit|MultiEdit|NotebookEdit`, and `WebSearch|WebFetch`),
all routed through the same guard:

- **`hooks/pre_tool_use.py`** blocks `Bash` commands that reach for raw
  `psql`/`psycopg2`/`sqlite3` against a database or store willow-mcp owns,
  redirecting to the matching MCP tool instead. It also blocks any call that
  would write the keys authorizing the agent's *own* egress — minting a lease,
  running `grant-net`, or editing a manifest to add `task_net` — and warns on a
  `task_submit` that hand-embeds a `# allow_net` directive.
- The full skill set (13): `session-start`, `consent`, `worktree`,
  `handoff-write`, `external-guard`, `schema-confirm`, `willow-serve`,
  `kart-tasks`, `debugging`, `review`, `tdd`, `brainstorming`,
  `persona-overlays`. A few load-bearing ones:
- **[`skills/schema-confirm.md`](skills/schema-confirm.md)** walks through
  reviewing and confirming a table's schema mapping before writing to it.
- **[`skills/willow-serve.md`](skills/willow-serve.md)** turns OAuth serve mode
  on/off on request (see [above](#turning-serve-mode-on-and-off)).
- **[`skills/kart-tasks.md`](skills/kart-tasks.md)** covers submitting and polling
  Kart tasks, the three-key egress model, and worker liveness.

See [docs/design/hooks-and-skills.md](docs/design/hooks-and-skills.md) for
the design and the reasoning behind shipping these alongside tools rather
than as a later add-on.

## License

Apache-2.0 — Sean Campbell 2026
