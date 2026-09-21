---
kind: doc
name: design-hooks-and-skills-ship-alongside-tools-not-after
description: "Design rule for willow-mcp: any new tool surface with a footgun or a multi-step human workflow ships its hook and/or skill in the same PR as the tool — covers the plugin packaging shape, the pre_tool_use.py contract, and the schema-confirm.md skill."
---

@markdownai v1.0

# Design: Hooks and Skills Ship Alongside Tools, Not After

Status: DRAFT — first hook + skill landing with this doc; not yet ratified as
a hard process rule, but intended as one.

@phase 1-problem-statement
## 1. Problem statement

`willow-mcp` ships MCP tools with nothing that teaches an agent — or a human
— how to use them correctly. Two concrete gaps existed before this change:

1. Nothing stops an agent from reaching for raw `psql`/`psycopg2`/`sqlite3`
   against the databases willow-mcp owns (`WILLOW_PG_DB`, `WILLOW_STORE_ROOT`)
   instead of the MCP tools. The fleet this package grew out of solves this
   with a hook; a standalone `pip install willow-mcp` gets none of that
   protection.
2. `schema_confirm_mapping` (docs/design/schema-adaptation.md §3.4) landed as
   a raw tool call with no guided workflow. A new adopter pointing willow-mcp
   at their own database has to hand-write a JSON `overrides` dict against a
   heuristic mapping they've never seen rendered — exactly the audience the
   schema-adaptation design exists to help, given the worst experience.

Both gaps share a root cause: hooks and skills were never part of "done" for
a tool. This doc makes them part of "done" going forward.

@phase 2-the-rule
## 2. The rule

**Every new tool surface that has a footgun (a wrong-but-easy way to use it)
or a multi-step human workflow (confirm a mapping, set up OAuth) ships its
hook and/or skill in the same PR as the tool.** Not a follow-up PR, not a
"someone should write a skill for this" note. If a tool doesn't need either
— most read tools don't — that's fine, nothing is required.

Two tools already shipped without this (PR #10's read-path tools needed
neither; PR #11's `schema_confirm_mapping` needed a skill and didn't get
one). This doc and its companion PR close that gap once, and the rule
applies from here on.

**Addendum (2026-07-08):** the rule then broke again — the task-queue surface
(`task_submit` + the `task_net` capability, B-19; the `# allow_net` directive
footgun, B-21/L-NET-01) shipped with neither skill nor hook, exactly the
footgun-plus-workflow case §2 describes. Closed retroactively: `skills/kart-tasks.md`
(submit/poll workflow, the `task_net`/`allow_net` model, the worker-liveness
caveat) and a `task_submit` matcher on `pre_tool_use.py` that warns when a
caller hand-embeds a stripped network directive. Logged as B-23. The lesson
stands: the rule is only real if it's checked at PR time, not remembered.

**Addendum (2026-07-09):** the rule held this time. B-32's egress leases
(`willow-mcp grant-net`, `lease.py`) shipped in the same PR as their guardrail:
a `Write|Edit|MultiEdit|NotebookEdit` matcher on `pre_tool_use.py`, plus a Bash
matcher, that **blocks** any call writing a key which authorizes the agent's own
egress — minting a lease under `mcp_apps/_net_leases/`, invoking `grant-net`, or
editing a manifest to add `task_net`. `skills/kart-tasks.md` gained the three-key
model in the same change. Note what the hook is and is not: it lives in the
agent's own harness, so it is a **guardrail, not a control** — the control is
`chown` plus `WILLOW_MCP_STRICT_TRUST_ROOT` (B-32 / L-NET-02). A hook that blocks
the crossing makes a mistake catchable and a deliberate crossing undeniable; it
does not make the crossing impossible, and the docs must never let it read that
way.

@phase 3-packaging-shape
## 3. Packaging shape

Bundled inside `willow-mcp` itself (not a separate plugin repo) — one
`pip install willow-mcp` gets the server, the tools, and the guardrails/
workflows together, matching "written alongside the tools." Modeled on the
Fylgja plugin layout already in use elsewhere in this operator's fleet, so
it's a familiar shape rather than a new convention:

```
willow-mcp/
  .claude-plugin/
    plugin.json          # registers hooks + skills for Claude Code
  hooks/
    pre_tool_use.py       # PreToolUse — guards + redirects
    tests_helpers ...      # pure functions, unit-tested directly
  skills/
    schema-confirm.md      # guided schema_confirm_mapping workflow
  src/willow_mcp/           # MCP server (unchanged)
```

`plugin.json` is what a Claude Code user's `.mcp.json`/plugin config points
at to pick up both the MCP server *and* the hook/skill layer in one install
step; a user of a different MCP client (Cursor, a custom agent) is
unaffected — they just don't get the Claude Code-specific hook/skill layer,
same as they already don't get any client-specific integration today.

@phase 4-pre-tool-use-py-contract
## 4. `pre_tool_use.py` contract

Implements Claude Code's `PreToolUse` hook protocol: reads a JSON object
from stdin (`{"tool_name": ..., "tool_input": {...}, "session_id": ...}`),
optionally prints a JSON decision to stdout (`{"decision": "block"|"warn",
"reason": "..."}`), always exits `0` — the decision is communicated via the
printed JSON, not the exit code. No output means "allow, no comment."

Scope for this pass: `Bash` commands that reach for `psql`, `psycopg2`, or
`sqlite3` against a path/dbname willow-mcp owns (`WILLOW_STORE_ROOT`,
`WILLOW_PG_DB`, or the literal `knowledge`/`records` table names) get
`decision: "block"` with a message naming the matching MCP tool
(`store_*`/`knowledge_*`/`kb_*`/`schema_confirm_mapping`). Everything else
is unmatched and allowed silently — this hook is a narrow guard, not a
general security scanner (willow-mcp already has one of those, in
`server.py`'s `_sanitize`/`_guarded` pipeline, which runs inside the MCP
server itself and applies regardless of which client is calling it).

Deliberately out of scope for this pass, left for the next hook/skill that
actually needs them:
- A `PostToolUse` hook reacting to an `unconfirmed_schema` error by
  suggesting `schema_confirm_mapping` — useful, but the read/write tools
  already return a self-describing error message naming the exact next
  call; a hook doing the same thing adds a second place that message can
  drift from the tool's own text. Revisit if the plain error text proves
  insufficient in practice.

  **Reaffirmed (2026-07-31):** checked, not just remembered. `server.py`'s
  `_require_confirmed()` still returns exactly `"unconfirmed_schema: table
  '<table>' has not been confirmed for this database — call
  schema_confirm_mapping, or edit the mapping file directly, then retry"` —
  the message and the code path are unchanged since this was written.
  Searched the gap backlog, CHANGELOG, and every handoff for a report of an
  agent stuck on or confused by this error; found none. Nothing has changed,
  so the rejection stands.
- Blocking non-Bash paths to the same databases (e.g. a Python one-liner
  tool) — `Bash` covers the common case; broadening the match surface is
  cheap to add later if a real gap shows up, not worth guessing at now.

  **Closed (2026-07-31):** a real gap showed up, and it's a more direct
  bypass than the one this named — a `Write`/`Edit`/`MultiEdit` targeting a
  willow-mcp-owned SQLite store file (`store.db`/`vault.db`/`kart.db`/
  `mcp_receipt.db`) directly needs **no DB client at all**, so `_CLIENT_RE`'s
  command/script-text scan never sees it; every existing guard on the
  Write/Edit path (`check_trust_root_write`) only watches lease/keystore/
  manifest targets, not the store files themselves. Added
  `check_owned_db_file_write()`, matched on filename (not resolved real
  path, so a relative or symlinked target is still caught) and wired
  alongside `check_trust_root_write` in the same `Write`/`Edit`/`MultiEdit`
  branch. Postgres has no local file to write into, so this is SQLite-only —
  the Bash-scoped raw-client guard is still the only coverage there, which is
  correct: reaching Postgres without a client isn't a thing. Tests pin both
  the block side (the four exact filenames) and the allow side (substring
  traps like `restore.db`/`backup_store.db`/`store.db.bak`, verified this
  doesn't regress to a bare-substring match), plus an end-to-end `main()`
  case in each direction.

**Addendum (2026-09-20):** sealed rule `c9ca1a09` (pair `72f528ab`, record
`b4a8cbe7`, gap `20e6d23971dc`) closed the "the fleet does not self-assign
models" guarantee in `specialists.json`'s `model_hint_session` field: nothing
enforced it at the point a specialist is actually spawned via the harness
`Agent` tool, so a caller could open `hanuman` under a heavier or lighter
model than its role is pinned to and nothing would say so. Added
`check_agent_spawn()`, wired to a new `Agent` `PreToolUse` matcher across all
three wiring configs (`plugin.json`, `deploy/claude-settings.json`,
`.claude/settings.json` — kept in step by `test_hook_wiring_sync.py`'s
existing matcher-parity pin). Detection is prompt-text only — a spawn prompt
naming a seat via `session_enter(app_id="<seat>"`, a bare `app_id=<seat>`, or
"You are `<Display name>`" — matched against `config/specialists.json`
(new bundle config `config/spawn_models.json` maps role → required session
model, currently `{"builder": "sonnet", "auditor": "opus"}`; a role absent
from the table is unconstrained by this guard). Three refusals, always a
block: the orchestrator seat (`willow`) as a spawn target at all;
`subagent_type="fork"` naming any specialist seat, because a fork inherits
the caller's model and cannot carry a pin; and a pinned-role seat spawned
with no `model` or the wrong one. Both loaders (`_load_specialist_rows`,
`_load_spawn_models`) are stdlib-only `open()`/`json.load()` reads at call
time, same fail-safe shape as `_load_remote_posture` above — no new imports,
and a missing/malformed config degrades to a literal fallback set rather
than silently disabling the guard for every seat (the reason text says so
when that happens).

@phase 5-schema-confirm-md-skill
## 5. `schema-confirm.md` skill

A guided walkthrough for the human/agent workflow the design doc's §3.2
mapping artifact implies but doesn't script:

1. Preview the mapping with `schema_confirm_mapping(table=..., preview=True)`
   — a read-only dry-run (added for issue #20) that returns the proposed
   mapping *and* a rendered `sample` row showing what each canonical field
   actually resolves to, writing nothing. Reviewing the sample is the whole
   point: a name match is an assertion, not evidence — a `content` column
   that is really a provenance blob (with the real text in `title`/`summary`)
   only reveals itself in the sample, not in the field names.
2. Show the guesses field-by-field *against the sample values*: which are
   `exact`, which are `alias` (name the aliased column), which are
   `unmapped` — and flag any field whose sample value is clearly the wrong
   data as an override to correct, not a mapping to accept.
3. Ask the human to accept each guess or supply a correction (or explicit
   "leave unmapped").
4. Call `schema_confirm_mapping` once with the accumulated overrides.
5. Confirm the result and note which write tools are now unlocked for that
   table.

This intentionally does not let the skill silently call
`schema_confirm_mapping` with zero overrides just to "get it working" —
confirming a mapping is a human decision (design doc §3.4/§8: gated more
strictly than a single write for exactly this reason), and the skill's job
is to make that decision well-informed, not to skip it.

**Addendum (2026-07-31):** revisited whether `check_native_web`'s hard block
(native `WebSearch`/`WebFetch`) should soften to a warn now that `willow_web_*`
has shipped and settled — it's the only guard in the module gating a
*capability* rather than an authority boundary, which made it worth checking
rather than assuming. It stays a block: the native tools aren't a worse style
of the same action, they're a different channel that skips every check the
MCP path enforces. `willow_web_fetch`/`willow_web_search` go through
`web_egress.egress_denial()` (the three-key gate — `web_net` + `consent.internet`
+ a live lease), and `web_fetch.fetch_url` additionally rejects private/loopback
hosts (SSRF) and wraps fetched content in the sandwich defense against prompt
injection. A warn would let an agent route around egress governance and SSRF
protection with one more tool call, not merely reach for a less-preferred one.
Recorded in `check_native_web`'s docstring so the reasoning doesn't have to be
rediscovered next time this is questioned.

**Addendum (2026-07-31):** decided the script-indirection guard's open
depth question — one level (current) vs. recursing into a script that a
script invokes. Staying at one level. The threat model is an agent reaching
for a raw client out of habit, and a habit doesn't produce a two-hop
indirection chain; writing one takes deliberate effort, which is already the
"no OS-level obstacle" case the module's docstring disclaims — B-32 is the
durable control for a deliberate crossing, not a deeper regex. Catching a
second hop would also mean recursively re-running the same brittle
command-text heuristic against the second script's source, compounding a
regex-based guess for a case outside what a tripwire owes. Pinned by
`test_check_bash_allows_a_two_level_script_chain`, which also asserts the
would-be-caught case really would be caught if invoked directly — otherwise
the test proves nothing.

**Addendum (2026-07-31):** built the mutation harness §3/§4 of the
2026-07-30 handoff asked for and that did not exist anywhere in the repo —
`tools/hook_mutation_check.py`, running the six specific per-guard mutations
that handoff named (not "delete the hook," the same too-coarse mistake as
renaming a SQL trigger instead of disabling it). First run found three real
gaps, not hypothetical ones:

- `_OWNED_MARKER_RE` losing its `WILLOW_STORE_ROOT` alternative changed no
  test's outcome, because the one fixture using it also contains the literal
  word `records` — a second, independent marker — so the fixture was
  over-determined the same way `test_check_bash_routing_allows_git_gh_inspect`
  already was.
- The `cd X && python3 y.py` script-indirection form had an allow-side test
  (a benign script survives it) but no block-side one — nothing ever invoked
  an actually-malicious script through that form.
- `check_native_web` had a block-side test for `WebSearch` but none for
  `WebFetch` — only allow-side coverage existed for it.

All three closed with new tests (`test_check_bash_blocks_on_willow_store_root_alone`,
`test_check_bash_blocks_a_malicious_script_via_the_cd_form`,
`test_check_native_web_blocks_webfetch` + `test_main_blocks_native_web_fetch`);
a second harness run confirms all six mutations are now caught. Same lesson
as the 2026-07-30 allow-side pass, found by the same method, one level up:
build the thing that goes looking, rather than trust that the last look was
enough.

**Addendum (2026-07-31, later the same day):** a UX audit found this hook
blocking its own project's documented onboarding path — `scripts/sandbox-
bootstrap.sh` (the README's one-command setup) trips `_script_reaches_owned_
store`, because it legitimately creates the Postgres database and applies
schema before any MCP tool exists to call instead, and its own source
contains both a raw `psql` invocation and `WILLOW_PG_DB`. A scan of
`scripts/` found 16 other files in the same position (diagnostics/
ratification/reconstruction tooling) — not an isolated case.

Fixed by exempting `scripts/` itself, not by allowlisting individual files
(too high-maintenance, and would keep missing new ones) and not by a marker
comment inside a script (weaker than the status quo — any agent-written
file could add the same comment and self-exempt). A path check anchored on
`CLAUDE_PROJECT_DIR`/cwd is closer to the actual distinction that matters: a
script already committed under `scripts/` went through the same review this
hook file did, which is a different trust class from an agent writing a new
script in the working tree mid-session — the actual thing this guard exists
to catch. Still a tripwire, not a control: an agent that edited one of these
files first could ride the exemption too, and the durable answer to that is
B-32, same as everywhere else in this module. Pinned by four new tests,
including one against the real `scripts/sandbox-bootstrap.sh` file rather
than only a fixture standing in for it.

**Addendum (2026-07-31):** closed the handoff's open "any `SessionStart`
hook change?" question — no action. Two separate `SessionStart` hooks exist:
`willow_mcp.session_start_hook` (packaged, bridges a supported client's
native event to `session_enter()`) and this repo's own
`.claude/hooks/session-start.sh` (dev-sandbox bootstrap only — venv,
Postgres, a Kart worker, a generated `.mcp.json`; never calls `session_enter`).
First read was "dogfooding gap," but `skills/session-start.md` says plainly
"Hooks are optional; this skill is mandatory" — an agent is expected to call
`session_enter` itself regardless of what the client's hook layer does, so
the divergence is working as designed.

The one candidate idea considered — inject a condensed hook/guard-surface
summary into `session_enter`'s orientation, so a session doesn't have to
re-derive "what's the current hook surface" the way this handoff's own §1
had to — doesn't earn its place: `session_enter()` already returns
`latest_handoff`, which delivers exactly that (this session found the
2026-07-30 handoff by grepping `docs/handoffs/`, but `latest_handoff` would
have surfaced the same document directly). Adding a second, hand-maintained
path to the same information is the duplicated-source-of-truth mistake this
doc's addenda have flagged repeatedly today — the over-determined test
fixtures, "counts in prose," the two hook copies gated by one test. It would
also add orientation noise to every session entering this project, not only
ones about to touch hooks. No code change.


**Addendum (2026-07-31):** closed the #220 deferral for missing skills on
`gap_promote`, `fork_delete`, `human_required_*`, `frank_append`, and
`knowledge_flag` / `knowledge_retract` — shipped `skills/gaps.md`,
`skills/forks.md`, `skills/human-required.md`, `skills/frank.md`, and
`skills/knowledge-curate.md` (bundled copies kept identical per
`tests/test_skills_sync.py`). Also trimmed stale B-32/B-28 narratives from
`docs/BUGS.md` Open section (both are Fixed in the summary table).

**Addendum (2026-07-31, item G):** built the counts-in-prose lint the
2026-07-30 handoff's question 8 asked about — `tools/counts_in_prose_lint.py`,
wired into the suite via `tests/test_counts_in_prose.py`. Didn't have to
invent a test case: checking it against this repo's own live claims found it
had already happened, silently — "`_guarded` wraps 109 tools" in three files
(`request_context.py`, `server.py`, `test_request_context.py`) and "103
tools" in two spots in `tools/README.md`, both stale (real counts: 103
`_guarded`-wrapped, 105 registered). Fixed all five. Scoped deliberately
narrow: a registry of specific (file, claim, real-value-function) entries,
not a general number-scanner — CHANGELOG.md/BUGS.md/handoffs/migrations state
a count as of a past moment on purpose (archive, don't delete), and flagging
those would be noise, not a guard, the same distinction this doc's own
addenda keep drawing between a live claim and a historical record.

@phase constraints
## Constraints

@constraint severity="critical"
**Addendum (2026-07-09):** the rule held this time. B-32's egress leases
(`willow-mcp grant-net`, `lease.py`) shipped in the same PR as their guardrail:
a `Write|Edit|MultiEdit|NotebookEdit` matcher on `pre_tool_use.py`, plus a Bash
matcher, that **blocks** any call writing a key which authorizes the agent's own
egress — minting a lease under `mcp_apps/_net_leases/`, invoking `grant-net`, or
editing a manifest to add `task_net`. `skills/kart-tasks.md` gained the three-key
model in the same change. Note what the hook is and is not: it lives in the
agent's own harness, so it is a **guardrail, not a control** — the control is
`chown` plus `WILLOW_MCP_STRICT_TRUST_ROOT` (B-32 / L-NET-02). A hook that blocks
the crossing makes a mistake catchable and a deliberate crossing undeniable; it
does not make the crossing impossible, and the docs must never let it read that
way.
