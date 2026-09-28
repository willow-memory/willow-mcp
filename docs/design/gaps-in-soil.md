---
kind: doc
name: design-gaps-in-soil-first-class-records-indexed-and-edged
description: "Design for gaps as ordinary SOIL records with typed, deterministically written edges (names_file, names_symbol, cites, closed_by, recurs, ruled_by) and bounded views; one confirmation call is the only judgment in the path. Dispatch AC4E4457."
---

@markdownai v1.0

# Design: gaps in SOIL — indexed and edged

Status: **PROPOSED** (design only; no implementation). Dispatch AC4E4457, Vishwakarma.
Base: willow-mcp `origin/master` at `c6eb20a` (2026-09-27T23:56-06:00). Every
`file:line` below is against that tree unless it names another repo.
Supersedes nothing; extends [`gap-backlog.md`](gap-backlog.md) (the shipped
backlog, PR #54), whose three-state lifecycle `open → resolved → promoted`
stays exactly as it is.

The operator's ask, 2026-09-28: gaps "properly moved to the soil store, so it
can be indexed and edged properly", and "99% of this can be run
deterministically… a model doesn't need to do most of this work, as far as
reading and reporting the gaps to the agent."

@phase 0-where-things-stand
## 0. Where things stand (verified)

| Claim | Verified at | Verdict |
|---|---|---|
| Gaps live in the SOIL collection `gaps` through `db.Store` | `gaps.py:31-32` | True. The store is per-collection SQLite with soft-delete (`db.py:178-189`, `db.py:643-652`). |
| They are walled off: own verbs, own module, no edges | `server.py:2493-2665`; `gaps.py` has no edge code | True. And `store_get`/`store_search` cannot reach them: `gaps` sits outside every seat's `store_scope` (docstring `server.py:2540-2543`; e.g. willow-bot's scope is `willow_bot_ci_deposits`, `idea_landings` only, `bundle/config/seats/willow-bot.manifest.json:100-103`). |
| Id = uuid5 of `topic \| sorted stopword-stripped token set` | `gaps.py:67-69` | True. |
| Different wording never bumps `asked_count`; siblings split | backlog read 2026-09-28 | True in substance, wrong in the counts — see §0.1. |
| `lineage_link` exists and its docstring names "an atom `motivated_by` a gap" | `server.py:1637-1648`, `lineage.py:124-131` | True. |
| Nothing writes gap edges | no gap-aware writer in `src/` | True. Also: `lineage`/`lineage_edges` are only in the `willow` seat's `store_scope` (`bundle/config/specialists.json`, willow entry), and `lineage_link` checks both collections (`server.py:1578-1585`) — so the steward **could not** write an edge through it today. |
| Gaps close only through a `Gap-Id:` trailer the steward reads | willow-bot `tick.py:3011-3130` | **Wrong.** `gap_resolve` is a public verb any `gap_write` holder calls (`server.py:2548-2554`); `gap_promote` closes too (`server.py:2619-2665`). The steward's path is one caller of `gap_resolve`, it sets `resolved` (not a terminal state), and it knows a **commit** (`merged <repo>@<sha>`, `tick.py:3109-3116`), never a PR or a dispatch. |
| Nothing re-checks old rows; 158600e03598 still open though `unit_status` shipped | `gap_get 158600e03598` → `open`; `server.py:6091-6092`; merge `0881a63` "#654 feat/unit-status-read" | True. |
| Nothing puts gaps in front of whoever is about to touch the code | `boot_context.py:137-167` | **Partly wrong.** Session boot already injects the top open gaps by `asked_count`. What is missing is *path-scoped* surfacing. The boot path also swallows every failure into "no section" (`boot_context.py:166-167`), which merges unreachable with empty and breaks INVARIANTS §1. |
| 07aa99036f09 went unseen while ratatosk #60 rewrote the listener template | `gap_get 07aa99036f09` → `open`, topic `ratatosk/listener-home-pin-tests-and-crown-mcp-guard`; ratatosk `3a4e9d3` "(#60)" | The row and the commit exist. That #60 touched the pinned template was taken from the brief; only the commit subject was checked. The gap text names **no file path**, which constrains §4.2. |

### 0.1 The sibling rows, counted

- `governance/ambient-artifact-resolution`: **7 rows** (3 open, 4 resolved), not 2.
  Each is logged as "Third instance…", "Fourth instance…" and cites
  `006e0144da95` in its text.
- `willow-bot/tests-write-into-the-live-steward-journal`: 2 rows (`0949e89d41ac`,
  `08901eb5a508`: "Same class, third artifact"). Correct.
- `nestor-ui`: 3 open rows under the exact topic (`0972c8d85884`,
  `10374e87f571`, `4fddc96dba8d`), plus `nestor-ui/*` and `nestor-ui-*` siblings.

The lesson changes the design. Most of these siblings are not dedup misses.
Agents *deliberately* log each instance and cite the parent by id in prose.
The relation is already stated. It is just not captured. A `cites` edge plus
an instance marker makes a strong candidate for `recurs` (§3), and it is
stronger than any similarity score.

### 0.2 Two facts that constrain the writers

1. **A soft-deleted id is a permanent tombstone.** `Store.put` upserts without
   touching `deleted` (`db.py:232-265`). Re-putting a deleted id writes data
   that stays invisible. `lineage_edges` uses composite ids
   `from::relation::to` (`lineage.py:72-79`). Revoking an edge with
   `store_delete` would therefore make that edge impossible to assert again.
   **Revocation must be a state change on the edge row, never a delete.**
2. **The broker cannot call codebase-memory-mcp.** That is a separate MCP
   server that a *client* talks to. willow-mcp has its own in-process symbol
   graph, `code_graph` (`server.py:8458-8468`, default
   `$WILLOW_HOME/code_graph/graph.db`). But its schema carries no repo column
   (`code_graph/schema.sql:4-22`), so one DB cannot hold two projects without
   path collisions. The deterministic writer therefore resolves files against
   the project registry's checkouts (`mcp_projects.project_paths`) and symbols
   against a per-project `code_graph` DB. codebase-memory-mcp stays the
   *seat-side* read tool (and the seat-side `detect_changes` cross-check), not
   the writer of record.

@phase 1-record-shape
## 1. Record shape

A gap stays in collection `gaps` and keeps its id (`gaps.py:67-69`). The
record stays the *fact of the ask*. Every relationship moves to edges.

```json
{
  "kind": "gap",
  "schema": 2,
  "topic": "ratatosk/listener-home-pin-tests-and-crown-mcp-guard",
  "question": "…",
  "status": "open",
  "asked_count": 1,
  "first_asked_at": "2026-09-28T03:57:27Z",
  "last_asked_at": "2026-09-28T03:57:27Z",
  "promoted_to": null,
  "resolution_note": null,
  "topic_history": [],
  "logged_by": "loki",
  "links": {
    "version": 1,
    "indexed_at": "2026-09-28T…Z",
    "inputs": {"ratatosk": "3a4e9d3…"},
    "unlinked": [{"token": "crown --listen", "reason": "not_a_path"}]
  }
}
```

**Stays in the record:** `topic`, `question`, `status`, `asked_count`, the two
timestamps, `promoted_to` (the `gap_promote` gate reads it,
`server.py:2645-2646`), `resolution_note`, `topic_history`. New fields:
`kind`/`schema` (so `store_search` hits are self-describing), `logged_by` (the
caller's `app_id`; legacy rows read `null`), and `links`. `links` is the
linker's own bookkeeping: its version, the checkout HEADs it resolved against,
and a bounded list (≤10) of tokens it could not link, each with a reason.

**Moves to edges:** every *relation*: files and symbols named, ids cited, what
closed it, what it recurs with, and which ruling answers it. `resolution_note`
is kept as it is written today. The steward's `merged <repo>@<sha>` note
*also* yields a `closed_by` edge (§2), so nothing has to parse the note later.

**Edge store.** Collection `gap_edges` holds the same `{from, to, relation,
context}` row as `lineage_edges`, and uses the same composite id
(`lineage.py:72-79`). It reuses the parametrised class
`Lineage(store, nodes="gaps", edges="gap_edges")` (`lineage.py:66-69`). It is a
separate collection because `lineage._all_edges` is a full scan sized for "this
willow's own provenance" (`lineage.py:81-85`). Gap edges would inflate every
`lineage_why`. Rows add:

```json
{"from": "gap:07aa99036f09", "to": "file:ratatosk:deploy/…template",
 "relation": "names_file", "context": "match=…",
 "state": "live", "writer": "linker@1", "evidence": "question[212:258]",
 "created_at": "…", "updated_at": "…"}
```

`state` ∈ `live | proposed | confirmed | rejected | revoked`. Only `recurs`
uses `proposed/confirmed/rejected`. `writer` names who owns the edge (§2.1).

**Node-id grammar** (one prefix per kind, so a `to` is never ambiguous):
`gap:<12hex>` · `file:<project>:<repo-relative path>` · `sym:<project>:<fqn>` ·
`dispatch:<8HEX>` · `pr:<org>/<repo>#<n>` · `commit:<project>@<40hex>` ·
`pair:<nestor pair id>`. An inbound `motivated_by` from a lineage atom stays in
`lineage_edges` with its bare 12-hex `to` (`lineage.py:111-118`). The gap views
join it read-only, so nothing existing is rewritten.

**Three-state on every read (INVARIANTS §1).** Every gap read returns
`{state: "populated" | "empty" | "unreachable", …}`. `Store.get` returning
`None` is *absent* (`db.py:273-289`). A raised `sqlite3` error is
*unreachable*, reported with its reason and never folded into `[]`. This
applies to the new views, to `gap_get`, and to `boot_context._gap_lines`, which
today returns `[]` on any exception (`boot_context.py:166-167`). The migration
is two-state per row: a gap is *linked*, or *linked with an unlinked
remainder*, and the remainder is always printed.

@phase 2-edge-vocabulary
## 2. Edge vocabulary

All edges run **from the gap**, except `recurs`, which runs gap → gap. Direction
is queried, never stored twice (`lineage.py:20-25`). Every writer is regex, a
filesystem or SQLite lookup, or an explicit verb call.

| Relation | From → To | Writer (deterministic) | Idempotent because | Revoked by |
|---|---|---|---|---|
| `names_file` | gap → `file:` | **linker**: path regex over `topic + question` (`[\w.-]+(?:/[\w.-]+)+\.(py\|js\|ts\|md\|json\|sh\|toml\|ya?ml\|sql\|service\|template)(?::\d+)?` plus bare `name.ext`). Project comes from an explicit repo token in the text, else the topic's first segment if it is a registry project. Linked only if `(project_root / path).is_file()` at the recorded HEAD. A bare filename is linked only if exactly one file in that project matches. | composite id; re-link writes the same row | linker re-derivation (writer-owned, §2.1), or `gap_edge_revoke` |
| `names_symbol` | gap → `sym:` | **linker**: identifier regex (backticked, `a.b`, `name()`, snake_case with `_`, or CamelCase, ≥4 chars), resolved by exact name in that project's `code_graph` DB. Linked only if exactly one fqn matches. `context` carries `file=<path>` so the path view needs no graph read. | composite id | same as `names_file` |
| `cites` | gap → `gap:`/`dispatch:`/`pr:` | **linker**: `\b[0-9a-f]{12}\b` → gap if `Store.get("gaps", id)` exists (12-hex also matches envelope ids, e.g. "envelope 2542e8cded0c" in 3d9dc9545d95, so existence is required). `\b[0-9A-F]{8}\b` with at least one digit → dispatch if `$WILLOW_HOME/dispatch/<ID>` exists. `[\w.-]+/[\w.-]+#\d+` → PR, kept with `context=unverified` (no network in the path). A bare `#N` becomes a PR only if the topic pins a project whose registry entry names its GitHub slug. | composite id | linker re-derivation, or `gap_edge_revoke` |
| `closed_by` | gap → `commit:` (later `pr:`, `dispatch:`) | **`gap_resolve` itself**, server-side: when `note` matches the steward's exact shape `^merged (\S+)@([0-9a-f]{40})$` (`tick.py:3115`), it writes `gap:<id> closed_by commit:<repo>@<sha>`. The steward is unchanged and needs no new scope. A later bite reads `Gap-Id:` lines from `handoff_write_v4` for `dispatch:` targets. | composite id per (gap, sha); the steward's own state file already dedups per (gap, `repo@sha`) (`tick.py:3108-3112`) | `gap_edge_revoke` only. A false close is revoked by an explicit act, never inferred. |
| `recurs` | newer gap → older gap (by `first_asked_at`, tie → smaller id) | **proposed by the linker** (§3) with `state=proposed`. **`gap_recurs_decide`** is the only verb that moves it to `confirmed` or `rejected`. | composite id. The linker only creates an edge that is absent, and never touches a `recurs` row whose state is not `proposed`, so a rejection is permanent. | `gap_edge_revoke` (confirmed → revoked) |
| `ruled_by` | gap → `pair:` | **linker**: `\b(?:sealed\|pair\|decision\|ruling)\s+([0-9a-f]{8})\b`, resolved read-only against the Nestor DB that `seal_handler._nestor_db_path` names (`seal_handler.py:53-62`). Linked only if exactly one pair matches the prefix **and** it is sealed. A draft pair goes to `links.unlinked` with reason `unsealed`. | composite id | linker re-derivation (a pair later unsealed or superseded drops out), or `gap_edge_revoke` |

### 2.1 Ownership decides who may rewrite an edge

- **Linker-owned** (`writer: linker@N`): `names_file`, `names_symbol`, `cites`,
  `ruled_by`, and `recurs` *while proposed*. Re-linking a gap (after
  `gap_retopic`, after a linker version bump, or in the migration) recomputes
  the set. Any linker-owned `live` edge no longer derived goes to
  `revoked` with `context: rederived@N`. It is a state flip, never a delete
  (§0.2).
- **Act-owned** (`writer: gap_resolve`, `writer: decide:<app_id>`,
  `writer: revoke:<app_id>`): `closed_by`, and `recurs` once decided. The
  linker never modifies these.
- `gap_edge_revoke(app_id, from, relation, to, reason)` sets
  `state=revoked` with `revoked_by`, `revoked_at` and `reason`. Re-asserting
  the same edge later flips it back to `live`/`confirmed` on the same id. That
  is possible because the row was never soft-deleted. The verb is gated with
  `gap_promote`, as `gap_retopic` is (`server.py:2575-2576`), and it writes a
  FRANK event the way `gap_retopic` does (`server.py:2581-2594`).

@phase 3-recurrence
## 3. Recurrence candidates

**Generation (deterministic).** For gap *g* against every other live gap *h*
(any status: a recurrence of a *resolved* gap is the most valuable signal,
because it says the close was false):

- `T(x)` = `set(gaps._tokens(topic_leaf(x) + " " + question(x)))`, the same
  tokenizer the id already uses (`gaps.py:43-47`). `J = |T(g)∩T(h)| / |T(g)∪T(h)|`.
- Signals, each boolean:
  - **S1 cite+marker:** *g* has a `cites` edge to *h*, and an instance marker
    (`same class|instance|again|reopens|recur|duplicate|sibling|follow-?up`)
    sits within 120 characters of the cited id. This catches every
    ambient-artifact sibling in §0.1.
  - **S2 shared file:** at least 1 shared `names_file` target, and `J ≥ 0.20`.
  - **S3 same topic:** the current or historical topic (`topic_history`) is
    equal, and `J ≥ 0.20`.
  - **S4 lexical:** `J ≥ 0.40`.
  - **S5 near-verbatim:** Nestor `StringMatcher` on the normalized first 200
    characters of each question, score `≥ 0.92` (Nestor's serve bar).
    Pre-filtered with `similarity_bound` so the real ratio is computed only
    for survivors. It is restricted to the head because `StringMatcher` is a
    `difflib.SequenceMatcher` ratio over characters
    (`nestor/matcher.py:234-245`). On multi-paragraph questions it measures
    edit distance, not sameness of class, so it cannot carry recurrence alone.
- A candidate exists if any signal fires. Its score is `1.0` for S1, else
  `max(J, S5)`. The linker keeps the top 5 per gap by (score desc, older
  first). Each is written as `recurs` `state=proposed` with
  `context: "S1,S3 J=0.31"`.

**Threshold.** The numbers above are provisional (Q3). The migration's report
prints a J histogram of every pair that fires S1–S3, so the thresholds are
calibrated against the real backlog before proposals run on every `gap_log`.

**Cost.** One `gap_log` checks O(N) pairs over a backlog of a few hundred rows.
The backfill checks O(N²), about 10⁵ token-set intersections. Both are small.

**Confirmation: the single judgment call.**

```
gap_recurs_decide(app_id, from_gap, to_gap, decision: "confirm" | "reject", note="")
```

This sets `state` to `confirmed` or `rejected`, with `decided_by=app_id`,
`decided_at` and `note`. It also accepts a pair that was never proposed (the
operator can see what the matcher cannot), and records `writer: decide:<app_id>`.
It writes a FRANK event. It is gated with `gap_promote`. Who may hold that for
this purpose is Q2.

**Nothing else depends on judgment.** Every consumer and the edge states it reads:

| Consumer | Reads | Judgment in it |
|---|---|---|
| ranked view (§4.1) | `recurs` **confirmed** only | none: the count comes from decided edges |
| candidates view (§4.1) | `recurs` **proposed**, shown as proposals | none: presented as unconfirmed, never counted |
| touching-paths view (§4.2) | `names_file`, `names_symbol` **live** | none: regex + filesystem + code_graph |
| may-be-resolved view (§4.3) | `names_file` **live** + `git log` | none |
| `closed_by` | `gap_resolve` note, exact regex | none |
| `ruled_by` | Nestor sealed state | a *human's* earlier seal, not a model's |
| status transitions | unchanged: `gap_resolve`, `gap_promote` | as today; no edge changes a status |

@phase 4-views
## 4. Views

Every view returns `{state, items, next_cursor, total, bounds}`. `items` uses the
brief shape (`gaps.py:147-158`: id, topic, status, asked_count, last_asked_at,
question[:200]) plus a `why` field saying which edge or tier matched. Bounds,
per gap 1477ebb2bc35: at most **25 rows**; at most **5 edges per relation per
row**, with a `+N more` count; and a **16 KB serialized page ceiling**. When the
next row would cross the ceiling the page ends early and `next_cursor` is set.
That is the byte guard `gaps.py:99-108` says a row cap alone cannot give.

### 4.1 Ranked (`gap_view(kind="ranked")`, later behind `gap_list(rank="recurs")`)

Clusters are the connected components over **confirmed** `recurs`. The
canonical member is the oldest. The sort key is (cluster size desc, Σ
`asked_count` desc, newest `last_asked_at` desc, canonical id asc). A row is the
canonical gap plus `members` (≤10 ids) and `size`. `kind="candidates"` lists
proposed `recurs` pairs, highest score first, for whoever runs
`gap_recurs_decide`.

### 4.2 Gaps touching these paths (`gap_touching(paths, project="")`)

Input: repo-relative paths, or a dispatch id, whose assignment is scanned for
paths with the `names_file` regex. Match tiers, in order, each capped:

1. **exact:** a `names_file` edge to one of the paths, or a directory prefix
   when the input ends in `/`;
2. **symbol:** a `names_symbol` edge whose `context.file` is one of the paths;
3. **project + stem** (≤5 rows): the gap's topic pins the same project, and a
   token of the path's basename stems (split on `/ . - _`) is in `T(gap)`.

Tier 3 exists because of 07aa99036f09. It names no file. Its topic pins
`ratatosk` and its tokens include `listener`, so a brief touching a
`…listener….template` path surfaces it. Tier 3 is labelled as the weaker
match in `why`.

Only `open` and `resolved` gaps are returned. `promoted` gaps are excluded.
`unindexed: n` counts gaps whose `links.version` is behind, so a partly
backfilled store says so instead of looking complete.

**Callers:**
- `dispatch_send` (`server.py:4544-4555`) scans `assignment_md` and returns
  `gaps_touching` in its result, and appends a bounded "Gaps touching these
  paths" section to the packet. The recipient reads it at `session_enter`.
- `session_enter` on a dispatch entry (`server.py:4932`) computes the same
  section from the assignment, so a packet sent before this ships still gets it.
- `pr_open_execute` (`server.py:5494-5506`): paths come from
  `git diff --name-only <base>...<head>` in the project's local checkout, with
  no network. With no local checkout the section is `unreachable`, never empty.
- `boot_context._gap_lines`: ranked view when there is no dispatch, and the
  three-state fix from §1.

### 4.3 May be resolved (`gap_view(kind="may_be_resolved", project="")`)

An open gap qualifies when a `names_file` target has a commit after the gap's
`last_asked_at`. Per project, **one** call over the registry checkout:
`git -C <root> log --since=<min last_asked_at over candidates> --name-only --format=%H%x00%cI`.
The result is joined in memory, and each row cites the commit that touched the
file. The result is only as fresh as the checkout, so the view reports each
project's HEAD and commit time ("pull before reconciling"). 158600e03598
qualifies once B2 links it to the `unit_status` code. This view *proposes a
re-check*. It never resolves anything. codebase-memory-mcp's `detect_changes`
is the equivalent seat-side cross-check. It is not in the writer's path
(§0.2).

@phase 5-migration
## 5. Migration

A Kart job, `python -m willow_mcp.gaps_link --backfill [--apply]`, is dry-run by
default. It runs with `set -euo pipefail` and is safe to run twice.

1. Read every live gap (`Store.all("gaps")`; soft-deleted rows are excluded by
   `db.py:291-307`). **Ids are never changed.** No row is re-put under a new
   id, and no field other than `kind`, `schema` and `links` is written. The
   write goes through `Store.update` with `_strip_meta`, the existing idiom
   (`gaps.py:268-272`).
2. Resolve the project registry and record each project's HEAD in
   `links.inputs`.
3. Run the linker (the §2 regexes) per gap, and write linker-owned edges that
   are absent. Existing `live` edges are left as they are, and act-owned edges
   are never touched.
4. Backfill `closed_by` from every existing `resolution_note` that matches the
   steward shape.
5. Generate `recurs` proposals (§3).
6. Print the report: gaps scanned; edges new/unchanged/rederived per relation;
   **unlinked tokens grouped by reason** (`no_project`, `not_found`,
   `ambiguous`, `not_a_path`, `unsealed`, `unknown_id`); gaps with zero edges;
   the J histogram; proposals made.

**Idempotence test (acceptance):** a second `--apply` on unchanged inputs
reports `new=0 rederived=0` for every relation.

The job needs the live store bound read-write. It must not use a throwaway
`WILLOW_HOME`. Its tests do use one, per the fleet's rule for Kart tests.

@phase 6-compatibility
## 6. Compatibility

| Verb | During the transition |
|---|---|
| `gap_log` | Same signature and id rule. After the write it runs the linker for that one gap. A linker failure never fails the log; the result adds `links: {state, counts}` and `recurs_candidates: [ids]`. |
| `gap_list` | Same arguments, same default sort (`gaps.py:227`). Gains `rank="recurs"` in B5 and becomes a thin wrapper over `gap_view` once B5 lands. |
| `gap_get` | Unchanged record. Gains `edges=True` (bounded per §4) and three-state. |
| `gap_resolve` | Unchanged behaviour. Also writes `closed_by` when the note has the steward shape. |
| `gap_retopic` | Unchanged. Also triggers a re-link, because the project can change with the topic. |
| `gap_promote` | **No change to the gate.** It still goes through `_knowledge_ingest_core` and the schema-confirmation check (`server.py:2655-2663`). The knowledge side already carries `gap:<id>` in its tags (`server.py:2654`), so the back-link exists without a new edge. |
| steward Gap-Id path | **No change in willow-bot.** It keeps calling `gap_resolve` with `merged <repo>@<sha>` (`tick.py:3114-3116`), and the edge is written broker-side. No `store_scope` widening, no manifest edit, no re-sign. |

@phase 7-build-split
## 7. Build split

Each bite is independently mergeable, and each ships its own tests, including
a mutation proof: break the code in a scratch copy and paste the red result.

1. **B1 — gaps touching these paths, read-time (first bite).** Adds
   `gaps.touching(paths, project)`: the §4.2 tiers, computed by regex over
   `topic + question` at read time. It needs no edge store and no migration.
   New verb `gap_touching` goes in `gap_read`. `dispatch_send` returns the
   section and `session_enter` shows it on dispatch entries. Three-state and
   §4 bounds are included. Tests: a fixture with a path-naming gap, a
   07aa99036f09-shaped gap (tier 3), an unreachable store, and a page at the
   byte ceiling.
2. **B2 — `gap_edges` + linker.** Adds `names_file`, `names_symbol`, `cites`
   and `ruled_by`, written on `gap_log`, plus `gap_get(edges=True)` and
   `gap_edge_revoke`. B1 switches to edges for gaps at the current
   `links.version` and keeps the read-time fallback for the rest.
3. **B3 — backfill job** (§5), with its report and the idempotence test.
4. **B4 — `closed_by`** from `gap_resolve` notes, plus backfill.
5. **B5 — `recurs` proposals, `gap_recurs_decide`, ranked and candidates
   views**, and `gap_list(rank=…)`. Proposals on `gap_log` are enabled only
   after the Q3 calibration.
6. **B6 — may-be-resolved view** (§4.3).
7. **B7 — `pr_open_execute` preflight, and the `boot_context` switch plus its
   three-state fix.**
8. **B8 — read-only store door** for `gaps` and `gap_edges`, only if Q1 is
   answered yes.

@phase 8-open-questions
## 8. Open questions for the operator

1. **Read door.** Should `gaps` and `gap_edges` be readable through
   `store_get`/`store_list`/`store_search`/`store_search_all` by every
   `gap_read` holder? That would be a read-only exception in
   `gate.collection_permitted`. Or should they stay behind the gap verbs? Adding
   them to a `store_scope` is **not** an option: scope also governs
   `store_put`/`store_update`/`store_delete` (`server.py:1413-1415`,
   `1464-1468`, `1495-1498`), which would let any seat rewrite or tombstone a
   gap outside the gap verbs.
2. **Who confirms `recurs`.** Should `gap_recurs_decide` be open to any
   `gap_promote` holder, models included (every decision recorded with
   `decided_by`, and the operator can revoke)? Or should it be operator-seat
   only?
3. **Thresholds.** Accept the provisional S2–S4 values (J 0.20/0.20/0.40) and
   S5 ≥ 0.92, with proposals on `gap_log` held until the backfill histogram has
   been read?
4. **Demand.** Should a confirmed `recurs` stay out of `asked_count`, so that
   it remains the literal ask counter and ranking uses cluster size? Or should
   it fold into the canonical row's `asked_count`?
5. **Re-ask after close.** `gap_log` on a `resolved` id keeps it `resolved`
   (`gaps.py:83`). With `closed_by` edges in place, a re-ask after the closing
   commit is evidence of a false close. Should it reopen the gap (status →
   `open`, keeping the `closed_by` edge marked `reasked_after`)?

@phase constraints
## Constraints

@constraint severity="critical"
No model is in the read, link or report path. The only judgment is
`gap_recurs_decide`, and no view counts an undecided `recurs` edge.

@constraint severity="critical"
Edges are never soft-deleted. Revocation is `state=revoked` on the same
composite id, because a tombstoned id cannot be written visibly again
(`db.py:232-265`).

@constraint severity="high"
Gap ids never change. Migration adds fields and edges; it never re-keys.

ΔΣ=42
