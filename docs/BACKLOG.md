# willow-mcp — Backlog

Concrete, actionable improvement items found by codebase audit (2026-08-24).
Not bugs (those go in `BUGS.md`), not blue-sky ideas (those go in `ideas.md`).
These are gaps, tech debt, and MCP server improvements discoverable from the
code itself.

**Conventions**
- **ID** — sequential `W-NN`. Stable; never reused.
- **Category** — `gap` (missing coverage / wiring) · `debt` (code quality / consistency) · `idea` (improvement the code is ready for).
- **Status** — `Open` · `Done` · `Wontfix`.

## Summary

| ID | Cat | Status | Component | One-line |
|----|-----|--------|-----------|----------|
| W-01 | gap | Done | plugin | 5 skill files on disk not registered in `plugin.json` |
| W-02 | gap | Done | tests | 8 MCP tools with zero test coverage |
| W-03 | gap | Done | tests | 29 source modules with no corresponding test file |
| W-04 | gap | Done | db | `get_pg()` silently returns None on Postgres connection failure -- no logging |
| W-05 | gap | Done | config | `.mcp.json` sets `WILLOW_PG_DB=willow`; Grove requires `willow_20` |
| W-06 | gap | Done | gate / kart | `check_kart_task()` exception silently swallowed in `task_submit` |
| W-07 | gap | Done | integrations | Jira stub has hardcoded placeholder `example.atlassian.net` URL |
| W-08 | gap | Done | deploy | Dockerfile bakes in `WILLOW_APP_ID=glama-inspect` |
| W-09 | debt | Open | error handling | 30+ `except Exception: pass` blocks with no logging (nest/ files need upstream-first) |
| W-10 | debt | Open | file I/O | Non-atomic writes in `session_inject.py`, `nest/taxonomy.py`, `nest/selflearn.py` (nest/ files need upstream-first) |
| W-11 | debt | Done | integrations | Mutable default dict `extra_headers: dict = {}` as class attribute on `BaseAdapter` |
| W-12 | debt | Open | web_search | Global cache replacement race in `reset_search_cache()` and `nest/embed.py` (nest/ file needs upstream-first) |
| W-13 | debt | Done | types | `type: ignore[return-value]` in `bound_receipt.py:312` |
| W-14 | debt | Done | integrations | Pinned `X-GitHub-Api-Version: 2022-11-28` will eventually deprecate |
| W-15 | debt | Done | packaging | `nestor-meaning` published on PyPI — optional extra `nestor` wired in pyproject.toml |
| W-16 | debt | Done | docs | B-33 `Ref` column says `willow-mcp#TBD` -- issue number never recorded |
| W-17 | debt | Done | packaging | Version falls back to `0.0.0+unknown` on fresh clone (no git tags) |
| W-18 | idea | Open | voice | Wire the RealtimeSTT wake-gate (`voice/wake_gate.py:73`) |
| W-19 | idea | Open | commitments | Wire Google Calendar sync transport (`commitments/calendar_source.py:116`) |
| W-20 | idea | Done | server | Make hardcoded limits configurable via `WILLOW_*` env vars |
| W-21 | idea | Done | tool_oracle | Rotate / truncate `pending.jsonl` (unbounded append-only file) |
| W-22 | idea | Open | mem_ratify | Doctrine values env-configurable via `WILLOW_FRONTIER_MIN_WITNESSES` / `WILLOW_CANONICAL_MIN_WITNESSES` / `WILLOW_REQUIRE_STEPWISE_PROMOTION` |
| W-23 | idea | Done | design | Specialist-registry TBD labels updated — 4/5 already implemented; only user-created extensions remain unimplemented |

---

## Detail

### W-01 · gap · 5 skills not in plugin.json

These skill files exist on disk and document real tool functionality but are not
delivered to Claude Code sessions via the plugin's `"skills"` array:

```
skills/forks.md
skills/frank.md
skills/gaps.md
skills/human-required.md
skills/knowledge-curate.md
```

Either add them to `.claude-plugin/plugin.json` or remove them if intentionally
excluded from the plugin surface.

### W-02 · gap · 8 tools with zero test coverage

These MCP tools are not referenced in any test file:

| Tool | Location |
|------|----------|
| `agent_dispatch_result` | `server.py:2855` |
| `friction_flags_list` | `server.py:1355` |
| `friction_scan` | `server.py:1334` |
| `knowledge_check` | `server.py:2073` |
| `knowledge_verify` | `server.py:2056` |
| `lineage_link` | `server.py:1288` |
| `lineage_list` | `server.py:1318` |
| `lineage_why` | `server.py:1302` |

### W-03 · gap · Dedicated tests added for governance_ledger, receipts, handoff

Most significant by line count: `dispatch.py` (787 lines), `db.py` (623),
`governance_ledger.py` (334), `session_binder.py` (275), `receipts.py` (236),
`worker.py` (219), `handoff.py` (179), `pgp.py` (159). Some are exercised
indirectly through integration tests but lack dedicated unit tests for edge
cases and error paths.

**Done (2026-08-24).** Added 77 dedicated tests across three new files:

- `test_governance_ledger.py` (30 tests) — `_decode`, `_payload`/`_payload_v2`
  canonicalization, `entry_hash`/`entry_hash_v2` sensitivity and determinism,
  `verify()` edge cases (empty chain, single row, content tamper, prev_hash
  break, expected_head match/mismatch), `rechain()` anchor guards
  (head_mismatch, untrusted, unreadable, unanchored, force bypass, marker
  append).
- `test_receipts.py` (26 tests) — `_entry_hash` pure function sensitivity,
  chain integrity (record+verify, tamper detection, deleted row detection),
  `on_record` observer, `tail()` ordering/scoping/limits, `since()` filtering,
  `distinct_tools()`, migration backfill of legacy unchained rows.
- `test_handoff.py` (21 tests) — `_utc_now` format, `_render_closeout`
  rendering (basic, findings table, no narrative, date extraction, role
  resolution, empty written_at), `handoff_write_v4` (success, wrong recipient,
  dispatch error), `handoff_read` (success, not found, symlink refused, no
  closeout), `verify_handoff` (verified, empty finding text, unresolved
  checklist, unclean envelope, not complete, dispatch error).

Remaining untested modules (dispatch, db, session_binder, worker, pgp) are
primarily Postgres-dependent and would benefit from integration-test fixtures.

### W-04 · gap · Postgres connection failure is silent

`get_pg()` at `db.py:101-102` and `:108-109` catches `Exception` and returns
`None` with no logging. This is the primary Postgres access path. A
misconfigured connection string, network partition, or auth failure produces
zero diagnostic output -- tools just see `postgres_unavailable` with no clue
why. At minimum: `logger.warning("Postgres connection failed: %s", exc)`.

### W-05 · gap · .mcp.json database name mismatch

`.mcp.json` sets `WILLOW_PG_DB=willow`; `.mcp.json.example` sets
`WILLOW_PG_DB=willow_20`. The Grove subsystem requires `willow_20`
(`grove.py:36-39`), so the live config causes all Grove tools to fail with
`GroveUnavailable`. The example file has the correct value.

### W-06 · gap · Kartikeya safety check silently swallowed

In `task_submit` (`server.py:2139`), the `check_kart_task()` call is wrapped in
`except Exception: blocked = None`. If kartikeya raises an unexpected error, the
safety check is silently skipped and the task proceeds without validation.

### W-07 · gap · Jira stub placeholder URL

`JiraStub` at `integrations.py:368` has `base_url = "https://example.atlassian.net"`.
The other stubs don't embed domain-specific URLs. This will need per-site
replacement when the integration is wired.

### W-08 · gap · Docker image bakes Glama app ID

`Dockerfile:33` sets `WILLOW_APP_ID=glama-inspect`, which is Glama-specific.
Users building from this Dockerfile must override it.

### W-09 · debt · 30+ silent exception swallowing

Over 30 `except Exception: pass` blocks swallow errors with zero logging.
Many are documented as deliberately fail-soft, but several in critical paths
have no logging at all. Most notable:

| File | Line | Context |
|------|------|---------|
| `server.py` | 346, 378, 4079, 4124, 4875 | Announce hook, binding observer, diagnostics, worker health |
| `integrations.py` | 113, 198 | Credential loading, adapter retry |
| `receipts.py` | 178 | Post-record observer |
| `oauth.py` | 94 | Token refresh (corrupt store -> empty, losing all tokens) |
| `announce.py` | 118 | Announcement sink write |
| `web_search.py` | 242 | Result parsing |
| `code_graph/indexer.py` | 62, 130 | AST parsing |

At minimum, these should `logger.debug()` the exception so failures are
diagnosable.

**Partially blocked:** The `nest/ocr.py` fix is vendored from upstream
`safe-app-store/libs/nest-pipeline/`. The change must land in
safe-app-store first, then be re-vendored here. The non-nest files
(`server.py`, `integrations.py`, etc.) can be fixed directly.

### W-10 · debt · Non-atomic file writes

Several files use `path.write_text()` without temp-file-then-rename, risking
corruption on crash. The main codebase uses atomic writes correctly (e.g.
`oauth.py:105-107`, `heartbeat.py:106-107`); these do not:

- `nest/taxonomy.py:171` -- cache write
- `nest/selflearn.py:91, 204` -- learned store
- `session_inject.py:67` -- dedup marker

**Partially blocked:** The `nest/taxonomy.py` and `nest/selflearn.py` fixes
are vendored from upstream `safe-app-store/libs/nest-pipeline/`. The changes
must land in safe-app-store first, then be re-vendored here.
`session_inject.py` can be fixed directly.

### W-11 · debt · Mutable class-level default dict

`BaseAdapter` at `integrations.py:86` has `extra_headers: dict = {}` as a
class attribute. If any subclass mutates it in place, it affects all instances.
Currently safe (GitHubAdapter overrides with a new literal) but fragile.

### W-12 · debt · Global cache replacement race

`reset_search_cache()` at `web_search.py:1022` replaces the global
`_SEARCH_CACHE` object without synchronization. A concurrent thread accessing
the old cache while another replaces it is a race. Same pattern in
`nest/embed.py:36` with `installed_models()`.

**Partially blocked:** The `nest/embed.py` fix is vendored from upstream
`safe-app-store/libs/nest-pipeline/`. The change must land in
safe-app-store first, then be re-vendored here. The `web_search.py` fix
can be applied directly.

### W-13 · debt · type: ignore override

`bound_receipt.py:312` has `return False, reason, detail  # type: ignore[return-value]`
-- the function's declared return type doesn't match this branch.

### W-14 · debt · Pinned GitHub API version

`GitHubAdapter` at `integrations.py:240` pins `X-GitHub-Api-Version: 2022-11-28`.
Should be tracked for periodic update or made configurable.

### W-15 · debt · Nestor now published on PyPI — extra wired

`nestor-meaning` has been published on PyPI since v0.3.0 (latest: 0.11.0).
The optional extra `nestor = ["nestor-meaning>=0.7.0,<1.0.0"]` is now wired
in `pyproject.toml`, and `nestor-meaning` is added to the `[tool.willow.fleet]`
roster with a Rule 2 surface row in `fleet-versioning.md`.

Floor at 0.7.0: `SqliteStore` landed in 0.6.0, `EntityResolver` in 0.7.0 —
both are imported by `tool_oracle.py`. Cap at `<1.0.0` per Rule 1
(nestor sets `bump-minor-pre-major: false`).

### W-16 · debt · B-33 missing issue number

`docs/BUGS.md` line 41 has `willow-mcp#TBD` -- the GitHub issue number was
never filled in.

### W-17 · debt · Version fallback on fresh clone

The package derives version from git tags via hatch-vcs. No tags on a fresh
clone means the version falls back to `0.0.0+unknown`, while `plugin.json` and
`.release-please-manifest.json` both say `2.13.1`. Confusing for contributors.

### W-18 · idea · Wire RealtimeSTT voice wake-gate

`RealtimeSTTGate` at `voice/wake_gate.py:73` exists for contract conformance
but raises `NotImplementedError`. The design doc
(`design/willow-voice-ingress-membrane.md`) is in place.

### W-19 · idea · Wire Google Calendar sync

`GCalSyncSource` at `commitments/calendar_source.py:116` has a full skeleton
but its transport raises `NotImplementedError` until an OAuth callable is
injected. The commitment tools always use `StubCalendarSource`. Real calendar
integration would enable commitment ingestion from actual calendar data.

### W-20 · idea · Make hardcoded limits configurable

Several operational limits are hardcoded with no override:

| Limit | File | Line |
|-------|------|------|
| `_TIMEOUT_SECONDS = 30` | `integrations.py` | 58 |
| `_MAX_RESPONSE_BYTES = 2MB` | `integrations.py` | 54 |
| `CALL_TIMEOUT_SECONDS = 30.0` | `mcp_federation_client.py` | 50 |
| `_RATE = 60.0, _BURST = 10.0` | `server.py` | 835-836 |
| `_MAX_BLOB_BYTES = 512KB` | `server.py` | 735 |

These should be overridable via `WILLOW_*` env vars with the current values as
defaults.

### W-21 · idea · Rotate pending.jsonl

`tool_oracle.pending()` at `tool_oracle.py:176` reads the entire `pending.jsonl`
into memory and reverses it. The file is append-only with no rotation. On a busy
system this becomes a memory pressure point. Consider log rotation or a
max-line read window.

### W-22 · idea · Doctrine values env-configurable (needs upstream-first)

Three constants in `ratify.py` are hardcoded placeholders. Should be
configurable via env vars following the W-20 pattern, with the same
conservative defaults:

- `WILLOW_FRONTIER_MIN_WITNESSES` (default `2`) — quorum for Contested → Frontier
- `WILLOW_CANONICAL_MIN_WITNESSES` (default `2`) — quorum for Frontier → Canonical
- `WILLOW_REQUIRE_STEPWISE_PROMOTION` (default `1`) — set `0`/`false` to allow tier skipping

**Blocked:** `ratify.py` is vendored from upstream Willow. The change must
land in the upstream Willow repo first, then be re-vendored here with an
updated pinned hash in `tests/test_mem_ratify.py`. Direct edits to the
vendored copy break the `vendor-sync` CI gate.

### W-23 · idea · Specialist-registry TBD labels updated

Four of five TBD items in `specialist-registry.md` were already implemented in
code and the labels were stale:

- `store_scope`: implemented in `gate.store_scope()` / `collection_permitted()` (B-24/B-25)
- `permissions`/`deny_tools` per-role: ratified in `permissions-matrix.md`, enforced in `gate.permitted()`
- Orchestrator role: ~40-tool `orchestrator` group in `gate.py`, `dispatch_write` split (B-51)
- `session-lifecycle.md` S-R1: marked done, S3 unblocked

Only "User-created extensions" (§10) remains genuinely unimplemented — no
`user_specialists.json` loader or persona overlay exists in the codebase.
