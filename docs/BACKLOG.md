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
| W-03 | gap | Open | tests | 29 source modules with no corresponding test file |
| W-04 | gap | Done | db | `get_pg()` silently returns None on Postgres connection failure -- no logging |
| W-05 | gap | Done | config | `.mcp.json` sets `WILLOW_PG_DB=willow`; Grove requires `willow_20` |
| W-06 | gap | Done | gate / kart | `check_kart_task()` exception silently swallowed in `task_submit` |
| W-07 | gap | Done | integrations | Jira stub has hardcoded placeholder `example.atlassian.net` URL |
| W-08 | gap | Done | deploy | Dockerfile bakes in `WILLOW_APP_ID=glama-inspect` |
| W-09 | debt | Done | error handling | 30+ `except Exception: pass` blocks with no logging |
| W-10 | debt | Done | file I/O | Non-atomic writes in `session_inject.py`, `nest/taxonomy.py`, `nest/selflearn.py` |
| W-11 | debt | Done | integrations | Mutable default dict `extra_headers: dict = {}` as class attribute on `BaseAdapter` |
| W-12 | debt | Done | web_search | Global cache replacement race in `reset_search_cache()` and `nest/embed.py` |
| W-13 | debt | Done | types | `type: ignore[return-value]` in `bound_receipt.py:312` |
| W-14 | debt | Done | integrations | Pinned `X-GitHub-Api-Version: 2022-11-28` will eventually deprecate |
| W-15 | debt | Open | packaging | `nestor` is an unpublished git dependency -- 3 tools permanently unavailable on standard install |
| W-16 | debt | Done | docs | B-33 `Ref` column says `willow-mcp#TBD` -- issue number never recorded |
| W-17 | debt | Done | packaging | Version falls back to `0.0.0+unknown` on fresh clone (no git tags) |
| W-18 | idea | Open | voice | Wire the RealtimeSTT wake-gate (`voice/wake_gate.py:73`) |
| W-19 | idea | Open | commitments | Wire Google Calendar sync transport (`commitments/calendar_source.py:116`) |
| W-20 | idea | Done | server | Make hardcoded limits configurable via `WILLOW_*` env vars |
| W-21 | idea | Done | tool_oracle | Rotate / truncate `pending.jsonl` (unbounded append-only file) |
| W-22 | idea | Open | mem_ratify | Finalize placeholder doctrine values before enabling enforcement |
| W-23 | idea | Open | design | Finish specialist-registry TBD sections (store_scope, permissions, extensions) |

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

### W-03 · gap · 29 modules with no test file

Most significant by line count: `dispatch.py` (787 lines), `db.py` (623),
`governance_ledger.py` (334), `session_binder.py` (275), `receipts.py` (236),
`worker.py` (219), `handoff.py` (179), `pgp.py` (159). Some are exercised
indirectly through integration tests but lack dedicated unit tests for edge
cases and error paths.

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

### W-10 · debt · Non-atomic file writes

Several files use `path.write_text()` without temp-file-then-rename, risking
corruption on crash. The main codebase uses atomic writes correctly (e.g.
`oauth.py:105-107`, `heartbeat.py:106-107`); these do not:

- `nest/taxonomy.py:171` -- cache write
- `nest/selflearn.py:91, 204` -- learned store
- `session_inject.py:67` -- dedup marker

### W-11 · debt · Mutable class-level default dict

`BaseAdapter` at `integrations.py:86` has `extra_headers: dict = {}` as a
class attribute. If any subclass mutates it in place, it affects all instances.
Currently safe (GitHubAdapter overrides with a new literal) but fragile.

### W-12 · debt · Global cache replacement race

`reset_search_cache()` at `web_search.py:1022` replaces the global
`_SEARCH_CACHE` object without synchronization. A concurrent thread accessing
the old cache while another replaces it is a race. Same pattern in
`nest/embed.py:36` with `installed_models()`.

### W-13 · debt · type: ignore override

`bound_receipt.py:312` has `return False, reason, detail  # type: ignore[return-value]`
-- the function's declared return type doesn't match this branch.

### W-14 · debt · Pinned GitHub API version

`GitHubAdapter` at `integrations.py:240` pins `X-GitHub-Api-Version: 2022-11-28`.
Should be tracked for periodic update or made configurable.

### W-15 · debt · Nestor unpublished dependency

`pyproject.toml:102-112` references `nestor` as a git dependency unavailable on
PyPI. `nestor_tool_route/seal/pending` gracefully return `status='unavailable'`,
but these 3 tools are non-functional on any standard install.

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

### W-22 · idea · Finalize mem_ratify placeholders

Three values marked "PLACEHOLDER -- owner must confirm" in `ratify.py`:
`FRONTIER_MIN_WITNESSES` (line 107), `CANONICAL_MIN_WITNESSES` (line 113),
`REQUIRE_STEPWISE_PROMOTION` (line 119). Must be operator-configured before
enforcement is enabled.

### W-23 · idea · Finish specialist-registry TBDs

`docs/design/specialist-registry.md` has six TBD items: `store_scope` (line 50),
`permissions`/`deny_tools` per-role schema (lines 160-161), orchestrator role
(line 186), and "User-created extensions" section (line 238).
`session-lifecycle.md` also marks the registry as draft with "permissions TBD"
(line 363).
