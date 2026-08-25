# tools/ — take the job off the model

Deterministic harnesses for jobs a model was doing by hand. Each one turns
conversational labor into a script or a tool call, so the next session runs the
tool instead of re-deriving the work.

Run them with the willow-mcp venv python and the live willow env sourced:

```sh
source /root/.willow-env.sh
VP=/home/user/willow-mcp/.venv/bin/python
```

## The scripts

| Script | Job it takes off the model | Run |
|---|---|---|
| **`mai_lint.py`** | "read the doc and check the mai format by hand" — validates frontmatter/schema/header, catches the #156 `@constraint:` colon drop and structural-swallow, the #157 `@phase`/`@macro`-in-frontmatter leak, and unbalanced blocks. Exit-coded for hooks/CI. CI runs it in `.github/workflows/tests.yml`; locally use `pre-commit` (see repo `.pre-commit-config.yaml`, #158) or `$VP tools/mai_lint.py [FILE|DIR...]`. | `$VP tools/mai_lint.py [FILE|DIR...]` |
| **`wtool.py`** | the substrate — call any of the 115 willow-mcp tools from a shell, so *any* script can do what a model does through the MCP client. | `$VP tools/wtool.py <tool> '<json>'` · `--list [substr]` |
| **`mai_metrics.py`** | "track how the loop is converging" — records one metric per bite into SOIL, reports the new-gaps-by-learnings curve. | `$VP tools/mai_metrics.py record '<json>'` · `report` |
| **`mai_prose_split.py`** | "judge which parts of a narrative doc are convertible" — separates PROTECTED PROSE from DIRECTIVE CANDIDATES (`@constraint`/`@phase`/`@env`/`@if consumer=`), emits a conversion PLAN (JSON), and a `prose_ratio` verdict flags story-shaped docs "do not force" instead of mangling them. | `$VP tools/mai_prose_split.py [--summary] FILE\|DIR...` |
| **`provision_gate.py`** | "hand-edit the gate manifest JSON" — unions the builder's introspection+loop permission groups into the manifest, validating every group name against `gate.PERMISSION_GROUPS` (loud-fails on a typo instead of granting nothing). | `$VP tools/provision_gate.py [manifest]` · `--print` |
| **`hook_mutation_check.py`** | "hand-flip a hook guard's regex and eyeball whether the suite still passes" — the six per-guard mutations named in the 2026-07-30 hooks handoff, run against `hooks/pre_tool_use.py`, reporting which test caught each one (or that none did). Refuses to run on a red baseline; never leaves a mutation in the tree. | `$VP tools/hook_mutation_check.py` |
| **`envelope_mutation_check.py`** | "prove each errno path in the constitutional envelope gate can actually fail" — PR #248's named gap: this repo had ordinary pytest assertions on `EnvelopeAuthority.check()` but no mutation-style proof they fire, unlike `safe-app-store/apps/jarvis`. Runs 17 per-guard mutations against `src/willow_mcp/envelopes.py`, reporting which test in `tests/test_governance_continuity.py` caught each one (13 came back GAP the first time this ran — closed by the tests it named missing). Refuses a red baseline; requires a *named* pytest failure, not just a nonzero exit (a collection error also exits nonzero and would be a false CAUGHT — see the module docstring). | `$VP tools/envelope_mutation_check.py` |
| **`counts_in_prose_lint.py`** | "eyeball whether a stated count in a docstring/README is still true" — checks a short registry of live, present-tense count claims (e.g. "`_guarded` wraps N tools") against the real number, computed fresh each run. Ignores historical narrative (CHANGELOG, BUGS.md, handoffs) on purpose — those are point-in-time records, not live claims. Item G from the 2026-07-30 hooks handoff. | `$VP tools/counts_in_prose_lint.py` |

## The wiring — hand-run job → the tool that already does it

The willow-mcp server exposes 115 tools. Most of the "jobs" a builder agent runs
by hand are already one of them. After `provision_gate.py`, the `safe-app-store`
identity is permitted to call each of these (verified live 2026-07-23):

| Job done by hand | Tool group (permission) | Verified |
|---|---|---|
| ouroboros gap loop (find → resolve → promote) | `gap_read` + `gap_write` + `gap_promote` | ✅ `gap_log`/`gap_list`/`gap_delete` |
| coupling map / impact analysis (was grep + md5sum) | `code_graph_read` + `code_graph_write` | ✅ indexed 112 files/1670 syms; `friction_floor` → 208L (matches the by-hand drift figure) |
| loud confirmation of a write (was reading records back) | `audit` → `receipts_tail` | ✅ shows every tool call + outcome |
| context recovery (was re-reading the transcript) | `context` → `context_save/get/list/expire` | ✅ save → get round-trip |
| handoff / closeout (was hand-written prose) | `dispatch_write` → `handoff_write_v4`, `verify_handoff`, `session_handoff_write` | granted |
| doc ingestion review | `nest_read` → `nest_status`, `nest_digest`, `nest_intake_*` | granted |
| provenance / "why this willow" | `lineage_read` → `lineage_why`, `lineage_list` | granted |
| the shared memory / KB | `store_*`, `knowledge_*`, `schema_admin` | ✅ `store_collections` → fleet, saps1, mai-loop-metrics |

## Notes

- **Durability.** The gate manifest lives in `$WILLOW_HOME/mcp_apps/<app>/` — a
  live-env file, not git. `provision_gate.py` is the durable source of truth for
  the grant; re-run it after any fresh container to restore the builder's tools.
- **Loud, never silent.** Every script here fails loudly: `mai_lint` exits 1 on a
  bad doc, `provision_gate` refuses an unknown group rather than granting
  nothing, `wtool` says so when the server won't start. Same rule the fleet runs
  on — a refused action is never reported as success.
- **The graph is rebuildable.** `code_graph_index` writes a local
  `$WILLOW_HOME/code_graph/graph.db`; delete it and re-index anytime.
