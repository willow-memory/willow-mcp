# Migration Gap Inventory — willow-2.0 → willow-mcp

Status: **INVENTORY** (2026-07-18, Draft 0.2 — verified against willow-2.0 source).
A stock-take, not an implementation. Draft 0.2 replaces the earlier estimate-based
version: willow-2.0 was cloned and its MCP surface diffed tool-by-tool against
willow-mcp, then scored on **production-fitness** using willow-2.0's own
`sap/mcp_profiles.py` tiers and its test coverage.

> **Two axes, not one.** "Get everything over" is the wrong frame. Most of
> willow-2.0's surface was never load-bearing — willow-2.0 itself hides it behind
> a `full`-only profile and ships it untested. So every gap is scored twice:
> **(1) capability** — is it already here (renamed), a genuine gap, or a
> deliberate non-goal? and **(2) production-fitness** — did it earn its place, or
> is it spec-ware to leave behind? The migration target is the *intersection*:
> genuine gaps that were actually used.

---

## 0. TL;DR

- willow-mcp is **not** a renamed superset of willow-2.0. The README's claim that
  "the tool API is identical" is **FALSE** and should be corrected — of
  willow-2.0's **169** `@mcp.tool` surfaces (`sap/sap_mcp.py`), only **15 names
  match exactly**. willow-mcp is a **re-scoped re-implementation** of the
  SOIL/KB/dispatch core.
- Counting renames, **~42 of 169** willow-2.0 capabilities already exist in
  willow-mcp (`soil_*`→`store_*`, `ledger_*`→`frank_*`, `agent_task_*`→`task_*`,
  `kb_get`→`kb_at`, `kb_search`/`kb_query`→`knowledge_search`, …).
- That leaves **~108 genuine capability gaps** and **~19 deliberately-dropped**
  fleet/fylgja tools. willow-mcp also adds **~58 product-only tools** willow-2.0
  never had (gap backlog, lineage, friction watcher, HMAC gate-seam sessions,
  integration adapters).
- **The 108 gaps are mostly not worth porting as-is.** Only **61 of 169**
  willow-2.0 tools have any test; **108 are untested**. willow-2.0's own profile
  system marks whole families (`workflow_*`, `routine_*`, `dream_*`, `mem_jeles_*`,
  `cmb_*`, `outcome_*`, `hook_*`, `tension_scan`, …) as `full`-only — i.e. never
  in the standard surface. The realistic port shortlist is **single digits**
  (see §6), not 108.
- The prior draft's largest "deferred" item — the Kart executor — already
  shipped as the `kartikeya` package (B-22 closed). Several Kart design docs are
  stale (§8).

---

## 1. Verified numbers

| Metric | Value | Source |
|---|---|---|
| willow-2.0 `sap_mcp.py` tools | **169** | `@mcp.tool` count |
| willow-mcp `server.py` tools | **97** | `@mcp.tool()` count (103 live incl. group expansions; was 73 at Draft 0.2, grown by the web/code_graph/fork/human-loop ports since) |
| Exact-name overlap | **15** | `comm` of both name lists |
| Already ported incl. renames (bucket A) | **~42** | §3, code-verified |
| Genuine capability gaps (bucket B) | **~108** | §4 |
| Deliberately dropped (bucket C) | **~19** | §5, cross-checked vs `session-lifecycle.md` §9 |
| willow-mcp product-only tools | **~58** | §7 |
| willow-2.0 tools with **any** test | **61 / 169** | grep of `tests/` per tool name |
| willow-2.0 tools that are `full`-profile-only | large | `mcp_profiles.py` `_FULL_ONLY_*` |

**willow-2.0's own tiers** (`sap/mcp_profiles.py`), used below as the
production-fitness signal:

- **minimal (~20)** — boot: `willow_*` facade, `fleet_status/health`, `kb_search`, `kart_task_run`.
- **core (~55)** — daily: `soil_*`, `ledger_*`, `kb_*`, `grove_*`, `handoff_*`, `agent_task_*`, `infer_chat`, `skill_list/load`.
- **standard (default)** — extended prefixes: `fork_*`, `code_graph_*`, `intake_*`, `mem_binder_*`, `policy_*`, `agent_dispatch/route/create`, `index_search/feedback`, `pg_edge_*`, `voice_*`.
- **full-only (never standard)** — `workflow_*`, `routine_*`, `cmb_*`, `context_*`, `outcome_*`, `hook_*`, `routing_*`, `session_query`, `tension_scan`, `dream_*`, `kb_backup/promote/extract/intelligence`, `mem_jeles_*`, `fleet_blast/restart/reload/governance/base17/persona`.

---

## 2. Bucket A — already ported under a new name (do NOT re-migrate)

Code-verified equivalences (docstrings/tables match):

| willow-2.0 | willow-mcp | Evidence |
|---|---|---|
| `soil_{get,search,search_all,list,stats,put,update,delete}` (8) | `store_{…}` | store runs on the SOIL store, `server.py:763,880`; identical docstrings |
| `ledger_{write,read,verify}` (3) | `frank_{append,read,verify}` | shared `frank_ledger` table, `server.py:2438` |
| `kb_search`, `kb_query` (2) | `knowledge_search` | same "AND search the Postgres KB" |
| `kb_get` (1) | `kb_at` | "fetch a single atom by id" |
| `journal_read`, `mem_check` (2) | `knowledge_search`(journal) / `kb_journal`; `knowledge_ingest` dedup gate | docstrings |
| `agent_task_{submit,status,list}` (3) | `task_{submit,status,list}` | Kart `tasks` table, `server.py:443` |
| `agent_dispatch` (1) | `dispatch_send` | dispatch packet files |
| `handoff_write_v3`, `handoff_latest`, `boot_digest` (3) | `session_handoff_write` / `handoff_read` / `session_enter` | v3 claims record ≡ closeout |
| `nest_file`, `nest_queue` (2) | `nest_promote` / `nest_status` (+ `nest_scan/digest`) | redesigned Nest family |
| `fleet_agents`, `fleet_system_status` (2) | `fleet_status` / `specialist_list` / `diagnostic_summary` | roster + health |

---

## 3. Bucket B — genuine capability gaps, scored for production-fitness

**Recommendation legend** (capability gap × production-fitness):
- 🟢 **PORT** — genuine gap, was core/standard tier, self-contained.
- 🟡 **EARN-FIRST** — real capability but `full`-only and/or untested in 2.0; port
  only when a concrete willow-mcp consumer needs it (the "surface is earned" rule).
  Consumer = the operator, asking, on the record. Enforced by `earn_mode:
  user-lease` — `willow-mcp grant-build <tool> --ttl 30m --reason "..."`
  (3h ceiling, same as `grant-net`); `willow-mcp earn-check` reads the whole
  roster. See `docs/design/slice-backlog.md` "Earn-first" section for the rule
  the seal opens.
- 🔴 **LEAVE** — heavy external deps or vestigial; don't bring into a clean product
  without a strong reason.

| Family (count) | 2.0 tier | Tested? | Rec | What it does |
|---|---|---|---|---|
| `willow_web_search`, `willow_web_fetch` (2) | core | partial | 🟢 **PORT** | **Only** open-web / guarded-fetch path; willow-mcp has none. Highest-value gap. |
| `code_graph_*` (6) | standard | ✗ | 🟢 **PORT** | Python symbol graph — callers/callees, blast radius. Self-contained (repo path + SQLite). |
| `fork_*` + `env_check` (8) | standard | ✓ | ✅ **PORTED** | SOIL-backed work-units (not fleet Postgres). Branch + PR tracking; merge/delete bookkeeping. |
| `human_attestation_*`, `human_required_queue_*` (5) | standard | ✗ | 🟢 **PORT** | Human-in-loop pause/attest queue. Pure DB state — pairs with the trust story. |
| `skill_{put,load,list,mastery}` (4) | core/std | partial | 🟡 EARN-FIRST | Skill registry + Bayesian mastery. `list/load` are core; `mastery/put` full-ish. |
| `cbm_*` (7) | full | ✗ | 🟡 EARN-FIRST | Codebase-memory CLI wrappers; pairs with `code_graph_*`, needs external CLI. |
| `index_*`, `cmb_*` (8) | std/full | ✗ | 🟡 EARN-FIRST | Extra KB sub-stores (`opus.atoms`, `cmb_atoms`) mirroring store patterns. |
| `intake_*` (4) | standard | partial | 🟡 EARN-FIRST | KB-tier routing layer — depends on jeles/binder/opus targets existing first. |
| `workflow_*` (5) | **full** | partial | 🟡 EARN-FIRST | Multi-phase engine; rides the present Kart `task_*` queue, so tractable. |
| `mem_binder_*`, `mem_ratify_*` (7) | std/full | ✗ | 🟡 EARN-FIRST | Ratification memory pipeline — new tables + lifecycle. |
| `soil_add_edge/edges_for/audit`, `pg_edge_*` (5) | core/std | partial | 🟡 EARN-FIRST | SOIL graph edges + KB edge graph + audit reader — extends store willow-mcp already owns. |
| `ledger_repair`, `handoff_search/rebuild`, `routing_log_read`, `session_query/review` (6) | std/full | ✗ | 🟡 EARN-FIRST | Maintenance/analytics readers over tables willow-mcp already writes. Cheap, low priority. |
| `mem_jeles_*`, `source_trail_verify`, `tension_scan` (10) | **full** | ✗ | 🔴 LEAVE | Institutional-source librarian: 64 connectors + embeddings + `mistral:7b`. Heavy. (Jeles *remote* search already wired via `integration_call`.) |
| `infer_{7b,chat,imagine,speak}` (4) | core/full | ✗ | 🔴 LEAVE | Local inference/TTS/image gen — Ollama/Groq/Novita wiring. Largest external surface. |
| `outcome_*` (3), `routine_*` (3) | **full** | ✗ | 🔴 LEAVE | Anthropic Outcomes API + Claude Code Routines — external-credential-bound. |
| `app_*` (4), `agent_create` (1), `voice_keyterms`, `fleet_blast`, `kb_backup/extract/intelligence` | std/full | ✗ | 🔴 LEAVE | SAFE-app lifecycle, agent provisioning, STT keyterms, blast-radius scan, KB ops — fleet-operational, not product-core. |

---

## 4. Bucket C — deliberately dropped (NOT migration targets)

Documented as intentional divergences in `session-lifecycle.md` §9 and
`product-layout.md` §9. willow-mcp replaced the mechanism by design.

- `dream_*`, `wce_*` — AutoDream synthesis + weekly witness rituals (§9 lists "dreams" as 2.0-only).
- `hook_list`, `hook_log_read`, `loop_list` — fylgja hook registry + declarative loops ("packet is boot").
- `fleet_reload/restart/identity_status/persona/base17/governance` — fleet-daemon ops (replaced by "any client + manifest `app_id`").
- `policy_{list,put,delete}` — replaced by manifest envelopes (`envelope_apply` + `exposure_config_get`).
- `kart_task_run`, `intake_schedule_fleet` — fleet-scoped Kart fallback + fleet-wide intake.

---

## 5. willow-mcp product-only innovations (no willow-2.0 equivalent)

~58 tools, notably: `gap_*` (6, self-observed backlog), `lineage_*` (4, provenance
graph), `friction_scan`/`friction_flags_list` (model-free failure watcher),
`session_bind`/`session_reconcile` (HMAC gate-seam check-in/out), `integration_*`
(3, external adapters behind the three-key egress gate), `exposure_*`/`envelope_apply`/
`schema_confirm_mapping`, `receipts_tail`/`whoami` (self-audit), `verify_handoff`,
`agent_clear`, `store_collections`/`store_stats`/`store_purge_collection`. These are
the security/identity/provenance work that motivates willow-mcp as the successor.

---

## 6. Recommended port shortlist (the actual migration)

Not "get everything over" — get the **used** gaps over:

```
🟢 PORT (genuine gap + was core/standard + self-contained)
  [x] willow_web_search / willow_web_fetch   PORTED 2026-07-21 — src/willow_mcp/web_search.py,
                                              web_fetch.py, external_guard.py, web_egress gate
                                              (web_read + web_net), native WebSearch/WebFetch hook
  [x] code_graph_*                            PORTED 2026-07-20 (willow-mcp#115) — src/willow_mcp/code_graph/
                                              + 6 tools (index/search/explain/walk/suggest/impact),
                                              code_graph_read/write gate groups, 13 tests
  [x] fork_* + env_check                      PORTED 2026-07-21 — src/willow_mcp/forks.py (SOIL-backed,
                                              NOT fleet Postgres) + 8 tools (create/join/log/merge/delete/
                                              status/list/env_check), fork_read/write gate groups, worktree
                                              skill wired. KB fork_id promotion deferred to fleet schema.
  [x] human_attestation_* / human_required_*  PORTED 2026-07-20 — src/willow_mcp/human_loop.py (SOIL-backed,
                                              NOT the fleet Postgres) + 5 tools (queue enqueue/resolve/list,
                                              attestation create/list), human_loop_read/write groups, 12 tests.
                                              Closed a forgery hole: attester = caller identity, non-forgeable
                                              by_human flag (an agent can't sign as the operator).

🟡 EARN-FIRST (wire only when a willow-mcp consumer needs it)
  [ ] workflow_*        rides existing Kart queue
  [ ] intake_*          once jeles/binder/opus targets exist
  [ ] skill_*, index_*, cbm_*, mem_binder_*, soil edges, maintenance readers

🔴 LEAVE (don't port into a clean product without a strong reason)
      mem_jeles_* / infer_* / outcome_* / routine_* / app_* / dreams / fleet ops

── also, still willow-mcp's own roadmap (from Draft 0.1, unrelated to 2.0 tools) ──
  [x] egress onboarding UX (setup-egress/onboard/doctor/run-net)  PORTED 2026-07-21 —
                                              closes half-deployed B-37 bootstrap pain
  [ ] G-2  role-envelope enforcement in gate.py   (blocked on permissions matrix)
  [ ] G-1  SOIL DAG + dag_next/dag_status          (S6 design exists)
  [ ] SEV  own $WILLOW_HOME state root             (dissolves B-36, advances B-38)
```

Cross-repo blockers unchanged from Draft 0.1 (fixes live in willow-2.0): **B-31**
(consent writer fails open), **B-35** (envelope metering never written), **B-28**
(`completed_at` on failed tasks). See `docs/BUGS.md`.

---

## 7. Housekeeping (not migration work, but misleading)

- `README.md` — the old "run the full willow-2.0 server directly — the tool API
  is identical" line was **false** (only 15/169 names match). **Fixed 2026-07-18**:
  reworded to "re-implements the SOIL/KB/dispatch core with a redesigned, smaller
  surface" and linked here.
- `docs/design/kart-productionization.md` — old status said "not yet started".
  **Fixed 2026-07-18**: marked SHIPPED/superseded (Kart shipped as `kartikeya`,
  B-22); stage 5 (willow-2.0 side) correctly noted still open.
- `docs/design/kart-lift-spec.md` — **already accurate** (marked IMPLEMENTED,
  stages 1–4 shipped, stage 5 open by design). No change needed.

---

## 7b. Driven comparison — what booting and using 2.0 actually revealed

willow-2.0 was stood up (`/workspace/willow-2.0`, venv, `sap/sap_mcp.py` over
stdio) and driven tool-by-tool against the live willow-mcp server. Driving
corrected several paper ratings:

**Boot friction (product-readiness gap, in willow-mcp's favor).** willow-2.0's
MCP server would not start standalone. In order: it hard-imports the fleet
`willow.fylgja` package (needs the whole repo on `PYTHONPATH`), refuses to boot
without `WILLOW_AGENT_NAME` ("you cannot be in this system without an agent
identity"), wants `WILLOW_SAFE_ROOT` or the SAP gate drops to RESTRICTED, and
runs a psutil **process reaper at startup that SIGTERMs any process whose command
line contains `sap_mcp` + the repo root** — which kills its own launcher unless
`WILLOW_MCP_SHADOW=1` is set. willow-mcp boots clean with none of this and
`diagnostic_summary` self-reports wiring. This is the productionization gap made
concrete, and it runs the *opposite* direction from "port 2.0's features in."

**Confirmed 🟢 — `code_graph_*` is the standout.** `code_graph_index` on the repo
indexed **847 files / 10,756 symbols into a local SQLite `code_graph.db`** with no
Postgres and no network; `code_graph_search "active_profile"` returned exact
FQN + kind + file:line + signature (`() -> str`). Instantly useful, zero external
deps, genuinely absent from willow-mcp. Strongest port candidate — elevate.

**Downgrade — `fork_*` is Postgres-backed in 2.0, not "bookkeeping."** `fork_create`/
`fork_list` failed with `relation "forks" does not exist`: forks need their own
Postgres table, so porting drags schema + migration, more weight than §3 credited.
**willow-mcp port (2026-07-21):** SOIL-backed `forks` collection — same API shape,
no fleet Postgres migration; `knowledge.fork_id` promotion deferred.

**Mixed — the `willow_*` facade.** `willow_status` genuinely delights: one call
returned local store + Postgres table counts + host hardware + ollama + kart +
human-required queue. But `willow_find` failed (`column "agent" does not exist`)
— several facade verbs are welded to a specific fleet Postgres schema. And
willow-mcp's `diagnostic_summary` already covers the *health*-facade need with a
product-appropriate lens (severance, identity bindings, net-lease forgeability,
schema-mapping state) that `willow_status` doesn't have. Port the *idea*
(intent-shaped verbs), not the fleet-coupled implementation.

**Confirmed real gap — `willow_web_search`.** Ran cleanly (returned 0 results —
no egress/backend in the sandbox), but it *exists*; willow-mcp has no web path at
all. Still the highest-value single gap.

**A place willow-mcp is already better, not behind.** `soil_put` (2.0) rejects a
record without a caller-supplied `id`/`_id`/`b17`; willow-mcp's `store_put`
auto-generates the id (`record_id` optional) and returns `{id, action}`. The
redesign improved caller ergonomics — not every difference is a gap to close.

**Stricter gate, by design.** As `app_id=willow`, willow-2.0 grants a blanket ACL
bypass (`_INFRA_ACL_BYPASS = {"willow"}`) — the seat can call anything. On
willow-mcp the same seat is held to its narrow `orchestrator` allow-list and
`store_put` is **gate-denied**. willow-mcp enforces least-privilege where 2.0
trusts the primary interface. That is the severance posture working, not a
missing feature.

---

## 8. Method & caveats

- willow-2.0 cloned to `/workspace/willow-2.0` (shallow); diff is against
  `sap/sap_mcp.py` (the canonical server). willow-2.0's **other** facades —
  `grove_tools.py` (17), `grove/mcp_local.py` (17), `mai/tools.py` (10),
  `openclaw_mcp.py` (5) — were **not** folded in; they are Grove/SAFE-app
  subsystems, out of scope for the core diff.
- Production-fitness = willow-2.0's own `mcp_profiles.py` tier + presence of a
  test naming the tool. Test-naming is a proxy: a few willow-mcp-ported tools are
  untested in 2.0 yet tested in the product, so "untested in 2.0" is directional,
  not absolute.
- Bucket A equivalences are code-verified (shared tables/docstrings), not
  name-guessed.

---

*Draft 0.2 — 2026-07-18. Verified against willow-2.0 @ `06519c3`. Supersedes the
estimate-based Draft 0.1.*
