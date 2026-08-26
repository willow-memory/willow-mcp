---
kind: doc
name: "slice-backlog-the-one-ordered-board"
description: "Status: LIVING (started 2026-07-21) — ordered backlog of every outstanding willow-mcp slice, consolidated from the roadmap docs and a code sweep."
---

@markdownai v1.0

# Slice backlog — the one ordered board

Status: **LIVING** — started 2026-07-21. One place to see every outstanding
slice so they stop being rediscovered by hand. Consolidated from the roadmap
docs (`willow-2.0-gap-inventory.md §6`, `session-lifecycle.md §10-11`,
`kart-productionization.md §6`, the design-doc "open questions"), the `docs/BUGS.md`
cross-repo blockers, and a code sweep for `not yet` / `deferred` / seam-stub markers.

**How to read.** Each slice is a checkbox. Tiers, not just priority:

- **Ready now** — unblocked, self-contained, could be a PR today.
- **Cleanup** — near-zero drift this sweep surfaced (stale comments, stale counts).
- **Earn-first** — a real capability, but deliberately deferred until a
  willow-mcp consumer needs it (the "surface is earned" rule). Do NOT build
  ahead of a consumer.
- **Leave** — non-goals, listed so they stop being re-litigated.
- **Cross-repo** — the fix lives in `willow-2.0`, not here.
- **Decisions** — blocked on an operator call, not on engineering.

A ticked box links to where it landed. When a slice turns out already-done,
tick it and note the mechanism — a stale tracker is its own small drift.

---

## Ready now (unblocked, self-contained)

- [x] **PG `dispatch_tasks` dual-write** — `dispatch.dispatch_send` /
  `dispatch_set_status` best-effort mirror packet routing + status into shared
  Postgres `dispatch_tasks` when the operator opts in
  (`WILLOW_MCP_DISPATCH_MIRROR`) and a host DB is reachable. Filesystem packet
  stays canonical; the mirror is off by default, silent without a DB, and
  swallows every DB fault. Closes the asymmetry where dispatch was the one
  subsystem the fleet couldn't see (store/knowledge/tasks/agents already mirror).
  `docs/schema/dispatch_tasks.postgres.sql` + 4 tests. *(session-lifecycle §11.)*

*(No other slice in this tier survived scoping — see the note below.)*

> **Scoping correction.** When this board was first written, two items sat here.
> The **SOIL DAG (`dag_next`/`dag_status`, S6/G-1)** turned out to have **no
> consumer anywhere** — nothing routes by `function`, and the orchestrator
> dispatches explicitly today — so building it would be speculative surface
> ahead of a need. Moved to earn-first per the "surface is earned" rule. The PG
> mirror survived because the operator's own willow-2.0 fleet is a real reader.

## Cleanup (this sweep)

- [x] **Subject-consent enforcement is live** — driven end-to-end: a non-owner
  `subject_id` with no grant is denied `subject_consent_denied` at `_gate`
  (`server.py:687`), and the four subject-scoped tools carry `subject_id`. The
  "correct-but-dormant / next slice" comment in `subject_consent_binding.py` was
  stale and is corrected. (This was PR #138's stated "next bite" — already done.)
- [x] **Kart worker-run skill section** — `skills/kart-tasks.md §0` already
  documents `willow-mcp worker --lane/--once` and `fleet_health` liveness; the
  `kart-productionization.md §6` tracker item that called it deferred is stale
  and is marked done.
- [x] **`gap-inventory.md` stale tool count** — "server.py tools = 73" refreshed
  to the current surface (97 `@mcp.tool()` / 103 live).

## Earn-first (wire only when a consumer needs it)

Per `gap-inventory.md §3/§6` — real capabilities, all `full`-only and/or untested
in willow-2.0. Order is rough tractability.

**Earn mode.** These rows are gated by `earn_mode: user-lease` — a tool leaves
earn-first when the operator has an active build lease for it, issued via
`willow-mcp grant-build <tool> --ttl 30m --reason "..."`. The lease has the
same 3h ceiling as `grant-net` (FRANK `cc553729`); when it expires the row
falls back to earn-first. `willow-mcp earn-check` reads the whole roster and
prints `ready` / `waiting` / `dry` per family so this stops being a
case-by-case argument. Rows without an explicit `earn_mode` inherit
`user-lease` from this section header. (Integration stubs in `integrations.py`
stay on `earn_mode: two-cite` — the ledger-count rule; different subject,
different rule.)

- [ ] **`workflow_*`** (5) — multi-phase engine; rides the existing Kart `task_*`
  queue, so the most tractable of this tier. `earn_mode: user-lease`.
- [ ] **`willow_web_search` Brave provider** — the seam ships (`web_search.py`
  `BraveSearchProvider`, `_IMPLEMENTED = False`); implement the real call +
  `BRAVE_API_KEY` path behind the `web_net` egress gate when a consumer needs a
  second provider. DDG is the working default today. **See also issue #288** —
  the alternative on the same question is dropping `web_search.py` entirely in
  favour of jeles; pick one, not both. `earn_mode: user-lease`.
- [ ] **Calendar gcal OAuth transport** — the calendar source + tests exist;
  the live gcal transport is a home-box OAuth step, deferred (`server.py:3829`).
  **`earn_mode: auth-flow-blocked`** — the operator ask exists (commitment
  ingestion); what's missing is the OAuth flow, not the earn condition. Not
  gated by the build-lease rule.
- [ ] **G-1 / S6 — SOIL DAG + `dag_next` / `dag_status`** — route dispatch by
  `function` → default `agent_id`, and walk a multi-step plan. Design exists
  (S6), tools absent (verified). Earn-first: no consumer today — the orchestrator
  dispatches explicitly. Build when a multi-step orchestration flow needs it.
  `earn_mode: user-lease`.

### Security / gate follow-ups (red-team 2026-07-31 → `docs/BUGS.md`)

- [x] **B-47** — Documented: README.md's "MCP config" section states the
  repo's `.cursor/mcp.json` is dev-only, names the missing env vars and
  what each absence means. Nothing to move -- this config never held
  fleet secrets by design.
- [x] **B-48** — Documented as a residual in `willow-gate-seam.md` D6, same
  class as #231: `_enforce_binding_gate` already covers `dispatch_write`
  when `WILLOW_MCP_ENFORCE_BINDING=1`, closes only once the operator also
  registers every builder seat. Making it refuse unregistered app_ids
  unconditionally was considered and deferred (breaking default-posture
  change).
- [x] **B-49** — Reconciled: already documented CLOSED in
  `willow-gate-seam.md` D3. No code change.
- [x] **B-50** — `schema_maps/` writability for `task_submit` on hardened
  installs. Done: relocated `schema_maps/<app_id>/` out from under
  `mcp_apps/<app_id>/` to its own top-level `$WILLOW_HOME` root (operator-
  approved amendment to the LOCKED `product-layout.md`) -- `paths.py`,
  `schema_profile.py`, `tree_view.py`, `tests/test_schema_profile.py` +
  `tests/test_tree_view.py`.
- [x] **B-51** — Split `verify_handoff` / `agent_clear` from builder `dispatch_write`;
  orchestrator-only verify + human attestation. Done: removed from the
  `dispatch_write` group in `gate.py`, `tests/test_gate.py` +
  `tests/test_at_m2_dispatch_lifecycle.py`.
- [ ] **B-52** — `dispatch/` trust-root + optional signed `meta.json`. Partial:
  `dispatch._meta_is_well_formed()` rejects hand-forged packets missing
  required fields, in `dispatch_read`/`dispatch_list`. Full closure still
  needs #231's uid separation.
- [x] **B-53** — Extend `ORCHESTRATOR_WRITE_TOOLS` to `dispatch_accept` +
  `handoff_write_v4`; regression for stdio `willow` without human env. Done:
  `human_session.py` + `tests/test_human_orchestrator.py` +
  `tests/test_at_m2_dispatch_lifecycle.py`.
- [x] **B-54** — Packet-party ACL on `dispatch_read` / `handoff_read`. Done:
  `dispatch.is_dispatch_party()`, checked in both `server.py` wrappers,
  `tests/test_dispatch_stack.py` + `tests/test_at_m2_dispatch_lifecycle.py`.
- [x] **B-55** — Assignment integrity (signed hash or operator-owned dispatch tree).
  Done (hash leg): `assignment_sha256` in `meta.json`, verified on
  `dispatch_read`; `dispatch_accept`/`handoff_write_v4` inherit it for free.
- [ ] **B-56** — Host egress key custody (#182) on operator workstations.
- [ ] **`intake_*`** (4) — KB-tier routing; needs jeles/binder/opus targets first.
  `earn_mode: user-lease` (also upstream-blocked on jeles/binder/opus arriving).
- [ ] **`skill_*`, `index_*` / `cmb_*`, `cbm_*`, `mem_binder_*` / `mem_ratify_*`**
  — registries and extra KB sub-stores mirroring existing store patterns.
  `earn_mode: user-lease`.
- [ ] **SOIL edges + `pg_edge_*`** (5) — graph edges over the store willow-mcp
  already owns. `earn_mode: user-lease`.
- [ ] **Maintenance / analytics readers** — `ledger_repair`, `handoff_search` /
  `handoff_rebuild`, `routing_log_read`, `session_query` / `session_review`.
  Cheap, low priority. `earn_mode: user-lease`.
- [ ] **6 integration stubs to earn** — `gmail`, `slack`, `notion`,
  `google-drive`, `datadog`, `jira`; each declared with what earns it
  (`integrations.py`). `earn_mode: two-cite` — different rule, different subject
  (see `integrations.py` `needs:` / `earned_by:` and the "twice" checklist in
  `docs/design/integrations.md §6`).

### Promoted from LEAVE (operator call, 2026-07-21 — fresh willow-2.0 diff @ `6e82a38`)

Operator elected to keep these on the radar rather than treat them as non-goals.
Still earn-first (build when a consumer needs it), but no longer written off.
All `earn_mode: user-lease` — same rule as the rest of the earn-first tier.

- [ ] **`tension_scan`** — scans the KB's frontier/contested atoms for semantic
  tensions or redundancies (contradictions between atoms). Strongest standalone
  fit: sits next to `lineage_*` / `friction_scan` / the deviation store.
- [ ] **`source_trail_verify`** — extract verifiable factual claims from text and
  check each against a source trail (fact-checking). Pairs with the KB and Jeles.
- [ ] **`infer_*`** (`infer_7b` / `infer_chat` / `infer_imagine` / `infer_speak`)
  — local/provider-routed inference: structured `mistral:7b` tasks, persona chat
  (Ollama/Gemini/Groq), image gen (OpenRouter flux-schnell), TTS. The local-first
  AI story; heavy external surface is why it was LEAVE.
- [ ] **`dream_*`** (`dream_check` / `dream_run` / `dream_schedule`) — the
  AutoDream synthesis pipeline: check conditions, run, or queue it as a Kart task.
- [ ] **`wce_*`** (`wce_check` / `wce_schedule`) — the weekly-witness ritual,
  dream's scheduled sibling (queues `wce_witness.py` as a Kart task).
- [ ] **`voice_keyterms`** — build STT keyterms for voice-input accuracy; feeds
  the existing voice subsystem.

## Leave (non-goals — do not port into a clean product without a strong reason)

`mem_jeles_*`, `outcome_*`, `routine_*`, `app_*` (SAFE-app lifecycle),
fleet-daemon ops (`fleet_reload/restart/persona/…`), `policy_*` (replaced by
envelopes), the fylgja `hook_*` / `loop_*` registries and `kart_task_run`
(replaced by "packet is boot" + the `worker`/`task_submit` path), and the
`product-layout.md` "future" shells (`packages/` loader, `ledgers/` writer).

## Cross-repo (fix lives in willow-2.0, tracked in `docs/BUGS.md`)

- [ ] **B-31** — consent writer fails open.
- [ ] **B-35** — envelope metering never written.
- [ ] **B-28** — `completed_at` set on failed tasks.
- [ ] **Kart lift-spec stage 5** — the willow-2.0 side of the executor lift
  (open by design; willow-mcp side shipped as `kartikeya`).

## Decisions (operator call, not engineering)

- [ ] **S3 / G-2 — role-envelope enforcement**: largely **subsumed** — the gate
  already enforces the registry `permissions` + `deny_tools` via the compiled
  manifest (`specialist-registry.md` S-R7, done), and `roles.py` is loader-only
  and unused at runtime. Decide: close S3, or re-scope the residual (a separate
  hook-side role check) as deliberate defense-in-depth. Not a clean build as
  written.
- [ ] **Guardian-consent — "Open questions for Sean"** (`guardian-consent-seam.md`):
  subject-identity model (stable owner-assigned handle vs per-corpus), where the
  consent store physically lives, and the Nest household default relation. These
  gate the household/UTETY consumers.
- [ ] **`gap-backlog.md §6`** — auto-drafting promotion candidates, and who
  verifies before `gap_promote` (operator / reviewer agent / quorum).
- [ ] **`schema-adaptation.md §8`** — open questions for the next schema pass
  (not blocking current writes).

@phase constraints
## Constraints

@constraint severity="critical"
- [ ] **B-31** — consent writer fails open.
