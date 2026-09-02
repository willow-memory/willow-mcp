---
name: orchestrator-routing
description: Willow seat routing — script-first and local-model defaults before cloud reasoning
---

@markdownai v1.0

# Orchestrator routing — script first, local models second

Willow seat (`app_id=willow`). **Take the job off the cloud model.** Run deterministic tools and scripts; reserve this session's reasoning for judgment, synthesis, and operator-facing decisions.

Shell front-end: `bash scripts/willow-seat.sh` (repo `willow-memory`).

---

## Routing ladder (strict order)

| Step | Question | Action | Not this |
|------|----------|--------|----------|
| 1 | Sealed fact? | `nestor_ask` / `nestor_check` — serve verbatim if sealed | Re-derive from memory |
| 2 | Deterministic? | `tools/*.py`, `scripts/fleet_seams.py`, `code_graph_*`, `gap_*`, `friction_scan`, `mai_lint.py` | Eyeball in chat |
| 3 | MCP read? | `wtool.py` or `willow-seat.sh wtool` | Re-implement query logic |
| 4 | Jeles corpus? | `federation_call` → `8cae3d1dcdf4` / `willow-seat.sh jeles` | Direct jeles MCP in Cursor; **`willow_web_*` / search-shaped `integration_call`** |
| 5 | Shell / git / network? | `task_submit` (Kart) after `fleet_health` | Raw bash (hooks steer) |
| 6 | NL → tool unknown? | `nestor_tool_route` — served or queued, never guess | Invent tool name |
| 7 | Draft only? | Loopback Ollama via Nestor (`nestor_draft`, `willow-lane4-3b` / `llama3.2:3b`) | Auto-seal or treat draft as fact |
| 8 | Open synthesis | Cloud seat (this session) | Default first |

---

## Script plane

| Job | Script / command |
|-----|------------------|
| Desk + health probe | `willow-seat.sh probe` |
| Dispatch queue | `willow-seat.sh desk` |
| Any MCP tool from shell | `willow-seat.sh wtool <tool> '<json>'` |
| Jeles federated call | `willow-seat.sh jeles <tool> ['<json>']` |
| Fleet seam check | `willow-seat.sh seams` |
| Ollama inventory | `willow-seat.sh ollama` |
| @markdownai lint | `willow-seat.sh lint-mai <paths>` |
| Gate manifest union | `tools/provision_gate.py` |

`wtool.py` is the substrate — every script should call through it, not re-spawn ad hoc MCP clients.

---

## Local models (when written for)

| Use | Model / path | Gate |
|-----|--------------|------|
| Nestor draft (suggestions only) | `willow-lane4-3b:latest` or `llama3.2:3b` via `OLLAMA_HOST` loopback | `nestor_draft`; human seals |
| Nest intake classify/embed | `nest_scan(use_embed=…, use_llm=…)` | Loopback Ollama; Kart `allow_localhost` |
| Specialist monitor seats (Loki, Ada) | `model_hint: local-3b` in specialists.json | Dispatch to those seats for audit/monitor |
| Voice ingress | whisper + Kokoro (`willow-mcp voice`) | Pure-script state machine; models injected |
| Cloud fallback | `WILLOW_INFERENCE_PROVIDER=auto` + keys | `consent.cloud_llm` for off-box |

**Never** treat `corpus_put`, `nestor_draft`, or unsealed KB as verified. Confidence ladder: `verified > corroborated > institutional > unverified`.

---

## Jeles replaces Willow web/integration egress (operator policy)

When **jeles-corpus federation is ratified and working** (`federation_call` → `8cae3d1dcdf4` succeeds):

| Retired for the willow seat | Use instead (federated jeles) |
|----------------------------|-------------------------------|
| `willow_web_search`, `willow_web_fetch`, `willow_institutional_search` | `corpus_web_search`, `corpus_institutional_search`, `corpus_verify_claim`, `corpus_host_card` |
| `integration_call` → `jeles` (remote search adapter) | Same corpus tools via federation — one organ, guarded at spawn |
| Granting `web_net` / `integration_net` to willow | **Do not pursue** while jeles federation is healthy |

**Do not grant** `web_net` or `integration_net` to the willow manifest for search/fetch work — that duplicates jeles behind a second egress class.

**Still separate (not replaced by jeles):** `integration_call` to **GitHub**, **Pangolin**, **UTETY**, **HuggingFace hub** when the job is a structured API (repos, PRs, vault resources) — not open-web or institutional catalogue search. Those remain earn/grant decisions; default is still jeles-first for anything jeles already covers.

**Failure mode:** if `federation_call` to jeles fails (consent, lease, spawn, guard), log it and surface — do not silently fall back to `willow_web_*` without operator say-so.

---

## Earn-first families (not live without operator grant)

`infer`, `dream`, `workflow`, `wce`, … — rostered in `build_lease.py`. Operator runs `willow-mcp grant-build <family> --ttl 30m --reason "…"` before implementation work. Agent may propose; never self-grant.

---

## Session habits

1. `session_enter` → `willow-seat.sh probe` (not hand-rolled status checks).
2. Before `task_submit`: `fleet_health` — stranded queue = stop.
3. Before `federation_call`: gates show `mcp_federation` + `consent.federation` + active lease.
4. Close with `session_handoff_write`; attach `verify` specs on action-driving claims (KB `7FE7CDC6`).
