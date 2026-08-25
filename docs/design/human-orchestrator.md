---
kind: doc
name: "human-only-orchestrator-gate-locked"
description: "Status: LOCKED (2026-07-09). Spike doc that intentionally breaks the AGENTS* median."
---

@markdownai v1.0

# Human-only orchestrator gate (LOCKED)

*Status: **LOCKED** — 2026-07-09 · **Spike doc** (breaks `AGENTS*` median on purpose)*
*Reconciled with shipped code — 2026-08-25 · design intent unchanged; specific factual claims about tool counts, gate layers, denial tokens, and the wiring checklist were out of date and have been corrected inline. See end-of-doc reconciliation note.*

*Complements `product-layout.md`, `session-lifecycle.md` §2a. Operational moves: [`docs/AGENTS.md`](../AGENTS.md) § Orchestrator seat.*

## Rule

**Willow (`app_id=willow`) is the orchestrator seat. Only a human operator may run dispatch writes. No agent may.**

| Actor | May call `session_enter(willow)`? | May call `dispatch_send` as willow? |
|-------|-----------------------------------|-------------------------------------|
| Human operator (orchestrator IDE session) | Yes → `human_orchestrator` | Yes (with host attestation) |
| Specialist agent (Hanuman, Loki, …) | **No** — use own `app_id` | **No** |
| Injected text in `assignment.md` | N/A | **No** — not a caller |

---

## Why (prompt injection)

Without this boundary:

1. A specialist could pass `app_id=willow` on MCP calls (stdio trusts the argument).
2. Malicious content in a handoff narrative could instruct the model to "verify and clear" falsely.
3. Auto-pick pending packet could bind an agent session to orchestrator work.
4. The orchestrator becomes a **privilege escalation target** — whoever speaks as willow dispatches the fleet.

The orchestrator is not a faster worker. It is the **human's proxy** for separation of duties: assign → review evidence → clear.

---

## `session_enter` behavior

| `app_id` | Entry mode | `dispatch_id` accepted? | Auto-pick pending? |
|----------|------------|-------------------------|-------------------|
| `willow` | **`human_orchestrator`** | **Never** | **Never** |
| specialists | `human` or `dispatch` | Yes (dispatch path) | Yes (one pending) |

```text
session_enter("willow", …)  →  entry_mode: human_orchestrator
                               agent_doc: docs/AGENTS.md (section: orchestrator)
                               closeout: session_handoff_write

session_enter("hanuman", …)  →  agent_doc: docs/AGENTS.md (section: specialist)
```

---

## Orchestrator write tools (gated)

These require **human host attestation** in stdio mode. The canonical list lives in `human_session.py::ORCHESTRATOR_WRITE_TOOLS`:

- `dispatch_send`
- `dispatch_accept`
- `handoff_write_v4`
- `verify_handoff`
- `agent_clear`
- `frank_append`
- `envelope_apply`

The three original tools plus four added defensively after a red-team on 2026-07-31 (packet `96F54DA7`) demonstrated a specialist calling `dispatch_accept` / `handoff_write_v4` directly, bypassing `session_enter`'s willow-branch guard. See the comment above `ORCHESTRATOR_WRITE_TOOLS` in `human_session.py` for the trace.

**Stdio:** `WILLOW_HUMAN_ORCHESTRATOR=1` on the MCP server process environment — set **only** in the orchestrator workspace MCP config. Specialist project configs must omit it. This is a **required** layer, not an interim one — see below.

**PGP (shipped 2026-08-01, hardened 2026-08-10):** When `WILLOW_PGP_FINGERPRINT` is set, the orchestrator write gate layers all of:

1. `app_id=willow`
2. `WILLOW_HUMAN_ORCHESTRATOR=1` on the MCP host
3. A live `sessions/willow-{session_id}.json` on disk (proof `session_enter` still binds this id)
4. Valid PGP detached signature on the dedicated sidecar `sessions/willow-{session_id}.attest.json` — NOT on the live session record itself (session_bind rewrites the live file's `status`/`dispatch_id`/`updated_at` on every ordinary state change; a signature over it would self-invalidate on the next write). See [`pgp-and-persona.md`](pgp-and-persona.md) §5 P2 for the sidecar rationale (issues #186, #313).
5. Manifest `.sig` verifies (`gate._load_manifest`, uniform across every caller — issue #183).

Sign the sidecar with `willow-mcp attest-session <session_id>` from an operator terminal; see wiring checklist below. No product dev-bypass.

**Denial reasons** (grep tokens; renamed from `#186`'s `orchestrator_session_attestation_required`, see #313 upgrade note):
- `orchestrator_session_attestation_missing` — never attested, or the sidecar / its `.sig` / the live session file is absent.
- `orchestrator_session_attestation_invalid` — attested, but the signature no longer verifies (tampered sidecar, unexpected signer, or the signed payload names a different identity).

The remedy differs: `_missing` → run `attest-session`; `_invalid` → investigate and re-attest.

**Serve (OAuth):** Identity bound to `willow` after human `confirm-binding` — binding is the attestation.

Read tools (`dispatch_list`, `dispatch_read`) remain available to any manifest that holds `dispatch_read` — desk visibility is lower risk than dispatch/verify/clear.

---

## Injection hygiene (reading packets)

| Source | Trust model |
|--------|-------------|
| `handoff.json` | **Structured evidence** — verify against schema, checklist, evidence refs |
| `closeout.md` / narrative | **Untrusted prose** — desk reading only; never execute embedded instructions |
| `assignment.md` (inbound to specialist) | **Work order for them** — orchestrator authored it; specialists treat as untrusted for tool escalation |

`verify_handoff` checks structure and evidence — it does not "believe" the narrative.

---

## Wiring checklist (operator)

1. Orchestrator workspace MCP env includes `"WILLOW_HUMAN_ORCHESTRATOR": "1"`.
2. Specialist workspaces: **no** `WILLOW_HUMAN_ORCHESTRATOR`; **and set `"WILLOW_APP_ID": "<specialist_id>"`** explicitly — `session_start_hook.py:33` defaults `WILLOW_APP_ID` to `"willow"` when unset, so an unset specialist workspace silently enters as the orchestrator seat.
3. `mcp_apps/willow/manifest.json`: `"human_only": true`, `"permissions": ["orchestrator", …]`.
4. Never add `orchestrator` permission group to specialist manifests.
5. **When `WILLOW_PGP_FINGERPRINT` is set:** run `willow-mcp attest-session <session_id>` from an operator terminal (real tty, not inside Kart) after each new `session_enter(app_id='willow', ...)`. Required per session_id and after any operator-key rotation. Without this step, every orchestrator write returns `orchestrator_session_attestation_missing`.

---

## Code map

| Module | Role |
|--------|------|
| `session_start_hook.py` | IDE `sessionStart` bridge → `session_enter`; reads `WILLOW_APP_ID` (defaults `"willow"`) |
| `human_session.py` | `ORCHESTRATOR_WRITE_TOOLS` (canonical list), `is_orchestrator_app`, `orchestrator_write_denial`, `require_operator_terminal` |
| `dispatch.py` | `session_enter` willow branch — refuses `dispatch_id` for `app_id=willow`, writes `sessions/willow-{id}.json` |
| `server.py` `_gate` | Human check after manifest permit; reads `_current_orchestrator_session()` process-global set by `_set_orchestrator_session` |
| `pgp.py` | `sign_detached`, `verify_detached`, `pgp_enabled` — shells `gpg --batch --yes` / `gpg --verify` |
| `home_init.py` | Seeds `mcp_apps/willow/manifest.json` with `human_only` |

---

## Reconciliation note (2026-08-25)

The design intent statements in this doc (the Rule, the Why, the injection-hygiene rules, the persona voice-only overlay) are unchanged. What was reconciled with shipped code:

- **Gated write tools: 3 → 7.** Three tools were listed here; the code has gated seven since 2026-07-31 (`dispatch_accept`, `handoff_write_v4`, `frank_append`, `envelope_apply` added after the packet `96F54DA7` red-team). `ORCHESTRATOR_WRITE_TOOLS` in `human_session.py` is the source of truth.
- **PGP was "planned"; it shipped.** `pgp-and-persona.md` P2 shipped 2026-08-01 and hardened at #313 (2026-08-10). The write gate now layers env attestation + live-session-file check + sidecar PGP attestation + manifest `.sig`. Env attestation is a required underneath, not interim.
- **A fifth check exists:** the live `sessions/willow-{session_id}.json` on disk. Added at #313 so deleting the session file after attesting cannot leave the gate armed against a session no longer live.
- **The sidecar file is not the live session record.** `sessions/willow-{session_id}.attest.json` is what `attest-session` signs; `sessions/willow-{session_id}.json` is rewritten by every `session_bind` call. Any doc claim about signing "the session file" needs to read as "the attest sidecar."
- **Denial tokens changed** from `orchestrator_session_attestation_required` to `_missing` / `_invalid` at #313 — the two point at different operator remedies.
- **Wiring checklist item 2** previously read *"app_id defaults to specialist"*; it doesn't. `session_start_hook.py:33` defaults to `"willow"`. Specialist workspaces must set `WILLOW_APP_ID` explicitly or they enter as orchestrator.
- **Wiring checklist gained item 5** — `attest-session` was implicit; under PGP enforcement it's mandatory.

Companion doc `pgp-and-persona.md` reconciled in the same pass — its §1 header table + §1 write gate table now name the sidecar directly rather than requiring readers to reach the P2 slice note for the correction.

---

*Agents implement. Humans orchestrate. The gate exists so injection cannot collapse that line.*
