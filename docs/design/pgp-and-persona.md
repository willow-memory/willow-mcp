---
kind: doc
name: pgp-persona-locked-decisions
description: "Locked decisions (draft 1.0, 2026-07-09) on PGP as willow-mcp's sole operator trust root and persona as a voice-only overlay that never touches app_id, Grove sender, or SOIL namespace."
---

@markdownai v1.0

# PGP + persona (LOCKED decisions)

*Status: **LOCKED** draft 1.0 — 2026-07-09*
*Reconciled with shipped code — 2026-08-25 · design intent unchanged; §1 header table and §1 write gate table now name the sidecar directly (previously buried in §5 P2 slice note), and the gated-tool count and 5th check are aligned with `human_session.py`. See end-of-doc reconciliation note.*
*Companion: `human-orchestrator.md` · `product-layout.md` · `session-lifecycle.md`*

---

@phase 1-pgp-operator-trust-root
## 1. PGP — operator trust root

### No product dev-bypass

willow-mcp ships **one mode: verify or deny**. There is no `dev_bypass`, no
`pgp_enforced` toggle, no "openable" escape hatch in product code that agents
or misconfiguration can stumble into.

The operator (you) may set **explicit env vars on the MCP host** you control.
That is outside the product's policy surface — not a code path agents invoke.

| Env (operator-set only) | Purpose |
|-------------------------|---------|
| `WILLOW_PGP_FINGERPRINT` | Required primary fingerprint — **one key for everything** |
| `WILLOW_HUMAN_ORCHESTRATOR` | Seat marker: this MCP host is the charter orchestrator workspace |

If `WILLOW_PGP_FINGERPRINT` is unset → PGP checks **fail closed** (deny signed operations).
If set → every signature must match that fingerprint or **it doesn't land**.

### One fingerprint, all artifacts

Same operator key signs:

| Artifact | Path |
|----------|------|
| App manifest | `mcp_apps/{app_id}/manifest.json` + `.sig` |
| Human session attestation | `sessions/willow-{session_id}.attest.json` + `.sig` — dedicated sidecar carrying only the stable `{app_id, session_id}` tuple (`paths.session_attestation_path`). **Not** the live `sessions/willow-{session_id}.json` record, which `session_bind` rewrites on every state change. See §5 P2 for the sidecar rationale. |
| Dispatch packet (phase P3) | `dispatch/{id}/meta.json` + `.sig` |
| Optional persona roster changes | `config/persona_roster.json` + `.sig` |
| Agent seed (ratified) | `$WILLOW_HOME/seeds/{agent_id}.json` + `.sig` — see `agent-seed.md` |

**Rule:** `gpg --verify` → parse `VALIDSIG` primary fingerprint → compare to
`WILLOW_PGP_FINGERPRINT`. Mismatch = deny. No alternate trusted keys in product.

Port verification logic from `willow-2.0/sap/core/gate.py::_verify_pgp` — do not
port `dev_bypass` / `_DEV_SAFE_ROOT`.

### Orchestrator write gate (layered)

The gated tools are enumerated in `human_session.py::ORCHESTRATOR_WRITE_TOOLS` — currently `dispatch_send`, `dispatch_accept`, `handoff_write_v4`, `verify_handoff`, `agent_clear`, `frank_append`, `envelope_apply`, `envelope_propose`, `envelope_ratify`, `envelope_reject` (ten tools — three originals plus four added 2026-07-31 after the packet `96F54DA7` red-team showed direct calls bypassing `session_enter`'s guard; plus three added in the envelope-accrual PR5 so authoring the operator's yes/no also requires keyring attestation). Each requires **all** of:

1. `app_id=willow`
2. `WILLOW_HUMAN_ORCHESTRATOR=1` on MCP host (charter seat config)
3. **Live `sessions/willow-{session_id}.json` on disk** — proof `session_enter` still binds this id. Added at #313 so deleting the live session file after attest cannot leave the gate armed against a session no longer live.
4. Valid PGP detached signature on the **sidecar** `sessions/willow-{session_id}.attest.json` — NOT on the live session record (see the header table row above and §5 P2 for why the sidecar exists). When PGP enabled.
5. Manifest `.sig` verifies. When PGP enabled.

Env-only was interim until P2 landed (issue #186); checks 1-2 are still required underneath, and 3-4 layer on top once `WILLOW_PGP_FINGERPRINT` is set. Manifest `.sig` (5) already enforces uniformly via `gate._load_manifest` (#183). Denial-reason tokens: `orchestrator_session_attestation_missing` (never attested / no live session file / no sidecar) vs `orchestrator_session_attestation_invalid` (sidecar present but signature no longer verifies) — see Upgrade note under §5.

### Signing stays host-side

`willow-mcp sign-manifest`, `willow-mcp attest-session` — operator terminal only.
Kart bwrap cannot reach gpg-agent (fleet lesson). Agents **request**; operator **signs**.

### Keyring path (PR1-PR8, 2026-08-25) — the new primary identity substrate

**PGP is no longer the only path.** The identity-in-session line (PRs #372-#376) ported the Nestor §5.8 per-verifier keyring into willow-mcp as `src/willow_mcp/keyring.py`, added client-side ed25519 signing via `sign_session` (`src/willow_mcp/session_signing.py`), and made the orchestrator write gate verify against BOTH paths — a v2 keyring sidecar OR a v1 PGP sidecar. New deployments should prefer the keyring path; PGP remains as legacy_key for migration and stays fully supported.

| Path | Signing tool | Identity substrate | Sidecar format |
|------|--------------|--------------------|----------------|
| **Keyring (PR1-PR8, preferred)** | `willow-mcp sign-session <session_id> --verifier NAME` or automatic on SessionStart when `WILLOW_OPERATOR_VERIFIER=NAME` is set (PR8) | `src/willow_mcp/keyring.py` (Ed25519 per-verifier) | `orchestrator_session_attestation_v2` — `{format, app_id, session_id, verifier, attested_at}` + hex ed25519 sig |
| **PGP (legacy)** | `willow-mcp attest-session <session_id>` | System `gpg` + `WILLOW_PGP_FINGERPRINT` | `orchestrator_session_attestation_v1` — `{format, app_id, session_id, attested_at}` + detached ASCII sig |

Both paths use the same layered gate above (checks 1-5) and the same denial tokens (`_missing` / `_invalid`). `orchestrator_write_denial` (`human_session.py`) resolves which sidecar shape to verify by reading the sidecar's `format` field.

**Compromised verifier discipline (PR8 Commit A):** the SessionStart auto-sign path REFUSES to open a session when `WILLOW_OPERATOR_VERIFIER` names a key that is unknown to the keyring OR has been revoked as compromised. `verifying_entry` returns None for both cases; the Nestor prior ("warn when the check can't be reliable; refuse when it can") applies. A compromised key that continued under graceful degrade would be exactly the fail-quiet-and-compound pattern the fleet forbids.

**Attribution cache (PR4):** `human_session._attributed_sessions` is a process-local set — the first orchestrator write per session pays the sidecar verify, subsequent writes are O(1). Cache-by-path: revocation across processes requires operator restart (mirrors `nestor.keyring`'s policy). `sessions_read_unverifiable` MCP tool (PR4) enumerates sessions whose sidecar exists but no longer verifies — the browsable trust-view after a rotation.

**Attribution rides dispatch (PR9):** `dispatch_send` writes `from_verifier` + `from_session` into the signed meta.json; `dispatch_accept` and `session_enter`'s specialist branch lift those fields onto the specialist's session record and into the attribution cache. A specialist inherits the operator's attribution through the dispatch packet, so its own gate misses can auto-propose envelopes attributed to the ORIGINATING operator — the queue view stays a queue of humans, not proxying processes.

The whole envelope-accrual loop (PR5-PR12) presumes an attributed session. Both paths above satisfy that presumption; a session with neither is unattributed and cannot auto-propose or ratify.

---

@phase 2-persona-new-shape-stays-forks
## 2. Persona — new shape (stays, forks)

Persona is **voice only** — never changes `app_id`, Grove sender, or SOIL namespace.

### Where picker lives

| Seat | Interactive picker? | Implementation home |
|------|---------------------|---------------------|
| **Charter orchestrator** (`~/github/willow`) | **Yes** | Host hook (fylgja / Cursor SessionStart) — **not** willow-mcp product core |
| **Specialist dispatch** | **No** — silent | `meta.json` `persona` / `role` → context injection via `session_enter` |
| **Specialist human entry** | **No** — default from manifest | `mcp_apps/{app_id}/manifest.json` `role` |

willow-mcp documents the contract; it does not ship the orchestrator menu UI.

### Specialist silent persona (packet)

```json
{
  "role": "loki",
  "persona": "loki",
  "persona_voice": "One-line cognitive frame for this assignment."
}
```

Injected on dispatch `session_enter` — no blocking, no menu.

---

@phase 3-persona-roster-project-scoped-user-extensions-draft-discuss
## 3. Persona roster — project-scoped + user extensions (DRAFT — discuss)

Two namespaces, merged at picker render time on **charter seat only**:

### A. Project roster (short, scoped)

**Source:** `<project_root>/.willow/personas.json` (or charter repo `personas/roster.json`)

- Curated by project owner — **small list** (e.g. 3–7 entries)
- Entries reference voice keys + optional one-line blurb
- May include `"locked": true` binding for this project (charter seat → Willow only)
- **Signed** when roster changes matter (`persona_roster.json.sig` optional slice)

Example:

```json
{
  "format": "persona_roster_v1",
  "project": "willow",
  "entries": [
    {"key": "willow", "label": "Willow — magistrate voice", "locked": true},
    {"key": "publius", "label": "Publius — deliberate consensus"},
    {"key": "jeles", "label": "Jeles — librarian lens (voice only)"}
  ]
}
```

**Principle:** project folder defines **which voices are in scope** for this desk —
not the full fleet menagerie.

### B. User extensions (operator-owned)

**Source:** `$WILLOW_HOME/personas/{key}.md` + `$WILLOW_HOME/config/user_personas.json`

- Operator creates custom personas (`+ Create new` in picker)
- Stored under **home**, not committed to project repo
- Available across projects unless project roster sets `"allow_user_extensions": false`
- Never grant orchestrator perms — voice overlay only

### Merge rules (picker render)

```
display_list = project_roster.entries
if allow_user_extensions (default true):
    display_list += user_personas not already in project keys
always append: { key: "__create__", label: "+ Create new persona" }
if project binding locked:
    hide picker — inject bound persona only
```

### Open questions (operator)

1. **Default `allow_user_extensions`?** — `true` (fleet today) vs `false` on charter seat?
2. **Jeles on orchestrator roster?** — voice lens yes; role remains librarian for dispatch targets.
3. **Roster in repo vs `.willow/`?** — charter: committed `personas/roster.json`; other projects: `.willow/personas.json` gitignored?
4. **PGP-sign roster changes?** — required on charter repo commits, or only at runtime load?

---

@phase 4-file-map-additions
## 4. File map additions

```
$WILLOW_HOME/
├── config/
│   ├── user_personas.json      # user-created persona registry
│   └── persona_roster.json     # optional home-level override
├── personas/
│   └── {key}.md                # user persona voice prose

<project_root>/
└── .willow/
    └── personas.json           # short project-scoped roster (charter: or personas/roster.json in repo)
```

---

@phase 5-implementation-slices
## 5. Implementation slices

| Slice | Deliverable | Status |
|-------|-------------|--------|
| P1 | `pgp.py` — verify only, fail closed, port from fleet gate | Shipped |
| P1 | Manifest `.sig` check in `gate.permitted()` when fingerprint env set | **Shipped 2026-07-31 (B-45, issue #183)** — landed in `gate._load_manifest()` rather than `permitted()` directly, so every caller of `_load_manifest` (`authorized`, `store_scope`, `permitted`, …) denies uniformly, not just the one this slice named. `willow-mcp sign-manifest` CLI added alongside. |
| P2 | `attest_session` CLI + session file `.sig` | **Shipped 2026-08-01 (issue #186), re-pointed 2026-08-10 (issue #313)** — `willow-mcp attest-session <session_id>` detach-signs a dedicated `sessions/willow-{session_id}.attest.json` sidecar holding only the stable `{app_id, session_id}` identity tuple (`paths.session_attestation_path`) — no longer the live `sessions/willow-{session_id}.json` record itself. That record carries mutable operational state (`status`/`dispatch_id`/`updated_at`) the server rewrites on every `session_bind` call (`session_enter`, `dispatch_accept`, `session_handoff_write`, `agent_clear`), so a signature over it self-invalidated on the very next ordinary write — including the closeout write that was supposed to end the session cleanly. The sidecar is written once, atomically with its `.sig`, by `attest-session`, and normal session writes never touch it. Operator-terminal only, same Kart/tty guard as `sign-manifest`. |
| P2 | Orchestrator write gate checks attestation | **Shipped 2026-08-01 (issue #186), hardened 2026-08-10 (issue #313)** — `human_session.orchestrator_write_denial` now also requires a valid signature on the *current* orchestrator session's attestation sidecar once `WILLOW_PGP_FINGERPRINT` is set (stdio only; serve mode keeps trusting the confirmed OAuth binding, unchanged), **and** a live `sessions/willow-{session_id}.json` on disk (proof `session_enter` still binds this id). Orchestrator write tools don't all carry a `session_id` argument, so the session the check verifies against is server-process state set by `session_enter(app_id='willow', ...)` (`server._set_orchestrator_session` / `_current_orchestrator_session`, read back in `_gate`) rather than a per-call parameter — no tool signature changed. Env-only attestation (`WILLOW_HUMAN_ORCHESTRATOR=1`) stays required underneath; this layers on top of it, not instead of it. The denial reason now distinguishes `orchestrator_session_attestation_missing` (never attested, or the sidecar/its `.sig`/live session file is absent) from `orchestrator_session_attestation_invalid` (attested, but the signature no longer verifies — tampered sidecar, unexpected signer, or the signed payload naming a different identity) — the operator's remedy differs between the two. **Token rename:** `#186` used `orchestrator_session_attestation_required` for both cases; parsers must switch to `_missing` / `_invalid`. |

---

### Upgrade note (#313)

After deploying the sidecar change:

1. **Re-attest once** for every live orchestrator session under PGP enforcement. Detached signatures on `sessions/willow-<id>.json` (the `#186` shape) are **ignored**; only `sessions/willow-<id>.attest.json` + `.sig` count.
2. **Denial tokens changed.** `orchestrator_session_attestation_required` is gone. Match `orchestrator_session_attestation_missing` (never attested / no live session file / no sidecar) or `orchestrator_session_attestation_invalid` (sidecar present but BAD).
3. A failed `attest-session` re-sign rolls the sidecar (and its `.sig`) back to the previous bytes — it never leaves a fresh unsigned sidecar on disk.

---

@phase 6-what-we-explicitly-reject
## 6. What we explicitly reject

- Product `dev_bypass` / `pgp_enforced` mode switch
- Interactive persona picker in willow-mcp pip package (charter hook only)
- Persona changing `app_id` or manifest permissions
- Multiple trusted PGP fingerprints in product code
- Agents signing anything inside Kart sandbox

---

*Operator decisions locked 2026-07-09: no dev bypass in product; one fingerprint; charter picker only; project roster + user extensions (details §3 open).*

---

## Reconciliation note (2026-08-25)

The design decisions in this doc — one fingerprint, no dev bypass, sidecar rather than live-record signing, host-side signing only — are unchanged. What was reconciled with shipped code so a reader top-to-bottom no longer sees the old shape first and has to reach §5 P2 for the correction:

- **§1 header table row for "Human session attestation"** now names `sessions/willow-{session_id}.attest.json` + `.sig` directly and cites the reason. Previously the header table said `sessions/willow-{session_id}.json`; only the P2 slice note (still below) explained the change.
- **§1 Orchestrator write gate table** now enumerates all seven gated tools (was three), adds check 3 (live session file on disk, added at #313), renames check 4 to name the sidecar rather than the live record, and lists the two denial-reason tokens. The doc previously mismatched `human-orchestrator.md` on tool count and mismatched itself on which file gets signed.
- **§5 P2 slice notes remain the source of truth for history** — they explain WHY the sidecar exists and why the gate hardened at #313. The §1 tables now agree with them at first read.
- Companion doc `human-orchestrator.md` reconciled in the same pass — its §Orchestrator write tools section, wiring checklist, and code map now match `human_session.py`.

@phase constraints
## Constraints

@constraint severity="critical"
- Operator creates custom personas (`+ Create new` in picker)
