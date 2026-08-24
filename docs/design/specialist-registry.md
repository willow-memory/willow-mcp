---
kind: doc
name: specialist-registry-schema-draft
description: "DRAFT schema unifying specialist definition (Function/Name/Roles/persona) across willow-mcp's JSON registry, Postgres table, and compiled manifests; permissions are ratified in permissions-matrix.md but registry source-of-truth and fail-closed defaults remain open."
---

@markdownai v1.0

# Specialist registry — schema (DRAFT)

*Status: **DRAFT** — 2026-07-09*  
*Permissions: **RATIFIED** — see `permissions-matrix.md`; compiled via `willow-mcp compile-agents`.*

Companion: `agent-seed.md` · `pgp-and-persona.md` · `human-orchestrator.md` · `product-layout.md` · `session-lifecycle.md`

---

@phase 1-purpose
## 1. Purpose

Unify specialist definition in **one registry** that serves:

| Consumer | Gets |
|----------|------|
| **Machine** | PG table or `config/specialists.json`; compiled `mcp_apps/{id}/manifest.json` |
| **User** | `docs/ROLES.md` table; assignment headers; orchestrator desk |
| **Session** | Silent persona inject on dispatch `session_enter`; no specialist picker |

Today this is scattered across `roles.py`, `agent_roster.json`, `persona_envelopes.json`, per-app manifests, and fleet `personas/*.md`. This doc is the target shape.

**Orchestrator (`willow`) is a separate seat class** — see §6. Specialists are dispatchable workers; Willow is human-only orchestrator.

---

@phase 2-column-schema-user-machine
## 2. Column schema (user + machine)

| Column | JSON / PG field | User label | Notes |
|--------|-----------------|------------|-------|
| **Function** | `function` | Function | Machine category — DAG routing, dispatch templates. Enum: `BUILD`, `AUDIT`, `RESEARCH`, `OPERATE`, `EMISSARY`, `ARCHITECT`, … |
| **Name** | `agent_id` | Name | Stable id: `hanuman`, `loki`. Equals `app_id`, Grove sender default, manifest dir name. |
| **Display** | `display_name` | — | Human label: "Hanuman", "Jeles". |
| **Roles** | `roles` | Roles | Tag list for routing, envelopes, meta.json. Primary in `role`. |
| **Role (primary)** | `role` | — | Single default for packets: `builder`, `auditor`, `librarian`, … |
| **Tool permissions** | `permissions` | Tool use | Gate permission groups. See `permissions-matrix.md`. |
| **Deny tools** | `deny_tools` | — | Explicit tool denials overlay (wins over allows). |
| **Persona file** | `persona_path` | Persona | Path to voice `.md` (relative to bundle or `$WILLOW_HOME/personas/`). |
| **Persona preload** | `persona_bundle` | — | Copy into wheel bundle on publish. |
| **Entry mode** | `entry_mode` | — | Default `dispatch`; `human` allowed for freeform resume. |
| **Store scope** | `store_scope` | — | SOIL collection prefixes. Implemented: `gate.store_scope()` / `collection_permitted()` — exact names or `prefix*` wildcards, fail-closed (B-24/B-25). |
| **Namespace** | `namespace` | — | SOIL/KB write lane prefix, e.g. `hanuman/`. |
| **Mandate** | `job` | — | One-line job description for assignments. |
| **Not** | `not_job` | — | Anti-patterns / out-of-scope defaults. |
| **Receive dispatch** | `receive_dispatch` | — | `true` for specialists. |
| **Grove sender** | `grove_sender` | — | Defaults to `agent_id`. |
| **Model hint** | `model_hint` | — | Optional UX only (Nest zero-cost map); not enforced. |
| **Sort order** | `sort_order` | — | Docs / desk ordering. |

### Optional later columns

| Field | Purpose |
|-------|---------|
| `kb_scope` | Postgres KB lane filter |
| `skills[]` | Default skill paths for this specialist |
| `signature` | PGP over canonical row blob — registry row doesn't land if sig mismatch |

---

@phase 3-function-vs-name-vs-roles
## 3. Function vs Name vs Roles

```
Function   WHAT (machine)     BUILD, AUDIT, RESEARCH, OPERATE
Name       WHO  (identity)    hanuman, loki, jeles  → agent_id
Roles      HOW  (tags)        builder, coordinator — routing + envelopes
role       primary tag        one default per packet
```

- **DAG** (future S6): routes by `function` → default `agent_id`.
- **Dispatch**: `dispatch_send(to_app=<Name>, …)`.
- **Packet** `meta.json`: `role`, `persona` (= `agent_id`), optional `persona_voice` one-liner; full voice from `persona_path` at `session_enter`.

---

@phase 4-specialist-rows-identity-mandate
## 4. Specialist rows (identity + mandate)

> Policy: `permissions-matrix.md`. Registry seed: `bundle/config/specialists.json`.

### Core five (+ extended fleet identities)

| Function | Name (`agent_id`) | Display | Roles | Persona file | Mandate (summary) | Not |
|----------|-------------------|---------|-------|--------------|-------------------|-----|
| BUILD | `hanuman` | Hanuman | builder, coordinator | `personas/hanuman.md` | Code, builds, tests, Kart; worktree + PR | Direct master commits |
| AUDIT | `loki` | Loki | auditor | `personas/loki.md` | Gap analysis, adversarial review | Build, KB writes |
| RESEARCH | `jeles` | Jeles | librarian, retrieval | `personas/jeles.md` | Retrieval, citation, sourced synthesis | Designer, builder, ADR author |
| OPERATE | `ada` | Ada | operator, monitor | `personas/ada.md` | Monitor-first, diagnostics, uptime | Change agent |
| EMISSARY | `skirnir` | Skirnir | gate, witness | `personas/skirnir.md` | Gate-witness, emissary | — |
| ARCHITECT | `vishwakarma` | Vishwakarma | architect, safe | `personas/vishwakarma.md` | SAFE / app-store architecture | Implementation default |

### Permissions (ratified 2026-07-09)

See **`permissions-matrix.md`** for the full allow/deny/scope table. Compile after edits:

```bash
willow-mcp compile-agents          # missing manifests only
willow-mcp compile-agents --force  # overwrite all
```

---

@phase 5-json-schema-standalone-seed
## 5. JSON schema (standalone / seed)

**Path:** `$WILLOW_HOME/config/specialists.json` (materialized by `willow-mcp-init` from product bundle).

```json
{
  "format": "specialist_registry_v1",
  "updated_at": "2026-07-09T00:00:00Z",
  "specialists": [
    {
      "agent_id": "hanuman",
      "function": "BUILD",
      "display_name": "Hanuman",
      "role": "builder",
      "roles": ["builder", "coordinator"],
      "permissions": [],
      "deny_tools": [],
      "persona_path": "personas/hanuman.md",
      "persona_bundle": true,
      "entry_mode": "dispatch",
      "store_scope": null,
      "namespace": "hanuman/",
      "job": "Code, builds, tests, Kart — worktree + PR",
      "not_job": "Direct master commits",
      "receive_dispatch": true,
      "grove_sender": "hanuman",
      "model_hint": "",
      "sort_order": 10
    }
  ]
}
```

**Empty `permissions` / `deny_tools` until operator decides** — compiled manifests must fail closed or use minimal read-only default until signed.

---

@phase 6-postgres-preloaded-when-db-wired
## 6. Postgres (preloaded — when DB wired)

```sql
CREATE TABLE IF NOT EXISTS specialists (
  agent_id         TEXT PRIMARY KEY,
  function         TEXT NOT NULL,
  display_name     TEXT NOT NULL,
  role             TEXT NOT NULL,
  roles            JSONB NOT NULL DEFAULT '[]',
  permissions      JSONB NOT NULL DEFAULT '[]',   -- per-role values ratified in permissions-matrix.md
  deny_tools       JSONB NOT NULL DEFAULT '[]',   -- per-role overlay; enforced in gate.permitted()
  persona_path     TEXT NOT NULL,
  persona_bundle   BOOLEAN NOT NULL DEFAULT true,
  entry_mode       TEXT NOT NULL DEFAULT 'dispatch',
  store_scope      JSONB,
  namespace        TEXT,
  job              TEXT,
  not_job          TEXT,
  receive_dispatch BOOLEAN NOT NULL DEFAULT true,
  grove_sender     TEXT,
  model_hint       TEXT,
  sort_order       INT NOT NULL DEFAULT 0,
  human_only       BOOLEAN NOT NULL DEFAULT false
);
```

Seed from bundle JSON on `willow-mcp-init` or migration. Bitemporal versioning optional later (fleet pattern).

---

@phase 7-orchestrator-seat-not-a-specialist-row
## 7. Orchestrator seat (not a specialist row)

| Function | Name | Seat | Entry | Picker | Permissions |
|----------|------|------|-------|--------|-------------|
| ORCHESTRATE | `willow` | orchestrator | `human_orchestrator` | Charter hook only | Ratified — `orchestrator` group in `gate.py` (~40 tools); `dispatch_write` excludes `verify_handoff`/`agent_clear` (B-51). |

Stored separately: `config/orchestrator.json` or top-level flag `human_only: true` on willow manifest — not mixed into specialist picker lists.

---

@phase 8-materialization-pipeline
## 8. Materialization pipeline

```
specialists.json (or PG specialists)
        │
        ├─► mcp_apps/{agent_id}/manifest.json   (permissions, store_scope, role)
        ├─► manifest.json.sig                   (operator PGP — one fingerprint)
        ├─► personas/{agent_id}.md              (bundle → $WILLOW_HOME/personas/)
        └─► docs/ROLES.md                       (generated user table)
```

**Rule:** Do not hand-edit compiled manifests long-term; edit registry, run `willow-mcp compile-agents` (future CLI).

---

@phase 9-session-behavior-specialists
## 9. Session behavior (specialists)

### Dispatch path (default)

```
dispatch_send(to_app=hanuman, …)
  → meta.json: role, persona, function from registry

session_enter(hanuman, session_id, dispatch_id)
  → entry_mode: dispatch
  → load persona_path (silent — no picker)
  → inject assignment.md
  → closeout: handoff_write_v4
```

### Human path (freeform resume)

```
session_enter(hanuman, session_id)
  → entry_mode: human
  → default voice from persona_path (still no picker)
  → closeout: session_handoff_write
```

**No interactive persona picker on specialist seats** — charter orchestrator only (`pgp-and-persona.md`).

---

@phase 10-user-created-extensions-tbd
## 10. User-created extensions (TBD)

| Type | Allowed? | Notes |
|------|----------|-------|
| Custom persona voice (`.md`) | Discuss | Overlay on existing `agent_id` — voice only |
| New `agent_id` | Requires signed registry row | Prevents injection minting `evil` with dispatch perms |
| User specialist row | Discuss | `$WILLOW_HOME/config/user_specialists.json` |

---

@phase 11-implementation-slices
## 11. Implementation slices

| Slice | Deliverable | Blocked on |
|-------|-------------|------------|
| S-R1 | This doc + JSON schema `specialist_registry_v1` | — |
| S-R2 | `config/specialists.json` seed (identity/mandate only; empty permissions) | — |
| S-R3 | `compile-agents` → manifests | **done** |
| S-R4 | PG table + seed migration | permissions decision |
| S-R5 | `session_enter` loads `persona_path` from registry | **done** |
| S-R6 | `specialist_list` / `specialist_get` MCP tools | **done** |
| S-R7 | Gate enforces registry `permissions` + `deny_tools` | **done** |

---

@phase 12-deprecations
## 12. Deprecations

| Current | Future |
|---------|--------|
| `src/willow_mcp/roles.py` `ROLE_ENVELOPES` allow/deny | Registry row; `roles.py` becomes loader only |
| `config/agent_roster.json` | Merged into `specialists.json` |
| `config/persona_envelopes.json` | Compiled from registry or removed |
| Hand-edited `mcp_apps/*/manifest.json` | Compiled + signed |

---

@phase 13-open-decisions-operator
## 13. Open decisions (operator)

1. ~~**Permissions per role**~~ — ratified in `permissions-matrix.md` (2026-07-09).
2. **Registry source of truth** — JSON in `$WILLOW_HOME` vs PG-primary vs repo-tracked bundle.
3. **Default bundle** — core five only vs full extended fleet in product wheel.
4. **User persona overlays** — allowed on charter only vs all projects.
5. **Fail-closed default** — empty `permissions` denies all tools vs read-only skeleton until signed.

---

*Written after session crash mid-design. Permissions explicitly undecided — update §4 table when policy is ratified.*

---

@phase constraints
## Constraints

@constraint severity="normal"
**No interactive persona picker on specialist seats** — charter orchestrator only (`pgp-and-persona.md`).
