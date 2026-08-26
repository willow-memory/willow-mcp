---
kind: doc
name: "session-lifecycle-willow-mcp"
description: "Draft 0.3 (2026-07-09, unratified) — session lifecycle design for willow-mcp: repo boundary, session modes, packet structure, closeout, envelopes/manifests, orchestrator flow, file map, and implementation slices."
---

@markdownai v1.0

# Session lifecycle — willow-mcp

*Draft 0.3 — 2026-07-09 — unratified.*

**Product:** [willow-mcp](https://github.com/willow-memory/willow-mcp) — agent-neutral MCP server (SOIL + Postgres KB + Kart).  
**Not in scope:** willow-2.0 fylgja hooks (`session_start.py`, persona picker, boot-done flags, Grove daemons). Those are fleet-internal; this design is what **any MCP client** gets from willow-mcp alone.

**North star:** [`WILLOW Complete System`](../../../Desktop/Nest/WILLOW%20Complete%20System.txt) (operator packet, July 2026) — zero-cost, packet-is-boot, orchestrator loop.

**Layout:** [`product-layout.md`](product-layout.md) (LOCKED) — repo + `$WILLOW_HOME` tree; run `willow-mcp-init` to scaffold.

**Specialists:** [`specialist-registry.md`](specialist-registry.md) (DRAFT) — unified Function/Name/Roles/persona schema; **tool permissions per role not decided yet**.

**Participant model:** [`agent-seed.md`](agent-seed.md) (DRAFT) — `agent_seed_v1` cognitive boot; orthogonal to registry permissions.

**Principle:** JSON for routing and machine state. **Markdown for assignments, findings, and narrative.**

---

@phase 1-repo-boundary
## 1. Repo boundary

| Layer | Repo | What it owns |
|-------|------|--------------|
| **Product** | `willow-mcp` | MCP tools, manifest ACL, Kart worker, dispatch packet I/O, session state, optional pre-tool hook |
| **Constitution** | `~/github/willow` | `CONSTITUTION.md`, `ORIENT.md` — law; willow-mcp **enforces**, does not author. `envelopes/` **no longer lives here** — the registry moved to `$WILLOW_HOME/constitutional/` (below), because a live registry is operator-instance data, not something a charter repo should carry in git. |
| **Fleet muscle** | `willow-2.0` | Optional upstream; same tool names when wired, but not required for this design |

willow-mcp today ships **121 MCP tools** across store, knowledge, task queue, dispatch, handoff, session, orchestrator write set, envelope authoring, Grove, FRANK, integrations, Nest, commitments, code-graph, human-loop, federated MCP, and diagnostics. The list changes with every PR; grep `@mcp.tool` in `src/willow_mcp/server.py` for the current inventory, or `README.md` for the count claim (kept in sync by `tests/test_counts_in_prose.py`).

**Historically added by this design (all shipped 2026-07 through 2026-08):** `dispatch_send`, `dispatch_list`, `dispatch_read`, `dispatch_accept`, `handoff_write_v4`, `handoff_read`, `verify_handoff`, `agent_clear`, `session_enter`, `session_bind`. DAG tools (`dag_*`) are still open — see §11.

---

@phase 2-two-session-modes
## 2. Two session modes

| Mode | Typical `app_id` | Job | Boot |
|------|------------------|-----|------|
| **Orchestrator** | `willow` | DAG, dispatch, verify, clear, report | `willow orient` — desk state, pending dispatches |
| **Specialist** | `loki`, `hanuman`, `jeles`, `ada`, … | Execute one packet; handoff; wait for clear | **Packet is the boot** — no ceremony |

Manifest at `$WILLOW_HOME/mcp_apps/<app_id>/manifest.json` defines permissions + optional `store_scope`. Role envelopes (tool allow/deny) live in manifest or referenced `$WILLOW_HOME/constitutional/pre-approved.json` — see §6.

---

## 2a. Session entry — what defines human vs system

**Rule:** How the session is entered determines the path. **Willow is always human-only** — see [`human-orchestrator.md`](human-orchestrator.md).

| Entry | Signal | Path | Closeout |
|-------|--------|------|----------|
| **Human orchestrator** | `app_id=willow` — operator session only | **`human_orchestrator`** | `session_handoff_write` — never `handoff_write_v4` |
| **Human specialist** | Normal prompt; no `dispatch_id` | **human** | `session_handoff_write` or `context_save` |
| **Dispatch specialist** | `dispatch_id` present | **dispatch** | `handoff_write_v4` |

```
Operator opens Willow seat                    →  entry_mode: human_orchestrator
Operator types "Hanuman, let's build"         →  entry_mode: human (hanuman app_id)
Orchestrator dispatches A1B2C3D4 → Loki       →  entry_mode: dispatch (loki accepts)
session_enter("willow", dispatch_id=…)        →  REJECTED (orchestrator_human_only)
```

**Orchestrator write tools** — the canonical list lives in `human_session.py::ORCHESTRATOR_WRITE_TOOLS`
(currently `dispatch_send`, `dispatch_accept`, `handoff_write_v4`, `verify_handoff`, `agent_clear`,
`frank_append`, `envelope_apply`, `envelope_propose`, `envelope_ratify`, `envelope_reject`;
ten tools — three originals plus four added after the 2026-07-31 red-team on packet `96F54DA7`,
plus three added in the envelope-accrual PR5 so authoring the operator's yes/no is also
keyring-attested). Each requires `WILLOW_HUMAN_ORCHESTRATOR=1` on the MCP host env (stdio) or
OAuth binding to willow (serve); when a keyring / PGP identity substrate is configured, a further
layered gate applies (live session file on disk + valid ed25519 sig on the keyring path or
PGP sig on the sidecar `sessions/willow-{id}.attest.json` + verified manifest `.sig`). See
[`human-orchestrator.md`](human-orchestrator.md) §Orchestrator write tools and
[`pgp-and-persona.md`](pgp-and-persona.md) §1 for the full layered gate and denial tokens.
Agents cannot invoke these as willow.

**Resolver:** `session_enter(app_id, session_id, dispatch_id="")` — see `dispatch.py`.

---

@constraint severity="normal"
**No persona picker. No boot-done flags. No 4-phase boot.**

```
IDLE → WORKING → DONE → VERIFIED → CLEARED → IDLE
```

| State | Meaning |
|-------|---------|
| **idle** | Session open; no active `dispatch_id` |
| **working** | `assignment.md` loaded; agent executing |
| **complete** | `handoff.json` + `closeout.md` written |
| **verified** | Orchestrator ran `verify_handoff` |
| **cleared** | Orchestrator ran `agent_clear`; specialist ready for next packet |
| **closed** | Dispatch archived |

State lives in **`dispatch/{id}/status.json`** and mirrored in **`sessions/{app_id}-{session_id}.json`**.

---

@phase 4-packet-structure-startup
## 4. Packet structure (startup)

**Directory:** `$WILLOW_HOME/dispatch/{dispatch_id}/`

```
dispatch/{dispatch_id}/
├── meta.json          # routing (machine)
├── assignment.md      # work order (pure markdown)
├── status.json        # pending | working | complete | verified | cleared | closed
├── closeout.md        # findings narrative (on complete)
└── handoff.json       # structured closeout (on complete)
```

### 4a. `meta.json`

```json
{
  "format": "startup_packet_meta_v1",
  "dispatch_id": "A1B2C3D4",
  "from_app": "willow",
  "to_app": "loki",
  "role": "loki",
  "phase": "operate",
  "reply_to": "willow",
  "priority": "normal",
  "assignment_path": "dispatch/A1B2C3D4/assignment.md",
  "context_refs": ["pr:786"],
  "created_at": "2026-07-09T04:32:00Z"
}
```

Indexed in SOIL `dispatch/index` and/or Postgres `dispatch_tasks` when host DB present.

### 4b. `assignment.md`

Pure markdown. **No `@markdownai` header.** Template: `docs/templates/ASSIGNMENT.template.md`.

Sections: Task · Checklist · Context · Out of scope · Success criteria.

Injected to the agent on session start via MCP `context_save` or client skill — not fylgja stdout.

### 4c. `status.json`

```json
{
  "status": "working",
  "updated_at": "2026-07-09T04:00:00Z",
  "handoff_path": null,
  "verified_at": null,
  "cleared_at": null
}
```

### 4d. Session file

**Path:** `$WILLOW_HOME/sessions/{app_id}-{session_id}.json`

```json
{
  "app_id": "loki",
  "session_id": "...",
  "status": "working",
  "dispatch_id": "A1B2C3D4"
}
```

Minimal. No anchor ceremony.

---

@phase 5-closeout
## 5. Closeout

### 5a. Specialist completes

```
handoff_write_v4(
  dispatch_id="A1B2C3D4",
  findings=[{"id": "gap-1", "text": "...", "severity": "high", "evidence": ["path:line"]}],
  narrative="..."
)
```

Writes:

- `dispatch/{id}/handoff.json` — structured
- `dispatch/{id}/closeout.md` — human-readable (template: `docs/templates/CLOSEOUT.template.md`)
- `status.json` → `complete`
- `agent_dispatch_result` (today) or `dispatch_complete` (proposed)

### 5b. Orchestrator verifies

```
handoff_read(dispatch_id="...")
verify_handoff(dispatch_id="...")   # checklist, evidence, envelope_clean
agent_clear(app_id="loki")          # status → cleared
dag_next(project_id="...")          # optional: dispatch next node
```

### 5c. `handoff.json` (structured)

The closeout MCP tool is named `handoff_write_v4` for its call-signature generation; the on-disk `handoff.json` format is **`handoff_v1`** — intentional, not a contract violation.

```json
{
  "format": "handoff_v1",
  "dispatch_id": "A1B2C3D4",
  "app_id": "loki",
  "reply_to": "willow",
  "findings": [],
  "narrative": "",
  "checklist_resolved": true,
  "envelope_clean": true,
  "written_at": "2026-07-09T06:00:00Z"
}
```

Narrative mirror optional in `closeout.md` for desk reading.

---

@phase 6-envelopes-manifests
## 6. Envelopes & manifests

**Manifest** (`mcp_apps/<app_id>/manifest.json`) — willow-mcp gate today:

```json
{
  "permissions": ["store_read", "knowledge_read", "task_queue", "context"],
  "store_scope": ["loki_*"],
  "role": "loki"
}
```

**Role envelope** — tool allow/deny per role (Nest packet § `$WILLOW_HOME/constitutional/pre-approved.json`). Enforced in `gate.py` when `role` is set:

| Role | allow (sketch) | deny (sketch) |
|------|----------------|---------------|
| willow | orchestrator tools + read | — (human-keyed for dispatch/clear) |
| hanuman | read, write, task_* | kb_promote |
| jeles | knowledge_search, knowledge_read, handoff_write_v4, context | write, task_submit, kb_promote, kb_journal |
| loki | read, knowledge_read, handoff_write_v4 | write, task_submit, knowledge_ingest |
| ada | read, knowledge_read, fleet_read | write, task_submit |

Constitutional grants (`$WILLOW_HOME/constitutional/pre-approved.json`) overlay manifest for the governance seat. Previously an optional mount pointed at a sibling `willow` repo; now this **is** the default — `WILLOW_ENVELOPE_REGISTRY` still overrides it for anyone who wants a different location.

### Canonical roles (fleet law — overrides Nest packet errors)

| Role | Job | Not |
|------|-----|-----|
| **Jeles** | Head Librarian — retrieval, citation, sourced synthesis, KB verification | Designer, builder, ADR author |
| **Hanuman** | Builder — code, tests, Kart | — |
| **Loki** | Auditor — gap analysis, adversarial review | Builder |
| **Ada** | Operator — monitor, uptime, diagnostics | Change agent |
| **Willow** | Orchestrator — DAG, dispatch, verify, report | Implementation |

**Jeles** is Hungarian for *excellent*; the name is a quality mark, not a person. The Stacks: local KB → open web → special collections (institutional sources). Synthesis on request; no unsourced output. Nest packet `docs/ROLES.md` had Jeles as "Designer" — **wrong**; librarian is canonical (`willow-2.0/willow/fylgja/personas/jeles.md`).

DAG nodes for research, literature review, citation checks, and KB seeding dispatch to **Jeles**. Design docs and build cards are **Hanuman** or orchestrator **DESIGN** phase unless the bite is explicitly retrieval.

---

@phase 7-orchestrator-willow
## 7. Orchestrator (Willow)

**User guide:** Nest packet `ORIENT.md` → ship as `docs/ORIENT.md` in willow-mcp or link to governance repo.

**Flow:**

```
Plan (DAG) → dispatch_send → monitor → verify_handoff → agent_clear → dag_next → report
```

**DAG** (project workflow): SOIL collection `projects/{project_id}/dag.json` or `store_put` under orchestrator `store_scope`.

**Tools (proposed):**

| Tool | Action |
|------|--------|
| `dispatch_send` | Write meta + assignment; set status pending |
| `dispatch_list` | List by `to_app`, status |
| `dispatch_read` | Return assignment.md + meta |
| `verify_handoff` | Check checklist, evidence, envelope |
| `agent_clear` | cleared → idle; optional next packet inject |
| `dag_status` / `dag_next` | Project graph |
| `status_report` | Operator summary |

**Specialist user guide:** Nest packet `AGENTS.md` → `docs/AGENTS.md`.

---

@phase 8-file-map-willow-mcp-product
## 8. File map (willow-mcp product)

### In repo (`willow-mcp/`)

| Path | Purpose |
|------|---------|
| `docs/design/session-lifecycle.md` | **This document** |
| `docs/SESSION_FLOW.md` | Operator-facing lifecycle (from Nest packet) |
| `docs/AGENTS.md` | Specialist guide |
| `docs/ORIENT.md` | Orchestrator guide |
| `docs/GLOSSARY.md` | Terms |
| `docs/ROLES.md` | Role definitions |
| `docs/templates/ASSIGNMENT.template.md` | Dispatch assignment |
| `docs/templates/CLOSEOUT.template.md` | Dispatch closeout |
| `src/willow_mcp/dispatch.py` | Packet I/O (proposed) |
| `src/willow_mcp/handoff.py` | handoff_write_v4 / verify (proposed) |
| `src/willow_mcp/gate.py` | Role envelope enforcement (extend) |
| `hooks/pre_tool_use.py` | Optional: redirect bash, block envelope violations |

### Runtime (`$WILLOW_HOME`)

| Path | Purpose |
|------|---------|
| `mcp_apps/<app_id>/manifest.json` | ACL |
| `dispatch/{id}/meta.json` | Packet routing |
| `dispatch/{id}/assignment.md` | Work order |
| `dispatch/{id}/status.json` | State machine |
| `dispatch/{id}/closeout.md` | Findings md |
| `dispatch/{id}/handoff.json` | Structured handoff |
| `sessions/{app_id}-{session_id}.json` | Thin session state |
| `store/` | SOIL SQLite (shared if pointed at fleet store) |
| `settings.global.json` | Consent (internet, cloud_llm) |

### Governance repo (`~/github/willow`) — law only

| Path | Relationship |
|------|----------------|
| `CONSTITUTION.md` | Supreme law; willow-mcp enforces via gate + envelopes |
| `design/session-startup-closeout.md` | **Deprecated** — pointer to this doc |

Authority grants (`envelopes/pre-approved.json`) **moved out of this repo** —
see `$WILLOW_HOME/constitutional/pre-approved.json` in the willow-mcp table
above. They were never really "law" in the same sense as the constitution
text; they're the operator's own instance data, so they don't belong in a
"law only" repo's git history any more than a vault does.

---

@phase 9-what-willow-2-0-is-and-is-not
## 9. What willow-2.0 is (and is not)

| willow-2.0 | willow-mcp |
|------------|------------|
| fylgja hooks, persona picker, boot flags | None — packet is boot |
| 100+ MCP tools, Grove, FRANK, dreams | **121 MCP tools** (2026-08-26) — full Grove/FRANK/nest/commitment/code-graph/human-loop/envelope-authoring/federation surfaces; count kept in sync by `tests/test_counts_in_prose.py` |
| Session-scoped named agents as daemons | Any client + manifest `app_id` |
| Optional host when `WILLOW_STORE_ROOT` points at fleet | Default standalone install |

Same operator may run both; designs must not require fylgja for willow-mcp to work.

---

@phase 10-implementation-slices
## 10. Implementation slices

| Slice | Repo | Deliverable |
|-------|------|-------------|
| S0 | willow-mcp | Templates + `SESSION_FLOW.md`, `AGENTS.md`, `ORIENT.md` from Nest packet |
| S1 | willow-mcp | `dispatch/` directory I/O + `dispatch_send` / `dispatch_read` | **done** |
| S2 | willow-mcp | `sessions/` file + `dispatch_accept` / `session_read` | **done** |
| S-R1 | `specialist-registry.md` + JSON schema | **done** — permissions ratified in `permissions-matrix.md`, enforced in `gate.py` |
| S3 | `roles.py` envelope enforcement | unblocked — permissions ratified; `roles.py` reads `allow_tools`/`deny_tools` from registry |
| S4 | willow-mcp | `handoff_write_v4`, `handoff_read`, `verify_handoff` | **done** |
| S5 | willow-mcp | `agent_clear`, status machine | **done** |
| S6 | willow-mcp | DAG in SOIL + `dag_next` |
| S7 | governance | Constitution cross-links only — no implementation |

---

@phase 11-open-questions
## 11. Open questions

- [x] `handoff.json` + `closeout.md` — **both** (implemented S4)
- [x] Postgres `dispatch_tasks` dual-write when host DB present (filesystem is canonical for standalone) — opt-in via `WILLOW_MCP_DISPATCH_MIRROR`, best-effort mirror in `dispatch.py`; `docs/schema/dispatch_tasks.postgres.sql`
- [x] **Jeles = librarian** (canon). Nest/DeepSeek "Designer" role rejected for `docs/ROLES.md`.
- [x] Dispatch tools: `dispatch_send`, `dispatch_read`, … shipped in `src/willow_mcp/dispatch.py` + `handoff.py`
- [ ] Where Nest `docs/ZERO_COST_DEPLOYMENT.md` lives — willow-mcp vs separate docs site
- [ ] Role envelope enforcement in `gate.py` (metadata in `roles.py`; hook enforcement = next slice)

---

@phase 12-conflicts-register-nest-packet-vs-fleet-canon
## 12. Conflicts register (Nest packet vs fleet canon)

*Use this when lifting docs from `WILLOW Complete System.txt` into willow-mcp. **Fleet wins** unless marked "Nest UX only".*

### Resolved

| Topic | Nest / DeepSeek | Canon | Status |
|-------|-----------------|-------|--------|
| **Jeles** | Designer | Head Librarian | **Fixed** in `roles.py` + §6 |
| **Dispatch tools** | Aspirational CLI | `dispatch_*`, `handoff_write_v4` MCP tools | **Shipped** S1–S5 |

### Role & persona

| Topic | Nest packet | Fleet canon | Action |
|-------|-------------|-------------|--------|
| **DAG "Design" node** | `agent: jeles` | Research → Jeles; design → Hanuman / Willow | Fix `EXAMPLES.md` when lifted |
| **Roster** | 5 roles only | + Skirnir, Vishwakarma, Oakenscroll, Publius | Label "core five" or expand `ROLES.md` |
| **Willow** | "All tools" | Orchestrator chair — no impl without envelope | Nest UX overshoot |
| **Loki** | handoff OK | No KB writes | Align deny list in envelopes |
| **Hanuman** | deny kb_promote | + worktree/PR, no master | Document in specialist guide |
| **Ada** | "routine ops" | Keeper of Quiet Uptime, Almanac | Nest undersells — use persona prose |

### Filename collisions (do not overwrite)

| File | Nest content | Governance / fleet | willow-mcp name |
|------|--------------|-------------------|-----------------|
| `ORIENT.md` | DAG dispatch CLI | Tri-modal seat (charter spike) | **Do not import** — charter keeps its own `ORIENT.md` |
| `AGENTS.md` | Nest packet guide | Governance cold-start | `docs/AGENTS.md` (`#orchestrator` / `#specialist`) |
| `envelopes/pre-approved.json` | Tool allow/deny per role | Article III.2 **authority grants** | `persona_envelopes` / manifest — **not** pre-approved |

### Constitution & law

| Topic | Nest | Fleet |
|-------|------|-------|
| Article 0 wording | Six bullets | `CONSTITUTION.md` Draft 0.7 — align, don't replace |
| Read constitution? | "You don't need to" | Governance seat reads it | Product vs seat split |
| PROTECTED_* | Omitted | Required | Add to product glossary |

### Tools & API gaps (Nest aspirational → willow-mcp)

| Nest | willow-mcp today |
|------|------------------|
| `willow orient`, `make setup` | `pip install`, MCP config, `willow-mcp worker` |
| `dag_next`, `dag_status`, `status_report` | **Not yet** — SOIL DAG = S6 |
| `session_start(agent=)` | Client opens session; `dispatch_accept` + `session_read` |
| `read`/`grep`/`glob` as MCP tools | IDE client tools — document separately |

### Data shape

| Topic | Nest | Design |
|-------|------|--------|
| Handoff | `handoff.json` sidecar | **Both** json + `closeout.md` (shipped) |
| Assignment in `agent_dispatch` string | Inline string | **`assignment.md`** + summary in meta |
| Session state | `sessions/*.json` | Shipped; no `session_anchor` in willow-mcp |

### Architecture

| Topic | Nest | Reality |
|-------|------|---------|
| Single `willow` repo | clone + make | **willow-mcp** + **willow** charter + **willow-2.0** fleet |
| Fixed model per role | Product map | Operator choice — Nest UX only |
| No ceremony | Packet boot | Correct for willow-mcp; willow-2.0 fylgja separate |

---

*Draft lineage: 0.3 (2026-07-09, conflicts register + dispatch stack shipped).*

---

@phase constraints
## Constraints

@constraint severity="normal"
**No persona picker. No boot-done flags. No 4-phase boot.**
