---
name: session-start
description: Session boot checklist — call session_enter, apply the persona overlay, and follow the Willow or specialist open sequence
---

@markdownai v1.0

# Willow — session start

Call **`session_enter(app_id, session_id, dispatch_id="")`** at session open.

Inference client (Cursor, Claude Code, local LLM host, …) is replaceable — the tool plane is willow-mcp. Hooks are optional; this skill is mandatory.

---

## Willow (`app_id=willow`)

Human operator seat only. Agents must not use `app_id=willow`.

Host MCP env must include **`WILLOW_HUMAN_ORCHESTRATOR=1`**. Specialist configs must omit it.

**Never** pass `dispatch_id` to `session_enter` for willow — rejected (`orchestrator_human_only`).

### Open (every Willow session)

Run in order:

| Step | Tool | Pass criteria |
|------|------|---------------|
| 1 | `session_enter("willow", session_id)` | `entry_mode: human_orchestrator` — read `message`, `agent_doc_section` |
| 2 | `diagnostic_summary(app_id="willow")` | `broken` → stop and report; `ok` or `degraded` → continue |
| 3 | `dispatch_list(app_id="willow", …)` | Desk view — pending / working / complete packets |
| 4 | `commitment_surface(app_id="willow")` | What may be worth the operator's attention now |
| 5 | `willow-mcp grove-listen --app-id willow --quiet &` then tail its log | Grove listener up — see **Grove listener** below |

Work in **whatever mode the user asks for** (governance, portfolio, commitments, dispatch, build). No lane declaration required at open.

Close with **`session_handoff_write`** — not `handoff_write_v4`.

Security: `docs/design/human-orchestrator.md`. Dispatch loop: `docs/SESSION_FLOW.md`.

### Charter home — ORIENT steps 1–3

When the charter project is mounted (`WILLOW_HANDOFF_PROJECT`, `WILLOW_PROJECT_ROOT`, or `~/github/willow` on disk), run **after** the open table above.

Collections follow `soil/manifest.json` under the project store (`WILLOW_STORE_ROOT`).

**Step 1 — law and startup docs (read files first)**

Read at `WILLOW_PROJECT_ROOT` (default `~/github/willow`):

- `CONSTITUTION.md`
- Associated startup docs for this seat (e.g. `ORIENT.md`, `AGENTS.md` as needed)

**Step 2 — project context (tri-modal SOIL)**

| Intent | willow-mcp call |
|--------|-----------------|
| Current focus stack | `store_get(app_id="willow", collection="stack", record_id="current")` |
| Portfolio threads | `store_list(app_id="willow", collection="pm/portfolio")` |
| Milestones / deadlines | `store_list(app_id="willow", collection="pm/milestones")` |
| Commitments lane | `store_list(app_id="willow", collection="pa/commitments")` |

**Step 3 — continuity**

| Intent | willow-mcp call |
|--------|-----------------|
| Startup continuity atoms | `kb_startup_continuity(app_id="willow")` |
| Active packet bodies | `handoff_read(app_id="willow", dispatch_id=…)` for items from `dispatch_list` |

If a call is gate-denied, note it and continue (`degraded` is acceptable).

**Step 4 — grants and collection map (read files)**

- `$WILLOW_HOME/constitutional/pre-approved.json` — active grants (local to this willow-mcp install; no longer in the governance repo)
- `AGENT_SERVICES.md` — seat obligations (governance repo)
- `soil/manifest.json` — collection map (governance repo)

Charter depth (flags, fleet read, `next_bite` writeback): `ORIENT.md` steps 4–6 in the governance repo.

### Vault / greenfield home

When `WILLOW_HOME` is a data-vault box only (no charter mount), skip the charter block. Open table (steps 1–4) is sufficient.

---

## Specialists (`app_id` = hanuman, loki, jeles, ada, skirnir, vishwakarma)

| Signal | Mode | Closeout |
|--------|------|----------|
| Normal prompt, no `dispatch_id` | **human** | `session_handoff_write` or `context_save` |
| `dispatch_id` / pending packet | **dispatch** | `handoff_write_v4` |

No `WILLOW_HUMAN_ORCHESTRATOR` on specialist MCP configs.

### Open (every specialist session)

| Step | Action |
|------|--------|
| 1 | `session_enter(app_id, session_id, dispatch_id=…)` — read `entry_mode`, `assignment` (if dispatch), `persona`, `closeout` / `closeout_tools` |
| 2 | Apply voice + boundaries from `persona-overlays.md` for your `app_id` |
| 3 | `diagnostic_summary(app_id=…)` when the role monitors or builds — `broken` → report once and stop |
| 4 | Open your ear on the Grove (see **Grove listener** below) — otherwise the fleet cannot reach you |
| 5 | Work within manifest permissions only |
| 6 | Close with the tool named in `closeout_tools` |

`session_enter` embeds persona text in the `persona` field (source: `$WILLOW_HOME/personas/<agent>.md`).
Overlays are voice and posture only — they do not change `app_id`, namespace, or grants.

| `app_id` | Role | Overlay focus |
|----------|------|---------------|
| `hanuman` | Builder | worktree + PR, Kart, tests |
| `loki` | Auditor | diff review, findings — no build |
| `jeles` | Librarian | `knowledge_search`, sourced synthesis |
| `ada` | Operator | `fleet_health`, monitor-first |
| `skirnir` | Witness | gate/session state, no inference fill |
| `vishwakarma` | Architect | manifests, trust chain, structure first |

Full overlay text: `persona-overlays.md`.

### Dispatch path

1. `session_enter` → read `assignment` and `closeout` from the response (`closeout.format` is the on-disk handoff JSON schema; the tool name `handoff_write_v4` is intentional)
2. Work within manifest permissions
3. Call `closeout.tool` (today: `handoff_write_v4`) — output will be `format: handoff_v1`

### Human path

1. `session_enter` → `entry_mode: human`
2. Work
3. `session_handoff_write`

## Grove listener (every seat, willow included)

`grove_inbox` and `grove_watch` are polls; a seat that is not polling hears
nothing. The listener is the push side: a background process that LISTENs on
Postgres, writes one line per message that concerns the seat, and announces
the seat with a HEARTBEAT so `grove_agents` shows it alive.

```bash
# background, once per session; a second launch for the same seat exits 0
willow-mcp grove-listen --app-id <your app_id> --quiet &
```

Then tail the log with your client's background monitor
(Claude Code: `Monitor` on `$WILLOW_HOME/logs/grove-listen-<app_id>.log`).
Lines and what to do with them:

| Line | Meaning | Response |
|------|---------|----------|
| `[MENTION:BROADCAST]` | `@all` on any channel | read the thread; act only if it names your role |
| `[MENTION:DIRECT:<you>]` | your handle or alias | reply on the thread (`grove_reply`) |
| `[BUS:COMMAND]` / `[BUS:EVENT]` … | bus message addressed to you | `grove_bus_receive`, then `grove_ack` when done |
| `[INBOX]` | a post in `#<your app_id>` | read it |
| `[CHANNEL]` | a channel you asked to follow (`--verbose-channels`) | informational |

The listener needs `grove_read`; `grove_write` adds the heartbeat. It reports
and never acts — replying, acking, dispatching stay yours, through the gated
tools. It never speaks as anyone but your resolved `grove_sender`.

## Constraints

@constraint severity=critical
Agents must not use `app_id=willow` — that seat is the human operator only. Never pass `dispatch_id` to `session_enter` for willow; it is rejected (`orchestrator_human_only`).
