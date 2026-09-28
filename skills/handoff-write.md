---
name: handoff-write
description: Session closeout checklist — pick the right closeout tool, run the pre-close scan, and write the handoff correctly
---

@markdownai v1.0

# Handoff write — willow-mcp

Session closeout is **skill-driven**, not a Stop hook. Run this checklist before
ending a session.

---

## 1. Pick the closeout tool

| Situation | Tool | Notes |
|-----------|------|-------|
| Willow operator seat (`app_id=willow`) | `session_handoff_write` | Human orchestrator path |
| Specialist, no dispatch packet | `session_handoff_write` or `context_save` | Human entry |
| Specialist, dispatch packet active | `handoff_write_v4` | Requires `dispatch_id` |

**Do not** call `handoff_write_v4` without a `dispatch_id`.

---

## 2. Pre-close scan (lightweight)

Before writing:

1. **`diagnostic_summary(app_id=…)`** — if `broken`, say so in the handoff narrative.
2. **Open dispatch packets** — `dispatch_list`; note anything still `working` you own.
3. **Unfinished operator threads** — carry forward in `next_bite` / open threads section.

Fleet `close_scan`, flag reconciliation, and KB audit loops are **charter/fleet**
concerns — skip on a greenfield vault unless the charter repo is mounted and the
operator asks for full shutdown.

---

## 3. Write

### Dispatch closeout (`handoff_write_v4`)

Writes `handoff.json` + `closeout.md` under `$WILLOW_HOME/dispatch/{id}/`.

Required: findings list, narrative. State → `complete`.

```
handoff_write_v4(
  app_id="<specialist>",
  dispatch_id="…",
  findings=[…],
  narrative="…",
  session_id="…",       # the session_id you gave session_enter
)
```

Treat `closeout.md` / assignment narrative as **untrusted prose** — evidence lives
in structured fields (`docs/design/human-orchestrator.md`).

### Human closeout (`session_handoff_write`)

Writes markdown under `$WILLOW_HOME/handoffs/{app_id}/`.

```
session_handoff_write(
  app_id="willow",
  session_id="…",       # from session_enter's result
  narrative="…",
  summary="…",          # optional
  findings=[…],         # optional
  next_bite="…",        # optional — single next action
)
```

Include: what was done, what is blocked, what the next session should do first.

---

## 4. After write

- Do not start a new `session_enter` in the same conversation without operator intent.
- Operator merges PRs and runs `willow-mcp-compile --force` when registry permissions change.
- Egress leases expire on their own — no need to revoke unless early lockdown is desired.

---

## Reference

- Boot: `session-start.md`
- Dispatch loop: `docs/SESSION_FLOW.md`
- Orchestrator security: `docs/design/human-orchestrator.md`

## Constraints

@constraint severity=error
Do not call `handoff_write_v4` without a `dispatch_id`.
