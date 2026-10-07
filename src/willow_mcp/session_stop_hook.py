"""SessionEnd hook — stack snapshot when closeout is skipped, friction-floor
join (Wave 2), and stage-1 pre-handoff instruments (sealed cdcd948c):
corpus-lens over the session log + willow-reconciler stub, each writing a
receipt under `$WILLOW_HOME/sessions/pre_handoff/`. Fail-open throughout —
see `session_friction_scan.py` and `session_pre_handoff.py`.

When ``session_handoff_write`` already closed the session, this hook skips
the instruments (gap 1d29f1d28f0e) so SessionEnd does not double-write the
stack. Grove ``deposit()`` still runs as the SessionEnd-only flush.
"""

from __future__ import annotations

import json
import sys

from .session_closeout import run_closeout_instruments, session_is_closed


def handle(payload: dict) -> dict:
    from .seat_identity import resolve_hook_app_id

    # Same seat rule as SessionStart (gaps acceefc0ec77 / 3727efb30041): never
    # default to willow, never trust an env that disagrees with .mcp.json.
    app_id, app_err = resolve_hook_app_id()
    session_id = str(
        payload.get("session_id")
        or payload.get("conversation_id")
        or ""
    )
    transcript_path = str(payload.get("transcript_path") or "")

    if app_id and session_is_closed(app_id, session_id):
        return {
            "skipped": "already_closed_by_handoff",
            "app_id": app_id,
            "session_id": session_id,
        }

    if app_err or not app_id:
        # Keep the pre-closeout shape: still run friction/pre_handoff with an
        # empty seat so SessionEnd never loses those joins on a seat miss.
        out = run_closeout_instruments("", session_id, transcript_path)
        out["stack_snapshot"] = {
            "error": "seat_unresolved",
            "detail": app_err or "WILLOW_APP_ID could not be resolved",
        }
        return out

    return run_closeout_instruments(app_id, session_id, transcript_path)


def main() -> None:
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    out = handle(payload)
    print(json.dumps(out))


if __name__ == "__main__":
    main()
