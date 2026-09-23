"""SessionEnd hook — stack snapshot when closeout is skipped, friction-floor
join (Wave 2), and stage-1 pre-handoff instruments (sealed cdcd948c):
corpus-lens over the session log + willow-reconciler stub, each writing a
receipt under `$WILLOW_HOME/sessions/pre_handoff/`. Fail-open throughout —
see `session_friction_scan.py` and `session_pre_handoff.py`."""

from __future__ import annotations

import json
import sys

from .session_friction_scan import scan_session_for_friction
from .session_pre_handoff import run_pre_handoff_instruments
from .stack_snapshot import write_stack_snapshot


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
    if app_err or not app_id:
        out: dict = {
            "stack_snapshot": {
                "error": "seat_unresolved",
                "detail": app_err or "WILLOW_APP_ID could not be resolved",
            }
        }
        seat_app = ""
    else:
        result = write_stack_snapshot(app_id, session_id)
        out = {"stack_snapshot": result}
        seat_app = app_id

    # Fail-open, belt and suspenders: scan_session_for_friction already never
    # raises, but SessionEnd must never fail to report a result over a signal
    # this hook only added on top of the stack snapshot it already wrote.
    try:
        out["friction_scan"] = scan_session_for_friction(session_id, transcript_path)
    except Exception as exc:
        out["friction_scan"] = {"error": "friction_scan_unavailable", "detail": str(exc)}

    # Stage 1 (cdcd948c): deterministic instruments + receipts. Never raises.
    try:
        out["pre_handoff"] = run_pre_handoff_instruments(
            seat_app or "unknown",
            session_id,
            transcript_path,
        )
    except Exception as exc:
        out["pre_handoff"] = {
            "stage": 1,
            "state": "failed",
            "reason": "pre_handoff_unavailable",
            "detail": str(exc),
        }
    return out


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
