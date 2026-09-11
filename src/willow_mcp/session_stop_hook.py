"""SessionEnd hook — stack snapshot capture when closeout is skipped, plus the
friction-floor join (Wave 2): scan this session's own transcript for the
mirror/sycophancy failure mode and let the watcher persist a flag if it
tripped. See `session_friction_scan.py` for the fail-open contract."""

from __future__ import annotations

import json
import os
import sys

from .session_friction_scan import scan_session_for_friction
from .stack_snapshot import write_stack_snapshot


def handle(payload: dict) -> dict:
    app_id = os.environ.get("WILLOW_APP_ID", "willow")
    session_id = str(
        payload.get("session_id")
        or payload.get("conversation_id")
        or ""
    )
    result = write_stack_snapshot(app_id, session_id)
    out = {"stack_snapshot": result}

    # Fail-open, belt and suspenders: scan_session_for_friction already never
    # raises, but SessionEnd must never fail to report a result over a signal
    # this hook only added on top of the stack snapshot it already wrote.
    try:
        transcript_path = str(payload.get("transcript_path") or "")
        out["friction_scan"] = scan_session_for_friction(session_id, transcript_path)
    except Exception as exc:
        out["friction_scan"] = {"error": "friction_scan_unavailable", "detail": str(exc)}
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
