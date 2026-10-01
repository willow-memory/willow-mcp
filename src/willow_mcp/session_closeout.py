"""Shared session closeout instruments — stack snapshot, friction scan,
pre-handoff receipts — plus a closed marker on the session record.

Used by ``session_handoff_write`` (the one closeout) and by
``session_stop_hook`` (SessionEnd fallback when the seat never closed).
Gap 1d29f1d28f0e: each used to assume the other ran.
"""

from __future__ import annotations

from typing import Any

from .dispatch import session_bind, session_read
from .session_friction_scan import scan_session_for_friction
from .session_pre_handoff import run_pre_handoff_instruments
from .stack_snapshot import write_stack_snapshot


def session_is_closed(app_id: str, session_id: str) -> bool:
    """True when a prior closeout marked this session closed."""
    if not app_id or not session_id:
        return False
    data = session_read(app_id, session_id)
    if data.get("error"):
        return False
    if data.get("status") == "closed":
        return True
    return bool(data.get("closed_at"))


def mark_session_closed(app_id: str, session_id: str) -> dict[str, Any]:
    """Bind status=closed (preserves verifier via session_bind)."""
    return session_bind(app_id, session_id, "", "closed")


def run_closeout_instruments(
    app_id: str,
    session_id: str,
    transcript_path: str = "",
) -> dict[str, Any]:
    """Stack snapshot + friction + pre-handoff. Fail-open throughout."""
    out: dict[str, Any] = {}
    if not app_id:
        out["stack_snapshot"] = {
            "error": "seat_unresolved",
            "detail": "app_id empty",
        }
        seat_app = ""
    else:
        out["stack_snapshot"] = write_stack_snapshot(app_id, session_id)
        seat_app = app_id

    try:
        out["friction_scan"] = scan_session_for_friction(
            session_id, transcript_path
        )
    except Exception as exc:
        out["friction_scan"] = {
            "error": "friction_scan_unavailable",
            "detail": str(exc),
        }

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
