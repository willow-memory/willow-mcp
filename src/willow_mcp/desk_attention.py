"""Desk attention slice for human-orchestrator session_enter.

Surfaces what the desk must notice at open without the operator opening
GitHub: open ``human_required`` review items (CI red / title fail) and
dispatch packets sitting at ``complete`` waiting for ``verify_handoff``.

Dew-rule: silent when nothing is askew. Never raises — orientation sugar.
"""
from __future__ import annotations

import logging
from typing import Any

MAX_REVIEW_ITEMS = 5
MAX_AWAITING_VERIFY = 5

_log = logging.getLogger("willow_mcp.desk_attention")


def collect_desk_attention(
    app_id: str,
    *,
    review_limit: int = MAX_REVIEW_ITEMS,
    verify_limit: int = MAX_AWAITING_VERIFY,
) -> dict[str, Any]:
    """Return ``{review: [...], awaiting_verify: [...], count: N}``.

    Empty lists when quiet or when a probe fails. Orchestrator-only callers
    decide whether to attach this to orientation; this function does not
    gate on ``is_orchestrator_app``.
    """
    out: dict[str, Any] = {"review": [], "awaiting_verify": [], "count": 0}
    try:
        out["review"] = _open_reviews(limit=max(0, int(review_limit)))
    except Exception:
        _log.debug("desk_attention review probe failed", exc_info=True)
        out["review"] = []
    try:
        out["awaiting_verify"] = _complete_awaiting_verify(
            app_id, limit=max(0, int(verify_limit))
        )
    except Exception:
        _log.debug("desk_attention verify probe failed", exc_info=True)
        out["awaiting_verify"] = []
    out["count"] = len(out["review"]) + len(out["awaiting_verify"])
    return out


def _open_reviews(*, limit: int) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    from . import human_loop
    from .db import Store

    rows = human_loop.list_queue(
        Store(), status="open", kind="review", limit=limit,
    )
    reviews: list[dict[str, Any]] = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        reviews.append({
            "id": row.get("id"),
            "title": row.get("title") or "",
            "priority": row.get("priority") or "normal",
            "source_ref": row.get("source_ref") or "",
            "created_at": row.get("created_at") or "",
        })
    return reviews


def _complete_awaiting_verify(app_id: str, *, limit: int) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    from . import dispatch as dispatch_stack

    listing = dispatch_stack.dispatch_list(
        to_app="", from_app=app_id, status="complete", limit=max(limit * 2, 20),
    )
    rows = (listing or {}).get("dispatches") or []
    waiting: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        reply_to = str(row.get("reply_to") or "").strip().lower()
        # Packet is waiting on the desk when it replies to this seat (or
        # willow by convention). status=complete already excludes verified.
        if reply_to and reply_to not in (app_id.lower(), "willow"):
            continue
        waiting.append({
            "dispatch_id": row.get("dispatch_id"),
            "to_app": row.get("to_app") or "",
            "summary": row.get("summary") or "",
            "reply_to": row.get("reply_to") or "",
            "created_at": row.get("created_at") or "",
            "waiting_for": "verify_handoff",
        })
        if len(waiting) >= limit:
            break
    return waiting


def attention_boot_lines(attention: dict[str, Any] | None) -> list[str]:
    """Render ``[DESK ATTENTION]`` lines, or ``[]`` when quiet / malformed."""
    try:
        if not attention or not int(attention.get("count") or 0):
            return []
        reviews = list(attention.get("review") or [])
        waiting = list(attention.get("awaiting_verify") or [])
        if not reviews and not waiting:
            return []
        lines = [f"[DESK ATTENTION] {attention['count']} item(s) need the desk:"]
        for item in reviews:
            title = str(item.get("title") or item.get("id") or "?")
            lines.append(f"  · review {item.get('id')}: {title}")
        for item in waiting:
            did = item.get("dispatch_id") or "?"
            summary = str(item.get("summary") or "")[:120]
            lines.append(
                f"  · verify_handoff {did}"
                + (f": {summary}" if summary else " (complete, unverified)")
            )
        return lines
    except Exception:
        _log.debug("desk_attention render failed", exc_info=True)
        return []
