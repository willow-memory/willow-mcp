"""Per-app security-signal summary over the receipt log.

The "repeated blocks from one app_id are a signal" completion the ShibaClaw
safety-adoption spec names for P1 and P2 (and, now, P3). It reads ONLY the
calling app's own receipts — the log is per-identity by design (`receipts.tail`
never crosses identities), so this stays a self-legibility surface ("what have
my guards been catching?"), not a cross-app operator view, which the receipt
log deliberately does not offer.

It counts the three security events the guards now record:

  * ``egress_denied``       — an SSRF / DNS-rebind refusal (P1): outcome
                              ``denied`` with a ``egress.*`` detail.
  * ``tool_output_escape``  — a neutralised boundary-forge attempt (P2):
                              outcome ``guard.tool_output_escape``.
  * ``install_blocked``     — a refused vulnerable install (P3): outcome
                              ``error`` with an ``INSTALL-AUDIT:`` detail.

``flagged`` is True when any one category reaches ``flag_threshold`` in the
window — a repeated pattern worth a human's eye, not a single stray block that
the guard already handled. Pure over the rows it is handed, and never raises:
a summary that cannot read is reported as unavailable, not an exception.
"""

from __future__ import annotations

#: `receipts.tail` caps its own limit at 200; ask for that whole recent window.
_DEFAULT_LIMIT = 200
_DEFAULT_FLAG_THRESHOLD = 3

_EGRESS_PREFIX = "egress."
_INSTALL_PREFIX = "INSTALL-AUDIT"
_ESCAPE_OUTCOME = "guard.tool_output_escape"


def _classify(outcome: str, detail: str) -> str | None:
    """The security-signal category of one receipt row, or None if it is not one."""
    detail = detail or ""
    if outcome == "denied" and detail.startswith(_EGRESS_PREFIX):
        return "egress_denied"
    if outcome == _ESCAPE_OUTCOME:
        return "tool_output_escape"
    if outcome == "error" and detail.startswith(_INSTALL_PREFIX):
        return "install_blocked"
    return None


def summarize(receipt_log, app_id: str, *, limit: int = _DEFAULT_LIMIT,
              flag_threshold: int = _DEFAULT_FLAG_THRESHOLD) -> dict:
    """Summarise the app's own recent security-event receipts.

    Rows come newest-first from `receipt_log.tail`, so the first row of a
    category is its most recent — that timestamp is the category's ``last``.
    For egress denials the structured reason (``egress.private_target`` etc.)
    is tallied so a caller can tell an SSRF probe from a refused redirect.
    """
    try:
        rows = receipt_log.tail(app_id or "-", limit)
    except Exception:
        return {"available": False, "detail": "receipt log unreadable"}

    signals: dict[str, dict] = {
        "egress_denied": {"count": 0, "last": None, "reasons": {}},
        "tool_output_escape": {"count": 0, "last": None},
        "install_blocked": {"count": 0, "last": None},
    }
    for row in rows:
        category = _classify(row.get("outcome", ""), row.get("detail", ""))
        if category is None:
            continue
        entry = signals[category]
        entry["count"] += 1
        if entry["last"] is None:  # newest-first, so the first seen is the latest
            entry["last"] = row.get("ts")
        if category == "egress_denied":
            # detail is "egress.<reason>: <url>"; keep just the reason token.
            reason = (row.get("detail") or "").split(":", 1)[0].strip()
            entry["reasons"][reason] = entry["reasons"].get(reason, 0) + 1

    total = sum(s["count"] for s in signals.values())
    flagged = any(s["count"] >= flag_threshold for s in signals.values())
    return {
        "available": True,
        "window": len(rows),
        "flag_threshold": flag_threshold,
        "flagged": flagged,
        "total": total,
        "signals": signals,
    }
