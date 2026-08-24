# willow_mcp/announce.py — graduated announcement volume over the receipt log.
#
# Phase 5 of the willow-gate seam (docs/design/willow-gate-seam.md §5). NOT a
# second audit log — ReceiptLog stays the single record of every gated call. This
# is a *policy over it*: it decides how LOUDLY each decision is announced on the
# operator's log channel, graduated by the caller's bound trust tier (louder for
# the LESS trusted, because that is where a human most needs to look), and always
# escalated for a denial or a reconciliation discrepancy.
#
# Pure and deterministic — stdlib logging + env only, no model, no willow-gate
# dependency, no PGP (seam-doc D5: the base stays free of python-gnupg). The
# encrypted-ledger channel willow-gate offers is left as a pluggable sink
# (set_sink) so an operator who wants it can wire it without the base taking on
# the crypto dependency.
#
# Off by default (WILLOW_MCP_ANNOUNCE): a plain local box is unchanged. When on,
# it costs nothing per call until a decision is recorded, and never raises into
# the record path (the caller swallows sink errors — an announcement must never
# break the audit write it rides on).
from __future__ import annotations

import logging
import os
from typing import Callable, Optional

logger = logging.getLogger("willow_mcp.announce")

# Volume ranks, quietest→loudest. SILENT is "do not announce".
SILENT, LOW, NORMAL, HIGH, ALERT = 0, 1, 2, 3, 4
_VOLUME_NAME = {SILENT: "silent", LOW: "low", NORMAL: "normal", HIGH: "high", ALERT: "alert"}

# Base volume by BOUND trust level — louder for the less trusted. An UNBOUND
# caller (None: no live session) is the least accountable, so it is loud by
# default, not silent. Elder's ordinary calls are silent; the trust is the point.
_BASE = {None: HIGH, 0: ALERT, 1: HIGH, 2: NORMAL, 3: LOW, 4: SILENT}

# Outcome floors — a denial or an integrity discrepancy is loud regardless of who
# did it; a soft failure (error / rate-limit) is at least HIGH. An `ok` and the
# reconcile summary carry no floor of their own (their volume is the tier's).
_OUTCOME_FLOOR = {
    "denied": ALERT, "reconcile_discrepancy": ALERT,
    # A real secret left the box under an operator exemption — loud regardless of
    # tier, or the one event you most want to see stays silent for a trusted app.
    "credential_returned": ALERT,
    "error": HIGH, "rate_limited": HIGH,
}

# Mechanism receipts, not actions — the binding-observation rows ride *every*
# gated call, so announcing them would just double every line. The actual tool's
# own `ok`/`denied` row is the thing worth hearing.
_NEVER_ANNOUNCE = frozenset({"bind_observed", "bind_enforced"})

# logging level per volume rank.
_LOG_LEVEL = {LOW: logging.DEBUG, NORMAL: logging.INFO, HIGH: logging.WARNING, ALERT: logging.ERROR}


def enabled() -> bool:
    """Master switch (WILLOW_MCP_ANNOUNCE), read live. Off ⇒ a plain local box is
    unchanged and the record path pays nothing."""
    return os.environ.get("WILLOW_MCP_ANNOUNCE", "").strip().lower() in ("1", "true", "yes", "on")


def audit_level() -> str:
    """`full` (default) announces per volume down to LOW; `minimal`
    (WILLOW_MCP_AUDIT_LEVEL=minimal) surfaces only the loud stuff — untrusted
    callers and every denial/discrepancy — and stays quiet about routine trusted
    activity."""
    return "minimal" if os.environ.get("WILLOW_MCP_AUDIT_LEVEL", "full").strip().lower() == "minimal" else "full"


def volume(trust_level: Optional[int], outcome: str) -> int:
    """The announcement volume for one decision: the louder of the tier's base
    volume and the outcome's floor."""
    base = _BASE.get(trust_level, HIGH)
    return max(base, _OUTCOME_FLOOR.get(outcome, SILENT))


def _threshold() -> int:
    return HIGH if audit_level() == "minimal" else LOW


# Pluggable emit sink. Default writes to the operator's log channel at the
# volume's level. willow-gate's PGP-encrypted announcement ledger can replace this
# via set_sink() without the base importing python-gnupg (seam-doc D5).
def _default_sink(record: dict) -> None:
    level = _LOG_LEVEL.get(record["volume"], logging.INFO)
    logger.log(level, "[willow announce] %s", record["message"])


_sink: Callable[[dict], None] = _default_sink


def set_sink(sink: Optional[Callable[[dict], None]]) -> None:
    """Replace the announcement sink (e.g. an encrypted ledger). None restores the
    default operator-log sink."""
    global _sink
    _sink = sink or _default_sink


def announce(app_id: str, tool: str, outcome: str, trust_level: Optional[int],
             detail: Optional[str] = None) -> Optional[int]:
    """Announce one gated decision at its graduated volume, or return None if it
    is suppressed (below the audit threshold, silent, or a mechanism receipt).
    Returns the emitted volume rank on success. Never raises — a sink failure is
    swallowed so an announcement can never break the audit write it rides on."""
    if not enabled() or outcome in _NEVER_ANNOUNCE:
        return None
    vol = volume(trust_level, outcome)
    if vol < _threshold() or vol == SILENT:
        return None
    tier = "unbound" if trust_level is None else f"L{trust_level}"
    message = f"app={app_id} tool={tool} outcome={outcome} tier={tier} vol={_VOLUME_NAME[vol]}"
    if audit_level() == "full" and detail:
        message += f" detail={detail}"
    try:
        _sink({"app_id": app_id, "tool": tool, "outcome": outcome,
               "trust_level": trust_level, "volume": vol, "message": message})
    except Exception:
        logger.debug("announce sink failed for tool=%s", tool, exc_info=True)
    return vol
