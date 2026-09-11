"""SessionStart join for the commitment membrane's dew rule.

``dew_surface()`` (commitment_ledger.py) and the MCP ``commitment_surface`` /
``commitment_list`` verbs already exist, but nothing calls them at boot — a
seat opens with no sight of a commitment coming due or a conflict it is
about to walk into. The session-start skill documents "check
commitment_surface" as a manual step; this module is the actual join into
``boot_context.build_boot_lines``, the same composition the other wave-1
hooks (blockers, gaps, trust-root fault, split-brain, nest) already join.

Follows the exact discipline the neighboring boot sections use
(``boot_context._gap_lines`` / ``_blocker_lines``): the ENTIRE body — the
restore, the dew evaluation, AND the dedup/sort/render that turns
surfacings into text — runs inside one try/except, so degrades to no line
on any fault, never raises, never throws past this module, and stays
silent when the dew rule has nothing to say (no imminent/conflicting/
unacknowledged commitment). This is deliberately NOT the nest_autointake
pattern of surfacing a fault message — a broken commitment surface should
be invisible at boot, not another line of noise.

Design: willow/design/willow-commitment-membrane.md · ΔΣ=42
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

#: Cap on how many surfacings render at boot. The dew rule is already
#: supposed to be sparse (imminent / conflict / mismatch only); this is a
#: backstop against a pathological backlog crowding out the rest of orient.
MAX_BOOT_COMMITMENTS = 5

#: Rendering order — a conflict is the most actionable, a mismatch (an
#: unacknowledged change) the least urgent of the three surfaced kinds.
_KIND_ORDER = {"conflict": 0, "imminent": 1, "mismatch": 2}


def _dedup_by_commitment(surfacings: list) -> list:
    """Collapse duplicate single-commitment surfacings before the cap.

    ``dew_surface`` can legitimately emit two rows for the SAME commitment
    — e.g. one that is both starting soon (``imminent``) and not yet
    acknowledged (``mismatch``). At boot that would read as two things
    needing attention when it is one, and would burn two of the cap-of-5
    slots on a single event. Keep the most urgent kind per commitment
    (``_KIND_ORDER``) and let it absorb the other row for that uid.

    ``conflict`` rows name two commitments and are a distinct signal (an
    overlap), not a duplicate of an imminent/mismatch row — always kept.
    """
    best: dict = {}
    conflicts = []
    for s in surfacings:
        if s.kind == "conflict" or len(s.uids) != 1:
            conflicts.append(s)
            continue
        key = s.uids[0]
        current = best.get(key)
        if current is None or _KIND_ORDER.get(s.kind, 9) < _KIND_ORDER.get(current.kind, 9):
            best[key] = s
    return conflicts + list(best.values())


def commitment_boot_lines(
    app_id: str,
    *,
    now: Optional[datetime] = None,
    limit: int = MAX_BOOT_COMMITMENTS,
) -> list[str]:
    """``[COMMITMENTS]`` boot section, or ``[]`` when the dew rule is silent.

    Restores the persisted ledger (no calendar fetch — same read as
    ``commitment_surface``) and evaluates ``dew_surface`` at ``now``
    (default: current UTC, naive — matching the ledger's internal clock
    convention documented in ``server._commitment_parse_dt``). Any
    failure anywhere in this function — a corrupt persisted record, a
    denied store, an import error, or a bad field on a surfacing while
    rendering — degrades to no line; this must never crash the boot path.
    """
    try:
        from ..server import _commitment_ledger_restored

        ledger = _commitment_ledger_restored()
        # Naive UTC "now", not tz-aware: Commitment.when is stored naive
        # (the ledger's documented convention), so an aware `now` here
        # would raise on the naive/aware subtraction inside dew_surface.
        at = now or datetime.now(timezone.utc).replace(tzinfo=None)
        surfacings = ledger.dew_surface(at)
        if not surfacings:
            return []

        surfacings = _dedup_by_commitment(surfacings)
        surfacings.sort(key=lambda s: _KIND_ORDER.get(s.kind, 9))
        shown = surfacings[:limit]
        header = f"[COMMITMENTS] {len(shown)} need attention"
        if len(surfacings) > len(shown):
            header += f" (of {len(surfacings)})"
        lines = [header + ":"]
        for s in shown:
            lines.append(f"  · [{s.kind}] {s.fact}")
        return lines
    except Exception:
        logging.getLogger("willow_mcp.commitments.boot").debug(
            "commitment boot surface failed", exc_info=True
        )
        return []
