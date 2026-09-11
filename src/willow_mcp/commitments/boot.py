"""SessionStart join for the commitment membrane's dew rule.

``dew_surface()`` (commitment_ledger.py) and the MCP ``commitment_surface`` /
``commitment_list`` verbs already exist, but nothing calls them at boot — a
seat opens with no sight of a commitment coming due or a conflict it is
about to walk into. The session-start skill documents "check
commitment_surface" as a manual step; this module is the actual join into
``boot_context.build_boot_lines``, the same composition the other wave-1
hooks (blockers, gaps, trust-root fault, split-brain, nest) already join.

Follows the exact discipline the neighboring boot sections use
(``boot_context._gap_lines`` / ``_blocker_lines``): degrades to no line on
any fault, never raises, never throws past this module, and stays silent
when the dew rule has nothing to say (no imminent/conflicting/unacknowledged
commitment). This is deliberately NOT the nest_autointake pattern of
surfacing a fault message — a broken commitment surface should be invisible
at boot, not another line of noise.

Design: willow/design/willow-commitment-membrane.md · ΔΣ=42
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

#: Cap on how many surfacings render at boot. The dew rule is already
#: supposed to be sparse (imminent / conflict / mismatch only); this is a
#: backstop against a pathological backlog crowding out the rest of orient.
MAX_BOOT_COMMITMENTS = 5

#: Rendering order — a conflict is the most actionable, a mismatch (an
#: unacknowledged change) the least urgent of the three surfaced kinds.
_KIND_ORDER = {"conflict": 0, "imminent": 1, "mismatch": 2}


def commitment_boot_lines(
    app_id: str,
    *,
    now: Optional[datetime] = None,
    limit: int = MAX_BOOT_COMMITMENTS,
) -> list[str]:
    """``[COMMITMENTS]`` boot section, or ``[]`` when the dew rule is silent.

    Restores the persisted ledger (no calendar fetch — same read as
    ``commitment_surface``) and evaluates ``dew_surface`` at ``now``
    (default: current UTC). Any failure — a corrupt persisted record, a
    denied store, an import error — degrades to no line; this must never
    crash the boot path.
    """
    try:
        from ..server import _commitment_ledger_restored

        ledger = _commitment_ledger_restored()
        at = now or datetime.utcnow()
        surfacings = ledger.dew_surface(at)
    except Exception:
        logging.getLogger("willow_mcp.commitments.boot").debug(
            "commitment boot surface failed", exc_info=True
        )
        return []

    if not surfacings:
        return []

    surfacings = sorted(surfacings, key=lambda s: _KIND_ORDER.get(s.kind, 9))
    shown = surfacings[:limit]
    header = f"[COMMITMENTS] {len(shown)} need attention"
    if len(surfacings) > len(shown):
        header += f" (of {len(surfacings)})"
    lines = [header + ":"]
    for s in shown:
        lines.append(f"  · [{s.kind}] {s.fact}")
    return lines
