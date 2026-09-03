#!/usr/bin/env python3
"""friction_floor.py — a smoke detector for the mirror, not a wall.
**Home: forge-play, `forge/friction_floor.py`.**

This module is the seam willow-mcp's own callers use — `friction.py` takes
`FrictionFloor` and `Turn` from here, the tests take `friction_score`,
`escalation_score` and `stance_friction` — kept so that no import path here
has to change. Every name in it is the Forge's.

Lineage, kept because two copies still exist on purpose: the scorer was
written for willow-gate (`src/willow_gate/friction_floor.py`) and copied here
byte-for-byte because it is pure stdlib with no egress and no PGP, while the
gate package pulls python-gnupg for its encrypted ledger. The Forge vendored
this copy on 2026-08-11 and aimed it at the maker's own rationale (the
engagement gate: waved-through decisions come back sooner). With forge-play
on PyPI the Forge's copy is the fleet's canonical stdlib one and willow-mcp
imports it; willow-gate keeps its own, inside the gate, where the gate's own
dependency posture applies. The Forge never imports willow-mcp.
"""
from __future__ import annotations

from forge.friction_floor import *  # noqa: F401,F403 — the Forge's names, all of them
from forge import friction_floor as _home

__doc__ = f"{__doc__}\n\n--- the module this re-exports ---\n\n{_home.__doc__ or ''}"
