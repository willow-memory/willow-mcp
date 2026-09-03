"""human_loop — the human-in-the-loop primitives: an attention queue and a
durable attestation record. **Home: forge-play, `forge/human_loop.py`.**

This module is the seam willow-mcp's own callers use — `from . import
human_loop` in `server.py`, `from willow_mcp import human_loop` in the tests —
kept so that no import path here has to change. Every name in it is the
Forge's: the queue (`enqueue` / `list_queue` / `resolve` / `queue_stats`), the
attestations (`create_attestation` / `list_attestations` / `has_attestation`),
`HumanLoopError`, and the constants.

History, because it explains the direction: this file was written here,
ported from willow-2.0's `core/human_required.py` + `core/human_attestation.py`
(migration shortlist §6), and the Forge vendored it byte-for-byte on
2026-08-11 with a drift check to keep the copy honest. The operator's decision
of 2026-09-02 reversed the plumbing — *Willow gains the dependency on the
engine; the apps here run only on it* — and forge-play 0.1.0 on PyPI (a
zero-runtime-dependency package, same promise as kartikeya and jeles) made the
import cheap. The Forge never imports willow-mcp; this is the only direction
the arrow may point.
"""
from __future__ import annotations

from forge.human_loop import *  # noqa: F401,F403 — the Forge's names, all of them
from forge import human_loop as _home

__doc__ = f"{__doc__}\n\n--- the module this re-exports ---\n\n{_home.__doc__ or ''}"
