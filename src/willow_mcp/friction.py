"""friction — the willow-mcp watcher around the vendored friction_floor.

The seam doc's Phase 1: wire willow-gate's model-free relationship smoke detector
into willow-mcp as a LOUD, HUMAN-FACING signal that never blocks and never
touches the auth path. `friction_floor` watches one thing — whether the agent has
stopped being *other* and started mirroring the user back, smoothed, WHILE the
user is escalating — and raises a flag when it does. It is a SIGNAL, not a
verdict (it false-positives and a clever mirror can duck it); its value is
observability: it makes an invisible thing leave a trace.

This wrapper adds two willow-mcp things to the pure scanner: it persists any flag
to a SOIL collection (the durable trace a human can review later, deduped by
content so re-scanning an overlapping window doesn't pile up copies), and it
exposes a list verb.

Two honest constraints carried from upstream:
  * It is DETERMINISTIC and MODEL-FREE — no LLM, no egress. Safe to run anywhere;
    it cannot leak and it cannot be gamed by the model it watches at runtime.
  * It must run OUTSIDE the model it watches — a mirror cannot audit itself. The
    intended caller is a harness/monitor feeding in a transcript window, NOT the
    watched agent scanning itself (that is theater). willow-mcp cannot enforce
    "outside"; it documents it.
"""
from __future__ import annotations

import hashlib
from typing import Optional

from .friction_floor import FrictionFloor, Turn

COLLECTION = "friction_flags"


class FrictionWatcher:
    def __init__(self, store, collection: str = COLLECTION):
        self.store = store
        self.collection = collection

    def scan(self, turns, window: int = 4, floor: float = 0.35,
              session_id: Optional[str] = None) -> dict:
        """Scan a transcript window and persist any flag it raises.

        `turns`: [{role: 'user'|'agent', text: str, ts?: number}, …]. Returns
        {tripped, flags, agent_turns, scanned_turns, window, floor}. A clean scan
        writes nothing; a tripped scan persists each flag (deduped by content).

        `session_id` is optional (default None preserves the original,
        session-agnostic behavior for callers — e.g. the ad hoc `friction_scan`
        MCP tool — that hand it an arbitrary window with no session concept).
        When a caller DOES know which session it is scanning, passing it here
        makes the dedup key and the stored flag both session-scoped: two
        different sessions that each produce the same low-friction episode
        persist as two distinct, attributable flags, and every stored flag
        that came from a known session carries that session_id. Without it, a
        bare sha256(message) key means a second session with an identically
        shaped episode silently overwrites the first session's flag, and
        nothing on the stored record says which session tripped."""
        if not isinstance(window, int) or window < 2:
            return {"error": "bad_window", "detail": "window must be an int >= 2"}
        try:
            floor = float(floor)
        except (TypeError, ValueError):
            return {"error": "bad_floor", "detail": "floor must be a number in [0,1]"}
        if not 0.0 <= floor <= 1.0:
            return {"error": "bad_floor", "detail": "floor must be in [0,1]"}

        norm = []
        for t in turns or []:
            if not isinstance(t, dict):
                continue
            role, text, ts = t.get("role"), t.get("text"), t.get("ts")
            if role not in ("user", "agent") or not isinstance(text, str):
                continue
            norm.append(Turn(role=role, text=text,
                             ts=ts if isinstance(ts, (int, float)) and not isinstance(ts, bool) else None))
        if not norm:
            return {"error": "no_valid_turns",
                    "detail": "turns must be a list of {role:'user'|'agent', text:str, ts?:number}"}

        flags = FrictionFloor(window=window, floor=floor).scan(norm)
        out = []
        for f in flags:
            fd = {"at_turn": f.at_turn, "streak": f.streak,
                  "mean_friction": f.mean_friction, "escalation": f.escalation,
                  "low_turns": list(f.low_turns), "message": f.message}
            if session_id:
                fd["session_id"] = session_id
            # Dedupe by content so a monitor re-scanning an overlapping window
            # doesn't record the same alarm twice — scoped by session_id (when
            # known) so two different sessions with the same-shaped episode
            # persist as two attributable flags rather than one overwriting
            # the other.
            dedupe_key = f"{session_id}:{f.message}" if session_id else f.message
            fid = "flag_" + hashlib.sha256(dedupe_key.encode("utf-8", "replace")).hexdigest()[:16]
            self.store.put(self.collection, fd, record_id=fid)
            out.append(fd)
        return {"tripped": bool(out), "flags": out,
                "agent_turns": sum(1 for t in norm if t.role == "agent"),
                "scanned_turns": len(norm), "window": window, "floor": floor}

    def list_flags(self, limit: int = 20) -> list:
        rows = self.store.all(self.collection)
        rows.sort(key=lambda r: r.get("_created", ""), reverse=True)
        out = []
        for r in rows[:max(1, limit)]:
            out.append({"id": r.get("_id"), "recorded_at": r.get("_created"),
                        "session_id": r.get("session_id"),
                        "escalation": r.get("escalation"),
                        "mean_friction": r.get("mean_friction"),
                        "low_turns": r.get("low_turns", []), "message": r.get("message")})
        return out
