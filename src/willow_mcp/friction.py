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

`friction_score` (what `FrictionFloor.scan` actually calls) is STANCE-BLIND:
it credits an agent turn's own pushback lexicon, grounding lexicon/digits/code
punctuation, and novelty — whatever text it's handed, regardless of whose
position it opposes. That is exactly why tool output must never be folded
into the text this module scores: a single routine tool call injects digits,
JSON punctuation, and unechoed tokens that read as "grounding" to a blind
scorer, so a caller that stuffs tool_use/tool_result text into an agent
turn's `text` lets a genuinely sycophantic agent hide behind any tool call at
all (willow-mcp#audit-E6EB3B12). `scan()` therefore only ever scores the
`text` it's given — a caller (session_friction_scan.py) is responsible for
keeping that to the agent's own prose — and instead accepts an optional,
side-channel `tool_active` flag per turn purely for the *stored flag's*
`tool_active_turns` annotation: reviewer context that can tell a quiet,
tool-grounded worker from a flatterer, but that never feeds the scorer and
therefore can never move a trip decision either direction.

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
        # Parallel to `norm`, index-for-index: whether that turn's *source*
        # (a caller like session_friction_scan.py) marked it as carrying tool
        # activity. This NEVER reaches friction_score/escalation_score — it is
        # attached to a flag only after FrictionFloor has already decided to
        # raise it, purely as a reviewer aid (see the note below the scan
        # call). A turn dict with no "tool_active" key behaves exactly as
        # before (False) — existing callers that don't know this key are
        # unaffected.
        tool_active = []
        for t in turns or []:
            if not isinstance(t, dict):
                continue
            role, text, ts = t.get("role"), t.get("text"), t.get("ts")
            if role not in ("user", "agent") or not isinstance(text, str):
                continue
            norm.append(Turn(role=role, text=text,
                             ts=ts if isinstance(ts, (int, float)) and not isinstance(ts, bool) else None))
            tool_active.append(bool(t.get("tool_active")))
        if not norm:
            return {"error": "no_valid_turns",
                    "detail": "turns must be a list of {role:'user'|'agent', text:str, ts?:number}"}

        flags = FrictionFloor(window=window, floor=floor).scan(norm)
        agent_indices = [i for i, t in enumerate(norm) if t.role == "agent"]
        out = []
        for f in flags:
            fd = {"at_turn": f.at_turn, "streak": f.streak,
                  "mean_friction": f.mean_friction, "escalation": f.escalation,
                  "low_turns": list(f.low_turns), "message": f.message}
            if session_id:
                fd["session_id"] = session_id
            # Tool-activity annotation — informational only. It is computed
            # from the SAME window FrictionFloor already flagged (the trailing
            # `streak` agent turns ending at `at_turn`), strictly AFTER
            # mean_friction/escalation decided this is a flag. It cannot
            # inflate or suppress that decision because it plays no part in
            # computing it: this is metadata a human reviewer uses to tell a
            # quiet, tool-grounded worker from a flatterer, never a lever a
            # flatterer can pull by calling a tool.
            try:
                pos = agent_indices.index(f.at_turn)
                window_idxs = agent_indices[max(0, pos - f.streak + 1): pos + 1]
            except ValueError:
                window_idxs = []
            fd["tool_active_turns"] = [i for i in window_idxs if tool_active[i]]
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
                        "low_turns": r.get("low_turns", []), "message": r.get("message"),
                        "tool_active_turns": r.get("tool_active_turns", [])})
        return out
