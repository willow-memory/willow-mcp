"""SessionEnd join for the friction floor (Wave 2): the scorer in
`friction_floor.py` / the persistence+dedup in `friction.py`'s `FrictionWatcher`
were both real and tested, but DARK — nothing on any real lifecycle ever called
`scan()`. This module is that join: read the session's own transcript at
SessionEnd, run it through the existing (unmodified, still-calibrated) watcher,
and let it persist a flag, scoped to THIS session, when it trips.

Two audit rounds shaped what this module does with tool activity — worth
stating plainly because the "obvious" fix in each direction is wrong:

  * Round 1 (MEDIUM): dropping tool_use/tool_result text entirely made a
    genuinely grounded agent (ran a test, got a short answer back, said little
    about it in prose) read as a content-free mirror and false-trip.
  * Round 2 (HIGH, this round): folding that tool text INTO the scored agent
    turn "fixed" round 1 by feeding `friction_score` — which is STANCE-BLIND
    and credits grounding/novelty from ANY text — enough digits and JSON
    punctuation that a single routine tool call per turn silently suppressed
    a genuinely sycophantic session's trip. That is a worse failure than
    round 1: it defeats the detector exactly where it matters most (tool-using
    coding sessions), and a flatterer can trigger the suppression on purpose
    just by calling a tool.

  The property that actually holds both halves at once: a sycophantic session
  trips REGARDLESS of whether it called tools (stance is scored from the
  agent's own prose, full stop — no tool text is ever handed to the scorer),
  and tool activity is carried instead as a separate, non-scoring `tool_active`
  flag per turn that `FrictionWatcher.scan` surfaces on the persisted flag as
  `tool_active_turns` (see friction.py). That annotation can tell a human
  reviewer "this window ran tools" so they can weigh a likely false positive
  faster — but, by construction, it has no path into mean_friction or
  escalation, so it can never inflate OR suppress the trip itself. A flatterer
  gets no lever here: calling a tool changes nothing about whether it trips.

Everything else is a wrapper around already-correct pieces:
  * `_read_transcript_turns` turns a Claude Code transcript JSONL into the
    `[{role, text, ts, tool_active}]` shape `FrictionWatcher.scan` accepts.
    `text` is prose only (the message's own `type: "text"` blocks) — tool
    payloads are never joined into it, so there is no unbounded string to cap
    in the first place.
  * `scan_session_for_friction` calls that scan and NEVER raises — SessionEnd
    is not a gate, so a bad transcript, a missing file, or a scorer surprise
    degrades to a named skip/error, not a blocked session close.
  * Idempotent AND attributable, per session: `session_id` is passed through
    to `FrictionWatcher.scan`, which folds it into both the dedup key and the
    stored flag. Two different sessions that each produce the same-shaped
    low-friction episode persist as two distinct flags, each naming which
    session tripped; replaying the SAME session's transcript still upserts
    the same record instead of stacking a duplicate.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from .db import Store
from .friction import FrictionWatcher

# Claude Code transcript record types that carry conversational text. Anything
# else (summaries, file-history snapshots, …) is silently skipped — not an
# error, just not a turn.
_TEXT_RECORD_TYPES = {"user", "assistant"}


def _extract_text(content: Any) -> str:
    """Join the `type: "text"` blocks of a Claude Code message `content`
    field. A plain string content is returned as-is. Deliberately ignores
    `tool_use`/`tool_result` blocks — see the module docstring for why tool
    payload text must never reach the scorer through here."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                text = block.get("text")
                if isinstance(text, str) and text:
                    parts.append(text)
        return "\n".join(parts)
    return ""


def _has_block_type(content: Any, block_type: str) -> bool:
    """Cheap presence check — never extracts or joins the block's text, so
    there is nothing here to cap or to leak into the scorer."""
    return isinstance(content, list) and any(
        isinstance(b, dict) and b.get("type") == block_type for b in content
    )


def _parse_ts(raw: Any) -> Optional[float]:
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        return float(raw)
    if isinstance(raw, str) and raw:
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def _read_transcript_turns(transcript_path: str) -> list[dict]:
    """Best-effort parse of a Claude Code transcript JSONL into
    `[{role, text, ts, tool_active}]`. Any read/parse failure — missing file,
    bad encoding, a malformed line — degrades to an empty list rather than
    raising; a transcript this hook can't read is a signal absence, not a
    reason to interrupt SessionEnd.

    An assistant turn's scored `text` is its `type: "text"` blocks ONLY.
    `tool_active` is a plain boolean: True if that assistant message itself
    contains a `tool_use` block, OR if the `tool_result` message relayed back
    for it follows immediately (a `tool_result`-carrying `user`-type record is
    mechanical relay, never a human turn, so it is folded as that boolean onto
    the preceding agent turn instead of becoming a fabricated user turn)."""
    turns: list[dict] = []
    try:
        with open(transcript_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except (ValueError, TypeError):
                    continue
                if not isinstance(rec, dict) or rec.get("type") not in _TEXT_RECORD_TYPES:
                    continue
                message = rec.get("message")
                if not isinstance(message, dict):
                    continue
                content = message.get("content")
                ts = _parse_ts(rec.get("timestamp"))

                if rec["type"] == "assistant":
                    text = _extract_text(content)
                    if text:
                        turns.append({
                            "role": "agent", "text": text, "ts": ts,
                            "tool_active": _has_block_type(content, "tool_use"),
                        })
                    continue

                # rec["type"] == "user"
                if _has_block_type(content, "tool_result"):
                    if turns and turns[-1]["role"] == "agent":
                        turns[-1]["tool_active"] = True
                    # Mechanical relay, not a human turn — never appended as
                    # its own "user" turn regardless of whether it folded.
                    continue
                text = _extract_text(content)
                if text:
                    turns.append({"role": "user", "text": text, "ts": ts})
    except (OSError, UnicodeDecodeError):
        return []
    return turns


def scan_session_for_friction(
    session_id: str,
    transcript_path: str,
    store: Optional[Store] = None,
    window: int = 4,
    floor: float = 0.35,
) -> dict:
    """SessionEnd entry point. Reads `transcript_path` (this session's own
    turns), scans it through the friction floor, and lets `FrictionWatcher`
    persist+dedupe any flag under this `session_id`. Fail-open by
    construction: every branch below returns a dict, none raise, so a caller
    (the Stop/SessionEnd hook) never has its own return value put at risk by
    this call.

    `window`/`floor` default to the watcher's own calibrated defaults — kept
    as parameters only so a test can probe the boundary, never to be loosened
    by a caller trying to make the detector quieter."""
    if not session_id:
        return {"skipped": "no_session_id"}
    if not transcript_path:
        return {"skipped": "no_transcript_path"}
    try:
        turns = _read_transcript_turns(transcript_path)
        if not turns:
            return {"skipped": "no_turns"}
        watcher = FrictionWatcher(store if store is not None else Store())
        result = watcher.scan(turns, window=window, floor=floor, session_id=session_id)
    except Exception as exc:  # fail-open: SessionEnd is not a gate
        return {"error": "friction_scan_failed", "detail": str(exc)}
    if isinstance(result, dict) and result.get("error"):
        # bad turns after all (e.g. every extracted turn had an unrecognized
        # role) — still not a reason to fail the session close.
        return {"skipped": result["error"]}
    return result
