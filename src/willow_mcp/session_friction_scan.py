"""SessionEnd join for the friction floor (Wave 2): the scorer in
`friction_floor.py` / the persistence+dedup in `friction.py`'s `FrictionWatcher`
were both real and tested, but DARK — nothing on any real lifecycle ever called
`scan()`. This module is that join: read the session's own transcript at
SessionEnd, run it through the existing (unmodified, still-calibrated) watcher,
and let its own dedup-by-content persist a flag when it trips.

Everything here is a wrapper around already-correct pieces:
  * `_read_transcript_turns` turns a Claude Code transcript JSONL into the
    `[{role, text, ts}]` shape `FrictionWatcher.scan` already accepts.
  * `scan_session_for_friction` calls that scan and NEVER raises — SessionEnd
    is not a gate, so a bad transcript, a missing file, or a scorer surprise
    degrades to a no-op, not a blocked session close.
  * Idempotency is inherited, not reimplemented: `FrictionWatcher.scan` dedupes
    each flag by a hash of its own message text (`friction.py`), so replaying
    the same session's transcript (same turns -> same message -> same
    record_id) upserts the same row instead of stacking a duplicate. Closing
    twice, or a harness that re-invokes SessionEnd, is safe for free.
  * No new false positives: the window/floor defaults and the scorer itself
    are untouched — this module only supplies turns, it does not retune
    calibration.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from .db import Store
from .friction import FrictionWatcher

# Claude Code transcript record types that carry conversational text. Anything
# else (tool results surfaced as their own record, summaries, file-history
# snapshots, …) is silently skipped — not an error, just not a turn.
_TEXT_RECORD_TYPES = {"user", "assistant"}
_ROLE_MAP = {"user": "user", "assistant": "agent"}


def _extract_text(content: Any) -> str:
    """Join the text blocks of a Claude Code message `content` field. A plain
    string content is returned as-is; a list of content blocks (text mixed
    with tool_use/tool_result) keeps only the `type: "text"` blocks — tool
    plumbing is not a conversational turn and would only add scorer noise."""
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
    `[{role, text, ts}]`. Any read/parse failure — missing file, bad
    encoding, a malformed line — degrades to an empty list rather than
    raising; a transcript this hook can't read is a signal absence, not a
    reason to interrupt SessionEnd."""
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
                text = _extract_text(message.get("content"))
                if not text:
                    continue
                turns.append({
                    "role": _ROLE_MAP[rec["type"]],
                    "text": text,
                    "ts": _parse_ts(rec.get("timestamp")),
                })
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
    persist+dedupe any flag. Fail-open by construction: every branch below
    returns a dict, none raise, so a caller (the Stop/SessionEnd hook) never
    has its own return value put at risk by this call.

    `window`/`floor` default to the watcher's own calibrated defaults — kept
    as parameters only so a test can probe the boundary, never to be loosened
    by a caller trying to make the detector quieter."""
    if not session_id or not transcript_path:
        return {"skipped": "no_transcript"}
    try:
        turns = _read_transcript_turns(transcript_path)
        if not turns:
            return {"skipped": "no_turns"}
        watcher = FrictionWatcher(store if store is not None else Store())
        result = watcher.scan(turns, window=window, floor=floor)
    except Exception as exc:  # fail-open: SessionEnd is not a gate
        return {"error": "friction_scan_failed", "detail": str(exc)}
    if isinstance(result, dict) and result.get("error"):
        # bad turns after all (e.g. every extracted turn had an unrecognized
        # role) — still not a reason to fail the session close.
        return {"skipped": result["error"]}
    return result
