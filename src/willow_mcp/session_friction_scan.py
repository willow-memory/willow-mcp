"""SessionEnd join for the friction floor (Wave 2): the scorer in
`friction_floor.py` / the persistence+dedup in `friction.py`'s `FrictionWatcher`
were both real and tested, but DARK — nothing on any real lifecycle ever called
`scan()`. This module is that join: read the session's own transcript at
SessionEnd, run it through the existing (unmodified, still-calibrated) watcher,
and let it persist a flag, scoped to THIS session, when it trips.

Everything here is a wrapper around already-correct pieces, plus two fixes
found in audit:
  * `_read_transcript_turns` turns a Claude Code transcript JSONL into the
    `[{role, text, ts}]` shape `FrictionWatcher.scan` already accepts. An
    assistant turn's `tool_use` blocks (name + input) and the `tool_result`
    relayed back for it are folded into that same agent turn's text as
    grounding evidence — NOT dropped, and NOT treated as a second human
    turn — so an agent that grounds itself by actually running something
    (tests, greps, file reads) doesn't read as a content-free mirror just
    because the substance of what it did lived in a tool block instead of
    prose. Capped in length so raw tool noise (a huge diff, a long log)
    can't itself swamp the scorer the other direction.
  * `scan_session_for_friction` calls that scan and NEVER raises — SessionEnd
    is not a gate, so a bad transcript, a missing file, or a scorer surprise
    degrades to a named skip/error, not a blocked session close.
  * Idempotent AND attributable, per session: `session_id` is passed through
    to `FrictionWatcher.scan`, which folds it into both the dedup key and the
    stored flag (`friction.py`). Two different sessions that each produce the
    same-shaped low-friction episode now persist as two distinct flags, each
    naming which session tripped; replaying the SAME session's transcript
    still upserts the same record instead of stacking a duplicate.
  * No new false positives: the window/floor defaults and the scorer itself
    are untouched — this module only supplies turns (now including the
    grounding fix above), it does not retune calibration.
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

# Caps keep tool grounding evidence legible to the scorer (which only needs a
# few digits/words/punctuation marks to register grounding) without letting a
# huge tool payload (a full diff, a long test log) dominate the turn's text
# or blow up what's persisted.
_TOOL_USE_REPR_CAP = 200
_TOOL_RESULT_TEXT_CAP = 500


def _extract_text(content: Any) -> str:
    """Join the `type: "text"` blocks of a Claude Code message `content`
    field. A plain string content is returned as-is."""
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


def _tool_use_snippets(content: Any) -> list[str]:
    """Compact `[tool_use:<name> <input>]` snippets for each tool_use block in
    an assistant message — the grounding evidence of what the agent actually
    DID (ran a command, read a file, greped a path), kept short enough that it
    adds signal without becoming the whole turn."""
    if not isinstance(content, list):
        return []
    out = []
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "tool_use":
            continue
        name = block.get("name")
        if not isinstance(name, str) or not name:
            continue
        try:
            input_repr = json.dumps(block.get("input"), sort_keys=True, default=str)
        except (TypeError, ValueError):
            input_repr = str(block.get("input"))
        out.append(f"[tool_use:{name} {input_repr}]"[:_TOOL_USE_REPR_CAP])
    return out


def _tool_result_snippets(content: Any) -> list[str]:
    """Compact `[tool_result: <text>]` snippets for each tool_result block in
    a user-role message — what came back from a tool the agent invoked. This
    is mechanical relay, not a human utterance, so it is never turned into a
    standalone user turn; the caller folds it into the agent turn that
    triggered it instead."""
    if not isinstance(content, list):
        return []
    out = []
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "tool_result":
            continue
        text = _extract_text(block.get("content"))
        if text:
            out.append(f"[tool_result: {text}]"[:_TOOL_RESULT_TEXT_CAP])
    return out


def _has_tool_result(content: Any) -> bool:
    return isinstance(content, list) and any(
        isinstance(b, dict) and b.get("type") == "tool_result" for b in content
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
    `[{role, text, ts}]`. Any read/parse failure — missing file, bad
    encoding, a malformed line — degrades to an empty list rather than
    raising; a transcript this hook can't read is a signal absence, not a
    reason to interrupt SessionEnd.

    An assistant turn's text is its `text` blocks PLUS a compact rendering of
    its `tool_use` blocks (what it actually ran). The `tool_result` a tool
    invocation returns arrives as its own `user`-type record in the raw
    transcript, but it is not a human turn — it's folded into the preceding
    agent turn's text as grounding evidence instead of becoming a second,
    fabricated user utterance."""
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
                    parts = [_extract_text(content), *_tool_use_snippets(content)]
                    text = "\n".join(p for p in parts if p)
                    if text:
                        turns.append({"role": "agent", "text": text, "ts": ts})
                    continue

                # rec["type"] == "user"
                if _has_tool_result(content):
                    relay = "\n".join(_tool_result_snippets(content))
                    if relay and turns and turns[-1]["role"] == "agent":
                        turns[-1]["text"] = turns[-1]["text"] + "\n" + relay
                    # A tool_result-carrying message is a mechanical relay, not
                    # a human turn, whether or not it also folded anywhere —
                    # never appended as its own "user" turn.
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
