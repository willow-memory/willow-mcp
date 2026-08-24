"""SessionStart dedup + continuation helpers (ported from fylgja session_inject)."""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

_DEDUP_TTL_SEC = 300


def _marker_path() -> Path:
    home = Path(os.environ.get("WILLOW_HOME", Path.home() / ".willow"))
    d = home / "run"
    d.mkdir(parents=True, exist_ok=True)
    return d / "session-inject-marker.json"

MAX_CORRECTIONS = 4
MAX_PREFERENCES = 3
MAX_HUMAN_CONFIRMATIONS = 2
CORRECTION_EXCERPT_CHARS = 100
PREFERENCE_EXCERPT_CHARS = 100
CONFIRMATION_EXCERPT_CHARS = 100


def excerpt_corpus(text: str, max_chars: int) -> str:
    s = " ".join(str(text).split())
    if len(s) <= max_chars:
        return s
    if max_chars <= 1:
        return s[:max_chars]
    return s[: max_chars - 1].rstrip() + "…"


def is_continuation_source(source: str) -> bool:
    return source in ("compact", "resume")


def is_fresh_source(source: str) -> bool:
    return source in ("startup", "clear", "")


def dedup_fingerprint(session_id: str, lines: list[str]) -> str:
    payload = f"{session_id}\n" + "\n".join(lines[:12])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def should_skip_duplicate(session_id: str, fingerprint: str) -> bool:
    if not session_id:
        return False
    try:
        marker = _marker_path()
        if not marker.is_file():
            return False
        data = json.loads(marker.read_text(encoding="utf-8"))
        if data.get("session_id") != session_id:
            return False
        if data.get("fingerprint") != fingerprint:
            return False
        age = time.time() - float(data.get("ts", 0))
        return age < _DEDUP_TTL_SEC
    except Exception:
        return False


def record_injection(session_id: str, fingerprint: str, *, lite: bool) -> None:
    if not session_id:
        return
    try:
        _marker_path().write_text(
            json.dumps(
                {
                    "session_id": session_id,
                    "fingerprint": fingerprint,
                    "lite": lite,
                    "ts": time.time(),
                }
            ),
            encoding="utf-8",
        )
    except Exception:
        pass


def minimal_continuation_block(agent: str, postgres: str, next_bite: str = "") -> list[str]:
    lines = [
        "[SESSION] continuation — prior INDEX omitted (dedup/token budget).",
        f"agent={agent}  postgres={postgres}",
    ]
    if next_bite:
        lines.append(f"NEXT: {next_bite[:160]}")
    return lines


def utc_clock_line() -> str:
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    local = datetime.now().astimezone()
    return f"[CLOCK] UTC {now.strftime('%Y-%m-%dT%H:%MZ')} · local {local.strftime('%Y-%m-%d %H:%M %Z')}"
