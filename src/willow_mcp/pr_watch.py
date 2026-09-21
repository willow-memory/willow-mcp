"""The PR watch file — who opened a pull request, so the steward can tell
that seat when its CI goes red (sealed pair 11ccb0f7, part 1).

``pr_open_execute`` opens PRs as willows-bot; the seat that asked was
recorded only in the FRANK citation (``actor`` + ``session``), which the
steward does not read. On 2026-09-21 ratatosk #48 went red two minutes after
the desk opened it, the steward filed it, and the desk heard from the
operator. The inbound half — steward → the seat that cares — needs one
durable fact the steward can read without willow-mcp in-process: *this PR
was opened by that seat, reachable on that Grove channel*.

That fact lives here: ``$WILLOW_HOME/willow-bot/pr_watch.json`` — the
steward's own state root, one JSON object keyed ``repo#pr``::

    {"willow-memory/ratatosk#48": {"app_id": "willow",
                                   "session_id": "371aa2fc-…",
                                   "channel": "#willow",
                                   "opened_at": "2026-09-21T02:03:12Z",
                                   "head": "feat/provider-ladder"}}

Channel convention is ``#<app_id>`` — the activation-rail convention
(``WAKE to=``, ``#app_id``), so the desk is ``#willow``. willow-mcp writes;
the steward reads; nothing else touches it. Never a token, never a key
name: the seat is named by app_id and session only.

Writes are atomic (tmp + ``os.replace``) and never raise into the PR open —
a PR that opened is open whether or not the watch row landed; the receipt
says which (three-state ``watch`` block: ``populated`` / ``unreachable``).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from . import paths

WATCH_FILE = "pr_watch.json"


def watch_path() -> Path:
    """``$WILLOW_HOME/willow-bot/pr_watch.json``. Routed through
    :func:`paths.willow_home` so a retired-home resolution raises rather
    than pointing at a dead tree."""
    return paths.willow_home() / "willow-bot" / WATCH_FILE


def channel_for(app_id: str) -> str:
    return f"#{(app_id or '').strip()}"


def watch_key(repo: str, number: int | str) -> str:
    return f"{repo}#{number}"


def load(path: Path | None = None) -> dict:
    """The watch table, or ``{}`` when absent or unreadable. Read-only; a
    malformed file reads as empty rather than raising into a caller that
    only wants to know whether a row exists."""
    p = path or watch_path()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def opened_by(app_id: str, session_id: str) -> dict:
    """The ``opened_by`` block a PR receipt carries: the seat, its session,
    and the channel the steward should speak on."""
    return {"app_id": app_id or "", "session_id": session_id or "",
            "grove_channel": channel_for(app_id)}


def record(*, repo: str, number: int | str, app_id: str, session_id: str,
           head: str, path: Path | None = None) -> dict:
    """Write (or overwrite) the watch row for ``repo#number``. Returns a
    three-state block for the receipt — ``populated`` with the path and
    key, or ``unreachable`` with the reason — and never raises."""
    key = watch_key(repo, number)
    row = {
        "app_id": app_id or "",
        "session_id": session_id or "",
        "channel": channel_for(app_id),
        "opened_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "head": head or "",
    }
    try:
        p = path or watch_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        table = load(p)
        table[key] = row
        tmp = p.with_suffix(p.suffix + f".tmp-{os.getpid()}")
        tmp.write_text(json.dumps(table, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, p)
    except Exception as exc:  # noqa: BLE001 — the PR is open; the row failing is reported, not raised
        return {"state": "unreachable", "reason": f"{type(exc).__name__}: {exc}"[:300], "key": key}
    return {"state": "populated", "path": str(p), "key": key, "channel": row["channel"]}
