"""willow-mcp hook runner — one entry point for every lifecycle hook.

Replaces four separate module invocations (`python -m willow_mcp.session_start_hook`,
`pre_tool_hook`, `session_stop_hook`, `stop_lint_hook`) with a single dispatcher:

    python -m willow_mcp.hook_runner --format {cursor,claude} <event>

Why:
- **Two-halves rule (Nestor decision `0225`).** A hook is only wired if the
  settings invoke it — separate assertions kept apart. Every event in the
  dispatch table below MUST have a matching invocation in
  `deploy/claude-settings.json` and `.claude-plugin/plugin.json`. Test
  `test_hook_wiring_sync.py` pins the join.
- **Cursor↔Claude dialect at one seam.** The underlying hook modules already
  sniff the payload via `cursor_hook_io.is_cursor_dialect()`; the `--format`
  arg is surfaced as `WILLOW_HOOK_FORMAT` for handlers that want it explicitly,
  but the runner does not translate on their behalf — it just picks the
  entry point.
- **Per-session boot sentinel.** On `session_start`, write
  `/tmp/willow-boot-done-<agent>-<sid>.flag` so parallel Claude Code windows
  on the same agent don't stomp each other's boot state — the bug named
  verbatim in `rudi193-cmd/willow-2.0/willow/fylgja/events/session_start.py`
  ("parallel windows all run as the same fleet identity, so the agent-keyed
  flag alone lets one window's SessionStart clear another's boot state
  mid-session (2026-07-04)"). The sentinel is best-effort — a filesystem
  failure must never fail the hook.

Backward compatibility: the existing `python -m willow_mcp.session_start_hook`
etc. entry points still work; this runner is a wrapper, not a replacement.
Adopting it in `deploy/claude-settings.json` is a follow-up commit.
"""

from __future__ import annotations

import argparse
import importlib
import io
import json
import os
import sys
from pathlib import Path
from typing import Callable

# Event → module:attr dispatch table. Additions here MUST land in the same
# PR as a matching `.claude/settings.json` / `plugin.json` invocation (two
# halves rule).
_EVENT_HANDLERS: dict[str, str] = {
    "session_start": "willow_mcp.session_start_hook:main",
    "pre_tool": "willow_mcp.pre_tool_hook:main",
    "session_stop": "willow_mcp.session_stop_hook:main",
    "stop_lint": "willow_mcp.stop_lint_hook:main",
}


def _resolve(target: str) -> Callable[[], None]:
    modpath, _, attr = target.partition(":")
    return getattr(importlib.import_module(modpath), attr)


def boot_sentinel_path(agent: str, session_id: str) -> Path:
    """Per-session sentinel path.

    Agent-only fallback (`/tmp/willow-boot-done-<agent>.flag`) preserves the
    legacy shape when no session_id is present in the payload — e.g., some
    older dialects or a hand-run of the hook without a session context.
    """
    sid = "".join(c for c in (session_id or "") if c.isalnum() or c in "_-")[:16]
    if sid:
        return Path(f"/tmp/willow-boot-done-{agent}-{sid}.flag")
    return Path(f"/tmp/willow-boot-done-{agent}.flag")


def _extract_session_id(payload: dict) -> str:
    return str(
        payload.get("session_id") or payload.get("conversation_id") or payload.get("parent_conversation_id") or ""
    )


def _write_boot_sentinel(payload: dict) -> None:
    """Best-effort per-session sentinel. Failures do not fail the hook."""
    try:
        agent = os.environ.get("WILLOW_APP_ID", "").strip() or "willow"
        path = boot_sentinel_path(agent, _extract_session_id(payload))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    except Exception:
        pass


def _snapshot_stdin_then_restore() -> tuple[str, dict]:
    """Read stdin once, parse JSON, and re-install a stream so the underlying
    hook's `json.load(sys.stdin)` still works.

    session_start_hook.main() reads stdin itself; the runner needs to peek at
    the payload to name the sentinel WITHOUT eating stdin from underneath.
    """
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
        if not isinstance(payload, dict):
            payload = {}
    except json.JSONDecodeError:
        payload = {}
    # Reinstall a buffer so downstream json.load(sys.stdin) succeeds.
    sys.stdin = io.StringIO(raw)
    return raw, payload


def main() -> None:
    parser = argparse.ArgumentParser(
        description="willow-mcp CLI-agnostic hook runner",
    )
    parser.add_argument("--format", choices=("cursor", "claude"), default="claude")
    parser.add_argument("event", choices=tuple(_EVENT_HANDLERS.keys()))
    args = parser.parse_args()

    # Handlers that sniff their own dialect via cursor_hook_io ignore this;
    # a handler that wants the explicit signal can read WILLOW_HOOK_FORMAT.
    os.environ["WILLOW_HOOK_FORMAT"] = args.format

    if args.event == "session_start":
        _raw, payload = _snapshot_stdin_then_restore()
        _write_boot_sentinel(payload)

    handler = _resolve(_EVENT_HANDLERS[args.event])
    handler()


if __name__ == "__main__":
    main()
