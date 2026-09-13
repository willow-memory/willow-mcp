"""Keep Cursor and Claude Code hook templates aligned."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .project_wiring import deploy_dir, resolve_willow_mcp_python


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def cursor_hooks_template() -> dict[str, Any]:
    from .project_wiring import render_cursor_hooks

    return render_cursor_hooks()


def claude_hooks_template() -> dict[str, Any]:
    data = _load(deploy_dir() / "claude-settings.json")
    hooks = data.get("hooks") or {}
    py = resolve_willow_mcp_python()
    return json.loads(json.dumps(hooks).replace("{{WILLOW_MCP_PYTHON}}", py))


def _extract_names(cmd: str) -> set[str]:
    """Extract the willow-mcp module + event fingerprint from a hook command.

    Post-2026-09-13 PR 2b, all lifecycle hooks route through
    `willow_mcp.hook_runner --format {cursor,claude} <event>`. Bare-module
    invocations like `willow_mcp.session_start_hook` are the pre-migration
    shape and still valid; either counts.

    Returns the event name (`session_start`, `pre_tool`, …) when the command
    goes through the runner, or the legacy module short-name (without the
    `_hook` suffix) when it's a bare invocation. Both cursor and claude
    templates should produce the same set of fingerprints — that's the
    parity invariant this feeds.
    """
    import re

    names: set[str] = set()
    m = re.search(
        r"willow_mcp\.hook_runner\s+--format\s+\S+\s+(\S+)",
        cmd,
    )
    if m:
        names.add(m.group(1))
        return names
    if "willow_mcp." in cmd:
        raw = cmd.split("willow_mcp.")[1].split()[0].strip("\"'")
        # Normalize legacy module names (e.g. `session_start_hook`) to the
        # same event fingerprint the runner uses (`session_start`).
        if raw.endswith("_hook"):
            names.add(raw[: -len("_hook")])
        else:
            names.add(raw)
    return names


def hook_module_names(hooks: dict[str, Any], *, claude: bool = False) -> set[str]:
    names: set[str] = set()
    if claude:
        for block in hooks.values():
            if not isinstance(block, list):
                continue
            for entry in block:
                for hook in entry.get("hooks") or []:
                    cmd = str(hook.get("command") or "")
                    names |= _extract_names(cmd)
        return names
    for _key, entries in hooks.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            cmd = str(entry.get("command") or "")
            names |= _extract_names(cmd)
    return names


def parity_report() -> dict[str, Any]:
    cursor_root = cursor_hooks_template()
    cursor = cursor_root.get("hooks") or cursor_root
    claude = claude_hooks_template()
    cursor_mods = hook_module_names(cursor, claude=False)
    claude_mods = hook_module_names(claude, claude=True)
    return {
        "cursor_modules": sorted(cursor_mods),
        "claude_modules": sorted(claude_mods),
        "aligned": cursor_mods == claude_mods,
        "missing_in_claude": sorted(cursor_mods - claude_mods),
        "missing_in_cursor": sorted(claude_mods - cursor_mods),
    }
