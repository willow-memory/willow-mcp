"""Resolve which seat a hook is firing for.

Gaps acceefc0ec77 / 3727efb30041: harness hooks often inherit a wrong
``WILLOW_APP_ID`` from a parent ``settings.local.json`` env block, while the
directory you opened carries the real seat in ``.mcp.json``. Where you open
chooses the seat — ``.mcp.json`` is authoritative when present; an env that
disagrees is a wiring fault, not a silent override.
"""
from __future__ import annotations

import json
import os
from typing import Any


def project_dir() -> str | None:
    """Harness project root for seat detection (``.mcp.json``)."""
    return (
        os.environ.get("CLAUDE_PROJECT_DIR")
        or os.environ.get("CURSOR_PROJECT_DIR")
        or os.environ.get("WILLOW_PROJECT_ROOT")
        or None
    )


def app_id_from_mcp_json(project: str | None = None) -> str | None:
    """Return ``WILLOW_APP_ID`` from the project's willow-mcp ``.mcp.json`` entry.

    Scans ``mcpServers`` for the first server whose env names an app_id.
    Missing or malformed files yield ``None`` (caller keeps current refuse /
    env rules). Not a trust boundary — only orientation for hooks.
    """
    root = project if project is not None else project_dir()
    if not root:
        return None
    path = os.path.join(root, ".mcp.json")
    try:
        with open(path, encoding="utf-8") as f:
            cfg: Any = json.load(f)
    except (OSError, ValueError):
        return None
    servers = cfg.get("mcpServers") if isinstance(cfg, dict) else None
    if not isinstance(servers, dict):
        return None
    for server in servers.values():
        if not isinstance(server, dict):
            continue
        env = server.get("env")
        if not isinstance(env, dict):
            continue
        app_id = str(env.get("WILLOW_APP_ID", "")).strip()
        if app_id:
            return app_id
    return None


def resolve_hook_app_id() -> tuple[str | None, str | None]:
    """Resolve the seat for a SessionStart / SessionEnd hook.

    Returns ``(app_id, error_message)``. On success ``error_message`` is
    ``None``. On failure ``app_id`` is ``None`` and ``error_message`` names
    the refuse reason.

    Rules (gap acceefc0ec77):
    * ``.mcp.json`` app_id, when present, is authoritative for this project.
    * Env ``WILLOW_APP_ID`` that disagrees with ``.mcp.json`` → refuse.
    * Env unset and ``.mcp.json`` present → use the config value.
    * Both unset → refuse (PR4: never default to willow).
    """
    env_app = os.environ.get("WILLOW_APP_ID", "").strip()
    config_app = app_id_from_mcp_json()
    if config_app and env_app and config_app != env_app:
        return None, (
            f"WILLOW_APP_ID env={env_app!r} disagrees with "
            f".mcp.json app_id={config_app!r} under "
            f"{project_dir() or '?'}. The directory you opened chooses the "
            "seat — clear the inherited env (often root "
            ".claude/settings.local.json) or open the matching project root. "
            "Gaps acceefc0ec77 / 3727efb30041."
        )
    app_id = config_app or env_app
    if not app_id:
        return None, (
            "WILLOW_APP_ID is not set on this MCP server env. Willow no longer "
            "defaults to 'willow' — an unset value used to silently claim the "
            "orchestrator seat. Set WILLOW_APP_ID=willow (orchestrator "
            "workspace) or WILLOW_APP_ID=<specialist_id> (specialist workspace) "
            "in your MCP config next to WILLOW_HUMAN_ORCHESTRATOR. See "
            "docs/design/human-orchestrator.md wiring checklist item 2."
        )
    return app_id, None
