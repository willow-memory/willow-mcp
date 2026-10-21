"""Remote-session enforcement posture (#164).

SessionStart records whether the Willow MCP stack is actually wired (MCP config,
PreToolUse hook registration, local diagnostic handshake). The PreToolUse hook
reads that marker in CCR sessions and fail-closes raw DB/network clients when the
gate is absent — better a blocked shell than an ungated one.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

from . import onescript_clock

MARKER_NAME = "remote_posture.json"
SCHEMA_VERSION = 1


def _utc_now() -> str:
    """In the one script's ``seconds_z`` format, from its one clock (flatten-2 F8:
    "Using the onescript at every path."). ``$ONESCRIPT_NOW`` pins it. With no one
    script reachable this falls back to the carried ``clock_local`` and says so (``onescript_clock.SOURCE``)."""
    return onescript_clock.clock().seconds_z()


def marker_path(*, willow_home: str | Path) -> Path:
    return Path(willow_home).expanduser() / "enforcement" / MARKER_NAME


def hooks_registered(project_dir: str | Path) -> bool:
    """True when .claude/settings.json wires hooks/pre_tool_use.py for Bash."""
    settings = Path(project_dir) / ".claude" / "settings.json"
    try:
        data = json.loads(settings.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    hooks = data.get("hooks") or {}
    pre = hooks.get("PreToolUse")
    if not isinstance(pre, list):
        return False
    needle = "pre_tool_use.py"
    for entry in pre:
        if not isinstance(entry, dict):
            continue
        for hook in entry.get("hooks") or []:
            if not isinstance(hook, dict):
                continue
            cmd = str(hook.get("command") or "")
            if needle in cmd:
                return True
    return False


def mcp_configured(project_dir: str | Path) -> bool:
    """True when .mcp.json declares a willow-mcp stdio server with WILLOW_HOME."""
    mcp_json = Path(project_dir) / ".mcp.json"
    try:
        data = json.loads(mcp_json.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        return False
    for name, server in servers.items():
        if not isinstance(server, dict):
            continue
        is_willow = "willow" in str(name).lower() or server.get("args") == ["-m", "willow_mcp"]
        if not is_willow:
            continue
        env = server.get("env")
        if isinstance(env, dict) and env.get("WILLOW_HOME"):
            return True
    return False


def diagnostic_verdict(*, app_id: str) -> tuple[Optional[str], Optional[str]]:
    """Run diagnostic_summary in-process; return (verdict, error)."""
    try:
        from .server import diagnostic_summary
    except Exception as exc:  # pragma: no cover - import guard
        return None, f"import_failed: {exc}"
    try:
        result = diagnostic_summary(app_id=app_id or "")
    except Exception as exc:
        return None, f"diagnostic_failed: {exc}"
    if not isinstance(result, dict):
        return None, "diagnostic_not_dict"
    if "error" in result:
        return None, str(result["error"])
    return str(result.get("verdict") or ""), None


def assess(
    *,
    project_dir: str | Path,
    willow_home: str | Path,
    app_id: str,
    remote: bool,
) -> dict[str, Any]:
    hooks_ok = hooks_registered(project_dir)
    mcp_ok = mcp_configured(project_dir)
    verdict, diag_err = diagnostic_verdict(app_id=app_id) if mcp_ok else (None, "mcp_not_configured")
    # Server package runnable and install wired — not whether the IDE client
    # connected this second (hooks cannot call MCP). Postgres may be down
    # (degraded) and store/knowledge tools may still be partially usable.
    mcp_live = bool(
        hooks_ok
        and mcp_ok
        and verdict in ("ok", "degraded")
        and diag_err is None
    )
    return {
        "schema": SCHEMA_VERSION,
        "remote": remote,
        "hooks_registered": hooks_ok,
        "mcp_configured": mcp_ok,
        "diagnostic_verdict": verdict,
        "diagnostic_error": diag_err,
        "mcp_live": mcp_live,
        "checked_at": _utc_now(),
        "project_dir": str(Path(project_dir).resolve()),
        "willow_home": str(Path(willow_home).resolve()),
        "app_id": app_id,
    }


def write_marker(posture: dict[str, Any], *, willow_home: str | Path) -> Path:
    path = marker_path(willow_home=willow_home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(posture, indent=2) + "\n", encoding="utf-8")
    return path


def load_marker(*, willow_home: Optional[str] = None, project_dir: Optional[str] = None) -> Optional[dict]:
    candidates: list[Path] = []
    if willow_home:
        candidates.append(marker_path(willow_home=willow_home))
    if project_dir:
        candidates.append(Path(project_dir) / ".willow" / "enforcement" / MARKER_NAME)
    for path in candidates:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    return None


def banner(posture: dict[str, Any]) -> str:
    if posture.get("mcp_live"):
        return ""
    lines = [
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "WILLOW ENFORCEMENT: MCP GATE NOT LIVE (remote session)",
        "Raw psql/sqlite3/curl and similar Bash will be BLOCKED by PreToolUse.",
    ]
    if not posture.get("hooks_registered"):
        lines.append("  ✗ PreToolUse hook not registered in .claude/settings.json")
    if not posture.get("mcp_configured"):
        lines.append("  ✗ .mcp.json missing willow-mcp with WILLOW_HOME env")
    if posture.get("diagnostic_error"):
        lines.append(f"  ✗ diagnostic_summary: {posture['diagnostic_error']}")
    elif posture.get("diagnostic_verdict") not in ("ok", "degraded", None):
        lines.append(f"  ✗ diagnostic_summary verdict: {posture.get('diagnostic_verdict')}")
    lines.append("  Fix: bash scripts/sandbox-bootstrap.sh — re-run SessionStart after.")
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    return "\n".join(lines)


def record_boot(
    *,
    project_dir: str,
    willow_home: str,
    app_id: str,
    remote: bool = True,
) -> dict[str, Any]:
    posture = assess(
        project_dir=project_dir,
        willow_home=willow_home,
        app_id=app_id,
        remote=remote,
    )
    write_marker(posture, willow_home=willow_home)
    if remote:
        text = banner(posture)
        if text:
            print(text, file=sys.stderr)
    return posture


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Record remote enforcement posture (#164)")
    parser.add_argument("command", choices=["record"])
    parser.add_argument("--project-dir", required=True)
    parser.add_argument("--willow-home", required=True)
    parser.add_argument("--app-id", default=os.environ.get("WILLOW_APP_ID", "willow"))
    parser.add_argument(
        "--remote",
        action=argparse.BooleanOptionalAction,
        default=os.environ.get("CLAUDE_CODE_REMOTE", "").strip().lower() == "true",
    )
    args = parser.parse_args(argv)
    if args.command == "record":
        record_boot(
            project_dir=args.project_dir,
            willow_home=args.willow_home,
            app_id=args.app_id,
            remote=args.remote,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
