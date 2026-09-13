"""Cursor hook stdin/stdout dialect for willow-mcp guards.

Claude PreToolUse uses ``tool_name`` / ``tool_input`` and honors
``{"decision": "block"}``. Cursor ``beforeShellExecution`` / ``beforeMCPExecution``
/ ``preToolUse`` use top-level ``command`` / ``server`` fields and honor
``{"permission": "deny"}``. Without this adapter, ``pre_tool_hook`` exits with no
stdout and failClosed blocks the agent.
"""
from __future__ import annotations

import json
import sys
from typing import Any


def hook_event_name(payload: dict[str, Any]) -> str:
    return str(payload.get("hook_event_name") or payload.get("hookEventName") or "")


def is_cursor_shell_event(payload: dict[str, Any]) -> bool:
    if hook_event_name(payload) == "beforeShellExecution":
        return True
    if isinstance(payload.get("command"), str) and payload.get("tool_name") in (
        None,
        "",
        "Shell",
    ):
        return True
    return False


def is_cursor_dialect(payload: dict[str, Any]) -> bool:
    """Cursor hook events use ``permission`` stdout; Claude uses ``decision``."""
    event = hook_event_name(payload)
    if event in ("beforeShellExecution", "beforeMCPExecution", "preToolUse"):
        return True
    return is_cursor_shell_event(payload) or is_cursor_mcp_event(payload)


def is_cursor_mcp_event(payload: dict[str, Any]) -> bool:
    if hook_event_name(payload) == "beforeMCPExecution":
        return True
    if payload.get("server") and payload.get("tool_name") and "tool_input" in payload:
        return True
    return False


def extract_shell_command(payload: dict[str, Any]) -> str:
    if isinstance(payload.get("command"), str):
        return payload["command"]
    tool_input = payload.get("tool_input") or payload.get("arguments") or {}
    if isinstance(tool_input, dict):
        cmd = tool_input.get("command")
        if isinstance(cmd, str):
            return cmd
    return ""


def normalize_cursor_mcp_payload(payload: dict[str, Any]) -> dict[str, Any]:
    server = str(payload.get("server") or payload.get("mcp_server") or "willow-mcp")
    tool = str(payload.get("tool_name") or payload.get("toolName") or "")
    tool_input = payload.get("tool_input") or payload.get("arguments") or {}
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except json.JSONDecodeError:
            tool_input = {}
    if not isinstance(tool_input, dict):
        tool_input = {}
    qualified = f"mcp__{server}__{tool}" if tool else tool
    return {"tool_name": qualified, "tool_input": tool_input}


def emit_cursor_permission(
    permission: str,
    *,
    user_message: str = "",
    agent_message: str = "",
) -> None:
    print(
        json.dumps(
            {
                "permission": permission,
                "user_message": user_message,
                "agent_message": agent_message or user_message,
            }
        )
    )


def emit_claude_block(reason: str) -> None:
    print(
        json.dumps(
            {
                "decision": "block",
                "reason": reason,
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                },
            }
        )
    )


def emit_claude_warn(reason: str) -> None:
    print(json.dumps({"decision": "warn", "reason": reason}))


def cursor_permission_for_guard(decision: str, reason: str) -> None:
    if decision == "block":
        emit_cursor_permission("deny", user_message=reason, agent_message=reason)
    elif decision == "warn":
        emit_cursor_permission(
            "ask",
            user_message=reason,
            agent_message=reason,
        )
    else:
        emit_cursor_permission("allow")


def run_cursor_shell_guards(
    command: str,
    *,
    check_bash_self_grant: Any,
    check_bash_remote_fail_closed: Any,
    check_bash: Any,
    check_bash_routing: Any,
) -> None:
    """Run bash guard helpers from pre_tool_use; print Cursor stdout and exit."""
    reason = (
        check_bash_self_grant(command)
        or check_bash_remote_fail_closed(command)
        or check_bash(command)
    )
    if reason:
        cursor_permission_for_guard("block", reason)
        sys.exit(0)
    routed = check_bash_routing(command)
    if routed:
        cursor_permission_for_guard(routed[0], routed[1])
        sys.exit(0)
    emit_cursor_permission("allow")
    sys.exit(0)
