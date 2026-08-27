"""Agent-agnostic IDE wiring for willow-mcp managed projects.

Materializes Cursor hooks, Claude settings, and active-agent markers from
``src/willow_mcp/deploy/`` templates — not fleet fylgja hooks.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from .paths import willow_home

_HOME_VAR = "{{HOME}}"

_DEFAULT_WIRING: dict[str, Any] = {
    "hooks": True,
    "active_agent": True,
    "claude_settings": "project",
}

_DESTRUCTIVE_WILLOW_DENY = [
    "mcp__willow__app_uninstall",
    "mcp__willow__policy_put",
    "mcp__willow__policy_delete",
    "mcp__willow__routine_register",
]

_HOOK_EVENTS: dict[str, dict[str, str]] = {
    "session_start": {"cursor": "sessionStart", "claude": "SessionStart"},
    "prompt_submit": {"cursor": "beforeSubmitPrompt", "claude": "UserPromptSubmit"},
    "pre_compact": {"cursor": "preCompact", "claude": "PreCompact"},
    "pre_tool_use": {"cursor": "preToolUse", "claude": "PreToolUse"},
    "stop": {"cursor": "stop", "claude": "Stop"},
    "session_end": {"cursor": "sessionEnd", "claude": "SessionEnd"},
    # Kept in the neutral vocabulary so a manifest gets a precise client
    # compatibility error instead of the less useful "unknown event".
    "notification": {"claude": "Notification"},
}

_TOOL_MATCHERS: dict[str, dict[str, str]] = {
    "shell": {"cursor": "Shell", "claude": "Bash"},
    "write": {
        "cursor": "Write",
        "claude": "Write|Edit|MultiEdit|NotebookEdit",
    },
    "mcp": {"cursor": "MCP:.*", "claude": "mcp__"},
    "web": {"cursor": "WebSearch|WebFetch", "claude": "WebSearch|WebFetch"},
    "task": {"cursor": "Task", "claude": "Task"},
}

_CLAUDE_EVENTS = {
    client_event: neutral_event
    for neutral_event, clients in _HOOK_EVENTS.items()
    if (client_event := clients.get("claude")) is not None
}

_CLAUDE_TOOL_MATCHERS = {
    clients["claude"]: neutral_tool
    for neutral_tool, clients in _TOOL_MATCHERS.items()
}


def deploy_dir() -> Path:
    return Path(__file__).resolve().parent / "deploy"


def expand_home(text: str) -> str:
    home = str(Path.home())
    return text.replace(_HOME_VAR, home).replace("${HOME}", home).replace("$HOME", home)


def resolve_willow_mcp_python() -> str:
    raw = os.environ.get("WILLOW_MCP_PYTHON", "").strip()
    if raw:
        return expand_home(raw)
    # Derived from willow_home(), not hardcoded: the 2026-08-10 org-folder move
    # relocated $WILLOW_HOME out of ~/github/.willow, and the old literal below
    # then silently lost to `which python3` — a system interpreter with no
    # willow_mcp installed. That fallback writes a .mcp.json whose server cannot
    # start, and nothing reports it. The legacy path stays as a back-compat
    # candidate for installs that have not moved yet.
    candidates = [
        willow_home() / "venvs" / "willow-mcp" / "bin" / "python",
        Path.home() / "github" / ".willow" / "venvs" / "willow-mcp" / "bin" / "python",
        shutil.which("python3"),
        sys.executable,
    ]
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(str(candidate))
        if path.is_file():
            # Absolute, NOT resolved. A venv's bin/python is a symlink chain
            # ending at the system interpreter (bin/python → python3 →
            # /usr/bin/pythonX.Y), and .resolve() follows it to the end — which
            # hands back a base interpreter that cannot import willow_mcp. A
            # venv is identified by the path you invoke, not by the binary
            # behind it, so the symlink is the answer and must be preserved.
            return os.path.abspath(str(path))
    return sys.executable


def _substitute_placeholders(obj: Any, values: dict[str, str]) -> Any:
    if isinstance(obj, str):
        out = obj
        for key, val in values.items():
            out = out.replace(f"{{{{{key}}}}}", val)
        return out
    if isinstance(obj, list):
        return [_substitute_placeholders(x, values) for x in obj]
    if isinstance(obj, dict):
        return {k: _substitute_placeholders(v, values) for k, v in obj.items()}
    return obj


def render_claude_permissions(servers: list[str]) -> dict[str, Any]:
    allow = [
        "Read(*)",
        "Edit(*)",
        "Write(*)",
        "Glob(*)",
        "Grep(*)",
        "Skill(*)",
        "Task(*)",
    ]
    for name in servers:
        if isinstance(name, str) and name:
            allow.append(f"mcp__{name}__*")
    seen: set[str] = set()
    deduped: list[str] = []
    for item in allow:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)

    deny = list(_DESTRUCTIVE_WILLOW_DENY) if "willow" in servers else []
    enabled = [s for s in servers if isinstance(s, str)]
    return {
        "permissions": {"allow": deduped, "deny": deny},
        "enableAllProjectMcpServers": True,
        "enabledMcpjsonServers": enabled,
    }


def normalize_wiring(entry: dict[str, Any]) -> dict[str, Any]:
    if "wiring" not in entry:
        return {k: False for k in _DEFAULT_WIRING}
    raw = entry.get("wiring")
    if raw is False:
        return {k: False for k in _DEFAULT_WIRING}
    if not isinstance(raw, dict):
        return dict(_DEFAULT_WIRING)
    out = dict(_DEFAULT_WIRING)
    out.update(raw)
    return out


def _project_root(project_id: str, entry: dict[str, Any]) -> Path:
    raw = str(entry.get("path") or "").strip()
    if not raw:
        raise ValueError(f"project {project_id!r}: path required")
    return Path(expand_home(raw)).resolve()


def _owned_path(project_id: str, root: Path, raw: Any, *, label: str) -> Path:
    value = str(raw or "").strip()
    if not value:
        raise ValueError(f"project {project_id!r}: {label} required")
    relative = Path(value)
    if relative.is_absolute():
        raise ValueError(f"project {project_id!r}: {label} must be project-relative")
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"project {project_id!r}: {label} escapes project root"
        ) from exc
    if not path.is_file():
        raise ValueError(f"project {project_id!r}: {label} not found: {path}")
    return path


def _hook_manifest_path(
    project_id: str,
    entry: dict[str, Any],
    wiring: dict[str, Any] | None = None,
) -> Path | None:
    selected = (wiring or normalize_wiring(entry)).get("hook_manifest")
    if selected in (None, False, ""):
        return None
    return _owned_path(
        project_id,
        _project_root(project_id, entry),
        selected,
        label="hook_manifest",
    )


def _load_hook_manifest(project_id: str, entry: dict[str, Any]) -> dict[str, Any] | None:
    path = _hook_manifest_path(project_id, entry)
    if path is None:
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"project {project_id!r}: unreadable hook_manifest {path}: {exc}"
        ) from exc
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError(f"project {project_id!r}: hook_manifest version must be 1")
    if not isinstance(data.get("hooks"), list) or not data["hooks"]:
        raise ValueError(f"project {project_id!r}: hook_manifest hooks[] required")
    _owned_path(
        project_id,
        _project_root(project_id, entry),
        data.get("command"),
        label="hook_manifest command",
    )
    return data


def _manifest_env(
    project_id: str,
    entry: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, str]:
    root = _project_root(project_id, entry)
    agent = str(entry.get("agent") or "willow").strip()
    values = {"PROJECT_ROOT": str(root), "AGENT": agent, "PROJECT_ID": project_id}
    env = {
        "WILLOW_APP_ID": agent,
        "WILLOW_AGENT_NAME": agent,
        "AGENT_NAME": agent,
        "WILLOW_PROJECT_ROOT": str(root),
    }
    declared = manifest.get("env")
    if declared is not None and not isinstance(declared, dict):
        raise TypeError(f"project {project_id!r}: hook_manifest env must be an object")
    for key, value in (declared or {}).items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypeError(
                f"project {project_id!r}: hook_manifest env values must be strings"
            )
        env[key] = _substitute_placeholders(value, values)
    return env


def _hook_command(
    project_id: str,
    entry: dict[str, Any],
    manifest: dict[str, Any],
    client: str,
    action: str,
) -> str:
    root = _project_root(project_id, entry)
    command = _owned_path(
        project_id,
        root,
        manifest.get("command"),
        label="hook_manifest command",
    )
    env = _manifest_env(project_id, entry, manifest)
    prefix = ["env", *(f"{key}={value}" for key, value in sorted(env.items()))]
    argv = [*prefix, str(command), client, action]
    return shlex.join(argv)


def _compiled_matcher(
    project_id: str,
    hook: dict[str, Any],
    *,
    client: str,
    event: str,
) -> str | None:
    tool = hook.get("tool")
    if event != "pre_tool_use":
        if tool is not None:
            raise ValueError(
                f"project {project_id!r}: tool matcher only applies to pre_tool_use"
            )
        if client == "cursor" and event == "prompt_submit":
            return "UserPromptSubmit"
        return None
    if not isinstance(tool, str) or tool not in _TOOL_MATCHERS:
        raise ValueError(
            f"project {project_id!r}: unsupported pre_tool_use tool matcher {tool!r}"
        )
    return _TOOL_MATCHERS[tool][client]


def _compile_hook_manifest(
    project_id: str,
    entry: dict[str, Any],
    manifest: dict[str, Any],
    *,
    client: str,
) -> dict[str, Any]:
    hooks: dict[str, list[dict[str, Any]]] = {}
    for index, raw_hook in enumerate(manifest["hooks"]):
        if not isinstance(raw_hook, dict):
            raise TypeError(
                f"project {project_id!r}: hook_manifest hooks[{index}] must be an object"
            )
        event = raw_hook.get("event")
        action = raw_hook.get("action")
        if not isinstance(event, str) or event not in _HOOK_EVENTS:
            raise ValueError(
                f"project {project_id!r}: unsupported hook event {event!r}"
            )
        mapped = _HOOK_EVENTS[event].get(client)
        if mapped is None:
            raise ValueError(
                f"project {project_id!r}: hook event {event!r} "
                f"is unsupported by {client}"
            )
        if not isinstance(action, str) or not action.strip():
            raise ValueError(
                f"project {project_id!r}: hook_manifest hooks[{index}] action required"
            )
        command = _hook_command(project_id, entry, manifest, client, action)
        matcher = _compiled_matcher(
            project_id,
            raw_hook,
            client=client,
            event=event,
        )
        if client == "cursor":
            compiled: dict[str, Any] = {"command": command}
            if matcher:
                compiled["matcher"] = matcher
            if isinstance(raw_hook.get("timeout"), int):
                compiled["timeout"] = raw_hook["timeout"]
            if isinstance(raw_hook.get("fail_closed"), bool):
                compiled["failClosed"] = raw_hook["fail_closed"]
            hooks.setdefault(mapped, []).append(compiled)
        else:
            if raw_hook.get("fail_closed") is True:
                raise ValueError(
                    f"project {project_id!r}: fail_closed is unsupported by claude"
                )
            nested: dict[str, Any] = {"type": "command", "command": command}
            if isinstance(raw_hook.get("timeout"), int):
                nested["timeout"] = raw_hook["timeout"]
            compiled = {"hooks": [nested]}
            if matcher:
                compiled["matcher"] = matcher
            hooks.setdefault(mapped, []).append(compiled)
    return hooks


def _claude_hooks_mode(
    project_id: str,
    entry: dict[str, Any],
    manifest: dict[str, Any] | None,
) -> str:
    mode = normalize_wiring(entry).get("claude_hooks", "generated")
    if mode not in ("generated", "tracked"):
        raise ValueError(
            f"project {project_id!r}: claude_hooks must be 'generated' or 'tracked'"
        )
    if mode == "tracked" and manifest is None:
        raise ValueError(
            f"project {project_id!r}: claude_hooks='tracked' requires hook_manifest"
        )
    return mode


def _manifest_semantics(manifest: dict[str, Any]) -> Counter[tuple[str, str | None, str]]:
    semantics: Counter[tuple[str, str | None, str]] = Counter()
    for hook in manifest["hooks"]:
        if not isinstance(hook, dict):
            continue
        event = hook.get("event")
        action = hook.get("action")
        tool = hook.get("tool") if event == "pre_tool_use" else None
        if isinstance(event, str) and isinstance(action, str):
            semantics[(event, tool if isinstance(tool, str) else None, action)] += 1
    return semantics


def _tracked_claude_semantics(
    project_id: str,
    data: dict[str, Any],
) -> Counter[tuple[str, str | None, str]]:
    raw_hooks = data.get("hooks")
    if not isinstance(raw_hooks, dict):
        raise ValueError(f"project {project_id!r}: tracked Claude hooks object missing")
    semantics: Counter[tuple[str, str | None, str]] = Counter()
    for claude_event, entries in raw_hooks.items():
        event = _CLAUDE_EVENTS.get(claude_event)
        if event is None:
            raise ValueError(
                f"project {project_id!r}: unsupported tracked Claude event "
                f"{claude_event!r}"
            )
        if not isinstance(entries, list):
            raise TypeError(
                f"project {project_id!r}: tracked Claude event {claude_event!r} "
                "must be a list"
            )
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
                raise TypeError(
                    f"project {project_id!r}: malformed tracked Claude "
                    f"{claude_event!r} entry"
                )
            matcher = entry.get("matcher")
            tool: str | None = None
            if event == "pre_tool_use":
                tool = (
                    _CLAUDE_TOOL_MATCHERS.get(matcher)
                    if isinstance(matcher, str)
                    else None
                )
                if tool is None:
                    raise ValueError(
                        f"project {project_id!r}: unsupported tracked Claude "
                        f"PreToolUse matcher {matcher!r}"
                    )
            elif matcher is not None:
                raise ValueError(
                    f"project {project_id!r}: unexpected matcher on tracked "
                    f"Claude event {claude_event!r}"
                )
            for nested in entry["hooks"]:
                command = nested.get("command") if isinstance(nested, dict) else None
                if not isinstance(command, str):
                    raise TypeError(
                        f"project {project_id!r}: tracked Claude command missing"
                    )
                actions = re.findall(r"\bclaude\s+([a-z][a-z0-9_]*)\b", command)
                if len(set(actions)) != 1:
                    raise ValueError(
                        f"project {project_id!r}: tracked Claude command must "
                        f"name one hook action: {command!r}"
                    )
                semantics[(event, tool, actions[0])] += 1
    return semantics


def _validate_tracked_claude_hooks(
    project_id: str,
    manifest: dict[str, Any],
    path: Path,
) -> None:
    data = _read_json(path)
    if data is None:
        raise ValueError(
            f"project {project_id!r}: tracked Claude settings missing or unreadable: {path}"
        )
    expected = _manifest_semantics(manifest)
    actual = _tracked_claude_semantics(project_id, data)
    if actual != expected:
        raise ValueError(
            f"project {project_id!r}: tracked Claude hooks drift from hook_manifest "
            f"→ {path}"
        )


def render_cursor_hooks(
    entry: dict[str, Any] | None = None,
    *,
    project_id: str = "project",
) -> dict[str, Any]:
    if entry is not None:
        manifest = _load_hook_manifest(project_id, entry)
        if manifest is not None:
            return {
                "version": 1,
                "hooks": _compile_hook_manifest(
                    project_id, entry, manifest, client="cursor"
                ),
            }
    template = json.loads((deploy_dir() / "hooks.json").read_text(encoding="utf-8"))
    return _substitute_placeholders(
        template,
        {"WILLOW_MCP_PYTHON": resolve_willow_mcp_python()},
    )


def runtime_env(agent: str, entry: dict[str, Any]) -> dict[str, str]:
    from .paths import store_root, willow_home

    env: dict[str, str] = {
        "WILLOW_AGENT_NAME": agent,
        "AGENT_NAME": agent,
        "WILLOW_APP_ID": agent,
        "WILLOW_HOME": str(willow_home().resolve()),
        "WILLOW_STORE_ROOT": str(store_root().resolve()),
        "WILLOW_MCP_PYTHON": resolve_willow_mcp_python(),
    }
    raw_overrides = entry.get("env")
    overrides: dict[str, Any] = raw_overrides if isinstance(raw_overrides, dict) else {}
    for key, val in overrides.items():
        if isinstance(val, str):
            # Names the legacy fleet SOIL path in order to DROP the override, never to use it.
            if key == "WILLOW_STORE_ROOT" and "github/willow/.willow/store" in expand_home(val):  # path-guard: allow
                continue
            env[key] = expand_home(val)
    return env


def render_project_claude_settings(
    entry: dict[str, Any],
    *,
    project_id: str = "project",
) -> dict[str, Any]:
    agent = str(entry.get("agent") or "willow").strip()
    servers = [s for s in (entry.get("servers") or []) if isinstance(s, str)]
    template = json.loads((deploy_dir() / "claude-settings.json").read_text(encoding="utf-8"))
    payload = render_claude_permissions(servers)
    manifest = _load_hook_manifest(project_id, entry)
    mode = _claude_hooks_mode(project_id, entry, manifest)
    if mode == "generated":
        payload["hooks"] = (
            _compile_hook_manifest(project_id, entry, manifest, client="claude")
            if manifest is not None
            else template.get("hooks", {})
        )
    payload["env"] = runtime_env(agent, entry)
    return _substitute_placeholders(
        payload,
        {"WILLOW_MCP_PYTHON": resolve_willow_mcp_python()},
    )


def wiring_paths(project_id: str, entry: dict[str, Any]) -> dict[str, Path]:
    root = _project_root(project_id, entry)
    return {
        "root": root,
        "active_agent": root / ".willow" / "active-agent",
        "cursor_hooks": root / ".cursor" / "hooks.json",
        "claude_settings": root / ".claude" / "settings.local.json",
        "claude_tracked_settings": root / ".claude" / "settings.json",
    }


def write_active_agent(project_root: Path, agent: str) -> None:
    path = project_root / ".willow" / "active-agent"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(agent.strip() + "\n", encoding="utf-8")
    tmp.replace(path)


def _write_json(path: Path, data: dict, *, dry_run: bool) -> None:
    if dry_run:
        print(f"[project_wiring] Would write {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)
    print(f"[project_wiring] Wrote {path}")


def _normalize_json(data: dict) -> str:
    return json.dumps(data, sort_keys=True, indent=2) + "\n"


def _read_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def audit_project_wiring(
    project_id: str,
    entry: dict[str, Any],
) -> list[str]:
    wiring = normalize_wiring(entry)
    if not any(wiring.values()):
        return []

    issues: list[str] = []
    paths = wiring_paths(project_id, entry)
    ides = entry.get("ides") or []
    agent = str(entry.get("agent") or "willow").strip()

    if not paths["root"].is_dir():
        issues.append(f"{project_id}: path does not exist → {paths['root']}")
        return issues

    tracked_claude_manifest: dict[str, Any] | None = None
    try:
        expected_cursor = (
            render_cursor_hooks(entry, project_id=project_id)
            if wiring.get("hooks") and "cursor" in ides
            else None
        )
        expected_claude = (
            render_project_claude_settings(entry, project_id=project_id)
            if wiring.get("claude_settings") == "project" and "claude" in ides
            else None
        )
        if wiring.get("claude_settings") == "project" and "claude" in ides:
            manifest = _load_hook_manifest(project_id, entry)
            if _claude_hooks_mode(project_id, entry, manifest) == "tracked":
                assert manifest is not None
                tracked_claude_manifest = manifest
    except (TypeError, ValueError) as exc:
        issues.append(f"{project_id}: hook wiring invalid: {exc}")
        return issues

    if wiring.get("active_agent"):
        if not paths["active_agent"].is_file():
            issues.append(f"{project_id}: missing active-agent → {paths['active_agent']}")
        else:
            active_on_disk = paths["active_agent"].read_text(encoding="utf-8").strip()
            if active_on_disk != agent:
                issues.append(
                    f"{project_id}: active-agent drift "
                    f"(want {agent!r}, got {active_on_disk!r})"
                )

    if wiring.get("hooks") and "cursor" in ides:
        assert expected_cursor is not None
        cursor_on_disk = _read_json(paths["cursor_hooks"])
        if cursor_on_disk is None:
            issues.append(f"{project_id}: missing cursor hooks → {paths['cursor_hooks']}")
        elif _normalize_json(cursor_on_disk) != _normalize_json(expected_cursor):
            issues.append(f"{project_id}: cursor hooks drift → {paths['cursor_hooks']}")

    if wiring.get("claude_settings") == "project" and "claude" in ides:
        assert expected_claude is not None
        claude_on_disk = _read_json(paths["claude_settings"])
        if claude_on_disk is None:
            issues.append(f"{project_id}: missing claude settings → {paths['claude_settings']}")
        else:
            for key in ("env", "permissions", "enableAllProjectMcpServers", "enabledMcpjsonServers", "hooks"):
                if claude_on_disk.get(key) != expected_claude.get(key):
                    issues.append(
                        f"{project_id}: claude settings drift ({key}) → {paths['claude_settings']}"
                    )
                    break

    if tracked_claude_manifest is not None:
        try:
            _validate_tracked_claude_hooks(
                project_id,
                tracked_claude_manifest,
                paths["claude_tracked_settings"],
            )
        except (TypeError, ValueError) as exc:
            issues.append(f"{project_id}: hook wiring invalid: {exc}")

    return issues


def sync_project_wiring(
    project_id: str,
    entry: dict[str, Any],
    *,
    dry_run: bool = False,
) -> None:
    wiring = normalize_wiring(entry)
    if not any(wiring.values()):
        return

    paths = wiring_paths(project_id, entry)
    ides = entry.get("ides") or []
    agent = str(entry.get("agent") or "willow").strip()

    # Compile every selected client before touching disk. A bad or unsupported
    # project manifest must not leave one IDE on the new policy and the other
    # on the old one.
    cursor_hooks = (
        render_cursor_hooks(entry, project_id=project_id)
        if wiring.get("hooks") and "cursor" in ides
        else None
    )
    claude_settings = (
        render_project_claude_settings(entry, project_id=project_id)
        if wiring.get("claude_settings") == "project" and "claude" in ides
        else None
    )

    paths["root"].mkdir(parents=True, exist_ok=True)

    if wiring.get("active_agent"):
        if dry_run:
            print(f"[project_wiring] Would write {paths['active_agent']} → {agent}")
        else:
            write_active_agent(paths["root"], agent)
            print(f"[project_wiring] Wrote {paths['active_agent']}")

    if wiring.get("hooks") and "cursor" in ides:
        assert cursor_hooks is not None
        _write_json(paths["cursor_hooks"], cursor_hooks, dry_run=dry_run)

    if wiring.get("claude_settings") == "project" and "claude" in ides:
        assert claude_settings is not None
        _write_json(
            paths["claude_settings"],
            claude_settings,
            dry_run=dry_run,
        )
