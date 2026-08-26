import json
import shlex
import shutil
from pathlib import Path

import pytest

from willow_mcp.mcp_projects import audit_project, sync_project
from willow_mcp.project_wiring import (
    audit_project_wiring,
    render_cursor_hooks,
    render_project_claude_settings,
    sync_project_wiring,
)

TEMPLATE = Path(__file__).parent / "templates" / "nestor-hook-manifest.json"


def _project(tmp_path: Path) -> tuple[Path, dict]:
    root = tmp_path / "nestor"
    hooks = root / "hooks"
    hooks.mkdir(parents=True)
    wrapper = hooks / "nestor-hook"
    wrapper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    wrapper.chmod(0o755)
    shutil.copyfile(TEMPLATE, hooks / "client-hooks.json")
    entry = {
        "path": str(root),
        "agent": "nestor",
        "servers": ["willow-mcp", "nestor"],
        "ides": ["cursor", "claude"],
        "wiring": {
            "hooks": True,
            "active_agent": True,
            "claude_settings": "project",
            "hook_manifest": "hooks/client-hooks.json",
        },
    }
    return root, entry


def _commands(config: dict, client: str) -> list[str]:
    commands: list[str] = []
    for entries in config["hooks"].values():
        for entry in entries:
            if client == "cursor":
                commands.append(entry["command"])
            else:
                commands.extend(hook["command"] for hook in entry["hooks"])
    return commands


def _write_tracked_claude_hooks(root: Path, entry: dict) -> Path:
    generated = render_project_claude_settings(entry, project_id="nestor")
    hooks = generated["hooks"]
    for entries in hooks.values():
        for hook_entry in entries:
            for nested in hook_entry["hooks"]:
                action = shlex.split(nested["command"])[-1]
                nested["command"] = f"./hooks/nestor-hook claude {action}"
    path = root / ".claude" / "settings.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"hooks": hooks}, indent=2) + "\n", encoding="utf-8")
    return path


def test_nestor_manifest_compiles_coherent_client_local_hooks(tmp_path):
    root, entry = _project(tmp_path)

    sync_project_wiring("nestor", entry)

    cursor = json.loads((root / ".cursor" / "hooks.json").read_text())
    claude = json.loads((root / ".claude" / "settings.local.json").read_text())

    assert set(cursor["hooks"]) == {
        "sessionStart",
        "beforeSubmitPrompt",
        "preCompact",
        "preToolUse",
        "stop",
        "sessionEnd",
    }
    assert {
        hook["matcher"] for hook in cursor["hooks"]["preToolUse"]
    } == {"MCP:.*", "Write", "Shell"}
    assert {
        hook["matcher"] for hook in claude["hooks"]["PreToolUse"]
    } == {"mcp__", "Write|Edit|MultiEdit|NotebookEdit", "Bash"}
    assert len(cursor["hooks"]["beforeSubmitPrompt"]) == 3
    assert len(claude["hooks"]["UserPromptSubmit"]) == 3

    for client, config in (("cursor", cursor), ("claude", claude)):
        commands = _commands(config, client)
        assert commands
        assert all("willow_mcp." not in command for command in commands)
        for command in commands:
            argv = shlex.split(command)
            assert "WILLOW_APP_ID=nestor" in argv
            assert "WILLOW_AGENT_NAME=nestor" in argv
            assert "AGENT_NAME=nestor" in argv
            assert f"NESTOR_PROJECT_ROOT={root}" in argv
            assert argv[-2] == client

    assert audit_project_wiring("nestor", entry) == []


def test_tracked_claude_hook_ownership_keeps_one_local_semantic_stack(tmp_path):
    root, entry = _project(tmp_path)
    tracked_path = _write_tracked_claude_hooks(root, entry)
    tracked_before = tracked_path.read_text(encoding="utf-8")
    entry["wiring"]["claude_hooks"] = "tracked"
    (root / ".claude" / "settings.local.json").write_text(
        json.dumps({"hooks": {"SessionStart": []}}),
        encoding="utf-8",
    )

    sync_project_wiring("nestor", entry)

    local = json.loads(
        (root / ".claude" / "settings.local.json").read_text(encoding="utf-8")
    )
    assert "hooks" not in local
    assert tracked_path.read_text(encoding="utf-8") == tracked_before
    assert audit_project_wiring("nestor", entry) == []


def test_tracked_claude_hook_drift_from_manifest_is_reported(tmp_path):
    root, entry = _project(tmp_path)
    tracked_path = _write_tracked_claude_hooks(root, entry)
    entry["wiring"]["claude_hooks"] = "tracked"
    sync_project_wiring("nestor", entry)
    tracked = json.loads(tracked_path.read_text(encoding="utf-8"))
    tracked["hooks"].pop("SessionEnd")
    tracked_path.write_text(json.dumps(tracked), encoding="utf-8")

    issues = audit_project_wiring("nestor", entry)

    assert any(
        "tracked Claude hooks drift from hook_manifest" in issue for issue in issues
    )


def test_custom_hook_audit_reports_client_drift(tmp_path):
    root, entry = _project(tmp_path)
    sync_project_wiring("nestor", entry)
    cursor_path = root / ".cursor" / "hooks.json"
    cursor = json.loads(cursor_path.read_text())
    cursor["hooks"]["preToolUse"].pop()
    cursor_path.write_text(json.dumps(cursor), encoding="utf-8")

    issues = audit_project("nestor", entry)

    assert any("cursor hooks drift" in issue for issue in issues)


def test_hook_manifest_refuses_path_outside_project_before_writing(tmp_path):
    root, entry = _project(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text(TEMPLATE.read_text(), encoding="utf-8")
    (root / "hooks" / "outside.json").symlink_to(outside)
    entry["wiring"]["hook_manifest"] = "hooks/outside.json"

    with pytest.raises(ValueError, match="escapes project root"):
        sync_project_wiring("nestor", entry)

    assert not (root / ".cursor").exists()
    assert not (root / ".claude").exists()
    assert not (root / ".willow").exists()


def test_unsupported_client_event_is_reported_and_generation_is_atomic(
    tmp_path, monkeypatch
):
    home = tmp_path / ".willow"
    monkeypatch.setenv("WILLOW_HOME", str(home))
    root, entry = _project(tmp_path)
    manifest_path = root / "hooks" / "client-hooks.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["hooks"].append({"event": "notification", "action": "reinject"})
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    issues = audit_project("nestor", entry)
    assert any(
        "hook event 'notification' is unsupported by cursor" in issue
        for issue in issues
    )

    with pytest.raises(ValueError, match="unsupported by cursor"):
        sync_project("nestor", entry)

    assert not (home / "mcp" / "nestor.mcp.json").exists()
    assert not (root / ".cursor").exists()
    assert not (root / ".claude").exists()
    assert not (root / ".mcp.json").exists()


def test_projects_without_manifest_keep_fleet_owned_templates(tmp_path):
    entry = {
        "path": str(tmp_path),
        "agent": "willow",
        "servers": ["willow-mcp"],
        "ides": ["cursor", "claude"],
        "wiring": {
            "hooks": True,
            "active_agent": False,
            "claude_settings": "project",
        },
    }

    cursor = render_cursor_hooks(entry, project_id="willow")
    claude = render_project_claude_settings(entry, project_id="willow")

    assert "willow_mcp.session_start_hook" in _commands(cursor, "cursor")[0]
    assert any(
        "willow_mcp.pre_tool_hook" in command
        for command in _commands(claude, "claude")
    )


def test_tracked_claude_hooks_are_validated_but_not_duplicated_locally(tmp_path):
    root, entry = _project(tmp_path)
    generated = render_project_claude_settings(entry, project_id="nestor")
    tracked = root / ".claude" / "settings.json"
    tracked.parent.mkdir(parents=True)
    tracked.write_text(json.dumps({"hooks": generated["hooks"]}), encoding="utf-8")
    entry["wiring"]["claude_hooks"] = "tracked"

    sync_project_wiring("nestor", entry)

    local = json.loads((root / ".claude" / "settings.local.json").read_text())
    assert "hooks" not in local
    assert audit_project_wiring("nestor", entry) == []


def test_tracked_claude_hook_drift_is_reported(tmp_path):
    root, entry = _project(tmp_path)
    generated = render_project_claude_settings(entry, project_id="nestor")
    generated["hooks"]["PreToolUse"].pop()
    tracked = root / ".claude" / "settings.json"
    tracked.parent.mkdir(parents=True)
    tracked.write_text(json.dumps({"hooks": generated["hooks"]}), encoding="utf-8")
    entry["wiring"]["claude_hooks"] = "tracked"

    issues = audit_project_wiring("nestor", entry)

    assert any("tracked Claude hooks drift from hook_manifest" in issue
               for issue in issues)
