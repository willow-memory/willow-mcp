import json
from pathlib import Path

import pytest

from willow_mcp.mcp_projects import (
    audit_all,
    audit_project,
    ensure_registry,
    load_registry,
    render_project_mcp,
    sync_project,
)
from willow_mcp.project_wiring import (
    expand_home,
    render_claude_permissions,
    resolve_willow_mcp_python,
)


def test_expand_home():
    home = str(Path.home())
    assert expand_home("{{HOME}}/github/foo") == f"{home}/github/foo"


def test_render_project_mcp_willow_mcp_charter(tmp_path, monkeypatch):
    wh = tmp_path / ".willow"
    monkeypatch.setenv("WILLOW_HOME", str(wh))
    monkeypatch.delenv("WILLOW_STORE_ROOT", raising=False)

    entry = {
        "path": str(tmp_path / "willow-charter"),
        "agent": "willow",
        "servers": ["willow-mcp", "codebase-memory-mcp"],
        "env": {
            "WILLOW_PROJECT_ROOT": str(tmp_path / "willow-charter"),
        },
    }
    payload = render_project_mcp("willow", entry)
    names = list(payload["mcpServers"])
    assert names[0] == "willow-mcp"
    wm = payload["mcpServers"]["willow-mcp"]
    assert wm["args"] == ["-m", "willow_mcp"]
    assert wm["env"]["WILLOW_APP_ID"] == "willow"
    assert wm["env"]["WILLOW_HUMAN_ORCHESTRATOR"] == "1"
    assert wm["env"]["WILLOW_STORE_ROOT"] == str((wh / "store").resolve())


def test_render_claude_permissions_willow_mcp():
    perms = render_claude_permissions(["willow-mcp", "codebase-memory-mcp"])
    assert "mcp__willow-mcp__*" in perms["permissions"]["allow"]
    assert "mcp__willow__app_uninstall" not in perms["permissions"]["deny"]


def test_sync_and_audit_roundtrip(tmp_path, monkeypatch):
    wh = tmp_path / ".willow"
    monkeypatch.setenv("WILLOW_HOME", str(wh))

    proj = tmp_path / "dispatches"
    proj.mkdir()
    (proj / ".cursor").mkdir(parents=True, exist_ok=True)

    registry = {
        "version": 1,
        "projects": {
            "test-proj": {
                "path": str(proj),
                "agent": "willow",
                "servers": ["willow-mcp"],
                "ides": ["cursor", "claude"],
                "wiring": {
                    "hooks": True,
                    "active_agent": True,
                    "claude_settings": "project",
                },
            }
        },
    }
    reg_path = wh / "mcp" / "projects.json"
    reg_path.parent.mkdir(parents=True)
    reg_path.write_text(json.dumps(registry), encoding="utf-8")

    entry = registry["projects"]["test-proj"]
    sync_project("test-proj", entry, dry_run=False)
    assert (wh / "mcp" / "test-proj.mcp.json").is_file()
    assert (proj / ".cursor" / "mcp.json").is_file()
    assert (proj / ".mcp.json").is_file()
    assert (proj / ".claude" / "settings.local.json").is_file()
    assert (proj / ".cursor" / "hooks.json").is_file()
    assert (proj / ".willow" / "active-agent").read_text().strip() == "willow"

    issues = audit_project("test-proj", entry)
    assert issues == [], f"expected no drift, got {issues}"


def test_render_project_mcp_with_env_overrides(tmp_path, monkeypatch):
    wh = tmp_path / ".willow"
    monkeypatch.setenv("WILLOW_HOME", str(wh))

    custom_store = tmp_path / "store" / ".willow" / "store"
    entry = {
        "path": str(tmp_path / "store"),
        "agent": "hanuman",
        "servers": ["willow-mcp"],
        "env": {"WILLOW_STORE_ROOT": str(custom_store)},
    }
    payload = render_project_mcp("hanuman-seat", entry)
    assert payload["mcpServers"]["willow-mcp"]["env"]["WILLOW_APP_ID"] == "hanuman"
    assert payload["mcpServers"]["willow-mcp"]["env"]["WILLOW_STORE_ROOT"] == str(
        custom_store.resolve()
    )


def test_nestor_project_can_override_only_its_static_server_args(tmp_path):
    draft_args = [
        "serve",
        "--engine",
        "ollama",
        "--ollama-model",
        "willow-lane4-3b:latest",
    ]
    nestor_entry = {
        "path": str(tmp_path / "nestor"),
        "agent": "nestor",
        "servers": ["nestor"],
        "server_args": {"nestor": draft_args},
    }
    other_entry = {
        "path": str(tmp_path / "other"),
        "agent": "willow",
        "servers": ["nestor"],
    }

    nestor = render_project_mcp("nestor", nestor_entry)
    other = render_project_mcp("other", other_entry)

    assert nestor["mcpServers"]["nestor"]["args"] == draft_args
    assert other["mcpServers"]["nestor"]["args"] == ["serve", "--read-only"]


@pytest.mark.parametrize(
    ("server_args", "message"),
    [
        ({"nestor": "serve"}, "non-empty list"),
        ({"nestor": ["serve", ""]}, "non-empty list"),
        ({"nestor": []}, "non-empty list"),
        ({"unknown": ["serve"]}, "only supports static servers"),
        ({"nestor": ["serve"]}, "unselected server"),
    ],
)
def test_server_args_refuses_invalid_or_dead_overrides(tmp_path, server_args, message):
    entry = {
        "path": str(tmp_path / "project"),
        "agent": "willow",
        "servers": ["codebase-memory-mcp"],
        "server_args": server_args,
    }

    with pytest.raises((TypeError, ValueError), match=message):
        render_project_mcp("project", entry)


def test_render_project_mcp_ignores_charter_local_store(tmp_path, monkeypatch):
    wh = tmp_path / ".willow"
    monkeypatch.setenv("WILLOW_HOME", str(wh))
    monkeypatch.delenv("WILLOW_STORE_ROOT", raising=False)

    entry = {
        "path": str(tmp_path / "willow-charter"),
        "agent": "willow",
        "servers": ["willow-mcp"],
        "env": {
            "WILLOW_STORE_ROOT": str(tmp_path / "willow-charter" / ".willow" / "store"),
        },
    }
    payload = render_project_mcp("willow", entry)
    assert payload["mcpServers"]["willow-mcp"]["env"]["WILLOW_STORE_ROOT"] == str(
        (wh / "store").resolve()
    )


def test_local_willow_entry_survives_load(tmp_path, monkeypatch):
    """A local 'willow' entry is the operator's, not the seed's.

    The seed ships with every willow-mcp install and names one charter-repo
    layout. It used to be overlaid onto any registry with a 'willow' key and
    persisted, so an operator whose charter repo lived elsewhere had their
    path silently rewritten on every load. The registry wins now.
    """
    wh = tmp_path / ".willow"
    monkeypatch.setenv("WILLOW_HOME", str(wh))
    reg_path = wh / "mcp" / "projects.json"
    reg_path.parent.mkdir(parents=True)
    reg_path.write_text(
        json.dumps(
            {
                "version": 1,
                "projects": {
                    "willow": {
                        "path": "{{HOME}}/somewhere/else/willow",
                        "agent": "willow",
                        "servers": ["willow-mcp"],
                        "env": {
                            "WILLOW_STORE_ROOT": "{{HOME}}/somewhere/else/willow/.willow/store"
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    data = load_registry(bootstrap=False)
    assert data["projects"]["willow"]["path"] == "{{HOME}}/somewhere/else/willow"


def test_local_github_entry_survives_load(tmp_path, monkeypatch):
    """Same guarantee for 'github', which outlived the first fix.

    'github' was left in the overlay because its seed path ({{HOME}}/github)
    carries no layout assumption — but the overlay replaces the whole entry,
    not just the path, so an operator's profile, env block and wiring keys
    were still being dropped on every load.
    """
    wh = tmp_path / ".willow"
    monkeypatch.setenv("WILLOW_HOME", str(wh))
    reg_path = wh / "mcp" / "projects.json"
    reg_path.parent.mkdir(parents=True)
    rich = {
        "path": "{{HOME}}/github",
        "agent": "willow",
        "profile": "core",
        "servers": ["willow-mcp"],
        "env": {"WILLOW_HANDOFF_PROJECT": "github"},
        "wiring": {"hooks": False, "active_agent": True, "python": False},
        "note": "operator's own note",
    }
    reg_path.write_text(
        json.dumps({"version": 1, "projects": {"github": rich}}), encoding="utf-8"
    )
    data = load_registry(bootstrap=False)
    assert data["projects"]["github"] == rich


def test_load_registry_does_not_rewrite_the_file(tmp_path, monkeypatch):
    """Loading is a read. It used to persist the overlay's edits as a side effect."""
    wh = tmp_path / ".willow"
    monkeypatch.setenv("WILLOW_HOME", str(wh))
    reg_path = wh / "mcp" / "projects.json"
    reg_path.parent.mkdir(parents=True)
    payload = json.dumps(
        {"version": 1, "projects": {"github": {"path": "{{HOME}}/github", "agent": "willow"}}}
    )
    reg_path.write_text(payload, encoding="utf-8")

    load_registry(bootstrap=False)
    assert reg_path.read_text(encoding="utf-8") == payload


def test_project_local_store_root_is_still_stripped_at_render(tmp_path, monkeypatch):
    """Dropping the seed overlay must not lose the store-root guard.

    Charter SOIL belongs in the fleet home, not in the project tree. That was
    a side effect of the overlay; _skip_store_override() enforces it directly,
    so it has to hold for a registry path the seed has never seen.
    """
    wh = tmp_path / ".willow"
    monkeypatch.setenv("WILLOW_HOME", str(wh))
    monkeypatch.delenv("WILLOW_STORE_ROOT", raising=False)

    entry = {
        "path": "{{HOME}}/somewhere/else/willow",
        "agent": "willow",
        "servers": ["willow-mcp"],
        "env": {"WILLOW_STORE_ROOT": "{{HOME}}/somewhere/else/willow/.willow/store"},
    }
    payload = render_project_mcp("willow", entry)
    assert payload["mcpServers"]["willow-mcp"]["env"]["WILLOW_STORE_ROOT"] == str(
        (wh / "store").resolve()
    )


def test_ensure_registry_from_seed(tmp_path, monkeypatch):
    wh = tmp_path / ".willow"
    monkeypatch.setenv("WILLOW_HOME", str(wh))

    path = ensure_registry(dry_run=False)
    assert path.is_file()
    data = load_registry(bootstrap=False)
    assert "willow" in data["projects"]
    assert "github" in data["projects"]


def test_audit_all_skips_symlink_alias_roots(tmp_path, monkeypatch):
    wh = tmp_path / ".willow"
    monkeypatch.setenv("WILLOW_HOME", str(wh))

    canonical = tmp_path / "store-public"
    canonical.mkdir()
    alias = tmp_path / "store-alias"
    alias.symlink_to(canonical, target_is_directory=True)
    (canonical / ".cursor").mkdir(parents=True, exist_ok=True)

    registry = {
        "version": 1,
        "projects": {
            "store-public": {
                "path": str(canonical),
                "agent": "willow",
                "servers": ["willow-mcp"],
                "ides": ["cursor", "claude"],
                "wiring": {"hooks": True, "active_agent": False, "claude_settings": "project"},
            },
            "store-alias": {
                "path": str(alias),
                "agent": "willow",
                "servers": ["willow-mcp"],
                "ides": ["cursor", "claude"],
                "wiring": {"hooks": True, "active_agent": False, "claude_settings": "project"},
            },
        },
    }
    reg_path = wh / "mcp" / "projects.json"
    reg_path.parent.mkdir(parents=True, exist_ok=True)
    reg_path.write_text(json.dumps(registry), encoding="utf-8")

    for pid in ("store-public", "store-alias"):
        sync_project(pid, registry["projects"][pid], dry_run=False)

    issues = audit_all()
    assert issues == []


def test_resolve_willow_mcp_python_keeps_the_venv_symlink(tmp_path, monkeypatch):
    """A venv is the path you invoke, not the binary behind it.

    bin/python is a symlink chain ending at the system interpreter. Resolving
    it hands back a base Python with no willow_mcp installed, and the .mcp.json
    that gets written names a server that cannot start — with nothing reporting
    it. This had no coverage, which is how it survived.
    """
    wh = tmp_path / ".willow"
    monkeypatch.setenv("WILLOW_HOME", str(wh))
    monkeypatch.delenv("WILLOW_MCP_PYTHON", raising=False)

    real = tmp_path / "usr" / "bin" / "python3.12"
    real.parent.mkdir(parents=True)
    real.write_text("#!/bin/sh\n", encoding="utf-8")

    venv_bin = wh / "venvs" / "willow-mcp" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python3").symlink_to(real)
    (venv_bin / "python").symlink_to("python3")

    resolved = resolve_willow_mcp_python()
    assert resolved == str(venv_bin / "python")
    assert resolved != str(real)


def test_resolve_willow_mcp_python_follows_willow_home(tmp_path, monkeypatch):
    """The venv candidate tracks $WILLOW_HOME instead of a hardcoded path.

    A hardcoded ~/github/.willow/venvs/... silently lost to `which python3`
    once $WILLOW_HOME moved, producing a system interpreter.
    """
    wh = tmp_path / "relocated" / ".willow"
    monkeypatch.setenv("WILLOW_HOME", str(wh))
    monkeypatch.delenv("WILLOW_MCP_PYTHON", raising=False)

    venv_bin = wh / "venvs" / "willow-mcp" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python").write_text("#!/bin/sh\n", encoding="utf-8")

    assert resolve_willow_mcp_python() == str(venv_bin / "python")
