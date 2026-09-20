"""Seat identity for hooks — .mcp.json wins; env mismatch refuses."""
from __future__ import annotations

import json
from pathlib import Path

from willow_mcp import seat_identity as si


def _write_mcp(tmp_path: Path, app_id: str) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "willow-mcp": {
                        "command": "willow-mcp",
                        "env": {"WILLOW_APP_ID": app_id},
                    }
                }
            }
        )
    )
    return root


def test_app_id_from_mcp_json_reads_server_env(tmp_path):
    root = _write_mcp(tmp_path, "heimdallr")
    assert si.app_id_from_mcp_json(str(root)) == "heimdallr"


def test_resolve_prefers_mcp_json_when_env_unset(tmp_path, monkeypatch):
    root = _write_mcp(tmp_path, "heimdallr")
    monkeypatch.delenv("WILLOW_APP_ID", raising=False)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(root))
    app_id, err = si.resolve_hook_app_id()
    assert err is None
    assert app_id == "heimdallr"


def test_resolve_refuses_env_mcp_mismatch(tmp_path, monkeypatch):
    root = _write_mcp(tmp_path, "heimdallr")
    monkeypatch.setenv("WILLOW_APP_ID", "willow")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(root))
    app_id, err = si.resolve_hook_app_id()
    assert app_id is None
    assert err is not None
    assert "disagrees" in err
    assert "heimdallr" in err
    assert "willow" in err


def test_resolve_ok_when_env_matches_mcp(tmp_path, monkeypatch):
    root = _write_mcp(tmp_path, "willow")
    monkeypatch.setenv("WILLOW_APP_ID", "willow")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(root))
    app_id, err = si.resolve_hook_app_id()
    assert err is None
    assert app_id == "willow"


def test_resolve_refuses_when_both_unset(monkeypatch):
    monkeypatch.delenv("WILLOW_APP_ID", raising=False)
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    monkeypatch.delenv("CURSOR_PROJECT_DIR", raising=False)
    monkeypatch.delenv("WILLOW_PROJECT_ROOT", raising=False)
    app_id, err = si.resolve_hook_app_id()
    assert app_id is None
    assert err is not None
    assert "WILLOW_APP_ID is not set" in err
