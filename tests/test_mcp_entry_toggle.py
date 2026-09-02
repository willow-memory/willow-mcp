"""Tests for scripts/mcp_entry_toggle.py — the .mcp.json serve-entry toggle that
`scripts/willow-serve` uses to keep the client entry in sync with the service.
"""
import importlib.util
import json
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).resolve().parent.parent / "scripts" / "mcp_entry_toggle.py"
_spec = importlib.util.spec_from_file_location("mcp_entry_toggle", _MODULE_PATH)
mcp_entry_toggle = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mcp_entry_toggle)

NAME = "willow-mcp-serve"
URL = "http://127.0.0.1:8765/mcp"


@pytest.fixture
def mcp_json(tmp_path):
    p = tmp_path / ".mcp.json"
    p.write_text(json.dumps({"mcpServers": {
        "willow-mcp": {"type": "stdio", "command": ".venv/bin/python3", "args": ["-m", "willow_mcp"]},
        "codebase-memory-mcp": {"type": "stdio", "command": "codebase-memory-mcp", "args": []},
    }}, indent=2) + "\n")
    return p


def _servers(p):
    return json.loads(p.read_text())["mcpServers"]


def test_add_inserts_http_entry(mcp_json):
    mcp_entry_toggle.toggle(str(mcp_json), NAME, URL, "add")
    servers = _servers(mcp_json)
    assert servers[NAME] == {"type": "http", "url": URL}


def test_add_preserves_existing_servers(mcp_json):
    mcp_entry_toggle.toggle(str(mcp_json), NAME, URL, "add")
    servers = _servers(mcp_json)
    assert "willow-mcp" in servers and "codebase-memory-mcp" in servers


def test_add_is_idempotent(mcp_json):
    mcp_entry_toggle.toggle(str(mcp_json), NAME, URL, "add")
    mcp_entry_toggle.toggle(str(mcp_json), NAME, URL, "add")
    assert list(_servers(mcp_json)).count(NAME) == 1


def test_remove_deletes_only_the_entry(mcp_json):
    mcp_entry_toggle.toggle(str(mcp_json), NAME, URL, "add")
    mcp_entry_toggle.toggle(str(mcp_json), NAME, URL, "remove")
    assert set(_servers(mcp_json)) == {"willow-mcp", "codebase-memory-mcp"}


def test_remove_is_idempotent(mcp_json):
    mcp_entry_toggle.toggle(str(mcp_json), NAME, URL, "remove")  # not present
    assert set(_servers(mcp_json)) == {"willow-mcp", "codebase-memory-mcp"}


def test_add_then_remove_round_trips(mcp_json):
    before = mcp_json.read_text()
    mcp_entry_toggle.toggle(str(mcp_json), NAME, URL, "add")
    mcp_entry_toggle.toggle(str(mcp_json), NAME, URL, "remove")
    assert json.loads(mcp_json.read_text()) == json.loads(before)


def test_unknown_action_raises(mcp_json):
    with pytest.raises(ValueError):
        mcp_entry_toggle.toggle(str(mcp_json), NAME, URL, "frobnicate")
