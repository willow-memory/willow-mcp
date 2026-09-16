"""bot_status (gap 158600e03598) — the desk reads the steward without a
shell. `read_status` never runs a real subprocess here; a fake `runner`
stands in for `subprocess.run`, and `test_bot_status_gate_and_visibility`
exercises the MCP tool through the gate the way a caller actually reaches it.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from willow_mcp import bot_status as bs
from willow_mcp import server
from willow_mcp.db import Store
from willow_mcp.receipts import ReceiptLog


def _fn(tool):
    return getattr(tool, "fn", tool)


@pytest.fixture
def mk_app(tmp_path, monkeypatch):
    apps = tmp_path / "apps"
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps))
    monkeypatch.setattr(server, "_store", Store(str(tmp_path / "store")))
    monkeypatch.setattr(server, "_receipt_log", ReceiptLog(str(tmp_path / "r.db")))
    monkeypatch.setattr(server, "_buckets", {})

    def _mk(app_id, perms):
        d = apps / app_id
        d.mkdir(parents=True, exist_ok=True)
        (d / "manifest.json").write_text(json.dumps({"permissions": perms}))
        return app_id

    return _mk


def _cp(argv, stdout="", stderr="", rc=0):
    return subprocess.CompletedProcess(argv, rc, stdout, stderr)


_POPULATED_REPORT = {
    "at": "2026-09-16T22:00:00+00:00",
    "willow_home": "/home/op/.willow",
    "version": {"status": "populated", "version": "0.4.0"},
    "running_commit": {"status": "populated", "sha": "abc123"},
    "heartbeat": {"status": "populated", "last": {"at": "2026-09-16T21:59:00+00:00"}},
    "tick": {"status": "populated", "last": {"at": "2026-09-16T21:59:00+00:00"}},
    "journal": {"status": "populated", "count": 3, "lines": [{"event": "tick"}]},
    "inbox": {"status": "empty", "total": 0, "depth_by_kind": {}},
    "cursors": {"status": "empty", "mirror_offset": None, "ci_offset": None, "chain_tip": None},
    "sync": {"status": "populated", "last_success": {"event": "steward_sweep"}},
}

_EMPTY_REPORT = {
    "at": "2026-09-16T22:00:00+00:00",
    "willow_home": "/home/op/.willow",
    "version": {"status": "unreachable", "detail": "importlib.metadata: not installed"},
    "running_commit": {"status": "unreachable", "detail": "no .git", "sha": None},
    "heartbeat": {"status": "empty", "detail": "no file", "last": None, "at": None},
    "tick": {"status": "empty", "detail": "no file", "last": None, "at": None},
    "journal": {"status": "empty", "count": 0, "lines": []},
    "inbox": {"status": "empty", "total": 0, "depth_by_kind": {}},
    "cursors": {"status": "empty", "mirror_offset": None, "ci_offset": None, "chain_tip": None},
    "sync": {"status": "empty", "last_success": None, "at": None},
}


def test_populated_report_yields_populated_state():
    runner = lambda argv, **kw: _cp(argv, stdout=json.dumps(_POPULATED_REPORT))  # noqa: E731
    out = bs.read_status(binary="/bin/willow-bot-steward", runner=runner)
    assert out["state"] == "populated"
    assert out["report"] == _POPULATED_REPORT
    assert "reason" not in out


def test_empty_report_yields_empty_state_with_reason():
    """Every field in the bot's own report says empty/unreachable, never
    populated — a fresh install with a binary that runs cleanly. This must
    stay distinct from an `unreachable` top-level state: the process ran and
    answered; it just has nothing yet."""
    runner = lambda argv, **kw: _cp(argv, stdout=json.dumps(_EMPTY_REPORT))  # noqa: E731
    out = bs.read_status(binary="/bin/willow-bot-steward", runner=runner)
    assert out["state"] == "empty"
    assert out["report"] == _EMPTY_REPORT
    assert out["reason"]


def test_unreachable_missing_binary():
    def runner(argv, **kw):
        raise FileNotFoundError(argv[0])

    out = bs.read_status(binary="/no/such/willow-bot-steward", runner=runner)
    assert out["state"] == "unreachable"
    assert out["reason"] == "binary_missing"


def test_unreachable_nonzero_exit():
    runner = lambda argv, **kw: _cp(argv, stderr="traceback: boom", rc=1)  # noqa: E731
    out = bs.read_status(binary="/bin/willow-bot-steward", runner=runner)
    assert out["state"] == "unreachable"
    assert out["reason"] == "nonzero_exit"
    assert out["returncode"] == 1
    assert "boom" in out["detail"]


def test_unreachable_timeout():
    def runner(argv, **kw):
        raise subprocess.TimeoutExpired(argv, kw.get("timeout", 5.0))

    out = bs.read_status(binary="/bin/willow-bot-steward", runner=runner)
    assert out["state"] == "unreachable"
    assert out["reason"] == "timeout"


def test_unreachable_bad_json():
    runner = lambda argv, **kw: _cp(argv, stdout="not json at all")  # noqa: E731
    out = bs.read_status(binary="/bin/willow-bot-steward", runner=runner)
    assert out["state"] == "unreachable"
    assert out["reason"] == "unparseable"


def test_unreachable_top_level_json_not_an_object():
    runner = lambda argv, **kw: _cp(argv, stdout=json.dumps([1, 2, 3]))  # noqa: E731
    out = bs.read_status(binary="/bin/willow-bot-steward", runner=runner)
    assert out["state"] == "unreachable"
    assert out["reason"] == "unparseable"


def test_resolve_binary_env_override(monkeypatch):
    monkeypatch.setenv(bs.BINARY_ENV, "/opt/willow-bot-steward")
    assert bs.resolve_binary() == "/opt/willow-bot-steward"


def test_resolve_binary_derives_from_willow_home(monkeypatch):
    monkeypatch.delenv(bs.BINARY_ENV, raising=False)
    monkeypatch.setenv("WILLOW_HOME", "/srv/willow")
    assert bs.resolve_binary() == "/srv/willow/venvs/willow-bot/bin/willow-bot-steward"


def test_bot_status_tool_gate_and_visibility(mk_app, monkeypatch):
    denied = mk_app("hanuman", ["store_read"])
    allowed = mk_app("frigg", ["fleet_read"])

    monkeypatch.setattr(bs, "read_status", lambda: {"state": "populated", "report": {}})

    out = _fn(server.bot_status)(app_id=denied)
    assert "gate denied" in out.get("error", "")

    out = _fn(server.bot_status)(app_id=allowed)
    assert out["state"] == "populated"

    from willow_mcp import gate

    assert gate.permitted(allowed, "bot_status")
    assert not gate.permitted(denied, "bot_status")
