"""One closeout: session_handoff_write owns stack+friction+closed;
SessionEnd skips when already closed (gap 1d29f1d28f0e).
"""

from __future__ import annotations

import json

import pytest

from willow_mcp import session_stop_hook
from willow_mcp.dispatch import session_bind, session_handoff_write, session_read
from willow_mcp.session_closeout import mark_session_closed, session_is_closed


@pytest.fixture(autouse=True)
def _box_home(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    monkeypatch.setenv("WILLOW_APP_ID", "willow")
    monkeypatch.setenv("WILLOW_PG_DB", "nonexistent_db_for_test")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "willow-mcp": {"env": {"WILLOW_APP_ID": "willow"}}
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(proj)
    yield


def test_session_is_closed_false_until_marked():
    assert session_is_closed("willow", "sid-a") is False
    mark_session_closed("willow", "sid-a")
    assert session_is_closed("willow", "sid-a") is True
    data = session_read("willow", "sid-a")
    assert data["status"] == "closed"


def test_handoff_write_marks_closed(monkeypatch, tmp_path):
    instruments: list[tuple] = []

    def fake_instruments(app_id, session_id, transcript_path=""):
        instruments.append((app_id, session_id))
        return {
            "stack_snapshot": {"ok": True},
            "friction_scan": {},
            "pre_handoff": {},
        }

    monkeypatch.setattr(
        "willow_mcp.session_closeout.run_closeout_instruments",
        fake_instruments,
    )

    out = session_handoff_write(
        "willow",
        "sid-handoff",
        narrative="closing out",
        summary="done",
        project="",
        workspace=str(tmp_path),
    )
    assert out.get("session_status") == "closed"
    assert session_is_closed("willow", "sid-handoff")
    assert instruments == [("willow", "sid-handoff")]
    assert "handoff_path" in out


def test_session_end_skips_when_already_closed(monkeypatch):
    mark_session_closed("willow", "sid-closed")
    ran: list = []

    def boom(*_a, **_k):
        ran.append(1)
        raise AssertionError("must not run instruments when already closed")

    monkeypatch.setattr(
        "willow_mcp.session_stop_hook.run_closeout_instruments", boom
    )
    monkeypatch.setattr(
        "willow_mcp.seat_identity.resolve_hook_app_id",
        lambda: ("willow", None),
    )
    out = session_stop_hook.handle(
        {"session_id": "sid-closed", "transcript_path": ""}
    )
    assert out.get("skipped") == "already_closed_by_handoff"
    assert ran == []


def test_session_end_runs_instruments_when_not_closed(monkeypatch):
    ran: list = []

    def fake_run(app_id, session_id, transcript_path=""):
        ran.append((app_id, session_id))
        return {"stack_snapshot": {"ok": True}}

    monkeypatch.setattr(
        "willow_mcp.session_stop_hook.run_closeout_instruments", fake_run
    )
    monkeypatch.setattr(
        "willow_mcp.seat_identity.resolve_hook_app_id",
        lambda: ("willow", None),
    )
    session_bind("willow", "sid-open", "", "active")
    out = session_stop_hook.handle(
        {"session_id": "sid-open", "transcript_path": "/tmp/t.jsonl"}
    )
    assert "skipped" not in out
    assert ran == [("willow", "sid-open")]
