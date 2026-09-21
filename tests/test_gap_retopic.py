"""Gap 42ec50583126 (apk/keyboard-act): gap_retopic moves a gap under a new
topic, keeps the move in topic_history, writes a FRANK gap_retopic event
when the ledger is reachable, and refuses the three bad asks.

Same isolation rule as test_gaps.py: the gaps store is a module-level
singleton, so each test owns a unique topic rather than a fresh store.
"""
from __future__ import annotations

import json

import pytest

from willow_mcp import gaps, server


@pytest.fixture
def app_id(tmp_path, monkeypatch):
    """Same isolation as test_server.py's fixture: a full_access app under a
    per-test WILLOW_HOME so the gate admits the tool without a live manifest."""
    apps_root = tmp_path / "mcp_apps"
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / "testapp"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(json.dumps({"permissions": ["full_access"]}))
    return "testapp"


# ── the module verb ───────────────────────────────────────────────────────────

def test_retopic_moves_the_gap_and_records_history():
    logged = gaps.log("t-retopic-src", "which unit installs the reloader?")
    out = gaps.retopic(logged["id"], "apk/keyboard-act-t1", by="willow", note="carried")
    assert out == {"id": logged["id"], "topic": "apk/keyboard-act-t1", "previous": "t-retopic-src"}

    rec = gaps.get(logged["id"])
    assert rec["topic"] == "apk/keyboard-act-t1"
    assert rec["question"] == "which unit installs the reloader?"
    assert rec["status"] == "open" and rec["asked_count"] == 1
    (entry,) = rec["topic_history"]
    assert entry["from"] == "t-retopic-src" and entry["to"] == "apk/keyboard-act-t1"
    assert entry["by"] == "willow" and entry["note"] == "carried" and entry["at"]


def test_listed_under_the_new_topic_only():
    logged = gaps.log("t-retopic-old", "does the list find it?")
    gaps.retopic(logged["id"], "t-retopic-new", by="willow")
    assert [r["_id"] for r in gaps.list_gaps(topic="t-retopic-new")["items"]] == [logged["id"]]
    assert gaps.list_gaps(topic="t-retopic-old")["items"] == []


def test_second_move_appends_history_and_id_is_stable():
    logged = gaps.log("t-retopic-a", "twice moved")
    gaps.retopic(logged["id"], "t-retopic-b", by="willow")
    out = gaps.retopic(logged["id"], "t-retopic-c", by="willow")
    assert out["previous"] == "t-retopic-b"
    rec = gaps.get(logged["id"])
    assert [h["to"] for h in rec["topic_history"]] == ["t-retopic-b", "t-retopic-c"]
    assert rec["_id"] == logged["id"]


def test_refusals():
    assert gaps.retopic("000000000000", "t-x", by="willow") == {"error": "not_found", "id": "000000000000"}
    logged = gaps.log("t-retopic-refuse", "empty and same")
    assert gaps.retopic(logged["id"], "   ", by="willow") == {"error": "topic is required"}
    assert gaps.retopic(logged["id"], "t-retopic-refuse", by="willow") == {
        "error": "already", "id": logged["id"], "topic": "t-retopic-refuse"}
    assert "topic_history" not in gaps.get(logged["id"])


def test_a_promoted_gap_may_still_be_retopiced():
    logged = gaps.log("t-retopic-promoted", "promoted but misfiled")
    gaps.mark_promoted(logged["id"], "KB-ATOM-1")
    out = gaps.retopic(logged["id"], "t-retopic-promoted-2", by="willow")
    assert out["topic"] == "t-retopic-promoted-2"
    rec = gaps.get(logged["id"])
    assert rec["status"] == "promoted" and rec["promoted_to"] == "KB-ATOM-1"


# ── the MCP tool ──────────────────────────────────────────────────────────────

class _FakeLedger:
    appended: list[tuple] = []

    def __init__(self, pg):
        self.pg = pg

    def append(self, project, event_type, content):
        _FakeLedger.appended.append((project, event_type, content))
        return "frank-rec-1"


def test_tool_writes_frank_event_when_ledger_reachable(app_id, monkeypatch):
    _FakeLedger.appended.clear()
    monkeypatch.setattr(server, "get_pg", lambda: object())
    monkeypatch.setattr("willow_mcp.governance_ledger.GovernanceLedger", _FakeLedger)
    logged = server.gap_log(app_id=app_id, topic="t-tool-retopic", question="frank event?")

    out = server.gap_retopic(app_id=app_id, gap_id=logged["id"], topic="t-tool-retopic-2", note="n")

    assert out["topic"] == "t-tool-retopic-2" and out["previous"] == "t-tool-retopic"
    assert out["frank"] == {"state": "populated", "id": "frank-rec-1"}
    (project, event, content), = _FakeLedger.appended
    assert (project, event) == ("willow", "gap_retopic")
    assert content == {"gap_id": logged["id"], "from": "t-tool-retopic",
                       "to": "t-tool-retopic-2", "by": app_id, "note": "n"}


def test_tool_reports_unreachable_ledger_and_the_move_stands(app_id, monkeypatch):
    monkeypatch.setattr(server, "get_pg", lambda: None)
    logged = server.gap_log(app_id=app_id, topic="t-tool-retopic-nopg", question="no ledger")

    out = server.gap_retopic(app_id=app_id, gap_id=logged["id"], topic="t-tool-retopic-nopg-2")

    assert out["topic"] == "t-tool-retopic-nopg-2"
    assert out["frank"] == {"state": "unreachable", "reason": "postgres_unavailable"}
    assert gaps.get(logged["id"])["topic"] == "t-tool-retopic-nopg-2"


def test_tool_refusal_passes_through_without_a_ledger_write(app_id, monkeypatch):
    _FakeLedger.appended.clear()
    monkeypatch.setattr(server, "get_pg", lambda: object())
    monkeypatch.setattr("willow_mcp.governance_ledger.GovernanceLedger", _FakeLedger)
    out = server.gap_retopic(app_id=app_id, gap_id="000000000000", topic="t-x")
    assert out["error"] == "not_found" and "frank" not in out
    assert _FakeLedger.appended == []


def test_retopic_sits_in_the_curator_group_not_gap_write():
    from willow_mcp import gate

    assert "gap_retopic" in gate.PERMISSION_GROUPS["gap_promote"]
    assert "gap_retopic" not in gate.PERMISSION_GROUPS["gap_write"]
