"""Dedicated unit tests for handoff.py — closeout rendering, handoff read/write,
and verify logic.

Tests the pure rendering function (_render_closeout) directly, and the I/O
functions via filesystem fixtures with mocked dispatch dependencies.
"""
from __future__ import annotations

import json
from unittest.mock import patch

from willow_mcp.handoff import (
    _render_closeout,
    _utc_now,
    handoff_read,
    handoff_write_v4,
    verify_handoff,
)


# ── _utc_now ─────────────────────────────────────────────────────────────────

def test_utc_now_format():
    ts = _utc_now()
    assert ts.endswith("Z")
    assert "+" not in ts
    assert len(ts) == 20


# ── _render_closeout (pure template rendering) ──────────────────────────────

def test_render_closeout_basic():
    handoff = {
        "written_at": "2024-08-01T12:00:00Z",
        "reply_to": "willow",
        "role": "auditor",
        "narrative": "Fixed the bug.",
        "findings": [],
        "checklist_resolved": True,
    }
    pkt = {"meta": {"role": "auditor", "summary": "Audit task"}}
    md = _render_closeout("dispatch-1", "loki", handoff, pkt)
    assert "---" in md
    assert "dispatch_id:" in md
    assert '"dispatch-1"' in md
    assert '"loki"' in md
    assert '"willow"' in md
    assert "# Closeout dispatch-1" in md
    assert "Fixed the bug." in md
    assert "- (none)" in md
    assert "[x] All assignment checklist items addressed" in md
    assert "## Assignment summary" in md
    assert "Audit task" in md


def test_render_closeout_with_findings():
    handoff = {
        "written_at": "2024-08-01T12:00:00Z",
        "reply_to": "willow",
        "role": None,
        "narrative": "Found issues.",
        "findings": [
            {"id": "F1", "text": "Memory leak", "severity": "high",
             "evidence": ["file.py:42"]},
            {"id": "F2", "text": "Missing test", "severity": "low",
             "evidence": ["module.py", "test/"]},
        ],
        "checklist_resolved": False,
    }
    pkt = {"meta": {}}
    md = _render_closeout("d2", "hanuman", handoff, pkt)
    assert "| F1 | Memory leak | high | file.py:42 |" in md
    assert "| F2 | Missing test | low | module.py, test/ |" in md
    assert "[ ] All assignment checklist items addressed" in md
    assert "## Assignment summary" not in md


def test_render_closeout_no_narrative():
    handoff = {
        "written_at": "2024-08-01T12:00:00Z",
        "reply_to": "willow",
        "narrative": "",
        "findings": [],
        "checklist_resolved": True,
    }
    pkt = {"meta": {}}
    md = _render_closeout("d3", "app1", handoff, pkt)
    assert "(no narrative)" in md


def test_render_closeout_date_extraction():
    handoff = {
        "written_at": "2024-08-01T12:00:00Z",
        "reply_to": "willow",
        "narrative": "done",
        "findings": [],
        "checklist_resolved": True,
    }
    pkt = {"meta": {}}
    md = _render_closeout("d4", "app1", handoff, pkt)
    assert 'date: "2024-08-01"' in md


def test_render_closeout_role_from_handoff():
    handoff = {
        "written_at": "2024-08-01T12:00:00Z",
        "reply_to": "willow",
        "role": "builder",
        "narrative": "done",
        "findings": [],
        "checklist_resolved": True,
    }
    pkt = {"meta": {"role": "auditor"}}
    md = _render_closeout("d5", "app1", handoff, pkt)
    assert 'role: "builder"' in md


def test_render_closeout_role_falls_back_to_pkt():
    handoff = {
        "written_at": "2024-08-01T12:00:00Z",
        "reply_to": "willow",
        "narrative": "done",
        "findings": [],
        "checklist_resolved": True,
    }
    pkt = {"meta": {"role": "librarian"}}
    md = _render_closeout("d6", "app1", handoff, pkt)
    assert 'role: "librarian"' in md


def test_render_closeout_empty_written_at():
    handoff = {
        "written_at": "",
        "reply_to": "willow",
        "narrative": "done",
        "findings": [],
        "checklist_resolved": True,
    }
    pkt = {"meta": {}}
    md = _render_closeout("d7", "app1", handoff, pkt)
    assert "date:" not in md


# ── handoff_write_v4 ────────────────────────────────────────────────────────

def test_handoff_write_v4_success(tmp_path):
    dispatch_id = "test-dispatch-1"
    app_id = "hanuman"
    dispatch_root = tmp_path / "dispatch" / dispatch_id
    dispatch_root.mkdir(parents=True)

    pkt = {
        "meta": {"to_app": "hanuman", "reply_to": "willow", "role": "builder",
                 "summary": "Build task"},
        "status": {"status": "active"},
    }
    with patch("willow_mcp.handoff.dispatch_read", return_value=pkt), \
         patch("willow_mcp.handoff.dispatch_dir", return_value=dispatch_root), \
         patch("willow_mcp.handoff.dispatch_set_status"):
        result = handoff_write_v4(
            app_id, dispatch_id,
            findings=[{"id": "F1", "text": "Found bug", "severity": "high"}],
            narrative="Fixed the issue.",
        )
    assert result["status"] == "complete"
    assert result["dispatch_id"] == dispatch_id
    assert result["reply_to"] == "willow"
    assert result["waiting_for"] == "verify_handoff"

    handoff_json = json.loads((dispatch_root / "handoff.json").read_text())
    assert handoff_json["format"] == "handoff_v1"
    assert handoff_json["app_id"] == app_id
    assert len(handoff_json["findings"]) == 1
    assert handoff_json["narrative"] == "Fixed the issue."

    closeout = (dispatch_root / "closeout.md").read_text()
    assert "# Closeout test-dispatch-1" in closeout


def test_handoff_write_v4_wrong_recipient(tmp_path):
    pkt = {"meta": {"to_app": "loki"}, "status": {}}
    with patch("willow_mcp.handoff.dispatch_read", return_value=pkt):
        result = handoff_write_v4("hanuman", "d1")
    assert result["error"] == "wrong_recipient"


def test_handoff_write_v4_dispatch_error():
    with patch("willow_mcp.handoff.dispatch_read",
               return_value={"error": "not_found"}):
        result = handoff_write_v4("app1", "bad-id")
    assert result["error"] == "not_found"


# ── handoff_read ─────────────────────────────────────────────────────────────

def test_handoff_read_success(tmp_path):
    dispatch_root = tmp_path / "dispatch" / "d1"
    dispatch_root.mkdir(parents=True)
    handoff_data = {"format": "handoff_v1", "app_id": "app1",
                    "findings": [], "narrative": "done"}
    (dispatch_root / "handoff.json").write_text(json.dumps(handoff_data))
    (dispatch_root / "closeout.md").write_text("# Closeout\n")

    with patch("willow_mcp.handoff.dispatch_dir", return_value=dispatch_root), \
         patch("willow_mcp.handoff.packet_symlink_refused", return_value=False):
        result = handoff_read("d1")
    assert result["dispatch_id"] == "d1"
    assert result["handoff"]["app_id"] == "app1"
    assert "Closeout" in result["closeout_md"]


def test_handoff_read_not_found(tmp_path):
    dispatch_root = tmp_path / "dispatch" / "d2"
    dispatch_root.mkdir(parents=True)
    with patch("willow_mcp.handoff.dispatch_dir", return_value=dispatch_root), \
         patch("willow_mcp.handoff.packet_symlink_refused", return_value=False):
        result = handoff_read("d2")
    assert result["error"] == "not_found"


def test_handoff_read_symlink_refused(tmp_path):
    dispatch_root = tmp_path / "dispatch" / "d3"
    dispatch_root.mkdir(parents=True)
    with patch("willow_mcp.handoff.dispatch_dir", return_value=dispatch_root), \
         patch("willow_mcp.handoff.packet_symlink_refused", return_value=True):
        result = handoff_read("d3")
    assert result["error"] == "symlinked_packet"


def test_handoff_read_no_closeout(tmp_path):
    dispatch_root = tmp_path / "dispatch" / "d4"
    dispatch_root.mkdir(parents=True)
    (dispatch_root / "handoff.json").write_text('{"format":"handoff_v1"}')
    with patch("willow_mcp.handoff.dispatch_dir", return_value=dispatch_root), \
         patch("willow_mcp.handoff.packet_symlink_refused", return_value=False):
        result = handoff_read("d4")
    assert result["closeout_md"] == ""


# ── verify_handoff ──────────────────────────────────────────────────────────

def test_verify_handoff_verified():
    pkt = {"meta": {"to_app": "app1"}, "status": {"status": "complete"}}
    handoff_data = {
        "checklist_resolved": True,
        "envelope_clean": True,
        "findings": [{"id": "F1", "text": "Found something"}],
    }
    hr = {"dispatch_id": "d1", "handoff": handoff_data, "closeout_md": ""}
    with patch("willow_mcp.handoff.dispatch_read", return_value=pkt), \
         patch("willow_mcp.handoff.handoff_read", return_value=hr), \
         patch("willow_mcp.handoff.dispatch_set_status"):
        result = verify_handoff("d1")
    assert result["verified"] is True
    assert result["status"] == "verified"
    assert result["findings_count"] == 1


def test_verify_handoff_fails_on_empty_finding_text():
    pkt = {"meta": {}, "status": {"status": "complete"}}
    handoff_data = {
        "checklist_resolved": True,
        "envelope_clean": True,
        "findings": [{"id": "F1", "text": ""}],
    }
    hr = {"dispatch_id": "d1", "handoff": handoff_data, "closeout_md": ""}
    with patch("willow_mcp.handoff.dispatch_read", return_value=pkt), \
         patch("willow_mcp.handoff.handoff_read", return_value=hr):
        result = verify_handoff("d1")
    assert result["verified"] is False


def test_verify_handoff_fails_on_unresolved_checklist():
    pkt = {"meta": {}, "status": {"status": "complete"}}
    handoff_data = {
        "checklist_resolved": False,
        "envelope_clean": True,
        "findings": [],
    }
    hr = {"dispatch_id": "d1", "handoff": handoff_data, "closeout_md": ""}
    with patch("willow_mcp.handoff.dispatch_read", return_value=pkt), \
         patch("willow_mcp.handoff.handoff_read", return_value=hr):
        result = verify_handoff("d1")
    assert result["verified"] is False


def test_verify_handoff_fails_on_unclean_envelope():
    pkt = {"meta": {}, "status": {"status": "complete"}}
    handoff_data = {
        "checklist_resolved": True,
        "envelope_clean": False,
        "findings": [],
    }
    hr = {"dispatch_id": "d1", "handoff": handoff_data, "closeout_md": ""}
    with patch("willow_mcp.handoff.dispatch_read", return_value=pkt), \
         patch("willow_mcp.handoff.handoff_read", return_value=hr):
        result = verify_handoff("d1")
    assert result["verified"] is False


def test_verify_handoff_not_complete():
    pkt = {"meta": {}, "status": {"status": "active"}}
    with patch("willow_mcp.handoff.dispatch_read", return_value=pkt):
        result = verify_handoff("d1")
    assert result["error"] == "not_complete"


def test_verify_handoff_dispatch_error():
    with patch("willow_mcp.handoff.dispatch_read",
               return_value={"error": "not_found"}):
        result = verify_handoff("d1")
    assert result["error"] == "not_found"
