"""Dedicated unit tests for handoff.py — closeout rendering, handoff read/write,
and verify logic.

Tests the pure rendering function (_render_closeout) directly, and the I/O
functions via filesystem fixtures with mocked dispatch dependencies.
"""
from __future__ import annotations

import json
from unittest.mock import patch

from willow_mcp.handoff import (
    _finding_evidence,
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
            findings=[{"id": "F1", "text": "Found bug", "severity": "high",
                       "evidence": ["12 passed"]}],
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
        "narrative": "Full suite green: 42 passed, 0 failed.",
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
        "narrative": "42 passed, 0 failed.",
    }
    hr = {"dispatch_id": "d1", "handoff": handoff_data, "closeout_md": ""}
    with patch("willow_mcp.handoff.dispatch_read", return_value=pkt), \
         patch("willow_mcp.handoff.handoff_read", return_value=hr):
        result = verify_handoff("d1")
    assert result["verified"] is False
    assert result["reason"] == "envelope not clean"


# ── findings shape (gaps cd337282ba63, 5805dba0ad47) ─────────────────────────
#
# handoff_write_v4 accepts any findings shape. The consumers must render what
# specialists actually wrote and, when they refuse, say which finding and why.


def _verify(handoff_data):
    pkt = {"meta": {}, "status": {"status": "complete"}}
    hr = {"dispatch_id": "d1", "handoff": handoff_data, "closeout_md": ""}
    with patch("willow_mcp.handoff.dispatch_read", return_value=pkt), \
         patch("willow_mcp.handoff.handoff_read", return_value=hr), \
         patch("willow_mcp.handoff.dispatch_set_status"):
        return verify_handoff("d1")


def test_verify_accepts_title_and_finding_shaped_findings():
    """loki wrote {n, branch, file, finding}; hanuman wrote title. Both are
    findings. D83F9739 and 3308526F were refused for the key name alone."""
    result = _verify({
        "checklist_resolved": True,
        "envelope_clean": True,
        "findings": [
            {"n": 1, "branch": "feat/x", "file": "a.py", "finding": "off by one"},
            {"title": "Missing test", "severity": "low"},
            {"summary": "docs drift"},
        ],
        "narrative": "Ran the suite: 17/17 tests passing, ruff clean.",
    })
    assert result["verified"] is True
    assert "reason" not in result


def test_verify_false_names_the_failing_finding_and_its_keys():
    result = _verify({
        "checklist_resolved": True,
        "envelope_clean": True,
        "findings": [
            {"id": "F1", "text": "fine"},
            {"id": "F2", "severity": "high", "evidence": ["x"]},
            {"id": "F3", "text": "   "},
        ],
    })
    assert result["verified"] is False
    assert result["invalid_findings"] == [
        {"index": 1, "keys": ["evidence", "id", "severity"]},
        {"index": 2, "keys": ["id", "text"]},
    ]
    assert "indexes 1, 2" in result["reason"]
    assert "text/title/finding/summary" in result["reason"]


def test_verify_reason_lists_every_failing_gate():
    result = _verify({
        "checklist_resolved": False,
        "envelope_clean": False,
        "findings": [{"id": "F1"}],
    })
    assert result["verified"] is False
    assert result["reason"].startswith("checklist not resolved; envelope not clean; ")
    assert result["findings_count"] == 1


def test_render_closeout_uses_title_or_finding_when_text_is_absent():
    handoff = {
        "written_at": "2026-09-10T00:00:00Z",
        "reply_to": "willow",
        "narrative": "n",
        "findings": [
            {"id": "L1", "finding": "off by one", "severity": "med", "evidence": "a.py:4"},
            {"id": "H1", "title": "Missing test", "evidence": ["b.py", "tests/"]},
        ],
        "checklist_resolved": True,
    }
    md = _render_closeout("d3", "loki", handoff, {"meta": {}})
    assert "| L1 | off by one | med | a.py:4 |" in md
    assert "| H1 | Missing test |  | b.py, tests/ |" in md


def test_render_closeout_does_not_split_string_evidence_into_characters():
    handoff = {
        "written_at": "2026-09-10T00:00:00Z",
        "reply_to": "willow",
        "narrative": "n",
        "findings": [{"id": "F1", "text": "leak", "evidence": "file.py:42"}],
        "checklist_resolved": True,
    }
    md = _render_closeout("d4", "hanuman", handoff, {"meta": {}})
    assert "| F1 | leak |  | file.py:42 |" in md
    assert "f, i, l, e" not in md


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


# ── pre-handoff verify: unbacked completion claims (dispatch F06C0BD0) ──────
#
# checklist_resolved=True is a claim ("I finished, tests pass"). A handoff
# whose findings are bare strings instead of {summary, severity}-shaped
# objects, or whose completion claim carries no checkable evidence, is
# caught here rather than taken on faith by the orchestrator.


def test_verify_fails_on_bare_string_findings():
    """Findings as plain strings, not objects, are not a shape verify_handoff
    accepts under any of its recognized keys — refused, not silently kept."""
    result = _verify({
        "checklist_resolved": True,
        "envelope_clean": True,
        "findings": ["Fixed the bug", "Added a test"],
        "narrative": "42 passed, 0 failed.",
    })
    assert result["verified"] is False
    assert result["invalid_findings"] == [
        {"index": 0, "keys": [], "type": "str"},
        {"index": 1, "keys": [], "type": "str"},
    ]


def test_verify_fails_on_complete_claim_without_evidence():
    """checklist_resolved=True with a narrative that only asserts success
    ("all tests pass") and no counted result anywhere is refused: an
    assertion is not evidence."""
    result = _verify({
        "checklist_resolved": True,
        "envelope_clean": True,
        "findings": [{"id": "F1", "text": "Found something"}],
        "narrative": "All tests pass and the suite is green.",
    })
    assert result["verified"] is False
    assert "no evidence backs it" in result["reason"]


def test_verify_passes_complete_claim_with_narrative_test_count():
    result = _verify({
        "checklist_resolved": True,
        "envelope_clean": True,
        "findings": [{"id": "F1", "text": "Found something"}],
        "narrative": "Ran the suite: 12/12 tests passing.",
    })
    assert result["verified"] is True
    assert "reason" not in result


def test_verify_passes_present_tense_and_bare_pass_phrasings():
    """The fleet's own docs/handoffs phrase a count as "passing" or the bare
    verb "pass" as often as "passed" (docs/BUGS.md "301 passing",
    docs/design/guardian-consent-seam.md "25 passing"/"19 passing"/"9
    passing", tests/test_calendar_source_gcal.py "11/11 pass.",
    docs/design/mcp-sdk-2-migration.md "1497 passed, 43 skipped, 8
    xfailed"). All must be accepted, each still requiring a digit next to
    the word so a bare "tests pass" is not smuggled through."""
    for narrative in [
        "42 passing.",
        "3402/3402 passing.",
        "all 3402 passing, 0 failures.",
        "42 pass.",
        "Ran: 11/11 pass.",
        "301 passing (developer shape).",
        "1497 passed, 43 skipped, 8 xfailed, 0 failures.",
    ]:
        result = _verify({
            "checklist_resolved": True,
            "envelope_clean": True,
            "findings": [{"id": "F1", "text": "Found something"}],
            "narrative": narrative,
        })
        assert result["verified"] is True, f"wrongly refused: {narrative!r}"


def test_verify_still_refuses_bare_pass_with_no_digit():
    """Widening the wordlist to accept "passing"/"pass" must not let a
    digit-free assertion through — "tests pass" alone still fails."""
    result = _verify({
        "checklist_resolved": True,
        "envelope_clean": True,
        "findings": [{"id": "F1", "text": "Found something"}],
        "narrative": "All tests pass, everything is passing now.",
    })
    assert result["verified"] is False
    assert "no evidence backs it" in result["reason"]


def test_verify_refuses_bare_verb_pass_as_evidence():
    """Audit finding, dispatch F06C0BD0 follow-up: the word-then-digit
    alternative used to match the transitive verb "pass" followed by any
    unrelated number — "I'll pass 3 items to review" wrongly satisfied the
    evidence gate. "N pass"/"N passing" (a real count) is fully covered by
    the digit-then-word alternative and must still work; only the
    word-then-digit reading of bare "pass" is dropped."""
    for narrative in [
        "I'll pass 3 items to review.",
        "Please pass 2 messages along.",
        "will pass 5 to Sean",
        "pass 1 note to the builder",
    ]:
        result = _verify({
            "checklist_resolved": True,
            "envelope_clean": True,
            "findings": [{"id": "F1", "text": "Found something"}],
            "narrative": narrative,
        })
        assert result["verified"] is False, f"wrongly accepted: {narrative!r}"
        assert "no evidence backs it" in result["reason"]

    for narrative in ["42 pass.", "3402/3402 passing."]:
        result = _verify({
            "checklist_resolved": True,
            "envelope_clean": True,
            "findings": [{"id": "F1", "text": "Found something"}],
            "narrative": narrative,
        })
        assert result["verified"] is True, f"wrongly refused: {narrative!r}"


def test_finding_evidence_treats_whitespace_only_string_as_empty():
    """evidence="   " (a whitespace-only string) used to pass while
    evidence=["   "] was correctly filtered out — both shapes now use the
    same strip-and-check emptiness test."""
    assert _finding_evidence({"evidence": "   "}) == []
    assert _finding_evidence({"evidence": ["   "]}) == []
    assert _finding_evidence({"evidence": ["  ", "real.py:1"]}) == ["real.py:1"]
    assert _finding_evidence({"evidence": "file.py:1"}) == ["file.py:1"]


def test_verify_refuses_complete_claim_with_only_whitespace_evidence():
    """A finding whose evidence is whitespace-only must not satisfy the
    completion-evidence gate in either shape."""
    for evidence in ["   ", ["   "]]:
        result = _verify({
            "checklist_resolved": True,
            "envelope_clean": True,
            "findings": [{"id": "F1", "text": "Found something", "evidence": evidence}],
            "narrative": "Done.",
        })
        assert result["verified"] is False, f"wrongly accepted evidence={evidence!r}"


def test_verify_passes_docs_only_claim_via_finding_evidence():
    """A genuinely-complete docs/config-only change has no test count to
    cite. The documented escape hatch is a finding's `evidence` field
    naming what was actually checked — not sniffing "docs-only" out of
    narrative prose, which a specialist could claim with nothing behind it.
    This does not force a docs change to fabricate a test count."""
    result = _verify({
        "checklist_resolved": True,
        "envelope_clean": True,
        "findings": [{
            "summary": "Updated README install instructions",
            "severity": "low",
            "evidence": ["diff reviewed: docs/README.md +12/-3, no src/ touched"],
        }],
        "narrative": "Docs-only change: updated README install steps, no code touched.",
    })
    assert result["verified"] is True
    assert "reason" not in result


def test_verify_refuses_docs_only_claim_with_no_finding_evidence():
    """A docs-only claim asserted in narrative prose alone, with no finding
    to back it, is still an unbacked claim — the escape hatch is the
    finding's evidence field, not the word "docs-only" itself."""
    result = _verify({
        "checklist_resolved": True,
        "envelope_clean": True,
        "findings": [{"id": "F1", "text": "Updated README"}],
        "narrative": "Docs-only change, no code touched, done.",
    })
    assert result["verified"] is False
    assert "no evidence backs it" in result["reason"]


def test_verify_passes_complete_claim_with_finding_evidence():
    """No countable narrative, but a finding carries its own evidence field
    — that is enough backing without also requiring narrative prose."""
    result = _verify({
        "checklist_resolved": True,
        "envelope_clean": True,
        "findings": [{"id": "F1", "text": "Fixed it", "evidence": ["test_x.py::test_y"]}],
        "narrative": "Done.",
    })
    assert result["verified"] is True
    assert "reason" not in result


def test_verify_honest_blocker_report_not_penalized_for_missing_evidence():
    """checklist_resolved=False is not a completion claim — the evidence
    gate must not compound onto an honest blocker/partial report. The
    pre-existing "checklist not resolved" gate still applies (unfinished
    work is not verified), but the reason must not also complain about
    missing test evidence — that complaint only applies to a claim."""
    result = _verify({
        "checklist_resolved": False,
        "envelope_clean": True,
        "findings": [{"id": "F1", "text": "Blocked: missing credentials"}],
        "narrative": "Could not proceed past the auth step.",
    })
    assert result["verified"] is False
    assert result["reason"] == "checklist not resolved"


# ── handoff_write_v4 refuses instead of dropping (gap 21f80b2b348a; sealed
# cdcd948c stage 2; gap 34c8e60f4260) ────────────────────────────────────────

def _write(tmp_path, dispatch_id="d-refuse", **kwargs):
    dispatch_root = tmp_path / "dispatch" / dispatch_id
    dispatch_root.mkdir(parents=True, exist_ok=True)
    pkt = {
        "meta": {"to_app": "hanuman", "reply_to": "willow", "role": "builder"},
        "status": {"status": "active"},
    }
    with patch("willow_mcp.handoff.dispatch_read", return_value=pkt), \
         patch("willow_mcp.handoff.dispatch_dir", return_value=dispatch_root), \
         patch("willow_mcp.handoff.dispatch_set_status"):
        return handoff_write_v4("hanuman", dispatch_id, **kwargs)


def test_write_refuses_unknown_top_level_key(tmp_path):
    """The exact BFF5284B shape: summary/details are not accepted fields --
    refused by name, never silently dropped into findings=[]/narrative=''."""
    result = _write(
        tmp_path, summary="Build task", details="did the thing",
    )
    assert result["error"] == "EINVAL"
    assert set(result["unknown_fields"]) == {"summary", "details"}
    assert "summary" in result["message"]
    assert "details" in result["message"]


def test_write_refuses_single_unknown_key_by_name(tmp_path):
    result = _write(
        tmp_path,
        findings=[{"id": "F1", "text": "x"}],
        narrative="done",
        notas="typo of narrative",
    )
    assert result["error"] == "EINVAL"
    assert result["unknown_fields"] == ["notas"]
    assert "accepted_fields" in result


def test_write_refuses_empty_findings_without_reason(tmp_path):
    result = _write(tmp_path, narrative="done")
    assert result["error"] == "EINVAL"
    assert "no_findings_reason" in result["message"]
    # Loki EB30E84F F3: this is the ONE refusal a real MCP client ever sees
    # for the BFF5284B (summary/details) shape, since the SDK drops the
    # unrecognized keys before this check runs -- it must name the
    # accepted fields, not just say "empty findings".
    assert "accepted_fields" in result
    assert "findings" in result["accepted_fields"]
    assert "narrative" in result["accepted_fields"]
    assert "field names" in result["message"] or "summary" in result["message"]


def test_write_accepts_empty_findings_with_reason_and_records_it(tmp_path):
    dispatch_id = "d-no-findings"
    result = _write(
        tmp_path, dispatch_id=dispatch_id,
        narrative="Investigated; 0 violations, nothing to report.",
        no_findings_reason="pure read-only audit, no issues found",
    )
    assert result["status"] == "complete"
    handoff_json = json.loads(
        (tmp_path / "dispatch" / dispatch_id / "handoff.json").read_text()
    )
    assert handoff_json["no_findings_reason"] == "pure read-only audit, no issues found"
    closeout = (tmp_path / "dispatch" / dispatch_id / "closeout.md").read_text()
    assert "pure read-only audit, no issues found" in closeout


def test_write_refuses_finding_with_no_statement(tmp_path):
    result = _write(
        tmp_path,
        narrative="done",
        findings=[{"id": "F1", "severity": "high"}],
    )
    assert result["error"] == "EINVAL"
    assert result["invalid_findings"] == [{"index": 0, "keys": ["id", "severity"]}]


def test_valid_write_then_passes_verify_handoff(tmp_path):
    """A valid write (through the new validator) is also accepted by
    verify_handoff — the writer refuses what the verifier would refuse, and
    accepts what the verifier accepts."""
    dispatch_id = "d-roundtrip"
    written = _write(
        tmp_path, dispatch_id=dispatch_id,
        findings=[{"id": "F1", "text": "Found it", "evidence": ["a.py:1"]}],
        narrative="Full suite: 12 passed, 0 failed.",
    )
    assert written["status"] == "complete"

    pkt = {"meta": {"to_app": "hanuman"}, "status": {"status": "complete"}}
    dispatch_root = tmp_path / "dispatch" / dispatch_id
    with patch("willow_mcp.handoff.dispatch_read", return_value=pkt), \
         patch("willow_mcp.handoff.dispatch_dir", return_value=dispatch_root), \
         patch("willow_mcp.handoff.dispatch_set_status"):
        verified = verify_handoff(dispatch_id)
    assert verified["verified"] is True


# ── the writer pre-flights the verifier's own completion-evidence and lint
# checks (rework of Loki's F3, 23CAD2B4; gap 34c8e60f4260 fully closed) ──────

def test_write_refuses_checklist_resolved_with_no_completion_evidence(tmp_path):
    """The exact split Loki measured: a finding with a statement but no
    evidence, and a narrative with no counted result, used to write fine
    and only fail later at verify_handoff. Now refused at write time with
    verify_handoff's own reason string."""
    result = _write(
        tmp_path,
        findings=[{"id": "F1", "text": "Found it"}],
        narrative="done",
    )
    assert result["error"] == "EINVAL"
    assert "no evidence backs it" in result["message"]


def test_write_and_verify_no_evidence_reason_strings_are_byte_identical(tmp_path):
    """Loki EB30E84F F5: the check FUNCTIONS were already shared, but the
    reason STRINGS were two independently-typed literals -- a drifted-copy
    risk of exactly the kind repair 1 exists to end. Both now come from one
    constant; prove it by comparing the writer's refusal message against
    the verifier's reason for the identical bad shape."""
    from willow_mcp.handoff import _NO_COMPLETION_EVIDENCE_REASON

    write_result = _write(
        tmp_path,
        findings=[{"id": "F1", "text": "Found it"}],
        narrative="done",
    )
    assert write_result["message"] == _NO_COMPLETION_EVIDENCE_REASON

    pkt = {"meta": {}, "status": {"status": "complete"}}
    handoff_data = {
        "checklist_resolved": True,
        "envelope_clean": True,
        "findings": [{"id": "F1", "text": "Found it"}],
        "narrative": "done",
    }
    hr = {"dispatch_id": "d-verify-same", "handoff": handoff_data, "closeout_md": ""}
    with patch("willow_mcp.handoff.dispatch_read", return_value=pkt), \
         patch("willow_mcp.handoff.handoff_read", return_value=hr):
        verified = verify_handoff("d-verify-same")
    assert _NO_COMPLETION_EVIDENCE_REASON in verified["reason"]
    assert write_result["message"] == _NO_COMPLETION_EVIDENCE_REASON


def test_write_accepts_checklist_resolved_false_without_evidence(tmp_path):
    """An honest blocker/partial report is not a completion claim -- the
    evidence gate must not fire when checklist_resolved=False (same
    exemption verify_handoff itself grants)."""
    result = _write(
        tmp_path,
        findings=[{"id": "F1", "text": "Blocked: missing credentials"}],
        narrative="Could not proceed past the auth step.",
        checklist_resolved=False,
    )
    assert result["status"] == "complete"


def test_write_accepts_checklist_resolved_with_narrative_count_and_no_finding_evidence(tmp_path):
    """The narrative-count path alone is enough -- matches
    _has_completion_evidence's OR, not an AND."""
    result = _write(
        tmp_path,
        findings=[{"id": "F1", "text": "Docs updated"}],
        narrative="Ran the suite: 17/17 tests passing.",
    )
    assert result["status"] == "complete"
