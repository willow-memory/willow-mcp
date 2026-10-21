"""The one script's scrub in willow-mcp (flatten-2 F12): the funnel, the Nest
finder, the journal tail, the git trace and the Sentry scrub all take their
rules from ``onescript/scrub.py``. Here: a key glued to letters is taken out
through each door, and with the one script out of reach each door refuses or
withholds and says why. It never reads from a copy of the old patterns.
"""
from __future__ import annotations

import pytest

from willow_mcp import observability as obs
from willow_mcp import onescript_reach, scrub_reach, secret_scan
from willow_mcp import push_executor as px
from willow_mcp.nest import secrets as nest_secrets

AWS = "AKIA" + "Q" * 16
WHY = "no one-script at /nowhere (set ONESCRIPT_HOME)"


@pytest.fixture
def lost(monkeypatch):
    """The one script is not where it was looked for."""

    def gone(name, home=None):
        raise onescript_reach.Unreachable(WHY)

    monkeypatch.setattr(scrub_reach, "_module", None)
    monkeypatch.setattr(onescript_reach, "module", gone)


def test_a_key_glued_to_letters_is_taken_out_through_every_door():
    glued = f"wrap{AWS}wrap"
    out, kinds = secret_scan.redact_egress({"v": glued})
    assert AWS not in out["v"] and kinds == ["aws_access_key_id"]
    assert AWS not in secret_scan.redact_journal_tail(glued)[0]
    assert ("aws_access_key", AWS) in nest_secrets.find_secrets(glued)
    assert AWS not in nest_secrets.redact_text(glued)
    assert AWS not in px._redact(glued)
    assert AWS not in obs._redact_str(glued)


def test_the_funnel_refuses_when_the_one_script_is_out_of_reach(lost):
    with pytest.raises(scrub_reach.ScrubUnreachable, match="ONESCRIPT_HOME"):
        secret_scan.redact_egress({"v": "anything"})
    assert secret_scan.scan_opaque(object()) == ["unreachable"]


def test_the_journal_tail_is_withheld_with_why(lost):
    text, kinds = secret_scan.redact_journal_tail("2026-09-27T10:00:00 all fine")
    assert kinds == ["unreachable"] and WHY in text and "all fine" not in text


def test_the_nest_finder_holds_rather_than_reads_clean(lost):
    found = nest_secrets.find_secrets("an ordinary note")
    assert found == [("unreachable", WHY)]
    assert nest_secrets.redact_text("an ordinary note") == f"[REDACTED:unreachable: {WHY}]"


def test_the_git_trace_and_sentry_scrub_withhold(lost):
    assert "all fine" not in px._redact("all fine") and "unreachable" in px._redact("all fine")
    assert obs._redact_str("a frame") == obs._REDACTED
    assert obs._sensitive_key("filename") is True  # cannot tell, so nothing is let through


def test_the_funnel_still_has_no_label_heuristics():
    payload = {"a": "primary_key=True", "b": "password=None", "c": "DB_PASSWORD=hunter2"}
    out, kinds = secret_scan.redact_egress(payload)
    assert out == payload and kinds == []
