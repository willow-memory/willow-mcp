"""Tests for the per-app security-signal summary and its diagnostic wiring."""

from __future__ import annotations

from willow_mcp import security_signals
from willow_mcp.receipts import ReceiptLog


def _log(tmp_path):
    return ReceiptLog(str(tmp_path / "r.db"))


def test_empty_log_has_no_signals(tmp_path):
    out = security_signals.summarize(_log(tmp_path), "app")
    assert out["available"] is True
    assert out["total"] == 0
    assert out["flagged"] is False
    assert out["signals"]["egress_denied"]["count"] == 0


def test_counts_each_security_event_type(tmp_path):
    log = _log(tmp_path)
    log.record("app", "willow_web_fetch", "denied", "egress.private_target: http://169.254.169.254/")
    log.record("app", "willow_web_fetch", "denied", "egress.redirect_refused: http://x/")
    log.record("app", "willow_web_fetch", "guard.tool_output_escape", "neutralised boundary")
    log.record("app", "task_submit", "error", "INSTALL-AUDIT: 1 vuln at/above high in evilpkg")
    log.record("app", "store_get", "ok", None)  # noise: not a security event

    out = security_signals.summarize(log, "app")
    assert out["total"] == 4
    assert out["signals"]["egress_denied"]["count"] == 2
    assert out["signals"]["tool_output_escape"]["count"] == 1
    assert out["signals"]["install_blocked"]["count"] == 1
    assert out["signals"]["egress_denied"]["reasons"] == {
        "egress.private_target": 1, "egress.redirect_refused": 1}


def test_flagged_only_when_a_category_reaches_the_threshold(tmp_path):
    log = _log(tmp_path)
    for _ in range(3):
        log.record("app", "willow_web_fetch", "denied", "egress.private_target: http://10.0.0.1/")
    out = security_signals.summarize(log, "app", flag_threshold=3)
    assert out["flagged"] is True

    out_high = security_signals.summarize(log, "app", flag_threshold=4)
    assert out_high["flagged"] is False  # three does not reach four


def test_signals_are_scoped_to_the_app(tmp_path):
    """The receipt log is per-identity; the summary must not count another app."""
    log = _log(tmp_path)
    log.record("mine", "willow_web_fetch", "denied", "egress.private_target: http://10/")
    log.record("other", "willow_web_fetch", "denied", "egress.private_target: http://10/")
    assert security_signals.summarize(log, "mine")["total"] == 1
    assert security_signals.summarize(log, "other")["total"] == 1


def test_last_is_the_most_recent_of_the_category(tmp_path):
    log = _log(tmp_path)
    log.record("app", "willow_web_fetch", "denied", "egress.private_target: http://a/")
    log.record("app", "willow_web_fetch", "denied", "egress.redirect_refused: http://b/")
    out = security_signals.summarize(log, "app")
    rows = log.tail("app", 10)  # newest-first
    assert out["signals"]["egress_denied"]["last"] == rows[0]["ts"]


def test_a_broken_log_reports_unavailable_not_raises():
    class _Boom:
        def tail(self, app_id, limit):
            raise RuntimeError("db gone")

    out = security_signals.summarize(_Boom(), "app")
    assert out["available"] is False


# ── diagnostic wiring ────────────────────────────────────────────────────────


def test_security_signals_is_wired_as_an_informational_subcheck():
    from willow_mcp import server

    assert "security_signals" in server._VERDICT_INFORMATIONAL_SUBCHECKS
    # The completeness guard must accept it (informational, verdict-exempt).
    server._assert_verdict_considers(["security_signals"])


def test_diag_helper_returns_the_summary(tmp_path, monkeypatch):
    from willow_mcp import server

    log = _log(tmp_path)
    log.record("app", "willow_web_fetch", "guard.tool_output_escape", "neutralised")
    monkeypatch.setattr(server, "_receipt_log", log)
    out = server._diag_security_signals("app")
    assert out["available"] is True
    assert out["signals"]["tool_output_escape"]["count"] == 1
