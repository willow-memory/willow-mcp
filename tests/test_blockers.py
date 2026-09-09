"""A seat should learn what it cannot do at entry, not when the gate refuses.

Each of these blockers was discovered mid-task in a real session: the
unattested session when `envelope_propose` refused an hour in, the dead lease
four days after it expired, the stopped worker when a task sat pending on a
lane with nothing draining it.

Two properties matter more than the individual checks. The list must never be
the reason `session_enter` fails — orientation is sugar. And a check that
throws must appear *as an entry*, because a silently missing blocker is worse
than no list: it reads as "clear".
"""
from __future__ import annotations

import json

import pytest

from willow_mcp import blockers


@pytest.fixture
def quiet(monkeypatch):
    """Every gate open, so a test can turn exactly one off."""
    monkeypatch.setattr(blockers, "_check_attestation", lambda a, s: None)
    monkeypatch.setattr(blockers, "_check_lease", lambda a: None)
    monkeypatch.setattr(blockers, "_check_consent", lambda: None)
    monkeypatch.setattr(blockers, "_check_worker", lambda: None)
    monkeypatch.setattr(blockers, "_check_postgres", lambda: None)
    monkeypatch.setattr(blockers, "_CHECKS", (
        ("session_unattested", blockers._check_attestation),
        ("no_egress_lease", blockers._check_lease),
        ("consent_internet_off", blockers._check_consent),
        ("no_live_worker", blockers._check_worker),
        ("postgres_unreachable", blockers._check_postgres),
    ))
    return monkeypatch


def _ids(out):
    return [i["id"] for i in out["items"]]


# ── shape ────────────────────────────────────────────────────────────────────

def test_a_clear_seat_reports_nothing_blocked(quiet):
    out = blockers.collect("willow", "s1")
    assert out["count"] == 0
    assert out["items"] == []
    assert out["resolved_home"]


def test_the_resolved_home_is_reported_even_when_clear(quiet, monkeypatch, tmp_path):
    """A seat pointed at the wrong home writes successfully into nothing. The
    only cheap moment to notice is before any work is done."""
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path / "box"))
    out = blockers.collect("willow", "s1")
    assert out["resolved_home"] == str(tmp_path / "box")
    assert out["willow_home_env_set"] is True


def test_an_unset_home_env_is_flagged_as_such(quiet, monkeypatch):
    monkeypatch.delenv("WILLOW_HOME", raising=False)
    out = blockers.collect("willow", "s1")
    assert out["willow_home_env_set"] is False


def test_every_item_names_an_effect_and_a_fix(quiet, monkeypatch):
    """A blocker the reader cannot connect to a symptom gets skimmed past."""
    monkeypatch.setattr(blockers, "_check_lease",
                        lambda a: blockers._item("x", "s", "e", "f"))
    monkeypatch.setattr(blockers, "_CHECKS",
                        (("no_egress_lease", blockers._check_lease),))
    item = blockers.collect("willow", "s1")["items"][0]
    assert item["effect"] and item["fix"] and item["summary"]


# ── individual gates ─────────────────────────────────────────────────────────

def test_an_unattested_orchestrator_session_is_blocked(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    (sessions / "willow-s1.json").write_text(
        json.dumps({"app_id": "willow", "verifier": ""}), encoding="utf-8")
    found = blockers._check_attestation("willow", "s1")
    assert found and found["id"] == "session_unattested"
    assert "envelope_propose" in found["effect"]
    assert "sign-session s1" in found["fix"]


def test_an_attested_session_is_not_blocked(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    (sessions / "willow-s1.json").write_text(
        json.dumps({"app_id": "willow", "verifier": "sean"}), encoding="utf-8")
    assert blockers._check_attestation("willow", "s1") is None


def test_a_specialist_is_not_asked_for_attestation(tmp_path, monkeypatch):
    """Only the orchestrator seat authors envelopes."""
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    assert blockers._check_attestation("binder", "s1") is None


def test_a_missing_session_record_reads_as_unattested(tmp_path, monkeypatch):
    """Absence is not attestation."""
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    found = blockers._check_attestation("willow", "s-nope")
    assert found and found["id"] == "session_unattested"


@pytest.mark.parametrize("status,fragment", [
    ("none", "no lease on disk"),
    ("expired", "expired at"),
    ("malformed", "malformed"),
    ("mismatch", "different app_id"),
])
def test_every_non_active_lease_state_blocks(monkeypatch, status, fragment):
    monkeypatch.setattr(blockers, "_check_lease", blockers._check_lease)
    import willow_mcp.lease as lease

    monkeypatch.setattr(lease, "read_lease", lambda a: {
        "status": status, "expires_at": "2026-09-05T06:57:46Z",
        "error": "malformed" if status == "malformed" else "names a different app_id",
    })
    found = blockers._check_lease("kart")
    assert found["id"] == "no_egress_lease"
    assert fragment in found["summary"]
    assert "git push" in found["effect"]


def test_an_active_lease_does_not_block(monkeypatch):
    import willow_mcp.lease as lease

    monkeypatch.setattr(lease, "read_lease", lambda a: {"status": "active"})
    assert blockers._check_lease("kart") is None


def test_consent_off_says_the_lease_will_not_help(monkeypatch):
    import willow_mcp.consent as consent

    monkeypatch.setattr(consent, "read_consent", lambda: {
        "consent": {"internet": False}, "canonical_path": "/x/settings.json",
        "source": "canonical"})
    found = blockers._check_consent()
    assert "will not help" in found["effect"]


def test_a_stopped_worker_says_the_queue_never_drains(monkeypatch):
    """The failure is not a refusal — task_submit accepts and nothing runs."""
    import willow_mcp.heartbeat as heartbeat

    monkeypatch.setattr(heartbeat, "read_workers",
                        lambda: {"alive": 0, "readiness": "absent"})
    found = blockers._check_worker()
    assert found["id"] == "no_live_worker"
    assert "never drains" in found["effect"]


def test_a_live_worker_does_not_block(monkeypatch):
    import willow_mcp.heartbeat as heartbeat

    monkeypatch.setattr(heartbeat, "read_workers", lambda: {"alive": 1})
    assert blockers._check_worker() is None


def test_unreachable_postgres_carries_the_recorded_reason(monkeypatch):
    import willow_mcp.db as db

    monkeypatch.setattr(db, "get_pg", lambda: None)
    monkeypatch.setattr(db, "last_pg_error", lambda: 'database "willow" does not exist')
    found = blockers._check_postgres()
    assert 'does not exist' in found["error"]


# ── degradation ──────────────────────────────────────────────────────────────

def test_a_raising_check_becomes_an_item_not_a_crash(quiet, monkeypatch):
    def _boom():
        raise RuntimeError("reader exploded")

    monkeypatch.setattr(blockers, "_check_worker", _boom)
    monkeypatch.setattr(blockers, "_CHECKS",
                        (("no_live_worker", blockers._check_worker),))
    out = blockers.collect("willow", "s1")
    assert _ids(out) == ["no_live_worker_check_failed"]
    assert "reader exploded" in out["items"][0]["summary"]
    assert "unknown, not clear" in out["items"][0]["effect"]


def test_one_broken_check_does_not_hide_the_others(quiet, monkeypatch):
    def _boom():
        raise RuntimeError("nope")

    monkeypatch.setattr(blockers, "_check_worker", _boom)
    monkeypatch.setattr(blockers, "_check_consent",
                        lambda: blockers._item("consent_internet_off", "s", "e", "f"))
    monkeypatch.setattr(blockers, "_CHECKS", (
        ("no_live_worker", blockers._check_worker),
        ("consent_internet_off", blockers._check_consent),
    ))
    assert _ids(blockers.collect("willow", "s1")) == [
        "no_live_worker_check_failed", "consent_internet_off"]


def test_collect_never_raises_even_with_every_check_broken(quiet, monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("all of it")

    monkeypatch.setattr(blockers, "_CHECKS", tuple(
        (name, _boom) for name, _ in blockers._CHECKS))
    out = blockers.collect("willow", "s1")
    assert out["count"] == 5
    assert all(i["id"].endswith("_check_failed") for i in out["items"])
