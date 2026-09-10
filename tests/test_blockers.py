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

def _seat(tmp_path, monkeypatch, *, keyring: bool = True):
    """An orchestrator home with a verifier configured.

    The keyring is what makes the attestation question meaningful. These tests
    used to assert on `verifier` in the session record, which is never written
    for this purpose -- `sign-session` writes a sidecar and the enforcing gate
    has read only that since #313. They now ask the same function the gate asks,
    so the two cannot drift apart again.
    """
    from willow_mcp import human_session
    from willow_mcp import keyring as keyring_mod

    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    sessions = tmp_path / "sessions"
    sessions.mkdir(exist_ok=True)
    human_session.clear_attribution_cache()

    if keyring:
        ring = keyring_mod.Keyring()
        ring.add("sean")
        path = tmp_path / "verifiers.json"
        path.write_text(json.dumps(ring.to_json()), encoding="utf-8")
        monkeypatch.setenv("WILLOW_KEYRING", str(path))
        keyring_mod.set_keyring(ring)
        monkeypatch.setattr(keyring_mod, "set_keyring", keyring_mod.set_keyring)
    else:
        monkeypatch.delenv("WILLOW_KEYRING", raising=False)
        keyring_mod.set_keyring(None)
    return sessions


@pytest.fixture(autouse=True)
def _drop_injected_keyring():
    """No test may leave a keyring installed for the next one."""
    yield
    from willow_mcp import human_session
    from willow_mcp import keyring as keyring_mod

    keyring_mod.set_keyring(None)
    human_session.clear_attribution_cache()


def test_an_unattested_orchestrator_session_is_blocked(tmp_path, monkeypatch):
    """A live session with no attestation sidecar: the gate refuses, so the
    seat must say so at entry."""
    sessions = _seat(tmp_path, monkeypatch)
    (sessions / "willow-s1.json").write_text(
        json.dumps({"app_id": "willow", "session_id": "s1"}), encoding="utf-8")
    found = blockers._check_attestation("willow", "s1")
    assert found and found["id"] == "session_unattested"
    assert "envelope_propose" in found["effect"]
    assert "sign-session s1" in found["fix"]
    # The remedy must carry the environment the operator's shell does not have.
    assert f"WILLOW_HOME={tmp_path}" in found["fix"]
    assert f"WILLOW_KEYRING={tmp_path / 'verifiers.json'}" in found["fix"]


def test_an_attested_session_is_not_blocked(tmp_path, monkeypatch):
    """Attested the way `sign-session` attests: a signed v2 sidecar on disk,
    and the session record left exactly as `session_bind` leaves it."""
    from willow_mcp import session_signing

    sessions = _seat(tmp_path, monkeypatch)
    (sessions / "willow-s1.json").write_text(
        json.dumps({"app_id": "willow", "session_id": "s1", "verifier": ""}),
        encoding="utf-8")
    attested_at = "2026-09-09T20:52:54Z"
    payload = {"format": "orchestrator_session_attestation_v2",
               "app_id": "willow", "session_id": "s1",
               "verifier": "sean", "attested_at": attested_at}
    sig = session_signing.sign_session(app_id="willow", session_id="s1",
                                       verifier="sean", attested_at=attested_at)
    (sessions / "willow-s1.attest.json").write_text(
        json.dumps(payload), encoding="utf-8")
    (sessions / "willow-s1.attest.json.sig").write_text(sig, encoding="utf-8")

    assert blockers._check_attestation("willow", "s1") is None


def test_a_specialist_is_not_asked_for_attestation(tmp_path, monkeypatch):
    """Only the orchestrator seat authors envelopes."""
    _seat(tmp_path, monkeypatch)
    assert blockers._check_attestation("binder", "s1") is None


def test_a_missing_session_record_reads_as_unattested(tmp_path, monkeypatch):
    """Absence is not attestation."""
    _seat(tmp_path, monkeypatch)
    found = blockers._check_attestation("willow", "s-nope")
    assert found and found["id"] == "session_unattested"


def test_no_verifier_configured_reports_nothing(tmp_path, monkeypatch):
    """The false positive in the other direction, and the reason the old check
    could not simply be patched: with neither a keyring nor a PGP fingerprint,
    `orchestrator_write_denial` returns early and NOTHING refuses. Reporting a
    blocker there sent the operator to fix a gate that was not shut."""
    from willow_mcp import human_session

    sessions = _seat(tmp_path, monkeypatch, keyring=False)
    (sessions / "willow-s1.json").write_text(
        json.dumps({"app_id": "willow", "session_id": "s1"}), encoding="utf-8")
    assert human_session.orchestrator_write_denial(
        "willow", "envelope_propose", serve_mode=False, session_id="s1") is None
    assert blockers._check_attestation("willow", "s1") is None


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


def test_an_unreadable_lease_blocks_with_a_chmod_fix_not_a_regrant(monkeypatch):
    """Gap d90246688413: the fix for a lease this process cannot read is a
    mode change. Telling the operator to re-issue reproduces the same file."""
    import willow_mcp.lease as lease

    monkeypatch.setattr(lease, "read_lease", lambda a: {
        "status": "unreadable", "path": "/box/mcp_apps/_net_leases/kart.json",
        "error": "permission denied: [Errno 13]", "expires_at": None,
    })
    found = blockers._check_lease("kart")
    assert found["id"] == "no_egress_lease"
    assert "cannot read it" in found["summary"]
    assert "/box/mcp_apps/_net_leases/kart.json" in found["summary"]
    assert "chmod 644 /box/mcp_apps/_net_leases/kart.json" in found["fix"]
    assert "grant-net" not in found["fix"].split("Do NOT")[0]
    assert found["path"] == "/box/mcp_apps/_net_leases/kart.json"


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
