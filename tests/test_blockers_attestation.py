"""The entry-time blocker and the enforcing gate must agree.

They did not. `blockers._check_attestation` read `verifier` out of the live
session record; `human_session.orchestrator_write_denial` has read the sidecar
since #313. `sign-session` writes the sidecar and never the record, so an
operator who attested correctly was told at every seat entry that they had not.

Observed on the operator box 2026-09-09: session_019SoVKij4nfLHzzYqWQVu3q was
signed at 20:52:54Z (verifier `sean`, ed25519), the write gate passed, and the
blocker still reported `session_unattested`. The first test here is that
reproduction, reduced to a keyring in tmp_path.
"""
from __future__ import annotations

import json

import pytest

from willow_mcp import blockers, human_session
from willow_mcp import keyring as keyring_mod
from willow_mcp import session_signing


@pytest.fixture
def attested_seat(tmp_path, monkeypatch):
    """A live orchestrator session, correctly attested the way sign-session
    does it: sidecar + .sig on disk, session record untouched.

    Returns (session_id, verifier). The keyring lives in tmp_path, so this runs
    identically inside Kart, where the real `config/verifiers.json` is not
    mounted (gap 4e1825878677).
    """
    home = tmp_path / "home"
    sessions = home / "sessions"
    sessions.mkdir(parents=True)
    monkeypatch.setenv("WILLOW_HOME", str(home))
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")

    ring_path = tmp_path / "verifiers.json"
    ring = keyring_mod.Keyring()
    ring.add("sean")
    ring_path.write_text(json.dumps(ring.to_json()), encoding="utf-8")
    monkeypatch.setenv("WILLOW_KEYRING", str(ring_path))
    keyring_mod.set_keyring(ring)
    human_session.clear_attribution_cache()

    session_id = "session_test_attested"
    verifier = "sean"
    attested_at = "2026-09-09T20:52:54Z"

    # The live session record, as session_bind leaves it: NO verifier field
    # content. This is the artifact the old check consulted.
    (sessions / f"willow-{session_id}.json").write_text(
        json.dumps({
            "app_id": "willow",
            "session_id": session_id,
            "status": "idle",
            "dispatch_id": "",
            "verifier": "",
            "updated_at": "2026-09-09T20:43:38Z",
        }),
        encoding="utf-8",
    )

    # The sidecar, as sign_session_cli writes it.
    payload = {
        "format": "orchestrator_session_attestation_v2",
        "app_id": "willow",
        "session_id": session_id,
        "verifier": verifier,
        "attested_at": attested_at,
    }
    sig_hex = session_signing.sign_session(
        app_id="willow", session_id=session_id,
        verifier=verifier, attested_at=attested_at,
    )
    attest = sessions / f"willow-{session_id}.attest.json"
    attest.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    (sessions / f"{attest.name}.sig").write_text(sig_hex + "\n", encoding="utf-8")

    try:
        yield session_id, verifier
    finally:
        keyring_mod.set_keyring(None)
        human_session.clear_attribution_cache()


def test_the_gate_passes_an_attested_session(attested_seat):
    """Precondition. If this fails the rest proves nothing."""
    session_id, _ = attested_seat
    assert human_session.orchestrator_write_denial(
        "willow", "envelope_propose", serve_mode=False, session_id=session_id
    ) is None


def test_the_blocker_agrees_with_the_gate(attested_seat):
    """THE REGRESSION. Against the old code this fails: the record's `verifier`
    is empty, so the blocker fired while the gate passed."""
    session_id, _ = attested_seat
    found = blockers.collect("willow", session_id)
    ids = [i["id"] for i in found["items"]]
    assert "session_unattested" not in ids, (
        "the seat reports unattested while the write gate accepts the same "
        f"session — blockers: {found['items']}"
    )


def test_an_unattested_session_is_still_reported(attested_seat, tmp_path):
    """The fix must not simply stop reporting. Remove the sidecar and the
    blocker returns, because now the gate refuses too."""
    session_id, _ = attested_seat
    sessions = tmp_path / "home" / "sessions"
    (sessions / f"willow-{session_id}.attest.json").unlink()
    (sessions / f"willow-{session_id}.attest.json.sig").unlink()
    human_session.clear_attribution_cache()

    found = blockers.collect("willow", session_id)
    item = next(i for i in found["items"] if i["id"] == "session_unattested")
    assert "never been attested" in item["summary"]


def test_the_reported_fix_names_home_and_keyring(attested_seat, tmp_path):
    """The remedy must run in a bare shell. Both vars live only in the MCP
    child's env block, so a command that omits them cannot work anywhere the
    operator can actually type."""
    session_id, _ = attested_seat
    sessions = tmp_path / "home" / "sessions"
    (sessions / f"willow-{session_id}.attest.json").unlink()
    (sessions / f"willow-{session_id}.attest.json.sig").unlink()
    human_session.clear_attribution_cache()

    item = next(i for i in blockers.collect("willow", session_id)["items"]
                if i["id"] == "session_unattested")
    fix = item["fix"]
    assert f"WILLOW_HOME={tmp_path / 'home'}" in fix
    assert f"WILLOW_KEYRING={tmp_path / 'verifiers.json'}" in fix
    assert "sign-session" in fix
    # One step. The old text told the operator to call session_enter again with
    # the hex of the .sig; PR3 made the sidecar the evidence and that second
    # step has been dead since.
    assert "session_enter" not in fix


def test_the_blocker_does_not_warm_the_cache(attested_seat):
    """`blockers` promises it adds no state. A seat-entry probe that warmed the
    attribution cache would make the NEXT write skip verification on the
    strength of a read-only report."""
    session_id, _ = attested_seat
    human_session.clear_attribution_cache()
    blockers.collect("willow", session_id)
    assert not human_session.is_session_attributed(session_id)


def test_the_blocker_does_not_clear_a_live_cache(attested_seat):
    """The other direction: nor may it invalidate an attribution the gate
    already earned."""
    session_id, _ = attested_seat
    human_session.orchestrator_write_denial(
        "willow", "envelope_propose", serve_mode=False, session_id=session_id
    )
    assert human_session.is_session_attributed(session_id)
    blockers.collect("willow", session_id)
    assert human_session.is_session_attributed(session_id)


def test_no_keyring_and_no_pgp_reports_nothing(attested_seat, monkeypatch):
    """The false positive in the other direction: with neither verifier
    configured the gate returns early and nothing refuses, so there is no
    blocker to report. The old check reported one on every session."""
    session_id, _ = attested_seat
    monkeypatch.delenv("WILLOW_KEYRING", raising=False)
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    keyring_mod.set_keyring(None)
    human_session.clear_attribution_cache()

    assert human_session.orchestrator_write_denial(
        "willow", "envelope_propose", serve_mode=False, session_id=session_id
    ) is None
    ids = [i["id"] for i in blockers.collect("willow", session_id)["items"]]
    assert "session_unattested" not in ids
