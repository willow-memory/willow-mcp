"""PR4: sessions_unverifiable read-only surface.

Enumerates orchestrator sessions whose attestation sidecar exists but no
longer verifies — the operator-facing trust-view an operator needs after
a keyring compromise, a rotation, or a tampered sidecar.
"""
from __future__ import annotations

import argparse
import json
from unittest import mock

import pytest

from willow_mcp import (
    dispatch,
    human_session,
    keyring as keyring_mod,
    paths,
    session_signing,
    sign_session_cli,
)


@pytest.fixture
def ring_with_rita(tmp_path):
    """conftest.py points $WILLOW_HOME at a session-scoped tmp dir so all
    tests share sessions/. list_unverifiable_sessions() globs that directory
    — clean it between tests so leftovers from prior tests don't leak
    into ours."""
    human_session.clear_attribution_cache()
    sd = paths.sessions_dir()
    if sd.is_dir():
        for p in sd.glob("willow-*"):
            p.unlink()
    with keyring_mod.isolated():
        k = keyring_mod.Keyring(path=str(tmp_path / "keys.json"))
        k.add("rita")
        k.save()
        keyring_mod.set_keyring(k)
        try:
            yield k
        finally:
            keyring_mod.set_keyring(None)
            human_session.clear_attribution_cache()
            if sd.is_dir():
                for p in sd.glob("willow-*"):
                    p.unlink()


def _attest(session_id: str, verifier: str = "rita"):
    sig = session_signing.sign_session(
        "willow", session_id, verifier, "2026-08-25T00:00:00Z"
    )
    dispatch.session_enter(
        app_id="willow",
        session_id=session_id,
        verifier=verifier,
        attested_at="2026-08-25T00:00:00Z",
        seal_sig=sig,
    )
    ns = argparse.Namespace(session_id=session_id, verifier=verifier)
    with mock.patch.object(human_session, "require_operator_terminal", lambda: None):
        assert sign_session_cli.cmd_sign_session(ns) == sign_session_cli.EXIT_OK


def test_returns_empty_when_no_sessions_dir():
    """A fresh state with no sessions/ directory returns [] rather than raising."""
    assert human_session.list_unverifiable_sessions() == []


def test_returns_empty_when_all_sidecars_verify(ring_with_rita):
    _attest("s-ok-1")
    _attest("s-ok-2")
    got = human_session.list_unverifiable_sessions()
    assert got == []


def test_lists_tampered_v2_sidecar(ring_with_rita):
    _attest("s-tampered")
    # Tamper: swap the verifier field on the signed sidecar
    ring_with_rita.add("sam")
    ring_with_rita.save()
    attest = paths.session_attestation_path("willow", "s-tampered")
    payload = json.loads(attest.read_text(encoding="utf-8"))
    payload["verifier"] = "sam"
    attest.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    got = human_session.list_unverifiable_sessions()
    assert len(got) == 1
    row = got[0]
    assert row["session_id"] == "s-tampered"
    assert row["verifier"] == "sam"  # tampered value shows through, that's the point
    assert row["format"] == "orchestrator_session_attestation_v2"
    assert "does not verify" in row["reason"]


def test_lists_session_after_compromise_revocation(ring_with_rita):
    """After keys revoke --compromised, all sessions attested by that
    verifier land here — this is the surface the operator uses to plan
    re-attestation."""
    _attest("s-a")
    _attest("s-b")
    # Baseline: none unverifiable
    assert human_session.list_unverifiable_sessions() == []

    ring_with_rita.revoke("rita", reason="stolen", compromised=True)
    ring_with_rita.save()

    got = human_session.list_unverifiable_sessions()
    got_ids = sorted(r["session_id"] for r in got)
    assert got_ids == ["s-a", "s-b"]
    for row in got:
        assert row["verifier"] == "rita"
        assert row["format"] == "orchestrator_session_attestation_v2"


def test_excludes_verifying_sessions_after_partial_compromise(ring_with_rita):
    """Only sessions signed by the compromised key land in the list;
    sessions signed by another (still trusted) verifier keep verifying."""
    ring_with_rita.add("sam")
    ring_with_rita.save()

    _attest("s-rita", verifier="rita")
    _attest("s-sam", verifier="sam")

    ring_with_rita.revoke("rita", reason="stolen", compromised=True)
    ring_with_rita.save()

    got = human_session.list_unverifiable_sessions()
    ids = sorted(r["session_id"] for r in got)
    assert ids == ["s-rita"], (
        f"only s-rita's sidecar should be unverifiable; got {ids}"
    )


def test_ignores_sessions_with_no_sidecar(ring_with_rita):
    """A session that was entered but never attested has no sidecar and is
    NOT listed here — that's unattested, not unverifiable."""
    # Enter but don't sign
    dispatch.session_enter(app_id="willow", session_id="s-no-sidecar")
    assert human_session.list_unverifiable_sessions() == []


def test_ignores_sidecar_with_missing_sig_file(ring_with_rita):
    """If the .sig file is missing, the sidecar is not in a verifiable state
    but is also not the operator-facing signal here — it's a broken pair,
    not a compromised one."""
    _attest("s-sig-gone")
    sig_file = (
        paths.session_attestation_path("willow", "s-sig-gone").parent
        / f"{paths.session_attestation_path('willow', 's-sig-gone').name}.sig"
    )
    sig_file.unlink()
    assert human_session.list_unverifiable_sessions() == []


def test_returns_sorted_by_session_id(ring_with_rita):
    """Deterministic output — glob results sorted for stable operator UX."""
    ring_with_rita.add("sam")
    ring_with_rita.save()

    _attest("s-charlie", verifier="rita")
    _attest("s-alpha", verifier="rita")
    _attest("s-bravo", verifier="rita")

    ring_with_rita.revoke("rita", compromised=True)
    ring_with_rita.save()

    got = human_session.list_unverifiable_sessions()
    ids = [r["session_id"] for r in got]
    assert ids == sorted(ids)
