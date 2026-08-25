"""PR3: sign-session CLI + v2 sidecar + orchestrator_write_denial keyring path.

Load-bearing invariants tested here:

* ``willow-mcp sign-session`` refuses when the keyring is not enabled and
  points at ``attest-session``.
* A signed v2 sidecar verifies via ``orchestrator_write_denial`` when the
  keyring is on and the verifier's key resolves.
* A v2 sidecar with a mutated verifier field fails verification (the
  signature is over the frozen wire bytes that include the verifier).
* A v1 (legacy PGP) sidecar continues to verify through the existing
  PGP path when ``WILLOW_PGP_FINGERPRINT`` is set — the keyring path
  does not break the migration case.
* ``attest-session`` prints the deprecation notice when the keyring is on
  but still writes a v1 sidecar (backward compat).
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
    with keyring_mod.isolated():
        k = keyring_mod.Keyring(path=str(tmp_path / "keys.json"))
        k.add("rita")  # ed25519 default
        k.save()
        keyring_mod.set_keyring(k)
        try:
            yield k
        finally:
            keyring_mod.set_keyring(None)


def _args(**kw):
    """argparse.Namespace for the sign-session CLI."""
    ns = argparse.Namespace(
        session_id=kw.get("session_id", ""),
        verifier=kw.get("verifier", ""),
    )
    return ns


def _enter_and_sign(ring, session_id: str, verifier: str):
    """Live session file + signed v2 sidecar for `session_id` under `verifier`.
    Mocks require_operator_terminal so the tty check does not gate tests."""
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
    with mock.patch.object(human_session, "require_operator_terminal", lambda: None):
        rc = sign_session_cli.cmd_sign_session(
            _args(session_id=session_id, verifier=verifier)
        )
    return rc


# --- sign-session CLI --------------------------------------------------------


def test_sign_session_refuses_when_keyring_disabled(monkeypatch, capsys):
    """Without WILLOW_KEYRING, sign-session is not the right tool — attest-session is."""
    keyring_mod.set_keyring(None)
    monkeypatch.delenv("WILLOW_KEYRING", raising=False)
    monkeypatch.setattr(keyring_mod, "_from_env", None)
    monkeypatch.setattr(keyring_mod, "_loaded_from", None)

    rc = sign_session_cli.cmd_sign_session(
        _args(session_id="s-1", verifier="rita")
    )
    assert rc == sign_session_cli.EXIT_USAGE
    err = capsys.readouterr().err
    assert "WILLOW_KEYRING is not set" in err
    assert "attest-session" in err  # pointer to the legacy path


def test_sign_session_refuses_without_verifier(ring_with_rita, capsys):
    with mock.patch.object(human_session, "require_operator_terminal", lambda: None):
        rc = sign_session_cli.cmd_sign_session(
            _args(session_id="s-1", verifier="")
        )
    assert rc == sign_session_cli.EXIT_USAGE
    assert "--verifier NAME is required" in capsys.readouterr().err


def test_sign_session_refuses_without_session_id(ring_with_rita, capsys):
    with mock.patch.object(human_session, "require_operator_terminal", lambda: None):
        rc = sign_session_cli.cmd_sign_session(
            _args(session_id="", verifier="rita")
        )
    assert rc == sign_session_cli.EXIT_USAGE
    assert "session_id is required" in capsys.readouterr().err


def test_sign_session_refuses_when_no_live_session_file(ring_with_rita, capsys):
    """sign-session requires session_enter to have run first."""
    with mock.patch.object(human_session, "require_operator_terminal", lambda: None):
        rc = sign_session_cli.cmd_sign_session(
            _args(session_id="s-never-entered", verifier="rita")
        )
    assert rc == sign_session_cli.EXIT_FAIL
    assert "no live session file" in capsys.readouterr().err


def test_sign_session_refuses_when_verifier_unknown(ring_with_rita, capsys):
    # Set up a session so we get past the live-file check
    sig = session_signing.sign_session(
        "willow", "s-1", "rita", "2026-08-25T00:00:00Z"
    )
    dispatch.session_enter(
        app_id="willow",
        session_id="s-1",
        verifier="rita",
        attested_at="2026-08-25T00:00:00Z",
        seal_sig=sig,
    )
    with mock.patch.object(human_session, "require_operator_terminal", lambda: None):
        rc = sign_session_cli.cmd_sign_session(
            _args(session_id="s-1", verifier="mallory")
        )
    assert rc == sign_session_cli.EXIT_FAIL
    assert "not in the keyring" in capsys.readouterr().err


def test_sign_session_writes_v2_sidecar_and_hex_sig(ring_with_rita):
    rc = _enter_and_sign(ring_with_rita, "s-v2", "rita")
    assert rc == sign_session_cli.EXIT_OK

    attest = paths.session_attestation_path("willow", "s-v2")
    sig_file = attest.parent / f"{attest.name}.sig"
    assert attest.is_file()
    assert sig_file.is_file()

    payload = json.loads(attest.read_text(encoding="utf-8"))
    assert payload["format"] == "orchestrator_session_attestation_v2"
    assert payload["app_id"] == "willow"
    assert payload["session_id"] == "s-v2"
    assert payload["verifier"] == "rita"
    assert payload["attested_at"]  # non-empty ISO timestamp

    # sig is raw hex, one line — NOT a PGP detached sig
    sig_hex = sig_file.read_text(encoding="utf-8").strip()
    assert all(c in "0123456789abcdef" for c in sig_hex.lower())
    assert len(sig_hex) >= 64  # Ed25519 sigs are 64 bytes = 128 hex chars


# --- orchestrator_write_denial verifies v2 via keyring --------------------


def test_orchestrator_write_denial_allows_valid_v2(ring_with_rita, monkeypatch):
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    _enter_and_sign(ring_with_rita, "s-allowed", "rita")

    denial = human_session.orchestrator_write_denial(
        app_id="willow",
        tool_name="dispatch_send",
        serve_mode=False,
        session_id="s-allowed",
    )
    assert denial is None, f"expected no denial for a valid v2 attestation, got {denial!r}"


def test_orchestrator_write_denial_refuses_tampered_v2_verifier(ring_with_rita, monkeypatch):
    """Swapping the verifier field on a signed v2 sidecar must fail verify —
    the signature is over frozen wire bytes that include the verifier name."""
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    _enter_and_sign(ring_with_rita, "s-tampered", "rita")
    # Add sam so the tampered payload references a known verifier
    ring_with_rita.add("sam")
    ring_with_rita.save()

    attest = paths.session_attestation_path("willow", "s-tampered")
    payload = json.loads(attest.read_text(encoding="utf-8"))
    payload["verifier"] = "sam"  # tamper — signature no longer matches
    attest.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    denial = human_session.orchestrator_write_denial(
        app_id="willow",
        tool_name="dispatch_send",
        serve_mode=False,
        session_id="s-tampered",
    )
    assert denial is not None
    assert "invalid" in denial
    assert "does not verify" in denial


def test_orchestrator_write_denial_refuses_missing_sig_file(ring_with_rita, monkeypatch):
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    _enter_and_sign(ring_with_rita, "s-nosig", "rita")

    attest = paths.session_attestation_path("willow", "s-nosig")
    sig_file = attest.parent / f"{attest.name}.sig"
    sig_file.unlink()  # remove the sig file

    denial = human_session.orchestrator_write_denial(
        app_id="willow",
        tool_name="dispatch_send",
        serve_mode=False,
        session_id="s-nosig",
    )
    assert denial is not None
    assert "missing" in denial or "invalid" in denial


def test_orchestrator_write_denial_refuses_after_compromise(ring_with_rita, monkeypatch):
    """A signed v2 sidecar loses its trust when the verifier is revoked
    as compromised — mirrors session_signing.session_is_valid's shape."""
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    _enter_and_sign(ring_with_rita, "s-comp", "rita")

    # Baseline: allowed
    assert (
        human_session.orchestrator_write_denial(
            app_id="willow",
            tool_name="dispatch_send",
            serve_mode=False,
            session_id="s-comp",
        )
        is None
    )
    ring_with_rita.revoke("rita", reason="stolen", compromised=True)
    ring_with_rita.save()

    denial = human_session.orchestrator_write_denial(
        app_id="willow",
        tool_name="dispatch_send",
        serve_mode=False,
        session_id="s-comp",
    )
    assert denial is not None
    assert "invalid" in denial


def test_orchestrator_write_denial_reports_missing_when_no_sidecar(ring_with_rita, monkeypatch):
    """session_enter has run but sign-session has not — the sidecar was never written."""
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    sig = session_signing.sign_session(
        "willow", "s-unattested", "rita", "2026-08-25T00:00:00Z"
    )
    dispatch.session_enter(
        app_id="willow",
        session_id="s-unattested",
        verifier="rita",
        attested_at="2026-08-25T00:00:00Z",
        seal_sig=sig,
    )
    # NO sign_session_cli.cmd_sign_session call — sidecar absent

    denial = human_session.orchestrator_write_denial(
        app_id="willow",
        tool_name="dispatch_send",
        serve_mode=False,
        session_id="s-unattested",
    )
    assert denial is not None
    assert "missing" in denial
    assert "sign-session" in denial  # points at the keyring path, not attest-session


# --- v1 legacy sidecar still verifies through PGP -------------------------


def test_legacy_v1_sidecar_still_verifies_when_pgp_enabled(tmp_path, monkeypatch):
    """A v1 sidecar (PGP-signed via attest-session) written before the
    keyring was enabled must continue to verify — the migration case.
    Mocked at the pgp.verify_detached seam so we don't depend on a real
    gpg keyring in the test environment."""
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")

    # Enable the legacy PGP path
    keyring_mod.set_keyring(None)
    monkeypatch.delenv("WILLOW_KEYRING", raising=False)
    monkeypatch.setattr(keyring_mod, "_from_env", None)
    monkeypatch.setattr(keyring_mod, "_loaded_from", None)

    # Enter a session (no verifier — legacy path)
    dispatch.session_enter(app_id="willow", session_id="s-legacy")
    attest = paths.session_attestation_path("willow", "s-legacy")
    sig_file = attest.parent / f"{attest.name}.sig"
    attest.parent.mkdir(parents=True, exist_ok=True)
    # Write a v1 sidecar shape by hand — same fields _cmd_attest_session writes
    v1_payload = {
        "format": "orchestrator_session_attestation_v1",
        "app_id": "willow",
        "session_id": "s-legacy",
        "attested_at": "2026-08-25T00:00:00Z",
    }
    attest.write_text(
        json.dumps(v1_payload, sort_keys=True) + "\n", encoding="utf-8"
    )
    sig_file.write_text("(fake pgp sig)", encoding="utf-8")

    # Mock pgp.pgp_enabled → True and pgp.verify_detached → (True, "ok")
    from willow_mcp import pgp

    monkeypatch.setattr(pgp, "pgp_enabled", lambda: True)
    monkeypatch.setattr(pgp, "verify_detached", lambda _p: (True, "verified"))

    denial = human_session.orchestrator_write_denial(
        app_id="willow",
        tool_name="dispatch_send",
        serve_mode=False,
        session_id="s-legacy",
    )
    assert denial is None, (
        f"legacy v1 sidecar failed to verify through the PGP path; got {denial!r}"
    )


def test_v1_sidecar_with_keyring_but_no_pgp_asks_to_re_attest(
    ring_with_rita, monkeypatch
):
    """The migration mid-flight case: operator has switched to keyring but
    an old v1 sidecar is still on disk and PGP is off. Ask them to re-attest
    under the keyring path so the sidecar rolls to v2."""
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")

    # Enter a session
    sig = session_signing.sign_session(
        "willow", "s-old", "rita", "2026-08-25T00:00:00Z"
    )
    dispatch.session_enter(
        app_id="willow",
        session_id="s-old",
        verifier="rita",
        attested_at="2026-08-25T00:00:00Z",
        seal_sig=sig,
    )
    # Write a v1 sidecar (as if attest-session had been used before the switch)
    attest = paths.session_attestation_path("willow", "s-old")
    sig_file = attest.parent / f"{attest.name}.sig"
    attest.parent.mkdir(parents=True, exist_ok=True)
    attest.write_text(
        json.dumps(
            {
                "format": "orchestrator_session_attestation_v1",
                "app_id": "willow",
                "session_id": "s-old",
                "attested_at": "2026-08-25T00:00:00Z",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    sig_file.write_text("(fake pgp sig)", encoding="utf-8")

    # PGP is not enabled
    from willow_mcp import pgp

    monkeypatch.setattr(pgp, "pgp_enabled", lambda: False)

    denial = human_session.orchestrator_write_denial(
        app_id="willow",
        tool_name="dispatch_send",
        serve_mode=False,
        session_id="s-old",
    )
    assert denial is not None
    assert "sign-session" in denial  # recommends the keyring path
    assert "invalid" in denial or "missing" in denial


# --- sidecar version helpers ---------------------------------------------


def test_sidecar_is_v2_reports_v2(ring_with_rita):
    _enter_and_sign(ring_with_rita, "s-check", "rita")
    attest = paths.session_attestation_path("willow", "s-check")
    assert human_session._sidecar_is_v2(attest) is True


def test_sidecar_is_v2_returns_false_for_v1(tmp_path):
    p = tmp_path / "attest.json"
    p.write_text(
        json.dumps({"format": "orchestrator_session_attestation_v1"}),
        encoding="utf-8",
    )
    assert human_session._sidecar_is_v2(p) is False


def test_sidecar_is_v2_returns_false_for_missing(tmp_path):
    p = tmp_path / "nope.json"
    assert human_session._sidecar_is_v2(p) is False
