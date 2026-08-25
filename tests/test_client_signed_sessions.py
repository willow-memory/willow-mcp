"""Frozen wire contract for session-attestation signatures.

The bytes ``session_signing._message`` produces MUST NOT drift. A client-side
signer (PR3's ``willow-mcp sign-session`` CLI, or the operator's own tool)
reproduces these bytes independently — the two sides only agree if they
compute *identical* bytes. If any assertion in this file starts to fail, that
is a protocol version bump communicated to every out-of-process signer, not
a refactor. Mirrors ``nestor/tests/test_client_signed_seals.py``.

Includes the round-trip: a sign/verify pair through a real Ed25519 keypair
under the keyring. If the round-trip breaks, so does every future PR that
depends on client-side signing (PR3, PR4).
"""
from __future__ import annotations

import json

import pytest

from willow_mcp import keyring as keyring_mod
from willow_mcp import session_signing


# --- FROZEN wire bytes -----------------------------------------------------


def test_wire_message_bytes_are_frozen_ascii():
    """The exact bytes for a known input. If this ever changes, every
    out-of-process signer must be told (protocol version bump)."""
    got = session_signing._message(
        app_id="willow",
        session_id="s-01",
        verifier="rita",
        attested_at="2026-08-25T19:47:29Z",
    )
    expected = b'["willow","s-01","rita","2026-08-25T19:47:29Z"]'
    assert got == expected, (
        f"wire bytes drifted!\n  expected: {expected!r}\n  got:      {got!r}\n"
        "This is a wire contract, not an implementation detail. Bump the "
        "protocol version and tell every out-of-process signer."
    )


def test_wire_message_bytes_preserve_non_ascii_literally():
    """ensure_ascii=False — non-ASCII characters emitted literally, not
    \\uXXXX escaped."""
    got = session_signing._message(
        app_id="willow",
        session_id="s-café",
        verifier="rüdi",
        attested_at="2026-08-25T19:47:29Z",
    )
    # UTF-8 bytes, literal characters
    assert "café".encode("utf-8") in got
    assert "rüdi".encode("utf-8") in got
    # No \u escaped sequences
    assert b"\\u" not in got


def test_wire_message_has_no_whitespace():
    """separators=(",", ":") — no whitespace after , or :."""
    got = session_signing._message("a", "b", "c", "d")
    assert b", " not in got
    assert b": " not in got
    assert got == b'["a","b","c","d"]'


def test_field_order_is_pinned():
    """The order [app_id, session_id, verifier, attested_at] is part of the
    wire contract. Swapping fields = different bytes = a signature over one
    field-order does not verify under another."""
    a = session_signing._message("APP", "SES", "VER", "AT")
    parsed = json.loads(a.decode("utf-8"))
    assert parsed == ["APP", "SES", "VER", "AT"], (
        "field order changed — that is a protocol break"
    )


def test_wire_message_is_distinct_from_nestor_seal_message():
    """A Nestor seal signature reused as a willow session attestation must
    NOT verify. The two protocols encode different field sets in different
    orders — mixing them by accident is exactly the failure this test
    exists to prevent."""
    willow_bytes = session_signing._message("willow", "s1", "rita", "2026-01-01T00:00:00Z")
    # Nestor's message is [source_norm, target_text, verifier] — 3 elements,
    # not 4, and no timestamp. Verify by shape.
    parsed = json.loads(willow_bytes.decode("utf-8"))
    assert len(parsed) == 4, (
        "willow session message MUST have 4 elements; a Nestor seal has 3. "
        "This shape difference is what keeps a Nestor sig from silently "
        "verifying as a willow session attestation."
    )


# --- Round-trip through the keyring ----------------------------------------


@pytest.fixture
def ring_with_rita(tmp_path):
    """Install a keyring with a locally-generated Ed25519 verifier."""
    with keyring_mod.isolated():
        k = keyring_mod.Keyring(path=str(tmp_path / "keys.json"))
        k.add("rita")  # ed25519 default
        k.save()
        keyring_mod.set_keyring(k)
        try:
            yield k
        finally:
            keyring_mod.set_keyring(None)


def test_sign_then_verify_round_trips(ring_with_rita):
    sig = session_signing.sign_session(
        "willow", "s-1", "rita", "2026-08-25T19:47:29Z"
    )
    assert session_signing.session_is_valid(
        "willow", "s-1", "rita", "2026-08-25T19:47:29Z", sig
    )


def test_signature_invalidates_when_app_id_changes(ring_with_rita):
    sig = session_signing.sign_session(
        "willow", "s-1", "rita", "2026-08-25T19:47:29Z"
    )
    assert not session_signing.session_is_valid(
        "notwillow", "s-1", "rita", "2026-08-25T19:47:29Z", sig
    )


def test_signature_invalidates_when_session_id_changes(ring_with_rita):
    sig = session_signing.sign_session(
        "willow", "s-1", "rita", "2026-08-25T19:47:29Z"
    )
    assert not session_signing.session_is_valid(
        "willow", "s-2", "rita", "2026-08-25T19:47:29Z", sig
    )


def test_signature_invalidates_when_verifier_changes(ring_with_rita):
    """The whole point of the primitive: swapping the verifier name on a
    signed sidecar must not silently verify."""
    ring_with_rita.add("sam")
    sig = session_signing.sign_session(
        "willow", "s-1", "rita", "2026-08-25T19:47:29Z"
    )
    assert not session_signing.session_is_valid(
        "willow", "s-1", "sam", "2026-08-25T19:47:29Z", sig
    )


def test_signature_invalidates_when_attested_at_changes(ring_with_rita):
    sig = session_signing.sign_session(
        "willow", "s-1", "rita", "2026-08-25T19:47:29Z"
    )
    assert not session_signing.session_is_valid(
        "willow", "s-1", "rita", "2026-08-25T19:47:30Z", sig
    )


def test_empty_signature_is_never_valid(ring_with_rita):
    assert not session_signing.session_is_valid(
        "willow", "s-1", "rita", "2026-08-25T19:47:29Z", ""
    )


def test_verify_fails_for_unknown_verifier(ring_with_rita):
    """An unknown name returns False without raising — the raise happens
    only at session_enter (_resolve_session_sig)."""
    sig = session_signing.sign_session(
        "willow", "s-1", "rita", "2026-08-25T19:47:29Z"
    )
    assert not session_signing.session_is_valid(
        "willow", "s-1", "mallory", "2026-08-25T19:47:29Z", sig
    )


def test_verify_fails_for_compromised_verifier(ring_with_rita):
    """A compromised key's past signatures no longer verify (rita's whole
    body of attestations goes to sessions_unverifiable — that surface lands
    in PR4)."""
    sig = session_signing.sign_session(
        "willow", "s-1", "rita", "2026-08-25T19:47:29Z"
    )
    assert session_signing.session_is_valid(
        "willow", "s-1", "rita", "2026-08-25T19:47:29Z", sig
    )  # baseline
    ring_with_rita.revoke("rita", reason="stolen", compromised=True)
    assert not session_signing.session_is_valid(
        "willow", "s-1", "rita", "2026-08-25T19:47:29Z", sig
    )


def test_verify_succeeds_for_rotated_verifier_on_old_sig(ring_with_rita):
    """Rotated (not compromised) key: past attestations still verify —
    rita left, her past sessions still stand."""
    sig = session_signing.sign_session(
        "willow", "s-1", "rita", "2026-08-25T19:47:29Z"
    )
    ring_with_rita.revoke("rita", reason="left the team")
    assert session_signing.session_is_valid(
        "willow", "s-1", "rita", "2026-08-25T19:47:29Z", sig
    )


def test_signing_enabled_reflects_keyring_state(ring_with_rita, monkeypatch):
    assert session_signing.signing_enabled() is True
    keyring_mod.set_keyring(None)
    monkeypatch.delenv("WILLOW_KEYRING", raising=False)
    monkeypatch.setattr(keyring_mod, "_from_env", None)
    monkeypatch.setattr(keyring_mod, "_loaded_from", None)
    assert session_signing.signing_enabled() is False


# --- attribution surface (never for serving) ------------------------------


def test_session_attribution_reports_verifier_when_sig_valid(ring_with_rita):
    sig = session_signing.sign_session(
        "willow", "s-1", "rita", "2026-08-25T19:47:29Z"
    )
    assert (
        session_signing.session_attribution(
            "willow", "s-1", "rita", "2026-08-25T19:47:29Z", sig
        )
        == "verifier"
    )


def test_session_attribution_reports_unsigned_for_empty_sig(ring_with_rita):
    assert (
        session_signing.session_attribution(
            "willow", "s-1", "rita", "2026-08-25T19:47:29Z", ""
        )
        == "unsigned"
    )


def test_session_attribution_reports_none_for_bogus_sig(ring_with_rita):
    assert (
        session_signing.session_attribution(
            "willow", "s-1", "rita", "2026-08-25T19:47:29Z", "deadbeef" * 16
        )
        == "none"
    )
