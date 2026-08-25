"""session_enter with seal_sig — server verifies, never signs.

The load-bearing invariants:

* an invalid signature refuses BEFORE the session file is written to disk
  (mirrors nestor/memory.py::_resolve_seal_sig's discipline);
* a valid signature writes the verifier into the session record;
* legacy path (no keyring) proceeds unchanged.
"""
from __future__ import annotations

import pytest

from willow_mcp import dispatch, keyring as keyring_mod, session_signing


@pytest.fixture
def ring_with_rita(tmp_path):
    with keyring_mod.isolated():
        k = keyring_mod.Keyring(path=str(tmp_path / "keys.json"))
        k.add("rita")
        k.save()
        keyring_mod.set_keyring(k)
        try:
            yield k
        finally:
            keyring_mod.set_keyring(None)


# --- server verifies, never signs; refuses BEFORE disk write --------------


def test_bad_sig_raises_before_session_file_is_written(ring_with_rita, tmp_path, monkeypatch):
    """The invariant: no session record on disk after refusal."""
    session_file = dispatch.session_path("willow", "s-bad")
    assert not session_file.is_file()

    with pytest.raises(session_signing.InvalidSessionSignatureError, match="does not verify"):
        dispatch.session_enter(
            app_id="willow",
            session_id="s-bad",
            verifier="rita",
            attested_at="2026-08-25T00:00:00Z",
            seal_sig="deadbeef" * 16,  # syntactically valid hex, cryptographically bogus
        )
    assert not session_file.is_file(), (
        "session file exists after a refused signature — the invariant is "
        "that refusal comes BEFORE any write"
    )


def test_verifier_without_sig_refuses_when_keyring_enabled(ring_with_rita):
    session_file = dispatch.session_path("willow", "s-no-sig")
    assert not session_file.is_file()
    with pytest.raises(session_signing.InvalidSessionSignatureError, match="without seal_sig"):
        dispatch.session_enter(
            app_id="willow", session_id="s-no-sig", verifier="rita"
        )
    assert not session_file.is_file()


def test_sig_without_verifier_refuses_when_keyring_enabled(ring_with_rita):
    session_file = dispatch.session_path("willow", "s-no-verifier")
    assert not session_file.is_file()
    with pytest.raises(session_signing.InvalidSessionSignatureError, match="without verifier"):
        dispatch.session_enter(
            app_id="willow",
            session_id="s-no-verifier",
            seal_sig="00" * 64,
        )
    assert not session_file.is_file()


def test_missing_attested_at_refuses(ring_with_rita):
    session_file = dispatch.session_path("willow", "s-no-at")
    assert not session_file.is_file()
    with pytest.raises(session_signing.InvalidSessionSignatureError, match="attested_at is empty"):
        dispatch.session_enter(
            app_id="willow",
            session_id="s-no-at",
            verifier="rita",
            seal_sig="00" * 64,
        )
    assert not session_file.is_file()


# --- valid signature writes the verifier to the session record ------------


def test_valid_sig_writes_verifier_to_session_record(ring_with_rita):
    sig = session_signing.sign_session(
        "willow", "s-ok", "rita", "2026-08-25T00:00:00Z"
    )
    result = dispatch.session_enter(
        app_id="willow",
        session_id="s-ok",
        verifier="rita",
        attested_at="2026-08-25T00:00:00Z",
        seal_sig=sig,
    )
    assert result.get("entry_mode") == "human_orchestrator"
    assert not result.get("error")

    record = dispatch.session_read("willow", "s-ok")
    assert record["verifier"] == "rita", (
        f"session record must name the verifier; got {record}"
    )
    assert record["app_id"] == "willow"
    assert record["session_id"] == "s-ok"


def test_verifier_survives_a_subsequent_bind(ring_with_rita):
    """A later status change (dispatch_accept, etc) must not overwrite the
    verifier with empty. session_bind's prior-record read guards this."""
    sig = session_signing.sign_session(
        "willow", "s-persist", "rita", "2026-08-25T00:00:00Z"
    )
    dispatch.session_enter(
        app_id="willow",
        session_id="s-persist",
        verifier="rita",
        attested_at="2026-08-25T00:00:00Z",
        seal_sig=sig,
    )
    dispatch.session_bind("willow", "s-persist", "", "working")
    record = dispatch.session_read("willow", "s-persist")
    assert record["verifier"] == "rita", (
        "verifier was overwritten by a later session_bind — "
        "session_bind must preserve prior verifier when the caller passes empty"
    )
    assert record["status"] == "working"


# --- legacy path: no keyring → three params are ignored -------------------


def test_no_keyring_ignores_verifier_and_sig(tmp_path, monkeypatch):
    """Pre-PR2 behavior is verbatim when keyring is disabled: even a
    bogus seal_sig doesn't raise."""
    keyring_mod.set_keyring(None)
    monkeypatch.delenv("WILLOW_KEYRING", raising=False)
    monkeypatch.setattr(keyring_mod, "_from_env", None)
    monkeypatch.setattr(keyring_mod, "_loaded_from", None)

    assert not session_signing.signing_enabled()

    result = dispatch.session_enter(
        app_id="willow",
        session_id="s-legacy",
        verifier="rita",  # ignored
        attested_at="2026-08-25T00:00:00Z",  # ignored
        seal_sig="deadbeef" * 16,  # ignored — would raise if keyring were on
    )
    assert result.get("entry_mode") == "human_orchestrator"
    assert not result.get("error")

    record = dispatch.session_read("willow", "s-legacy")
    # verifier field is present but empty (backward-compatible field addition)
    assert record.get("verifier", "") == ""


def test_legacy_path_writes_no_verifier_when_nothing_supplied(tmp_path, monkeypatch):
    """The pre-PR2 caller signature (no verifier/attested_at/seal_sig) is
    the majority backward-compat case."""
    keyring_mod.set_keyring(None)
    monkeypatch.delenv("WILLOW_KEYRING", raising=False)
    monkeypatch.setattr(keyring_mod, "_from_env", None)
    monkeypatch.setattr(keyring_mod, "_loaded_from", None)

    result = dispatch.session_enter(
        app_id="willow", session_id="s-classic"
    )
    assert result.get("entry_mode") == "human_orchestrator"
    record = dispatch.session_read("willow", "s-classic")
    assert record.get("verifier", "") == ""


# --- keyring enabled but nothing supplied → downgrade -----------------------


def test_keyring_enabled_but_no_verifier_downgrades(ring_with_rita):
    """When the keyring is on and the caller supplies neither verifier nor
    seal_sig, we do NOT raise — matches by_human_attested's downgrade shape.
    The session record lands with verifier="", which is unattested."""
    result = dispatch.session_enter(
        app_id="willow", session_id="s-downgrade"
    )
    assert result.get("entry_mode") == "human_orchestrator"
    assert not result.get("error")
    record = dispatch.session_read("willow", "s-downgrade")
    assert record.get("verifier", "") == ""


# --- specialist branch: params ignored (PR2 scope is orchestrator only) ----


def test_specialist_branch_ignores_verifier(ring_with_rita, tmp_path):
    """Attribution propagation to specialists is out of scope for PR2.
    A specialist session_enter with verifier=rita must not refuse and must
    not attribute the specialist session to rita."""
    result = dispatch.session_enter(
        app_id="hanuman",
        session_id="s-hanuman",
        verifier="rita",
        attested_at="2026-08-25T00:00:00Z",
        seal_sig="deadbeef" * 16,  # not verified for specialist branch
    )
    # Hanuman may fail for a different reason (unknown app, no manifest, etc)
    # — but NOT for signature invalidity, because we don't route the check
    # through the specialist branch.
    if not result.get("error"):
        record = dispatch.session_read("hanuman", "s-hanuman")
        # PR2: verifier does not land on specialist records; that's PR4+ scope
        assert record.get("verifier", "") == ""
