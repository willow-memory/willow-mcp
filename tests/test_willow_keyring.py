"""willow_mcp.keyring — per-verifier identity, ported from Nestor #5.8.

Same behaviors as ``nestor/tests/test_keyring.py`` but scoped to the keyring
primitive itself (PR1 of the identity-in-session plan). Later PRs land the
wiring at ``session_enter`` / ``orchestrator_write_denial`` and cover those
integrations in their own tests. If any of these assertions ever needs to be
weakened, that is a covenant regression — see ``docs/covenant-lineage.md`` in
the Nestor repo for why.
"""
import json
import os
import stat

import pytest

from willow_mcp import keyring as keyring_mod


@pytest.fixture
def ring(tmp_path):
    """A ring with two verifiers on disk, then installed process-wide.

    ``isolated()`` covers the case a caller has ``WILLOW_KEYRING`` exported
    in their shell — without it, ``load()`` would fight the fixture.
    """
    with keyring_mod.isolated():
        k = keyring_mod.Keyring(path=str(tmp_path / "keyring.json"))
        k.add("rita")
        k.add("sam")
        k.save()
        keyring_mod.set_keyring(k)
        try:
            yield k
        finally:
            keyring_mod.set_keyring(None)


# --- what an attestation now proves -----------------------------------------


def test_a_name_the_keyring_does_not_know_cannot_sign(ring):
    """The whole point of the primitive: unknown names cannot attest."""
    with pytest.raises(keyring_mod.UnknownVerifierError, match="not in the keyring"):
        ring.signing_entry("mallory")


def test_signing_entry_returns_the_named_verifier(ring):
    entry = ring.signing_entry("rita")
    assert entry.name == "rita"
    assert entry.kind == "ed25519"
    assert entry.private, "locally-generated ed25519 must carry the private half"


def test_a_public_only_ed25519_entry_cannot_sign(ring, tmp_path):
    """Nestor#17's acceptance property: a keyring that can verify a peer must
    not be able to sign as them. The refusal happens at signing_entry, before
    any attestation is written."""
    ring.add("peer", key=os.urandom(32), kind="ed25519")  # register PUBLIC key only
    with pytest.raises(keyring_mod.KeyringError, match="PUBLIC key"):
        ring.signing_entry("peer")


# --- revocation: the question the operator has to answer --------------------


def test_a_rotated_key_keeps_its_verifying_ability(ring):
    """rita left. Nobody else held her key, so her past attestations still stand."""
    ring.revoke("rita", reason="left the team")
    assert ring.status("rita") == "revoked"
    assert ring.verifying_key("rita") is not None, (
        "verifying_key must still resolve — past attestations still serve"
    )
    with pytest.raises(keyring_mod.RevokedKeyError, match="cannot make new"):
        ring.signing_entry("rita")


def test_a_compromised_key_loses_all_trust(ring):
    """An HMAC (or a stolen ed25519 private half) carries no timestamp, so
    nothing it signed can be told apart from what the thief signed — none of
    it verifies."""
    ring.revoke("sam", reason="laptop stolen", compromised=True)
    assert ring.status("sam") == "compromised"
    assert ring.verifying_key("sam") is None, (
        "compromised keys must not verify anything — past or new"
    )
    with pytest.raises(keyring_mod.RevokedKeyError):
        ring.signing_entry("sam")


def test_compromised_is_one_way(ring):
    """A key reported stolen does not become un-stolen because a later call
    forgot to say so."""
    ring.revoke("sam", compromised=True)
    ring.revoke("sam", reason="second thoughts")  # no compromised= flag this time
    assert ring.status("sam") == "compromised"


def test_status_covers_the_four_states(ring):
    assert ring.status("rita") == "active"
    assert ring.status("mallory") == "unknown"
    ring.revoke("rita")
    assert ring.status("rita") == "revoked"
    ring.revoke("sam", compromised=True)
    assert ring.status("sam") == "compromised"


# --- rotate ---------------------------------------------------------------


def test_rotating_a_key_needs_saying_so(ring):
    """Overwriting a key by accident silently invalidates every attestation
    that verifier ever made — not something a typo should be able to do."""
    with pytest.raises(keyring_mod.KeyringError, match="already has a key"):
        ring.add("rita")
    old_key = ring.get("rita").key
    new_entry = ring.add("rita", rotate=True)
    assert new_entry.key != old_key


# --- persistence ----------------------------------------------------------


def test_save_and_load_round_trip(tmp_path):
    path = str(tmp_path / "keys.json")
    k = keyring_mod.Keyring(path=path)
    k.add("rita")
    k.add("sam")
    k.revoke("sam", reason="test", compromised=True)
    k.save()

    with keyring_mod.isolated():
        loaded = keyring_mod.load(path)
    assert set(loaded.names()) == {"rita", "sam"}
    assert loaded.status("rita") == "active"
    assert loaded.status("sam") == "compromised"
    assert loaded.get("sam").reason == "test"


def test_save_writes_0600(tmp_path):
    path = str(tmp_path / "keys.json")
    k = keyring_mod.Keyring(path=path)
    k.add("rita")
    k.save()
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600, (
        f"keyring must be 0600 (found {oct(mode)}) — same reason ssh refuses "
        f"group-readable private keys"
    )


def test_load_refuses_group_readable_secret_material(tmp_path):
    path = str(tmp_path / "keys.json")
    k = keyring_mod.Keyring(path=path)
    k.add("rita")  # ed25519 with private half — secret material
    k.save()
    os.chmod(path, 0o640)
    with keyring_mod.isolated():
        with pytest.raises(keyring_mod.KeyringError, match="readable by other users"):
            keyring_mod.load(path)


def test_load_accepts_group_readable_when_only_public_keys(tmp_path):
    """A keyring holding only ed25519 public keys is distributable — commit
    it, mirror it, hand it to a peer for import."""
    path = str(tmp_path / "keys.json")
    # Write a public-only keyring by hand (add() with peer key = public only)
    k = keyring_mod.Keyring(path=path)
    k.add("peer", key=os.urandom(32), kind="ed25519")
    k.save()
    os.chmod(path, 0o644)
    with keyring_mod.isolated():
        loaded = keyring_mod.load(path)
    assert loaded.get("peer") is not None
    assert not loaded.get("peer").private


def test_load_refuses_missing_file(tmp_path):
    with keyring_mod.isolated():
        with pytest.raises(keyring_mod.KeyringError, match="no keyring"):
            keyring_mod.load(str(tmp_path / "nope.json"))


def test_load_refuses_non_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("not json {", encoding="utf-8")
    os.chmod(str(path), 0o600)
    with keyring_mod.isolated():
        with pytest.raises(keyring_mod.KeyringError, match="not valid JSON"):
            keyring_mod.load(str(path))


def test_from_json_refuses_unknown_kind(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(
        json.dumps({"version": 1, "verifiers": [
            {"name": "rita", "key": "abcd", "kind": "rot13"}
        ]}),
        encoding="utf-8",
    )
    os.chmod(str(path), 0o600)
    with keyring_mod.isolated():
        with pytest.raises(keyring_mod.KeyringError, match="unknown kind"):
            keyring_mod.load(str(path))


def test_from_json_refuses_wrong_length_ed25519_public(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(
        json.dumps({"version": 1, "verifiers": [
            {"name": "rita", "key": "abcd", "kind": "ed25519"}
        ]}),
        encoding="utf-8",
    )
    os.chmod(str(path), 0o600)
    with keyring_mod.isolated():
        with pytest.raises(keyring_mod.KeyringError, match="must be 32 bytes"):
            keyring_mod.load(str(path))


# --- process-wide resolution ----------------------------------------------


def test_injected_keyring_wins_over_env(tmp_path, monkeypatch):
    """Set the env AND inject — the injection is the caller's explicit intent."""
    env_path = tmp_path / "env.json"
    inj_path = tmp_path / "inj.json"

    env_ring = keyring_mod.Keyring(path=str(env_path))
    env_ring.add("env_verifier")
    env_ring.save()

    inj_ring = keyring_mod.Keyring(path=str(inj_path))
    inj_ring.add("inj_verifier")
    inj_ring.save()

    monkeypatch.setenv("WILLOW_KEYRING", str(env_path))
    keyring_mod.set_keyring(inj_ring)
    try:
        got = keyring_mod.get_keyring()
        assert got is inj_ring
        assert "inj_verifier" in got
        assert "env_verifier" not in got
    finally:
        keyring_mod.set_keyring(None)


def test_env_keyring_loads_when_no_injection(tmp_path, monkeypatch):
    path = str(tmp_path / "env.json")
    k = keyring_mod.Keyring(path=path)
    k.add("rita")
    k.save()

    keyring_mod.set_keyring(None)  # ensure no injection
    # Bust the env cache by moving the env var — clean state
    monkeypatch.setattr(keyring_mod, "_from_env", None)
    monkeypatch.setattr(keyring_mod, "_loaded_from", None)
    monkeypatch.setenv("WILLOW_KEYRING", path)

    got = keyring_mod.get_keyring()
    assert got is not None
    assert "rita" in got


def test_enabled_reflects_configuration(tmp_path, monkeypatch):
    keyring_mod.set_keyring(None)
    monkeypatch.setattr(keyring_mod, "_from_env", None)
    monkeypatch.setattr(keyring_mod, "_loaded_from", None)
    monkeypatch.delenv("WILLOW_KEYRING", raising=False)
    assert keyring_mod.enabled() is False

    k = keyring_mod.Keyring()
    keyring_mod.set_keyring(k)
    try:
        assert keyring_mod.enabled() is True
    finally:
        keyring_mod.set_keyring(None)


def test_isolated_pops_env_and_injection(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_KEYRING", str(tmp_path / "keys.json"))
    k = keyring_mod.Keyring()
    keyring_mod.set_keyring(k)
    try:
        with keyring_mod.isolated():
            assert keyring_mod.get_keyring() is None
            assert "WILLOW_KEYRING" not in os.environ
        # restored on exit
        assert os.environ.get("WILLOW_KEYRING") == str(tmp_path / "keys.json")
        assert keyring_mod.get_keyring() is k
    finally:
        keyring_mod.set_keyring(None)


# --- opt-in semantics -----------------------------------------------------


def test_no_env_no_injection_means_disabled(monkeypatch):
    """The whole legacy path stays untouched when nobody configures a keyring."""
    keyring_mod.set_keyring(None)
    monkeypatch.setattr(keyring_mod, "_from_env", None)
    monkeypatch.setattr(keyring_mod, "_loaded_from", None)
    monkeypatch.delenv("WILLOW_KEYRING", raising=False)
    assert keyring_mod.get_keyring() is None
    assert keyring_mod.enabled() is False
