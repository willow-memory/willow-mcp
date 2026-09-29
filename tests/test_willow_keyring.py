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
from willow_mcp import reloader as reloader_mod


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



# --- net-signer-unit fallback resolution ------------------------------------
# Ruling serve-keyring-resolve-not-install-2026-09-28 (Loki 5003520D REVISE,
# blocking, "resolve, don't install"): with no WILLOW_KEYRING and nothing
# injected, get_keyring() tries exactly one more source before giving up --
# the net-signer SYSTEM unit's own Environment=, with ownership/writability
# checks. Any failed check means no keyring, never a guess.


def _reset_unit_keyring_state(monkeypatch):
    keyring_mod.set_keyring(None)
    monkeypatch.setattr(keyring_mod, "_from_env", None)
    monkeypatch.setattr(keyring_mod, "_loaded_from", None)
    monkeypatch.setattr(keyring_mod, "_from_unit", None)
    monkeypatch.setattr(keyring_mod, "_unit_attempted", False)
    monkeypatch.setattr(keyring_mod, "_unit_reason", "")
    monkeypatch.setattr(keyring_mod, "_unit_path", None)
    monkeypatch.delenv("WILLOW_KEYRING", raising=False)


def _public_ring_file(path, name="alice", key_hex="11" * 32, mode=0o644):
    path.write_text(json.dumps({
        "version": 1,
        "verifiers": [{"name": name, "key": key_hex, "kind": "ed25519",
                       "revoked_at": "", "compromised": False, "reason": "",
                       "created_at": "2026-01-01T00:00:00Z"}],
        "public_only": True,
    }))
    os.chmod(path, mode)


def test_unit_resolved_ring_is_accepted(tmp_path, monkeypatch):
    _reset_unit_keyring_state(monkeypatch)
    ring = tmp_path / "verifiers.public.json"
    _public_ring_file(ring)
    monkeypatch.setattr(reloader_mod, "resolve_keyring_path", lambda: (ring, "net-signer-unit"))
    monkeypatch.setattr(os, "geteuid", lambda: 994)  # not this test's own uid

    got = keyring_mod.get_keyring()
    assert got is not None
    assert "alice" in got
    status = keyring_mod.unit_keyring_status()
    assert status["attempted"] is True
    assert status["path"] == str(ring)
    assert status["reason"] == ""


def test_default_fallback_source_is_refused(tmp_path, monkeypatch):
    _reset_unit_keyring_state(monkeypatch)
    ring = tmp_path / "verifiers.public.json"
    _public_ring_file(ring)
    monkeypatch.setattr(reloader_mod, "resolve_keyring_path", lambda: (ring, "default"))
    monkeypatch.setattr(os, "geteuid", lambda: 994)

    got = keyring_mod.get_keyring()
    assert got is None
    status = keyring_mod.unit_keyring_status()
    assert "default" in status["reason"]


def test_ring_owned_by_this_process_is_refused(tmp_path, monkeypatch):
    _reset_unit_keyring_state(monkeypatch)
    ring = tmp_path / "verifiers.public.json"
    _public_ring_file(ring)  # created by this test process -- owned by its own euid
    monkeypatch.setattr(reloader_mod, "resolve_keyring_path", lambda: (ring, "net-signer-unit"))

    got = keyring_mod.get_keyring()
    assert got is None
    status = keyring_mod.unit_keyring_status()
    assert "own uid" in status["reason"] or "owned by this process" in status["reason"]


def test_group_writable_ring_file_is_refused(tmp_path, monkeypatch):
    _reset_unit_keyring_state(monkeypatch)
    ring = tmp_path / "verifiers.public.json"
    _public_ring_file(ring, mode=0o664)
    monkeypatch.setattr(reloader_mod, "resolve_keyring_path", lambda: (ring, "net-signer-unit"))
    monkeypatch.setattr(os, "geteuid", lambda: 994)

    got = keyring_mod.get_keyring()
    assert got is None
    status = keyring_mod.unit_keyring_status()
    assert "writable" in status["reason"]


def test_group_writable_parent_dir_is_refused(tmp_path, monkeypatch):
    _reset_unit_keyring_state(monkeypatch)
    d = tmp_path / "egress"
    d.mkdir()
    ring = d / "verifiers.public.json"
    _public_ring_file(ring)
    os.chmod(d, 0o775)
    monkeypatch.setattr(reloader_mod, "resolve_keyring_path", lambda: (ring, "net-signer-unit"))
    monkeypatch.setattr(os, "geteuid", lambda: 994)

    got = keyring_mod.get_keyring()
    assert got is None
    status = keyring_mod.unit_keyring_status()
    assert "writable" in status["reason"]


def test_symlink_to_a_writable_target_is_refused(tmp_path, monkeypatch):
    # The symlink itself lives in a SAFE directory; its resolved target's
    # PARENT is the world-writable one. A check that used the symlink's own
    # parent (never resolving first) would miss this entirely -- resolving
    # first is what makes the parent-writability check mean anything.
    _reset_unit_keyring_state(monkeypatch)
    safe_dir = tmp_path / "safe"
    safe_dir.mkdir()
    os.chmod(safe_dir, 0o700)
    writable_dir = tmp_path / "writable"
    writable_dir.mkdir()
    os.chmod(writable_dir, 0o777)
    real = writable_dir / "real-ring.json"
    _public_ring_file(real, mode=0o644)
    link = safe_dir / "verifiers.public.json"
    link.symlink_to(real)
    monkeypatch.setattr(reloader_mod, "resolve_keyring_path", lambda: (link, "net-signer-unit"))
    monkeypatch.setattr(os, "geteuid", lambda: 994)

    got = keyring_mod.get_keyring()
    assert got is None
    status = keyring_mod.unit_keyring_status()
    assert "writable" in status["reason"]
    # names the RESOLVED target's parent directory, not the symlink's own
    assert str(writable_dir) in status["reason"]


def test_private_ring_is_refused(tmp_path, monkeypatch):
    _reset_unit_keyring_state(monkeypatch)
    ring = tmp_path / "verifiers.public.json"
    ring.write_text(json.dumps({
        "version": 1,
        "verifiers": [{"name": "alice", "key": "11" * 32, "kind": "ed25519",
                       "private": "22" * 32, "revoked_at": "", "compromised": False,
                       "reason": "", "created_at": ""}],
    }))
    os.chmod(ring, 0o600)
    monkeypatch.setattr(reloader_mod, "resolve_keyring_path", lambda: (ring, "net-signer-unit"))
    monkeypatch.setattr(os, "geteuid", lambda: 994)

    got = keyring_mod.get_keyring()
    assert got is None
    status = keyring_mod.unit_keyring_status()
    assert "public-only" in status["reason"] or "private" in status["reason"]


def test_env_still_wins_over_unit_fallback(tmp_path, monkeypatch):
    _reset_unit_keyring_state(monkeypatch)
    env_path = tmp_path / "env-keyring.json"
    k = keyring_mod.Keyring(path=str(env_path))
    k.add("env_verifier")
    k.save()
    monkeypatch.setenv("WILLOW_KEYRING", str(env_path))

    called = []

    def fake_resolve():
        called.append(1)
        raise AssertionError("unit resolution must not run when WILLOW_KEYRING is set")

    monkeypatch.setattr(reloader_mod, "resolve_keyring_path", fake_resolve)

    got = keyring_mod.get_keyring()
    assert got is not None
    assert "env_verifier" in got
    assert not called


def test_unit_resolution_is_cached_once_per_process(tmp_path, monkeypatch):
    _reset_unit_keyring_state(monkeypatch)
    ring = tmp_path / "verifiers.public.json"
    _public_ring_file(ring)
    calls = []

    def fake_resolve():
        calls.append(1)
        return ring, "net-signer-unit"

    monkeypatch.setattr(reloader_mod, "resolve_keyring_path", fake_resolve)
    monkeypatch.setattr(os, "geteuid", lambda: 994)

    first = keyring_mod.get_keyring()
    second = keyring_mod.get_keyring()
    assert first is second
    assert len(calls) == 1
