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


def _trust_owner(monkeypatch, path):
    """R3 (Loki 9C8C97FD) pins the ring's owner to root or the net-signer
    unit's own User=, not merely 'not this process's own euid'. These
    fixtures write the ring as the TEST process's own uid (neither root
    nor willow-operator on a dev box) -- stub the trust check to accept
    that uid so a test about writability/symlinks/private-halves is not
    incidentally about ownership too."""
    from willow_mcp import keyring as keyring_mod

    monkeypatch.setattr(keyring_mod, "_trusted_ring_owner_uids",
                        lambda: {os.stat(path).st_uid})


def test_unit_resolved_ring_is_accepted(tmp_path, monkeypatch):
    _reset_unit_keyring_state(monkeypatch)
    ring = tmp_path / "verifiers.public.json"
    _public_ring_file(ring)
    monkeypatch.setattr(reloader_mod, "resolve_keyring_path", lambda: (ring, "net-signer-unit"))
    monkeypatch.setattr(os, "geteuid", lambda: 994)  # not this test's own uid
    _trust_owner(monkeypatch, ring)

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
    _trust_owner(monkeypatch, ring)

    got = keyring_mod.get_keyring()
    assert got is None
    status = keyring_mod.unit_keyring_status()
    # Loki 5771FE1F T1: the ring's owner is trusted here so ONLY the source
    # gate (source != "net-signer-unit") can be responsible for the refusal
    # -- otherwise this test passes by accident on a pytest tmp_path
    # substring coincidence (the path is built from this test's own name,
    # which contains "default") while the owner-pin check does the real
    # refusing and mutant A (source gate disabled) survives. Assert the
    # source gate's exact wording.
    assert "resolved via 'default'" in status["reason"]


def test_ring_owned_by_this_process_is_refused(tmp_path, monkeypatch):
    _reset_unit_keyring_state(monkeypatch)
    ring = tmp_path / "verifiers.public.json"
    _public_ring_file(ring)  # created by this test process -- not root, not willow-operator
    monkeypatch.setattr(reloader_mod, "resolve_keyring_path", lambda: (ring, "net-signer-unit"))
    # Spoof euid away from both the file's real owner AND the ancestor dirs'
    # real owner (same test uid) -- isolates the OWNER-of-the-FILE check as
    # the only thing that can refuse here (the ancestor-owned-by-own-euid
    # check would otherwise backstop a disabled owner check and mask it).
    monkeypatch.setattr(os, "geteuid", lambda: 994)

    got = keyring_mod.get_keyring()
    assert got is None
    status = keyring_mod.unit_keyring_status()
    # R3 (Loki 9C8C97FD): the owner check is now a positive allowlist (root or
    # the net-signer unit's own User=), not merely "not this process's euid" --
    # a ring owned by this test's own uid is refused for that reason.
    assert "not root or" in status["reason"]


def test_group_writable_ring_file_is_refused(tmp_path, monkeypatch):
    _reset_unit_keyring_state(monkeypatch)
    ring = tmp_path / "verifiers.public.json"
    _public_ring_file(ring, mode=0o664)
    monkeypatch.setattr(reloader_mod, "resolve_keyring_path", lambda: (ring, "net-signer-unit"))
    monkeypatch.setattr(os, "geteuid", lambda: 994)
    _trust_owner(monkeypatch, ring)

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
    _trust_owner(monkeypatch, ring)

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
    _trust_owner(monkeypatch, real)

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
    _trust_owner(monkeypatch, ring)

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
    _trust_owner(monkeypatch, ring)

    first = keyring_mod.get_keyring()
    second = keyring_mod.get_keyring()
    assert first is second
    assert len(calls) == 1



# --- R1 (Loki 9C8C97FD): a malformed entry REFUSES the whole ring, and the
# diagnostic (unit_keyring_status) and get_keyring() always agree ----------


def _malformed_ring_file(path, verifiers, mode=0o644):
    path.write_text(json.dumps({"version": 1, "verifiers": verifiers, "public_only": True}))
    os.chmod(path, mode)


def test_malformed_bad_hex_key_refuses_both_diag_and_get_keyring(tmp_path, monkeypatch):
    _reset_unit_keyring_state(monkeypatch)
    ring = tmp_path / "verifiers.public.json"
    _malformed_ring_file(ring, [{"name": "alice", "key": "not-hex-at-all", "kind": "ed25519",
                                 "revoked_at": "", "compromised": False, "reason": "",
                                 "created_at": ""}])
    monkeypatch.setattr(reloader_mod, "resolve_keyring_path", lambda: (ring, "net-signer-unit"))
    monkeypatch.setattr(os, "geteuid", lambda: 994)
    _trust_owner(monkeypatch, ring)

    got = keyring_mod.get_keyring()
    assert got is None
    status = keyring_mod.unit_keyring_status()
    assert status["path"] is None
    assert status["reason"]


def test_malformed_wrong_length_key_refuses_both_diag_and_get_keyring(tmp_path, monkeypatch):
    _reset_unit_keyring_state(monkeypatch)
    ring = tmp_path / "verifiers.public.json"
    _malformed_ring_file(ring, [{"name": "alice", "key": "11" * 10, "kind": "ed25519",
                                 "revoked_at": "", "compromised": False, "reason": "",
                                 "created_at": ""}])
    monkeypatch.setattr(reloader_mod, "resolve_keyring_path", lambda: (ring, "net-signer-unit"))
    monkeypatch.setattr(os, "geteuid", lambda: 994)
    _trust_owner(monkeypatch, ring)

    got = keyring_mod.get_keyring()
    assert got is None
    status = keyring_mod.unit_keyring_status()
    assert status["path"] is None
    assert status["reason"]


def test_malformed_missing_name_refuses_both_diag_and_get_keyring(tmp_path, monkeypatch):
    _reset_unit_keyring_state(monkeypatch)
    ring = tmp_path / "verifiers.public.json"
    _malformed_ring_file(ring, [{"key": "11" * 32, "kind": "ed25519",
                                 "revoked_at": "", "compromised": False, "reason": "",
                                 "created_at": ""}])
    monkeypatch.setattr(reloader_mod, "resolve_keyring_path", lambda: (ring, "net-signer-unit"))
    monkeypatch.setattr(os, "geteuid", lambda: 994)
    _trust_owner(monkeypatch, ring)

    got = keyring_mod.get_keyring()
    assert got is None
    status = keyring_mod.unit_keyring_status()
    assert status["path"] is None
    assert status["reason"]


def test_malformed_non_dict_entry_refuses_both_diag_and_get_keyring(tmp_path, monkeypatch):
    _reset_unit_keyring_state(monkeypatch)
    ring = tmp_path / "verifiers.public.json"
    _malformed_ring_file(ring, ["mallory"])
    monkeypatch.setattr(reloader_mod, "resolve_keyring_path", lambda: (ring, "net-signer-unit"))
    monkeypatch.setattr(os, "geteuid", lambda: 994)
    _trust_owner(monkeypatch, ring)

    # R2: this used to raise AttributeError out of get_keyring() the first
    # time keyring.load() (not load_public_ring, which only SKIPPED it)
    # hit a bare string entry. It must instead be a named refusal.
    got = keyring_mod.get_keyring()
    assert got is None
    status = keyring_mod.unit_keyring_status()
    assert status["path"] is None
    assert status["reason"]


# --- R2 (Loki 9C8C97FD): ANY exception in the fallback is a named state ---


def test_resolver_raising_is_a_named_no_keyring_state_not_an_exception(tmp_path, monkeypatch):
    _reset_unit_keyring_state(monkeypatch)

    def _boom():
        raise RuntimeError("systemd bus exploded")

    monkeypatch.setattr(reloader_mod, "resolve_keyring_path", _boom)

    got = keyring_mod.get_keyring()  # must not raise
    assert got is None
    status = keyring_mod.unit_keyring_status()
    assert status["path"] is None
    # Tight on purpose (not just "an error was named somewhere"): this must be
    # _resolve_unit_keyring's OWN inner guard around resolve_keyring_path()
    # that names it, not get_keyring's outer catch-all -- the two wordings
    # differ ("resolution raised" vs "unit keyring fallback raised") so a
    # mutant that drops the inner guard (N7) still shows a reason (via the
    # outer guard) but with the WRONG wording, and this assertion catches
    # that instead of being satisfied either way.
    assert "resolution raised" in status["reason"]
    assert "RuntimeError" in status["reason"]


def test_load_public_ring_bytes_raising_something_other_than_keyringerror_is_named(tmp_path, monkeypatch):
    """A non-dict verifier entry passes _resolve_unit_keyring's own check
    (net_signer.load_public_ring_bytes also refuses it now, R1) -- but this
    pins the OUTER guard (get_keyring's except Exception) against whatever
    kind of exception the load path could still raise, per R2: it must
    never escape as a bare AttributeError/TypeError/etc."""
    _reset_unit_keyring_state(monkeypatch)
    ring = tmp_path / "verifiers.public.json"
    _public_ring_file(ring)
    _trust_owner(monkeypatch, ring)
    monkeypatch.setattr(os, "geteuid", lambda: 994)
    monkeypatch.setattr(reloader_mod, "resolve_keyring_path", lambda: (ring, "net-signer-unit"))

    def _boom(data, label):
        raise AttributeError("simulated: 'str' object has no attribute 'get'")

    monkeypatch.setattr(keyring_mod, "load_bytes", _boom)

    got = keyring_mod.get_keyring()
    assert got is None
    status = keyring_mod.unit_keyring_status()
    assert status["path"] is None
    assert status["reason"]


# --- R3 (Loki 9C8C97FD): fd-bound read closes the TOCTOU window, and the
# ancestor walk climbs past the immediate parent ----------------------------


def test_toctou_swap_between_checks_and_load_does_not_leak_the_swapped_file(tmp_path, monkeypatch):
    _reset_unit_keyring_state(monkeypatch)
    ring = tmp_path / "verifiers.public.json"
    _public_ring_file(ring, name="alice")
    monkeypatch.setattr(reloader_mod, "resolve_keyring_path", lambda: (ring, "net-signer-unit"))
    monkeypatch.setattr(os, "geteuid", lambda: 994)
    _trust_owner(monkeypatch, ring)

    real_open = os.open
    swapped = {"done": False}

    def swap_after_open(path, flags, *a, **kw):
        fd = real_open(path, flags, *a, **kw)
        if not swapped["done"] and str(path) == str(ring):
            swapped["done"] = True
            # An attacker replaces the file at this PATH via a rename the
            # instant after our fd was opened -- a NEW inode takes over
            # ring's directory entry while our fd still references the
            # OLD one. A path-based reopen (the pre-R3 shape) would load
            # the NEW inode's content; the fd-bound read must not.
            evil = ring.with_suffix(".evil")
            _public_ring_file(evil, name="mallory")
            os.replace(evil, ring)
        return fd

    monkeypatch.setattr(os, "open", swap_after_open)

    got = keyring_mod.get_keyring()
    assert got is not None
    assert "alice" in got
    assert "mallory" not in got
    assert swapped["done"], "the swap never actually ran -- test is not exercising the window"


def test_0777_grandparent_is_refused(tmp_path, monkeypatch):
    _reset_unit_keyring_state(monkeypatch)
    grandparent = tmp_path / "grandparent"
    grandparent.mkdir()
    os.chmod(grandparent, 0o777)
    parent = grandparent / "egress"
    parent.mkdir()
    os.chmod(parent, 0o755)
    ring = parent / "verifiers.public.json"
    _public_ring_file(ring)
    monkeypatch.setattr(reloader_mod, "resolve_keyring_path", lambda: (ring, "net-signer-unit"))
    monkeypatch.setattr(os, "geteuid", lambda: 994)
    _trust_owner(monkeypatch, ring)

    got = keyring_mod.get_keyring()
    assert got is None
    status = keyring_mod.unit_keyring_status()
    assert str(grandparent) in status["reason"]


def test_0777_grandparent_with_sticky_bit_is_accepted(tmp_path, monkeypatch):
    """The sticky bit is the exemption the ruling explicitly allows (the
    real /tmp shape: 1777) -- a world-writable ancestor with it set is not
    refused."""
    _reset_unit_keyring_state(monkeypatch)
    grandparent = tmp_path / "grandparent"
    grandparent.mkdir()
    os.chmod(grandparent, 0o1777)  # world-writable + sticky
    parent = grandparent / "egress"
    parent.mkdir()
    os.chmod(parent, 0o755)
    ring = parent / "verifiers.public.json"
    _public_ring_file(ring)
    monkeypatch.setattr(reloader_mod, "resolve_keyring_path", lambda: (ring, "net-signer-unit"))
    monkeypatch.setattr(os, "geteuid", lambda: 994)
    _trust_owner(monkeypatch, ring)

    got = keyring_mod.get_keyring()
    assert got is not None
    assert "alice" in got


# --- item 4 (Loki 9C8C97FD): reloader._resolve_keyring_path's own labelling,
# exercised directly -- not via a wholesale monkeypatch of the function
# itself, which is what let N2/N3/N4/N9 survive against this suite ---------


def test_resolve_keyring_path_own_env_ring_is_labelled_default(monkeypatch, tmp_path):
    import subprocess

    own_env_ring = tmp_path / "own-env-ring.json"
    monkeypatch.setenv("WILLOW_NET_SIGNER_RING", str(own_env_ring))

    def fake_run(argv, **kw):
        return subprocess.CompletedProcess(argv, 1, "", "Unit could not be found.")

    path, source = reloader_mod._resolve_keyring_path(runner=fake_run)
    assert source == "default"
    assert path == own_env_ring


def test_resolve_keyring_path_default_fallback_with_no_env_is_labelled_default(monkeypatch, tmp_path):
    import subprocess

    monkeypatch.delenv("WILLOW_NET_SIGNER_RING", raising=False)

    def fake_run(argv, **kw):
        return subprocess.CompletedProcess(argv, 1, "", "Unit could not be found.")

    path, source = reloader_mod._resolve_keyring_path(runner=fake_run)
    assert source == "default"


def test_resolve_keyring_path_only_the_system_units_environment_yields_net_signer_unit(monkeypatch, tmp_path):
    import subprocess

    unit_ring = tmp_path / "unit-ring.json"

    def fake_run(argv, **kw):
        assert argv[0] == reloader_mod._SYSTEMCTL_BIN
        return subprocess.CompletedProcess(
            argv, 0, f"Environment=WILLOW_NET_SIGNER_RING={unit_ring}\n", "")

    path, source = reloader_mod._resolve_keyring_path(runner=fake_run)
    assert source == "net-signer-unit"
    assert path == unit_ring



def test_trusted_owner_check_raising_is_caught_by_the_outer_guard(tmp_path, monkeypatch):
    """R2/N6: an exception from a step _resolve_unit_keyring does NOT wrap
    itself (here, _trusted_ring_owner_uids) must still be caught -- by
    get_keyring's own outer except Exception -- rather than escaping to a
    caller that never asked for per-verifier identity."""
    _reset_unit_keyring_state(monkeypatch)
    ring = tmp_path / "verifiers.public.json"
    _public_ring_file(ring)
    monkeypatch.setattr(reloader_mod, "resolve_keyring_path", lambda: (ring, "net-signer-unit"))
    monkeypatch.setattr(os, "geteuid", lambda: 994)

    def _boom():
        raise ValueError("simulated failure inside an inner check")

    monkeypatch.setattr(keyring_mod, "_trusted_ring_owner_uids", _boom)

    got = keyring_mod.get_keyring()  # must not raise
    assert got is None
    status = keyring_mod.unit_keyring_status()
    assert status["path"] is None
    assert "unit keyring fallback raised" in status["reason"]
    assert "ValueError" in status["reason"]



def test_load_bytes_keyringerror_after_checks_pass_is_a_clean_refusal(tmp_path, monkeypatch):
    """R1/N4/N9: if the two loaders ever diverge (load_public_ring_bytes
    accepts a ring that keyring.load_bytes then refuses), get_keyring's
    path/reason must reflect the REAL failure -- never report a path as
    resolved (diag-looking 'ok') while the keyring itself is None. That
    three-state collapse is exactly what Loki 9C8C97FD found."""
    _reset_unit_keyring_state(monkeypatch)
    ring = tmp_path / "verifiers.public.json"
    _public_ring_file(ring)
    monkeypatch.setattr(reloader_mod, "resolve_keyring_path", lambda: (ring, "net-signer-unit"))
    monkeypatch.setattr(os, "geteuid", lambda: 994)
    _trust_owner(monkeypatch, ring)

    def _boom(data, label):
        raise keyring_mod.KeyringError("simulated divergence between the two loaders")

    monkeypatch.setattr(keyring_mod, "load_bytes", _boom)

    got = keyring_mod.get_keyring()
    assert got is None
    status = keyring_mod.unit_keyring_status()
    assert status["path"] is None
    assert "resolved but failed to load" in status["reason"]
