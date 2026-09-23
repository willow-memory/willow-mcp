"""frank_head_anchor.py — the externally-held FRANK chain head (#280).

Pure filesystem module, no Postgres. Every status `read_anchor()` can return
is exercised here, because a caller (`rechain()`, `frank_verify`) treats each
one differently and a status this suite doesn't pin is a status those
callers were never actually tested against.
"""
import json

import pytest

from willow_mcp import frank_head_anchor as fha
from willow_mcp import paths as _paths
from willow_mcp import pgp as _pgp

HEAD_A = "a" * 64
HEAD_B = "b" * 64


@pytest.fixture
def home(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    return tmp_path


def test_no_file_is_unanchored(home):
    assert fha.read_anchor() == {"status": "unanchored", "head": None}


def test_write_then_read_round_trips(home):
    path = fha.write_anchor(HEAD_A, 7, anchored_by="rudi")
    assert path == home / "constitutional" / "frank_head_anchor.json"
    assert path.exists()

    anchor = fha.read_anchor()
    assert anchor["status"] == "anchored"
    assert anchor["head"] == HEAD_A
    assert anchor["count"] == 7
    assert anchor["anchored_by"] == "rudi"
    assert anchor["anchored_at"]  # non-empty timestamp


def test_write_anchor_accepts_none_head_for_empty_chain(home):
    fha.write_anchor(None, 0, anchored_by="op")
    anchor = fha.read_anchor()
    assert anchor["status"] == "anchored"
    assert anchor["head"] is None
    assert anchor["count"] == 0


def test_write_anchor_defaults_anchored_by_to_user(home, monkeypatch):
    monkeypatch.setenv("USER", "envuser")
    fha.write_anchor(HEAD_A, 1)
    assert fha.read_anchor()["anchored_by"] == "envuser"


def test_write_anchor_rejects_malformed_head(home):
    for bad in ("not-hex", "A" * 64, "a" * 63, "a" * 65, ""):
        with pytest.raises(ValueError):
            fha.write_anchor(bad, 1)


def test_write_anchor_is_atomic_and_0600(home):
    fha.write_anchor(HEAD_A, 1)
    p = home / "constitutional" / "frank_head_anchor.json"
    assert (p.stat().st_mode & 0o777) == 0o600
    # no leftover temp file
    leftovers = [f for f in p.parent.iterdir() if f.name != p.name]
    assert leftovers == []


def test_rewrite_replaces_atomically(home):
    fha.write_anchor(HEAD_A, 1, anchored_by="first")
    fha.write_anchor(HEAD_B, 2, anchored_by="second")
    anchor = fha.read_anchor()
    assert anchor["head"] == HEAD_B
    assert anchor["count"] == 2
    assert anchor["anchored_by"] == "second"


# ── fail-closed on anomalies: never silently treated as "matches" ──────────

def test_malformed_json_is_unreadable(home):
    d = home / "constitutional"
    d.mkdir(parents=True)
    p = d / "frank_head_anchor.json"
    p.write_text("{not json")
    p.chmod(0o600)
    anchor = fha.read_anchor()
    assert anchor["status"] == "unreadable"
    assert anchor["head"] is None


def test_missing_head_key_is_unreadable(home):
    d = home / "constitutional"
    d.mkdir(parents=True)
    p = d / "frank_head_anchor.json"
    p.write_text(json.dumps({"count": 1}))
    p.chmod(0o600)
    anchor = fha.read_anchor()
    assert anchor["status"] == "unreadable"


def test_non_hex_head_is_unreadable(home):
    d = home / "constitutional"
    d.mkdir(parents=True)
    p = d / "frank_head_anchor.json"
    p.write_text(json.dumps({"head": "drop table frank_ledger", "count": 1}))
    p.chmod(0o600)
    anchor = fha.read_anchor()
    assert anchor["status"] == "unreadable"
    assert anchor["head"] is None


def test_non_dict_json_is_unreadable(home):
    d = home / "constitutional"
    d.mkdir(parents=True)
    p = d / "frank_head_anchor.json"
    p.write_text(json.dumps(["not", "a", "dict"]))
    p.chmod(0o600)
    anchor = fha.read_anchor()
    assert anchor["status"] == "unreadable"


def test_world_writable_anchor_file_is_untrusted(home):
    fha.write_anchor(HEAD_A, 1)
    p = home / "constitutional" / "frank_head_anchor.json"
    p.chmod(0o666)  # loosened -- an attacker with local write access could do this
    anchor = fha.read_anchor()
    assert anchor["status"] == "untrusted"
    assert anchor["head"] is None


def test_world_writable_parent_dir_is_untrusted(home):
    fha.write_anchor(HEAD_A, 1)
    (home / "constitutional").chmod(0o777)
    anchor = fha.read_anchor()
    assert anchor["status"] == "untrusted"


# ── Loki audit A38D41C2, F10 ────────────────────────────────────────────
# read_anchor()'s own docstring promises "never raises". Before the fix,
# paths.trusted_read()'s trust-owner-plus-signature branch could raise
# pgp.PgpFingerprintConflict or pgp.PgpSourceUnreadable (both RuntimeError,
# not PermissionError) when the trust-config file conflicted or could not
# be trusted — and read_anchor() caught only PermissionError, so either one
# escaped its "never raises" contract. Exercised by monkeypatching
# paths.trusted_read directly (the anchor file in these tests is
# self-owned, so it never actually reaches trusted_read's trust-owner
# branch in a plain test fixture) — this targets the except clause itself,
# not the deeper ownership plumbing pgp's own test suite already covers.

def test_pgp_conflict_during_trust_check_is_untrusted_not_a_crash(home, monkeypatch):
    fha.write_anchor(HEAD_A, 1)

    def _raise_conflict(path):
        raise _pgp.PgpFingerprintConflict("simulated conflict for test")

    monkeypatch.setattr(_paths, "trusted_read", _raise_conflict)
    anchor = fha.read_anchor()  # must not raise
    assert anchor["status"] == "untrusted"
    assert anchor["head"] is None


def test_pgp_source_unreadable_during_trust_check_is_untrusted_not_a_crash(home, monkeypatch):
    fha.write_anchor(HEAD_A, 1)

    def _raise_unreadable(path):
        raise _pgp.PgpSourceUnreadable("simulated unreadable trust config for test")

    monkeypatch.setattr(_paths, "trusted_read", _raise_unreadable)
    anchor = fha.read_anchor()  # must not raise
    assert anchor["status"] == "untrusted"
    assert anchor["head"] is None


def test_symlinked_anchor_file_is_untrusted(home):
    d = home / "constitutional"
    d.mkdir(parents=True)
    real = home / "elsewhere.json"
    real.write_text(json.dumps({"head": HEAD_A, "count": 1}))
    (d / "frank_head_anchor.json").symlink_to(real)
    anchor = fha.read_anchor()
    assert anchor["status"] == "untrusted"
