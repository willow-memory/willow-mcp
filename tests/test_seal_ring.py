"""Nestor seals verify against the signer's public ring, not WILLOW_KEYRING.

The incident (Ada 0B46D2DF): two keypairs both named "sean campbell" -- the
one nestor-ui signs seals with, and the one the seat holds in
``WILLOW_KEYRING`` for session attestation. Every seal-verification site
(reloader, seed_loader, manifest_grant_executor, constitutional) now reads
``seal_ring`` (``WILLOW_SEAL_RING``, else /etc/willow-mcp/verifiers.public.json)
and must keep working when the two disagree. Keys here are generated per
test; nothing reads a real ring.
"""
from __future__ import annotations

import json
import re
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from willow_mcp import keyring as keyring_mod
from willow_mcp import manifest_grant_executor as mgx
from willow_mcp import net_signer as ns
from willow_mcp import reloader
from willow_mcp import seal_ring
from willow_mcp import seed_loader as sl

NAME = "sean campbell"
SOURCE_NORM = "restart the broker"
RID = "receipt-7"
TARGET = f"yes — restart onto pull receipt {RID}"
BOOT_TARGET = "boot-correction: fleet\nUse the seal ring."


def _make_keyring(tmp_path: Path, fname: str) -> keyring_mod.Keyring:
    k = keyring_mod.Keyring(path=str(tmp_path / fname))
    k.add(NAME, kind="ed25519")
    k.save()
    return k


def _sign(kr, source_norm: str, target_text: str) -> str:
    priv = Ed25519PrivateKey.from_private_bytes(kr.get(NAME).private)
    return priv.sign(ns.seal_message(source_norm, target_text, NAME)).hex()


def _nestor_db(tmp_path: Path, rows) -> Path:
    db = tmp_path / "nestor.db"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE tm_pairs (
            id TEXT PRIMARY KEY, source_text TEXT NOT NULL, source_norm TEXT NOT NULL,
            source_lang TEXT NOT NULL, target_text TEXT NOT NULL, target_lang TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft', verifier TEXT NOT NULL DEFAULT '',
            weight REAL NOT NULL DEFAULT 1.0, origin TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL, seal_sig TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '', superseded_by TEXT NOT NULL DEFAULT '',
            visibility TEXT NOT NULL DEFAULT 'internal'
        );
    """)
    for pid, source_norm, target, sig in rows:
        conn.execute(
            "INSERT INTO tm_pairs (id, source_text, source_norm, source_lang, target_text, "
            "target_lang, status, verifier, created_at, seal_sig, superseded_by) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (pid, source_norm, source_norm, "decision", target, "decision", "sealed", NAME,
             datetime.now(timezone.utc).isoformat(), sig, ""))
    conn.commit()
    conn.close()
    return db


# ── the sites, each reduced to "did this seal verify?" ──────────────────────

def _site_reloader(kr_signer, tmp_path):
    db = _nestor_db(tmp_path, [("p1", SOURCE_NORM, TARGET, _sign(kr_signer, SOURCE_NORM, TARGET))])
    return reloader.find_sealing_decision(RID, db)["state"]


def _site_ruling_pin(kr_signer, tmp_path):
    """reloader._ruling_sealed_detail -- the pinned-ruling check that shares
    _load_verify_ring with find_sealing_decision, called from its own site."""
    target = "the pinned ruling"
    db = _nestor_db(tmp_path, [(reloader.RULING_PAIR_ID, SOURCE_NORM, target,
                                _sign(kr_signer, SOURCE_NORM, target))])
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(reloader, "RULING_TEXT_SHA256", None)   # the text pin is not under test here
        ok, _why = reloader._ruling_sealed_detail(db)
    return "populated" if ok else "refused"


def _site_seed_loader(kr_signer, tmp_path):
    db = _nestor_db(tmp_path, [("p2", SOURCE_NORM, BOOT_TARGET, _sign(kr_signer, SOURCE_NORM, BOOT_TARGET))])
    return sl.load_sealed_corrections(db_path=db)["state"]


def _site_manifest_grant(kr_signer, tmp_path):
    row = {"source_norm": SOURCE_NORM, "target_text": TARGET, "verifier": NAME,
           "seal_sig": _sign(kr_signer, SOURCE_NORM, TARGET),
           "created_at": datetime.now(timezone.utc).isoformat(), "pair_id": "p3"}
    refusal, _sealed = mgx._verify_seal_only("p3", sealed_row=row)
    return "populated" if refusal is None else "refused"


SITES = {
    "reloader.find_sealing_decision": (_site_reloader, "populated", "empty"),
    "reloader._ruling_sealed_detail": (_site_ruling_pin, "populated", "refused"),
    "seed_loader.load_sealed_corrections": (_site_seed_loader, "populated", "refused"),
    "manifest_grant_executor._verify_seal_only": (_site_manifest_grant, "populated", "refused"),
}
UNREACHABLE = {
    "reloader.find_sealing_decision": "unreachable",
    "reloader._ruling_sealed_detail": "refused",       # fails CLOSED, never raises
    "seed_loader.load_sealed_corrections": "unreachable",
    "manifest_grant_executor._verify_seal_only": "refused",
}


@pytest.fixture
def pair(tmp_path):
    """Two DIFFERENT keypairs under the same verifier name: A signs the seal
    (nestor-ui), B is the seat's own WILLOW_KEYRING entry."""
    return _make_keyring(tmp_path, "signer.json"), _make_keyring(tmp_path, "seat.json")


@pytest.fixture
def seat_keyring():
    """Install a keyring as the seat's WILLOW_KEYRING (session attestation)."""
    with keyring_mod.isolated():
        def _install(kr):
            keyring_mod.set_keyring(kr)
        yield _install
        keyring_mod.set_keyring(None)


@pytest.mark.parametrize("site", SITES)
def test_seal_by_A_verifies_when_seal_ring_holds_A_and_seat_keyring_holds_B(
        site, pair, tmp_path, seat_keyring, publish_seal_ring):
    signer, seat = pair
    publish_seal_ring(signer)
    seat_keyring(seat)
    fn, ok_state, _bad = SITES[site]
    assert fn(signer, tmp_path) == ok_state


@pytest.mark.parametrize("site", SITES)
def test_seal_by_A_is_refused_when_seal_ring_holds_B_and_seat_keyring_holds_A(
        site, pair, tmp_path, seat_keyring, publish_seal_ring):
    """The reverse: the seat keyring happens to hold the signer's key. It must
    not rescue a seal -- only the seal ring counts."""
    signer, seat = pair
    publish_seal_ring(seat)
    seat_keyring(signer)
    fn, ok_state, bad_state = SITES[site]
    got = fn(signer, tmp_path)
    assert got != ok_state and got == bad_state


@pytest.mark.parametrize("site", SITES)
def test_ring_carrying_a_private_half_is_refused(site, pair, tmp_path, seat_keyring, monkeypatch):
    """The seat's own signing keyring (private halves) pointed at as the seal
    ring is refused, even though it holds the signer's key."""
    signer, _seat = pair
    private_bearing = tmp_path / "private-bearing.json"
    shutil.copyfile(signer.path, private_bearing)
    assert json.loads(private_bearing.read_text())["verifiers"][0].get("private")
    monkeypatch.setenv("WILLOW_SEAL_RING", str(private_bearing))
    seat_keyring(signer)
    fn, ok_state, _bad = SITES[site]
    assert fn(signer, tmp_path) != ok_state
    ring, err = seal_ring.load_seal_ring()
    assert ring is None and err["state"] == "unreachable" and "private" in err["cause"]


@pytest.mark.parametrize("site", SITES)
def test_missing_ring_is_unreachable_and_never_falls_back_to_the_seat_keyring(
        site, pair, tmp_path, seat_keyring, monkeypatch):
    signer, _seat = pair
    monkeypatch.setenv("WILLOW_SEAL_RING", str(tmp_path / "absent.json"))
    # WILLOW_KEYRING names a PUBLIC-only file holding the signer's key, so a
    # fallback to it WOULD verify the seal (a private-bearing one would be
    # refused for the wrong reason). It must NOT be used.
    fallback = tmp_path / "seat-public.json"
    ns.export_public_ring(Path(signer.path), fallback)
    monkeypatch.setenv("WILLOW_KEYRING", str(fallback))
    seat_keyring(signer)
    fn, ok_state, _bad = SITES[site]
    assert fn(signer, tmp_path) == UNREACHABLE[site]
    ring, err = seal_ring.load_seal_ring()
    assert ring is None and err["state"] == "unreachable"


def test_unset_env_resolves_to_the_system_public_ring(monkeypatch):
    monkeypatch.delenv("WILLOW_SEAL_RING", raising=False)
    assert seal_ring.seal_ring_path() == Path("/etc/willow-mcp/verifiers.public.json")
    monkeypatch.setenv("WILLOW_SEAL_RING", "  ")
    assert seal_ring.seal_ring_path() == Path("/etc/willow-mcp/verifiers.public.json")
    monkeypatch.setenv("WILLOW_SEAL_RING", "/x/ring.json")
    assert seal_ring.seal_ring_path() == Path("/x/ring.json")


def test_empty_or_malformed_ring_is_unreachable(tmp_path, monkeypatch):
    p = tmp_path / "r.json"
    monkeypatch.setenv("WILLOW_SEAL_RING", str(p))
    p.write_text(json.dumps({"verifiers": []}))
    assert seal_ring.load_seal_ring()[1]["state"] == "unreachable"
    p.write_text("{not json")
    assert seal_ring.load_seal_ring()[1]["state"] == "unreachable"
    p.write_text(json.dumps({"verifiers": [{"name": "x", "key": "00", "kind": "hmac"}]}))
    assert seal_ring.load_seal_ring()[1]["state"] == "unreachable"


# ── session attestation keeps WILLOW_KEYRING exactly as before ───────────────

def test_seat_keyring_still_loads_from_willow_keyring_whatever_the_seal_ring_says(
        pair, tmp_path, monkeypatch):
    """get_keyring() -- the one session attestation, sign-session and envelope
    attribution use -- reads WILLOW_KEYRING and ignores WILLOW_SEAL_RING."""
    _signer, seat = pair
    with keyring_mod.isolated():
        monkeypatch.setenv("WILLOW_KEYRING", seat.path)
        monkeypatch.setenv("WILLOW_SEAL_RING", str(tmp_path / "absent.json"))
        got = keyring_mod.get_keyring()
        assert got is not None
        assert got.get(NAME).key == seat.get(NAME).key
        assert got.get(NAME).private  # the signing half is still there: attestation can sign


def test_seat_keyring_is_not_the_seal_ring_even_when_both_are_set(pair, tmp_path, monkeypatch, publish_seal_ring):
    signer, seat = pair
    with keyring_mod.isolated():
        publish_seal_ring(signer)
        monkeypatch.setenv("WILLOW_KEYRING", seat.path)
        assert keyring_mod.get_keyring().get(NAME).key == seat.get(NAME).key
        assert seal_ring.load_seal_ring()[0][NAME]["key"] == signer.get(NAME).key


SRC_DIR = Path(__file__).resolve().parent.parent / "src" / "willow_mcp"


def _module_source(mod: str) -> str:
    return (SRC_DIR / f"{mod}.py").read_text(encoding="utf-8")


def _names_the_seal_ring(src: str) -> bool:
    """A scan: does this source mention the seal ring at all?"""
    return re.search(r"seal_ring|WILLOW_SEAL_RING", src) is not None


def _get_keyring_call_lines(src: str) -> list[int]:
    """A scan: the line of every call to ``get_keyring`` in this source."""
    import ast

    return [n.lineno for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Call)
            and getattr(n.func, "attr", getattr(n.func, "id", "")) == "get_keyring"]


def test_the_seal_ring_scan_fires_on_a_planted_reference():
    """Planted: a source that names the seal ring is reported; one that does not is not."""
    assert _names_the_seal_ring("ring = os.environ['WILLOW_SEAL_RING']\n")
    assert _names_the_seal_ring("from . import seal_ring\n")
    assert not _names_the_seal_ring("ring = os.environ['WILLOW_KEYRING']\n")


def test_the_get_keyring_scan_fires_on_a_planted_call():
    """Planted: a bare call and an attribute call are both reported, with
    their line; a mention in a docstring or a different name is not."""
    assert _get_keyring_call_lines("x = 1\nkr = get_keyring()\n") == [2]
    assert _get_keyring_call_lines("from . import keyring as k\nkr = k.get_keyring()\n") == [2]
    assert _get_keyring_call_lines('"""get_keyring() is the seat keyring"""\nx = keyring_path()\n') == []


ATTESTATION_MODULES = ("session_signing", "human_session", "sign_session_cli",
                       "session_start_hook", "envelope_authoring", "keyring")


@pytest.mark.parametrize("mod", ATTESTATION_MODULES)
def test_attestation_modules_do_not_touch_the_seal_ring(mod):
    assert not _names_the_seal_ring(_module_source(mod)), (
        f"{mod} must keep reading WILLOW_KEYRING only")


SEAL_SITES = ("reloader", "manifest_grant_executor", "seed_loader", "constitutional")


@pytest.mark.parametrize("mod", SEAL_SITES)
def test_seal_sites_read_the_seal_ring_and_never_get_keyring(mod):
    """Every module that calls net_signer.verify_seal for a Nestor seal
    resolves its ring through seal_ring and does not call get_keyring()."""
    src = _module_source(mod)
    assert _names_the_seal_ring(src)
    assert not _get_keyring_call_lines(src), f"{mod} calls get_keyring()"
