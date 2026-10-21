"""willow-mcp's signing code held to the one script's ``sign.py`` (flatten-2 F14).

The operator ruled (2026-10-21) that the trust owner's root-owned venv never
imports a sibling checkout, so ``net_signer``, ``keyring``, ``session_signing``
(reached from ``human_session``), ``dispatch_signing``, ``session_binder`` and
``manifest_grant_executor`` keep their own signing code. This file lives
OUTSIDE the trust path: it reaches the one script and holds each kept copy to
it, byte for byte or verdict for verdict.

The rule for a verifier is one-directional: the one script's verifier may never
accept what a kept copy rejected (``sign accepts => copy accepts``). The one
script is stricter on purpose in two places, listed where they are tested:
a non-canonical ``s`` and a small-order or non-canonical public key.
Every key here is a throwaway.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from willow_mcp import (
    dispatch_signing,
    net_signer,
    onescript_sign,
    session_binder,
    session_signing,
)

pytest.importorskip("cryptography")


@pytest.fixture(scope="module")
def sign():
    return onescript_sign.sign()


def _keypair(sign):
    priv = sign.ed25519_generate()
    return priv, bytes.fromhex(sign.ed25519_public_hex(priv))


# ---- the seal message

@pytest.mark.parametrize(
    "args",
    [("s", "t", "v"), ("s é", "t ☃ 日本", "v"), ("", "", ""), ('q"\\', "\n", "\U0001d11e")],
)
def test_net_signer_seal_message_is_the_one_scripts(sign, args):
    assert net_signer.seal_message(*args) == sign.seal_message(*args)


def test_net_signer_seal_digest_covers_the_one_scripts_bytes(sign):
    seal = {"source_norm": "sé", "target_text": "t", "verifier": "v", "seal_sig": "ab"}
    want = hashlib.sha256(sign.seal_message("sé", "t", "v") + b"\n" + b"ab").hexdigest()
    assert net_signer.seal_digest(seal) == want


# ---- raw Ed25519: session_signing signs and verifies like sign.py

def test_session_signing_ed25519_bytes_are_the_one_scripts(sign):
    priv, pub = _keypair(sign)
    msg = session_signing._message("app", "sess", "ada", "2026-10-21T00:00:00+00:00")
    sig = session_signing._sign_ed25519(priv, msg)
    assert sig == sign.ed25519_sign(priv, msg)  # Ed25519 is deterministic
    assert session_signing._verify_ed25519(pub, msg, sig) is True
    assert sign.ed25519_verify_hex(pub.hex(), msg, sig) == (True, "")
    bad = sig[:-2] + ("00" if sig[-2:] != "00" else "01")
    assert session_signing._verify_ed25519(pub, msg, bad) is False
    assert sign.ed25519_verify_hex(pub.hex(), msg, bad)[0] is False


def test_session_signing_hmac_is_the_one_scripts(sign):
    key, msg = b"k" * 32, b"payload"
    assert session_signing._sign_hmac(key, msg) == sign.hmac_hex(key, msg)
    assert session_signing._verify_hmac(key, msg, sign.hmac_hex(key, msg)) is True
    assert session_signing._verify_hmac(key, msg, "0" * 64) is False


# ---- net_signer.verify_seal: same verdict, sign never wider

def _seal(sign, priv, **over):
    s = {
        "source_norm": "approve", "target_text": "do the thing", "verifier": "ada",
        "created_at": datetime.now(UTC).isoformat(),
    }
    s.update(over)
    s["seal_sig"] = sign.ed25519_sign(priv, net_signer.seal_message(s["source_norm"], s["target_text"], s["verifier"]))
    return s


def _ring(pub):
    return {"ada": {"key": pub, "kind": "ed25519", "revoked_at": None, "compromised": False}}


def _both(sign, seal, ring):
    ok_copy = net_signer.verify_seal(seal, ring)[0]
    ok_one, _ = sign.ed25519_verify(
        ring["ada"]["key"],
        sign.seal_message(seal["source_norm"], seal["target_text"], seal["verifier"]),
        bytes.fromhex(seal["seal_sig"]),
    )
    return ok_copy, ok_one


def test_net_signer_and_sign_agree_on_a_real_seal_and_a_forged_one(sign):
    priv, pub = _keypair(sign)
    seal = _seal(sign, priv)
    assert _both(sign, seal, _ring(pub)) == (True, True)
    forged = dict(seal, target_text="do another thing")
    assert _both(sign, forged, _ring(pub)) == (False, False)
    _, other = _keypair(sign)
    assert _both(sign, seal, _ring(other)) == (False, False)


def test_non_canonical_s_is_refused_by_both(sign):
    priv, pub = _keypair(sign)
    seal = _seal(sign, priv)
    raw = bytes.fromhex(seal["seal_sig"])
    s = int.from_bytes(raw[32:], "little") + sign.L
    seal["seal_sig"] = (raw[:32] + s.to_bytes(32, "little")).hex()
    assert _both(sign, seal, _ring(pub)) == (False, False)


def test_sign_is_never_wider_than_the_kept_copy_on_odd_keys_and_signatures(sign):
    """small-order and non-canonical keys, short and long signatures: wherever
    the one script says yes, the kept copy said yes; it may say no where the
    copy said yes (the explicit rejections)."""
    sigs = [b"\x00" * 64, b"\x01" + b"\x00" * 63, b"\x00" * 32 + b"\x01" + b"\x00" * 31, b"\x00" * 63, b"\x00" * 65]
    keys = [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ]
    for k in keys:
        for sig in sigs:
            seal = {"source_norm": "a", "target_text": "t", "verifier": "ada",
                    "created_at": datetime.now(UTC).isoformat(), "seal_sig": sig.hex()}
            ring = _ring(bytes.fromhex(k))
            copy_ok, one_ok = _both(sign, seal, ring)
            assert not one_ok or copy_ok, (k, sig.hex())


# ---- the public-only keyring rules: where the two loaders differ, on the record

PUB = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"


def _entry(**kw):
    return {"name": "ada", "key": PUB, "kind": "ed25519", **kw}


def _agree(sign, tmp_path, raw: dict):
    p = tmp_path / "r.json"
    p.write_text(json.dumps(raw))
    try:
        copy = {n: e["key"] for n, e in net_signer.load_public_ring(p).items()}
    except (ValueError, KeyError, TypeError, AttributeError):
        copy = None
    try:
        one = {n: e["key"] for n, e in sign.load_keyring(p)["verifiers"].items()}
    except sign.Unverifiable:
        one = None
    return copy, one


@pytest.mark.parametrize(
    "raw",
    [
        {"verifiers": [_entry()]},
        {"verifiers": [_entry(), _entry(name="bo")]},
        {"verifiers": [_entry(private="00")]},
        {"verifiers": [_entry(kind="hmac")]},
        {"verifiers": [_entry(key="00" * 31)]},
        {"verifiers": [_entry(key="zz")]},
        {"verifiers": [_entry(revoked_at="2026-01-01", compromised=True, reason="x")]},
    ],
)
def test_loaders_give_the_same_verdict_and_keys_on_the_shared_cases(sign, tmp_path, raw):
    copy, one = _agree(sign, tmp_path, raw)
    assert copy == one


def test_the_known_differences_are_the_one_scripts_being_stricter_on_fields(sign, tmp_path):
    # nestor's rule: any field NAMED for private material refuses; net_signer's
    # refuses a truthy `private` and a `legacy_key`. Both stay (the trust owner's
    # ring reader is not widened or narrowed); neither accepts a private half.
    copy, one = _agree(sign, tmp_path, {"verifiers": [_entry(seed="00")]})
    assert one is None and copy is not None  # sign refuses, net_signer never looked at `seed`
    copy, one = _agree(sign, tmp_path, {"verifiers": [_entry()], "legacy_key": "00"})
    assert copy is None and one is not None  # net_signer refuses a legacy_key ring; the verifier side ignores it
    copy, one = _agree(sign, tmp_path, {"verifiers": [_entry(private="")]})
    assert copy is not None and one is None  # an empty `private` field still names private material to sign.py


# ---- HMAC seals: dispatch_signing and session_binder keep their own, same bytes

def test_dispatch_signing_hmac_is_the_one_scripts(sign, monkeypatch):
    key = b"d" * 32
    monkeypatch.setattr(dispatch_signing, "_ensure_key", lambda: key)
    meta = {"from_app": "a", "to_app": "b", "priority": 1, "t": "é"}
    assert dispatch_signing.sign_meta(meta) == sign.hmac_hex(key, dispatch_signing._canonical_bytes(meta))
    meta["signature"] = dispatch_signing.sign_meta(meta)
    assert dispatch_signing.signature_status(meta) == dispatch_signing.SIG_VALID


def test_session_binder_hmac_is_the_one_scripts(sign):
    key = b"s" * 32
    header = {k: "v" for k in session_binder._SIGNED_FIELDS}
    assert session_binder.expected_header_sig(key, header) == sign.hmac_hex(key, session_binder._canonical(header))
    msg = json.dumps(["call", "sid", "app", "tool", "n"], separators=(",", ":")).encode()
    assert session_binder.call_sig(key, "sid", "app", "tool", "n") == sign.hmac_hex(key, msg)
    assert session_binder.call_sig(key, "sid", "app", "tool", "n") == hmac.new(key, msg, hashlib.sha256).hexdigest()


# ---- keyring generation: what the kept keyring makes, the one verifier accepts

def test_a_keyring_made_keypair_signs_what_sign_verifies(sign):
    from willow_mcp import keyring

    priv, pub = keyring._ed25519_generate()
    assert len(priv) == 32 and len(pub) == 32
    assert sign.ed25519_public_hex(priv) == pub.hex()
    sig = sign.ed25519_sign(priv, b"m")
    assert sign.ed25519_verify(pub, b"m", bytes.fromhex(sig)) == (True, "")


# ---- the trust owner's signing code stays off the reach

TRUST_SIGNING_MODULES = (
    "keyring", "human_session", "net_signer", "seal_ring", "dispatch_signing",
    "session_binder", "manifest_grant_executor", "egress_authorization",
)


def _names_the_reach(text: str) -> bool:
    return re.search(r"onescript_(sign|reach)", text) is not None


def _trust_modules_naming_the_reach(root: Path) -> list[str]:
    return [
        n for n in TRUST_SIGNING_MODULES
        if _names_the_reach((root / f"{n}.py").read_text(encoding="utf-8"))
    ]


def test_trust_owner_signing_modules_do_not_import_the_one_script():
    """keyring, human_session, net_signer, seal_ring, dispatch_signing,
    session_binder, manifest_grant_executor and egress_authorization are loaded
    by the root-owned venv (operator ruling 2026-10-21): they keep their own
    signing code and never name the reach."""
    import willow_mcp

    assert _trust_modules_naming_the_reach(Path(willow_mcp.__file__).parent) == []


def test_the_reach_guard_fires_on_a_planted_import(tmp_path):
    for n in TRUST_SIGNING_MODULES:
        (tmp_path / f"{n}.py").write_text("import hmac\n", encoding="utf-8")
    (tmp_path / "net_signer.py").write_text("from .onescript_sign import sign\n", encoding="utf-8")
    (tmp_path / "keyring.py").write_text("from . import onescript_reach\n", encoding="utf-8")
    assert _trust_modules_naming_the_reach(tmp_path) == ["keyring", "net_signer"]
    assert _names_the_reach("from .onescript_sign import sign")
    assert not _names_the_reach("import hmac")
