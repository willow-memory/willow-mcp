"""sign.py -- signing and keys, once (flatten-2 F14).

Four places turned the same few rules into code: the bytes a Nestor seal is
signed over (`nestor_seal.message` and willow-mcp `net_signer.seal_message`,
byte-identical), the rules a public-only keyring must pass, raw-hex Ed25519
sign and verify (the one script, willow-mcp `session_signing`, `net_signer`,
Grove `u2u`), and the HMAC seals (`gate`, `bound_receipt`, `session_signing`).
The operator: "Using the onescript at every path." Key FILES and where they
live do not move; this module reads and writes none of them.

What is here, by name:

    seal_message         the bytes a Nestor seal covers (canon.compact_utf8)
    load_keyring         the public-only keyring rules (nestor_seal's, verbatim)
    ed25519_verify       raw Ed25519, ONE pinned verifier (below)
    ed25519_sign         raw 32-byte private key -> hex signature
    verifier_pin         the library, its version and the rules, to stamp a record
    hmac_hex, hmac_parts, hmac_equal   the HMAC-SHA256 seal and its constant-time check

THE PINNED VERIFIER. Ed25519 verifiers disagree across libraries: whether a
non-canonical ``s`` (``s >= L``) is accepted, whether the check is cofactored
(``[8][s]B = [8]R + [8][k]A``) or not, whether a non-canonical or small-order
public key is. (RFC 8032 section 5.1.7 and ZIP-215 differ; two libraries can
accept and reject the same signature.) This module fixes ONE verifier:

  * the signature is exactly 64 bytes, ``s`` is read little-endian and must be
    ``< L`` (checked here, before the library is called);
  * the public key is exactly 32 bytes, its ``y`` must be ``< p`` (canonical)
    and it must not be one of the eight small-order points (either sign bit);
  * then ``cryptography``'s single, cofactorless ``verify``. Never a batch
    verify, never another library's, never mixed with one: a signature that
    passes one rule set and fails another is how two machines come to disagree
    about a seal.

``verifier_pin()`` records the library and its version so a record can stamp
which verifier said yes. Rejecting more than a copy did is allowed; accepting
what a copy rejected is not (every extra check here only narrows).

Needs ``cryptography`` for Ed25519 and says so (``have_ed25519``): without it
the answer is ``unreachable`` (``NO_CRYPTO``), never a silent pass and never a
silent refusal of every real seal. HMAC needs only the standard library.

Never write or print a real key here: tests generate throwaway ones.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

from . import canon_local as canon

#: The Ed25519 group order and field prime (RFC 8032 section 5.1).
L = 2**252 + 27742317777372353535851937790883648493
P = 2**255 - 19

_Y_MASK = (1 << 255) - 1

#: ``y`` of the eight small-order points (five distinct values); the sign bit of
#: an encoding is ignored when matching, so both signs of each are refused.
_SMALL_ORDER_Y = frozenset(
    {
        0,
        1,
        P - 1,
        int.from_bytes(
            bytes.fromhex(
                "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"
            ),
            "little",
        )
        & _Y_MASK,
        int.from_bytes(
            bytes.fromhex(
                "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"
            ),
            "little",
        )
        & _Y_MASK,
    }
)

#: The verifier's version id; bump it if a rule above changes.
PIN_ID = "wgrv-sign-ed25519/v1"

#: Said when the Ed25519 check can't run here. It is `unreachable`, not a
#: refusal of the signature itself: it was never judged.
NO_CRYPTO = "unreachable: an ed25519 seal needs the cryptography package here"

#: What an Ed25519 check that ran and said no is called.
BAD_SIGNATURE = "the signature does not verify"


class Unverifiable(ValueError):
    """The keyring or store can't be read. Said plainly, never a pass."""


# --------------------------------------------------------------- seal message


def seal_message(source_norm: str, target_text: str, verifier: str) -> bytes:
    """The bytes a Nestor seal signature is taken over (frozen by Nestor): the
    JSON array ``[source_norm, target_text, verifier]``, compact separators,
    ``ensure_ascii=False``, UTF-8. willow-mcp ``net_signer.seal_message`` keeps
    its own copy for the trust owner's root-owned venv, held to this by
    ``willow-mcp/tests/test_sign_parity.py``."""
    return canon.compact_utf8.bytes([source_norm, target_text, verifier])


# --------------------------------------------------------------- keyring

#: A keyring is public keys. An entry with a field named for private material is
#: refused, whatever else it holds.
PRIVATE_FIELDS = ("priv", "secret", "seed", "passphrase", "signing", "hmac")


def load_keyring(path: str | Path) -> dict:
    """The operator's keyring file, as the verifying side needs it: name -> key.

    Only ed25519 public keys are accepted. An HMAC entry is a shared secret
    (whoever can verify with it can also forge with it), and an entry that
    carries private material is a keyring someone else could have written from
    the signing side; both are refused, naming the entry, never skipped. A key
    is exactly 32 bytes."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        entries = {}
        for v in raw.get("verifiers", []):
            name = str(v["name"])
            odd = sorted(
                k for k in v if any(p in str(k).lower() for p in PRIVATE_FIELDS)
            )
            if odd:
                raise Unverifiable(
                    f"keyring entry {name!r} carries {odd}; a keyring holds public "
                    "keys only"
                )
            kind = str(v.get("kind", ""))
            if kind != "ed25519":
                raise Unverifiable(
                    f"keyring entry {name!r} is kind {kind!r}; only ed25519 "
                    "public keys are accepted"
                )
            key = bytes.fromhex(v["key"])
            if len(key) != 32:
                raise Unverifiable(f"keyring entry {name!r} is not a 32-byte key")
            # Nestor's own fields (`nestor.keyring.VerifierKey`): a key is revoked
            # when `revoked_at` is set; `compromised` says why that matters.
            entries[name] = {
                "key": key,
                "kind": kind,
                "compromised": bool(v.get("compromised", False)),
                "revoked": bool(v.get("revoked_at", "")),
                "reason": str(v.get("reason", "")),
            }
    except Unverifiable:
        raise
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        raise Unverifiable(f"keyring unreadable: {type(e).__name__}") from e
    return {"verifiers": entries}


# --------------------------------------------------------------- ed25519


def have_ed25519() -> bool:
    """Whether this interpreter can check an ed25519 seal at all."""
    try:
        import cryptography.hazmat.primitives.asymmetric.ed25519  # noqa: F401
    except ImportError:
        return False
    return True


def verifier_pin() -> dict:
    """What a record stamps to say which verifier said yes: the id of these
    rules, the library, its version. ``library`` is ``None`` when it is absent
    (then every verify is ``unreachable``)."""
    try:
        import cryptography

        lib, ver = "cryptography", str(cryptography.__version__)
    except ImportError:
        lib, ver = None, None
    return {
        "id": PIN_ID,
        "library": lib,
        "version": ver,
        "rules": [
            "sig 64 bytes, s < L",
            "public key 32 bytes, y < p, not small-order",
            "single cofactorless verify, never batch",
        ],
    }


def public_key_problem(key: bytes) -> str:
    """ "" when `key` is an acceptable Ed25519 public key encoding; else why.
    32 bytes, canonical ``y`` (``< p``), not one of the eight small-order points."""
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        return "the public key is not 32 bytes"
    y = int.from_bytes(key, "little") & _Y_MASK
    if y >= P:
        return "the public key is a non-canonical encoding"
    if y in _SMALL_ORDER_Y:
        return "the public key is a small-order point"
    return ""


def signature_problem(sig: bytes) -> str:
    """ "" when `sig` is a canonical Ed25519 signature shape; else why.
    64 bytes, ``s`` (the last 32, little-endian) strictly below ``L``."""
    if not isinstance(sig, (bytes, bytearray)) or len(sig) != 64:
        return "the signature is not 64 bytes"
    if int.from_bytes(sig[32:], "little") >= L:
        return "the signature's s is not canonical (s >= L)"
    return ""


def ed25519_verify(key: bytes, msg: bytes, sig: bytes) -> tuple[bool, str]:
    """(True, "") when `sig` is a valid Ed25519 signature of `msg` under the raw
    32-byte `key`, by the pinned rules above; else (False, why). `why` is
    ``NO_CRYPTO`` when the library is missing (unreachable: nothing was judged)
    and ``BAD_SIGNATURE`` when the library ran and said no. Never raises on bad
    input."""
    why = public_key_problem(key) or signature_problem(sig)
    if why:
        return False, why
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return False, NO_CRYPTO
    try:
        Ed25519PublicKey.from_public_bytes(bytes(key)).verify(bytes(sig), msg)
    except (InvalidSignature, ValueError):
        return False, BAD_SIGNATURE
    return True, ""


def ed25519_verify_hex(key_hex: str, msg: bytes, sig_hex: str) -> tuple[bool, str]:
    """As `ed25519_verify`, with the key and signature as hex strings. Bad hex
    is (False, why), never a raise."""
    try:
        key, sig = bytes.fromhex(key_hex), bytes.fromhex(sig_hex)
    except (ValueError, TypeError):
        return False, "the key or signature is not hex"
    return ed25519_verify(key, msg, sig)


def ed25519_sign(private_key: bytes, msg: bytes) -> str:
    """Sign `msg` with a raw 32-byte Ed25519 private key; the signature as hex.
    Raises ``ValueError`` for a key that isn't 32 bytes (the signing side has
    no `unreachable` to say; the caller holds the key)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(bytes(private_key)).sign(msg).hex()


def ed25519_public_hex(private_key: bytes) -> str:
    """The raw public key (hex) of a raw 32-byte private key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return (
        Ed25519PrivateKey.from_private_bytes(bytes(private_key))
        .public_key()
        .public_bytes_raw()
        .hex()
    )


def ed25519_generate() -> bytes:
    """A fresh raw 32-byte private key. The CALLER decides where it is kept; this
    writes no file."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.generate().private_bytes_raw()


# --------------------------------------------------------------- hmac


def hmac_hex(key: bytes, message: bytes) -> str:
    """HMAC-SHA256 of `message` under `key`, hex (willow-mcp `bound_receipt` and
    `session_signing`; the gate's seal is `hmac_parts`)."""
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def hmac_parts(key: bytes, *parts: str) -> str:
    """The gate's seal: HMAC-SHA256 over the parts joined by ``\\x1f``, UTF-8."""
    return hmac_hex(key, "\x1f".join(parts).encode())


def hmac_equal(a: str | bytes, b: str | bytes) -> bool:
    """Constant-time equality for two proofs. A ``str`` is UTF-8 with
    ``errors="replace"`` first, so a non-ASCII or lone-surrogate proof is a
    plain mismatch, never a ``TypeError`` (and never a match)."""
    if isinstance(a, str):
        a = a.encode("utf-8", "replace")
    if isinstance(b, str):
        b = b.encode("utf-8", "replace")
    return hmac.compare_digest(a, b)
