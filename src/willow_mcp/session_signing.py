"""willow_mcp.session_signing — sign and verify session attestations.

Port of ``nestor/signing.py`` scoped to the one seam PR2 of the
identity-in-session plan needs: a frozen wire format that a client-side
signer (PR3 lands the actual signer) can reproduce byte-for-byte, and a
server-side verifier that never signs.

Same three-part contract as Nestor's signing surface:

* **The bytes a signature is taken over are frozen.** :func:`_message` is a
  wire contract, not an implementation detail. If it ever must change, that
  is a protocol version bump communicated to every out-of-process signer,
  not a refactor. ``tests/test_client_signed_sessions.py`` pins the exact
  output for a known input for exactly this reason.
* **The server verifies; it does not sign on the client-supplied path.**
  :func:`sign_session` produces a signature for CLI ergonomics (a caller
  handing a session record to the operator's own signing tool needs to be
  able to reproduce the fixture path); the load-bearing invariant is that
  :func:`session_is_valid` refuses everything unverifiable **before** any
  ``session_bind`` write.
* **The keyring resolves who signs what.** With no keyring installed,
  :func:`signing_enabled` is False and callers stay on the legacy
  PGP-fingerprint path. With a keyring installed, the verifier name is
  looked up there — an unknown name raises through :mod:`willow_mcp.keyring`
  before any bytes are computed.

The message shape is deliberately different from Nestor's seal message
(``[source_norm, target_text, verifier]``): a willow session attestation
binds ``[app_id, session_id, verifier, attested_at]``. The two protocols
must not verify each other — a Nestor seal signature reused as a willow
session attestation would silently authenticate the wrong claim if the
byte encoding accidentally lined up. Distinct field sets keep the
protocols separate at the encoding layer.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Optional

from . import keyring as keyring_mod


class InvalidSessionSignatureError(Exception):
    """A session attestation carries a signature that does not verify.

    Raised at the entry point (``session_enter``) before any session record
    is written to disk, mirroring the ``InvalidSealSignatureError`` shape
    from ``nestor/memory.py:_resolve_seal_sig``. A caller seeing this has
    handed a signature that does not match the frozen wire bytes for the
    stated verifier's key — either the caller's signer is drifting, the
    payload was tampered en route, or the verifier's key on this instance
    differs from the one that produced the signature.
    """


class SigningRequiredError(Exception):
    """Signing is required on this deployment and no key or keyring is
    available. Raised only when ``WILLOW_REQUIRE_SEAL_KEY`` is set (mirrors
    Nestor's fail-closed switch). Absent that env var, an unsignable call
    downgrades to unsigned rather than refusing."""


def _message(
    app_id: str, session_id: str, verifier: str, attested_at: str
) -> bytes:
    """The bytes a session attestation signature is taken over.

    JSON array, field order ``[app_id, session_id, verifier, attested_at]``.
    Encoded with ``separators=(",", ":")`` (no whitespace after ``,``/``:``)
    and ``ensure_ascii=False`` (non-ASCII characters emitted literally, not
    as ``\\uXXXX`` escapes). UTF-8 bytes.

    **FROZEN — a wire contract, not an implementation detail.** A client-side
    signer (PR3 lands one; the operator may write their own) reproduces these
    bytes independently, without importing this function. The two sides only
    agree if they compute *identical* bytes. If this encoding ever must
    change, that is a protocol version bump communicated to every signer, not
    a refactor. ``tests/test_client_signed_sessions.py`` pins the exact
    output for a known input.
    """
    return json.dumps(
        [app_id, session_id, verifier, attested_at],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sign_ed25519(private_key: bytes, message: bytes) -> str:
    """Sign ``message`` with a raw 32-byte Ed25519 private key. Returns hex."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.from_private_bytes(private_key)
    return priv.sign(message).hex()


def _verify_ed25519(public_key: bytes, message: bytes, sig_hex: str) -> bool:
    """Verify a hex signature against ``message`` under a raw 32-byte public key."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        sig = bytes.fromhex(sig_hex)
    except ValueError:
        return False
    pub = Ed25519PublicKey.from_public_bytes(public_key)
    try:
        pub.verify(sig, message)
        return True
    except InvalidSignature:
        return False


def _sign_hmac(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _verify_hmac(key: bytes, message: bytes, sig_hex: str) -> bool:
    return hmac.compare_digest(_sign_hmac(key, message), sig_hex)


def signing_enabled() -> bool:
    """True iff session signing is in force (a keyring is installed).

    With no keyring, the legacy PGP-fingerprint + env-var path stays in
    force and this module's server-side verifier short-circuits: nothing
    verifies, nothing raises, and callers fall back to the pre-PR2 shape.
    """
    return keyring_mod.enabled()


def sign_session(
    app_id: str,
    session_id: str,
    verifier: str,
    attested_at: str,
    key: Optional[bytes] = None,
) -> str:
    """Produce a hex signature over the frozen wire message.

    When ``key`` is passed, it is used directly (HMAC secret or Ed25519
    private half — the caller says which by keyring context). When ``key`` is
    ``None``, the keyring's ``signing_entry(verifier)`` is consulted — which
    raises :class:`willow_mcp.keyring.UnknownVerifierError` for an unknown
    name and :class:`willow_mcp.keyring.RevokedKeyError` for a revoked one,
    before any bytes are computed.

    **The server should almost never call this.** The whole point of PR3's
    client-signing seam is that operator private keys never reach the server
    process. This function exists for test fixtures and for the operator-side
    CLI (PR3's ``willow-mcp sign-session``). If the server calls it, the
    keyring must hold an entry with a local ``private`` half — which for
    ed25519 means the operator generated their key on this instance, which is
    the shape PR3 exists to leave behind.
    """
    ring = keyring_mod.get_keyring()
    if key is None:
        if ring is None:
            raise SigningRequiredError(
                "no keyring installed and no key supplied — "
                "cannot sign session attestation"
            )
        entry = ring.signing_entry(verifier)
        key = entry.private if entry.kind == "ed25519" else entry.key
        kind = entry.kind
    else:
        # Caller-supplied key — infer kind from length (Ed25519 private half
        # is 32 bytes; HMAC secrets are conventionally 32 too but we can't
        # tell them apart without more context). The keyring is the source of
        # truth when it exists; consult it for the kind.
        entry = ring.get(verifier) if ring else None
        kind = entry.kind if entry else "hmac"

    message = _message(app_id, session_id, verifier, attested_at)
    if kind == "ed25519":
        return _sign_ed25519(key, message)
    return _sign_hmac(key, message)


def session_is_valid(
    app_id: str,
    session_id: str,
    verifier: str,
    attested_at: str,
    seal_sig: str,
    key: Optional[bytes] = None,
) -> bool:
    """Verify a signature against the frozen wire message under
    ``verifier``'s public/verifying key.

    When ``key`` is passed, verify against it directly. When ``key`` is
    ``None``, look ``verifier`` up in the keyring — a name the keyring does
    not know or has revoked as compromised returns False without raising.
    That downgrade shape matches Nestor's ``seal_is_valid``: a caller asking
    "does this signature verify?" gets a bool, not an exception. The refusal
    layer is at :func:`_resolve_session_sig` (see ``dispatch.session_enter``),
    which raises :class:`InvalidSessionSignatureError` when this returns False
    for a supplied signature.

    Empty ``seal_sig`` returns False — no signature is not a valid signature.
    """
    if not seal_sig:
        return False
    message = _message(app_id, session_id, verifier, attested_at)
    ring = keyring_mod.get_keyring()

    if key is not None:
        # Caller supplied a key. Try ed25519 first (fixed 32-byte public), then
        # HMAC. This mirrors the multi-kind fallback shape signing does; a
        # caller-supplied key with no keyring context can be either.
        if len(key) == 32 and _verify_ed25519(key, message, seal_sig):
            return True
        return _verify_hmac(key, message, seal_sig)

    if ring is None:
        return False

    entry = ring.verifying_entry(verifier)
    if entry is None:
        # Unknown OR compromised — either way, the signature does not attest
        # anything trustworthy. Compare Nestor's verifying_key(): returns None
        # for exactly these two cases.
        return False

    if entry.kind == "ed25519":
        return _verify_ed25519(entry.key, message, seal_sig)
    return _verify_hmac(entry.key, message, seal_sig)


def session_attribution(
    app_id: str,
    session_id: str,
    verifier: str,
    attested_at: str,
    seal_sig: str,
) -> str:
    """Report what a session attestation's signature proves.

    Returns one of:

    * ``"verifier"`` — signature verifies under ``verifier``'s own key in the
      keyring. Attributable to a person.
    * ``"legacy"`` — signature verifies under the keyring's ``legacy_key``
      (pre-keyring deployment migration). Signed by the deployment, not by
      any specific operator — the honest description of what shared-secret
      attestations always were.
    * ``"unsigned"`` — no signature present.
    * ``"none"`` — signature present but does not verify under any known key.

    **This is for surfaces only.** Never route a serving decision through
    this string — the serving path calls :func:`session_is_valid` and gets a
    bool. Attribution reporting is one level above that: the string tells a
    human what kind of trust a row carries, not whether to trust it.
    """
    if not seal_sig:
        return "unsigned"
    if session_is_valid(app_id, session_id, verifier, attested_at, seal_sig):
        return "verifier"
    ring = keyring_mod.get_keyring()
    if ring is not None and ring.legacy_key:
        message = _message(app_id, session_id, verifier, attested_at)
        if _verify_hmac(ring.legacy_key, message, seal_sig):
            return "legacy"
    return "none"
