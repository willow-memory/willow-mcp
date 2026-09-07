"""HMAC signing/verification for dispatch packet meta.json (B-52, issue #241).

The bite: ``$WILLOW_HOME/dispatch/`` is operator-writable (the MCP runtime
writes packets there on every ``dispatch_send``, so it cannot be locked away
from the runtime uid the way the egress signing key is -- see
``egress_setup.py``'s module docstring). Anyone with filesystem access at
that uid can ``mkdir`` a packet directory and drop a hand-written
``meta.json`` that satisfies ``dispatch._meta_is_well_formed()`` (the
pre-existing partial mitigation: format marker + required fields present),
and it would show up in ``dispatch_list``/``dispatch_read`` indistinguishable
from a packet ``dispatch_send`` actually wrote.

Fix: ``dispatch_send`` now signs every field of ``meta.json`` (everything
except the signature itself) with an HMAC-SHA256 keyed by a secret this
runtime holds, and every read path (``dispatch_read``, inherited for free by
``dispatch_accept``/``handoff_write_v4``/``session_enter``) and
``dispatch_list`` recompute and check it before treating a packet as trusted.

Key custody deliberately reuses the ``_SECRET_FILE_NAMES`` convention
(``trust_root_setup.py``) rather than the egress key's "outside WILLOW_HOME,
interactive-CLI-only" posture: the egress key authorizes real-world network
egress and is written once by an interactive operator command precisely so
the MCP runtime never needs write access to it (B-37). A dispatch signing
key has a different shape -- every ``dispatch_send`` call needs to use it, so
it MUST be readable (and, to be regenerated on a fresh install, writable) by
the runtime uid; there is no interactive-CLI-only option here without
breaking `dispatch_send` itself. So instead of hiding the key from the
runtime, this follows ``vault.key``'s posture: a top-level $WILLOW_HOME file,
auto-created 0600 on first use, named in ``_SECRET_FILE_NAMES`` so
``repair-runtime-perms``/``harden-trust-root`` give it the SAME owner-only
custody vault.key gets. On a single-uid host (every install today, per B-32's
own accounting) the runtime uid and the operator uid are the same one, so an
attacker who can write dispatch/meta.json by hand can also read this key and
forge a signature over it -- this closes the "drop a bare {...} and it's
trusted" hole the red-team actually demonstrated (DEADBEEF), and once #231's
uid separation is deployed the key stops being readable by that same
attacker at all. Not a claim of closure beyond what every other B-3x entry in
this class already claims.

Back-compat: a packet ``meta.json`` written before this signing existed (or
one that predates any given host's cutover) has no ``signature`` field at
all. That is treated as its own status -- ``legacy_unsigned`` -- distinct
from ``invalid`` (a ``signature`` field present but wrong, i.e. the content
was edited, or someone tried to forge one without the key): legacy packets
are flagged and kept OUT of the normal trusted list (same as invalid ones)
by default, but ``dispatch_read``/``dispatch_accept`` still let them through
with a ``signature_status`` flag rather than hard-refusing -- an operator
upgrading mid-flight should not lose in-flight packets. Under
``WILLOW_MCP_STRICT_TRUST_ROOT=1`` (the repo's existing strict-mode
convention, ``lease.strict_trust_root()``), legacy-unsigned packets are
hard-refused too, on the theory that a hardened host has no excuse for an
unsigned packet still in flight. A packet with a present-but-WRONG signature
is always hard-refused on read, strict mode or not -- that is tamper
evidence, not an upgrade artifact, and mirrors B-55's ``assignment_tampered``
(never gated behind strict mode either).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets as _secrets
import stat
from pathlib import Path

from . import lease, paths

#: Signature verification outcomes for a packet's meta.json.
SIG_VALID = "valid"
SIG_LEGACY_UNSIGNED = "legacy_unsigned"
SIG_INVALID = "invalid"

_KEY_FILE_NAME = "dispatch_signing.key"
_KEY_BYTES = 32
_SIGNATURE_FIELD = "signature"
_ALG = "hmac-sha256"


def signing_key_path() -> Path:
    return paths.dispatch_signing_key_path()


def _ensure_key() -> bytes:
    """Load the runtime's dispatch-signing secret, generating it 0600 on first
    use (mirrors ``vault.py``'s ``init()``). Re-asserts 0600 on every load so a
    permission drift (e.g. a stray ``repair-runtime-perms`` gap) never leaves
    it group/world-readable between reads."""
    path = signing_key_path()
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass  # lost a create race to a concurrent caller; fall through to read
        else:
            with os.fdopen(fd, "wb") as f:
                f.write(_secrets.token_bytes(_KEY_BYTES))
    try:
        path.chmod(0o600)
    except OSError:
        pass  # best-effort hygiene; a read-only mount still lets us read the key
    return path.read_bytes()


def _canonical_bytes(meta: dict) -> bytes:
    """Canonical encoding of every meta field EXCEPT the signature itself.
    Sorted keys + compact separators so sign-time and verify-time serialize
    identically regardless of field insertion order; any change to any other
    field (from_app, to_app, assignment_sha256, priority, ...) changes this
    output and therefore invalidates the signature."""
    signable = {k: v for k, v in meta.items() if k != _SIGNATURE_FIELD}
    return json.dumps(signable, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_meta(meta: dict) -> str:
    """HMAC-SHA256 over every field of `meta` except `signature`, hex-encoded.
    Call with the packet's meta dict fully populated (minus `signature`)."""
    key = _ensure_key()
    return hmac.new(key, _canonical_bytes(meta), hashlib.sha256).hexdigest()


def signature_status(meta: dict) -> str:
    """Classify `meta`'s signature: SIG_VALID / SIG_LEGACY_UNSIGNED / SIG_INVALID.

    Never raises -- a malformed or missing key file, or a non-hex signature
    value, resolves to SIG_INVALID (fail-closed: an unreadable trust input
    must never be treated as trusted), not to SIG_LEGACY_UNSIGNED."""
    sig = meta.get(_SIGNATURE_FIELD)
    if sig is None:
        return SIG_LEGACY_UNSIGNED
    if not isinstance(sig, str) or not sig:
        return SIG_INVALID
    try:
        expected = sign_meta(meta)
    except OSError:
        return SIG_INVALID
    return SIG_VALID if hmac.compare_digest(expected, sig) else SIG_INVALID


def strict_mode() -> bool:
    """WILLOW_MCP_STRICT_TRUST_ROOT — reuses lease.py's existing convention
    rather than inventing a second strict-mode env var for the same host."""
    return lease.strict_trust_root()


def key_file_mode_exposed() -> bool:
    """True if the signing key currently exists and is group/world accessible
    (hygiene check, same shape as trust_root_setup.secret_file_exposure() —
    this key is one of _SECRET_FILE_NAMES, so that sweep already covers it;
    this standalone helper exists for direct unit testing)."""
    path = signing_key_path()
    try:
        if not path.is_file():
            return False
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return False
    return bool(mode & 0o077)
