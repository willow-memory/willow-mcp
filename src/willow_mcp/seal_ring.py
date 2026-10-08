"""The ring a Nestor SEAL is verified against: the signer's public ring.

Two jobs used to share one file. ``WILLOW_KEYRING`` is the seat's own
keyring: session attestation signs with it (``sign-session`` needs a private
half) and envelope attribution reads it. Nestor seals are signed by a
different party -- nestor-ui, with ``$WILLOW_HOME/verifiers.json`` -- so a
seal can only be checked against a ring that carries the SIGNER's public key.
When the seat keyring was regenerated (2026-10-01) it silently became a
different keypair under the same verifier name, and every seal made after
2026-09-14 stopped verifying here (Ada 0B46D2DF, willows-grove
``docs/design/nestor-seal-keyring.md``).

Every seal-verification site (``reloader``, ``manifest_grant_executor``,
``seed_loader``, ``constitutional``) now resolves its ring here instead:

* ``WILLOW_SEAL_RING`` if set, else ``/etc/willow-mcp/verifiers.public.json``
  -- the root-owned, public-only export of the signer's keyring, already the
  net-signer's anchor;
* public halves only: a file carrying a ``private`` half, a ``legacy_key``,
  or any non-ed25519 entry is refused (``net_signer.load_public_ring_bytes``);
* a missing, unreadable, malformed or empty ring is ``unreachable`` -- there
  is no fallback to ``WILLOW_KEYRING`` and nothing passes without a ring.

Session attestation, ``sign-session`` and envelope attribution do not import
this module and keep reading ``WILLOW_KEYRING`` exactly as before.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

SEAL_RING_ENV = "WILLOW_SEAL_RING"
DEFAULT_SEAL_RING = Path("/etc/willow-mcp/verifiers.public.json")


def seal_ring_path() -> Path:
    """The configured seal ring: ``WILLOW_SEAL_RING``, else the system default."""
    raw = os.environ.get(SEAL_RING_ENV, "").strip()
    return Path(raw).expanduser() if raw else DEFAULT_SEAL_RING


def load_seal_ring() -> tuple[Optional[dict], Optional[dict]]:
    """Load the ``net_signer.verify_seal`` ring for Nestor seals.

    Returns ``(ring, None)`` on success, or ``(None, {"state": "unreachable",
    "cause": ...})`` when the ring cannot be read or is not a public-only
    ring. Never raises and never consults ``WILLOW_KEYRING``.
    """
    from . import net_signer

    path = seal_ring_path()
    try:
        data = path.read_bytes()
    except OSError as exc:
        return None, {"state": "unreachable",
                      "cause": f"seal ring {str(path)!r} could not be read "
                               f"({type(exc).__name__}: {exc}) — a seal cannot be verified "
                               "without a ring to verify it against"}
    try:
        ring = net_signer.load_public_ring_bytes(data, path)
    except Exception as exc:  # noqa: BLE001 -- a bad ring is "no ring", never a raise
        return None, {"state": "unreachable",
                      "cause": f"seal ring {str(path)!r} is not a usable public-only ring "
                               f"({exc}) — a seal cannot be verified against it"}
    if not ring:
        return None, {"state": "unreachable",
                      "cause": f"seal ring {str(path)!r} holds no verifier — a seal cannot "
                               "be verified against an empty ring"}
    return ring, None
