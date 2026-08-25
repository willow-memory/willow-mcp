"""willow-mcp sign-session — client-side session attestation signer.

PR3 of the identity-in-session plan. Replaces the server-side pinentry burden
that `willow-mcp attest-session` invokes by moving signing off the MCP server
process onto the operator's own device (keyring file). The signing key never
reaches the server process — matches the Nestor discipline shipped in
decision `0077` (``memory.add_pair(..., seal_sig=...)`` — the server verifies
a client-produced signature, never signs on the caller's behalf).

The mechanic:

1. Operator runs ``willow-mcp sign-session <session_id> --verifier <name>``
   from their own terminal. The command requires an operator-owned tty and
   refuses inside Kart, same guard ``attest-session`` uses.
2. The command reads the live session record at ``sessions/willow-{id}.json``
   as proof ``session_enter`` bound this id.
3. It builds the ``orchestrator_session_attestation_v2`` sidecar payload
   (``{format, app_id, session_id, verifier, attested_at}`` — verifier is
   the field this bumps from v1) and signs it using the operator's ed25519
   private key held in ``$WILLOW_KEYRING``.
4. Sidecar and hex-encoded signature land next to each other at
   ``sessions/willow-{id}.attest.json`` (paths.session_attestation_path) and
   ``sessions/willow-{id}.attest.json.sig``, atomically with prior-content
   rollback on failure — same discipline ``attest-session`` uses so a failed
   re-sign cannot leave an unsigned sidecar on disk.
5. ``human_session.orchestrator_write_denial`` (updated in this PR) reads
   the v2 sidecar via :mod:`willow_mcp.session_signing` and verifies against
   the keyring's verifying key for ``verifier``. Legacy ``_v1`` sidecars
   continue to verify through the existing PGP path.

Assumes same-machine deployment (the operator's keyring is on the same box
as the sessions/ directory — the typical local willow-mcp deployment).
Multi-machine deployments will need a wire protocol for handing the signed
sidecar back; that's out of scope for PR3.

Compare Nestor's client-side surface: ``nestor/ui_page.py`` runs WebCrypto
Ed25519 non-extractable in a browser. Willow's equivalent browser page is
optional and deferred to a follow-up — the terminal signer is the MVP that
removes the pinentry-on-server pain today.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Optional

from . import keyring as keyring_mod
from . import session_signing


EXIT_OK = 0
EXIT_USAGE = 2
EXIT_FAIL = 1

ATTEST_FORMAT_V2 = "orchestrator_session_attestation_v2"


def _now_iso_z() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _build_payload(session_id: str, verifier: str, attested_at: str) -> dict:
    """The v2 sidecar payload. Order matches ``session_signing._message``'s
    field order for the signed bytes — the sidecar itself is stored as
    sorted JSON but the signature is over the frozen wire message, which
    uses this order."""
    return {
        "format": ATTEST_FORMAT_V2,
        "app_id": "willow",
        "session_id": session_id,
        "verifier": verifier,
        "attested_at": attested_at,
    }


def cmd_sign_session(args: argparse.Namespace) -> int:
    """Sign a session attestation client-side under the operator's keyring key.

    Returns an exit code. Refuses on:
    * keyring not enabled (no ``WILLOW_KEYRING``) → point at ``attest-session``
      which still handles the legacy PGP path.
    * no operator-owned tty (require_operator_terminal fails).
    * no live session record on disk → session_enter has not run.
    * verifier not in the keyring, or holds only the public half → cannot
      sign as them here.
    """
    from . import human_session
    from . import paths

    if not keyring_mod.enabled():
        print(
            "Error: WILLOW_KEYRING is not set. sign-session is the client-signing "
            "path for the per-verifier keyring; without one, use "
            "`willow-mcp attest-session` (legacy PGP-fingerprint path). See "
            "docs/design/pgp-and-persona.md.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    try:
        human_session.require_operator_terminal()
    except PermissionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    session_id = (args.session_id or "").strip()
    if not session_id:
        print("Error: session_id is required", file=sys.stderr)
        return EXIT_USAGE
    verifier = (args.verifier or "").strip()
    if not verifier:
        print(
            "Error: --verifier NAME is required. This names the operator who "
            "is attesting the session; it must match an entry in the keyring "
            "at $WILLOW_KEYRING (add one with `willow-mcp keys add NAME`).",
            file=sys.stderr,
        )
        return EXIT_USAGE

    live_session = paths.session_path("willow", session_id)
    if not live_session.is_file():
        print(
            f"Error: no live session file at {live_session} — "
            f"call session_enter(app_id='willow', session_id={session_id!r}) "
            "before signing.",
            file=sys.stderr,
        )
        return EXIT_FAIL

    ring = keyring_mod.get_keyring()
    assert ring is not None  # keyring_mod.enabled() said so above
    try:
        entry = ring.signing_entry(verifier)  # raises Unknown / Revoked / public-only
    except (
        keyring_mod.UnknownVerifierError,
        keyring_mod.RevokedKeyError,
        keyring_mod.KeyringError,
    ) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_FAIL

    attested_at = _now_iso_z()

    # Sign the frozen wire message. session_signing.sign_session() consults
    # the keyring for the private half; no key ever leaves this process.
    try:
        sig_hex = session_signing.sign_session(
            app_id="willow",
            session_id=session_id,
            verifier=verifier,
            attested_at=attested_at,
        )
    except session_signing.SigningRequiredError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_FAIL

    payload = _build_payload(session_id, verifier, attested_at)

    attest_file = paths.session_attestation_path("willow", session_id)
    sig_file = attest_file.parent / f"{attest_file.name}.sig"
    attest_file.parent.mkdir(parents=True, exist_ok=True)

    # Preserve prior sidecar+sig so a failed re-sign leaves the previous
    # attestation intact. Same discipline attest-session uses (see the
    # `previous_attest` / `previous_sig` handling in server._cmd_attest_session).
    previous_attest: Optional[bytes] = (
        attest_file.read_bytes() if attest_file.is_file() else None
    )
    previous_sig: Optional[bytes] = (
        sig_file.read_bytes() if sig_file.is_file() else None
    )

    try:
        # Sidecar stored as sorted-JSON for stable diffing; signature is
        # over session_signing._message which uses field-order, not
        # sort-order (the two are decoupled by design — sidecar readability
        # vs signature stability).
        attest_file.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        sig_file.write_text(sig_hex + "\n", encoding="utf-8")
    except OSError as exc:
        # Rollback on any write failure so the on-disk state stays coherent.
        if previous_attest is not None:
            attest_file.write_bytes(previous_attest)
        elif attest_file.is_file():
            attest_file.unlink()
        if previous_sig is not None:
            sig_file.write_bytes(previous_sig)
        elif sig_file.is_file():
            sig_file.unlink()
        print(f"Error: could not write attestation: {exc}", file=sys.stderr)
        return EXIT_FAIL

    key_kind = entry.kind
    print(
        f"Attested (v2, {key_kind}): {attest_file}\n"
        f"  verifier    {verifier}\n"
        f"  attested_at {attested_at}\n"
        f"  sig         {sig_file}\n"
        "\n"
        f"orchestrator_write_denial verifies this against {verifier}'s key in "
        "the keyring. Ordinary session writes (session_handoff_write, "
        "dispatch_accept, agent_clear, ...) do not invalidate it — the "
        "signed payload is identity-only."
    )
    return EXIT_OK


def register(subparsers: "argparse._SubParsersAction") -> None:
    """Register the ``sign-session`` subparser on a willow-mcp argparse
    subparsers action."""
    p = subparsers.add_parser(
        "sign-session",
        help="Client-side sign a v2 orchestrator session attestation using the "
        "operator's keyring key (PR3; operator terminal only; replaces "
        "attest-session's server-side pinentry burden for keyring-enabled "
        "deployments)",
    )
    p.add_argument(
        "session_id",
        help="session_id passed to session_enter(app_id='willow', ...)",
    )
    p.add_argument(
        "--verifier",
        required=True,
        help="verifier name in the keyring (must match a `willow-mcp keys add`)",
    )
    p.set_defaults(func=cmd_sign_session)
