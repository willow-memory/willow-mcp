"""willow-mcp keys — who can attest for a session, and with what key.

Thin CLI shell around :mod:`willow_mcp.keyring`. Ported from
``nestor/cli.py::cmd_keys`` in the same shape and with the same operator UX:

* ``willow-mcp keys add NAME [--type ed25519 --public HEX] [--rotate]``
  Adds a verifier. Without ``--type`` this generates an ed25519 keypair
  locally. With ``--public`` it registers a peer's public key — this instance
  can then verify that peer's attestations without ever being able to produce
  one.
* ``willow-mcp keys revoke NAME [--reason TEXT] [--compromised]``
  Retires a key. ``--compromised`` means the key was taken and every
  attestation it signed becomes unservable (surfaces via
  ``sessions_unverifiable``, PR4). Without it, past attestations still serve;
  the key just cannot make new ones.
* ``willow-mcp keys list [--json]``
  Enumerates verifiers, with status.
* ``willow-mcp keys status NAME``
  Reports one verifier's status.

The subparser wiring lives in :func:`register` — call it from wherever
``willow-mcp``'s main argparse builder assembles subcommands.
"""
from __future__ import annotations

import argparse
import json as _json
import sys

from . import keyring as keyring_mod

EXIT_OK = 0
EXIT_USAGE = 2


def _emit(payload: dict, as_json: bool, human: str) -> None:
    if as_json:
        print(_json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(human)


def cmd_keys(args: argparse.Namespace) -> int:
    """Dispatch a ``willow-mcp keys`` subcommand. Returns an exit code."""
    path = args.keyring or keyring_mod.keyring_path()
    if not path:
        print(
            "no keyring path: pass --keyring PATH or set WILLOW_KEYRING.\n"
            "Without one, the legacy PGP-fingerprint path stays in force and "
            "an attestation proves the key was present, not who was.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    if args.keys_command == "list":
        try:
            ring = keyring_mod.load(path)
        except keyring_mod.KeyringError as exc:
            print(f"cannot read keyring at {path}: {exc}", file=sys.stderr)
            return EXIT_USAGE
        rows = [
            {
                "name": e.name,
                "status": ring.status(e.name),
                "created_at": e.created_at,
                "revoked_at": e.revoked_at,
                "reason": e.reason,
                "kind": e.kind,
            }
            for e in ring.entries()
        ]
        human_lines = [f"{len(rows)} verifier(s) in {path}"]
        for r in rows:
            note = f"  {r['reason']}" if r["reason"] else ""
            kind_note = f" [{r['kind']}]"
            human_lines.append(
                f"  {r['status']:<12} {r['name']}{kind_note}{note}"
            )
        if ring.legacy_key:
            human_lines.append(
                "  legacy       (attestations made before this keyring still verify)"
            )
        _emit(
            {
                "keyring": path,
                "verifiers": rows,
                "legacy_key": bool(ring.legacy_key),
            },
            args.json,
            "\n".join(human_lines),
        )
        return EXIT_OK

    if args.keys_command == "status":
        if not args.name:
            print("`willow-mcp keys status` needs a NAME.", file=sys.stderr)
            return EXIT_USAGE
        try:
            ring = keyring_mod.load(path)
        except keyring_mod.KeyringError as exc:
            print(f"cannot read keyring at {path}: {exc}", file=sys.stderr)
            return EXIT_USAGE
        entry = ring.get(args.name)
        status = ring.status(args.name)
        payload = {
            "keyring": path,
            "name": args.name,
            "status": status,
            "kind": entry.kind if entry else None,
            "created_at": entry.created_at if entry else "",
            "revoked_at": entry.revoked_at if entry else "",
            "reason": entry.reason if entry else "",
        }
        human = f"{args.name}: {status}"
        if entry and entry.reason:
            human += f" ({entry.reason})"
        _emit(payload, args.json, human)
        return EXIT_OK

    # add / revoke both write, so both start from whatever is there (or nothing).
    try:
        ring = keyring_mod.load(path)
    except keyring_mod.KeyringError:
        if args.keys_command != "add":
            raise
        ring = keyring_mod.Keyring(path=path)

    if args.keys_command == "add":
        if not args.name:
            print("`willow-mcp keys add` needs a NAME.", file=sys.stderr)
            return EXIT_USAGE
        # Legacy PGP-fingerprint bridge is not this PR's job -- see the
        # module docstring's "Legacy fingerprint migration is not this
        # module's job" note. --adopt-shared-key is accepted for CLI shape
        # parity with the plan and rejected here with a message pointing
        # forward.
        if getattr(args, "adopt_shared_key", False):
            print(
                "--adopt-shared-key is not wired in PR1 (this PR ships the "
                "keyring primitive only). Legacy PGP-fingerprint migration "
                "lands with PR3's client-signing seam; see "
                "docs/design/identity-in-session.md when it exists.",
                file=sys.stderr,
            )
            return EXIT_USAGE
        peer_key = bytes.fromhex(args.public) if args.public else None
        try:
            entry = ring.add(
                args.name, key=peer_key, rotate=args.rotate, kind=args.key_type
            )
        except keyring_mod.KeyringError as exc:
            print(str(exc), file=sys.stderr)
            return EXIT_USAGE
        ring.save(path)
        # Print the half that actually opens a client-signing session. For a
        # peer-registered ed25519 (--public HEX) there is no signing key to
        # hand back -- the caller supplied the public half and the private
        # half lives with them. For a locally-generated ed25519 the private
        # half is what the operator's client-signer needs. For hmac (not the
        # recommended path here) it is the shared secret.
        if entry.kind == "ed25519" and not entry.private:
            _emit(
                {
                    "keyring": path,
                    "name": entry.name,
                    "kind": entry.kind,
                    "public_key": entry.key.hex(),
                    "rotated": args.rotate,
                },
                args.json,
                f"added {entry.name} to {path} (ed25519, public key only)\n"
                f"  public  {entry.key.hex()}\n"
                f"  This is {entry.name}'s PUBLIC key: it verifies their "
                f"attestations but cannot sign one. {entry.name} signs "
                f"client-side with the private half, which never reaches "
                f"this instance; the keyring file is 0600 and holds only "
                f"this public copy.",
            )
            return EXIT_OK
        sign_key = (
            entry.private if entry.kind == "ed25519" else entry.key
        ).hex()
        kind_note = " (ed25519)" if entry.kind == "ed25519" else " (hmac)"
        stored_note = (
            "the file itself is 0600 and holds this signing key alongside "
            "the public half willow verifies attestations against."
            if entry.kind == "ed25519"
            else "the file itself is 0600 and holds the copy willow verifies "
            "against."
        )
        _emit(
            {
                "keyring": path,
                "name": entry.name,
                "kind": entry.kind,
                "key": sign_key,
                "rotated": args.rotate,
            },
            args.json,
            f"added {entry.name} to {path}{kind_note}\n"
            f"  key  {sign_key}\n"
            f"  This is the only time it is printed. {entry.name} needs it "
            f"to attest a session; {stored_note}",
        )
        return EXIT_OK

    if args.keys_command == "revoke":
        if not args.name:
            print("`willow-mcp keys revoke` needs a NAME.", file=sys.stderr)
            return EXIT_USAGE
        try:
            entry = ring.revoke(
                args.name, reason=args.reason, compromised=args.compromised
            )
        except keyring_mod.UnknownVerifierError as exc:
            print(str(exc), file=sys.stderr)
            return EXIT_USAGE
        ring.save(path)
        consequence = (
            "Every attestation it signed stops being served and lands in "
            "the unverifiable list (PR4) for re-attestation — a stolen "
            "key's attestations cannot be told apart from the thief's."
            if entry.compromised
            else "Attestations it already made keep serving: nobody else "
            "held the key, so they are still that operator's sessions. It "
            "just cannot make new ones."
        )
        _emit(
            {
                "keyring": path,
                "name": entry.name,
                "status": ring.status(entry.name),
                "compromised": entry.compromised,
                "reason": entry.reason,
                "revoked_at": entry.revoked_at,
            },
            args.json,
            f"revoked {entry.name} ({ring.status(entry.name)})\n"
            f"  {consequence}",
        )
        return EXIT_OK

    print(
        f"unknown keys subcommand {args.keys_command!r}", file=sys.stderr
    )
    return EXIT_USAGE


def register(subparsers: "argparse._SubParsersAction") -> None:
    """Register the ``keys`` subparser on a willow-mcp argparse subparsers."""
    keys = subparsers.add_parser(
        "keys",
        help="who can attest for a session, and with what key",
    )
    keys.add_argument(
        "keys_command", choices=("list", "add", "revoke", "status")
    )
    keys.add_argument("name", nargs="?", default="", help="the verifier")
    keys.add_argument(
        "--keyring",
        default="",
        help="keyring file path (default: $WILLOW_KEYRING)",
    )
    keys.add_argument(
        "--rotate",
        action="store_true",
        help="replace an existing entry (invalidates its past attestations "
        "if they can no longer verify)",
    )
    keys.add_argument(
        "--type",
        dest="key_type",
        default="ed25519",
        choices=("hmac", "ed25519"),
        help="ed25519 (default) generates a keypair locally; hmac is provided "
        "for parity with Nestor but puts the operator's signing secret on "
        "the server",
    )
    keys.add_argument(
        "--public",
        default="",
        help="ed25519: register a peer's PUBLIC key (32-byte hex). Verifies "
        "their attestations; cannot sign one",
    )
    keys.add_argument(
        "--reason", default="", help="recorded with a revocation"
    )
    keys.add_argument(
        "--compromised",
        action="store_true",
        help="revoke: the key was taken; past attestations become unservable",
    )
    keys.add_argument(
        "--adopt-shared-key",
        dest="adopt_shared_key",
        action="store_true",
        help="reserved for PR3's PGP-fingerprint migration; rejected in PR1",
    )
    keys.add_argument(
        "--json", action="store_true", help="machine-readable output"
    )
    keys.set_defaults(func=cmd_keys)
