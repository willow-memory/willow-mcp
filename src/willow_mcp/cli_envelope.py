"""willow-mcp envelope — operator surface for the envelope authoring loop.

PR5 of the envelope-accrual plan. Thin CLI shell around
:mod:`willow_mcp.envelope_authoring`. Mirrors the shape of ``cli_keys.py``
(PR1) and ``sign_session_cli.py`` (PR3):

* ``willow-mcp envelope ratify <proposal_id> --verifier NAME``
  Move a proposal from ``proposals[]`` to ``active[]``. Operator terminal
  only; keyring verifier must be active.
* ``willow-mcp envelope reject <proposal_id> --verifier NAME
  --reason TEXT [--reopen-when TEXT]``
  Record a "no" on the proposal. Same guard as ratify. ``reopen_when``
  distinguishes NEVER (empty) from NOT YET (non-empty), mirroring
  :func:`nestor.memory.reject_match`'s policy.
* ``willow-mcp envelope list [--grantee GLOB] [--verb VERB] [--json]``
  Read-only enumeration of currently active envelopes.
* ``willow-mcp envelope pending [--limit N] [--json]``
  The operator's queue view — proposals awaiting ratification, oldest
  first.

**No `propose` subcommand here** — propose is orchestrator-attributed and
lives in the MCP tool surface (``envelope_propose``); a CLI propose would
either bypass attribution (unsafe) or duplicate the MCP tool's shape
without the surrounding session context. Operators who need to seed the
registry by hand still hand-edit ``pre-approved.json`` as they always have.

**No FRANK ledger writes from the CLI path.** The subprocess doesn't hold
a Postgres connection; the ledger event is written by the MCP tool
counterparts. A CLI ratify still writes the atomic active[] rename — the
in-registry record survives — but the FRANK event is absent. Deployments
that require every ratification to be ledgered should run the equivalent
MCP tool inside an attributed session instead.
"""
from __future__ import annotations

import argparse
import json as _json
import sys

from . import envelope_authoring as _ea
from . import human_session as _human_session


EXIT_OK = 0
EXIT_USAGE = 2
EXIT_FAIL = 1


def _emit(payload: dict, as_json: bool, human: str) -> None:
    if as_json:
        print(_json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(human)


def _require_operator() -> str | None:
    """Wrap require_operator_terminal in a caller-friendly error message.
    Returns None on success, or the error message on failure."""
    try:
        _human_session.require_operator_terminal()
    except PermissionError as exc:
        return str(exc)
    return None


def cmd_envelope(args: argparse.Namespace) -> int:
    """Dispatch a ``willow-mcp envelope`` subcommand."""
    if args.envelope_command == "list":
        rows = _ea.list_active(
            grantee=args.grantee or None, verb=args.verb or None
        )
        human_lines = [
            f"{len(rows)} active envelope(s)"
            + (f" grantee={args.grantee!r}" if args.grantee else "")
            + (f" verb={args.verb!r}" if args.verb else "")
        ]
        for row in rows:
            human_lines.append(
                f"  {row['id']}  {row.get('verb')}  {row.get('grantee')}"
                + (f"  expires={row['expires_at']}" if row.get("expires_at") else "")
            )
        _emit(
            {"active": rows, "count": len(rows)}, args.json,
            "\n".join(human_lines),
        )
        return EXIT_OK

    if args.envelope_command == "pending":
        rows = _ea.list_pending(oldest_first=True, limit=args.limit)
        human_lines = [f"{len(rows)} pending proposal(s) — oldest first"]
        for row in rows:
            proposed_by = row.get("proposed_by") or {}
            human_lines.append(
                f"  {row['id']}  {row.get('verb')}  {row.get('grantee')}"
                f"  by {proposed_by.get('verifier', '?')}"
                f"  at {row.get('proposed_at', '?')}"
            )
            if row.get("notes"):
                human_lines.append(f"    reason: {row['notes']}")
        _emit(
            {"pending": rows, "count": len(rows)}, args.json,
            "\n".join(human_lines),
        )
        return EXIT_OK

    if args.envelope_command == "ratify":
        if not args.proposal_id:
            print("`willow-mcp envelope ratify` needs a proposal_id.", file=sys.stderr)
            return EXIT_USAGE
        if not args.verifier:
            print("`--verifier NAME` is required.", file=sys.stderr)
            return EXIT_USAGE
        tty_err = _require_operator()
        if tty_err:
            print(f"Error: {tty_err}", file=sys.stderr)
            return EXIT_USAGE
        try:
            row = _ea.ratify(args.proposal_id, verifier=args.verifier)
        except _ea.EnvelopeAuthoringError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return EXIT_FAIL
        _emit(
            {"ok": True, "envelope": row}, args.json,
            f"Ratified {row['id']} (verb={row['verb']}, grantee={row['grantee']}, "
            f"issued_by=root by verifier {args.verifier}).\n"
            f"  ratified_via: {row.get('ratified_via', '')}\n"
            "Note: no FRANK ledger event from CLI (subprocess has no Postgres); "
            "use the envelope_ratify MCP tool inside an attributed session to "
            "get one.",
        )
        return EXIT_OK

    if args.envelope_command == "reject":
        if not args.proposal_id:
            print("`willow-mcp envelope reject` needs a proposal_id.", file=sys.stderr)
            return EXIT_USAGE
        if not args.verifier:
            print("`--verifier NAME` is required.", file=sys.stderr)
            return EXIT_USAGE
        if not args.reason:
            print("`--reason TEXT` is required.", file=sys.stderr)
            return EXIT_USAGE
        tty_err = _require_operator()
        if tty_err:
            print(f"Error: {tty_err}", file=sys.stderr)
            return EXIT_USAGE
        try:
            row = _ea.reject(
                args.proposal_id, reason=args.reason,
                verifier=args.verifier, reopen_when=args.reopen_when,
            )
        except _ea.EnvelopeAuthoringError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return EXIT_FAIL
        never_or_not_yet = "NOT YET (reopen_when set)" if args.reopen_when else "NEVER"
        _emit(
            {"ok": True, "rejection": row}, args.json,
            f"Rejected {args.proposal_id} ({never_or_not_yet}) by verifier "
            f"{args.verifier}.\n"
            f"  reason: {args.reason}"
            + (f"\n  reopen_when: {args.reopen_when}" if args.reopen_when else "")
            + "\n"
            "Note: no FRANK ledger event from CLI (subprocess has no Postgres); "
            "use the envelope_reject MCP tool inside an attributed session to "
            "get one.",
        )
        return EXIT_OK

    print(f"unknown envelope subcommand {args.envelope_command!r}", file=sys.stderr)
    return EXIT_USAGE


def register(subparsers: "argparse._SubParsersAction") -> None:
    """Register the ``envelope`` subparser on a willow-mcp argparse
    subparsers action. Called from ``server.py``'s main argparse builder,
    same pattern as :func:`cli_keys.register` and
    :func:`sign_session_cli.register`."""
    env = subparsers.add_parser(
        "envelope",
        help="operator surface for envelope authoring: ratify a proposal, "
        "reject one, list active, view pending queue (PR5 of the "
        "envelope-accrual plan)",
    )
    env.add_argument(
        "envelope_command", choices=("list", "pending", "ratify", "reject")
    )
    env.add_argument(
        "proposal_id", nargs="?", default="",
        help="proposal id (for ratify/reject)",
    )
    env.add_argument(
        "--verifier", default="",
        help="operator verifier name from the keyring (required for "
        "ratify/reject)",
    )
    env.add_argument(
        "--reason", default="",
        help="reason for rejection (required for reject)",
    )
    env.add_argument(
        "--reopen-when", dest="reopen_when", default="",
        help="condition under which a rejection can be revisited (empty "
        "= NEVER; non-empty = NOT YET)",
    )
    env.add_argument(
        "--grantee", default="",
        help="list: filter active envelopes by grantee",
    )
    env.add_argument(
        "--verb", default="",
        help="list: filter active envelopes by verb",
    )
    env.add_argument(
        "--limit", type=int, default=50,
        help="pending: maximum proposals to show (default: 50)",
    )
    env.add_argument(
        "--json", action="store_true", help="machine-readable output"
    )
    env.set_defaults(func=cmd_envelope)
