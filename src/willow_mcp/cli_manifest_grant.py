"""willow-mcp manifest-grant — the CLI wrapper around the split
``manifest.grant`` request/apply queue (verb 18; pair ``b74019ac``,
amending ``d5504878``: the broker never publishes; unit-honesty rework
pair ``6bd11def``), and the four trust-owner verbs sharing the same queue
(``envelope.revoke``, ``manifest.retire``, ``manifest.create``,
``federation.ratify`` — pair ``1bd6fd29``).

Split out of ``server.py`` (gap ``035d287206e1``, 2026-09-22): the first
live tick of the trust-owner system unit crashed at IMPORT --
``server.py``'s module body runs several side effects that assume the
BROKER's uid and a broker-writable ``$WILLOW_HOME`` (``_receipt_log =
ReceiptLog()`` chief among them), and ``manifest-grant apply`` is the one
subcommand a DIFFERENT uid (the trust owner, ``willow-operator``) runs
routinely, via ``willow-mcp-manifest-grant.service``. This module, and
``__main__.py``'s dedicated fast path to it, let ``apply`` reach
:func:`manifest_grant_executor.manifest_grant_apply` without ever
importing ``server.py`` at all -- every function this module calls
(``manifest_grant_executor``, ``.db.get_pg``, ``.governance_ledger``,
``.human_session``) is import-safe: none of them import ``server.py`` or
construct anything under ``$WILLOW_HOME`` as a module-level side effect.

Mirrors the shape of ``cli_envelope.py`` (PR5) and ``cli_keys.py`` (PR1).
``server.py``'s own argparse tree still registers this module's
``register()`` and delegates to :func:`cmd_manifest_grant` for every OTHER
invocation path (the full CLI, in-process test calls to ``server.main()``)
-- the split only matters for ``__main__.py``'s early, server-avoiding
fast path, described there.
"""
from __future__ import annotations

import argparse
import json
import os
import sys


EXIT_OK = 0
EXIT_FAIL = 1


def cmd_manifest_grant(args: argparse.Namespace) -> int:
    """Dispatch a ``willow-mcp manifest-grant`` subcommand. Returns an exit
    code rather than raising ``SystemExit`` itself, so both call sites
    (``server.py``'s thin wrapper and ``__main__.py``'s fast path) can each
    decide how to exit their own process."""
    from . import manifest_grant_executor

    if args.mg_action == "apply":
        from .db import get_pg
        from .governance_ledger import GovernanceLedger

        pg = get_pg()
        ledger = GovernanceLedger(pg) if pg else None
        result = manifest_grant_executor.manifest_grant_apply(pair_id=args.pair_id, ledger=ledger)
        print(json.dumps(result, indent=2, default=str))
        return EXIT_OK if result.get("ok") else EXIT_FAIL

    from .human_session import require_operator_terminal

    try:
        require_operator_terminal()
    except PermissionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_FAIL

    if args.mg_action == "status":
        result = manifest_grant_executor.manifest_grant_status(args.pair_id)
        print(json.dumps(result, indent=2, default=str))
        return EXIT_FAIL if result.get("state") in ("not_found", "unreachable") else EXIT_OK

    if args.mg_action == "retry":
        from .db import get_pg
        from .governance_ledger import GovernanceLedger

        pg = get_pg()
        ledger = GovernanceLedger(pg) if pg else None
        result = manifest_grant_executor.manifest_grant_retry(
            args.app_id, args.pair_id, ledger=ledger, project="willow-mcp",
        )
        print(json.dumps(result, indent=2, default=str))
        return EXIT_OK if result.get("ok") else EXIT_FAIL

    # request
    from .db import get_pg
    from .governance_ledger import GovernanceLedger

    pg = get_pg()
    ledger = GovernanceLedger(pg) if pg else None
    result = manifest_grant_executor.manifest_grant_request(
        args.app_id,
        envelope_id=args.envelope or "",
        pair_id=args.pair_id,
        project="willow-mcp",
        ledger=ledger,
    )
    print(json.dumps(result, indent=2, default=str))
    return EXIT_OK if result.get("ok") else EXIT_FAIL


def register(subparsers: "argparse._SubParsersAction") -> None:
    """Register the ``manifest-grant`` subparser on a willow-mcp argparse
    subparsers action. Called both from ``server.py``'s main argparse
    builder (the full CLI tree) and from ``__main__.py``'s own minimal,
    server-avoiding parser for the ``apply`` fast path -- one definition,
    two front doors."""
    manifest_grant_p = subparsers.add_parser(
        "manifest-grant",
        help="manifest.grant (verb 18): request (broker, verify+write pending), "
             "apply (trust-owner unit, sign+publish), "
             "status (read pending/done/failed), retry (requeue a transient failure)",
    )
    mg_sub = manifest_grant_p.add_subparsers(dest="mg_action", required=True)

    mg_request_p = mg_sub.add_parser(
        "request",
        help="Broker side: verify a sealed pair against every precondition and "
             "write one pending request — signs nothing, cites the envelope only "
             "after the request is durable on disk",
    )
    mg_request_p.add_argument("pair_id", help="sealed Nestor pair id to request")
    mg_request_p.add_argument(
        "--envelope", dest="envelope", default="",
        help="which active manifest.grant envelope to cite (required if more than one governs 'willow')",
    )
    mg_request_p.add_argument(
        "--app-id", dest="app_id", default=os.environ.get("WILLOW_APP_ID", "willow"),
        help="orchestrator identity to run as (default $WILLOW_APP_ID or 'willow')",
    )

    mg_apply_p = mg_sub.add_parser(
        "apply",
        help="Apply side: drain pending/ (or one pair_id), re-verify "
             "the seal and pre-state fresh, sign and publish under signed_pair_lock, "
             "roll back through the same staged path on any failure. What "
             "willow-mcp-manifest-grant.timer runs, as the trust owner's own uid.",
    )
    mg_apply_p.add_argument("pair_id", nargs="?", default=None,
                            help="apply only this pending pair_id (default: drain all of pending/)")

    mg_status_p = mg_sub.add_parser(
        "status", help="Read which of pending/ done/ failed/ holds a pair_id's request",
    )
    mg_status_p.add_argument("pair_id")

    mg_retry_p = mg_sub.add_parser(
        "retry",
        help="Requeue a failed/<pair_id> request back to pending/, but only when "
             "the recorded failure reason is transient (EUNREACH/ecorrupt/"
             "eunexpected/eperm_pending); refuses eforged/eseal_mismatch/"
             "escalation/edrift by name.",
    )
    mg_retry_p.add_argument("pair_id", help="failed pair_id to requeue")
    mg_retry_p.add_argument(
        "--app-id", dest="app_id", default=os.environ.get("WILLOW_APP_ID", "willow"),
        help="orchestrator identity to run as (default $WILLOW_APP_ID or 'willow')",
    )

    manifest_grant_p.set_defaults(func=cmd_manifest_grant)
