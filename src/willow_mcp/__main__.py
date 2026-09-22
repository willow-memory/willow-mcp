"""Entry point: python3 -m willow_mcp [--serve] [--port PORT] [--host HOST]

`manifest-grant` is special-cased BEFORE `server` is ever imported (gap
`035d287206e1`, 2026-09-22): `server.py`'s module body runs several
side effects that assume the BROKER's uid and a broker-writable
`$WILLOW_HOME` (`_receipt_log = ReceiptLog()`, `_store = Store()`), and
`manifest-grant apply` is the one subcommand a DIFFERENT uid — the trust
owner, `willow-operator`, via `willow-mcp-manifest-grant.service` — runs
routinely. Measured on the box: the first live tick died at IMPORT,
inside `ReceiptLog()`'s `sqlite3.connect`, with `willow-operator` unable
to even traverse `$WILLOW_HOME` (`710 sean-campbell:sean-campbell`) —
never mind write to it. `cli_manifest_grant.py` and everything it calls
(`manifest_grant_executor`, `.db`, `.governance_ledger`, `.human_session`)
are import-safe: none of them import `server` or construct anything under
`$WILLOW_HOME` as a module-level side effect (verified by reading each,
not assumed) — the only way to guarantee that for the apply process is to
never let `server` load in the first place.
"""
import sys


def _dispatch_manifest_grant_without_importing_server() -> int:
    """`python3 -m willow_mcp manifest-grant ...` reaches
    `cli_manifest_grant.cmd_manifest_grant` through this module's OWN tiny
    argparse tree — never `server.py`'s. Returns the process exit code."""
    import argparse

    from . import cli_manifest_grant

    parser = argparse.ArgumentParser(prog="willow-mcp")
    subparsers = parser.add_subparsers(dest="command", required=True)
    cli_manifest_grant.register(subparsers)
    args = parser.parse_args(sys.argv[1:])
    return cli_manifest_grant.cmd_manifest_grant(args)


if len(sys.argv) > 1 and sys.argv[1] == "manifest-grant":
    sys.exit(_dispatch_manifest_grant_without_importing_server())

from .server import main  # noqa: E402 — must follow the manifest-grant early-exit above

# Observability (opt-in, egress-gated): inert unless WILLOW_SENTRY_DSN is set.
# Treats Sentry as a hostile egress destination — see observability.py. Wired
# here rather than in server.main() so it covers every MCP-client-spawned
# server (the lane the experiment observes); CLI subcommand one-shots via the
# console scripts deliberately do not init telemetry.
from .observability import init_observability  # noqa: E402 — same reason

init_observability()
main()
