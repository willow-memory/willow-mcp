"""willow_mcp/seat_daemon.py — the full per-seat Grove activation rail.

Closes the third gap of the activation rail (see
docs/design/grove-activation-rail.md): the only daemon that has run in
production so far is ``seal_daemon.run_seal_watch_forever`` — the seal watch
ALONE, with no Grove bus and no ``activate`` wired in. This module builds
the real thing for one seat: a single ``ratatosk.daemon.SeatDaemon`` that
runs the Grove bus poll, the seal-ledger watch, and the heartbeat together,
on ``SeatDaemon.run_forever``'s one cadence — nothing new is reimplemented,
every piece already exists:

* ``node``/``channel`` = the seat's own RAW ``app_id`` — the exact channel
  ``grove_tools.post_wake_envelope`` posts a dispatch WAKE to, the exact
  identity `validate_envelope` checks a WAKE's ``to`` field against, AND —
  just as importantly — the exact identity ratatosk's own
  ``BusListener.is_own_post`` compares an incoming message's stored
  ``sender`` against to decide "is this my own post talking to itself".
  Every automated post this daemon makes (heartbeat, wake-ack, any chat
  reply `BusListener`'s default handlers produce) is therefore stored
  under this SAME raw ``app_id`` too — see
  ``grove_tools.build_mcp_call``'s ``_shim_resolve_sender`` for why that is
  deliberately NOT the seat's resolved persona display name. Any daylight
  between what `node` says and what a self-authored post's `sender`
  actually says breaks `is_own_post` silently: nonce-based replay
  detection cannot catch a self-authored reply either (it mints a fresh
  nonce on every parse), so `is_own_post` is the ONLY thing stopping a seat
  from re-processing its own traffic forever — see
  docs/design/grove-activation-rail.md's "self-post loop closure" section.
* ``mcp_call`` = ``grove_tools.build_mcp_call(app_id)`` — an in-process
  shim, not a second MCP transport, since this daemon runs inside
  willow-mcp's own process rather than as a separate ratatosk client.
* ``activate`` = ``activation.build_activate(app_id)`` — the real
  surface-only wake handler (NOTICE, not spawn).
* the seal-ledger wiring ``seal_daemon.build_seal_daemon`` already
  assembles (ledger path, offset path, ``seal_handler.on_seal``,
  ``seal_predicate``) is reused verbatim by delegating construction to it.

``seal_daemon.run_seal_watch_forever`` (seal-only, no bus) is UNCHANGED and
remains the standalone deployment path for a box with no Grove activation
rail wired up. This module is the fuller sibling: same seal watch, plus a
live Grove bus and a real ``activate``.
"""
from __future__ import annotations

import argparse
import signal
import sys
from pathlib import Path
from typing import Optional

from . import activation
from . import grove_tools
from . import seal_daemon
from . import seal_handler


def build_full_seat_daemon(
    app_id: str,
    *,
    ledger_path: Optional[Path] = None,
    offset_path: Optional[Path] = None,
    on_seal=seal_handler.on_seal,
    log_path: Optional[Path] = None,
    **daemon_kwargs,
):
    """Build the real per-seat ``SeatDaemon``: Grove bus + seal watch +
    surface-only activate, for ``app_id``.

    ``daemon_kwargs`` (``poll_interval``, ``heartbeat_interval``, ...) pass
    straight through to ``SeatDaemon`` via ``seal_daemon.build_seal_daemon``
    — nothing here reinvents that plumbing. Raises ``ImportError`` — with a
    message telling the operator what to do about it — if willow-ratatosk is
    not installed or predates 1.7.0's ``seal_predicate`` parameter, same as
    ``build_seal_daemon`` itself.

    ``node`` and ``channel`` are both the raw ``app_id`` — see this
    module's docstring for why that has to stay true (``is_own_post`` loop
    closure).
    """
    return seal_daemon.build_seal_daemon(
        node=app_id,
        channel=app_id,
        mcp_call=grove_tools.build_mcp_call(app_id),
        ledger_path=ledger_path,
        offset_path=offset_path,
        on_seal=on_seal,
        activate=activation.build_activate(app_id, log_path=log_path),
        **daemon_kwargs,
    )


def main(argv: Optional[list] = None) -> None:
    """Console entrypoint: ``python -m willow_mcp.seat_daemon --app-id <id>``.

    Runs the FULL rail for one seat — Grove bus (wake -> NOTICE), seal
    watch, and heartbeat, together. SIGTERM and SIGINT both call
    ``daemon.request_stop`` so a process manager (systemd) can stop this
    cleanly, same shape as ``seal_daemon.main`` and ratatosk's own
    ``daemon.main``.
    """
    parser = argparse.ArgumentParser(
        prog="willow-mcp-seat-daemon",
        description=(
            "Run the full Grove activation rail (bus + seal watch + "
            "surface-only wake activation) for one seat."
        ),
    )
    parser.add_argument(
        "--app-id", required=True, dest="app_id",
        help="the seat this daemon runs for (Grove node/channel + activation log)",
    )
    parser.add_argument("--poll-interval", type=float, default=2.0)
    parser.add_argument(
        "--heartbeat-interval", type=float, default=None,
        help="seconds between Grove heartbeats (defaults to SeatDaemon's own default)",
    )
    args = parser.parse_args(argv)

    daemon_kwargs = {"poll_interval": args.poll_interval}
    if args.heartbeat_interval is not None:
        daemon_kwargs["heartbeat_interval"] = args.heartbeat_interval

    daemon = build_full_seat_daemon(args.app_id, **daemon_kwargs)

    signal.signal(signal.SIGTERM, daemon.request_stop)
    signal.signal(signal.SIGINT, daemon.request_stop)

    daemon.run_forever(on_status=lambda msg: print(f"  [{args.app_id}] {msg}", flush=True))


if __name__ == "__main__":
    main(sys.argv[1:])
