"""Wires ``seal_handler.on_seal`` to the ratatosk seal-watch daemon.

The watch itself (``ratatosk.daemon.SeatDaemon`` / ``JsonlTailWatcher``)
lives in ``willow-ratatosk``, on the held ``feat/ratatosk-listener-daemon``
branch — it is generic on purpose and knows nothing about Nestor, seals, or
SOIL. This module is the willow-mcp-specific launcher: it supplies the real
ledger path, the willow-mcp seal handler, and — critically — the *correct*
predicate for what a seal record looks like on the real Nestor ledger.

Predicate seam, verified against the installed ``SeatDaemon``: its
constructor builds its own ``JsonlTailWatcher`` internally and hardcodes::

    op_predicate=lambda record: record.get("op") == "seal"

with no parameter to override it. The real ledger's seal records use
``kind``, not ``op`` — so ``SeatDaemon``'s own default predicate never
fires against the real ledger. There is no constructor seam to pass a
different predicate through. That is a real gap in ``SeatDaemon`` and
belongs in a fix to the held ratatosk branch (see the seal_handler
dispatch's findings) — it is not fixed here.

Workaround used here rather than reimplementing the daemon: construct
``SeatDaemon`` with no ``seal_ledger_path`` (so it builds no watcher of its
own), then replace ``daemon.seal_watcher`` with a ``JsonlTailWatcher`` built
directly against the correct predicate. This keeps ``SeatDaemon``'s
heartbeat / run_forever / stop-signal machinery — none of that is wrong —
and only replaces the one piece that hardcodes the wrong field name.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Callable, Optional

from . import paths
from . import seal_handler

logger = logging.getLogger(__name__)

try:
    from ratatosk.daemon import JsonlTailWatcher, SeatDaemon
    RATATOSK_AVAILABLE = True
    _IMPORT_ERROR: Optional[BaseException] = None
except ImportError as exc:  # pragma: no cover - exercised via the guard test
    JsonlTailWatcher = None  # type: ignore[assignment,misc]
    SeatDaemon = None  # type: ignore[assignment,misc]
    RATATOSK_AVAILABLE = False
    _IMPORT_ERROR = exc

#: Env override for the Nestor ledger path, mirroring the
#: WILLOW_*/RATATOSK_SEAL_LEDGER read-at-call-time convention elsewhere in
#: the fleet rather than baking a path in at import time.
NESTOR_LEDGER_ENV = "WILLOW_NESTOR_LEDGER"

#: Name of the offset file this daemon persists under the willow-mcp store
#: root — separate from ratatosk's own data root, since this is a
#: willow-mcp-owned watch position, not a ratatosk one.
_OFFSET_FILENAME = "seal_watch.offset"


def seal_predicate(record: dict) -> bool:
    """The real predicate for a governance-decision seal on the Nestor
    ledger: ``kind == "seal"`` AND ``source_lang == "decision"``.

    A plain module-level function (not a lambda closed over daemon state) so
    it can be imported and asserted against directly — including against a
    real sample seal record, and against an ``op``-only shape that a
    predicate written for the wrong field name would wrongly accept or
    reject.
    """
    return (
        isinstance(record, dict)
        and record.get("kind") == "seal"
        and record.get("source_lang") == "decision"
    )


def default_ledger_path() -> Path:
    override = os.environ.get(NESTOR_LEDGER_ENV, "").strip()
    if override:
        return Path(override).expanduser()
    return paths.willow_home() / "ledger.jsonl"


def default_offset_path() -> Path:
    return paths.store_root() / _OFFSET_FILENAME


def _seed_offset_at_eof_if_absent(ledger_path: Path, offset_path: Path) -> None:
    """First-run posture: watch only NEW seals.

    ``JsonlTailWatcher`` defaults a missing offset file to 0 — read the
    ledger from the start — which is right for a watcher with no history
    and wrong for this one: the real ledger already carries ~619 historical
    seals, and replaying them on first boot would re-fire every one through
    a handler that, while idempotent, has no governance record to match most
    of them against (they are not all decision seals) and would still cost a
    full ledger scan for nothing. So: if no offset file exists yet, seed it
    at the ledger's current size (EOF) before the watcher is ever built.
    Once an offset file exists, this is a no-op forever — a real restart
    resumes from wherever the watcher left off, same as any other run.
    """
    if offset_path.exists():
        return
    offset_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        size = ledger_path.stat().st_size
    except FileNotFoundError:
        size = 0
    tmp = offset_path.with_name(offset_path.name + ".tmp")
    tmp.write_text(str(size), encoding="utf-8")
    tmp.replace(offset_path)


def build_seal_daemon(
    *,
    node: Optional[str] = None,
    channel: Optional[str] = None,
    mcp_call=None,
    ledger_path: Optional[Path] = None,
    offset_path: Optional[Path] = None,
    on_seal: Callable[[dict], object] = seal_handler.on_seal,
    **daemon_kwargs,
):
    """Build a ``SeatDaemon`` wired to watch the Nestor ledger for
    governance-decision seals and hand each one to ``on_seal``.

    Raises ``ImportError`` — with a message telling the operator what to do
    about it — if ``willow-ratatosk`` is not installed, or is installed but
    predates the seal-watch daemon (``ratatosk.daemon`` with ``SeatDaemon``/
    ``JsonlTailWatcher``). That is the real, current state of the released
    package: the daemon lives on the held ``feat/ratatosk-listener-daemon``
    branch and is not yet in any release.
    """
    if not RATATOSK_AVAILABLE:
        raise ImportError(
            "willow-ratatosk is not installed with the seal-watch daemon "
            "(ratatosk.daemon.SeatDaemon / JsonlTailWatcher). Install or "
            "release willow-ratatosk's feat/ratatosk-listener-daemon branch "
            "before building the seal daemon."
        ) from _IMPORT_ERROR

    ledger = Path(ledger_path) if ledger_path is not None else default_ledger_path()
    offset = Path(offset_path) if offset_path is not None else default_offset_path()
    _seed_offset_at_eof_if_absent(ledger, offset)

    daemon = SeatDaemon(
        node=node,
        channel=channel,
        mcp_call=mcp_call,
        **daemon_kwargs,
    )
    # Replace whatever seal_watcher SeatDaemon may have built for itself
    # (None, since we did not pass it seal_ledger_path) with one carrying
    # the correct predicate. See module docstring for why this cannot be
    # done through SeatDaemon's constructor.
    daemon.seal_watcher = JsonlTailWatcher(
        ledger_path=ledger,
        op_predicate=seal_predicate,
        callback=on_seal,
        offset_store_path=offset,
    )
    return daemon
