"""One tick of the seal watch, as a verb: drain the Nestor ledger from the
stored offset and hand every governance-decision seal to ``seal_handler``.

Sealed decision 72292afd (2026-09-18): the seal watcher runs on the willow-bot
steward tick, not as its own unit. ``seal_daemon`` keeps the long-running
shape (``JsonlTailWatcher`` polled forever) for a box that wants it; this
module is the same walk done once, synchronously, returning a receipt the
steward journal and ``bot_status`` can show. Gap ``7a114cfb8cc4``: three
operator seals sat unpropagated for hours and nothing on the desk could say
whether the standalone unit was alive, stalled, or reading the wrong file.

Shares ``seal_daemon``'s ledger path, offset file and predicate, so a box that
switches from the unit to the tick resumes exactly where the unit stopped, and
the two never disagree about what "watched" means. Do not run both at once:
they would race on the offset file (``on_seal`` is idempotent, so the damage
is wasted work, not a wrong record — but the receipt would lie about who did
it).

Three states, never collapsed:

* ``unreachable`` — the ledger is missing, unreadable, or the offset cannot
  be persisted; ``reason`` names which. Nothing is consumed.
* ``empty``       — the ledger was read and holds no new bytes past the
  offset.
* ``populated``   — new records were read; ``drained`` counts them,
  ``results`` counts each ``on_seal`` outcome, ``upgraded`` lists the
  governance record ids that flipped to sealed.

At-least-once: the offset is written only after every record in the batch
has been handed to the handler, so a crash mid-batch replays the batch next
tick. ``on_seal`` is idempotent by contract, so a replay is a clean
``already``.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Callable, Optional

from . import seal_daemon, seal_handler

logger = logging.getLogger(__name__)

#: Upper bound on records handled per drain, so one tick stays bounded on a
#: ledger that grew a lot while nothing watched. The rest is picked up next
#: tick; the receipt says ``truncated: true`` when this bites.
DEFAULT_MAX_RECORDS = 500


def _read_offset(offset_path: Path) -> int:
    try:
        return int(offset_path.read_text(encoding="utf-8").strip() or "0")
    except FileNotFoundError:
        return 0
    except (OSError, ValueError):
        # Unreadable or garbage offset: start from 0 rather than guess. The
        # handler is idempotent, so the cost is one full pass, not a wrong
        # record. Logged so the receipt's ``offset_before`` is explicable.
        logger.warning("seal_drain: offset file %s unreadable — starting from 0", offset_path)
        return 0


def _write_offset(offset_path: Path, value: int) -> None:
    offset_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = offset_path.with_name(offset_path.name + ".tmp")
    tmp.write_text(str(value), encoding="utf-8")
    tmp.replace(offset_path)


def drain(
    *,
    ledger_path: Optional[Path] = None,
    offset_path: Optional[Path] = None,
    on_seal: Callable[[dict], str] = seal_handler.on_seal,
    max_records: int = DEFAULT_MAX_RECORDS,
    seed_at_eof_if_absent: bool = True,
) -> dict:
    """Walk the ledger once from the stored offset. See the module docstring
    for the receipt shape.

    ``seed_at_eof_if_absent`` keeps ``seal_daemon``'s first-run posture: with
    no offset file yet, watch only NEW seals rather than replaying the ~600
    historical ones. Pass ``False`` to walk from the start (a backfill).
    """
    ledger = Path(ledger_path) if ledger_path is not None else seal_daemon.default_ledger_path()
    offset_file = (Path(offset_path) if offset_path is not None
                   else seal_daemon.default_offset_path(ledger))
    receipt: dict = {"ledger": str(ledger), "offset_path": str(offset_file)}

    if seed_at_eof_if_absent:
        try:
            seal_daemon._seed_offset_at_eof_if_absent(ledger, offset_file)
        except OSError as exc:
            receipt.update(state="unreachable", reason="offset_unwritable",
                           error=f"{type(exc).__name__}: {exc}")
            return receipt

    try:
        size = ledger.stat().st_size
    except FileNotFoundError:
        receipt.update(state="unreachable", reason="ledger_missing")
        return receipt
    except OSError as exc:
        receipt.update(state="unreachable", reason="ledger_unreadable",
                       error=f"{type(exc).__name__}: {exc}")
        return receipt

    start = _read_offset(offset_file)
    rotated = False
    if start > size:
        # The ledger shrank under us: rotated or rewritten. Start over; the
        # handler's idempotence makes the replay safe, and the receipt says so.
        rotated = True
        start = 0
    receipt.update(offset_before=start, size=size, rotated=rotated)

    if start == size:
        receipt.update(state="empty", drained=0)
        return receipt

    results = {"upgraded": 0, "already": 0, "unmatched": 0, "skipped": 0, "error": 0}
    upgraded_pairs: list[str] = []
    malformed = 0
    drained = 0
    truncated = False
    new_offset = start

    try:
        with open(ledger, "rb") as fh:
            fh.seek(start)
            while True:
                if drained >= max_records:
                    truncated = True
                    break
                line_start = fh.tell()
                raw = fh.readline()
                if not raw:
                    break
                if not raw.endswith(b"\n"):
                    # A partial trailing line is a write in progress — leave it
                    # for next tick rather than parse half a record.
                    new_offset = line_start
                    break
                new_offset = fh.tell()
                drained += 1
                try:
                    record = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    malformed += 1
                    continue
                if not seal_daemon.seal_predicate(record):
                    results["skipped"] += 1
                    continue
                outcome = on_seal(record)
                results[outcome if outcome in results else "error"] += 1
                if outcome == "upgraded":
                    upgraded_pairs.append(str(record.get("pair_id")))
    except OSError as exc:
        receipt.update(state="unreachable", reason="ledger_unreadable",
                       error=f"{type(exc).__name__}: {exc}", drained=drained)
        return receipt

    try:
        _write_offset(offset_file, new_offset)
    except OSError as exc:
        # Records were handled but the position was not saved: next tick
        # replays them (idempotent). Say so rather than report a clean drain.
        receipt.update(state="unreachable", reason="offset_unwritable",
                       error=f"{type(exc).__name__}: {exc}",
                       drained=drained, results=results, upgraded=upgraded_pairs,
                       offset_after=start)
        return receipt

    receipt.update(
        state="populated",
        drained=drained,
        malformed=malformed,
        results=results,
        upgraded=upgraded_pairs,
        offset_after=new_offset,
        truncated=truncated,
    )
    return receipt
