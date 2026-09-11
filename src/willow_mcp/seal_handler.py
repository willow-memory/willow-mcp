"""The willow-mcp side of the seal watch: what happens when a seal is seen.

Closes the consumer half of "nothing watches when things are sealed". The
ratatosk seal-watch daemon (``seal_daemon.py`` in this package, wired against
``willow-ratatosk``'s ``SeatDaemon``/``JsonlTailWatcher``) tails the Nestor
ledger and calls ``on_seal`` for every record matching the seal predicate.
This module is the handler: it does the SOIL-side work, and nothing else.

Ground truth (verified against the live ledger + store, not assumed):

- A seal record's kind field is ``kind`` — NOT ``op``. Example keys: ``ts,
  prev, kind, pair_id, verifier, source_lang, target_lang, source_sha,
  origin, upgraded_from``.
- The full ``seal_sig`` is NOT in the ledger record. It lives in Nestor's
  own SQLite database (``nestor.db``, table ``tm_pairs``, column
  ``seal_sig``, keyed by ``id == pair_id``). This handler reads only a
  16-character prefix of it, best-effort — a missing or unreadable
  nestor.db must never block the SOIL upgrade, because the ledger record
  alone (verifier, ts, pair_id) is enough to mark the decision sealed.
- Governance decisions live in the ``projects_willow_governance_decisions``
  SOIL collection. A sealed decision's record carries ``nestor_pair_id`` —
  that is the correlation key back to the ledger's ``pair_id``.

Delivery guarantee this handler is written against: the daemon calling it is
**at-least-once** (see ``ratatosk.daemon.JsonlTailWatcher``'s docstring on
the held ``feat/ratatosk-listener-daemon`` branch). ``on_seal`` therefore
MUST be idempotent — a second call for a pair_id already sealed is a clean
no-op, not a duplicate write or a duplicate notice.
"""
from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Optional

from . import paths
from .db import Store

logger = logging.getLogger(__name__)

#: The SOIL collection holding governance decisions. Scoped deliberately —
#: the ledger carries ~619 seals across many domains (translations, etc.);
#: only source_lang == "decision" seals correlate to a record in here.
GOVERNANCE_COLLECTION = "projects_willow_governance_decisions"

#: How many leading characters of the full seal_sig to carry into SOIL. The
#: full signature lives in nestor.db, not here — this is a fingerprint for
#: display/audit, not a verification artifact.
_SIG_PREFIX_LEN = 16


def _nestor_db_path() -> Path:
    """Where Nestor's own SQLite ledger lives — ``nestor.db`` next to the
    JSONL ledger under $WILLOW_HOME, unless overridden for a test or an
    alternate deployment layout."""
    import os

    override = os.environ.get("WILLOW_NESTOR_DB", "").strip()
    if override:
        return Path(override).expanduser()
    return paths.willow_home() / "nestor.db"


def _seal_sig_prefix(pair_id: str, db_path: Optional[Path] = None) -> Optional[str]:
    """Best-effort lookup of the first ``_SIG_PREFIX_LEN`` chars of
    ``seal_sig`` for ``pair_id`` from Nestor's own database.

    Never raises. A missing file, a locked file, a missing table/column, or
    simply no matching row all resolve to ``None`` — the caller upgrades the
    SOIL record from the ledger fields regardless and just omits (or leaves
    unset) the signature prefix.
    """
    path = db_path if db_path is not None else _nestor_db_path()
    try:
        uri = f"file:{path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error:
        logger.warning(
            "seal_handler: nestor.db at %s unreadable — upgrading pair_id=%s "
            "without a seal_sig prefix", path, pair_id,
        )
        return None
    try:
        row = conn.execute(
            "SELECT seal_sig FROM tm_pairs WHERE id = ?", (pair_id,)
        ).fetchone()
    except sqlite3.Error:
        logger.warning(
            "seal_handler: nestor.db query failed for pair_id=%s — upgrading "
            "without a seal_sig prefix", pair_id, exc_info=True,
        )
        return None
    finally:
        conn.close()
    if not row or not row[0]:
        return None
    return str(row[0])[:_SIG_PREFIX_LEN]


def _strip_meta(record: dict) -> dict:
    return {k: v for k, v in record.items() if not k.startswith("_")}


def _find_governance_record(store: Store, pair_id: str) -> Optional[tuple[str, dict]]:
    """Scan governance decisions for the one carrying this pair_id.

    ``Store`` has no field-indexed lookup, only ``all``/``search`` (text
    LIKE) — a plain scan-and-match is the same shape every other
    non-id-keyed lookup in this codebase uses over this store layer.
    """
    for rec in store.all(GOVERNANCE_COLLECTION):
        if rec.get("nestor_pair_id") == pair_id:
            return rec.get("_id"), rec
    return None


def on_seal(record: dict, *, store: Optional[Store] = None,
            db_path: Optional[Path] = None) -> str:
    """Handle one ledger record. Called by the seal-watch daemon.

    Returns one of:
      "skipped"   — not a decision seal (guard failed, or no pair_id)
      "unmatched" — a decision seal with no local governance record for it
                    (sealed elsewhere, or not tracked here) — normal, not an
                    error
      "already"   — the matching record is already status=sealed — clean
                    idempotent no-op
      "upgraded"  — the matching record was upgraded to status=sealed
      "error"     — the store itself is broken; logged, never raised

    Never raises on a well-formed or malformed input record. The only path
    that could raise is a genuinely broken store, and even that is caught
    and turned into a logged "error" result so a single bad call cannot take
    the daemon's poll loop down with it (the daemon is at-least-once, so a
    retried "error" call gets another chance next poll).
    """
    try:
        return _on_seal(record, store=store, db_path=db_path)
    except Exception:
        logger.error(
            "seal_handler: unexpected failure processing seal record "
            "pair_id=%r", record.get("pair_id") if isinstance(record, dict) else None,
            exc_info=True,
        )
        return "error"


def _on_seal(record: dict, *, store: Optional[Store], db_path: Optional[Path]) -> str:
    if not isinstance(record, dict) or record.get("kind") != "seal" \
            or record.get("source_lang") != "decision":
        logger.debug(
            "seal_handler: skipped non-decision-seal record (kind=%r "
            "source_lang=%r)",
            record.get("kind") if isinstance(record, dict) else None,
            record.get("source_lang") if isinstance(record, dict) else None,
        )
        return "skipped"

    pair_id = record.get("pair_id")
    if not pair_id:
        logger.info("seal_handler: decision seal missing pair_id, skipping: %r", record)
        return "skipped"

    st = store if store is not None else Store()
    match = _find_governance_record(st, pair_id)
    if match is None:
        logger.info(
            "seal_handler: no governance record for pair_id=%s — sealed "
            "elsewhere or not tracked locally", pair_id,
        )
        return "unmatched"

    record_id, gov = match
    if gov.get("status") == "sealed":
        logger.info(
            "seal_handler: pair_id=%s already sealed on governance record "
            "%s — no-op", pair_id, record_id,
        )
        return "already"

    sig_prefix = _seal_sig_prefix(pair_id, db_path=db_path)

    updated = _strip_meta(gov)
    updated["status"] = "sealed"
    updated["nestor_pair_id"] = pair_id
    updated["nestor_verifier"] = record.get("verifier")
    updated["sealed_at"] = record.get("ts")
    if sig_prefix:
        updated["nestor_seal_sig_prefix"] = sig_prefix

    st.update(GOVERNANCE_COLLECTION, record_id, updated)

    # Lightweight notice of the propagation — a log line is the minimum bar
    # this needs to clear; a seal needs no human action, so this deliberately
    # does not go through human_required_enqueue.
    logger.info(
        "seal_handler: propagated seal pair_id=%s -> governance record %s "
        "sealed (verifier=%s, sig_prefix=%s)",
        pair_id, record_id, updated["nestor_verifier"],
        "present" if sig_prefix else "missing",
    )
    return "upgraded"
