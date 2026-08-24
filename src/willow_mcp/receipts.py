"""willow_mcp/receipts.py — append-only audit trail for every tool call.

Phase 4c. One row per tool call regardless of outcome (ok / denied /
rate_limited / error). Dedicated SQLite connection — never shares the
Store's connections, so a busy receipt log can't stall a store_* call
or vice versa.
"""
import contextlib
import hashlib
import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("willow_mcp.receipts")
from typing import Optional

from . import paths

_SCHEMA = """
CREATE TABLE IF NOT EXISTS receipts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    app_id     TEXT NOT NULL,
    tool       TEXT NOT NULL,
    outcome    TEXT NOT NULL,
    detail     TEXT,
    prev_hash  TEXT,
    entry_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_receipts_ts     ON receipts(ts DESC);
CREATE INDEX IF NOT EXISTS idx_receipts_app_id ON receipts(app_id);
"""

# Hash-chain the log (B12), mirroring governance_ledger: each row's entry_hash
# folds in the previous row's, so an edited/deleted/reordered row breaks the
# chain and verify() names the first bad link. The chain is UNKEYED (sha256, like
# governance_ledger) — its tamper-EVIDENCE holds within the real security
# boundary, which is OS ownership: on a hardened install this .db is owned by
# willow-operator and the agent uid cannot write it (willow-mcp#181). A canonical
# JSON array is hashed, not a concatenation, so a separator inside a field cannot
# forge a collision (the Nestor B4 lesson).
_GENESIS = "0" * 64

# Seconds a writer waits for SQLite's write lock before raising "database is
# locked". Every chained append now takes that lock (BEGIN IMMEDIATE), so a
# second willow-mcp process sharing this $WILLOW_HOME *queues* instead of
# forking the chain — but only if it is willing to wait. sqlite3's 5s default is
# thin for a home on network storage; a receipt write is milliseconds, so a
# generous ceiling costs nothing and a spurious failure costs an audit row.
_BUSY_TIMEOUT = 30.0


def _entry_hash(prev_hash: str, ts: str, app_id: str, tool: str,
                outcome: str, detail: Optional[str]) -> str:
    payload = json.dumps([prev_hash, ts, app_id, tool, outcome, detail],
                         ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ReceiptLog:
    """Append-only SQLite log of every tool call."""

    def __init__(self, db_path: Optional[str] = None, on_record=None):
        # Default under $WILLOW_HOME so the audit trail stays inside the
        # sovereign box (the data-vault boundary). Explicit db_path wins, then
        # the WILLOW_MCP_RECEIPT_DB override, then $WILLOW_HOME/mcp_receipt.db.
        self.path = Path(
            db_path
            or os.environ.get("WILLOW_MCP_RECEIPT_DB")
            or (paths.willow_home() / "mcp_receipt.db")
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        # isolation_level=None (autocommit) so this module issues its OWN
        # transactions. The chain's read-head-then-append MUST be one atomic unit
        # across PROCESSES, and only an explicit `BEGIN IMMEDIATE` gives that:
        # sqlite3's implicit transactions begin DEFERRED at the first *write*, so
        # the SELECT that reads the chain head would sit outside the write lock and
        # two processes would both read the same head. `timeout` is how long a
        # writer waits for the lock before raising "database is locked".
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False,
                                     isolation_level=None, timeout=_BUSY_TIMEOUT)
        self._conn.executescript(_SCHEMA)
        self._migrate_backfill()
        # Optional post-write observer (app_id, tool, outcome, detail) → None. The
        # announcement policy (Phase 5) rides here so it sees EVERY record site
        # from one wiring point; it must never break the audit write, so its
        # errors are swallowed. The log stays the single record — the observer
        # only decides how loudly to surface a row, never writes a second one.
        self.on_record = on_record

    @contextlib.contextmanager
    def _write_txn(self):
        """One `BEGIN IMMEDIATE` … COMMIT/ROLLBACK around a read-then-write.

        IMMEDIATE (not the sqlite3 default DEFERRED) takes the RESERVED write lock
        up front, *before* the read — which is the whole point. The chain head is
        read and the next row appended under one lock, so two processes sharing a
        $WILLOW_HOME serialise instead of both reading the same head and appending
        two rows that each claim it as prev_hash. That fork is unrepairable: the
        log is append-only, so verify() fails from then on forever and
        session_reconcile refuses every session (server.py's
        `receipt_integrity_failed`). self._lock is still held outside this — it
        keeps this process's threads off one connection — but a threading.Lock
        says nothing to another process, which is exactly the gap.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")

    def _migrate_backfill(self) -> None:
        """Add the chain columns to a pre-B12 table and hash any unchained rows
        in id order, establishing the chain over existing history. Idempotent:
        rows that already carry an entry_hash advance the chain from it."""
        with self._lock, self._write_txn():
            cols = {r[1] for r in self._conn.execute("PRAGMA table_info(receipts)")}
            if "prev_hash" not in cols:
                self._conn.execute("ALTER TABLE receipts ADD COLUMN prev_hash TEXT")
            if "entry_hash" not in cols:
                self._conn.execute("ALTER TABLE receipts ADD COLUMN entry_hash TEXT")
            rows = self._conn.execute(
                "SELECT id, ts, app_id, tool, outcome, detail, entry_hash "
                "FROM receipts ORDER BY id ASC"
            ).fetchall()
            prev, updates = _GENESIS, []
            for id_, ts, app_id, tool, outcome, detail, entry_hash in rows:
                if entry_hash is None:
                    eh = _entry_hash(prev, ts, app_id, tool, outcome, detail)
                    updates.append((prev, eh, id_))
                    prev = eh
                else:
                    prev = entry_hash
            for prev_h, eh, id_ in updates:
                self._conn.execute(
                    "UPDATE receipts SET prev_hash = ?, entry_hash = ? WHERE id = ?",
                    (prev_h, eh, id_))

    def verify(self) -> dict:
        """Walk the chain in id order; return {ok, count, head} or, at the first
        broken link, {ok: False, broken_at: id, reason}. A row edited, deleted, or
        reordered out of band breaks either the prev linkage or the recomputed
        entry_hash. session_reconcile calls this before trusting the log as ground
        truth, so a silently-tampered audit trail can no longer reconcile clean."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, ts, app_id, tool, outcome, detail, prev_hash, entry_hash "
                "FROM receipts ORDER BY id ASC"
            ).fetchall()
        prev = _GENESIS
        for id_, ts, app_id, tool, outcome, detail, prev_hash, entry_hash in rows:
            if prev_hash != prev:
                return {"ok": False, "broken_at": id_, "reason": "prev_hash linkage"}
            if entry_hash != _entry_hash(prev, ts, app_id, tool, outcome, detail):
                return {"ok": False, "broken_at": id_, "reason": "entry_hash mismatch"}
            prev = entry_hash
        return {"ok": True, "count": len(rows), "head": prev}

    def record(self, app_id: str, tool: str, outcome: str, detail: Optional[str] = None) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        with self._lock, self._write_txn():
            row = self._conn.execute(
                "SELECT entry_hash FROM receipts ORDER BY id DESC LIMIT 1").fetchone()
            prev = row[0] if row and row[0] else _GENESIS
            entry = _entry_hash(prev, ts, app_id, tool, outcome, detail)
            self._conn.execute(
                "INSERT INTO receipts (ts, app_id, tool, outcome, detail, prev_hash, entry_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (ts, app_id, tool, outcome, detail, prev, entry)
            )
        if self.on_record is not None:
            try:
                self.on_record(app_id, tool, outcome, detail)
            except Exception:
                logger.debug("on_record observer failed for %s/%s", app_id, tool, exc_info=True)

    def since(self, app_id: str, ts_iso: str, outcome: Optional[str] = None,
              limit: int = 2000) -> list[dict]:
        """This app_id's receipts at or after `ts_iso`, oldest first.

        The session-reconciliation feed (willow-gate seam H3): `tools_used` must
        come from the receipt log, or a declare-vs-did diff silently passes on
        out-of-band use. ISO-8601 UTC timestamps sort lexicographically in
        chronological order, so a string `ts >= ?` bound is a correct time window.
        Optionally narrow to a single `outcome` (e.g. only calls that actually
        ran). Scoped to one app_id, like tail() — never another identity's calls.
        """
        limit = max(1, min(int(limit), 10000))
        q = ("SELECT ts, tool, outcome, detail FROM receipts "
             "WHERE app_id = ? AND ts >= ?")
        params: list = [app_id, ts_iso]
        if outcome is not None:
            q += " AND outcome = ?"
            params.append(outcome)
        q += " ORDER BY id ASC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(q, tuple(params)).fetchall()
        return [{"ts": r[0], "tool": r[1], "outcome": r[2], "detail": r[3]} for r in rows]

    def distinct_tools(self, app_id: str, ts_iso: str,
                       outcome: Optional[str] = None) -> list[str]:
        """The DISTINCT set of tool names this app_id recorded at or after
        `ts_iso` (optionally filtered to one `outcome`). Unbounded by row count on
        purpose: this feeds session reconciliation, where a truncated row window
        would let a late privileged call fall outside the diff and read as clean.
        A DISTINCT tool set is small (bounded by the tool catalogue) regardless of
        call volume, so there is nothing to cap."""
        q = "SELECT DISTINCT tool FROM receipts WHERE app_id = ? AND ts >= ?"
        params: list = [app_id, ts_iso]
        if outcome is not None:
            q += " AND outcome = ?"
            params.append(outcome)
        with self._lock:
            rows = self._conn.execute(q, tuple(params)).fetchall()
        return [r[0] for r in rows]

    def tail(self, app_id: str, limit: int = 20) -> list[dict]:
        """Return this app_id's own most-recent receipts, newest first.

        Scoped to the single app_id on purpose — the audit trail is a
        self-legibility feature ('what did I just do?'), never a way to read
        another identity's calls. A caller only ever sees its own rows.
        """
        limit = max(1, min(int(limit), 200))
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, tool, outcome, detail FROM receipts "
                "WHERE app_id = ? ORDER BY id DESC LIMIT ?",
                (app_id, limit),
            ).fetchall()
        return [{"ts": r[0], "tool": r[1], "outcome": r[2], "detail": r[3]} for r in rows]
