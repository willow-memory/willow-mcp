"""Database — Postgres (Unix socket) and SQLite store aligned with willow-2.0 WillowStore."""

import base64
import json
import logging
import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import psycopg2
import psycopg2.extras

from . import postgres_lifecycle

logger = logging.getLogger("willow_mcp.db")

_pg_conn = None
_pg_lock = threading.Lock()

# server.py's _sanitize() already rejects a path-traversal collection before
# a tool call reaches Store — this is a second, independent check inside
# Store itself, so a future direct caller (a script, a test, a new code
# path) can't reach the filesystem with an unsanitized collection name just
# because it bypassed the MCP guard pipeline.
_COLLECTION_RE = re.compile(r"^[A-Za-z0-9_\-]{1,128}$")
_FIELD_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


# ── Keyset-cursor helpers ──────────────────────────────────────────────────────
#
# Pagination follows the MCP protocol's keyset cursor pattern (PRIOR_ART.md §1,
# "Cursor pagination" row — verdict: Spec, no library needed).  The cursor
# encodes the last-seen sort key so a subsequent call can resume from there
# without offset drift.  Base64-URL encoding keeps the cursor opaque and
# transport-safe.

def encode_cursor(sort_key: str) -> str:
    """Encode a sort key (typically an id or timestamp) into an opaque cursor."""
    return base64.urlsafe_b64encode(sort_key.encode("utf-8")).rstrip(b"=").decode("ascii")


def decode_cursor(cursor: str) -> str:
    """Decode an opaque cursor back to its sort key."""
    # Re-pad base64 — urlsafe_b64decode is lenient about padding in stdlib but
    # adding it explicitly avoids surprises across Python versions.
    padded = cursor + "=" * (-len(cursor) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")


def _validate_collection(collection: str) -> str:
    if not collection or not _COLLECTION_RE.match(collection):
        raise ValueError(f"invalid collection name: {collection!r}")
    return collection


def collection_in_scope(collection: str, scope: Optional[list]) -> bool:
    """True if `collection` is allowed under a manifest's optional `store_scope`.

    `scope=None` means unrestricted *within this install's own store* — unscoped
    apps keep seeing everything they always could; this is opt-in isolation, not
    a retroactive lockdown. Which store that is depends on WILLOW_STORE_ROOT: an
    install may share the wider fleet's store or hold its own, and
    `diagnostic_summary`'s `severance` check reports which. Sharing is a default,
    not a design commitment — an unscoped grant's blast radius is whatever store
    this process resolved. A pattern ending in "*" matches by prefix (e.g.
    "myapp_*"); otherwise it's an exact match. Empty list means "no collections"
    (deny-all), not "unrestricted" — callers that want unrestricted must omit the
    field entirely.
    """
    if scope is None:
        return True
    for pattern in scope:
        if pattern.endswith("*"):
            if collection.startswith(pattern[:-1]):
                return True
        elif collection == pattern:
            return True
    return False


def get_pg() -> Optional[psycopg2.extensions.connection]:
    """Return a Postgres connection via Unix socket, or None."""
    global _pg_conn

    def _connect():
        conn = psycopg2.connect(
            dbname=os.environ.get("WILLOW_PG_DB", "willow"),
            user=os.environ.get("WILLOW_PG_USER", os.environ.get("USER", "")),
        )
        conn.autocommit = True
        return conn

    with _pg_lock:
        try:
            if _pg_conn is None or _pg_conn.closed:
                _pg_conn = _connect()
            _pg_conn.cursor().execute("SELECT 1")
            return _pg_conn
        except Exception as exc:
            logger.warning("Postgres connection failed: %s", exc)
            _pg_conn = None
            if postgres_lifecycle.ensure_enabled() and postgres_lifecycle.try_recover():
                try:
                    _pg_conn = _connect()
                    _pg_conn.cursor().execute("SELECT 1")
                    return _pg_conn
                except Exception as exc_retry:
                    logger.warning("Postgres connection failed after recovery: %s", exc_retry)
                    _pg_conn = None
            return None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    id         TEXT PRIMARY KEY,
    data       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deviation  REAL NOT NULL DEFAULT 0.0,
    action     TEXT NOT NULL DEFAULT 'work_quiet',
    deleted    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_deleted ON records(deleted);
"""

def _action_for(deviation: float) -> str:
    if deviation >= 1.571:
        return "stop"
    if deviation >= 0.785:
        return "flag"
    return "work_quiet"


class Store:
    """SQLite-backed store aligned with willow-2.0 WillowStore.

    Schema: one records table per collection, data stored as JSON blob.
    Shares WILLOW_STORE_ROOT with willow-2.0 when set to the same path.
    """

    def __init__(self, store_root: Optional[str] = None):
        self.root = Path(store_root or os.environ.get(
            "WILLOW_STORE_ROOT",
            Path.home() / ".willow" / "store"
        ))
        self.root.mkdir(parents=True, exist_ok=True)
        self._conns: dict[str, sqlite3.Connection] = {}
        # RLock (not Lock): _conn() is called from within an already-locked
        # method body below, and a plain Lock would deadlock on re-entry.
        self._lock = threading.RLock()

    def _conn(self, collection: str) -> sqlite3.Connection:
        _validate_collection(collection)
        with self._lock:
            if collection not in self._conns:
                db_path = self.root / collection / "store.db"
                db_path.parent.mkdir(parents=True, exist_ok=True)
                conn = sqlite3.connect(str(db_path), check_same_thread=False)
                conn.executescript(_SCHEMA)
                conn.commit()
                self._conns[collection] = conn
            return self._conns[collection]

    def put(self, collection: str, record: dict, record_id: str = None,
            deviation: float = 0.0) -> tuple[str, str]:
        rid = record_id or str(uuid.uuid4())[:8].lower()
        action = _action_for(deviation)
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._conn(collection)
            # Upsert, not replace — and the omitted columns are the security fix.
            #
            # This was `INSERT OR REPLACE`, which in SQLite DELETEs the existing
            # row and INSERTs a new one, so the two columns left out of the
            # statement took their schema defaults — and `deleted` defaults to 0
            # (:84). Re-putting a known id therefore UNDELETED it and stamped a
            # fresh created_at: store_delete was not durable, and a purged row
            # could be replaced under the same id with different content and a
            # forged creation time, using only store_write.
            #
            # `created_at` and `deleted` are absent from the DO UPDATE list, so
            # an existing row keeps both. That is what makes the tombstone hold:
            # a re-put of a soft-deleted id updates the data but leaves the row
            # deleted with its creation time intact, so it stays invisible to
            # get/all/search/update/stats. Rewriting created_at was also a live
            # data bug on every ordinary write — put(record_id=...) is the update
            # idiom across human_loop, lineage, gaps, forks, friction,
            # seed_mirror and context_save.
            #
            # Deliberately NOT a refusal, though a write that lands invisibly is
            # unsatisfying. `store_purge_collection` is in `store_write`, and
            # nothing in this module ever sets `deleted` back to 0 — so raising
            # here would let any app holding store_write tombstone a collection
            # and permanently brick every stable-id writer against it
            # (context_save, human_loop.resolve, gaps, forks, lineage, …) with no
            # recovery path in code. That trades a forgery for an agent-reachable
            # denial of service, and the forgery is already dead without it. If
            # the tombstone is ever given an operator-only exit, revisit: a
            # refusal is only honest once recovery exists.
            conn.execute(
                "INSERT INTO records (id, data, created_at, updated_at, deviation, action, deleted) "
                "VALUES (?, ?, ?, ?, ?, ?, 0) "
                "ON CONFLICT(id) DO UPDATE SET "
                "data = excluded.data, updated_at = excluded.updated_at, "
                "deviation = excluded.deviation, action = excluded.action",
                (rid, json.dumps(record), now, now, deviation, action)
            )
            conn.commit()
        return rid, action

    def get(self, collection: str, record_id: str) -> Optional[dict]:
        with self._lock:
            conn = self._conn(collection)
            row = conn.execute(
                "SELECT data, created_at, updated_at, deviation, action "
                "FROM records WHERE id = ? AND deleted = 0",
                (record_id,)
            ).fetchone()
        if not row:
            return None
        record = json.loads(row[0])
        record["_id"] = record_id
        record["_created"] = row[1]
        record["_updated"] = row[2]
        record["_deviation"] = row[3]
        record["_action"] = row[4]
        return record

    def all(self, collection: str) -> list[dict]:
        with self._lock:
            conn = self._conn(collection)
            rows = conn.execute(
                "SELECT id, data, created_at, updated_at, deviation, action "
                "FROM records WHERE deleted = 0 ORDER BY created_at"
            ).fetchall()
        results = []
        for row in rows:
            record = json.loads(row[1])
            record["_id"] = row[0]
            record["_created"] = row[2]
            record["_updated"] = row[3]
            record["_deviation"] = row[4]
            record["_action"] = row[5]
            results.append(record)
        return results

    def all_paginated(self, collection: str, *,
                      limit: int = 50, cursor: Optional[str] = None,
                      ) -> tuple[list[dict], Optional[str]]:
        """Keyset-paginated variant of ``all()``.

        Sorted by ``created_at ASC`` — the same order ``all()`` uses — with
        the cursor encoding the ``(created_at, id)`` pair of the last record
        returned.  Returns ``(items, next_cursor)`` where *next_cursor* is
        ``None`` when there are no more pages.
        """
        limit = max(1, limit)
        with self._lock:
            conn = self._conn(collection)
            if cursor:
                after = decode_cursor(cursor)
                # cursor format: "created_at\x00id"
                parts = after.split("\x00", 1)
                if len(parts) == 2:
                    after_ts, after_id = parts
                else:
                    after_ts, after_id = parts[0], ""
                rows = conn.execute(
                    "SELECT id, data, created_at, updated_at, deviation, action "
                    "FROM records WHERE deleted = 0 "
                    "AND (created_at > ? OR (created_at = ? AND id > ?)) "
                    "ORDER BY created_at, id LIMIT ?",
                    (after_ts, after_ts, after_id, limit + 1),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, data, created_at, updated_at, deviation, action "
                    "FROM records WHERE deleted = 0 ORDER BY created_at, id LIMIT ?",
                    (limit + 1,),
                ).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        results = []
        for row in rows:
            record = json.loads(row[1])
            record["_id"] = row[0]
            record["_created"] = row[2]
            record["_updated"] = row[3]
            record["_deviation"] = row[4]
            record["_action"] = row[5]
            results.append(record)
        next_cursor = None
        if has_more and results:
            last = results[-1]
            next_cursor = encode_cursor(f"{last['_created']}\x00{last['_id']}")
        return results, next_cursor

    def update(self, collection: str, record_id: str, record: dict,
               deviation: float = 0.0) -> Optional[str]:
        now = datetime.now(timezone.utc).isoformat()
        action = _action_for(deviation)
        with self._lock:
            conn = self._conn(collection)
            result = conn.execute(
                "UPDATE records SET data = ?, updated_at = ?, deviation = ?, action = ? "
                "WHERE id = ? AND deleted = 0",
                (json.dumps(record), now, deviation, action, record_id)
            )
            conn.commit()
        return record_id if result.rowcount > 0 else None

    def search(self, collection: str, query: str) -> list[dict]:
        """Multi-keyword AND search (all tokens must appear in JSON data)."""
        tokens = query.split()
        if not tokens:
            return []
        conditions = " AND ".join(["data LIKE ?"] * len(tokens))
        params = tuple(f"%{t}%" for t in tokens)
        with self._lock:
            conn = self._conn(collection)
            rows = conn.execute(
                f"SELECT id, data, deviation, action FROM records "  # nosec B608 - conditions is `" AND ".join(["data LIKE ?"] * len(tokens))`, a fixed literal repeated N times; every token value is a bound param
                f"WHERE deleted = 0 AND {conditions}",
                params
            ).fetchall()
        results = []
        for row in rows:
            record = json.loads(row[1])
            record["_id"] = row[0]
            record["_deviation"] = row[2]
            record["_action"] = row[3]
            results.append(record)
        return results

    def search_paginated(self, collection: str, query: str, *,
                         limit: int = 50, cursor: Optional[str] = None,
                         ) -> tuple[list[dict], Optional[str]]:
        """Keyset-paginated variant of ``search()``.

        Sorted by ``id ASC`` — deterministic ordering for keyword hits.
        Returns ``(items, next_cursor)``.
        """
        tokens = query.split()
        if not tokens:
            return [], None
        limit = max(1, limit)
        conditions = " AND ".join(["data LIKE ?"] * len(tokens))
        params: list = [f"%{t}%" for t in tokens]
        where = f"deleted = 0 AND {conditions}"
        if cursor:
            after_id = decode_cursor(cursor)
            where += " AND id > ?"
            params.append(after_id)
        with self._lock:
            conn = self._conn(collection)
            rows = conn.execute(
                f"SELECT id, data, deviation, action FROM records "  # nosec B608 - same safety note as search()
                f"WHERE {where} ORDER BY id LIMIT ?",
                (*params, limit + 1),
            ).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        results = []
        for row in rows:
            record = json.loads(row[1])
            record["_id"] = row[0]
            record["_deviation"] = row[2]
            record["_action"] = row[3]
            results.append(record)
        next_cursor = None
        if has_more and results:
            next_cursor = encode_cursor(results[-1]["_id"])
        return results, next_cursor

    def _json_col_expr(self, field: str) -> str:
        """Map a logical field name to a SQL expression for query_paginated.

        ``_id`` → ``id``, ``_created`` → ``created_at``,
        ``_updated`` → ``updated_at``; anything else →
        ``json_extract(data, '$.field')``.  Field names are validated
        against ``_FIELD_NAME_RE`` to prevent injection.
        """
        if field == "_id":
            return "id"
        if field == "_created":
            return "created_at"
        if field == "_updated":
            return "updated_at"
        if not _FIELD_NAME_RE.match(field):
            raise ValueError(f"invalid field name for query: {field!r}")
        return f"json_extract(data, '$.{field}')"

    def query_paginated(self, collection: str, *,
                        filters: Optional[dict] = None,
                        sort: Optional[list] = None,
                        limit: int = 50,
                        cursor: Optional[str] = None,
                        ) -> tuple[list[dict], Optional[str]]:
        """Filtered and sorted keyset pagination via ``json_extract``.

        Pushes filtering, sorting, and cursor comparison into SQL so only
        the requested page is loaded — unlike ``all()`` which reads every
        record then slices in Python.

        Parameters
        ----------
        filters : dict, optional
            Equality filters on JSON data fields, e.g. ``{"status": "open"}``.
        sort : list of (field, direction), optional
            Sort spec.  Each entry is ``(field_name, "ASC"|"DESC")``.
            Defaults to ``[("_created", "ASC"), ("_id", "ASC")]``.
            Special names: ``_id`` → id column, ``_created`` → created_at,
            ``_updated`` → updated_at; all others use json_extract.
        limit : int
            Max records per page (default 50).
        cursor : str, optional
            Opaque cursor from a previous call's ``next_cursor``.

        Returns ``(items, next_cursor)`` where *next_cursor* is ``None``
        when there are no more pages.
        """
        limit = max(1, limit)
        if sort is None:
            sort = [("_created", "ASC"), ("_id", "ASC")]

        col_exprs = [self._json_col_expr(f) for f, _ in sort]

        where_parts = ["deleted = 0"]
        params: list = []

        if filters:
            for field, value in filters.items():
                where_parts.append(f"{self._json_col_expr(field)} = ?")
                params.append(value)

        if cursor:
            cursor_vals = json.loads(decode_cursor(cursor))
            or_clauses: list[str] = []
            for i in range(len(sort)):
                and_parts: list[str] = []
                for j in range(i):
                    and_parts.append(f"{col_exprs[j]} = ?")
                    params.append(cursor_vals[j])
                _, direction = sort[i]
                op = "<" if direction.upper() == "DESC" else ">"
                and_parts.append(f"{col_exprs[i]} {op} ?")
                params.append(cursor_vals[i])
                or_clauses.append(f"({' AND '.join(and_parts)})")
            where_parts.append(f"({' OR '.join(or_clauses)})")

        order_parts = [f"{col_exprs[i]} {sort[i][1].upper()}"
                       for i in range(len(sort))]

        with self._lock:
            conn = self._conn(collection)
            rows = conn.execute(
                f"SELECT id, data, created_at, updated_at, deviation, action "  # nosec B608 - col_exprs built from _json_col_expr which validates field names against _FIELD_NAME_RE
                f"FROM records WHERE {' AND '.join(where_parts)} "
                f"ORDER BY {', '.join(order_parts)} LIMIT ?",
                (*params, limit + 1),
            ).fetchall()

        has_more = len(rows) > limit
        rows = rows[:limit]
        results = []
        for row in rows:
            record = json.loads(row[1])
            record["_id"] = row[0]
            record["_created"] = row[2]
            record["_updated"] = row[3]
            record["_deviation"] = row[4]
            record["_action"] = row[5]
            results.append(record)

        next_cursor = None
        if has_more and results:
            last = results[-1]
            vals = []
            for field, _ in sort:
                if field == "_id":
                    vals.append(last["_id"])
                elif field == "_created":
                    vals.append(last["_created"])
                elif field == "_updated":
                    vals.append(last["_updated"])
                else:
                    vals.append(last.get(field))
            next_cursor = encode_cursor(json.dumps(vals))

        return results, next_cursor

    def list_collections(self, scope: Optional[list] = None) -> list[str]:
        """Every collection under this store root, or only those matching
        `scope` if given — the same enumeration `search_all` walks, factored
        out so a caller that only wants "what collections exist" (e.g. a
        dashboard's roots/storage view) doesn't have to run a query to get it.
        """
        names = []
        for db_file in sorted(self.root.rglob("store.db")):
            col = str(db_file.parent.relative_to(self.root))
            if col.startswith("."):
                continue
            try:
                _validate_collection(col)
            except ValueError:
                # An on-disk directory that predates _validate_collection or
                # was created outside this class — skip it rather than let
                # one bad entry crash enumeration.
                continue
            if not collection_in_scope(col, scope):
                continue
            names.append(col)
        return names

    def search_all(self, query: str, scope: Optional[list] = None) -> list[dict]:
        """Search every collection, or only those matching `scope` if given.

        `scope=None` preserves today's default: search everything under this
        store root — which is the wider fleet's store unless WILLOW_STORE_ROOT
        says otherwise, so the reach of an unscoped search is whatever store this
        process resolved (`diagnostic_summary`'s `severance` check). Pass a
        manifest's `store_scope` list to confine an app's search_all to the
        same collections its other store_* calls are restricted to.
        """
        results = []
        for col in self.list_collections(scope):
            for record in self.search(col, query):
                record["_collection"] = col
                results.append(record)
        return results

    def search_all_paginated(self, query: str, *,
                             scope: Optional[list] = None,
                             limit: int = 50,
                             cursor: Optional[str] = None,
                             ) -> tuple[list[dict], Optional[str]]:
        """Keyset-paginated variant of ``search_all()``.

        The cursor encodes ``collection\\x00id`` so the scan can resume from
        the correct collection and record.  Returns ``(items, next_cursor)``.
        """
        limit = max(1, limit)
        after_col, after_id = "", ""
        if cursor:
            decoded = decode_cursor(cursor)
            parts = decoded.split("\x00", 1)
            if len(parts) == 2:
                after_col, after_id = parts
            else:
                after_col = parts[0]

        results: list[dict] = []
        collections = self.list_collections(scope)
        for col in collections:
            if after_col and col < after_col:
                continue
            items, _ = self.search_paginated(
                col, query,
                limit=limit - len(results) + 1,
                cursor=encode_cursor(after_id) if (col == after_col and after_id) else None,
            )
            for record in items:
                record["_collection"] = col
                results.append(record)
                if len(results) > limit:
                    break
            # Reset after_id once we've moved past the cursor's collection
            if col == after_col:
                after_id = ""
            if len(results) > limit:
                break

        has_more = len(results) > limit
        results = results[:limit]
        next_cursor = None
        if has_more and results:
            last = results[-1]
            next_cursor = encode_cursor(f"{last['_collection']}\x00{last['_id']}")
        return results, next_cursor

    def delete(self, collection: str, record_id: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._conn(collection)
            result = conn.execute(
                "UPDATE records SET deleted = 1, updated_at = ? WHERE id = ? AND deleted = 0",
                (now, record_id)
            )
            conn.commit()
        return result.rowcount > 0

    def stats(self, scope: Optional[list] = None) -> list[dict]:
        """Per-collection live-record counts (deleted=0), for the collections
        visible under `scope`. Same enumeration as list_collections, plus a
        COUNT per collection — a cheap "what's in the store, and how much".
        Returned sorted by count descending, then name."""
        out = []
        for col in self.list_collections(scope=scope):
            with self._lock:
                conn = self._conn(col)
                n = conn.execute(
                    "SELECT COUNT(*) FROM records WHERE deleted = 0"
                ).fetchone()[0]
            out.append({"collection": col, "count": n})
        out.sort(key=lambda r: (-r["count"], r["collection"]))
        return out

    def purge_collection(self, collection: str) -> int:
        """Soft-delete every live record in a collection at once — a bulk
        `delete`. Archive, not drop: rows stay in the db (deleted=1) and remain
        recoverable, they just fall out of get/list/search. Returns how many
        records were purged. Never touches the collection's on-disk store.db
        (hard removal stays an operator/filesystem act, out of the tool surface).
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._conn(collection)
            result = conn.execute(
                "UPDATE records SET deleted = 1, updated_at = ? WHERE deleted = 0",
                (now,),
            )
            conn.commit()
        return result.rowcount
