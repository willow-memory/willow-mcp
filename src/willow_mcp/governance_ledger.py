"""Narrow adapter over the existing Postgres ``frank_ledger`` hash chain.

Threat model (#280), written down rather than implied:

* The chain is tamper-EVIDENT against anyone who can write rows but cannot
  rewrite the whole table consistently. It is NOT tamper-proof against the
  database operator: ``rechain()`` re-hashes rows from their current content,
  so *edit a row, run rechain()* yields a chain ``verify()`` calls valid —
  the migration and the forgery are the same operation.
* A hash chain vouches for every line except the newest. The close is a head
  recorded somewhere the chain's writer cannot reach: ``verify()`` takes
  ``expected_head`` for exactly that — hold the ``head`` value it returns in
  a CI variable, a monitoring system, an ops runbook, anywhere outside this
  database — and a silent relink becomes a detected one. ``frank_head_anchor.py``
  gives that a concrete home (``$WILLOW_HOME/constitutional/frank_head_anchor.json``,
  CLI-written only) and the ``frank_verify`` MCP tool reads it automatically,
  so an operator does not have to wire ``expected_head`` through by hand.
* ``rechain()`` reads that same anchor before migrating anything: if one is
  present and the chain's CURRENT (pre-migration) head does not match it,
  ``rechain()`` refuses rather than silently laundering whatever happened to
  the chain since the anchor was last set — see its docstring. No anchor on
  disk (the default — anchoring is opt-in) degrades to "proceed, unguarded,"
  logged rather than silent, so an install that never opted in is not newly
  broken.
* ``rechain()`` is additionally self-documenting: a run that migrated
  anything appends a ``governance.rechain`` row recording the pre-migration
  head and row count. That raises the cost of a QUIET relink; it does not
  stop a determined operator (who can delete the marker AND the anchor file
  and relink again) — only an externally-held head, actually anchored, does.
  FRANK mirroring into this table gives Nestor "someone else remembers" ONLY
  to the extent that this someone's head is anchored outside; without an
  anchor it degrades to "someone else has a copy that will agree with
  whatever it now says."
"""
from __future__ import annotations

import hashlib
import json
import uuid

# psycopg2 is imported lazily inside the DB methods so the pure hash functions
# (entry_hash / entry_hash_v2) import and test without a database present.

TABLE = "frank_ledger"
LOCK_KEY = 8817001


def _decode(content):
    if isinstance(content, str):
        try:
            return json.loads(content)
        except (json.JSONDecodeError, TypeError):
            return content
    return content


def _payload(event_type: str, content) -> str:
    return json.dumps(
        {"event_type": event_type, "content": _decode(content)}, sort_keys=True
    )


def entry_hash(prev_hash: str | None, event_type: str, content) -> str:
    """v1 — legacy coverage: hashes only event_type + content. Retained so
    pre-A7 rows still verify; NOT used for new appends (see entry_hash_v2)."""
    return hashlib.sha256(
        f"{prev_hash or ''}{_payload(event_type, content)}".encode()
    ).hexdigest()


def _payload_v2(record_id: str, project: str, event_type: str, content) -> str:
    return json.dumps(
        {"id": record_id, "project": project, "event_type": event_type,
         "content": _decode(content)}, sort_keys=True)


def entry_hash_v2(prev_hash: str | None, record_id: str, project: str,
                  event_type: str, content) -> str:
    """v2 (box audit A7): the hash now covers ``id`` and ``project`` as well.
    v1 excluded them, so FRANK's ``project`` column could be re-pointed by a
    direct UPDATE and ``verify()`` — which re-hashed only event_type+content —
    would not notice. (``created_at`` is server-set by clock_timestamp() and so
    is not known at hash time; it stays out of the digest.)"""
    return hashlib.sha256(
        f"{prev_hash or ''}{_payload_v2(record_id, project, event_type, content)}".encode()
    ).hexdigest()


class GovernanceLedger:
    def __init__(self, pg):
        self.pg = pg

    def _chain_insert(
        self, cur, record_id: str, project: str, event_type: str, content: dict
    ) -> str:
        """Read the current head and append one row chained to it.

        The session advisory lock already serializes cooperating writers, so the
        prev_hash race only arises against a writer that did not take the lock.
        The ``frank_ledger_no_fork`` UNIQUE index (docs/schema/frank-ledger-
        prevent-fork.sql) turns that into an IntegrityError instead of a silent
        fork; here we re-read the new head and retry, bounded, so the chain stays
        single-headed no matter which writer wins (§4.1).
        """
        import psycopg2
        from psycopg2.extras import Json
        for _ in range(5):
            cur.execute(
                f"SELECT hash FROM {TABLE} ORDER BY created_at DESC LIMIT 1"  # nosec B608 - TABLE is the module-level constant "frank_ledger"; no user input reaches this string
            )
            row = cur.fetchone()
            previous = row[0] if row else None
            digest = entry_hash_v2(previous, record_id, project, event_type, content)
            try:
                cur.execute(
                    f"INSERT INTO {TABLE} "  # nosec B608 - TABLE is the module-level constant "frank_ledger"; all values below are bound params
                    "(id, project, event_type, content, prev_hash, hash, created_at) "
                    "VALUES (%s, %s, %s, %s, %s, %s, clock_timestamp())",
                    (record_id, project, event_type, Json(content), previous, digest),
                )
                self.pg.commit()
                return digest
            except psycopg2.IntegrityError:
                self.pg.rollback()
        raise RuntimeError("frank chain append could not converge without forking")

    def append(self, project: str, event_type: str, content: dict) -> str:
        """Serialize against the shared chain head and append one existing-shape row."""
        record_id = str(uuid.uuid4())
        cur = self.pg.cursor()
        locked = False
        try:
            cur.execute("SELECT pg_advisory_lock(%s)", (LOCK_KEY,))
            locked = True
            self._chain_insert(cur, record_id, project, event_type, content)
            return record_id
        finally:
            if locked:
                cur.execute("SELECT pg_advisory_unlock(%s)", (LOCK_KEY,))
            cur.close()

    def append_citation(
        self, project: str, content: dict, *, max_count: int | None
    ) -> tuple[str, str]:
        """Atomically meter and append a citation under the shared chain lock."""
        record_id = str(uuid.uuid4())
        cur = self.pg.cursor()
        locked = False
        outcome = str(content.get("outcome", "EAMBIG"))
        try:
            cur.execute("SELECT pg_advisory_lock(%s)", (LOCK_KEY,))
            locked = True
            if outcome == "granted" and max_count is not None:
                cur.execute(
                    f"SELECT COUNT(*) FROM {TABLE} "  # nosec B608 - TABLE is the module-level constant "frank_ledger"; envelope_id is a bound param
                    "WHERE event_type='envelope_citation' "
                    "AND content->>'envelope_id'=%s "
                    "AND content->>'outcome'='granted'",
                    (content["envelope_id"],),
                )
                if int(cur.fetchone()[0]) >= max_count:
                    outcome = "EDQUOT"
                    content = {**content, "outcome": outcome}
            self._chain_insert(cur, record_id, project, "envelope_citation", content)
            return record_id, outcome
        finally:
            if locked:
                cur.execute("SELECT pg_advisory_unlock(%s)", (LOCK_KEY,))
            cur.close()

    def verify(self, expected_head: str | None = None) -> dict:
        """Walk the chain. ``expected_head`` is the externally-held anchor:
        pass the ``head`` a previous verify returned (kept OUTSIDE this
        database) and "is this the same chain it was yesterday?" gets an
        answer, which internal consistency alone can never give (#280).

        A head that differs from the anchor has two very different causes and
        the caller has to be able to tell them apart (gap d6d0a632184f). The
        chain may simply have GROWN since the anchor was taken -- every append
        moves the head, so a stale anchor ALWAYS mismatches -- or it may have
        been relinked by an edit-then-``rechain()``. The discriminator is
        whether the anchored head is still somewhere in this chain: if the
        running head equals ``expected_head`` at any point in the walk, every
        entry up to there is byte-identical to what was anchored and
        everything after it is an append. If it never appears, the anchored
        chain is not a prefix of this one, which is the relink.

        ``anchor_in_chain`` reports that, with ``anchor_index`` (1-based) and
        ``entries_since_anchor`` for the benign case. ``valid`` stays False
        for BOTH -- the caller asked whether the head still matches and it
        does not -- so no existing gate is loosened by the new distinction.
        """
        cur = self.pg.cursor()
        cur.execute(
            f"SELECT id, project, event_type, content, prev_hash, hash "  # nosec B608 - TABLE is the module-level constant "frank_ledger"; no user input reaches this string
            f"FROM {TABLE} ORDER BY created_at ASC"
        )
        rows = cur.fetchall()
        cur.close()
        previous = None
        anchor_index = None
        for index, row in enumerate(rows, start=1):
            record_id, project, event_type, content, prev_hash, stored_hash = row
            # A row is intact if its stored hash matches the v2 digest (id +
            # project covered) OR the legacy v1 digest (pre-A7 rows). Both are
            # accepted so the code upgrade doesn't flag an un-migrated chain as
            # tampered; a simple project-column UPDATE on a v2 row still breaks
            # BOTH digests and is caught. Run rechain() to bring v1 rows to v2.
            # The two conditions are reported apart (same shape as
            # receipts.ReceiptLog.verify) because they fail for different
            # reasons: a linkage break means rows were reordered, inserted or
            # deleted; a digest break means a row's own content was edited.
            if prev_hash != previous:
                return {"valid": False, "broken_at": record_id,
                        "count": len(rows), "head": previous,
                        "reason": "prev_hash linkage"}
            if not (entry_hash_v2(previous, record_id, project, event_type, content) == stored_hash
                    or entry_hash(previous, event_type, content) == stored_hash):
                return {"valid": False, "broken_at": record_id,
                        "count": len(rows), "head": previous,
                        "reason": "entry_hash mismatch"}
            previous = stored_hash
            if expected_head is not None and previous == expected_head:
                anchor_index = index
        if expected_head is not None and previous != expected_head:
            # Internally consistent but not the chain the caller anchored:
            # exactly what an edit-plus-rechain forgery looks like from
            # outside. broken_at stays None so the two failures are
            # distinguishable.
            extended = anchor_index is not None
            return {"valid": False, "broken_at": None, "count": len(rows),
                    "head": previous, "expected_head": expected_head,
                    "anchor_in_chain": extended,
                    "anchor_index": anchor_index,
                    "entries_since_anchor": (
                        len(rows) - anchor_index if extended else None),
                    "reason": (
                        "chain extends the anchored chain"
                        if extended
                        else "anchored head is not in this chain")}
        return {"valid": True, "broken_at": None, "count": len(rows),
                "head": previous}

    def rechain(self, *, force: bool = False) -> dict:
        """One-time migration (box audit A7): re-hash every row under v2 so the
        ``id``/``project`` columns become tamper-evident for legacy entries too,
        re-linking prev_hash as it goes. Idempotent — a fully-v2 chain is left
        unchanged. Must run under the same advisory lock as appends.

        Anchor-guarded (#280), fail-closed on anything but a clean absence:
        before touching anything, the CURRENT (pre-migration) head is
        compared against the externally-held anchor at
        ``frank_head_anchor.read_anchor()``.

        * ``status == "anchored"`` and it does not match ``pre_head`` →
          refused. That mismatch is exactly what "edit a row, then run
          rechain()" looks like from outside the database, and it is also
          what an ordinary unexpected chain mutation since the last anchor
          looks like. Either way the caller needs to look before this
          proceeds.
        * ``status`` is "untrusted" or "unreadable" (the anchor file EXISTS
          but fails the trust check, or is corrupt/malformed) → also
          refused. A file that is there but cannot be trusted is a reason to
          stop, not a reason to fall back to "no anchor" — that fallback is
          exactly the gap an attacker with local write access would reach
          for (corrupt the anchor to make rechain() ignore it).
        * ``status == "unanchored"`` (the anchor file plainly does not
          exist) → proceeds unguarded, same as before this existed.
          Anchoring is opt-in, not opt-out, and this is the one status that
          unambiguously means "never configured," not "configured and now
          broken."

        ``force=True`` is the explicit operator override for every refusal
        case above — typically: investigate, then either run
        ``willow-mcp frank-anchor write`` to accept the current head (after
        which a plain retry proceeds with no force needed, since the anchor
        now matches) or pass ``force=True`` directly when a fresh anchor
        isn't practical.

        Self-documenting regardless: a run that migrated anything appends a
        ``governance.rechain`` row — pre-migration head, rows migrated — so a
        relink leaves a mark IN the chain it relinked. That makes a quiet
        rechain loud; it does not make a malicious one impossible (the
        operator can delete the marker AND the anchor file and relink
        again), which is why an externally-held, actually-anchored head
        remains the real close. A run that migrated nothing appends nothing,
        so repeated idempotent runs do not grow the chain."""
        cur = self.pg.cursor()
        locked = False
        try:
            cur.execute("SELECT pg_advisory_lock(%s)", (LOCK_KEY,))
            locked = True
            cur.execute(
                f"SELECT id, project, event_type, content, hash "  # nosec B608 - TABLE is the module-level constant "frank_ledger"; no user input reaches this string
                f"FROM {TABLE} ORDER BY created_at ASC")
            rows = cur.fetchall()
            pre_head = rows[-1][4] if rows else None
            if not force:
                from .frank_head_anchor import read_anchor
                anchor = read_anchor()
                if anchor["status"] == "anchored":
                    if anchor["head"] != pre_head:
                        return {"refused": True, "reason": "head_mismatch",
                                "anchored_head": anchor["head"], "pre_head": pre_head,
                                "migrated": 0, "count": len(rows)}
                elif anchor["status"] != "unanchored":
                    # An anchor file EXISTS but can't be trusted or parsed —
                    # that is an anomaly, not "no anchor configured," so it
                    # is not treated as equivalent to unanchored.
                    return {"refused": True, "reason": anchor["status"],
                            "anchored_head": None, "pre_head": pre_head,
                            "migrated": 0, "count": len(rows)}
            previous, migrated = None, 0
            for record_id, project, event_type, content, stored_hash in rows:
                digest = entry_hash_v2(previous, record_id, project, event_type, content)
                if digest != stored_hash:
                    cur.execute(
                        f"UPDATE {TABLE} SET prev_hash = %s, hash = %s WHERE id = %s",  # nosec B608 - TABLE is the module-level constant "frank_ledger"; all values are bound params
                        (previous, digest, record_id))
                    migrated += 1
                previous = digest
            if migrated:
                # Chained onto the walk's own head, under the same lock the
                # walk held — no re-read, no retry loop. Plain %s::jsonb so
                # this stays runnable without psycopg2.extras (and testable
                # against the same fake cursor as the rest of this class).
                marker_id = str(uuid.uuid4())
                marker = {"pre_migration_head": pre_head,
                          "migrated": migrated, "count": len(rows)}
                digest = entry_hash_v2(previous, marker_id, "governance",
                                       "governance.rechain", marker)
                cur.execute(
                    f"INSERT INTO {TABLE} "  # nosec B608 - TABLE is the module-level constant "frank_ledger"; all values are bound params
                    "(id, project, event_type, content, prev_hash, hash, created_at) "
                    "VALUES (%s, %s, %s, %s::jsonb, %s, %s, clock_timestamp())",
                    (marker_id, "governance", "governance.rechain",
                     json.dumps(marker), previous, digest))
                previous = digest
            self.pg.commit()
            return {"migrated": migrated, "count": len(rows),
                    "pre_head": pre_head, "head": previous}
        finally:
            if locked:
                cur.execute("SELECT pg_advisory_unlock(%s)", (LOCK_KEY,))
            cur.close()

    def citation_count(self, envelope_id: str) -> int:
        cur = self.pg.cursor()
        cur.execute(
            f"SELECT COUNT(*) FROM {TABLE} "  # nosec B608 - TABLE is the module-level constant "frank_ledger"; envelope_id is a bound param
            "WHERE event_type = 'envelope_citation' "
            "AND content->>'envelope_id' = %s "
            "AND content->>'outcome' = 'granted'",
            (envelope_id,),
        )
        count = int(cur.fetchone()[0])
        cur.close()
        return count

    def citations(self, envelope_id: str) -> list[dict]:
        from psycopg2.extras import RealDictCursor
        cur = self.pg.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            f"SELECT * FROM {TABLE} "  # nosec B608 - TABLE is the module-level constant "frank_ledger"; envelope_id is a bound param
            "WHERE event_type = 'envelope_citation' "
            "AND content->>'envelope_id' = %s ORDER BY created_at ASC",
            (envelope_id,),
        )
        rows = [dict(row) for row in cur.fetchall()]
        cur.close()
        return rows
