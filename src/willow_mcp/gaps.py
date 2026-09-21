"""gaps.py — fleet-wide "what don't we know yet" backlog.

Deliberately shared across apps (like knowledge_search / store_search_all)
rather than scoped per app_id — the whole point is a single backlog any
agent in the fleet can read from and add candidates to, the same way the
SOIL store is shared by default (see db.py's collection_in_scope note).
`topic` is a free-form namespace a caller can filter by, not an isolation
boundary — an operator who wants real isolation should scope the gap_*
tool group out of an app's manifest instead.

A gap moves through three states:
  open      -> logged, nobody has acted on it yet
  resolved  -> someone is working it / has an answer, not yet trusted
  promoted  -> landed in the knowledge base via gap_promote (see server.py)

resolve() is bookkeeping only — it never writes to the knowledge base.
Only promote (mark_promoted(), called from server.gap_promote after a
successful _knowledge_ingest_core() write) can close a gap out for good,
so "promoted" always means "an actual knowledge atom exists for this."
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from .db import Store

_COLLECTION = "gaps"
_store = Store()

_STOP = {
    "the", "and", "for", "with", "from", "that", "this", "these", "those",
    "have", "has", "had", "was", "were", "are", "is", "been", "being",
    "what", "who", "when", "where", "why", "how", "which", "would", "could",
    "should", "does", "did", "about", "into", "your", "you", "tell", "show",
    "find", "give", "please", "can", "will", "its", "it's",
}


def _tokens(text: str) -> list[str]:
    return [
        t for t in re.findall(r"[a-z0-9][a-z0-9_-]{2,}", (text or "").lower())
        if t not in _STOP
    ]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _strip_meta(record: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in record.items() if not k.startswith("_")}


def log(topic: str, question: str) -> dict[str, Any]:
    """Log or bump a gap. Repeated asks — same topic + normalized question,
    stopwords stripped — increment asked_count instead of duplicating.
    asked_count is the backlog's own priority signal."""
    topic = (topic or "").strip()
    question = (question or "").strip()
    if not topic or not question:
        return {"error": "topic and question are required"}

    tokens = tuple(sorted(set(_tokens(question))))
    key = f"{topic}|{'|'.join(tokens) or question.lower()}"
    gap_id = uuid.uuid5(uuid.NAMESPACE_URL, key).hex[:12]

    existing = _store.get(_COLLECTION, gap_id)
    if existing and existing.get("status") == "promoted":
        return {
            "id": gap_id,
            "status": "promoted",
            "promoted_to": existing.get("promoted_to"),
            "asked_count": existing.get("asked_count", 0),
        }

    record = {
        "topic": topic,
        "question": question,
        "status": (existing or {}).get("status", "open"),
        "asked_count": (existing or {}).get("asked_count", 0) + 1,
        "first_asked_at": (existing or {}).get("first_asked_at") or _now(),
        "last_asked_at": _now(),
        "promoted_to": (existing or {}).get("promoted_to"),
    }
    rid, _action = _store.put(_COLLECTION, record, record_id=gap_id)
    return {"id": rid, "status": record["status"], "asked_count": record["asked_count"]}


def list_gaps(
    topic: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> dict[str, Any]:
    """Most-asked first. Filter by topic and/or status (open|resolved|promoted).

    Returns ``{items, next_cursor}`` — *next_cursor* is ``None`` when there
    are no more pages.  Uses SQL-level filtering and keyset pagination via
    json_extract — only the requested page is loaded from the database.
    """
    filters: dict[str, Any] = {}
    if topic:
        filters["topic"] = topic
    if status:
        filters["status"] = status

    items, next_cursor = _store.query_paginated(
        _COLLECTION,
        filters=filters,
        sort=[("asked_count", "DESC"), ("_id", "ASC")],
        limit=limit,
        cursor=cursor,
    )
    return {"items": items, "next_cursor": next_cursor}


def get(gap_id: str) -> Optional[dict[str, Any]]:
    return _store.get(_COLLECTION, gap_id)


def resolve(gap_id: str, note: str = "") -> dict[str, Any]:
    """Mark a gap as being worked or answered — bookkeeping only, never
    writes to the knowledge base. See server.gap_promote to land a
    verified answer and close the gap out."""
    existing = _store.get(_COLLECTION, gap_id)
    if not existing:
        return {"error": "not_found"}
    if existing.get("status") == "promoted":
        return {"error": "already_promoted", "promoted_to": existing.get("promoted_to")}

    record = _strip_meta(existing)
    record["status"] = "resolved"
    if note:
        record["resolution_note"] = note
    _store.update(_COLLECTION, gap_id, record)
    return {"id": gap_id, "status": "resolved"}


def retopic(gap_id: str, topic: str, *, by: str, note: str = "") -> dict[str, Any]:
    """Move a gap under a new topic, keeping the move on the record.

    Gap 42ec50583126 (apk/keyboard-act): ``log`` fixes ``topic`` at creation
    and the backlog is fleet-shared rather than in any seat's store_scope, so
    nothing could rename a gap — the apk/keyboard-act list had to be built as
    carrier rows citing their sources. This is the honest verb: the topic
    changes, ``topic_history`` appends ``{from, to, at, by, note}`` so the old
    name is never lost, and the record's id is unchanged (the id is derived
    from the ORIGINAL topic+question at log time and stays stable — a later
    ``log`` under the old topic would bump this same row, which is the point:
    one gap, one id).

    Refuses an unknown id (``not_found``), an empty topic, and a topic equal to
    the current one (``already``). Promoted gaps may be re-topiced — the
    knowledge atom they point at is unaffected. Returns ``{id, topic,
    previous}``. Bookkeeping only; the FRANK event is the caller's.
    """
    topic = (topic or "").strip()
    if not topic:
        return {"error": "topic is required"}
    existing = _store.get(_COLLECTION, gap_id)
    if not existing:
        return {"error": "not_found", "id": gap_id}
    previous = existing.get("topic") or ""
    if previous == topic:
        return {"error": "already", "id": gap_id, "topic": topic}

    record = _strip_meta(existing)
    record["topic"] = topic
    history = list(record.get("topic_history") or [])
    entry: dict[str, Any] = {"from": previous, "to": topic, "at": _now(), "by": by or ""}
    if note:
        entry["note"] = note
    history.append(entry)
    record["topic_history"] = history
    _store.update(_COLLECTION, gap_id, record)
    return {"id": gap_id, "topic": topic, "previous": previous}


def delete(gap_id: str) -> dict[str, Any]:
    """Soft-delete a single gap — for clearing junk or test entries the backlog
    accumulated, without touching the collection's real gaps (which is why this
    is gap-level, not a whole-collection purge). Archive, not drop: the record
    is retained (deleted=1) and simply falls out of list_gaps. Returns
    {deleted, id}, or {error: not_found} for an unknown id."""
    if not _store.get(_COLLECTION, gap_id):
        return {"error": "not_found", "id": gap_id}
    return {"deleted": _store.delete(_COLLECTION, gap_id), "id": gap_id}


def purge_topic(topic: str) -> dict[str, Any]:
    """Soft-delete every gap under an exact `topic` in one pass — a bulk
    gap_delete for clearing a whole junk/test namespace without making one
    rate-limited MCP call per gap. Promoted gaps are left intact: they point at
    a real knowledge atom, so they're protected here the same way resolve()
    refuses them. Archive, not drop — purged gaps are retained (deleted=1) and
    just fall out of gap_list. Returns {purged, skipped_promoted, topic}."""
    topic = (topic or "").strip()
    if not topic:
        return {"error": "topic is required"}
    rows = [r for r in _store.all(_COLLECTION) if r.get("topic") == topic]
    purged = skipped = 0
    for r in rows:
        if r.get("status") == "promoted":
            skipped += 1
            continue
        if _store.delete(_COLLECTION, r["_id"]):
            purged += 1
    return {"purged": purged, "skipped_promoted": skipped, "topic": topic}


def mark_promoted(gap_id: str, knowledge_id: str) -> None:
    """Called by server.gap_promote after a successful knowledge write —
    not a public tool itself, so it doesn't validate gap_id existence the
    way the public functions do; the caller already looked the gap up."""
    existing = _store.get(_COLLECTION, gap_id)
    if not existing:
        return
    record = _strip_meta(existing)
    record["status"] = "promoted"
    record["promoted_to"] = knowledge_id
    _store.update(_COLLECTION, gap_id, record)
