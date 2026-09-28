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

import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .db import Store, decode_cursor, encode_cursor

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


#: Hard ceiling on one gap_list page (gap 1477ebb2bc35) when `brief=True`
#: (the default): a full record can run over a KB, and the backlog's own
#: operator flagged a 50-95 KB page as the reason the only working read
#: door was also the worst one. Applied regardless of what `limit` asks for.
MAX_LIST_LIMIT = 25

#: The ceiling when `brief=False` (Loki EB30E84F F1): a full record carries
#: the whole question text and every metadata key, so the SAME 25-row cap
#: measured 134,233 bytes (~33.5k tokens) against 5 KB questions -- over a
#: real MCP client's ~25k-token tool-result budget by a third, recreating
#: gap 1477ebb2bc35 one flag away from the default. Question text is not
#: itself size-bounded at write time (`log()`), so a byte-budget mid-page
#: would still need a floor somewhere; a materially lower row ceiling for
#: the shape that carries full records is the smaller change and the fix
#: Loki named as acceptable.
MAX_LIST_LIMIT_FULL = 5


def _parse_iso(value: str) -> Optional[datetime]:
    """A timezone-aware UTC `datetime` for `value`, or `None` if it does not
    parse (Loki EB30E84F F4: the old `since` filter was a raw string
    compare against `last_asked_at` -- correct only when both sides are the
    exact same string shape; a 'Z'-suffixed `since` sorted AFTER a
    microsecond-bearing same-second `last_asked_at` because '.' < 'Z', and
    an unparseable `since` like "yesterday" silently matched nothing rather
    than refusing). Naive values are assumed UTC, matching `_now()`'s own
    `isoformat()` output before a `Z`/offset is ever added."""
    try:
        dt = datetime.fromisoformat((value or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _matches_topic(row_topic: str, topic: str) -> bool:
    """Exact match, or `row_topic` is namespaced under `topic` on a '/'
    boundary -- "a/b/c" is under "a/b", but "a/bc" is not (gap 1477ebb2bc35:
    `topic` used to be exact-only, so a caller filtering by a parent
    namespace had to enumerate every child topic by hand)."""
    return row_topic == topic or row_topic.startswith(topic + "/")


def _matches_query(row: dict[str, Any], tokens: list[str]) -> bool:
    """Whitespace tokens, AND, substring over topic+question -- the same
    rule `Store.search` (db.py) uses, reimplemented here in Python because
    this filter runs over `topic`+`question` together and alongside the
    topic-prefix/since filters, neither of which a single SQL equality
    filter (`query_paginated`'s `filters` dict) can express."""
    haystack = f"{row.get('topic', '')} {row.get('question', '')}".lower()
    return all(tok in haystack for tok in tokens)


def _brief_view(row: dict[str, Any]) -> dict[str, Any]:
    """id/topic/status/asked_count/last_asked_at + the first 200 chars of
    the question -- everything a caller usually needs to decide whether to
    `gap_get` the full record, at a fraction of its size."""
    return {
        "id": row.get("_id"),
        "topic": row.get("topic"),
        "status": row.get("status"),
        "asked_count": row.get("asked_count"),
        "last_asked_at": row.get("last_asked_at"),
        "question": (row.get("question") or "")[:200],
    }


def list_gaps(
    topic: Optional[str] = None,
    status: Optional[str] = None,
    query: Optional[str] = None,
    since: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
    brief: bool = True,
) -> dict[str, Any]:
    """Most-asked first. Filter by:

    * ``topic`` — exact match, or namespace prefix (see `_matches_topic`).
    * ``status`` — open | resolved | promoted, exact.
    * ``query`` — whitespace tokens, AND, substring over topic+question
      (see `_matches_query`) — the rule `Store.search` uses.
    * ``since`` — an ISO-8601 timestamp, parsed (not string-compared —
      Loki EB30E84F F4) and normalized to UTC; keeps rows whose
      ``last_asked_at`` is ``>=`` it. An unparseable ``since`` is refused
      (``{error: EINVAL}``), never silently treated as "match nothing".

    Returns ``{items, next_cursor}`` — *next_cursor* is ``None`` when there
    are no more pages, or ``{error: EINVAL, ...}`` if ``since`` does not
    parse. ``limit`` is capped at `MAX_LIST_LIMIT` (25) when ``brief=True``
    (the default) or `MAX_LIST_LIMIT_FULL` (5) when ``brief=False``,
    regardless of what is asked for — a full record is large enough that
    the brief page's row cap does not also bound it (Loki EB30E84F F1).
    ``brief`` (default ``True``) returns `_brief_view` per row;
    ``brief=False`` returns the full record (gap 1477ebb2bc35).

    Loads the collection once (`Store.all`, the same primitive
    `purge_topic` already uses) rather than pushing these filters into SQL:
    `query_paginated`'s `filters` dict is equality-only, and none of
    `topic`-as-prefix, the `query` substring-over-two-fields match, or the
    `since` threshold are a single equality comparison. The backlog is
    meant to stay one small, fleet-shared queue (module docstring), not a
    table that needs its own query planner -- and the page cap above keeps
    what gets returned bounded either way. The cursor here is therefore a
    plain offset into the filtered, sorted list (opaque via the same
    `encode_cursor`/`decode_cursor` helpers `query_paginated` uses), not a
    keyset into a sort key -- correct and stable as long as the underlying
    rows are not being retired between pages of the SAME query, which for a
    backlog a caller is actively paging through is the expected case.
    """
    cap = MAX_LIST_LIMIT if brief else MAX_LIST_LIMIT_FULL
    limit = max(1, min(limit, cap))
    tokens = query.lower().split() if query else []

    since_dt = None
    if since:
        since_dt = _parse_iso(since)
        if since_dt is None:
            return {"error": "EINVAL",
                    "message": f"`since` is not a parseable ISO-8601 timestamp: {since!r}"}

    rows = _store.all(_COLLECTION)
    if topic:
        rows = [r for r in rows if _matches_topic(r.get("topic") or "", topic)]
    if status:
        rows = [r for r in rows if r.get("status") == status]
    if since_dt is not None:
        rows = [r for r in rows
                if (_parse_iso(r.get("last_asked_at") or "") or datetime.min.replace(tzinfo=timezone.utc))
                >= since_dt]
    if tokens:
        rows = [r for r in rows if _matches_query(r, tokens)]

    rows.sort(key=lambda r: (-(r.get("asked_count") or 0), r.get("_id") or ""))

    offset = 0
    if cursor:
        try:
            offset = int(decode_cursor(cursor))
        except (ValueError, TypeError):
            offset = 0
    page = rows[offset:offset + limit]
    next_cursor = encode_cursor(str(offset + limit)) if offset + limit < len(rows) else None

    items = [_brief_view(r) for r in page] if brief else page
    return {"items": items, "next_cursor": next_cursor}


def get(gap_id: str) -> Optional[dict[str, Any]]:
    return _store.get(_COLLECTION, gap_id)


def get_gap(gap_id: str) -> dict[str, Any]:
    """The full record for one gap by id -- the read door `list_gaps`'
    query/topic/since filters can't substitute for (gap 1477ebb2bc35):
    `store_get` refuses ``gaps`` (outside every seat's `store_scope`), and
    `list_gaps` has no id lookup. Returns the record, or ``{error:
    not_found}``."""
    record = _store.get(_COLLECTION, gap_id)
    if record is None:
        return {"error": "not_found", "id": gap_id}
    return record


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


# ── gap_touching (B1 of docs/design/gaps-in-soil.md, §4.2) ────────────────────
#
# Read-time only: no edge store, no migration. Every open/resolved gap is
# scanned at call time with the same regexes the design's linker (B2) will
# later persist as `names_file`/`names_symbol` edges. Three tiers, in order:
#   1. exact  — a path from `paths` appears verbatim in the gap's own text
#      (or the text names a file under a directory prefix, when a `paths`
#      entry ends in "/").
#   2. symbol — an identifier in the gap's text resolves to EXACTLY ONE
#      symbol in the per-project code_graph DB, and that symbol's file is
#      one of `paths`.
#   3. project+stem (weaker, capped at 5) — the gap's topic pins `project`,
#      and a token of one of the `paths`' basenames (split on "/ . - _")
#      is among the gap's own tokenizer output. This is the only tier that
#      finds 07aa99036f09 (topic `ratatosk/listener-home-pin-tests-and-
#      crown-mcp-guard`, no file path in its text at all).

#: Path-looking substrings inside gap text: the same shape the design's
#: `names_file` linker will use (§2) — a repo-relative path (one or more
#: "/"-separated segments) or a bare `name.ext` (zero segments), unified
#: into one pattern. Loki A4836541 L1c: each segment is length-bounded
#: ({1,80}) and the whole thing is \b-anchored, so a long unbroken
#: `[\w.-]`-run backtracks at most O(80) per starting offset instead of
#: O(run-length) — re.finditer's per-position restart stays linear in the
#: text length rather than quadratic.
_PATH_EXTS = r"py|js|ts|md|json|sh|toml|ya?ml|sql|service|template"
_PATH_SEG = r"[\w.-]{1,80}"
_PATH_RE = re.compile(
    rf"\b{_PATH_SEG}(?:/{_PATH_SEG}){{0,10}}\.(?:{_PATH_EXTS})(?::\d+)?\b"
)

#: Identifier-looking substrings: backticked names, `name()` calls,
#: snake_case (>=4 chars), or CamelCase with at least two humps — the same
#: shape the design's `names_symbol` linker will use (§2). Length-bounded
#: per group for the same backtracking reason as `_PATH_RE`.
_IDENT_RE = re.compile(
    r"`([A-Za-z_][A-Za-z0-9_.]{3,40})`"
    r"|\b([A-Za-z_][A-Za-z0-9_]{3,40})\(\)"
    r"|\b([a-z][a-z0-9]{0,40}_[a-z0-9_]{2,40})\b"
    r"|\b([A-Z][a-z0-9]{1,40}(?:[A-Z][a-z0-9]{1,40}){1,10})\b"
)

#: §4 bounds (gap 1477ebb2bc35's row cap, applied here too): at most 25 rows.
MAX_TOUCHING_ROWS = 25

#: Tier 3 is the weak one — capped tighter than the page itself (§4.2).
MAX_TOUCHING_TIER3_ROWS = 5

#: The 16 KB serialized-page ceiling §4 requires alongside the row cap — a
#: row cap alone under-bounds a page of large `question` text (same reasoning
#: as MAX_LIST_LIMIT_FULL above).
MAX_TOUCHING_BYTES = 16 * 1024

#: Loki A4836541 B2: tier 2's hard budget. Both bounds are checked before
#: EVERY unique-identifier lookup (not per row — see `_resolve_tier2_matches`),
#: so the worst case is bounded regardless of backlog size or graph size.
#: 500 indexed lookups is generous headroom over any real backlog observed
#: (B9F28JGJ's 20k-symbol graph needed 1185 lookups to time out at ~50ms
#: each under the OLD unindexed LOWER() scan; indexed lookups cost close to
#: 0 by comparison) while still being a real, enforced ceiling.
MAX_TIER2_LOOKUPS = 500
MAX_TIER2_SECONDS = 2.0


def _gap_text(row: dict[str, Any]) -> str:
    return f"{row.get('topic', '')} {row.get('question', '')}"


def _extract_paths(text: str) -> list[str]:
    out = []
    for m in _PATH_RE.finditer(text or ""):
        out.append(re.sub(r":\d+$", "", m.group(0)))
    return out


def paths_in_text(text: str) -> list[str]:
    """Public wrapper over `_extract_paths` for callers outside this module
    (`dispatch_send`, `session_enter`) that need to turn an assignment's
    free text into the `paths` `touching()` takes — same regex, so a path
    dispatch_send finds is exactly what a later `touching()` call on it
    would find too. Order-preserving, de-duplicated."""
    seen: list[str] = []
    for p in _extract_paths(text):
        if p not in seen:
            seen.append(p)
    return seen


def _extract_identifiers(text: str) -> list[str]:
    out = []
    for m in _IDENT_RE.finditer(text or ""):
        ident = next((g for g in m.groups() if g), None)
        if ident:
            out.append(ident)
    return out


def _basename_stems(paths: list[str]) -> set[str]:
    stems: set[str] = set()
    for p in paths:
        base = p.rstrip("/").rsplit("/", 1)[-1]
        for tok in re.split(r"[./\-_]", base):
            if tok:
                stems.add(tok.lower())
    return stems


def _project_root(project: str) -> Optional[Path]:
    """The registered checkout root for `project`, or None — never raises.
    Loki A4836541 M2: used ONLY to verify a flat-DB tier-2 match actually
    lives in the caller's own project before it is trusted; a per-project
    DB needs no such check (it is already scoped)."""
    if not project:
        return None
    try:
        from . import mcp_projects

        reg = mcp_projects.load_registry()
        entry = (reg.get("projects") or {}).get(project)
        if not entry:
            return None
        return mcp_projects.project_paths(project, entry)["root"]
    except Exception:
        return None


def _code_graph_db_for(project: str) -> tuple[Optional[Path], str]:
    """Resolve the per-project code_graph DB path (design §0.2: the graph
    schema has no repo column, so the deterministic path is one DB per
    project). Today's code_graph_index only ever writes the flat
    `$WILLOW_HOME/code_graph/graph.db` (server.py's `_code_graph_db`), so a
    per-project `$WILLOW_HOME/code_graph/<project>/graph.db` is checked
    first (forward-compatible with B2's linker, which will need to start
    writing one DB per project) and the flat path is the fallback.

    Returns `(path, source)` where `source` is `"per_project"`, `"flat"`,
    or `"none"` — the caller (Loki A4836541 M2) uses `source` to decide
    whether a match needs cross-repo verification: a flat-DB match is
    unscoped and must be checked against the caller's own project
    checkout before it is trusted; a per-project DB is already scoped and
    needs no such check."""
    from . import paths as _paths

    home = _paths.willow_home()
    if project:
        per_project = home / "code_graph" / project / "graph.db"
        if per_project.is_file():
            return per_project, "per_project"
    flat = home / "code_graph" / "graph.db"
    if flat.is_file():
        return flat, "flat"
    return None, "none"


def _ordered_unique_identifiers(live: list[dict[str, Any]]) -> list[str]:
    """Loki 28B97C69 M4: a deterministic identifier order, independent of
    PYTHONHASHSEED. The live backlog carries more unique identifiers than
    the tier-2 budget, so WHICH ones get resolved (and therefore which
    gaps get labelled) must not depend on Python's per-process string-hash
    salt — the same input has to yield the same output every run. Rows are
    sorted by `last_asked_at` descending (most recently asked first, ties
    broken by id for a total order) rather than relying on `_store.all`'s
    own row order; identifiers are then taken in each row's own extraction
    order, first-seen-wins, using a list + a `seen` set rather than a bare
    `set()` for the return value itself."""
    ordered_rows = sorted(
        live,
        key=lambda r: (str(r.get("last_asked_at") or ""), str(r.get("_id") or "")),
        reverse=True,
    )
    seen: set[str] = set()
    result: list[str] = []
    for row in ordered_rows:
        for ident in _extract_identifiers(_gap_text(row)):
            if ident not in seen:
                seen.add(ident)
                result.append(ident)
    return result


def _defines_symbol(file_path: Path, name: str) -> bool:
    """Loki 28B97C69 Q4/fold-in: a weak stand-in for "the file's content
    hash matches" (the flat code_graph DB stores neither a project/root
    column nor a content hash to compare against — see `_code_graph_db_for`
    ). Re-reads the file AS FOUND IN THE CALLER'S OWN CHECKOUT and checks
    that it actually defines `name` (a `def`/`class` at that name) rather
    than trusting the flat DB's stale (file_path, name) pairing blindly.
    This is exactly what catches Q4's willow-bot `_guarded_home` row
    resolving against willow-mcp's own `tests/conftest.py`, which never
    defines it: the file exists (M2's first check passes) but does not
    define the symbol (this check fails), so the match is dropped.
    Never raises — an unreadable file is "cannot determine", so it drops
    the match rather than trusting it."""
    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    pattern = re.compile(rf"\b(?:def|class)\s+{re.escape(name)}\b")
    return bool(pattern.search(text))


def _resolve_tier2_matches(
    db_path: Path, identifiers: list[str], project: str, db_source: str,
) -> tuple[dict[str, list[str]], str]:
    """Loki A4836541 B2: ONE connection for the whole call, ONE indexed
    lookup per UNIQUE identifier across the entire backlog (never per row —
    the old code ran rows × identifiers_per_row fresh-connection LOWER()
    full scans, which is how a 20k-symbol graph exceeded 60s). `name = ?`
    (no `LOWER()`) so `idx_symbols_name` is used. Bounded by both a lookup
    count and a wall-clock budget, checked before every lookup, so the
    worst case is bounded regardless of the backlog or the graph's size.

    M2 (tightened per Loki 28B97C69 Q4): a flat-DB match is trusted only
    if the symbol's defining file exists in the caller's own project
    checkout (`_project_root`) AND that file actually defines the symbol
    there (`_defines_symbol`, a stand-in for a content-hash match the
    schema has no column to check directly) — a flat DB carries no repo
    column, so mere path existence let a symbol from one repo (e.g.
    willow-bot's `_guarded_home` in its own `tests/conftest.py`) get
    labelled tier 2 for a different repo's file of the same relative path
    that never defines it. If either signal cannot be determined (no
    project root, unreadable file), the match is dropped, never trusted.

    Returns `(identifier -> [file_path, ...], health)`, health one of
    `"indexed"` (every identifier resolved within budget), `"unreachable"`
    (the DB raised on open or on a query), or `"budget_exhausted"`
    (stopped early; the returned map is a genuine partial result, not a
    failure — every identifier resolved before the budget ran out is
    trustworthy)."""
    import time

    matches: dict[str, list[str]] = {}
    root = _project_root(project) if db_source == "flat" else None
    start = time.monotonic()
    try:
        conn = sqlite3.connect(str(db_path))
    except sqlite3.Error:
        return {}, "unreachable"
    try:
        count = 0
        for ident in identifiers:
            if count >= MAX_TIER2_LOOKUPS or (time.monotonic() - start) > MAX_TIER2_SECONDS:
                return matches, "budget_exhausted"
            count += 1
            try:
                rows = conn.execute(
                    "SELECT DISTINCT file_path FROM symbols WHERE name = ?",
                    (ident,),
                ).fetchall()
            except sqlite3.Error:
                return matches, "unreachable"
            files = [r[0] for r in rows]
            if db_source == "flat" and files:
                files = [
                    f for f in files
                    if root is not None
                    and (root / f).is_file()
                    and _defines_symbol(root / f, ident)
                ]
            matches[ident] = files
    finally:
        conn.close()
    return matches, "indexed"


def touching(
    paths: Optional[list[str]],
    project: str = "",
    limit: int = MAX_TOUCHING_ROWS,
) -> dict[str, Any]:
    """§4.2: open/resolved gaps whose text touches any of `paths` — a
    dispatch's or a diff's file list — in three labelled tiers (see the
    module comment above `_PATH_RE`). `promoted` gaps are never returned
    (their knowledge atom is the closure, not another surfacing).

    Three-state on every call (INVARIANTS §1): `state` is one of
    `"populated"`, `"empty"`, or `"unreachable"`. A `Store.all` failure is
    reported as `unreachable` with its `reason` and an empty `items` — it
    is NEVER folded into the same shape an honestly-empty backlog returns,
    which is the exact bug this design calls out in `boot_context._gap_lines`
    (left for B7, see docs/design/gaps-in-soil.md §7).

    `tier2_health` reports the CODE GRAPH's own state separately (Loki
    A4836541 M1) rather than folding a missing/unreachable/exhausted graph
    into the same "empty" a truly-empty backlog returns: `"not_attempted"`
    (the store read itself failed, or there was nothing to scan),
    `"unindexed"` (no code_graph DB found for `project`), `"indexed"`
    (queried, within budget), `"unreachable"` (the DB raised), or
    `"budget_exhausted"` (see `_resolve_tier2_matches`).

    Bounded (§4): at most `MAX_TOUCHING_ROWS` (25) rows, tier 3 additionally
    capped at `MAX_TOUCHING_TIER3_ROWS` (5) — `total` is counted BEFORE
    that cap, so it still reflects every real match — and the serialized
    page never exceeds `MAX_TOUCHING_BYTES` (16 KB). `truncated` is True
    when the row cap, the byte ceiling, OR the tier-3 cap itself cut real
    rows (Loki 28B97C69 NITS(a): a caller with few real tier-3 matches
    still needs to know the cap dropped some, even when the page never
    gets close to the row/byte bounds). There is no `cursor` parameter, so
    a truncated page has no way to ask for the next one — `next_cursor`
    was dropped rather than shipped as a promise this verb cannot keep.

    Only a QUALIFIED path (containing "/") is eligible for tier 1's exact
    match (Loki A4836541 M3): a bare `paths` entry like `tick.py` is
    ambiguous across every repo that has one, so it contributes only to
    tier 3's basename-stem set, never to "exact". Symmetrically, gap text
    naming a bare filename for a qualified input path is caught the same
    way, through tier 3 — not missed, and not mislabelled "exact" either.

    Read-time only (B1): no edge store, no migration, no model anywhere in
    the path — regex, a code_graph SQLite read, and set intersection.
    """
    try:
        rows = _store.all(_COLLECTION)
    except Exception as exc:
        return {
            "state": "unreachable",
            "reason": f"{type(exc).__name__}: {exc}",
            "items": [],
            "truncated": False,
            "total": 0,
            "tier2_health": "not_attempted",
        }

    clean_paths = [p.strip() for p in (paths or []) if (p or "").strip()]
    live = [r for r in rows if r.get("status") in ("open", "resolved")]

    if not clean_paths or not live:
        return {
            "state": "empty", "items": [], "truncated": False, "total": 0,
            "tier2_health": "not_attempted",
        }

    limit = max(1, min(int(limit or MAX_TOUCHING_ROWS), MAX_TOUCHING_ROWS))

    # M3: only a qualified ("has a '/'") path is eligible for tier 1. A bare
    # basename still feeds tier 3's stem set (via _basename_stems, below,
    # which runs over every clean path regardless).
    exact_paths = {p for p in clean_paths if "/" in p and not p.endswith("/")}
    dir_prefixes = [p for p in clean_paths if p.endswith("/")]
    basename_tokens = _basename_stems(clean_paths)

    db_path, db_source = _code_graph_db_for(project)
    tier2_matches: dict[str, list[str]] = {}
    tier2_health = "unindexed"
    if db_path is not None:
        # M4: deterministic order (not a bare `set()`'s hash-randomized
        # iteration) so which identifiers make it inside the tier-2 budget
        # -- and therefore which gaps get labelled -- is stable run to run.
        ordered_idents = _ordered_unique_identifiers(live)
        if ordered_idents:
            tier2_matches, tier2_health = _resolve_tier2_matches(
                db_path, ordered_idents, project, db_source,
            )
        else:
            tier2_health = "indexed"

    tier1: list[tuple[dict, str]] = []
    tier2: list[tuple[dict, str]] = []
    tier3: list[tuple[dict, str]] = []

    for row in live:
        text = _gap_text(row)

        why = None
        for fp in _extract_paths(text):
            if fp in exact_paths or any(fp.startswith(pfx) for pfx in dir_prefixes):
                why = f"exact:{fp}"
                break
        if why:
            tier1.append((row, why))
            continue

        if tier2_matches:
            symbol_why = None
            for ident in _extract_identifiers(text):
                files = tier2_matches.get(ident) or []
                if len(files) == 1 and files[0] in clean_paths:
                    symbol_why = f"symbol:{ident}"
                    break
            if symbol_why:
                tier2.append((row, symbol_why))
                continue

        if project:
            topic = str(row.get("topic") or "")
            topic_head = topic.split("/", 1)[0]
            if topic_head == project:
                hit = sorted(set(_tokens(text)) & basename_tokens)
                if hit:
                    tier3.append((row, f"project+stem:{hit[0]}"))

    total = len(tier1) + len(tier2) + len(tier3)  # before the tier-3 cap (L1a)
    # NITS(a): the tier-3 cap itself is a truncation even when the row/byte
    # loop below never has to cut anything -- a caller with a small `paths`
    # list and >5 real tier-3 matches must not see truncated=False.
    truncated = len(tier3) > MAX_TOUCHING_TIER3_ROWS
    tier3 = tier3[:MAX_TOUCHING_TIER3_ROWS]
    ordered = tier1 + tier2 + tier3

    items: list[dict[str, Any]] = []
    total_bytes = 0
    for row, why in ordered:
        if len(items) >= limit:
            truncated = True
            break
        brief = _brief_view(row)
        brief["why"] = why
        row_bytes = len(json.dumps(brief, separators=(",", ":")).encode("utf-8"))
        if items and total_bytes + row_bytes > MAX_TOUCHING_BYTES:
            truncated = True
            break
        items.append(brief)
        total_bytes += row_bytes

    return {
        "state": "populated" if items else "empty",
        "items": items,
        "truncated": truncated,
        "total": total,
        "tier2_health": tier2_health,
    }
