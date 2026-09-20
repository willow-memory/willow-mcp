"""willow_mcp/kb_verify.py — Knowledge-base source verification and health checks.

Ports the verification patterns from 2.0's source_trail_verify and 1.9's
mem_check into willow-mcp's schema-profile-aware KB surface.  `verify_sources`
and `check_health` are read-only and return a structured verdict dict with an
outcome key plus evidence — the same shape frank_verify and the canonical
verify tools use.

`verify_and_record` (below) is the ONLY function in this module that writes.
It wraps the two read-only checks with a persistence layer: a durable,
timestamped `verification_log` SOIL trail (GAP #3) plus a training_corpus
example per run. The pure functions above remain side-effect-free when called
directly — persistence is opt-in, not implicit in the verdict computation.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from . import kb_curate as kbc
from . import schema_profile as sp
from ._kb_sql import KNOWLEDGE_FIELDS, build_select, row_to_dict
from .training_corpus import (
    SOURCE_KB_VERIFY,
    TrainingExample,
    append_training_example,
)

logger = logging.getLogger(__name__)

# SOIL collection for the durable verification trail (GAP #3).
VERIFICATION_LOG_COLLECTION = "verification_log"


def _query_records(pg, app_id: str, *, domain: Optional[str] = None,
                   limit: int = 200) -> dict:
    """Shared query: fetch KB records with schema-profile awareness.

    Returns {"records": [...], "present": [...], "unmapped": [...], "total": N}
    on success, or an error dict.
    """
    mapping = sp.resolve(pg, app_id, "knowledge", KNOWLEDGE_FIELDS)
    if "error" in mapping:
        return mapping
    fields = mapping["fields"]
    if fields["id"]["column"] is None or fields["content"]["column"] is None:
        return {"error": "schema_unusable",
                "detail": "'knowledge' table has no mappable 'id' or 'content' column"}

    select_clause, present, unmapped = build_select(KNOWLEDGE_FIELDS, fields)

    tags_col = fields["tags"]["column"]
    cols_by_name = {c.name: c for c in sp.introspect(pg, "knowledge")}
    retract_sql, retract_params = kbc.sql_exclude_retracted(tags_col, cols_by_name)

    sql = f"SELECT {select_clause} FROM knowledge WHERE 1=1{retract_sql}"  # nosec B608 - select_clause/retract_sql built from confirmed schema_profile mapping; all values are bound params
    params: list = list(retract_params)

    if domain and fields["domain"]["column"]:
        sql += f' AND "{fields["domain"]["column"]}" = %s'
        params.append(domain)
    sql += " LIMIT %s"
    params.append(limit)

    cur = pg.cursor()
    cur.execute(sql, params)
    rows = cur.fetchall()
    cur.close()

    records = [row_to_dict(r, present, unmapped) for r in rows]
    return {"records": records, "present": present, "unmapped": unmapped,
            "total": len(records)}


def verify_sources(pg, app_id: str, *, domain: Optional[str] = None,
                   limit: int = 200) -> dict:
    """Check knowledge records for source provenance.

    Returns {outcome, total, sourced, unsourced, unsourced_records,
    recommendation}.  outcome is "pass" / "warn" / "fail".
    """
    result = _query_records(pg, app_id, domain=domain, limit=limit)
    if "error" in result:
        return result

    records = result["records"]
    unmapped = result["unmapped"]
    total = result["total"]

    if "source" in unmapped:
        return {
            "outcome": "warn",
            "total": total,
            "sourced": 0,
            "unsourced": total,
            "unsourced_records": [],
            "recommendation": ("The 'source' column is not mapped in this "
                               "schema — source verification is unavailable."),
            "_unmapped": unmapped,
        }

    sourced_count = 0
    unsourced_recs = []
    for rec in records:
        if (rec.get("source") or "").strip():
            sourced_count += 1
        else:
            unsourced_recs.append(rec)
    unsourced_count = len(unsourced_recs)

    if total == 0:
        outcome = "pass"
        recommendation = "No knowledge records found."
    elif unsourced_count == 0:
        outcome = "pass"
        recommendation = f"All {total} records have source attribution."
    elif unsourced_count / total < 0.2:
        outcome = "warn"
        recommendation = (f"{unsourced_count}/{total} records lack source "
                          "attribution.")
    else:
        outcome = "fail"
        recommendation = (f"{unsourced_count}/{total} records lack source "
                          "attribution — coverage is below 80%.")

    return {
        "outcome": outcome,
        "total": total,
        "sourced": sourced_count,
        "unsourced": unsourced_count,
        "unsourced_records": [
            {"id": r.get("id"),
             "content": (r.get("content") or "")[:120],
             "domain": r.get("domain")}
            for r in unsourced_recs[:20]
        ],
        "recommendation": recommendation,
    }


def check_health(pg, app_id: str, *, domain: Optional[str] = None,
                 limit: int = 200) -> dict:
    """Broader health check on knowledge records (mem_check analog).

    Returns {flags, recommendation, evidence}.
    """
    result = _query_records(pg, app_id, domain=domain, limit=limit)
    if "error" in result:
        return result

    records = result["records"]
    unmapped = result["unmapped"]
    total = result["total"]

    flags = []
    unsourced = 0
    domainless = 0
    content_hashes: dict[str, str] = {}
    duplicates = []

    source_mapped = "source" not in unmapped
    domain_mapped = "domain" not in unmapped

    for rec in records:
        if source_mapped and not (rec.get("source") or "").strip():
            unsourced += 1
        if domain_mapped and not (rec.get("domain") or "").strip():
            domainless += 1

        content_key = (rec.get("content") or "").strip()[:200].lower()
        if content_key in content_hashes:
            duplicates.append({
                "id": rec.get("id"),
                "duplicate_of": content_hashes[content_key],
                "content": content_key[:80],
            })
        else:
            content_hashes[content_key] = rec.get("id")

    if unsourced > 0:
        flags.append({"flag": "unsourced_records", "count": unsourced,
                       "detail": f"{unsourced}/{total} records have no source"})
    if domainless > 0:
        flags.append({"flag": "domainless_records", "count": domainless,
                       "detail": f"{domainless}/{total} records have no domain"})
    if duplicates:
        flags.append({"flag": "duplicate_content", "count": len(duplicates),
                       "detail": f"{len(duplicates)} records share content"})

    if not flags:
        recommendation = "Knowledge base is healthy — no issues found."
    elif len(flags) == 1:
        recommendation = flags[0]["detail"] + "."
    else:
        recommendation = (f"{len(flags)} issues found: "
                          + "; ".join(f["flag"] for f in flags) + ".")

    result_dict: dict = {
        "flags": flags,
        "recommendation": recommendation,
        "evidence": {
            "total": total,
            "unsourced_count": unsourced,
            "domainless_count": domainless,
            "duplicate_groups": duplicates[:10],
        },
    }
    if unmapped:
        result_dict["_unmapped"] = unmapped
    return result_dict


# ── Persistence layer (GAP #3) ──────────────────────────────────────────────
#
# Everything above this line is the original, read-only surface: pure
# functions that compute a verdict and return it. Nothing above ever touches
# a store. What follows is additive — a thin wrapper that calls those pure
# functions and then records the outcome, so real verify/health runs leave a
# durable, timestamped trail instead of evaporating once the caller reads the
# response.

CHECK_KINDS = ("verify_sources", "check_health")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def record_verification(store, *, record_id: str, outcome: str, check_kind: str,
                        evidence: Optional[dict] = None, ts: Optional[str] = None
                        ) -> str:
    """Persist one timestamped verification outcome to the durable log.

    Keyed by `record_id + ts` (plus a short random suffix to rule out a
    same-instant collision) rather than by `record_id` alone: the whole point
    of this log is a history, not a snapshot. `store.put` upserts by id, so a
    key that dropped the timestamp would make a second verification of the
    same target silently replace the first instead of accumulating a trail
    a human (or a later curator) can read the arc of over time.

    Returns the stored row's `record_id`.
    """
    if not record_id or not isinstance(record_id, str):
        raise ValueError("record_id must be a non-empty str")
    if outcome not in ("pass", "warn", "fail"):
        raise ValueError(f"outcome must be one of pass/warn/fail, got {outcome!r}")
    if not check_kind or not isinstance(check_kind, str):
        raise ValueError("check_kind must be a non-empty str")

    ts = ts or _now_iso()
    row = {
        "record_id": record_id,
        "outcome": outcome,
        "check_kind": check_kind,
        "evidence": evidence if evidence is not None else {},
        "ts": ts,
    }
    log_id = f"{record_id}::{ts}::{uuid.uuid4().hex[:8]}"
    store.put(VERIFICATION_LOG_COLLECTION, row, record_id=log_id)
    return log_id


def iter_verification_log(store, record_id: Optional[str] = None) -> list[dict]:
    """Read back the verification trail, optionally filtered by `record_id`.

    Mirrors the populated/empty/unreachable contract the other SOIL readers
    follow: an empty or unreachable collection reads back as an empty list,
    never an exception. Rows come back in `store.all()`'s created_at order
    (oldest first) — the natural order for reading a history.
    """
    rows = store.all(VERIFICATION_LOG_COLLECTION)
    if record_id is not None:
        rows = [r for r in rows if r.get("record_id") == record_id]
    return rows


def _health_outcome(health_result: dict) -> str:
    """Map check_health's {flags, ...} shape onto pass/warn/fail.

    check_health has no outcome field of its own (it predates this
    persistence layer and its own docstring commits it to staying read-only
    and shape-stable); this derives one only for the log/training-example
    side, using the same "how many distinct things are wrong" signal
    verify_sources already uses via its 20% threshold.
    """
    flags = health_result.get("flags") or []
    if not flags:
        return "pass"
    if len(flags) >= 2:
        return "fail"
    return "warn"


def verify_and_record(pg, store, app_id: str, *, check_kind: str = "verify_sources",
                      domain: Optional[str] = None, limit: int = 200,
                      record_id: Optional[str] = None) -> dict:
    """Run a read-only verification, then persist the outcome — best effort.

    Calls `verify_sources` or `check_health` (chosen by `check_kind`), then
    records the result to the durable `verification_log` and appends a
    matching `training_corpus` example (source=kb_verify,
    label_kind=verification) — the reward signal a later curation stage
    consumes.

    Persistence is best-effort relative to the verdict: a store write
    failure is logged (not swallowed silently) but never raised, so a broken
    log or corpus store cannot turn a successful verification into a failed
    MCP tool call. The verdict dict returned is always exactly what the
    underlying read-only function computed, plus `_verification_logged`
    (bool) noting whether persistence succeeded.
    """
    if check_kind not in CHECK_KINDS:
        raise ValueError(f"check_kind must be one of {CHECK_KINDS}, got {check_kind!r}")

    if check_kind == "verify_sources":
        verdict = verify_sources(pg, app_id, domain=domain, limit=limit)
    else:
        verdict = check_health(pg, app_id, domain=domain, limit=limit)

    result = dict(verdict)
    result["_verification_logged"] = False

    if "error" in verdict:
        # The read-only check itself couldn't run (e.g. unusable schema) —
        # nothing was verified, so there is no outcome worth logging.
        return result

    outcome = verdict.get("outcome") if check_kind == "verify_sources" else _health_outcome(verdict)
    rid = record_id or f"{app_id}:{domain or '_all'}"
    ts = _now_iso()

    try:
        record_verification(store, record_id=rid, outcome=outcome,
                            check_kind=check_kind, evidence=verdict, ts=ts)
        result["_verification_logged"] = True
    except Exception:
        logger.exception("verify_and_record: failed to persist verification_log "
                         "row for record_id=%r check_kind=%r", rid, check_kind)

    try:
        example = TrainingExample(
            source=SOURCE_KB_VERIFY,
            input={"record_id": rid, "check_kind": check_kind,
                  "domain": domain, "app_id": app_id},
            large_label={"outcome": outcome},
            label_kind="verification",
            provenance={"ts": ts, "check_kind": check_kind},
        )
        append_training_example(store, example)
    except Exception:
        logger.exception("verify_and_record: failed to append training_corpus "
                         "example for record_id=%r check_kind=%r", rid, check_kind)

    return result
