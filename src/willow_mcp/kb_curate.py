"""Gated in-place KB curation via tags — flag and retract without hard deletes."""

from __future__ import annotations

import json
from typing import Any, Optional

from . import onescript_clock

FLAGGED_MARKER = "kb:flagged"
RETRACT_TAG = "kb:retracted"
FLAG_PREFIX = "kb:flag-json:"
RETRACT_PREFIX = "kb:retract-json:"
_VALID_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})


def _utc_now() -> str:
    """In the one script's ``seconds_z`` format, from its one clock (flatten-2 F8:
    "Using the onescript at every path."). ``$ONESCRIPT_NOW`` pins it. With no one
    script reachable this falls back to the carried ``clock_local`` and says so (``onescript_clock.SOURCE``)."""
    return onescript_clock.clock().seconds_z()


def normalize_tags(raw: Any) -> list:
    if raw is None:
        return []
    if isinstance(raw, list):
        return list(raw)
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []
        return list(parsed) if isinstance(parsed, list) else []
    return []


def _encode_json_tag(prefix: str, payload: dict, *, max_len: int = 120) -> str:
    blob = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    tag = prefix + blob
    if len(tag) <= max_len:
        return tag
    trimmed = dict(payload)
    reason = str(trimmed.get("reason") or "")
    if reason:
        trimmed["reason"] = reason[: max(0, max_len - len(prefix) - 40)] + "…"
    tag = prefix + json.dumps(trimmed, separators=(",", ":"), ensure_ascii=True)
    return tag[:max_len]


def parse_curate_tags(tags: Any) -> tuple[Optional[dict], bool, Optional[dict]]:
    """Return (flag_meta, retracted, retract_meta) from a tags value."""
    flag_meta: Optional[dict] = None
    retract_meta: Optional[dict] = None
    retracted = False
    for item in normalize_tags(tags):
        if not isinstance(item, str):
            continue
        if item == RETRACT_TAG:
            retracted = True
        elif item.startswith(RETRACT_PREFIX):
            try:
                retract_meta = json.loads(item[len(RETRACT_PREFIX) :])
            except json.JSONDecodeError:
                retract_meta = {"reason": item[len(RETRACT_PREFIX) :]}
            retracted = True
        elif item.startswith(FLAG_PREFIX):
            try:
                flag_meta = json.loads(item[len(FLAG_PREFIX) :])
            except json.JSONDecodeError:
                flag_meta = {"reason": item[len(FLAG_PREFIX) :], "severity": "medium"}
    return flag_meta, retracted, retract_meta


def merge_flag_tags(
    existing: Any,
    *,
    app_id: str,
    reason: str,
    severity: str,
    refs: Optional[list] = None,
) -> list:
    sev = (severity or "medium").strip().lower()
    if sev not in _VALID_SEVERITIES:
        sev = "medium"
    meta = {
        "severity": sev,
        "reason": (reason or "").strip() or "(no reason given)",
        "refs": list(refs or []),
        "at": _utc_now(),
        "by": app_id,
    }
    kept = [
        t
        for t in normalize_tags(existing)
        if isinstance(t, str)
        and not t.startswith(FLAG_PREFIX)
        and t != FLAGGED_MARKER
    ]
    kept.append(FLAGGED_MARKER)
    kept.append(_encode_json_tag(FLAG_PREFIX, meta))
    return kept


def merge_retract_tags(existing: Any, *, app_id: str, reason: str) -> list:
    meta = {
        "reason": (reason or "").strip() or "(no reason given)",
        "at": _utc_now(),
        "by": app_id,
    }
    kept = [
        t
        for t in normalize_tags(existing)
        if isinstance(t, str) and not t.startswith(RETRACT_PREFIX)
    ]
    if RETRACT_TAG not in kept:
        kept.append(RETRACT_TAG)
    kept.append(_encode_json_tag(RETRACT_PREFIX, meta))
    return kept


def enrich_atom(record: dict) -> dict:
    flag_meta, retracted, retract_meta = parse_curate_tags(record.get("tags"))
    if flag_meta:
        record["kb_flag"] = flag_meta
    if retracted:
        record["retracted"] = True
        if retract_meta:
            record["kb_retract"] = retract_meta
    return record


def sql_exclude_retracted(tags_col: Optional[str], cols_by_name: dict) -> tuple[str, list]:
    """Append AND … to hide retracted atoms when tags are mapped."""
    if not tags_col:
        return "", []
    col_info = cols_by_name.get(tags_col)
    dtype = col_info.data_type if col_info else None
    if dtype == "ARRAY":
        return f' AND NOT (%s = ANY("{tags_col}"))', [RETRACT_TAG]
    if dtype in ("jsonb", "json"):
        return f' AND NOT ("{tags_col}" @> %s::jsonb)', [json.dumps([RETRACT_TAG])]
    return f' AND NOT ("{tags_col}"::text LIKE %s)', [f'%"{RETRACT_TAG}"%']
