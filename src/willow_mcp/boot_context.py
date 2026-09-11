"""SessionStart INDEX lines (corrections, stack snapshot, degraded boot)."""

from __future__ import annotations

import logging
from typing import Any

from .boot_health import degraded_boot_line, postgres_status, split_brain_boot_line
from .seed_loader import load_corpus_lanes
from .session_inject import (
    MAX_CORRECTIONS,
    MAX_HUMAN_CONFIRMATIONS,
    MAX_PREFERENCES,
    dedup_fingerprint,
    is_continuation_source,
    minimal_continuation_block,
    record_injection,
    should_skip_duplicate,
    utc_clock_line,
)
from .stack_snapshot import read_stack_snapshot


def _trust_root_fault_lines(app_id: str) -> list[str]:
    """Fail-closed at SessionStart (hook spec #3, gap 37d44bfa1f4c): a broken
    keyring, an unsigned/invalid manifest, or a self-writable grant under strict
    enforcement must block loudly at boot rather than surface as a mid-task
    denial. Reuses the exact probes/severity classification diagnostic_summary
    already computes (`server._diag_trust_root_boot_problems`) — no duplicated
    logic here. A healthy trust root returns [] and this stays silent."""
    if not app_id:
        return []
    try:
        from .server import _diag_trust_root_boot_problems
        problems = _diag_trust_root_boot_problems(app_id)
    except Exception:
        logging.getLogger("willow_mcp.boot_context").debug(
            "trust-root boot probe failed", exc_info=True)
        return []
    if not problems:
        return []
    lines = ["[BOOT FAULT] TRUST ROOT BROKEN — do not proceed until resolved:"]
    for p in problems:
        check = p.get("check", "?")
        detail = p.get("detail") or "broken"
        lines.append(f"  · {check}: {detail}")
        fix = p.get("fix")
        if fix:
            lines.append(f"    FIX: {fix}")
    lines.append("")
    return lines


#: Cap on how many open gaps get surfaced at boot — enough to be useful,
#: small enough that a busy backlog doesn't crowd out the rest of orient.
MAX_BOOT_GAPS = 3


def _blocker_lines(orientation: dict[str, Any]) -> list[str]:
    """Surface what `session_enter` already found this seat blocked on.

    Reuses `orientation["blockers"]` verbatim (computed by `blockers.collect`
    in server.py) rather than re-deriving attestation/lease state here — this
    module must never diverge from what session_enter already decided.

    `orientation["records"]` is also consulted, read-only, for the
    collection-denied signal: that error lives on each standing-record read
    (`_collection_denied` in server.py), not inside `blockers.collect`, so it
    is folded in here rather than invented as a second blocker computation.
    """
    try:
        blockers = orientation.get("blockers") or {}
        items = list(blockers.get("items") or [])

        records = orientation.get("records") or {}
        if isinstance(records, dict):
            for logical, record in records.items():
                if isinstance(record, dict) and "collection_denied" in str(
                    record.get("error") or ""
                ):
                    items.append({
                        "id": "collection_denied",
                        "summary": f"'{logical}' orientation read denied: {record['error']}",
                        "fix": "widen this app's store_scope, or ignore if intentional",
                    })

        items = [item for item in items if isinstance(item, dict)]
        if not items:
            return []

        lines: list[str] = [f"[BLOCKERS] {len(items)} at seat entry:"]
        for item in items:
            summary = str(item.get("summary") or item.get("id") or "?")
            fix = item.get("fix")
            line = f"  · {summary}"
            if fix:
                line += f" — fix: {fix}"
            lines.append(line)
        return lines
    except Exception:
        return []


def _gap_lines(limit: int = MAX_BOOT_GAPS) -> list[str]:
    """Top open gaps by asked_count, via the same backlog gap_list reads.

    Read-only and best-effort: an empty backlog, a denied read, or any other
    failure all degrade to "no gap section" rather than an error or a false
    alarm at boot.
    """
    try:
        from . import gaps as gap_backlog

        result = gap_backlog.list_gaps(status="open", limit=limit)

        items = (result or {}).get("items") or []
        if not items:
            return []

        lines = [f"[GAPS] top {len(items)} open (by asked_count):"]
        for gap in items:
            if not isinstance(gap, dict):
                continue
            topic = gap.get("topic", "?")
            question = str(gap.get("question", ""))[:80]
            asked = gap.get("asked_count", 0)
            lines.append(f"  · [{topic}] {question} (asked {asked}×)")
        if len(lines) == 1:
            # Every row was malformed — degrade to no gap section rather
            # than emitting a header with nothing under it.
            return []
        return lines
    except Exception:
        return []


def build_boot_lines(
    app_id: str,
    session_id: str,
    source: str,
    enter_result: dict[str, Any],
    *,
    lite: bool | None = None,
) -> list[str]:
    lite_inject = is_continuation_source(source) if lite is None else lite
    lines: list[str] = [utc_clock_line(), f"agent={app_id}  postgres={postgres_status()}"]

    orientation = enter_result.get("orientation") or {}
    snap = orientation.get("stack_snapshot") or read_stack_snapshot(app_id)
    handoff = orientation.get("latest_handoff") or {}
    if handoff and not handoff.get("error"):
        path = handoff.get("path") or handoff.get("filename") or ""
        if path:
            lines.append(f"handoff: {path}")

    corpus = load_corpus_lanes()
    if corpus.get("corrections"):
        cap = min(2, MAX_CORRECTIONS) if lite_inject else MAX_CORRECTIONS
        shown = corpus["corrections"][:cap]
        total = int(corpus.get("correction_total") or len(corpus["corrections"]))
        head = f"corrections — operator ({len(shown)}"
        if total > len(shown):
            head += f"/{total}"
        lines.append(head + "):")
        for c in shown:
            lines.append(f"  · {c}")
    if corpus.get("preferences") and not lite_inject:
        shown = corpus["preferences"][:MAX_PREFERENCES]
        if shown:
            lines.append(f"preferences — operator ({len(shown)}):")
            for p in shown:
                lines.append(f"  · {p}")
    if corpus.get("confirmations"):
        cap = 1 if lite_inject else MAX_HUMAN_CONFIRMATIONS
        shown = corpus["confirmations"][:cap]
        if shown:
            lines.append(f"confirmations — operator ({len(shown)}):")
            for c in shown:
                lines.append(f"  · {c}")

    if snap:
        snap_tasks = snap.get("open_tasks", [])
        snap_threads = snap.get("open_threads", [])
        snap_decisions = snap.get("open_decisions", [])
        snap_ts = str(snap.get("written_at", ""))[:16]
        if snap_tasks or snap_threads or snap_decisions:
            lines.append(f"[STACK] as of {snap_ts}:")
            for t in snap_tasks[:5]:
                if isinstance(t, dict):
                    lines.append(f"  task: {t.get('title', t.get('id', '?'))[:80]}")
            for th in snap_threads[:3]:
                lines.append(f"  thread: {str(th)[:80]}")
            for d in snap_decisions[:3]:
                lines.append(f"  decision pending: {str(d)[:80]}")

    degraded = degraded_boot_line(app_id)
    if degraded:
        lines.append(degraded)

    split_brain_line = split_brain_boot_line()
    if split_brain_line:
        lines.append(split_brain_line)

    lines.extend(_blocker_lines(orientation))
    if not lite_inject:
        lines.extend(_gap_lines())

    if lite_inject:
        lines.append("[SESSION] compact/resume — trimmed boot injection.")

    fingerprint = dedup_fingerprint(session_id, lines)
    if should_skip_duplicate(session_id, fingerprint):
        next_bite = ""
        lines = minimal_continuation_block(app_id, postgres_status(), next_bite)
        record_injection(session_id, fingerprint, lite=True)
    else:
        record_injection(session_id, fingerprint, lite=lite_inject)

    # Trust-root fault is never deduped/trimmed away — a broken keyring, an
    # unsigned manifest, or a self-writable grant under strict enforcement must
    # be loud on every single boot line, continuation or not (hook spec #3).
    fault_lines = _trust_root_fault_lines(app_id)
    if fault_lines:
        lines = fault_lines + lines

    return lines
