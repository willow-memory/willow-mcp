"""Handoff write/read/verify for dispatch closeout."""

from __future__ import annotations

import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import handoff_validation as hv
from .dispatch import dispatch_read, dispatch_set_status, packet_lock, packet_symlink_refused
from .paths import dispatch_dir


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _write_json(path: Path, data: dict) -> None:
    """Atomic write (bite 1, dispatch 9BA76253, LOW-5): temp file + os.replace
    so a reader never observes a partially-written handoff.json."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _write_text_atomic(path: Path, text: str) -> None:
    """Same atomicity as `_write_json`, for closeout.md's plain-text body."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


# Shared reason strings (Loki EB30E84F F5): _has_completion_evidence and
# _judge_lint_claims were already the SAME functions handoff_write_v4's
# write-time pre-flight and verify_handoff's post-hoc check both call --
# but the MESSAGE text describing why each refused was two independently
# typed literals, exactly the drifted-copy risk repair 1 (this validator
# module) exists to end. One constant / one formatter, used by both.
_NO_COMPLETION_EVIDENCE_REASON = (
    "checklist_resolved claims completion but no evidence backs it: "
    "narrative carries no counted test/check result (e.g. '42 "
    "passed', '0 violations') and no finding carries an `evidence` "
    "field — a bare assertion is not evidence"
)


def _lint_refusal_reason(lint_refusals: list) -> str:
    return (
        f"{len(lint_refusals)} lint claim(s) not measured against the CI pin: "
        + "; ".join(f"finding {v['finding_index']}: {v['reason']}" for v in lint_refusals)
    )


#: Bite 1 of next-bites-2026-09-28 (dispatch 2E590F1B, plan 6AE6ACE1): a
#: handoff only ever lands on a packet the specialist actually holds
#: (`working`), and a packet that already closed one handoff refuses a
#: second -- these are the states past which a write is refused rather
#: than silently overwriting whatever verdict already landed there (the
#: ratatosk-Gemini-vs-Loki race, gaps f9dff345ece7/71ce64eae9fd/
#: 0147276f1097). `withdrawn` stays a separate, pre-existing refusal
#: (invalid_transition, above) -- terminal for a different reason (the
#: orchestrator retired the packet) with its own error shape callers
#: already depend on. `cleared` is deliberately NOT closed here:
#: dispatch_accept accepts a `cleared` packet again (pending/cleared ->
#: working) for a recurring dispatch, so a handoff attempt against a
#: `cleared` packet just hasn't been accepted yet (ESTATE), not "already
#: closed" (ECLOSED).
_CLOSED_STATUSES: frozenset = frozenset({"complete", "verified", "failed"})


def _refused_sidecar_dir(dispatch_id: str) -> Path:
    return dispatch_dir(dispatch_id) / "refused"


def _sidecar_count(dispatch_id: str) -> int:
    """How many refused-handoff sidecars sit next to this packet -- the
    signal `verify_handoff` surfaces so the desk can see a race happened,
    without reading or judging their content itself. Never raises: a
    dispatch_id `dispatch_dir` itself refuses (malformed, e.g. from a test
    fixture that never went through dispatch_send) reads as "no sidecars
    to report" rather than blowing up a verify call that has nothing to do
    with the sidecar feature."""
    try:
        d = _refused_sidecar_dir(dispatch_id)
        if not d.is_dir():
            return 0
        return sum(1 for p in d.iterdir() if p.is_file() and not p.name.startswith("."))
    except (OSError, ValueError):
        return 0


def _history_count(dispatch_id: str) -> int:
    """How many archived cycles (F3, dispatch 1AD03A64) sit under this
    packet's history/ -- one subdirectory per re-accept-and-archive. Same
    never-raises discipline as _sidecar_count."""
    try:
        d = dispatch_dir(dispatch_id) / "history"
        if not d.is_dir():
            return 0
        return sum(1 for p in d.iterdir() if p.is_dir())
    except (OSError, ValueError):
        return 0


def _write_refused_sidecar(dispatch_id: str, writer_app: str, payload: dict,
                           reason: str, *, session_id: str = "") -> str:
    """Write one refused-handoff sidecar next to the packet, atomically and
    without ever colliding with another sidecar -- two writers racing a
    closed (or not-yet-accepted) packet must both land, not clobber each
    other, and the original handoff.json this function never touches stays
    byte-for-byte as it was. Filename carries a UTC timestamp, the writer's
    app_id, and a random token -- the token is what actually keeps two
    refusals in the same wall-clock second from colliding, the timestamp
    alone would not. Writes to a per-call temp file in the same directory
    and `os.replace`s it into place -- atomic on POSIX, so a reader
    (`_sidecar_count`) never sees a partial file mid-write.

    Bite 1 LOW-4 (dispatch 9BA76253): a write failure here (disk full,
    read-only mount) is caught and reported as an empty string rather than
    propagating an OSError -- the refusal itself (ECLOSED/ESTATE/ESESSION)
    must stand even when its sidecar could not be written; the caller
    folds this into ``sidecar_error`` on the returned refusal."""
    sidecar_dir = _refused_sidecar_dir(dispatch_id)
    ts = _utc_now()
    token = uuid.uuid4().hex[:8]
    safe_app = re.sub(r"[^A-Za-z0-9_.-]", "_", writer_app or "unknown")
    fname = f"{ts.replace(':', '')}-{safe_app}-{token}.json"
    body = {
        "writer_app": writer_app,
        "session_id": session_id or "",
        "dispatch_id": dispatch_id,
        "reason": reason,
        "written_at": ts,
        "payload": payload,
    }
    try:
        sidecar_dir.mkdir(parents=True, exist_ok=True)
        tmp = sidecar_dir / f".{fname}.{os.getpid()}.{token}.tmp"
        tmp.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
        target = sidecar_dir / fname
        os.replace(tmp, target)
    except OSError:
        return ""
    return str(target)


_receipt_log_lock = threading.Lock()
_receipt_log_singleton = None


def _handoff_receipt_log():
    """Lazy, module-private `ReceiptLog` -- constructed on first real use,
    never at import time (the same `_LazySingleton` discipline server.py
    documents at gap 035d287206e1: a receipt log construction is a real
    side effect, `mkdir` + `sqlite3.connect`, that must not run for every
    process that merely imports this module, including one running under a
    uid that cannot write $WILLOW_HOME at all)."""
    global _receipt_log_singleton
    if _receipt_log_singleton is None:
        with _receipt_log_lock:
            if _receipt_log_singleton is None:
                from .receipts import ReceiptLog
                _receipt_log_singleton = ReceiptLog()
    return _receipt_log_singleton


def _record_handoff_refusal_receipt(app_id: str, dispatch_id: str, errno: str,
                                     reason: str) -> None:
    """A refusal is `receipts_tail`-visible (bite 1's own requirement) --
    but strictly secondary to the refusal itself: a receipt log that can't
    be opened (read-only $WILLOW_HOME, disk full) must never turn an honest
    refusal into an unhandled exception."""
    try:
        _handoff_receipt_log().record(
            app_id, "handoff_write_v4", f"refused_{errno.lower()}",
            f"dispatch_id={dispatch_id} reason={reason}",
        )
    except Exception:  # noqa: BLE001 -- the refusal already happened; logging it failing is not itself a failure
        pass


def _create_handoff_exclusive(path: Path, data: dict) -> bool:
    """Atomically create `path` (handoff.json) exactly once. `O_EXCL` means a
    second creator gets FileExistsError rather than silently overwriting the
    first writer's verdict. Bite 1 HIGH-1 (dispatch 9BA76253): callers here
    already hold the cross-process `packet_lock`, which is what actually
    keeps two writers from racing in the first place -- this is the LAST
    LINE of defence if that lock is ever bypassed, held at the wrong
    granularity, or simply not taken by some caller this module doesn't know
    about. Returns False (never raises) on losing the create race; the
    caller turns that into ECLOSED plus a sidecar, same as the state-check
    path above it."""
    # F6 (dispatch 1AD03A64): write to a temp file in the same directory
    # FIRST, then `os.link` it into place -- `os.link` fails with
    # FileExistsError exactly like O_EXCL did (same last-line exclusivity),
    # but no reader can ever observe a zero-length or partially-written
    # handoff.json, because the temp file is fully written and closed
    # before the link that makes it visible under its real name.
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2) + "\n"
    tmp = path.parent / f".{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
    tmp.write_text(payload, encoding="utf-8")
    try:
        os.link(tmp, path)
        return True
    except FileExistsError:
        return False
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def _eclosed_refusal(dispatch_id: str, app_id: str, session_id: str,
                      findings_list: list, narrative: str,
                      checklist_resolved: bool, envelope_clean: bool,
                      no_findings_reason, reason: str, cur: str = "complete") -> dict:
    """Shared ECLOSED refusal shape: write the sidecar (LOW-4: a failed
    sidecar write is caught, folded into `sidecar_error`, and the receipt is
    still written), record the receipt, return the refusal dict. `cur` is
    the packet's actual on-disk status (complete/verified/failed) -- NOT
    hardcoded, so a caller can tell which closed state it lost to."""
    payload = {
        "app_id": app_id, "dispatch_id": dispatch_id,
        "findings": findings_list, "narrative": narrative,
        "checklist_resolved": checklist_resolved,
        "envelope_clean": envelope_clean,
        "no_findings_reason": no_findings_reason,
    }
    sidecar_path = _write_refused_sidecar(
        dispatch_id, app_id, payload, reason, session_id=session_id,
    )
    _record_handoff_refusal_receipt(app_id, dispatch_id, "ECLOSED", reason)
    out = {
        "error": "ECLOSED", "message": reason, "status": cur,
        "dispatch_id": dispatch_id, "sidecar": sidecar_path,
    }
    if not sidecar_path:
        out["sidecar_error"] = "sidecar write failed; refusal stands, no sidecar on disk"
    return out


def handoff_write_v4(
    app_id: str,
    dispatch_id: str,
    *,
    findings: Optional[list[dict]] = None,
    narrative: str = "",
    checklist_resolved: bool = True,
    envelope_clean: bool = True,
    no_findings_reason: Optional[str] = None,
    session_id: str = "",
    **_unknown_fields,
) -> dict:
    # gap 21f80b2b348a / 34c8e60f4260 / sealed cdcd948c stage 2: refuse a
    # misspelled or unmigrated field by NAME, never drop it silently.
    # `**_unknown_fields` catches anything a direct/test caller passes beyond
    # the declared parameters -- see handoff_validation's module docstring
    # for the documented limit of this catch on the MCP tool boundary
    # itself, where the SDK's own arg-validation layer can drop an unknown
    # top-level JSON key before it ever reaches this function.
    # Structural checks first (B-16 pattern: gate before sanitize) -- a call
    # against the wrong packet or a withdrawn one is refused on ITS terms,
    # not preempted by a content-shape refusal the caller may never see.
    pkt = dispatch_read(dispatch_id)
    if pkt.get("error"):
        return pkt
    if pkt["meta"].get("to_app", "").lower() != app_id.lower():
        return {"error": "wrong_recipient", "expected": pkt["meta"].get("to_app")}

    findings_list = list(findings or [])

    # Bite 1 (dispatch 9BA76253, rework of 2E590F1B/262F89A1): everything
    # from here on decides who, if anyone, gets to write handoff.json --
    # that decision is made under the cross-process packet_lock, re-reading
    # status AFTER acquiring it (Loki F1: a read taken before the lock can
    # be stale by the time this caller wins it).
    with packet_lock(dispatch_dir(dispatch_id)):
        pkt = dispatch_read(dispatch_id)
        if pkt.get("error"):
            return pkt
        cur = pkt.get("status", {}).get("status", "pending")

        if cur == "withdrawn":
            # Terminal (gap afa515539c0a): the orchestrator retired this
            # packet; a closeout against it would resurrect work nobody
            # asked for.
            return {"error": "invalid_transition", "from": cur, "to": "complete",
                    "dispatch_id": dispatch_id}

        # ECLOSED is checked before ESTATE (gap 70069fbb7f1b): a closed
        # packet is never merely "not yet working", it already has a
        # verdict on it.
        if cur in _CLOSED_STATUSES:
            reason = (
                f"packet {dispatch_id!r} is already {cur!r} -- a handoff was "
                f"already written and this packet is closed; the original "
                f"handoff stays unchanged, this write is kept in a sidecar"
            )
            return _eclosed_refusal(
                dispatch_id, app_id, session_id, findings_list, narrative,
                checklist_resolved, envelope_clean, no_findings_reason, reason,
                cur=cur,
            )

        if cur != "working":
            reason = (
                f"packet {dispatch_id!r} is {cur!r}, not 'working' -- the "
                f"accepting seat must call dispatch_accept before writing a "
                f"handoff"
            )
            # ESTATE writes no sidecar (Q1/F8): the packet was never
            # accepted, so there is no verdict to protect and no accepting
            # session this payload could belong to.
            _record_handoff_refusal_receipt(app_id, dispatch_id, "ESTATE", reason)
            return {"error": "ESTATE", "message": reason, "status": cur,
                    "dispatch_id": dispatch_id}

        # HIGH-2 (Loki F2): the packet is 'working' -- but only the SESSION
        # that actually accepted it may write the handoff. accepted_session_id
        # is recorded solely by dispatch_accept (see its docstring); an
        # empty/absent value means either a legacy packet accepted before
        # this field existed, or one accepted with no session_id supplied at
        # all -- nothing recorded to check a caller against, so that shape
        # keeps the pre-existing permissive behavior rather than refusing a
        # caller for a gap in packets written before this bite.
        accepted_session_id = str(pkt.get("status", {}).get("accepted_session_id") or "")
        if accepted_session_id and accepted_session_id != session_id:
            reason = (
                f"packet {dispatch_id!r} was accepted by a different "
                f"session -- this write's session_id does not match the "
                f"session that called dispatch_accept. Remedy: pass the "
                f"session_id you gave session_enter (or dispatch_accept's "
                f"own return) as handoff_write_v4's session_id argument"
            )
            payload = {
                "app_id": app_id, "dispatch_id": dispatch_id,
                "findings": findings_list, "narrative": narrative,
                "checklist_resolved": checklist_resolved,
                "envelope_clean": envelope_clean,
                "no_findings_reason": no_findings_reason,
            }
            sidecar_path = _write_refused_sidecar(
                dispatch_id, app_id, payload, reason, session_id=session_id,
            )
            _record_handoff_refusal_receipt(app_id, dispatch_id, "ESESSION", reason)
            out = {
                "error": "ESESSION", "message": reason, "status": cur,
                "dispatch_id": dispatch_id, "sidecar": sidecar_path,
            }
            if not sidecar_path:
                out["sidecar_error"] = "sidecar write failed; refusal stands, no sidecar on disk"
            return out

        # Content-shape checks (B-16 pattern: gate before sanitize) run AFTER
        # every structural/state refusal above -- a call against a withdrawn,
        # closed, not-yet-accepted, or wrong-session packet is refused on
        # ITS terms, not preempted by a content-shape refusal about a
        # payload nobody with standing on this packet asked to see judged.
        refusal = hv.write_refusal(
            extra_kwargs=_unknown_fields,
            findings=findings_list,
            checklist_resolved=checklist_resolved,
            no_findings_reason=no_findings_reason,
        )
        if refusal:
            return refusal

        # Rework of Loki's F3 (23CAD2B4; gap 34c8e60f4260): verify_handoff
        # refused a checklist_resolved=True claim backed by nothing
        # checkable, but the writer wrote it anyway and left the specialist
        # to discover the refusal later. These are the EXACT SAME checks
        # verify_handoff runs below (_has_completion_evidence,
        # _judge_lint_claims) -- not a second, drifted copy -- called here,
        # before the write, with the same reason strings, so a doomed
        # handoff is refused at write time instead of round-tripping through
        # complete -> verify_handoff -> false.
        if checklist_resolved:
            draft = {"narrative": narrative, "findings": findings_list}
            if not _has_completion_evidence(draft):
                return {
                    "error": "EINVAL",
                    "message": _NO_COMPLETION_EVIDENCE_REASON,
                }
            lint_verdicts = _judge_lint_claims(
                draft, findings_list, pkt.get("meta"),
            )
            lint_refusals = [v for v in lint_verdicts if v["verdict"] == "refuse"]
            if lint_refusals:
                return {
                    "error": "EINVAL",
                    "message": _lint_refusal_reason(lint_refusals),
                    "lint_claims": lint_verdicts,
                }

        root = dispatch_dir(dispatch_id)
        handoff = {
            # BC504427: format handoff_v1 is intentional — tool name reflects call-signature gen.
            "format": "handoff_v1",
            "dispatch_id": dispatch_id,
            "app_id": app_id,
            "reply_to": pkt["meta"].get("reply_to", "willow"),
            "role": pkt["meta"].get("role"),
            "findings": findings_list,
            "narrative": narrative,
            "checklist_resolved": checklist_resolved,
            "envelope_clean": envelope_clean,
            "written_at": _utc_now(),
        }
        if no_findings_reason:
            handoff["no_findings_reason"] = no_findings_reason

        created = _create_handoff_exclusive(root / "handoff.json", handoff)
        if not created:
            # F3 (dispatch 1AD03A64, Loki 10A39E21 F3): this is NOT
            # unreachable -- a stale handoff.json left by a cleared cycle
            # that was re-accepted without going through dispatch_accept's
            # archive step (a legacy packet accepted before F3 shipped, or
            # the archive step itself failing) lands here while the
            # packet's real status is 'working', not 'complete'. `cur`
            # (read under this same lock, above) names what actually
            # holds, so the refusal is labelled with the packet's real
            # state instead of a hardcoded 'complete' -- also still the
            # backstop the mutation matrix exercises directly against
            # O_EXCL/os.link with the lock bypassed.
            reason = (
                f"packet {dispatch_id!r} already has a handoff.json -- lost "
                f"the exclusive-create race"
            )
            return _eclosed_refusal(
                dispatch_id, app_id, session_id, findings_list, narrative,
                checklist_resolved, envelope_clean, no_findings_reason, reason,
                cur=cur,
            )

        closeout = _render_closeout(dispatch_id, app_id, handoff, pkt)
        _write_text_atomic(root / "closeout.md", closeout)

        dispatch_set_status(
            dispatch_id,
            "complete",
            handoff_path=f"dispatch/{dispatch_id}/handoff.json",
            already_locked=True,
        )
        return {
            "dispatch_id": dispatch_id,
            "status": "complete",
            "reply_to": handoff["reply_to"],
            "waiting_for": "verify_handoff",
        }


def _render_closeout(dispatch_id: str, app_id: str, handoff: dict, pkt: dict) -> str:
    written = handoff.get("written_at") or ""
    date = written[:10] if len(written) >= 10 else ""
    reply_to = handoff.get("reply_to", "willow")
    fm_lines = [
        "kind: closeout",
        f"dispatch_id: {json.dumps(dispatch_id)}",
        f"from: {json.dumps(app_id)}",
        f"to: {json.dumps(reply_to)}",
    ]
    if date:
        fm_lines.append(f"date: {json.dumps(date)}")
    role = handoff.get("role") or pkt.get("meta", {}).get("role")
    if role:
        fm_lines.append(f"role: {json.dumps(role)}")

    lines = [
        "---",
        *fm_lines,
        "---",
        "",
        "@markdownai v1.0",
        "",
        f"# Closeout {dispatch_id}",
        "",
        f"**From:** {app_id}",
        f"**To:** {reply_to}",
        f"**Date:** {written}",
        "",
        "## What Was Done",
        "",
        handoff.get("narrative") or "(no narrative)",
        "",
        "## Findings",
        "",
    ]
    findings = handoff.get("findings") or []
    if not findings:
        reason = handoff.get("no_findings_reason")
        lines.append(f"- (none — {reason})" if reason else "- (none)")
    else:
        lines.append("| ID | Finding | Severity | Evidence |")
        lines.append("|----|---------|----------|----------|")
        for f in findings:
            if not isinstance(f, dict):
                lines.append(f"|  | {f} |  |  |")
                continue
            lines.append(
                f"| {f.get('id', '')} | {_finding_text(f)} | {f.get('severity', '')} "
                f"| {', '.join(_finding_evidence(f))} |"
            )
    lines.extend([
        "",
        "## Checklist",
        "",
        f"- [{'x' if handoff.get('checklist_resolved') else ' '}] All assignment checklist items addressed",
        "",
    ])
    summary = pkt.get("meta", {}).get("summary", "")
    if summary:
        lines.extend(["## Assignment summary", "", summary, ""])
    return "\n".join(lines)


def handoff_read(dispatch_id: str) -> dict:
    root = dispatch_dir(dispatch_id)
    # B-52/#241: handoff.json/closeout.md are read here directly (not via
    # dispatch_read), so they need their own symlink refusal -- otherwise a
    # symlinked handoff.json/closeout.md could disclose an arbitrary file's
    # content to the orchestrator/reply_to reading this closeout.
    if packet_symlink_refused(root):
        return {"error": "symlinked_packet", "dispatch_id": dispatch_id}
    path = root / "handoff.json"
    if not path.exists():
        return {"error": "not_found", "dispatch_id": dispatch_id}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        return {"error": f"read_failed: {e}"}
    closeout_path = root / "closeout.md"
    closeout = closeout_path.read_text(encoding="utf-8") if closeout_path.exists() else ""
    return {"dispatch_id": dispatch_id, "handoff": data, "closeout_md": closeout}


#: The keys a finding may carry its one-line statement under, in the order
#: they are tried. `text` is the documented shape; the others are what
#: specialists have actually written (loki: {n, branch, file, finding};
#: hanuman: title/summary). Gaps cd337282ba63 and 5805dba0ad47: a finding
#: with any of these is a finding — refusing it for its key name stranded a
#: finished packet (3308526F, eight substantive findings, verified:false, no
#: reason) and rendered a blank closeout table.
#
# These three now delegate to handoff_validation (gap 21f80b2b348a /
# 34c8e60f4260) — the ONE validator module verify_handoff below and
# handoff_write_v4 above both run, so a shape the writer would refuse is
# exactly the shape the verifier refuses, not a second drifted copy of it.
_FINDING_TEXT_KEYS: tuple[str, ...] = hv.FINDING_TEXT_KEYS


def _finding_text(f: dict) -> str:
    """The finding's statement under whichever accepted key it used, or ''."""
    return hv.finding_text(f)


def _finding_evidence(f: dict) -> list[str]:
    """Evidence as a list of strings. A bare string is one item — joining it
    with ', ' used to split it into characters in the closeout table.

    A whitespace-only value is empty in either shape: the list branch
    already filtered `["   "]` out via its `str(x).strip()` check; the
    string branch used to only reject the exact empty string, so
    `evidence="   "` passed while `evidence=["   "]` did not. Both now use
    the same strip-and-check test for "is there anything here" — content is
    still returned unstripped, only the emptiness test changed."""
    return hv.finding_evidence(f)


def _invalid_findings(findings: list) -> list[dict]:
    """Every finding that carries no statement under any accepted key, with
    its index and the keys it did carry, so verified:false names its cause.
    This is a SHAPE check only (does the finding say anything) -- whether a
    checklist_resolved=True claim is actually BACKED by evidence is a
    separate, whole-handoff question `_has_completion_evidence`/
    `_judge_lint_claims` answer below (and that handoff_write_v4 now
    pre-flights identically -- Loki 23CAD2B4 F3)."""
    return hv.invalid_findings(findings)


# Pre-handoff verify (wave-2 hook, dispatch F06C0BD0): a handoff can declare
# checklist_resolved=True — "I'm done, tests pass" — without carrying anything
# that makes the claim checkable. verify_handoff already refuses on
# malformed findings (_invalid_findings above); this closes the sibling gap
# for the completion claim itself. It is the dispatch-handoff analogue of the
# Stop-hook green-claim gate (hooks/stop_lint_gate.py): that hook actually
# re-runs ruff rather than trusting "lint is clean" in a session's own words.
# There is no equivalent generic command to re-run here (every dispatch's
# test suite differs), so the check instead requires the claim to be
# *checkable*: a number tied to a test/check word ("42 passed", "301
# passing", "938 passed, 0 failed", "11/11 pass", "0 violations"), or a
# finding that already carries its own `evidence` (the per-finding field
# _finding_evidence reads). A bare assertion ("tests pass", "all done")
# satisfies neither and is refused by name — this never fabricates the
# missing evidence or auto-passes, it only names what's absent so the
# specialist supplies it.
#
# Wordlist: grepped this repo's own docs/handoffs for how the fleet actually
# phrases a count (docs/BUGS.md "301 passing", docs/design/mcp-sdk-2-
# migration.md "1497 passed, 43 skipped, 8 xfailed", docs/design/guardian-
# consent-seam.md "25 passing"/"19 passing"/"9 passing", tests/
# test_calendar_source_gcal.py "11/11 pass.", docs/repatriation/
# THE_COLLABORATION.md "938 passed, 0 failed.") — present-tense "passing" and
# the bare verb "pass" are as common as "passed" and were missing from the
# first cut, which wrongly refused ordinary phrasing this fleet already
# uses. All three require a digit immediately adjacent (word boundary
# enforced) so a digit-free "tests pass" still does not match.
#
# "pass"/"passing" only appear in the digit-THEN-word alternative below, not
# in the word-THEN-digit one: "42 pass" and "11/11 pass." are real test
# counts, but "pass 3 items to review" / "will pass 5 to Sean" is the verb
# "pass" used transitively — the word-then-digit shape false-accepted those
# as evidence (audit finding, dispatch F06C0BD0 follow-up). "N pass"/"N
# passing" is already fully covered by the first alternative, so dropping
# them from the second loses no real phrasing and closes the false-accept.
#
# Non-test changes (docs-only, config-only — no test count exists to cite):
# the finding-`evidence` field is the documented escape hatch, not a
# separate exemption path. A docs-only claim still names, in a finding's
# `evidence`, what was actually checked (e.g. "diff reviewed: docs/README.md
# +12/-3, no src/ touched") — sniffing "this is docs-only" out of free-text
# narrative would let a specialist claim the exemption in prose with nothing
# behind it, which is exactly the unbacked-claim failure mode this hook
# exists to catch. One structured path (narrative count OR finding
# evidence), not two, keeps the gate from being talked around.
#
# Deliberately does NOT fire when checklist_resolved is False: an honest
# blocker/partial report is a valid handoff, not a claim, and carries no
# obligation to show test evidence for work it says it did not finish.
#
# Shape, not truth: this matches a digit adjacent to a test/check word — it
# cannot tell "42 passed" (a real run) from "added 5 tests" (a plan) or a
# fabricated number. Actually running the claim would need a fixed test
# command, and there isn't one that's valid across every dispatch's repo and
# language (unlike the Stop-hook's ruff, which is one fixed tool this repo
# declares). Left as a documented shape check, matching the rest of
# verify_handoff (which also checks findings are dict-shaped, not that they
# are true) and the "deterministic, no model cost" constraint — tightening
# it into a truth check is future work if a fleet-wide reporting convention
# to hook into ever exists.
_EVIDENCE_RE = re.compile(
    r"\d+\s*(?:/\s*\d+)?\s*(?:passed|passing|pass|failed|failing|errors?|"
    r"tests?|checks?|violations?)\b"
    r"|\b(?:passed|failed|tests?|checks?)\s*[:=]?\s*\d+",
    re.IGNORECASE,
)


def _narrative_has_test_evidence(narrative: str) -> bool:
    """True when the narrative ties a number to a test/check word — "42
    passed", "301 passing", "11/11 pass", "0 violations". A word alone
    ("tests pass", "green", "done") is an assertion, not a count, and does
    not match."""
    return bool(narrative) and bool(_EVIDENCE_RE.search(narrative))


def _findings_carry_evidence(findings: list) -> bool:
    """True when at least one finding supplies its own `evidence` field
    (the same field _finding_evidence renders into the closeout table).
    This is the documented path for a completion claim with no test count
    to cite — a docs-only or config-only change names what it checked here
    instead of the narrative needing a fabricated number."""
    for f in findings:
        if isinstance(f, dict) and _finding_evidence(f):
            return True
    return False


def _has_completion_evidence(handoff: dict) -> bool:
    """The gate for a checklist_resolved=True claim: some checkable backing
    exists somewhere in the handoff, either a counted result in the
    narrative or evidence attached to a finding."""
    narrative = handoff.get("narrative") or ""
    findings = handoff.get("findings") or []
    return _narrative_has_test_evidence(narrative) or _findings_carry_evidence(findings)


def verify_handoff(dispatch_id: str) -> dict:
    pkt = dispatch_read(dispatch_id)
    if pkt.get("error"):
        return pkt
    st = pkt.get("status", {}).get("status")
    if st != "complete":
        return {"error": "not_complete", "status": st}

    hr = handoff_read(dispatch_id)
    if hr.get("error"):
        return hr
    handoff = hr["handoff"]
    checklist = bool(handoff.get("checklist_resolved"))
    envelope = bool(handoff.get("envelope_clean"))
    findings = handoff.get("findings") or []
    invalid = _invalid_findings(findings)

    reasons: list[str] = []
    if not checklist:
        reasons.append("checklist not resolved")
    if not envelope:
        reasons.append("envelope not clean")
    if invalid:
        reasons.append(
            f"{len(invalid)} finding(s) carry no statement under any of "
            f"{'/'.join(_FINDING_TEXT_KEYS)}: indexes "
            f"{', '.join(str(b['index']) for b in invalid)}"
        )
    if checklist and not _has_completion_evidence(handoff):
        reasons.append(_NO_COMPLETION_EVIDENCE_REASON)
    lint_verdicts = _judge_lint_claims(handoff, findings, pkt.get("meta"))
    lint_refusals = [v for v in lint_verdicts if v["verdict"] == "refuse"]
    lint_advisories = [v for v in lint_verdicts if v["verdict"] == "advisory"]
    if checklist and lint_refusals:
        reasons.append(_lint_refusal_reason(lint_refusals))
    verified = not reasons

    if verified:
        dispatch_set_status(dispatch_id, "verified", verified_at=_utc_now())

    out = {
        "dispatch_id": dispatch_id,
        "verified": verified,
        "checklist_resolved": handoff.get("checklist_resolved"),
        "envelope_clean": handoff.get("envelope_clean"),
        "findings_count": len(findings),
        # Bite 1 (dispatch 2E590F1B): a sidecar count the desk can see
        # without opening the refused/ directory itself -- verify_handoff
        # still reads only the ORIGINAL handoff for its verdict; sidecars
        # never change `verified`, they are exposed so a race is visible.
        "sidecar_count": _sidecar_count(dispatch_id),
        "history_count": _history_count(dispatch_id),
        "status": "verified" if verified else "complete",
    }
    if reasons:
        # verified:false always says why. Before this the orchestrator saw
        # two clean booleans, a findings count and a false, and had to open
        # handoff.json by hand to learn which finding the gate objected to.
        out["reason"] = "; ".join(reasons)
        if invalid:
            out["invalid_findings"] = invalid
    if lint_verdicts:
        out["lint_claims"] = lint_verdicts
    if lint_advisories:
        # Unreachable pin: said, never a refusal (three-state, not collapsed).
        out["advisory"] = "; ".join(v["reason"] for v in lint_advisories)
    return out


# Sealed pair 11ccb0f7 part (4): a green claim names its linter. A finding
# whose evidence claims lint/format clean must name the ruff version it was
# measured with, and that version must be the one the repo's CI pins —
# ratatosk #48 (2026-09-21) went red because 0.15.0 was clean where the
# pinned 0.16.7 was not. The repo root, per finding: the finding's own
# `repo_root` / `workspace`, then the dispatch packet's `gaps_project`
# checkout, then a repo named by evidence paths, then an explicit handoff
# `repo_root` — not the handoff's session `workspace` and not the desk's
# WILLOW_PROJECT_ROOT until those are exhausted (gap 0b5a2aa26001). No root
# at all → the pin is `unreachable` and the verdict is advisory — never a
# refusal on a repo the verifier could not read.
_NO_ROOT_PIN = {
    "state": "unreachable",
    "reason": "no repo root: neither the finding nor the handoff names repo_root/workspace and WILLOW_PROJECT_ROOT is unset",
    "version": None,
    "source": None,
}


def _lint_pin_root(
    finding: dict,
    handoff: dict,
    dispatch_meta: dict | None = None,
) -> str:
    from . import ci_lint_pin

    return ci_lint_pin.lint_repo_root(
        finding, handoff, dispatch_meta=dispatch_meta,
    )


def _judge_lint_claims(
    handoff: dict,
    findings: list,
    dispatch_meta: dict | None = None,
) -> list[dict]:
    from . import ci_lint_pin

    pins: dict[str, dict] = {}
    verdicts: list[dict] = []
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        root = _lint_pin_root(f, handoff, dispatch_meta)
        if root not in pins:
            pins[root] = ci_lint_pin.ci_lint_pin(root) if root else dict(_NO_ROOT_PIN)
        for v in ci_lint_pin.judge_findings([f], pins[root]):
            v["finding_index"] = i
            v["repo_root"] = root or None
            verdicts.append(v)
    return verdicts
