"""Handoff write/read/verify for dispatch closeout."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .dispatch import dispatch_read, dispatch_set_status, packet_symlink_refused
from .paths import dispatch_dir


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def handoff_write_v4(
    app_id: str,
    dispatch_id: str,
    *,
    findings: Optional[list[dict]] = None,
    narrative: str = "",
    checklist_resolved: bool = True,
    envelope_clean: bool = True,
) -> dict:
    pkt = dispatch_read(dispatch_id)
    if pkt.get("error"):
        return pkt
    if pkt["meta"].get("to_app", "").lower() != app_id.lower():
        return {"error": "wrong_recipient", "expected": pkt["meta"].get("to_app")}

    root = dispatch_dir(dispatch_id)
    handoff = {
        # BC504427: format handoff_v1 is intentional — tool name reflects call-signature gen.
        "format": "handoff_v1",
        "dispatch_id": dispatch_id,
        "app_id": app_id,
        "reply_to": pkt["meta"].get("reply_to", "willow"),
        "role": pkt["meta"].get("role"),
        "findings": list(findings or []),
        "narrative": narrative,
        "checklist_resolved": checklist_resolved,
        "envelope_clean": envelope_clean,
        "written_at": _utc_now(),
    }
    _write_json(root / "handoff.json", handoff)

    closeout = _render_closeout(dispatch_id, app_id, handoff, pkt)
    (root / "closeout.md").write_text(closeout, encoding="utf-8")

    dispatch_set_status(
        dispatch_id,
        "complete",
        handoff_path=f"dispatch/{dispatch_id}/handoff.json",
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
        lines.append("- (none)")
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
_FINDING_TEXT_KEYS: tuple[str, ...] = ("text", "title", "finding", "summary")


def _finding_text(f: dict) -> str:
    """The finding's statement under whichever accepted key it used, or ''."""
    for key in _FINDING_TEXT_KEYS:
        val = f.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def _finding_evidence(f: dict) -> list[str]:
    """Evidence as a list of strings. A bare string is one item — joining it
    with ', ' used to split it into characters in the closeout table.

    A whitespace-only value is empty in either shape: the list branch
    already filtered `["   "]` out via its `str(x).strip()` check; the
    string branch used to only reject the exact empty string, so
    `evidence="   "` passed while `evidence=["   "]` did not. Both now use
    the same strip-and-check test for "is there anything here" — content is
    still returned unstripped, only the emptiness test changed."""
    raw = f.get("evidence")
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw] if raw.strip() else []
    if isinstance(raw, (list, tuple)):
        return [str(x) for x in raw if str(x).strip()]
    return [str(raw)] if str(raw).strip() else []


def _invalid_findings(findings: list) -> list[dict]:
    """Every finding that carries no statement under any accepted key, with
    its index and the keys it did carry, so verified:false names its cause."""
    bad: list[dict] = []
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            bad.append({"index": i, "keys": [], "type": type(f).__name__})
        elif not _finding_text(f):
            bad.append({"index": i, "keys": sorted(f.keys())})
    return bad


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
        reasons.append(
            "checklist_resolved claims completion but no evidence backs it: "
            "narrative carries no counted test/check result (e.g. '42 "
            "passed', '0 violations') and no finding carries an `evidence` "
            "field — a bare assertion is not evidence"
        )
    verified = not reasons

    if verified:
        dispatch_set_status(dispatch_id, "verified", verified_at=_utc_now())

    out = {
        "dispatch_id": dispatch_id,
        "verified": verified,
        "checklist_resolved": handoff.get("checklist_resolved"),
        "envelope_clean": handoff.get("envelope_clean"),
        "findings_count": len(findings),
        "status": "verified" if verified else "complete",
    }
    if reasons:
        # verified:false always says why. Before this the orchestrator saw
        # two clean booleans, a findings count and a false, and had to open
        # handoff.json by hand to learn which finding the gate objected to.
        out["reason"] = "; ".join(reasons)
        if invalid:
            out["invalid_findings"] = invalid
    return out
