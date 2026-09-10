"""Handoff write/read/verify for dispatch closeout."""

from __future__ import annotations

import json
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
    with ', ' used to split it into characters in the closeout table."""
    raw = f.get("evidence")
    if raw is None or raw == "":
        return []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, (list, tuple)):
        return [str(x) for x in raw if str(x).strip()]
    return [str(raw)]


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
