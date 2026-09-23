"""SessionEnd stage-1 instruments (sealed pair cdcd948c).

Before (or at) closeout, run deterministic, no-token tools over this session's
log and write receipts the handoff / next start can read:

  1. corpus-lens over the session transcript (when available)
  2. willow-reconciler stub over what the session touched (receipt only until
     the session-touched scan lands)

Fail-open: SessionEnd never blocks. A missing binary, bad path, or tool error
becomes a named receipt state, not an exception to the hook.

Receipts land under::

    $WILLOW_HOME/sessions/pre_handoff/<app_id>-<session_id>/
        corpus-lens.json
        reconciler.json
        stage1.json   # rollup

See decision ``session-envelope-start-and-end-2026-09-22``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .paths import sessions_dir

_SAFE = re.compile(r"[^a-zA-Z0-9_\-]")


def pre_handoff_dir(app_id: str, session_id: str) -> Path:
    safe_app = _SAFE.sub("_", (app_id or "unknown")[:64])
    safe_sid = _SAFE.sub("_", (session_id or "unknown")[:64])
    return sessions_dir() / "pre_handoff" / f"{safe_app}-{safe_sid}"


def _write_receipt(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _guess_adapter(transcript_path: str) -> str:
    """Pick a corpus-lens adapter from path shape. Cursor agent transcripts
    live under agent-transcripts/; Claude Code under ~/.claude/projects/."""
    p = (transcript_path or "").replace("\\", "/").lower()
    if "agent-transcripts" in p or "/.cursor/" in p:
        return "cursor"
    if "/.claude/" in p or "claude" in p:
        return "claude-code"
    return "cursor"


def _run_corpus_lens(transcript_path: str, out_dir: Path) -> dict[str, Any]:
    """Run corpuslens over a one-file corpus (symlink in a temp dir).

    corpus-lens dir adapters refuse a bare file; stage the transcript alone
    under a temp directory so the run is scoped to THIS session.
    """
    base: dict[str, Any] = {
        "tool": "corpus-lens",
        "at": _now(),
        "transcript_path": transcript_path or "",
    }
    if not transcript_path:
        base.update({"state": "skipped", "reason": "no_transcript_path"})
        return base
    src = Path(transcript_path)
    if not src.is_file():
        base.update({"state": "skipped", "reason": "transcript_missing", "path": str(src)})
        return base

    corpuslens = shutil.which("corpuslens")
    if not corpuslens:
        # Editable installs often expose the module without a PATH entry.
        python = shutil.which("python3") or shutil.which("python")
        if not python:
            base.update({"state": "skipped", "reason": "corpuslens_not_on_path"})
            return base
        cmd_prefix = [python, "-m", "corpuslens"]
    else:
        cmd_prefix = [corpuslens]

    adapter = _guess_adapter(transcript_path)
    report_path = out_dir / "corpus-lens-report.json"
    try:
        with tempfile.TemporaryDirectory(prefix="willow-pre-handoff-") as tmp:
            link = Path(tmp) / src.name
            try:
                link.symlink_to(src.resolve())
            except OSError:
                link.write_bytes(src.read_bytes())
            argv = [
                *cmd_prefix,
                "run",
                str(Path(tmp)),
                "--adapter",
                adapter,
                "--format",
                "json",
                "--out",
                str(report_path),
            ]
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
                env={**os.environ, "PYTHONUNBUFFERED": "1"},
            )
        base["argv"] = argv[len(cmd_prefix) :]  # drop absolute binary path
        base["returncode"] = proc.returncode
        if proc.returncode != 0:
            base.update(
                {
                    "state": "failed",
                    "reason": "corpuslens_nonzero",
                    "stderr_tail": (proc.stderr or "")[-800:],
                    "stdout_tail": (proc.stdout or "")[-400:],
                }
            )
            return base
        summary: dict[str, Any] = {"state": "ok", "adapter": adapter}
        if report_path.is_file():
            try:
                doc = json.loads(report_path.read_text(encoding="utf-8"))
                # Keep the receipt small — headline rates only, not the full doc.
                if isinstance(doc, dict):
                    summary["report_keys"] = sorted(doc.keys())[:24]
                    audit = doc.get("audit") or doc.get("Audit")
                    if audit is not None:
                        summary["audit"] = audit if isinstance(audit, (str, dict, list)) else str(audit)[:500]
            except Exception as exc:
                summary["report_parse_error"] = str(exc)
            summary["report_path"] = str(report_path)
        else:
            summary["stdout_tail"] = (proc.stdout or "")[-600:]
        base.update(summary)
        return base
    except subprocess.TimeoutExpired:
        base.update({"state": "failed", "reason": "corpuslens_timeout"})
        return base
    except Exception as exc:
        base.update({"state": "failed", "reason": "corpuslens_error", "detail": str(exc)})
        return base


def _run_reconciler_stub(app_id: str, session_id: str) -> dict[str, Any]:
    """Stage-1 stub: receipt that names the sealed contract without scanning.

    Full 'what the session touched' join is a later bite (willow-reconciler
    session scan). Writing the stub means stage-1 always leaves an artifact
    next start can see, instead of silent absence.
    """
    return {
        "tool": "willow-reconciler",
        "at": _now(),
        "state": "stub",
        "reason": "session_touched_scan_not_built",
        "app_id": app_id,
        "session_id": session_id,
        "sealed_pair": "cdcd948c-6dbf-414d-94db-72c2bdf0c493",
        "next": "build reconciler session-touched scan; replace this stub",
    }


def run_pre_handoff_instruments(
    app_id: str,
    session_id: str,
    transcript_path: str = "",
) -> dict[str, Any]:
    """Run stage-1 instruments and write receipts. Never raises."""
    try:
        out_dir = pre_handoff_dir(app_id, session_id)
        out_dir.mkdir(parents=True, exist_ok=True)
        lens = _run_corpus_lens(transcript_path, out_dir)
        _write_receipt(out_dir / "corpus-lens.json", lens)
        recon = _run_reconciler_stub(app_id, session_id)
        _write_receipt(out_dir / "reconciler.json", recon)
        rollup = {
            "stage": 1,
            "at": _now(),
            "app_id": app_id,
            "session_id": session_id,
            "receipt_dir": str(out_dir),
            "corpus_lens": {"state": lens.get("state")},
            "reconciler": {"state": recon.get("state")},
            "sealed_pair": "cdcd948c-6dbf-414d-94db-72c2bdf0c493",
        }
        _write_receipt(out_dir / "stage1.json", rollup)
        return rollup
    except Exception as exc:
        return {
            "stage": 1,
            "state": "failed",
            "reason": "pre_handoff_unavailable",
            "detail": str(exc),
            "at": _now(),
        }
