"""willow_mcp/unit_ops.py — user-bus helper for unit.install enable.

Cursor stdio willow-mcp often has no ``DBUS_SESSION_BUS_ADDRESS``. Writing the
unit file under ``unit_install_execute`` succeeds; ``systemctl --user enable
--now`` fails. Kart must never gain the bus (SOIL
``kart-vs-operator-systemctl-broker-2026-09-23``).

This module is the broker half of the queue: ``enqueue_enable`` drops a JSON
request under ``$WILLOW_HOME/unit_ops/pending/``. The systemd ``--user`` oneshot
``willow-mcp-unit-ops`` (inherits the session bus) drains with ``tick``:
``daemon-reload`` + ``enable --now`` for the named unit, then cites the
``unit.install`` envelope (meters ``max_count``) and inks a FRANK
``unit_install`` receipt. Broker-own units are refused (same EPERM as reload).
"""
from __future__ import annotations

import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from . import paths
from .unit_reload_executor import (
    _SYSTEMCTL_TIMEOUT_S,
    _run,
    is_broker_unit,
    show_unit,
)

EVENT = "unit_install"
VERB = "unit.install"


def unit_ops_dir() -> Path:
    d = paths.willow_home() / "unit_ops"
    d.mkdir(parents=True, exist_ok=True)
    return d


def pending_dir() -> Path:
    d = unit_ops_dir() / "pending"
    d.mkdir(parents=True, exist_ok=True)
    return d


def done_dir() -> Path:
    d = unit_ops_dir() / "done"
    d.mkdir(parents=True, exist_ok=True)
    return d


def failed_dir() -> Path:
    d = unit_ops_dir() / "failed"
    d.mkdir(parents=True, exist_ok=True)
    return d


def enqueue_enable(
    *,
    app_id: str,
    unit: str,
    enable_target: str,
    source: str,
    envelope_id: str,
    project: str,
    session: str = "",
    head: str = "",
    written: list[str] | None = None,
    judged_units: list[str] | None = None,
) -> str:
    """Write one pending enable request. Returns the pending id."""
    pending_id = str(uuid.uuid4())
    payload = {
        "id": pending_id,
        "action": "enable",
        "app_id": app_id,
        "unit": unit,
        "enable_target": enable_target or unit,
        "source": source,
        "envelope_id": envelope_id,
        "project": project or "willow",
        "session": session,
        "head": head,
        "written": list(written or []),
        "judged_units": list(judged_units or [unit]),
        "queued_at": datetime.now(timezone.utc).isoformat(),
    }
    path = pending_dir() / f"{pending_id}.json"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return pending_id


def status(pending_id: str) -> dict:
    """Three-state lookup for a pending enable id."""
    pid = (pending_id or "").strip()
    if not pid:
        return {"error": "EINVAL", "reason": "pending_id required"}
    for state, directory in (
        ("pending", pending_dir()),
        ("done", done_dir()),
        ("failed", failed_dir()),
    ):
        path = directory / f"{pid}.json"
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                return {"error": "EIO", "reason": str(exc), "state": state}
            return {"ok": True, "state": state, "pending_id": pid, **data}
    return {"ok": False, "state": "missing", "pending_id": pid, "error": "not_found"}


def _move(src: Path, dest_dir: Path) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / src.name
    os.replace(src, dest)
    return dest


def process_one(
    path: Path,
    *,
    ledger=None,
    runner: Optional[Callable] = None,
) -> dict:
    """Enable one pending request. Cites the envelope only on success."""
    from .envelopes import EnvelopeAuthority

    try:
        req = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": "EIO", "reason": str(exc), "path": str(path)}

    pending_id = req.get("id") or path.stem
    unit = (req.get("unit") or "").strip()
    enable_target = (req.get("enable_target") or unit).strip()
    envelope_id = (req.get("envelope_id") or "").strip()
    app_id = (req.get("app_id") or "").strip()
    project = (req.get("project") or "willow").strip()
    source = (req.get("source") or "").strip()
    judged = list(req.get("judged_units") or ([unit] if unit else []))

    if not unit or not envelope_id or not app_id:
        detail = {**req, "failed_at": datetime.now(timezone.utc).isoformat(),
                  "error": "EINVAL",
                  "reason": "pending request missing unit/envelope_id/app_id"}
        fail_path = _move(path, failed_dir())
        fail_path.write_text(json.dumps(detail, indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")
        return {"ok": False, "error": "EINVAL", "pending_id": pending_id,
                "reason": detail["reason"]}

    if is_broker_unit(unit) or is_broker_unit(enable_target):
        detail = {**req, "failed_at": datetime.now(timezone.utc).isoformat(),
                  "error": "EPERM",
                  "reason": "broker own unit is never a unit-ops enable target"}
        fail_path = _move(path, failed_dir())
        fail_path.write_text(json.dumps(detail, indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")
        return {"ok": False, "error": "EPERM", "pending_id": pending_id,
                "reason": detail["reason"]}

    call_args = {"units": judged, "sources": [source] if source else []}
    if ledger is None:
        detail = {**req, "failed_at": datetime.now(timezone.utc).isoformat(),
                  "error": "EAMBIG", "reason": "no governance ledger"}
        fail_path = _move(path, failed_dir())
        fail_path.write_text(json.dumps(detail, indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")
        return {"ok": False, "error": "EAMBIG", "pending_id": pending_id,
                "reason": detail["reason"]}

    auth = EnvelopeAuthority(ledger)
    checked = auth.check(
        envelope_id, actor=app_id, verb=VERB, call_args=call_args,
    )
    if not checked.get("ok"):
        detail = {**req, "failed_at": datetime.now(timezone.utc).isoformat(),
                  "error": checked.get("errno", "EAMBIG"),
                  "reason": checked.get("reason", "")}
        fail_path = _move(path, failed_dir())
        fail_path.write_text(json.dumps(detail, indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")
        return {"ok": False, "error": checked.get("errno", "EAMBIG"),
                "pending_id": pending_id, "reason": checked.get("reason", "")}

    for argv in (
        ["systemctl", "--user", "daemon-reload"],
        ["systemctl", "--user", "enable", "--now", enable_target],
    ):
        try:
            proc = _run(argv, runner=runner, timeout=_SYSTEMCTL_TIMEOUT_S)
        except FileNotFoundError:
            _move(path, failed_dir())
            return {"ok": False, "error": "EUNREACH", "pending_id": pending_id,
                    "reason": "systemctl_missing"}
        except subprocess.TimeoutExpired:
            _move(path, failed_dir())
            return {"ok": False, "error": "ETIMEDOUT", "pending_id": pending_id,
                    "reason": f"{' '.join(argv[2:])} timed out"}
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout or "").strip()[-300:]
            detail = {**req, "failed_at": datetime.now(timezone.utc).isoformat(),
                      "error": "EINSTALL",
                      "reason": tail or f"{' '.join(argv[2:])} exited {proc.returncode}"}
            fail_path = _move(path, failed_dir())
            fail_path.write_text(json.dumps(detail, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
            return {"ok": False, "error": "EINSTALL", "pending_id": pending_id,
                    "reason": detail["reason"]}

    cited = auth.authorize_and_cite(
        envelope_id, actor=app_id, verb=VERB, call_args=call_args,
        project=project, session=req.get("session") or "",
    )
    if not cited.get("ok"):
        # Enabled but could not cite — leave a failed marker with detail.
        fail_path = _move(path, failed_dir())
        detail = {**req, "enabled_without_cite": True,
                  "cite_error": cited.get("errno"), "cite_reason": cited.get("reason")}
        fail_path.write_text(json.dumps(detail, indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")
        return {"ok": False, "error": cited.get("errno", "EAMBIG"),
                "pending_id": pending_id, "reason": cited.get("reason", ""),
                "enabled_without_cite": True}

    state_after = show_unit(unit, runner=runner)
    receipt_id = None
    try:
        receipt_id = ledger.append(project, EVENT, {
            "actor": "willow-mcp-unit-ops",
            "via": app_id,
            "unit": unit,
            "source": source,
            "enabled": enable_target,
            "pending_id": pending_id,
            "head": req.get("head") or "",
            "written": req.get("written") or [],
            "judged_units": judged,
            "active_state_after": state_after.get("ActiveState"),
            "session": req.get("session") or "",
            "citation_id": cited.get("citation_id"),
            "envelope_id": envelope_id,
        })
    except Exception as exc:  # noqa: BLE001
        receipt_id = f"receipt_error:{type(exc).__name__}:{exc}"

    done = {**req, "completed_at": datetime.now(timezone.utc).isoformat(),
            "citation_id": cited.get("citation_id"), "receipt_id": receipt_id,
            "state_after": {k: state_after.get(k) for k in
                            ("ActiveState", "ActiveEnterTimestamp", "MainPID")
                            if state_after.get(k) is not None}}
    done_path = _move(path, done_dir())
    done_path.write_text(json.dumps(done, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "ok": True,
        "installed": True,
        "pending_id": pending_id,
        "unit": unit,
        "enabled": enable_target,
        "envelope_id": envelope_id,
        "citation_id": cited.get("citation_id"),
        "receipt_id": receipt_id,
        "state_after": state_after,
    }


def tick(*, ledger=None, runner: Optional[Callable] = None, limit: int = 8) -> dict:
    """Drain up to ``limit`` pending enable requests (oldest first)."""
    pending = sorted(pending_dir().glob("*.json"), key=lambda p: p.stat().st_mtime)
    results = []
    for path in pending[: max(1, limit)]:
        results.append(process_one(path, ledger=ledger, runner=runner))
    return {
        "ok": True,
        "processed": len(results),
        "remaining": max(0, len(pending) - len(results)),
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    """CLI: ``python -m willow_mcp.unit_ops tick``."""
    import sys

    from .db import get_pg
    from .governance_ledger import GovernanceLedger

    args = list(argv if argv is not None else sys.argv[1:])
    if not args or args[0] in ("-h", "--help"):
        print("usage: python -m willow_mcp.unit_ops tick", file=sys.stderr)
        return 2
    if args[0] != "tick":
        print(f"unknown command: {args[0]!r}", file=sys.stderr)
        return 2
    pg = get_pg()
    if not pg:
        print("unit_ops: postgres unavailable", file=sys.stderr)
        return 1
    ledger = GovernanceLedger(pg)
    out = tick(ledger=ledger)
    print(json.dumps(out, indent=2, default=str))
    ok = out.get("ok") and all(r.get("ok") for r in out.get("results") or [True])
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
