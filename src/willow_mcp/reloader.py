"""willow_mcp/reloader.py — the hand that restarts the broker onto a pull it
already brought home; the broker itself never touches the switch.

Decision ``e961aff8`` (operator, 2026-09-18; Nestor pair
``e961aff8-f722-4781-b924-55c0a489a085``, gap ``2451a10a19a3``):
:func:`unit_reload_executor.execute_unit_reload` refuses the broker's own
unit by design (``EPERM`` — a broker that can restart itself is a
self-grant). So the restart lives in a *separate* systemd ``--user`` unit,
``willow-mcp-reloader``, that owns exactly one act — ``systemctl --user
restart <broker unit>`` — and fires only when BOTH:

1. a FRANK ``git_pull`` receipt exists for the broker's own checkout (the
   request — written by :mod:`pull_executor` when the desk or the steward's
   sweep pulled a merge home), AND
2. a sealed Nestor decision names that receipt by its FRANK row id (the
   confirm — the operator's seal, made from a phone if need be).

Request and confirm sit on different principals and the reloader is a
third; that is the shape of brokered push (ruling 2026-09-10) pointed at
the broker's own process. The alternative — ``Restart=`` plus a graceful
self-exit after the pull — was considered and refused in the same seal:
the broker would then decide when it reloads itself.

The preflight is the executor's own, run here by a different principal:
the unit's ``ActiveEnterTimestamp`` must predate the receipt (``EALREADY``
otherwise — the unit is already on code no older than what was pulled,
which is also what makes a polling reloader idempotent: one restart, then
quiet), and the checkout's HEAD must still equal the receipt's ``after``
sha (``EDRIFT`` otherwise — the tree moved again since the pull, and the
seal named *that* receipt, not whatever is there now).

What the reloader does NOT do: propose the decision. The seal is the
operator's; the draft the operator seals is the desk's (``decision_propose``
naming the receipt id). A reloader that wrote its own confirm would be the
self-grant again, one process removed. When the receipt is there and the
seal is not, the reloader says so (``ENOSEAL``) and waits.

Three states, never collapsed (INVARIANTS §1): the Nestor database
unreadable is ``unreachable``, no sealed pair naming the receipt is
``empty``, a match is ``populated``. Only the act leaves FRANK ink — a
``unit_reload`` receipt with ``actor=willow-mcp-reloader`` citing the pull
receipt, the sealing pair and its verifier; refusals go to the journal.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from . import paths
from . import unit_reload_executor as urx

logger = logging.getLogger(__name__)

#: The principal on the FRANK receipt. Not an MCP app_id — no manifest, no
#: tool surface — but a name the ledger can tell apart from the broker
#: (``willow``) that wrote the pull receipt and the operator who sealed it.
ACTOR = "willow-mcp-reloader"

#: The broker unit this fleet actually runs (`scripts/willow-serve install`
#: writes it); the bare ``willow-mcp.service`` is the other spelling
#: :data:`unit_reload_executor._BROKER_UNIT_SUFFIXES` refuses.
DEFAULT_UNIT = "willow-mcp-serve.service"
DEFAULT_REPO = "willow-memory/willow-mcp"
#: Polling cadence for the timer; a pull receipt is minutes old before
#: anyone can have sealed a decision naming it.
DEFAULT_INTERVAL = "60s"

UNIT_PREFIX = "willow-mcp-reloader"
SERVICE_UNIT = f"{UNIT_PREFIX}.service"
TIMER_UNIT = f"{UNIT_PREFIX}.timer"

_ENV_UNIT = "WILLOW_RELOADER_UNIT"
_ENV_CHECKOUT = "WILLOW_RELOADER_CHECKOUT"
_ENV_REPO = "WILLOW_RELOADER_REPO"

_SYSTEMCTL_TIMEOUT_S = 15

#: Verb 17 (`unit.install`, sealed 197aafa5): installing a unit is a broker
#: act under an envelope, not a keyboard act. The CLI keeps the keyboard
#: path for a box with no broker, behind `--keyboard`, so typing it is a
#: stated choice and not the default a runbook copies.
KEYBOARD_REFUSAL = (
    "install: use unit_install_execute (verb 17, unit.install) — the broker "
    "writes, enables and starts the unit from the tracked template under an "
    "envelope with a FRANK receipt. On a box with no broker, pass --keyboard."
)


# ── configuration ─────────────────────────────────────────────────────────────

def default_checkout() -> Optional[Path]:
    """The broker's own checkout: ``WILLOW_RELOADER_CHECKOUT`` if set, else
    the source tree this module was imported from when that tree is a git
    checkout (the editable install the served broker runs on). ``None`` when
    neither holds — a wheel install has no tree to pull."""
    override = os.environ.get(_ENV_CHECKOUT, "").strip()
    if override:
        return Path(override).expanduser()
    tree = Path(__file__).resolve().parents[2]
    if (tree / ".git").exists():
        return tree
    return None


@dataclass(frozen=True)
class ReloaderConfig:
    unit: str
    checkout: Optional[Path]
    repo: str
    nestor_db: Path


def default_config() -> ReloaderConfig:
    from .seal_handler import _nestor_db_path

    return ReloaderConfig(
        unit=os.environ.get(_ENV_UNIT, DEFAULT_UNIT).strip() or DEFAULT_UNIT,
        checkout=default_checkout(),
        repo=os.environ.get(_ENV_REPO, DEFAULT_REPO).strip() or DEFAULT_REPO,
        nestor_db=_nestor_db_path(),
    )


# ── the confirm: a sealed decision naming the receipt ─────────────────────────

def find_sealing_decision(receipt_id: str, db_path: Path) -> dict:
    """Look in Nestor's own database for a sealed ``decision`` pair whose
    text names ``receipt_id``.

    Returns ``{"state": "populated", "pair_id", "verifier", "sealed_at"}``,
    ``{"state": "empty"}`` when no sealed pair names it, or
    ``{"state": "unreachable", "cause": ...}`` when the database cannot be
    read — three states, because "no seal" and "cannot see the seals" call
    for different next moves (wait vs. fix the path) and a reloader that
    reported both as "no" would restart nothing forever, silently.

    A seal is a row with ``status = 'sealed'``, a non-empty ``seal_sig``, and
    no ``superseded_by`` — the same three facts ``nestor serve`` requires
    before it will serve a pair as verified. The ledger record alone is not
    consulted: it carries the pair id and verifier but not the text, and the
    text is where the receipt id lives.
    """
    rid = (receipt_id or "").strip()
    if not rid:
        return {"state": "empty"}
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        return {"state": "unreachable", "cause": f"{type(exc).__name__}: {exc}", "path": str(db_path)}
    try:
        rows = conn.execute(
            "SELECT id, verifier, created_at FROM tm_pairs "
            "WHERE source_lang = 'decision' AND status = 'sealed' "
            "AND seal_sig != '' AND superseded_by = '' "
            "AND (instr(source_text, ?) > 0 OR instr(target_text, ?) > 0) "
            "ORDER BY created_at DESC",
            (rid, rid),
        ).fetchall()
    except sqlite3.Error as exc:
        return {"state": "unreachable", "cause": f"{type(exc).__name__}: {exc}", "path": str(db_path)}
    finally:
        conn.close()
    if not rows:
        return {"state": "empty"}
    pair_id, verifier, created_at = rows[0]
    return {"state": "populated", "pair_id": pair_id, "verifier": verifier,
            "sealed_at": created_at, "count": len(rows)}


# ── the check ─────────────────────────────────────────────────────────────────

def _refuse(errno: str, reason: str, **extra) -> dict:
    return {"ok": False, "act": False, "error": errno, "reason": reason, **extra}


def check(config: ReloaderConfig, *, ledger, runner: Optional[Callable] = None) -> dict:
    """Decide whether the restart is due. Never restarts anything.

    Returns ``{"ok": True, "act": True, ...}`` with the receipt, HEAD, seal
    and unit state when every condition holds; otherwise ``ok=False`` with
    the executor's errnos (``EINVAL``, ``EUNREACH``, ``ENORECEIPT``,
    ``EALREADY``, ``EDRIFT``) plus the reloader's own ``ENOSEAL`` (receipt
    present, no sealed decision names it — the waiting state) and
    ``ESEALS`` (the seal store cannot be read).
    """
    unit = (config.unit or "").strip()
    if not urx.is_broker_unit(unit):
        # Inverse of the executor's EPERM: this unit exists ONLY for the
        # broker. Anything else is verb 15's job, under an envelope.
        return _refuse("EINVAL", f"{unit!r} is not the broker's unit — reload it "
                                 f"through unit_reload_execute under a unit.reload envelope")
    if config.checkout is None:
        return _refuse("EINVAL", f"no broker checkout: set {_ENV_CHECKOUT} or run from an editable install")
    path = Path(config.checkout).expanduser()
    if not (path / ".git").exists():
        return _refuse("EINVAL", f"{path} is not a git checkout (no .git)")
    if ledger is None:
        return _refuse("EAMBIG", "no governance ledger: a restart that cannot be matched to a pull receipt is not performed")

    receipt = ledger.latest_event(urx.PULL_EVENT, match={"repo": config.repo, "checkout": str(path)})
    if receipt is None:
        return _refuse("ENORECEIPT", f"no git_pull receipt for repo={config.repo!r} checkout={str(path)!r}")
    receipt_id = receipt.get("id")
    if not receipt_id:
        return _refuse("EAMBIG", "the pull receipt carries no row id; a seal cannot name it")
    content = receipt["content"]

    state = urx.show_unit(unit, runner=runner)
    if not state.get("ok"):
        return _refuse("EUNREACH", f"unit state unreachable: {state.get('cause')}",
                       cause=state.get("cause"), detail=state.get("detail"), receipt_id=receipt_id)

    active_enter = urx._parse_systemd_timestamp(state.get("ActiveEnterTimestamp"))
    receipt_at = urx._as_utc(receipt.get("created_at"))
    if active_enter is not None and receipt_at is not None and active_enter >= receipt_at:
        return _refuse("EALREADY",
                       f"{unit} has been active since {state.get('ActiveEnterTimestamp')!r}, "
                       f"which is no older than pull receipt {receipt_id} — already on that code",
                       receipt_id=receipt_id, receipt=content)

    head = urx._git(path, "rev-parse", "HEAD", runner=runner)
    if head.returncode != 0:
        return _refuse("EINVAL", f"could not read HEAD of {path}", receipt_id=receipt_id)
    current_head = (head.stdout or "").strip()
    after = content.get("after")
    if after and current_head != after:
        return _refuse("EDRIFT",
                       f"{path} HEAD is {current_head!r} but receipt {receipt_id}'s after-sha is "
                       f"{after!r} — the tree moved again since the pull; the seal names the receipt, not the tree",
                       receipt_id=receipt_id, receipt=content, head=current_head)

    seal = find_sealing_decision(receipt_id, config.nestor_db)
    if seal["state"] == "unreachable":
        return _refuse("ESEALS", f"seal store unreachable: {seal.get('cause')}",
                       receipt_id=receipt_id, path=seal.get("path"))
    if seal["state"] == "empty":
        return _refuse("ENOSEAL",
                       f"pull receipt {receipt_id} ({(content.get('before') or '')[:7]} -> {(after or '?')[:7]}) "
                       f"is waiting for a sealed decision that names it — the desk proposes, the operator seals",
                       receipt_id=receipt_id, receipt=content, head=current_head)

    return {"ok": True, "act": True, "unit": unit, "repo": config.repo, "checkout": str(path),
            "receipt_id": receipt_id, "receipt": content, "head": current_head,
            "seal": seal, "state_before": state}


# ── the act ───────────────────────────────────────────────────────────────────

def run_once(config: ReloaderConfig, *, ledger, runner: Optional[Callable] = None,
             project: str = "willow-mcp") -> dict:
    """One tick: check, and when due, ``systemctl --user restart`` the
    broker unit and write the FRANK ``unit_reload`` receipt. A refusal is
    returned as-is (``reloaded=False``); it is not ink."""
    verdict = check(config, ledger=ledger, runner=runner)
    if not verdict.get("act"):
        verdict["reloaded"] = False
        return verdict

    unit = verdict["unit"]
    try:
        restarted = urx._run(["systemctl", "--user", "restart", unit], runner=runner,
                             timeout=_SYSTEMCTL_TIMEOUT_S)
    except FileNotFoundError:
        return {**verdict, "ok": False, "reloaded": False, "error": "EUNREACH", "reason": "systemctl_missing"}
    except subprocess.TimeoutExpired:
        return {**verdict, "ok": False, "reloaded": False, "error": "ETIMEDOUT",
                "reason": f"systemctl restart exceeded {_SYSTEMCTL_TIMEOUT_S}s"}
    if restarted.returncode != 0:
        tail = (restarted.stderr or restarted.stdout or "").strip()[-300:]
        return {**verdict, "ok": False, "reloaded": False, "error": "ERESTART",
                "reason": tail or f"systemctl restart exited {restarted.returncode}"}

    out = {**verdict, "reloaded": True, "state_after": urx.show_unit(unit, runner=runner)}
    try:
        out["reload_receipt_id"] = ledger.append(project, urx.EVENT, {
            "actor": ACTOR, "unit": unit, "repo": config.repo, "checkout": str(verdict["checkout"]),
            "head": verdict["head"], "pull_receipt_id": verdict["receipt_id"],
            "nestor_pair_id": verdict["seal"]["pair_id"], "nestor_verifier": verdict["seal"]["verifier"],
            "decision": "e961aff8",
        })
    except Exception as exc:  # noqa: BLE001 — the restart happened; the receipt failing is reported, not hidden
        out["receipt_error"] = f"{type(exc).__name__}: {exc}"
    return out


# ── the units ─────────────────────────────────────────────────────────────────
# Same doctrine as repo_sweep_service: install/uninstall manage unit files and
# daemon-reload only. They never start, stop, enable or disable a live unit —
# whether the reloader runs is the operator's decision, not the installer's.

def _template(name: str) -> Path:
    return Path(__file__).resolve().parent / "bundle" / "deploy" / name


def unit_dir() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base.expanduser() / "systemd" / "user"


def _safe(value: object, field: str) -> str:
    text = str(value)
    if not text or any(char in text for char in ("\n", "\r", '"')):
        raise ValueError(f"{field} contains characters unsafe for a systemd unit")
    return text


def render_units(config: ReloaderConfig, *, python: Optional[Path] = None,
                 interval: str = DEFAULT_INTERVAL) -> dict[str, str]:
    """The .service and .timer bodies, rendered together so the timer's
    ``Unit=`` can never drift from the service it schedules."""
    if config.checkout is None:
        raise ValueError(f"no broker checkout to render: set {_ENV_CHECKOUT}")
    values = {
        "PYTHON": python or Path(sys.executable),
        "WILLOW_HOME": paths.willow_home(),
        "WILLOW_STORE_ROOT": paths.store_root(),
        "PG_DB": paths.pg_db(),
        "NESTOR_DB": config.nestor_db,
        "UNIT": config.unit,
        "CHECKOUT": config.checkout,
        "REPO": config.repo,
        "INTERVAL": interval,
        "SERVICE_UNIT": SERVICE_UNIT,
    }
    out: dict[str, str] = {}
    for unit, tmpl in ((SERVICE_UNIT, f"{UNIT_PREFIX}.service.template"),
                       (TIMER_UNIT, f"{UNIT_PREFIX}.timer.template")):
        rendered = _template(tmpl).read_text(encoding="utf-8")
        for key, value in values.items():
            safe = str(value) if key == "PYTHON" else _safe(value, key)
            rendered = rendered.replace(f"@{key}@", safe)
        if "@" in rendered:
            raise ValueError(f"{unit} template contains unresolved placeholders")
        out[unit] = rendered
    return out


def _systemctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["systemctl", "--user", *args], check=False,
                          capture_output=True, text=True, timeout=15)


def install_services(config: ReloaderConfig, *, destination: Optional[Path] = None,
                     reload: bool = True, interval: str = DEFAULT_INTERVAL) -> dict:
    root = Path(destination) if destination is not None else unit_dir()
    root.mkdir(parents=True, exist_ok=True)
    written = []
    for unit, body in render_units(config, interval=interval).items():
        path = root / unit
        path.write_text(body, encoding="utf-8")
        written.append(str(path))
    if reload:
        result = _systemctl("daemon-reload")
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout or "systemctl daemon-reload failed").strip())
    # started/enabled are always empty and that is the contract, not an omission.
    return {"installed": written, "started": [], "enabled": []}


def service_status(*, destination: Optional[Path] = None,
                   runner: Callable[..., subprocess.CompletedProcess] = _systemctl) -> dict:
    root = Path(destination) if destination is not None else unit_dir()
    units = []
    for name in (SERVICE_UNIT, TIMER_UNIT):
        path = root / name
        active = False
        if path.is_file():
            result = runner("is-active", name)
            active = result.returncode == 0 and result.stdout.strip() == "active"
        units.append({"unit": name, "path": str(path), "installed": path.is_file(), "active": active})
    return {"services": units}


def uninstall_services(*, destination: Optional[Path] = None, reload: bool = True,
                       runner: Callable[..., subprocess.CompletedProcess] = _systemctl) -> dict:
    root = Path(destination) if destination is not None else unit_dir()
    status = service_status(destination=root, runner=runner)
    active = [u["unit"] for u in status["services"] if u["active"]]
    if active:
        raise RuntimeError("refusing to uninstall an active reloader unit; stop it explicitly first: "
                           + ", ".join(active))
    removed = []
    for u in status["services"]:
        path = Path(u["path"])
        if path.is_file():
            path.unlink()
            removed.append(str(path))
    if reload:
        result = runner("daemon-reload")
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout or "systemctl daemon-reload failed").strip())
    return {"removed": removed}


# ── entrypoint ────────────────────────────────────────────────────────────────

def _live_ledger():
    from .db import get_pg
    from .governance_ledger import GovernanceLedger

    pg = get_pg()
    return GovernanceLedger(pg) if pg else None


def main(argv: Optional[list] = None) -> int:
    """``python -m willow_mcp.reloader {tick,check,install,status,uninstall}``.

    ``tick`` is what the timer runs: one check, one restart at most, exit 0
    whether or not the restart was due (a waiting reloader is not a failed
    one). ``check`` is the same without the act. Exit 1 only when the act
    was due and failed — that is the row the journal should go red on.
    """
    parser = argparse.ArgumentParser(
        prog="willow-mcp-reloader",
        description="Restart the broker onto a sealed pull receipt (decision e961aff8).")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("tick", "check"):
        p = sub.add_parser(name)
        p.add_argument("--unit", default=None)
        p.add_argument("--checkout", default=None)
        p.add_argument("--repo", default=None)
    inst = sub.add_parser("install", help="write the .service and .timer (never enables or starts them) — "
                                          "the keyboard path; the broker path is unit_install_execute")
    inst.add_argument("--interval", default=DEFAULT_INTERVAL, help="OnUnitActiveSec= for the timer")
    inst.add_argument("--no-reload", action="store_true")
    inst.add_argument("--keyboard", action="store_true",
                      help="I am at a keyboard on a box with no broker; write the units by hand")
    sub.add_parser("status")
    un = sub.add_parser("uninstall")
    un.add_argument("--no-reload", action="store_true")
    args = parser.parse_args(argv)

    config = default_config()
    if args.command in ("tick", "check"):
        if args.unit or args.checkout or args.repo:
            config = ReloaderConfig(
                unit=args.unit or config.unit,
                checkout=Path(args.checkout).expanduser() if args.checkout else config.checkout,
                repo=args.repo or config.repo,
                nestor_db=config.nestor_db,
            )
        ledger = _live_ledger()
        if args.command == "check":
            out = check(config, ledger=ledger)
        else:
            out = run_once(config, ledger=ledger)
        print(json.dumps(out, default=str, indent=2))
        # Due-and-failed is the only exit that should wake anyone.
        return 1 if (out.get("act") and not out.get("reloaded")) else 0
    if args.command == "install":
        if not args.keyboard:
            print(KEYBOARD_REFUSAL, file=sys.stderr)
            return 2
        print(json.dumps(install_services(config, reload=not args.no_reload, interval=args.interval), indent=2))
        return 0
    if args.command == "status":
        print(json.dumps(service_status(), indent=2))
        return 0
    print(json.dumps(uninstall_services(reload=not args.no_reload), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
