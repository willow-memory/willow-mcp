"""willow_mcp/unit_reload_executor.py — restart a systemd --user unit onto
code a git_pull receipt already brought home; nobody types.

The fourth verb of the brokered merge loop, after :mod:`push_executor`
(verb 3, ``git.push``) and :mod:`pr_executor` (verb 4, ``pr.open``);
:mod:`pull_executor` (verb-less by design) is the third act. Verb 15,
``unit.reload``, sealed under governance decision ``06075e99`` (operator,
2026-09-16; Nestor pair ``06075e99-c16d-4703-88c5-52b70fae7cf2``) — see
``src/willow_mcp/bundle/constitutional/syscall-table.json`` row 15.

Gap ``c96dc96927e8``: nothing connected "a merge landed" to "the process
serving it restarted." ``pull_executor`` already writes a FRANK
``git_pull`` receipt (repo, checkout, before -> after sha) on every pull
it performs; this module refuses to restart a unit unless that receipt
exists AND is newer than the unit's own ``ActiveEnterTimestamp`` — i.e.
the code moved and the unit has not yet noticed — and refuses again if
the checkout's current HEAD no longer matches the receipt's ``after`` sha
(the tree moved again since the pull, so the receipt is stale).

What it refuses, each with its own errno so a caller never has to guess
which of three very different problems it hit:

* the user bus unreachable, the unit unknown, or ``systemctl`` missing —
  distinct causes under ``EUNREACH`` (the desk's own three-state contract,
  never collapsed to one, INVARIANTS §1);
* no ``git_pull`` FRANK receipt for ``repo``+``checkout`` at all
  (``ENORECEIPT``);
* a unit that has been active since before the pull receipt even exists —
  i.e. it is already running on code no older than what was pulled
  (``EALREADY``);
* a checkout whose HEAD has drifted past the receipt's ``after`` sha
  (``EDRIFT``);
* the broker's own unit, by name, regardless of what the envelope's
  bounds say (``EPERM`` — a broker that can restart itself is a broker an
  agent can use to kill the thing enforcing every other refusal here).

What it does, in order: preflight (above), check-and-cite against the
``unit.reload`` envelope that governs the caller — the same indivisible
``authorize_and_cite`` :func:`push_executor.execute_push` performs —
``systemctl --user restart <unit>``, re-read the unit's state, and a
FRANK ``unit_reload`` receipt. ``bot_status.read_status()`` is inlined
when the unit is a willow-bot unit (the steward already reports its own
running commit); otherwise the checkout's HEAD stands in for it.
"""
from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

VERB = "unit.reload"
EVENT = "unit_reload"
PULL_EVENT = "git_pull"

_SYSTEMCTL_TIMEOUT_S = 10
_GIT_TIMEOUT_S = 30

#: The broker's own unit(s) — never a grantable reload (row 15) or install
#: (row 17) target regardless of what bounds an envelope carries. Matched
#: on the unit STEM, so a per-instance unit (``willow-mcp-serve@1.service``)
#: and a non-service unit of the same name (``willow-mcp-serve.socket``) are
#: both caught — Loki FECF6FED: the old suffix match let both through while
#: its docstring claimed otherwise, and row 17 can *install* such a unit.
_BROKER_UNIT_STEMS = ("willow-mcp", "willow-mcp-serve")
_BROKER_UNIT_SUFFIXES = tuple(f"{s}.service" for s in _BROKER_UNIT_STEMS)  # kept for readers

#: Errnos for which an ask is worth filing: the verb is real and the actor
#: is the right one; what is missing is a grant the operator could issue.
_ASKABLE = frozenset({"ENOENT", "EAMBIG", "EEXPIRED", "EDQUOT", "ENOGRANTS"})

_SHOW_PROPERTIES = (
    "ActiveState", "ActiveEnterTimestamp", "ActiveEnterTimestampMonotonic",
    "MainPID", "ExecMainStartTimestamp",
)

#: `systemctl --user show` timestamp formats it actually prints (locale
#: fixed to C by the unit files this fleet ships). Tried in order.
_SYSTEMD_TS_FORMATS = ("%a %Y-%m-%d %H:%M:%S %Z", "%a %Y-%m-%d %H:%M:%S %z")


def _refuse(errno: str, reason: str, **extra) -> dict:
    return {"ok": False, "error": errno, "reason": reason, "reloaded": False, **extra}


def _run(argv: list[str], *, runner: Optional[Callable] = None,
         timeout: float) -> subprocess.CompletedProcess:
    run = runner or subprocess.run
    # `systemctl show` prints timestamps in the process's local zone and
    # `_parse_systemd_timestamp` reads the result as UTC (strptime's %Z does
    # not carry an offset). On a box west of Greenwich that read the unit
    # as having started hours EARLIER than it did, which is invisible to a
    # one-shot call but makes a polling caller (`reloader`) see "older than
    # the receipt" on every tick after its own restart. Pin the zone so the
    # printed text and the parse agree.
    env = {**os.environ, "TZ": "UTC", "LC_ALL": "C"}
    return run(argv, capture_output=True, text=True, timeout=timeout, check=False, env=env)


def _git(checkout: Path, *args: str, runner: Optional[Callable] = None) -> subprocess.CompletedProcess:
    run = runner or subprocess.run
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    return run(
        ["git", "-C", str(checkout), *args],
        capture_output=True, text=True, timeout=_GIT_TIMEOUT_S, env=env, check=False,
    )


def _parse_show(stdout: str) -> dict:
    out: dict[str, str] = {}
    for line in (stdout or "").splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            out[k] = v
    return out


def is_broker_unit(unit: str) -> bool:
    """True if ``unit`` names the broker's own unit in any systemd spelling —
    ``willow-mcp-serve.service``, a per-instance ``willow-mcp-serve@1.service``,
    or any other unit type on that stem (``.socket``, ``.timer``, ...) — never
    a grantable reload or install target, per rows 15 and 17. Compared on the
    stem (name before ``@`` and before the last ``.``), case-insensitively, so
    a template's ``Alias=``/``Also=`` value is judged the same way as an
    argument."""
    u = (unit or "").strip().lower()
    if not u or "/" in u or "." not in u:
        return False
    stem = u.rsplit(".", 1)[0].split("@", 1)[0]
    return stem in _BROKER_UNIT_STEMS


def is_willow_bot_unit(unit: str) -> bool:
    """Whether the steward's own status report should ride in the receipt
    instead of the checkout's bare HEAD — willow-bot already reports its
    running commit, which is a richer fact than a sha alone."""
    return "willow-bot" in (unit or "")


def _parse_systemd_timestamp(value: str) -> Optional[datetime]:
    v = (value or "").strip()
    if not v or v.lower() in ("n/a", "0"):
        return None
    for fmt in _SYSTEMD_TS_FORMATS:
        try:
            dt = datetime.strptime(v, fmt)
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    return None


def _as_utc(value) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def show_unit(unit: str, *, runner: Optional[Callable] = None) -> dict:
    """Read-only ``systemctl --user show`` for ``unit``. Never raises: every
    way this can fail comes back as ``{"ok": False, "reason": "unreachable",
    "cause": ...}`` with a cause distinct from the others (``no_user_bus``,
    ``unit_unknown``, ``systemctl_missing``, ``timeout``) — the desk's own
    three-state contract, applied to one unit instead of the whole panel."""
    try:
        proc = _run(
            ["systemctl", "--user", "show", unit,
             f"--property={','.join(_SHOW_PROPERTIES)}"],
            runner=runner, timeout=_SYSTEMCTL_TIMEOUT_S,
        )
    except FileNotFoundError:
        return {"ok": False, "reason": "unreachable", "cause": "systemctl_missing"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "reason": "unreachable", "cause": "timeout"}
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        lowered = detail.lower()
        if "failed to connect to bus" in lowered or "failed to get d-bus connection" in lowered:
            return {"ok": False, "reason": "unreachable", "cause": "no_user_bus",
                    "detail": detail[-300:]}
        return {"ok": False, "reason": "unreachable", "cause": "unit_unknown",
                "detail": detail[-300:]}
    props = _parse_show(proc.stdout)
    if not props.get("ActiveState"):
        # `systemctl show` on a unit systemd has never heard of exits 0 with
        # empty properties rather than a nonzero code — naming this
        # `unit_unknown` explicitly rather than reporting it as "reachable
        # but empty".
        return {"ok": False, "reason": "unreachable", "cause": "unit_unknown",
                "detail": f"{unit!r} returned no properties"}
    return {"ok": True, "unit": unit, **props}


def _file_ask(app_id: str, *, unit: str, errno: str, reason: str, fields,
              task_id: str, store=None) -> dict:
    """Same shape as :func:`push_executor._file_ask` — the row lands on the
    ``gates`` surface (``kind=consent`` under ``unit.<unit>``) rather than
    the review queue, so an operator watching ``willow-mcp gates`` sees "an
    agent asked to reload X" the same way they see a push or PR ask."""
    from . import gate_request

    detail = f"{errno}: {reason}"
    if fields:
        detail += f" (fields: {', '.join(str(f) for f in fields)})"
    summary = (
        f"{app_id or 'an agent'} asked to reload unit {unit!r} and was "
        f"refused: {detail}. Ratify a unit.reload envelope with bounds "
        f"(units=[{unit!r}]) and the agent can ask again."
    )
    return gate_request.open_request(
        app_id or "", f"unit.{unit}", task_id=task_id, reason=summary, store=store,
    )


def execute_unit_reload(
    app_id: str,
    *,
    unit: str,
    checkout: str | Path,
    repo: str,
    envelope_id: str = "",
    project: str,
    session: str = "",
    task_id: str = "",
    ledger=None,
    store=None,
    runner: Optional[Callable] = None,
) -> dict:
    """Restart ``unit`` under the ``unit.reload`` envelope that governs
    ``app_id`` — or refuse, cite the refusal, and file the ask.

    ``ledger`` is a :class:`GovernanceLedger`; the MCP tool builds it from
    the live Postgres, tests pass a fake. ``runner`` replaces
    ``subprocess.run`` for both ``systemctl`` and ``git`` calls in tests.
    """
    from .envelopes import EnvelopeAuthority, governing_envelope_ids

    unit = (unit or "").strip()
    repo = (repo or "").strip()
    if not unit or not repo:
        return _refuse("EINVAL", "a reload names a unit and a repo (org/name)")
    if is_broker_unit(unit):
        return _refuse(
            "EPERM",
            f"{unit!r} is the broker's own unit — never a grantable reload "
            f"target, regardless of what an envelope's bounds say",
        )

    path = Path(checkout).expanduser()
    if not (path / ".git").exists():
        return _refuse("EINVAL", f"{path} is not a git checkout (no .git)")

    state = show_unit(unit, runner=runner)
    if not state.get("ok"):
        return _refuse(
            "EUNREACH", f"unit state unreachable: {state.get('cause')}",
            cause=state.get("cause"), detail=state.get("detail"),
        )

    if ledger is None:
        return _refuse(
            "EAMBIG",
            "no governance ledger: a reload that cannot be checked against "
            "a pull receipt or cited is not performed",
        )

    receipt = ledger.latest_event(PULL_EVENT, match={"repo": repo, "checkout": str(path)})
    if receipt is None:
        return _refuse(
            "ENORECEIPT",
            f"no git_pull receipt for repo={repo!r} checkout={str(path)!r} — "
            f"a reload only follows a pull this broker already performed",
        )
    content = receipt["content"]

    active_enter = _parse_systemd_timestamp(state.get("ActiveEnterTimestamp"))
    receipt_at = _as_utc(receipt.get("created_at"))
    if active_enter is not None and receipt_at is not None and active_enter >= receipt_at:
        return _refuse(
            "EALREADY",
            f"{unit} has been active since {state.get('ActiveEnterTimestamp')!r}, "
            f"which is no older than the pull receipt — nothing to reload onto",
            receipt=content,
        )

    head = _git(path, "rev-parse", "HEAD", runner=runner)
    if head.returncode != 0:
        return _refuse("EINVAL", f"could not read HEAD of {path}")
    current_head = (head.stdout or "").strip()
    after = content.get("after")
    if after and current_head != after:
        return _refuse(
            "EDRIFT",
            f"{path} HEAD is {current_head!r} but the pull receipt's after-sha "
            f"is {after!r} — the tree moved again since the pull",
            receipt=content, head=current_head,
        )

    call_args = {"units": [unit]}
    try:
        matches = governing_envelope_ids(VERB, app_id)
    except (OSError, ValueError) as exc:
        return _refuse("EAMBIG", f"envelope registry unreadable: {exc}")
    if envelope_id:
        if envelope_id not in matches:
            result = _refuse(
                "ENOENT", f"envelope {envelope_id!r} does not govern {VERB} "
                          f"for {app_id!r}", envelope_ids=matches,
            )
            result["ask"] = _file_ask(app_id, unit=unit, errno="ENOENT",
                                      reason=result["reason"], fields=None,
                                      task_id=task_id, store=store)
            return result
        matches = [envelope_id]
    if not matches:
        result = _refuse("ENOENT", f"no active {VERB} envelope governs {app_id!r}")
        result["ask"] = _file_ask(app_id, unit=unit, errno="ENOENT",
                                  reason=result["reason"], fields=None,
                                  task_id=task_id, store=store)
        return result
    if len(matches) > 1:
        return _refuse(
            "EAMBIG", f"multiple active {VERB} envelopes govern {app_id!r} — "
                      f"pass envelope_id to name which one to cite",
            envelope_ids=matches,
        )

    result = EnvelopeAuthority(ledger).authorize_and_cite(
        matches[0], actor=app_id, verb=VERB, call_args=call_args,
        project=project, session=session,
    )
    if not result.get("ok"):
        errno = result.get("errno", "EAMBIG")
        out = _refuse(errno, result.get("reason", ""), envelope_id=matches[0],
                      citation_id=result.get("citation_id"), fields=result.get("fields"))
        if errno in _ASKABLE:
            out["ask"] = _file_ask(app_id, unit=unit, errno=errno,
                                   reason=out["reason"], fields=result.get("fields"),
                                   task_id=task_id, store=store)
        return out

    try:
        restarted = _run(["systemctl", "--user", "restart", unit],
                          runner=runner, timeout=_SYSTEMCTL_TIMEOUT_S)
    except FileNotFoundError:
        return {"ok": False, "reloaded": False, "error": "EUNREACH",
                "reason": "systemctl_missing", "envelope_id": matches[0],
                "citation_id": result.get("citation_id")}
    except subprocess.TimeoutExpired:
        return {"ok": False, "reloaded": False, "error": "ETIMEDOUT",
                "reason": f"systemctl restart exceeded {_SYSTEMCTL_TIMEOUT_S}s",
                "envelope_id": matches[0], "citation_id": result.get("citation_id")}
    if restarted.returncode != 0:
        tail = (restarted.stderr or restarted.stdout or "").strip()[-300:]
        return {"ok": False, "reloaded": False, "error": "ERESTART",
                "reason": tail or f"systemctl restart exited {restarted.returncode}",
                "envelope_id": matches[0], "citation_id": result.get("citation_id")}

    state_after = show_unit(unit, runner=runner)

    steward = None
    if is_willow_bot_unit(unit):
        from . import bot_status as _bot_status
        try:
            steward = _bot_status.read_status()
        except Exception as exc:  # noqa: BLE001 — the restart happened; a steward read failing is reported, not hidden
            steward = {"state": "unreachable", "reason": f"bot_status_failed: {exc}"}

    receipt_out = {
        "ok": True, "reloaded": True, "unit": unit, "repo": repo,
        "checkout": str(path), "head": current_head,
        "envelope_id": matches[0], "citation_id": result.get("citation_id"),
        "state_before": state, "state_after": state_after,
        "pull_receipt": content,
    }
    if steward is not None:
        receipt_out["steward"] = steward

    try:
        rec = ledger.append(project, EVENT, {
            "actor": app_id, "unit": unit, "repo": repo, "checkout": str(path),
            "head": current_head, "session": session,
            "citation_id": result.get("citation_id"),
        })
        receipt_out["receipt_id"] = rec
    except Exception as exc:  # noqa: BLE001 — the reload happened; the receipt failing is reported, not hidden
        receipt_out["receipt_error"] = f"{type(exc).__name__}: {exc}"
    return receipt_out
