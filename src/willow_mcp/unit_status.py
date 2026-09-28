"""willow_mcp/unit_status.py — the desk can see whether a unit is actually
running, not just enabled.

Gap ``158600e03598`` (continued): ``bot_status`` reads willow-bot's own
status report, but nothing let the desk ask systemd itself "is this unit
loaded, active, restart-looping, or dead" — an urgent item was closed
tonight on a ``default.target.wants`` symlink (enabled) with nobody able
to show whether the unit was actually *running*. Memory: a restart-looping
unit samples ``active`` on any single read, which looks identical to a
healthy one unless ``NRestarts``/``ActiveEnterTimestamp`` are read too.

This module reuses :func:`unit_reload_executor.show_unit` for the
per-unit property read (extending its ``_SHOW_PROPERTIES`` with
``SubState``/``NRestarts``/``UnitFileState``/``ExecMainStatus``) and adds:

* enumeration, when ``unit`` is empty, of every loaded ``willow-*`` /
  ``ratatosk-*`` unit (``systemctl --user list-units``) UNIONED with
  enabled-but-not-loaded unit files (``systemctl --user list-unit-files``)
  — so a unit that was enabled but has never started still shows up;
* a bounded, redacted ``journalctl --user -u <unit>`` tail per unit;
* the "restarting" guard: ``NRestarts > 0`` within the last 60s, or
  ``SubState == "auto-restart"``.

Three-state at the top level (INVARIANTS §1): ``populated`` / ``empty`` (no
matching units) / ``unreachable`` (``cause``: ``no_user_bus``,
``systemctl_missing``, ``timeout`` — never collapsed into ``empty``). The
journal tail carries its OWN three-state per unit, same causes plus
``unit_unknown``, since a unit can enumerate fine while its journal read
fails independently.

Read-only: no writes, no envelope, no FRANK citation. Not a general
systemd reader — a unit named outside the two allowed prefixes is refused
``EINVAL``.
"""
from __future__ import annotations

import re
import subprocess
from datetime import datetime, timezone
from typing import Callable, Optional

from . import secret_scan
from .unit_reload_executor import (
    _parse_systemd_timestamp,
    _run,
    is_auto_restart_substate,
    show_unit,
)

#: Strict full-match unit name (Loki 6ACB1F10 F1): a bare `startswith` let
#: every trick through as argv to systemctl/journalctl — a glob (`willow-
#: *.service`), a `..` climb, an embedded space or newline, a trailing
#: `--all`, or a bare `willow-` prefix with nothing after it. The character
#: class deliberately excludes glob metacharacters (`*?[]`), whitespace and
#: control characters; the required `.(service|timer)` suffix, anchored with
#: `fullmatch` (never `$`, whose "one trailing newline" leniency would let
#: `willow-x.service\n` through), means anything appended after the suffix
#: fails outright.
_UNIT_NAME_RE = re.compile(
    r"^(?:willow|ratatosk)-[A-Za-z0-9][A-Za-z0-9_.@-]*\.(?:service|timer)$"
)

_LIST_TIMEOUT_S = 10
_JOURNAL_TIMEOUT_S = 10
_DEFAULT_JOURNAL_LINES = 20
_MAX_JOURNAL_LINES = 200
_RESTART_WINDOW_S = 60


def _refuse(errno: str, reason: str, **extra) -> dict:
    return {"ok": False, "error": errno, "reason": reason, **extra}


def _is_allowed(unit: str) -> bool:
    if ".." in unit:
        return False
    return bool(_UNIT_NAME_RE.fullmatch(unit))


def _classify_failure(detail: str) -> str:
    lowered = detail.lower()
    if "failed to connect to bus" in lowered or "failed to get d-bus connection" in lowered:
        return "no_user_bus"
    return "unit_unknown"


def _list_loaded_units(runner: Optional[Callable]) -> tuple[Optional[list], Optional[dict]]:
    """``systemctl --user list-units --all --plain --no-legend`` -> unit
    names, or ``(None, unreachable)`` with a cause distinct from the
    others — mirrors :func:`unit_reload_executor.show_unit`'s own
    three-cause split, applied to the listing call instead of one unit."""
    try:
        proc = _run(
            ["systemctl", "--user", "list-units", "--all", "--plain", "--no-legend"],
            runner=runner, timeout=_LIST_TIMEOUT_S,
        )
    except FileNotFoundError:
        return None, {"cause": "systemctl_missing"}
    except subprocess.TimeoutExpired:
        return None, {"cause": "timeout"}
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        if "failed to connect to bus" in detail.lower() or "failed to get d-bus connection" in detail.lower():
            return None, {"cause": "no_user_bus", "detail": detail[-300:]}
        return None, {"cause": "systemctl_missing", "detail": detail[-300:]}
    names = []
    for line in (proc.stdout or "").splitlines():
        parts = line.split()
        if parts:
            names.append(parts[0])
    return names, None


def _list_enabled_unit_files(runner: Optional[Callable]) -> tuple[Optional[list], Optional[dict]]:
    """``systemctl --user list-unit-files --plain --no-legend`` -> unit file
    names whose state is ``enabled`` — so a unit enabled via a
    ``default.target.wants`` symlink that has never started still shows up,
    which is exactly the gap tonight's urgent item hit."""
    try:
        proc = _run(
            ["systemctl", "--user", "list-unit-files", "--plain", "--no-legend"],
            runner=runner, timeout=_LIST_TIMEOUT_S,
        )
    except FileNotFoundError:
        return None, {"cause": "systemctl_missing"}
    except subprocess.TimeoutExpired:
        return None, {"cause": "timeout"}
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        if "failed to connect to bus" in detail.lower() or "failed to get d-bus connection" in detail.lower():
            return None, {"cause": "no_user_bus", "detail": detail[-300:]}
        return None, {"cause": "systemctl_missing", "detail": detail[-300:]}
    names = []
    for line in (proc.stdout or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "enabled":
            names.append(parts[0])
    return names, None


def _is_restarting(state: dict, *, now: Optional[datetime] = None) -> bool:
    """The "active is not bound" guard, in code: a unit sampled mid
    crash-loop reports ``ActiveState=active`` on any single read. True when
    ``NRestarts`` is positive AND the current activation is recent (within
    ``_RESTART_WINDOW_S``), or when systemd itself is already mid-backoff
    (``SubState == "auto-restart"``)."""
    if is_auto_restart_substate(state):
        return True
    try:
        n_restarts = int(state.get("NRestarts") or 0)
    except (TypeError, ValueError):
        n_restarts = 0
    if n_restarts <= 0:
        return False
    active_enter = _parse_systemd_timestamp(state.get("ActiveEnterTimestamp"))
    if active_enter is None:
        return False
    reference = now or datetime.now(timezone.utc)
    return (reference - active_enter).total_seconds() < _RESTART_WINDOW_S


#: Real systemd (measured on 259: Loki 6ACB1F10 F4, Kart RCMPD1A3) prints
#: this literal line on stdout with rc=0 for a unit with an empty journal —
#: never a "no lines" signal to the caller, an empty state to us.
_NO_ENTRIES_SENTINEL = "-- No entries --"
#: ...and prints this on stderr, ALSO with rc=0, when the journal itself is
#: unreadable (no persistent journal, permission denied) — indistinguishable
#: from "empty" by return code alone, so checked by text regardless of rc.
_NO_JOURNAL_FILES_MARKER = "no journal files"


def journal_tail(unit: str, journal_lines: int, *, runner: Optional[Callable] = None) -> dict:
    """A bounded ``journalctl`` tail for ``unit``. The JOINED tail text is
    redacted through :func:`secret_scan.redact_journal_tail` BEFORE it is
    split into lines — a per-line redaction defeats the private-key rule's
    own multi-line PEM match (Loki 6ACB1F10 F3: the block survived whole
    because each line, seen alone, never matched the block pattern).
    ``redact_journal_tail`` is a WIDER, journal-scoped pattern set than the
    shared ``server._guarded`` funnel's ``redact_egress`` — labelled
    KEY=/TOKEN=/SECRET=/PASSWORD= assignments and a bare ``password=`` are
    precise enough for a journal line but over-redact a general tool response
    (``primary_key=True``, ``sort_key=lambda``, a credential SOURCE like
    ``env:OPENAI_API_KEY`` — Loki 0DFFEFA6 B3), so they apply ONLY here and
    in the ELOOP/EDEAD journal paths below, never the general egress funnel.
    Its own three-state contract:
    ``populated`` / ``empty`` (no journal lines, INCLUDING journalctl's own
    ``-- No entries --`` sentinel, rc=0) / ``unreachable`` (a cause distinct
    per failure, including ``journal_unreadable`` for journalctl's rc=0
    "No journal files were found" case — never collapsed into ``populated``
    just because the exit code was 0). Public (no leading underscore): reused
    by :mod:`unit_reload_executor` and :mod:`unit_install_executor` to attach
    a journal tail to an ``ELOOP``/``EDEAD`` refusal (gap d30c923424a0's
    amendment, and Loki 6ACB1F10 F2) without a second redactor."""
    try:
        proc = _run(
            # No `-q` (Loki 0DFFEFA6 B1): on real systemd 259, `-q` silences
            # BOTH signals this function reads from the text below — an
            # unreadable journal (`No journal files were found.`, rc=0) comes
            # back completely empty and indistinguishable from a genuinely
            # empty one. Never add it back without a real-systemd probe.
            ["journalctl", "--user", "-u", unit, "-n", str(journal_lines),
             "--no-pager", "-o", "short-iso", "--"],
            runner=runner, timeout=_JOURNAL_TIMEOUT_S,
        )
    except FileNotFoundError:
        return {"state": "unreachable", "cause": "systemctl_missing"}
    except subprocess.TimeoutExpired:
        return {"state": "unreachable", "cause": "timeout"}

    stderr_detail = (proc.stderr or "").strip()
    if _NO_JOURNAL_FILES_MARKER in stderr_detail.lower():
        # rc is 0 here on real systemd — the failure is legible only in the
        # TEXT, never the return code (Loki 6ACB1F10 F4).
        return {"state": "unreachable", "cause": "journal_unreadable",
                "detail": stderr_detail[-300:]}
    if proc.returncode != 0:
        detail = stderr_detail or (proc.stdout or "").strip()
        return {"state": "unreachable", "cause": _classify_failure(detail), "detail": detail[-300:]}

    raw = proc.stdout or ""
    stripped = raw.strip()
    if not stripped or stripped == _NO_ENTRIES_SENTINEL:
        return {"state": "empty", "lines": []}

    redacted_text, kinds_found = secret_scan.redact_journal_tail(raw)
    lines = [line for line in redacted_text.splitlines() if line.strip()]
    out = {"state": "populated", "lines": lines}
    if kinds_found:
        out["redacted_kinds"] = sorted(kinds_found)
    return out


def _unit_entry(unit: str, *, journal_lines: int, runner: Optional[Callable],
                 now: Optional[datetime]) -> dict:
    state = show_unit(unit, runner=runner)
    if not state.get("ok"):
        return {
            "unit": unit, "state": "unreachable",
            "cause": state.get("cause"), "detail": state.get("detail"),
        }
    return {
        "unit": unit,
        "active_state": state.get("ActiveState"),
        "sub_state": state.get("SubState"),
        "main_pid": state.get("MainPID"),
        "n_restarts": state.get("NRestarts"),
        "active_enter_timestamp": state.get("ActiveEnterTimestamp"),
        "unit_file_state": state.get("UnitFileState"),
        "exec_main_status": state.get("ExecMainStatus"),
        "restarting": _is_restarting(state, now=now),
        "journal": journal_tail(unit, journal_lines, runner=runner),
    }


def read_unit_status(
    *,
    unit: str = "",
    journal_lines: int = _DEFAULT_JOURNAL_LINES,
    runner: Optional[Callable] = None,
    now: Optional[datetime] = None,
) -> dict:
    """Read-only ``systemctl --user`` + ``journalctl --user`` view of one
    unit, or every ``willow-*``/``ratatosk-*`` unit. Never raises: every
    failure mode comes back as a structured three-state result. ``runner``
    replaces ``subprocess.run`` for both ``systemctl`` and ``journalctl``
    calls in tests; ``now`` replaces ``datetime.now(timezone.utc)`` so the
    "restarting" window is deterministic under test."""
    unit = (unit or "").strip()
    if unit and not _is_allowed(unit):
        return _refuse(
            "EINVAL",
            f"{unit!r} is not a willow-*/ratatosk-* unit — this is not a "
            f"general systemd reader",
        )

    try:
        journal_lines = int(journal_lines)
    except (TypeError, ValueError):
        journal_lines = _DEFAULT_JOURNAL_LINES
    journal_lines = max(1, min(journal_lines, _MAX_JOURNAL_LINES))

    if unit:
        entry = _unit_entry(unit, journal_lines=journal_lines, runner=runner, now=now)
        if entry.get("state") == "unreachable":
            cause = entry.get("cause")
            if cause in ("no_user_bus", "systemctl_missing", "timeout"):
                return {"state": "unreachable", "cause": cause, "detail": entry.get("detail")}
            # unit_unknown: the bus answered, this named unit just doesn't
            # exist — "no matching units", not an unreachable desk.
            return {"state": "empty", "reason": f"{unit!r} is not known to systemd", "units": []}
        return {"state": "populated", "units": [entry]}

    loaded, err = _list_loaded_units(runner)
    if err is not None:
        return {"state": "unreachable", **err}
    enabled_files, err = _list_enabled_unit_files(runner)
    if err is not None:
        return {"state": "unreachable", **err}

    matched = sorted({name for name in (loaded + enabled_files) if _is_allowed(name)})
    if not matched:
        return {"state": "empty", "reason": "no willow-*/ratatosk-* units found", "units": []}

    units_out = [
        _unit_entry(name, journal_lines=journal_lines, runner=runner, now=now)
        for name in matched
    ]
    return {"state": "populated", "units": units_out}
