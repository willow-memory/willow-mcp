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
import re
import subprocess
import time
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
    # Added for unit_status (gap 158600e03598): SubState/NRestarts feed the
    # "restarting" guard (a unit sampled `active` mid crash-loop still LOOKS
    # active — INVARIANTS "active is not bound"); UnitFileState distinguishes
    # "enabled but never started" from "loaded and running";
    # ExecMainStatus is the last exit code, useful once a unit has stopped.
    "SubState", "NRestarts", "UnitFileState", "ExecMainStatus",
    # Added for the install/reload restart-loop guard (gap d30c923424a0):
    # RestartUSec sizes the gap between the two post-action samples.
    "RestartUSec",
    # Added per Loki 6ACB1F10 F4: on real systemd 259, `systemctl show` on a
    # unit it has never heard of exits 0 with ActiveState=inactive (not the
    # empty-properties shape this module's fake reproduced) — LoadState is
    # the only property that actually says "not-found" for such a unit.
    "LoadState",
    # Added per Loki 0DFFEFA6 B2: a timer-activated (or directly reloaded)
    # `Type=oneshot` unit runs once and goes `inactive` on its own — that is
    # success, not death. `Type` tells `liveness_refusal_after_action` this
    # is a oneshot at all; `Result` is the last-run verdict systemd itself
    # records (`success`/`exit-code`/...), read in preference to inferring
    # success from `ExecMainStatus` alone.
    "Type", "Result",
)

#: `sample_restart_loop`'s wait between its two `show_unit` calls: doubled
#: RestartUSec, clamped to this range so a fast-restarting unit (RestartSec=
#: 100ms) still gets a real gap to loop again in, and a slow one (RestartSec=
#: 30s) does not turn every install/reload into a half-minute call.
_RESTART_WAIT_MIN_S = 2.0
_RESTART_WAIT_MAX_S = 15.0

_DURATION_UNIT_S = {"us": 1e-6, "ms": 1e-3, "s": 1.0, "min": 60.0, "h": 3600.0}
#: Longest unit spellings first (`min`/`ms`/`us` before the bare `s`/`h` they
#: contain), so findall never splits e.g. "ms" into an "m" it doesn't have
#: and a trailing "s" it does.
_DURATION_TOKEN_RE = re.compile(r"(\d+(?:\.\d+)?)\s*(us|ms|min|h|s)\b")


def is_auto_restart_substate(state: dict) -> bool:
    """True when a `show_unit`-shaped state's `SubState` is systemd's own
    mid-backoff marker. The one-line piece of the "active is not bound"
    guard (INVARIANTS) shared verbatim between `unit_status`'s single-sample
    `restarting` flag and this module's two-sample `restart_loop` check, so
    the two heuristics never drift apart on what "restarting" means."""
    return (state.get("SubState") or "").strip() == "auto-restart"


def _parse_restart_wait_s(value: str) -> float:
    """2x `RestartUSec`, clamped to [`_RESTART_WAIT_MIN_S`,
    `_RESTART_WAIT_MAX_S`]. `systemctl --user show` (without `--value`)
    pretty-prints `*USec` properties the same way it pretty-prints
    timestamps — `RestartUSec=100ms`, `RestartUSec=1min 30s`, `RestartUSec=0`,
    or `RestartUSec=infinity` for a unit that never restarts. Absent, empty,
    zero, unparseable, or infinite all fall back to the FLOOR of the clamp —
    a wait this function cannot ground in a real number should be the
    shortest defensible one, never a guessed-long one."""
    v = (value or "").strip()
    if not v or v.lower() == "infinity":
        return _RESTART_WAIT_MIN_S
    total_s = 0.0
    matched = False
    for amount, unit in _DURATION_TOKEN_RE.findall(v):
        total_s += float(amount) * _DURATION_UNIT_S[unit]
        matched = True
    if not matched:
        try:
            total_s = float(v)
            matched = True
        except ValueError:
            return _RESTART_WAIT_MIN_S
    if total_s <= 0:
        return _RESTART_WAIT_MIN_S
    return max(_RESTART_WAIT_MIN_S, min(total_s * 2, _RESTART_WAIT_MAX_S))


def _restart_loop_between(first: dict, second: dict) -> bool:
    """True when either sample shows systemd already mid-backoff
    (`is_auto_restart_substate`), or `NRestarts` climbed between the two
    samples, or `ActiveEnterTimestamp` moved — any one of the three is a
    restart that happened between the samples, which a single post-action
    `show_unit` call cannot see (gap d30c923424a0: unit_install_executor
    reported `ok` on one sample while the unit was restart-looping)."""
    if is_auto_restart_substate(first) or is_auto_restart_substate(second):
        return True
    if not first.get("ok") or not second.get("ok"):
        return False
    try:
        n1 = int(first.get("NRestarts") or 0)
        n2 = int(second.get("NRestarts") or 0)
    except (TypeError, ValueError):
        n1 = n2 = 0
    if n2 > n1:
        return True
    enter1, enter2 = first.get("ActiveEnterTimestamp"), second.get("ActiveEnterTimestamp")
    if enter1 and enter2 and enter1 != enter2:
        return True
    return False


def _oneshot_run_failed(second: dict) -> bool:
    """True when ``second`` (a ``show_unit``-shaped sample) shows concrete
    evidence that a oneshot's run FAILED — ``Result`` present and not
    ``"success"``, or a non-zero ``ExecMainStatus``. False for a unit that
    simply has not run yet (both fields absent) — absence is not failure."""
    result = (second.get("Result") or "").strip()
    if result and result != "success":
        return True
    try:
        exec_status = int(second.get("ExecMainStatus"))
    except (TypeError, ValueError):
        return False
    return exec_status != 0


def liveness_refusal_after_action(
    loop_sample: dict, *, timer_state: Optional[dict] = None,
) -> Optional[dict]:
    """``None`` when a unit is genuinely alive and stable after an install or
    reload: the second post-action sample is reachable, its ``ActiveState``
    is ``"active"``, and no restart loop was detected between the two
    samples. Otherwise a dict naming exactly why not — never collapsed into
    ``ok=True`` (Loki 6ACB1F10 F2):

    * ``EUNREACH`` — the second sample itself could not be read (timeout, no
      user bus) — the OLD code silently reported ``ok=True`` with a dead
      ``state_after`` in this case;
    * ``EDEAD`` — the second sample answered but the unit is not active (a
      ``Restart=no`` unit that crashed once and stayed down, or one that was
      inactive/dead across both samples).

    ``timer_state`` (Loki 0DFFEFA6 B2): when the install/reload enabled a
    TIMER (a ``.timer`` sibling, or the unit itself is one), pass a fresh
    ``show_unit`` sample of the TIMER here — its liveness (``ActiveState ==
    "active"``, i.e. waiting for the next tick), not the activated service's,
    is what "came up correctly" means. The service a timer activates is
    almost always ``Type=oneshot``: it runs once per tick and goes
    ``inactive`` between ticks, which judged as the SERVICE's own liveness
    reads a correct install as ``EDEAD`` on every single tick boundary — and,
    because that judgment runs AFTER the envelope is already cited, by
    design, a genuine refusal here still spends a (sometimes ``max_count=1``)
    grant on an install/reload that wrote and enabled the unit before
    liveness was ever checked. This is not a bug to fix; it is the order
    ``execute_unit_install``/``execute_unit_reload`` actually run in, and the
    payload and receipt say so honestly (``installed``/``reloaded`` stay
    true, the event is ``<event>_dead``).

    Absent a timer, a ``Type=oneshot`` service that already completed one
    successful run — ``Result=="success"``, or ``ActiveState=="inactive"``
    with ``ExecMainStatus=="0"`` — is accepted the same way: the identical
    "ran once and exited cleanly" shape a directly reloaded/installed oneshot
    takes with no timer at all ("the same logic, inferred").

    A timer being healthy says nothing about whether the oneshot it just
    activated actually succeeded on ITS first run inside the sample window
    (``OnBootSec`` can have long elapsed on a running box, so the timer fires
    at once). When the timer is up but the sampled service shows a run that
    FAILED (``Result`` not ``"success"``, or a non-zero ``ExecMainStatus``),
    this refuses ``EFAILED`` rather than reporting the install/reload ok —
    manifest-grant's first apply refusing ``efingerprint_absent``, say, must
    not read as a successful install.

    Shared between :func:`unit_reload_executor.execute_unit_reload` and
    :func:`unit_install_executor.execute_unit_install` so the two verbs never
    drift on what "the unit actually came up" means. Skips the check
    entirely when ``loop_sample["restart_loop"]`` is already true — that
    is the caller's ``ELOOP`` refusal, a different (and more specific) shape.
    """
    if loop_sample.get("restart_loop"):
        return None
    second = loop_sample.get("second") or {}
    if not second.get("ok"):
        return {
            "errno": "EUNREACH",
            "reason": (
                f"second post-action sample is unreachable "
                f"({second.get('cause')}) — not reporting ok on a unit whose "
                f"post-action state could not be read"
            ),
            "cause": second.get("cause"),
        }

    if timer_state is not None:
        if not timer_state.get("ok"):
            return {
                "errno": "EUNREACH",
                "reason": (
                    f"the timer's post-action state is unreachable "
                    f"({timer_state.get('cause')}) — not reporting ok on a "
                    f"timer whose liveness could not be read"
                ),
                "cause": timer_state.get("cause"),
            }
        if timer_state.get("ActiveState") != "active":
            return {
                "errno": "EDEAD",
                "reason": (
                    f"timer is {timer_state.get('ActiveState')!r} after the "
                    f"action, not active — not reporting ok on a timer that "
                    f"did not come up"
                ),
            }
        if second.get("Type") == "oneshot" and _oneshot_run_failed(second):
            return {
                "errno": "EFAILED",
                "reason": (
                    f"the timer is active, but the oneshot it activates "
                    f"failed its first run inside the sample window "
                    f"(Result={second.get('Result')!r}, "
                    f"ExecMainStatus={second.get('ExecMainStatus')!r}) — not "
                    f"reporting ok on an install/reload whose service failed"
                ),
            }
        return None

    if second.get("ActiveState") == "active":
        return None

    if second.get("Type") == "oneshot" and (
        second.get("Result") == "success"
        or (second.get("ActiveState") == "inactive"
            and str(second.get("ExecMainStatus")) == "0")
    ):
        return None

    return {
        "errno": "EDEAD",
        "reason": (
            f"unit is {second.get('ActiveState')!r} after the action, "
            f"not active — not reporting ok on a unit that did not come up"
        ),
    }


def sample_restart_loop(
    unit: str, *, runner: Optional[Callable] = None,
    sleeper: Optional[Callable[[float], None]] = None,
    wait_s: Optional[float] = None,
) -> dict:
    """Two `show_unit` samples spaced ~2x`RestartUSec` apart (clamped to
    [2, 15]s), so an install or reload that just acted on `unit` can tell a
    restart loop from a merely-active unit before reporting `ok` — the same
    "active is not bound" guard `unit_status` applies to a single sample,
    made definitive here because these two callers control the timing a
    read-only status query does not. `sleeper` replaces `time.sleep` for
    tests — never a real sleep under test. `wait_s` overrides the computed
    wait entirely (also a test seam). Returns ``{"first", "second",
    "restart_loop", "wait_s"}``."""
    first = show_unit(unit, runner=runner)
    wait = wait_s if wait_s is not None else _parse_restart_wait_s(first.get("RestartUSec", ""))
    sleep = sleeper or time.sleep
    sleep(wait)
    second = show_unit(unit, runner=runner)
    return {
        "first": first, "second": second,
        "restart_loop": _restart_loop_between(first, second),
        "wait_s": wait,
    }

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
            ["systemctl", "--user", "show",
             f"--property={','.join(_SHOW_PROPERTIES)}", "--", unit],
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
    # Real systemd (Loki 6ACB1F10 F4, Kart RCMPD1A3, systemd 259) exits 0 on
    # an unknown unit with ActiveState=inactive and LoadState=not-found —
    # NOT with empty properties, which only the old test fake reproduced.
    # LoadState is the property that actually distinguishes "systemd has
    # never heard of this unit" from "loaded and merely inactive".
    if props.get("LoadState") == "not-found":
        return {"ok": False, "reason": "unreachable", "cause": "unit_unknown",
                "detail": f"{unit!r} is not known to systemd (LoadState=not-found)"}
    if not props.get("ActiveState"):
        # Belt-and-suspenders for a systemd that returns rc=0 with empty
        # properties instead (the shape the pre-F4 fake exercised).
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
    sleeper: Optional[Callable[[float], None]] = None,
) -> dict:
    """Restart ``unit`` under the ``unit.reload`` envelope that governs
    ``app_id`` — or refuse, cite the refusal, and file the ask.

    ``ledger`` is a :class:`GovernanceLedger`; the MCP tool builds it from
    the live Postgres, tests pass a fake. ``runner`` replaces
    ``subprocess.run`` for both ``systemctl`` and ``git`` calls in tests.
    ``sleeper`` replaces ``time.sleep`` in :func:`sample_restart_loop` for
    tests — never a real sleep under test.
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

    # Liveness (below, via `liveness_refusal_after_action`) is judged AFTER
    # this citation, by design: the restart already has to happen to sample
    # it. A genuine EDEAD/EFAILED/EUNREACH refusal past this point still
    # spends the grant this call cites.
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

    # Gap d30c923424a0: a single post-restart sample reads a restart-looping
    # unit as merely `active`. Two samples, spaced to give a fast-restarting
    # unit room to loop again, tell the difference before this reports `ok`.
    loop_sample = sample_restart_loop(unit, runner=runner, sleeper=sleeper)
    state_after = loop_sample["second"]

    if loop_sample["restart_loop"]:
        from . import unit_status as _unit_status
        journal = _unit_status.journal_tail(unit, 20, runner=runner)
        out = {
            "ok": False, "reloaded": False, "error": "ELOOP",
            "reason": (
                f"{unit} restarted but is restart-looping (NRestarts/"
                f"ActiveEnterTimestamp changed or SubState=auto-restart across "
                f"a {loop_sample['wait_s']}s sample) — not reporting ok on a "
                f"unit that is not stable"
            ),
            "unit": unit, "repo": repo, "checkout": str(path), "head": current_head,
            "envelope_id": matches[0], "citation_id": result.get("citation_id"),
            "state_before": state, "state_first": loop_sample["first"],
            "state_after": state_after, "journal": journal,
        }
        try:
            out["receipt_id"] = ledger.append(project, f"{EVENT}_restart_loop", {
                "actor": app_id, "unit": unit, "repo": repo, "checkout": str(path),
                "head": current_head, "session": session,
                "citation_id": result.get("citation_id"),
                "state_first": loop_sample["first"], "state_second": state_after,
            })
        except Exception as exc:  # noqa: BLE001 — the loop was detected; the receipt failing is reported, not hidden
            out["receipt_error"] = f"{type(exc).__name__}: {exc}"
        return out

    dead = liveness_refusal_after_action(loop_sample)
    if dead is not None:
        from . import unit_status as _unit_status
        journal = _unit_status.journal_tail(unit, 20, runner=runner)
        out = {
            "ok": False, "reloaded": False, "error": dead["errno"],
            "reason": dead["reason"],
            "unit": unit, "repo": repo, "checkout": str(path), "head": current_head,
            "envelope_id": matches[0], "citation_id": result.get("citation_id"),
            "state_before": state, "state_first": loop_sample["first"],
            "state_after": state_after, "journal": journal,
        }
        try:
            out["receipt_id"] = ledger.append(project, f"{EVENT}_dead", {
                "actor": app_id, "unit": unit, "repo": repo, "checkout": str(path),
                "head": current_head, "session": session,
                "citation_id": result.get("citation_id"), "errno": dead["errno"],
                "state_first": loop_sample["first"], "state_second": state_after,
            })
        except Exception as exc:  # noqa: BLE001 — the refusal happened; the receipt failing is reported, not hidden
            out["receipt_error"] = f"{type(exc).__name__}: {exc}"
        return out

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
