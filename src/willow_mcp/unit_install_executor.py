"""willow_mcp/unit_install_executor.py — write, enable and start a systemd
--user unit from a template tracked in a named repo; nobody types.

Verb 17, ``unit.install``, sealed under governance decision ``197aafa5``
(operator, 2026-09-21; Nestor pair ``197aafa5-1904-4ec9-a5a6-f113f07047b4``)
— see ``src/willow_mcp/bundle/constitutional/syscall-table.json`` row 17.
Sibling of :mod:`unit_reload_executor` (verb 15): reload restarts a unit
that already exists onto pulled code; this module creates or replaces the
unit *definition* — what runs under the operator's identity — which is a
different act and so a different row.

Gap ``aae735965d2a`` (carrying ``cd0787ddc141``): every fleet unit — the
reloader, the repo-sweep timer, the net signer, the seal watcher — was
installed at a keyboard (``python -m ... install`` then ``systemctl --user
enable --now``), and Kart cannot reach the user bus. The APK has no
keyboard (operator rule 2026-09-16), so the install is a broker verb.

What keeps this from being a general write-to-systemd verb: the unit's
content is never free text. ``source`` is ``org/name@relative/path`` and
must be a **tracked, clean** file in that repo's verified clone at its
current HEAD; the receipt records the HEAD sha and the template's digest,
so the installed unit is reviewable in a PR before it is ever installable
and traceable to a commit afterwards. Rendering uses the same ``@KEY@``
substitution the fleet's own installers use (:mod:`reloader`,
:mod:`repo_sweep_service`) with values drawn from this process's own
resolved environment — a placeholder the broker cannot fill is a refusal,
not a guess.

Refusals, each with its own errno, all before any envelope citation:

* ``EINVAL`` — malformed ``unit`` or ``source``;
* ``EPERM`` — ``unit`` is the broker's own unit, regardless of bounds;
* ``EUNREACH`` — the user bus, ``systemctl`` or the binary unreachable
  (cause distinct per failure, from :func:`unit_reload_executor.show_unit`'s
  probe);
* ``ENOSRC`` — no verified clone for the repo, the path not a tracked
  file, the tree dirty at that path, or HEAD unreadable;
* ``ENAME`` — the template's declared unit name is not ``unit``;
* ``ETEMPLATE`` — a placeholder this process cannot fill, or an unsafe
  value;
* ``EBOUNDS``-class refusals come back from the envelope gate itself with
  the field named (``ENOENT``/``EAMBIG``/``EDQUOT``/...), cited in FRANK and
  filed to the gates surface like row 15's.

The declared name: a ``# unit: <name>`` header line anywhere in the
template wins; otherwise the file name with ``.template`` stripped
(``willow-mcp-reloader.service.template`` declares
``willow-mcp-reloader.service``) — the convention every ``deploy/*.template``
already follows by filename.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional

from . import paths
from .unit_reload_executor import (
    _SYSTEMCTL_TIMEOUT_S,
    _git,
    _run,
    is_broker_unit,
    show_unit,
)

VERB = "unit.install"
EVENT = "unit_install"

#: Errnos for which an ask is worth filing (same set as row 15).
_ASKABLE = frozenset({"ENOENT", "EAMBIG", "EEXPIRED", "EDQUOT", "ENOGRANTS"})

_UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]*\.(service|timer|socket|path|target)$")
_DECLARED_RE = re.compile(r"^\s*#\s*unit:\s*(\S+)\s*$", re.MULTILINE)
_PLACEHOLDER_RE = re.compile(r"@([A-Z][A-Z0-9_]*)@")


def _refuse(errno: str, reason: str, **extra) -> dict:
    return {"ok": False, "error": errno, "reason": reason, "installed": False, **extra}


def unit_dir() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base.expanduser() / "systemd" / "user"


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse_source(source: str) -> tuple[str, str]:
    """``org/name@relative/path`` -> ``(repo, path)``; ``("", "")`` when
    malformed. The path must be relative and must not climb."""
    s = (source or "").strip()
    if s.count("@") != 1:
        return "", ""
    repo, rel = s.split("@", 1)
    repo, rel = repo.strip(), rel.strip()
    if repo.count("/") != 1 or not rel:
        return "", ""
    p = Path(rel)
    if p.is_absolute() or ".." in p.parts:
        return "", ""
    return repo, rel


def declared_unit_name(template_text: str, template_path: Path) -> str:
    m = _DECLARED_RE.search(template_text or "")
    if m:
        return m.group(1)
    name = template_path.name
    return name[: -len(".template")] if name.endswith(".template") else name


def _safe(value: object, field: str) -> str:
    text = str(value)
    if not text or any(char in text for char in ("\n", "\r", '"')):
        raise ValueError(f"{field} contains characters unsafe for a systemd unit")
    return text


def render_values(unit: str) -> dict[str, str]:
    """The placeholders this process can fill from its own resolved
    environment — the same names the fleet's installers use. Anything a
    template asks for beyond these is ``ETEMPLATE``."""
    values: dict[str, object] = {
        "PYTHON": Path(sys.executable),
        "UNIT": unit,
        "WILLOW_HOME": paths.willow_home(),
        "WILLOW_STORE_ROOT": paths.store_root(),
        "PG_DB": paths.pg_db(),
        "USER": os.environ.get("USER", ""),
        "HOME": Path.home(),
        "XDG_CONFIG_HOME": os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")),
    }
    try:
        from .seal_handler import _nestor_db_path
        values["NESTOR_DB"] = _nestor_db_path()
    except Exception:  # noqa: BLE001 — optional; a template that needs it will refuse by name
        pass
    return {k: str(v) for k, v in values.items() if str(v)}


def render_template(text: str, unit: str, *, values: Optional[dict[str, str]] = None) -> str:
    """``@KEY@`` substitution with the fleet installers' rules: every value
    is checked for unit-unsafe characters, an unresolved placeholder is a
    ``ValueError`` naming it, and ``willow-2.0`` is refused (the units exist
    because that tree went away)."""
    vals = values if values is not None else render_values(unit)
    rendered = text
    for key, value in vals.items():
        safe = str(value) if key == "PYTHON" else _safe(value, key)
        rendered = rendered.replace(f"@{key}@", safe)
    left = sorted(set(_PLACEHOLDER_RE.findall(rendered)))
    if left:
        raise ValueError(f"unresolved placeholder(s) this process cannot fill: {left}")
    if "willow-2.0" in rendered:
        raise ValueError("template must not reference willow-2.0")
    return rendered


def _file_ask(app_id: str, *, unit: str, source: str, errno: str, reason: str,
              fields, task_id: str, store=None) -> dict:
    """Same surface as :func:`unit_reload_executor._file_ask` — a ``unit.``
    row on ``gates``; ``@install`` on the gate id tells the panel this is
    verb 17, not verb 15."""
    from . import gate_request

    detail = f"{errno}: {reason}"
    if fields:
        detail += f" (fields: {', '.join(str(f) for f in fields)})"
    summary = (
        f"{app_id or 'an agent'} asked to install unit {unit!r} from {source!r} "
        f"and was refused: {detail}. Ratify a unit.install envelope with bounds "
        f"(units=[{unit!r}], sources=[{source!r}]) and the agent can ask again."
    )
    return gate_request.open_request(
        app_id or "", f"unit.{unit}@install", task_id=task_id, reason=summary, store=store,
    )


def _resolve_source(repo: str, rel: str, *, root: Optional[Path], runner) -> dict:
    """The tracked template for ``repo@rel`` or an ``ENOSRC`` refusal."""
    from .pull_executor import resolve_clone_status

    status = resolve_clone_status(repo, root=root, runner=runner)
    clone = status.get("clone")
    if clone is None:
        if status.get("error") == "EAMBIG":
            return _refuse("ENOSRC", f"{repo!r} resolves to more than one clone: "
                                     f"{status.get('candidates')}")
        return _refuse("ENOSRC", f"no verified clone of {repo!r} under the github root")
    clone = Path(clone)
    tracked = _git(clone, "ls-files", "--error-unmatch", "--", rel, runner=runner)
    if tracked.returncode != 0:
        return _refuse("ENOSRC", f"{rel!r} is not a tracked file in {repo!r}")
    dirty = _git(clone, "status", "--porcelain", "--", rel, runner=runner)
    if dirty.returncode != 0:
        return _refuse("ENOSRC", f"could not read the status of {rel!r} in {repo!r}")
    if (dirty.stdout or "").strip():
        return _refuse("ENOSRC", f"{rel!r} in {repo!r} has uncommitted changes — "
                                 f"a unit installs from HEAD, never from a dirty tree")
    head = _git(clone, "rev-parse", "HEAD", runner=runner)
    if head.returncode != 0 or not (head.stdout or "").strip():
        return _refuse("ENOSRC", f"could not read HEAD of {clone}")
    path = clone / rel
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return _refuse("ENOSRC", f"could not read {path}: {exc}")
    return {"ok": True, "clone": clone, "path": path, "text": text,
            "head": (head.stdout or "").strip()}


def _timer_sibling(path: Path) -> Optional[Path]:
    """``foo.service.template`` -> ``foo.timer.template`` beside it, when it
    exists; the timer is installed with its service so ``Unit=`` never
    points at a service that was not written."""
    name = path.name
    if not name.endswith(".service.template"):
        return None
    cand = path.with_name(name[: -len(".service.template")] + ".timer.template")
    return cand if cand.is_file() else None


def execute_unit_install(
    app_id: str,
    *,
    unit: str,
    source: str,
    envelope_id: str = "",
    project: str,
    session: str = "",
    task_id: str = "",
    ledger=None,
    store=None,
    runner: Optional[Callable] = None,
    github_root: Optional[Path] = None,
    destination: Optional[Path] = None,
    values: Optional[dict[str, str]] = None,
) -> dict:
    """Install ``unit`` from ``source`` under the ``unit.install`` envelope
    that governs ``app_id`` — or refuse, cite the refusal, and file the ask.

    ``ledger`` is a :class:`GovernanceLedger`; ``runner`` replaces
    ``subprocess.run`` for ``systemctl`` and ``git``; ``github_root`` /
    ``destination`` / ``values`` are test seams for the clone root, the
    systemd user directory, and the render values.
    """
    from .envelopes import EnvelopeAuthority, governing_envelope_ids

    unit = (unit or "").strip()
    source = (source or "").strip()
    if not unit or not _UNIT_RE.match(unit):
        return _refuse("EINVAL", "an install names a unit like `name.service` (or .timer/.socket/.path/.target)")
    repo, rel = parse_source(source)
    if not repo:
        return _refuse("EINVAL", "source must be `org/name@relative/path` inside that repo")
    if is_broker_unit(unit):
        return _refuse(
            "EPERM",
            f"{unit!r} is the broker's own unit — never a grantable install "
            f"target, regardless of what an envelope's bounds say",
        )

    # The user bus first: `show` on a unit that is not yet installed is
    # `unit_unknown` (reachable — the install is what creates it); only
    # `no_user_bus`, `systemctl_missing` and `timeout` are unreachable here.
    state_before = show_unit(unit, runner=runner)
    if not state_before.get("ok") and state_before.get("cause") != "unit_unknown":
        return _refuse(
            "EUNREACH", f"unit state unreachable: {state_before.get('cause')}",
            cause=state_before.get("cause"), detail=state_before.get("detail"),
        )

    src = _resolve_source(repo, rel, root=github_root, runner=runner)
    if not src.get("ok"):
        return src
    declared = declared_unit_name(src["text"], src["path"])
    if declared != unit:
        return _refuse(
            "ENAME", f"template {rel!r} declares unit {declared!r}, not {unit!r}",
            declared=declared,
        )
    # One value set for the service and its timer: `@UNIT@` is the service
    # in both (a timer's `Unit=` names the service it schedules — rendering
    # them apart is how a timer drifts from its service, which the fleet's
    # own installers render together for exactly that reason).
    timer_path = _timer_sibling(src["path"])
    timer_name = declared_unit_name("", timer_path) if timer_path is not None else ""
    vals = dict(values) if values is not None else render_values(unit)
    vals.setdefault("SERVICE_UNIT", unit)
    if timer_name:
        vals.setdefault("TIMER_UNIT", timer_name)
    try:
        rendered = render_template(src["text"], unit, values=vals)
    except ValueError as exc:
        return _refuse("ETEMPLATE", str(exc))

    timer_rendered = ""
    if timer_path is not None:
        try:
            timer_rendered = render_template(
                timer_path.read_text(encoding="utf-8"), unit, values=vals,
            )
        except (OSError, ValueError) as exc:
            return _refuse("ETEMPLATE", f"timer sibling {timer_path.name}: {exc}")

    if ledger is None:
        return _refuse(
            "EAMBIG",
            "no governance ledger: an install that cannot be cited is not performed",
        )

    call_args = {"units": [unit], "sources": [source]}
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
            result["ask"] = _file_ask(app_id, unit=unit, source=source, errno="ENOENT",
                                      reason=result["reason"], fields=None,
                                      task_id=task_id, store=store)
            return result
        matches = [envelope_id]
    if not matches:
        result = _refuse("ENOENT", f"no active {VERB} envelope governs {app_id!r}")
        result["ask"] = _file_ask(app_id, unit=unit, source=source, errno="ENOENT",
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
            out["ask"] = _file_ask(app_id, unit=unit, source=source, errno=errno,
                                   reason=out["reason"], fields=result.get("fields"),
                                   task_id=task_id, store=store)
        return out

    # ── the act ──────────────────────────────────────────────────────────────
    root = Path(destination) if destination is not None else unit_dir()
    root.mkdir(parents=True, exist_ok=True)
    target = root / unit
    replaced = target.is_file()
    previous_digest = _digest(target.read_text(encoding="utf-8")) if replaced else ""
    written = [str(target)]
    target.write_text(rendered, encoding="utf-8")
    if timer_path is not None:
        timer_target = root / timer_name
        timer_target.write_text(timer_rendered, encoding="utf-8")
        written.append(str(timer_target))

    enable_target = timer_name or unit
    for argv in (["systemctl", "--user", "daemon-reload"],
                 ["systemctl", "--user", "enable", "--now", enable_target]):
        try:
            proc = _run(argv, runner=runner, timeout=_SYSTEMCTL_TIMEOUT_S)
        except FileNotFoundError:
            return {"ok": False, "installed": False, "error": "EUNREACH", "reason": "systemctl_missing",
                    "written": written, "envelope_id": matches[0], "citation_id": result.get("citation_id")}
        except subprocess.TimeoutExpired:
            return {"ok": False, "installed": False, "error": "ETIMEDOUT",
                    "reason": f"{' '.join(argv[2:])} exceeded {_SYSTEMCTL_TIMEOUT_S}s",
                    "written": written, "envelope_id": matches[0], "citation_id": result.get("citation_id")}
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout or "").strip()[-300:]
            return {"ok": False, "installed": False, "error": "EINSTALL",
                    "reason": tail or f"{' '.join(argv[2:])} exited {proc.returncode}",
                    "written": written, "envelope_id": matches[0], "citation_id": result.get("citation_id")}

    state_after = show_unit(unit, runner=runner)

    receipt_out = {
        "ok": True, "installed": True, "unit": unit, "source": source,
        "repo": repo, "path": rel, "head": src["head"],
        "template_digest": _digest(src["text"]), "rendered_digest": _digest(rendered),
        "replaced": replaced, "previous_digest": previous_digest,
        "timer": timer_name, "written": written,
        "envelope_id": matches[0], "citation_id": result.get("citation_id"),
        "state_before": state_before, "state_after": state_after,
    }
    try:
        rec = ledger.append(project, EVENT, {
            "actor": app_id, "unit": unit, "source": source, "repo": repo, "path": rel,
            "head": src["head"], "template_digest": receipt_out["template_digest"],
            "rendered_digest": receipt_out["rendered_digest"], "replaced": replaced,
            "previous_digest": previous_digest, "timer": timer_name,
            "active_state_after": state_after.get("ActiveState"),
            "active_enter_after": state_after.get("ActiveEnterTimestamp"),
            "session": session, "citation_id": result.get("citation_id"),
        })
        receipt_out["receipt_id"] = rec
    except Exception as exc:  # noqa: BLE001 — the install happened; the receipt failing is reported, not hidden
        receipt_out["receipt_error"] = f"{type(exc).__name__}: {exc}"
    return receipt_out
