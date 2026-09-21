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
from datetime import datetime, timezone
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


#: The one keyboard guard every `install` CLI shares (reloader, net_signer,
#: and the server's repo-sweep / worker / voice service actions). The
#: keyboard path stays for a box with no broker, behind `--keyboard`, so
#: typing it is a stated choice and not the default a runbook copies.
KEYBOARD_REFUSAL = (
    "install: use unit_install_execute (verb 17, unit.install) — the broker "
    "writes, enables and starts the unit from the tracked template under an "
    "envelope with a FRANK receipt. On a box with no broker, pass --keyboard."
)


def keyboard_install_refused(args, *, out=None) -> bool:
    """True (and the refusal printed to ``out`` or stderr) when an ``install``
    CLI was invoked without ``--keyboard``. Callers return exit 2."""
    if getattr(args, "keyboard", False):
        return False
    print(KEYBOARD_REFUSAL, file=out or sys.stderr)
    return True


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


def _resolve_clone(repo: str, *, root: Optional[Path], runner) -> dict:
    """The verified clone of ``repo`` and its HEAD, or an ``ENOSRC`` refusal.

    HEAD must be reachable from a remote-tracking ref: the seal's rationale
    is that a unit is *reviewable in a PR before it is ever installable*,
    and a local-only commit — a branch the builder never pushed, a detached
    HEAD nobody else can see — is not (Loki FECF6FED; same shape as gap
    fedcaaba36b7, resolved against branches that never landed). A
    local-only template is therefore not installable through this verb."""
    from .pull_executor import resolve_clone_status

    status = resolve_clone_status(repo, root=root, runner=runner)
    clone = status.get("clone")
    if clone is None:
        if status.get("error") == "EAMBIG":
            return _refuse("ENOSRC", f"{repo!r} resolves to more than one clone: "
                                     f"{status.get('candidates')}")
        return _refuse("ENOSRC", f"no verified clone of {repo!r} under the github root")
    clone = Path(clone)
    head = _git(clone, "rev-parse", "HEAD", runner=runner)
    if head.returncode != 0 or not (head.stdout or "").strip():
        return _refuse("ENOSRC", f"could not read HEAD of {clone}")
    sha = (head.stdout or "").strip()
    on_remote = _git(clone, "branch", "-r", "--contains", "HEAD", runner=runner)
    if on_remote.returncode != 0 or not (on_remote.stdout or "").strip():
        return _refuse("ENOSRC", f"HEAD {sha[:12]} of {repo!r} is not on any remote — "
                                 f"a unit installs from a commit that was reviewable in a PR, "
                                 f"never from a local-only commit")
    return {"ok": True, "clone": clone, "head": sha,
            "remote_refs": [r.strip() for r in on_remote.stdout.splitlines() if r.strip()]}


def _read_tracked(clone: Path, repo: str, rel: str, *, runner) -> dict:
    """One tracked, clean, in-tree regular file at HEAD — or ``ENOSRC``.

    ``git ls-files --error-unmatch`` says git tracks *something* at ``rel``;
    it says nothing about a symlink's target (git tracks the link). A tracked
    symlink pointing outside the tree would install whatever the target holds
    at install time, and the receipt's digest would be of that, not of what a
    PR reviewer saw (Loki FECF6FED). So: refuse a symlink outright
    (``lstat``, and mode ``120000`` from ``ls-files -s``), and refuse any path
    whose realpath is not under the clone's realpath. Digest what the PR
    shows."""
    ls = _git(clone, "ls-files", "-s", "--error-unmatch", "--", rel, runner=runner)
    if ls.returncode != 0:
        return _refuse("ENOSRC", f"{rel!r} is not a tracked file in {repo!r}")
    mode = (ls.stdout or "").split(None, 1)[0] if (ls.stdout or "").strip() else ""
    if mode == "120000":
        return _refuse("ENOSRC", f"{rel!r} in {repo!r} is a tracked symlink — "
                                 f"a unit installs from a file, never through a link")
    dirty = _git(clone, "status", "--porcelain", "--", rel, runner=runner)
    if dirty.returncode != 0:
        return _refuse("ENOSRC", f"could not read the status of {rel!r} in {repo!r}")
    if (dirty.stdout or "").strip():
        return _refuse("ENOSRC", f"{rel!r} in {repo!r} has uncommitted changes — "
                                 f"a unit installs from HEAD, never from a dirty tree")
    path = clone / rel
    if path.is_symlink():
        return _refuse("ENOSRC", f"{rel!r} in {repo!r} is a symlink on disk — "
                                 f"a unit installs from a file, never through a link")
    try:
        inside = path.resolve().is_relative_to(clone.resolve())
    except OSError as exc:
        return _refuse("ENOSRC", f"could not resolve {path}: {exc}")
    if not inside or not path.is_file():
        return _refuse("ENOSRC", f"{rel!r} resolves outside {repo!r}'s tree or is not a regular file")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return _refuse("ENOSRC", f"could not read {path}: {exc}")
    return {"ok": True, "path": path, "text": text}


def _timer_sibling_rel(rel: str) -> Optional[str]:
    """``foo.service.template`` -> ``foo.timer.template`` (a repo-relative
    path, so the timer goes through the SAME tracked/clean/in-tree checks as
    the service; a timer that fails them refuses the install — Loki
    FECF6FED found an untracked sibling being the unit actually enabled)."""
    if not rel.endswith(".service.template"):
        return None
    return rel[: -len(".service.template")] + ".timer.template"


_SECTION_RE = re.compile(r"^\s*\[(?P<name>[^\]]+)\]\s*$")
#: Keys whose values name OTHER units. `enable` honours Alias= (creates the
#: alias name), Also= (enables the named units); the rest bind or order —
#: naming the broker's unit in any of them is content the argument-level
#: EPERM was written to forbid (Loki FECF6FED, finding 3).
_UNIT_NAMING_KEYS = {
    "Install": ("Alias", "Also", "WantedBy", "RequiredBy", "UpheldBy"),
    "Unit": ("Requires", "Requisite", "Wants", "BindsTo", "PartOf", "Upholds",
             "Conflicts", "Before", "After", "OnFailure", "OnSuccess",
             "PropagatesReloadTo", "ReloadPropagatedFrom", "JoinsNamespaceOf"),
    "Timer": ("Unit",),
    "Socket": ("Service",),
    "Path": ("Unit",),
}


def broker_units_named(rendered: str) -> list[str]:
    """Every unit name in the rendered text's naming keys that is the
    broker's — an EPERM before citation when non-empty."""
    hits: list[str] = []
    section = ""
    for raw in rendered.splitlines():
        line = raw.strip()
        m = _SECTION_RE.match(line)
        if m:
            section = m.group("name").strip()
            continue
        if not line or line.startswith(("#", ";")) or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key.strip() not in _UNIT_NAMING_KEYS.get(section, ()):
            continue
        for name in value.split():
            if is_broker_unit(name):
                hits.append(f"[{section}] {key.strip()}={name}")
    return hits


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

    clone_info = _resolve_clone(repo, root=github_root, runner=runner)
    if not clone_info.get("ok"):
        return clone_info
    clone, head_sha = clone_info["clone"], clone_info["head"]
    src = _read_tracked(clone, repo, rel, runner=runner)
    if not src.get("ok"):
        return src
    declared = declared_unit_name(src["text"], src["path"])
    if declared != unit:
        return _refuse(
            "ENAME", f"template {rel!r} declares unit {declared!r}, not {unit!r}",
            declared=declared,
        )
    # The timer sibling is a repo-relative path put through the SAME
    # tracked/clean/in-tree/regular-file checks as the service; an absent
    # sibling is "no timer", a present one that fails them refuses the whole
    # install (a timer is the unit that actually gets enabled).
    timer_rel = _timer_sibling_rel(rel)
    timer_src: Optional[dict] = None
    timer_name = ""
    if timer_rel is not None and (clone / timer_rel).exists():
        timer_src = _read_tracked(clone, repo, timer_rel, runner=runner)
        if not timer_src.get("ok"):
            timer_src["reason"] = f"timer sibling: {timer_src['reason']}"
            return timer_src
        timer_name = declared_unit_name("", timer_src["path"])
    # One value set for the service and its timer: `@UNIT@` is the service
    # in both (a timer's `Unit=` names the service it schedules — rendering
    # them apart is how a timer drifts from its service, which the fleet's
    # own installers render together for exactly that reason).
    vals = dict(values) if values is not None else render_values(unit)
    vals.setdefault("SERVICE_UNIT", unit)
    if timer_name:
        vals.setdefault("TIMER_UNIT", timer_name)
    try:
        rendered = render_template(src["text"], unit, values=vals)
    except ValueError as exc:
        return _refuse("ETEMPLATE", str(exc))
    timer_rendered = ""
    if timer_src is not None:
        try:
            timer_rendered = render_template(timer_src["text"], unit, values=vals)
        except ValueError as exc:
            return _refuse("ETEMPLATE", f"timer sibling {timer_rel}: {exc}")

    # EPERM on CONTENT, not only on the argument: `enable` creates Alias=
    # names and enables Also= units, so a template naming the broker's unit
    # in [Install]/[Unit]/[Timer] reaches the name the argument check forbids.
    named = broker_units_named(rendered) + [f"timer: {h}" for h in broker_units_named(timer_rendered)]
    if named:
        return _refuse(
            "EPERM",
            f"the rendered unit names the broker's own unit — never grantable, "
            f"regardless of bounds: {'; '.join(named)}",
            named=named,
        )

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
    # Replace is reversible: the previous unit is kept beside the new one as
    # `<unit>.pre-install-<ts>` and put back if enable fails, so a failed
    # install never leaves a changed definition of what runs under the
    # operator's identity with only a sha256 surviving (Loki FECF6FED).
    # Every failure after citation inks a FRANK row — the grant was spent.
    root = Path(destination) if destination is not None else unit_dir()
    root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    targets: list[tuple[Path, str]] = [(root / unit, rendered)]
    if timer_src is not None:
        targets.append((root / timer_name, timer_rendered))
    replaced = (root / unit).is_file()
    previous_digest = _digest((root / unit).read_text(encoding="utf-8")) if replaced else ""
    backups: list[tuple[Path, Path]] = []
    written: list[str] = []
    for target, body in targets:
        if target.is_file():
            keep = target.with_name(f"{target.name}.pre-install-{stamp}")
            os.replace(target, keep)
            backups.append((target, keep))
        tmp = target.with_name(target.name + ".new")
        tmp.write_text(body, encoding="utf-8")
        os.replace(tmp, target)
        written.append(str(target))

    def _fail(errno: str, reason: str) -> dict:
        restored = []
        for target, _ in targets:
            try:
                target.unlink()
            except OSError:
                pass
        for target, keep in backups:
            try:
                os.replace(keep, target)
                restored.append(str(target))
            except OSError as exc:  # noqa: PERF203 — report, never hide
                restored.append(f"{target}: restore failed: {exc}")
        out = {"ok": False, "installed": False, "error": errno, "reason": reason,
               "written": written, "restored": restored, "previous_digest": previous_digest,
               "envelope_id": matches[0], "citation_id": result.get("citation_id")}
        try:
            out["receipt_id"] = ledger.append(project, f"{EVENT}_failed", {
                "actor": app_id, "unit": unit, "source": source, "repo": repo, "path": rel,
                "head": head_sha, "errno": errno, "reason": reason, "written": written,
                "restored": restored, "previous_digest": previous_digest,
                "session": session, "citation_id": result.get("citation_id"),
            })
        except Exception as exc:  # noqa: BLE001 — the failure happened; the receipt failing is reported, not hidden
            out["receipt_error"] = f"{type(exc).__name__}: {exc}"
        return out

    enable_target = timer_name or unit
    for argv in (["systemctl", "--user", "daemon-reload"],
                 ["systemctl", "--user", "enable", "--now", enable_target]):
        try:
            proc = _run(argv, runner=runner, timeout=_SYSTEMCTL_TIMEOUT_S)
        except FileNotFoundError:
            return _fail("EUNREACH", "systemctl_missing")
        except subprocess.TimeoutExpired:
            return _fail("ETIMEDOUT", f"{' '.join(argv[2:])} exceeded {_SYSTEMCTL_TIMEOUT_S}s")
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout or "").strip()[-300:]
            return _fail("EINSTALL", tail or f"{' '.join(argv[2:])} exited {proc.returncode}")

    state_after = show_unit(unit, runner=runner)

    receipt_out = {
        "ok": True, "installed": True, "unit": unit, "source": source,
        "repo": repo, "path": rel, "head": head_sha, "remote_refs": clone_info["remote_refs"],
        "template_digest": _digest(src["text"]), "rendered_digest": _digest(rendered),
        "timer_template_digest": _digest(timer_src["text"]) if timer_src else "",
        "replaced": replaced, "previous_digest": previous_digest,
        "previous_kept": [str(k) for _, k in backups],
        "timer": timer_name, "written": written,
        "envelope_id": matches[0], "citation_id": result.get("citation_id"),
        "state_before": state_before, "state_after": state_after,
    }
    try:
        rec = ledger.append(project, EVENT, {
            "actor": app_id, "unit": unit, "source": source, "repo": repo, "path": rel,
            "head": head_sha, "template_digest": receipt_out["template_digest"],
            "rendered_digest": receipt_out["rendered_digest"],
            "timer_template_digest": receipt_out["timer_template_digest"],
            "replaced": replaced, "previous_digest": previous_digest,
            "previous_kept": receipt_out["previous_kept"], "timer": timer_name,
            "active_state_after": state_after.get("ActiveState"),
            "active_enter_after": state_after.get("ActiveEnterTimestamp"),
            "session": session, "citation_id": result.get("citation_id"),
        })
        receipt_out["receipt_id"] = rec
    except Exception as exc:  # noqa: BLE001 — the install happened; the receipt failing is reported, not hidden
        receipt_out["receipt_error"] = f"{type(exc).__name__}: {exc}"
    return receipt_out
