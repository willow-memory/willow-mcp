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

What the bounds judge (Loki 0B774ED3 + 1AEBF250, enumerated from what
``systemctl --user enable --now <unit>`` can create or start): the unit,
its timer sibling, every ``[Install] Alias=``/``Also=`` name, the
activation target of a ``.timer``/``.socket``/``.path``, and every
non-``.target`` name in the ``[Unit]`` start keys ``Requires=``/``Wants=``/
``BindsTo=``/``Upholds=`` (pulled into the same start transaction) and
``OnFailure=``/``OnSuccess=`` (started later). Scope — stated, not judged:

* a ``.target`` install is a dependency hub: starting it also starts every
  *already-installed* unit that elected into it from its own ``[Install]
  WantedBy=``/``RequiredBy=``/``UpheldBy=`` — outside the template's
  content, so it cannot be judged from it;
* the installed unit's own ``WantedBy=``/``RequiredBy=``/``UpheldBy=``
  symlinks create no new unit — the created NAME is the installed unit's,
  which is judged; the directory owner is not;
* ``DefaultInstance=`` is the argument: ``_UNIT_RE`` admits ``foo@.service``
  and an instance name is what ``unit`` names, so it is judged as ``unit``;
* ``.target`` names in the start keys are exempt (ambient system targets —
  otherwise every envelope lists ``default.target``); ``Requisite=``/
  ``Conflicts=``/``PartOf=``/``Before=``/``After=`` are conditions and
  ordering, not starts — exempt; ``.d/`` drop-ins are refused by
  ``_UNIT_RE``.
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


#: Backups kept per unit after a successful replace; older ones are pruned
#: and named in the receipt. Bounded so `previous_kept` cannot grow forever
#: (Loki 02195799).
BACKUPS_KEPT = 3
_BACKUP_TAG = ".pre-install-"


def _fresh_backup_path(target: Path, stamp: str) -> Path:
    """``<unit>.pre-install-<µs stamp>``, with a counter suffix when that
    name already exists — a second install in the same instant never
    overwrites the first's backup."""
    keep = target.with_name(f"{target.name}{_BACKUP_TAG}{stamp}")
    n = 1
    while keep.exists():
        keep = target.with_name(f"{target.name}{_BACKUP_TAG}{stamp}-{n}")
        n += 1
    return keep


#: The only backup names this verb writes: `<stamp>` is `%Y%m%dT%H%M%S.%fZ`,
#: optionally `-N`. Anything else beside a unit is not ours to prune (Loki
#: 0B774ED3: a `…pre-install-junk` file sorted as "newest" and a real backup
#: was deleted in its place).
_BACKUP_STAMP_RE = re.compile(r"^\d{8}T\d{6}\.\d{6}Z(-\d+)?$")


def _prune_backups(target: Path, keep_n: int = BACKUPS_KEPT) -> tuple[list[str], list[str]]:
    """Delete all but the newest ``keep_n`` STAMP-SHAPED backups of ``target``
    (lexical order on the stamp is chronological). Returns ``(pruned,
    unrecognised)`` — a file under the backup prefix whose suffix is not a
    stamp is left alone and named, never counted as newest."""
    prefix = f"{target.name}{_BACKUP_TAG}"
    stamped: list[Path] = []
    unrecognised: list[str] = []
    for p in target.parent.iterdir():
        if not p.name.startswith(prefix) or not p.is_file():
            continue
        if _BACKUP_STAMP_RE.match(p.name[len(prefix):]):
            stamped.append(p)
        else:
            unrecognised.append(str(p))
    stamped.sort()
    pruned: list[str] = []
    for old in stamped[:-keep_n] if keep_n > 0 else stamped:
        try:
            old.unlink()
            pruned.append(str(old))
        except OSError as exc:
            pruned.append(f"{old}: prune failed: {exc}")
    return pruned, sorted(unrecognised)


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
    template asks for beyond these is ``ETEMPLATE``.

    ``TRUST_OWNER`` (added for ``willow-mcp-manifest-grant.service``, Loki
    audit 3 finding 3): the username that owns ``$WILLOW_HOME/mcp_apps`` —
    the identity a trust-owner unit's ``User=`` must run as, resolved from
    the filesystem rather than guessed from this process's own ``$USER``
    (which, run from the broker's own session, names the broker — the one
    identity the design says never publishes). Left out of the values
    entirely (never filled with an empty or wrong guess) when
    ``mcp_apps`` does not exist yet or the owning uid has no passwd entry;
    a template asking for ``@TRUST_OWNER@`` then refuses ``ETEMPLATE`` by
    name instead of silently rendering the broker's own identity in.

    ``WILLOW_KEYRING`` / ``WILLOW_PGP_FINGERPRINT`` are filled from this
    process's own environment when set — same "resolved values, not
    guesses" rule; a template needing one that is unset here refuses
    ``ETEMPLATE`` rather than rendering an empty ``Environment=`` line."""
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
    apps_root = Path(os.environ.get("WILLOW_MCP_APPS_ROOT", paths.willow_home() / "mcp_apps"))
    try:
        import pwd
        if apps_root.is_dir():
            values["TRUST_OWNER"] = pwd.getpwuid(apps_root.stat().st_uid).pw_name
    except (OSError, KeyError):  # noqa: BLE001 — no owner resolvable; leave unfilled, refuse by name
        pass
    for env_key in ("WILLOW_KEYRING", "WILLOW_PGP_FINGERPRINT"):
        val = os.environ.get(env_key, "").strip()
        if val:
            values[env_key] = val
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


def _file_ask(app_id: str, *, units: list[str], source: str, errno: str, reason: str,
              fields, task_id: str, store=None) -> dict:
    """Same surface as :func:`unit_reload_executor._file_ask` — a ``unit.``
    row on ``gates``; ``@install`` on the gate id tells the panel this is
    verb 17, not verb 15. ``units`` is the full judged set (the unit and
    every name the enable creates or starts), so the bounds the ask
    proposes are the bounds that would grant it — an ask naming only the
    installed unit refused again on the same Also= (Loki 1AEBF250)."""
    from . import gate_request

    unit = units[0]
    detail = f"{errno}: {reason}"
    if fields:
        detail += f" (fields: {', '.join(str(f) for f in fields)})"
    summary = (
        f"{app_id or 'an agent'} asked to install unit {unit!r} from {source!r} "
        f"and was refused: {detail}. Ratify a unit.install envelope with bounds "
        f"(units={list(units)!r}, sources=[{source!r}]) and the agent can ask again."
    )
    return gate_request.open_request(
        app_id or "", f"unit.{unit}@install", task_id=task_id, reason=summary, store=store,
    )


def _outside_bounds(rows: list[dict], envelope_id: str, *, judged: list[str], source: str) -> list[str]:
    """The judged names the cited envelope's bounds do not list, as
    ``units=[...]`` / ``sources=[...]`` strings for a refusal reason; empty
    when the envelope's row is not among ``rows`` or its bounds are not the
    list shape (the gate already said why)."""
    bounds = next((r.get("bounds") for r in rows if r.get("id") == envelope_id), None)
    if not isinstance(bounds, dict):
        return []
    out: list[str] = []
    granted_units = bounds.get("units")
    if isinstance(granted_units, list):
        missing = [u for u in judged if u not in granted_units]
        if missing:
            out.append(f"units not in bounds: {missing!r}")
    granted_sources = bounds.get("sources")
    if isinstance(granted_sources, list) and source not in granted_sources:
        out.append(f"source not in bounds: {source!r}")
    return out


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
    # Only the NAMED repo's remote counts: resolve_clone_status verified that
    # `origin` is org/name, so a ref under origin/* is a commit reviewable in
    # a PR on that repo. A `fork` remote the builder controls is not (Loki
    # 02195799): filter before judging.
    on_remote = _git(clone, "branch", "-r", "--contains", "HEAD", runner=runner)
    if on_remote.returncode != 0:
        return _refuse("ENOSRC", f"could not read remote refs of {clone}")
    origin_refs = [
        r.strip().split(" ", 1)[0] for r in (on_remote.stdout or "").splitlines()
        if r.strip().split(" ", 1)[0].startswith("origin/")
        and r.strip().split(" ", 1)[0] != "origin/HEAD"
    ]
    if not origin_refs:
        return _refuse("ENOSRC", f"HEAD {sha[:12]} of {repo!r} is not on origin — "
                                 f"a unit installs from a commit that was reviewable in a PR "
                                 f"on the named repo, never from a local-only or fork-only commit")
    return {"ok": True, "clone": clone, "head": sha, "remote_refs": origin_refs}


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
#: alias name), Also= (enables the named units); the rest bind, start or
#: order — naming the broker's unit in any of them is content the
#: argument-level EPERM was written to forbid (Loki FECF6FED, finding 3).
#: This is the broker-name sweep; which of these the BOUNDS judge is
#: :func:`enable_effects`.
_UNIT_NAMING_KEYS = {
    "Install": ("Alias", "Also", "WantedBy", "RequiredBy", "UpheldBy"),
    "Unit": ("Requires", "Requisite", "Wants", "BindsTo", "PartOf", "Upholds",
             "Conflicts", "Before", "After", "OnFailure", "OnSuccess",
             "PropagatesReloadTo", "ReloadPropagatedFrom", "JoinsNamespaceOf"),
    "Timer": ("Unit",),
    "Socket": ("Service",),
    "Path": ("Unit",),
}


def _logical_lines(text: str) -> list[str]:
    """The unit file as systemd reads it: a line ending in a backslash is
    concatenated with the following line (systemd.syntax). Parsing physical
    lines let `WantedBy=default.target \\` + `willow-mcp-serve.service` hide
    the broker's name on a line with no `=` (Loki 02195799). Section and key
    names stay case-sensitive, as systemd's are — `[install] alias=` is not
    an escape because systemd ignores it too."""
    out: list[str] = []
    buf = ""
    for raw in text.splitlines():
        if raw.rstrip().endswith("\\"):
            buf += raw.rstrip()[:-1].rstrip() + " "
            continue
        out.append((buf + raw.lstrip()) if buf else raw)
        buf = ""
    if buf:
        out.append(buf)
    return out


def unit_keys(rendered: str, section: str) -> dict[str, list[str]]:
    """``{key: [values...]}`` for one section of the rendered text, over
    logical lines, last-assignment-wins per systemd but every value kept so a
    repeated key is judged in full."""
    found: dict[str, list[str]] = {}
    current = ""
    for raw in _logical_lines(rendered):
        line = raw.strip()
        m = _SECTION_RE.match(line)
        if m:
            current = m.group("name").strip()
            continue
        if current != section or not line or line.startswith(("#", ";")) or "=" not in line:
            continue
        key, _, value = line.partition("=")
        found.setdefault(key.strip(), []).append(value.strip())
    return found


def broker_units_named(rendered: str) -> list[str]:
    """Every unit name in the rendered text's naming keys that is the
    broker's — an EPERM before citation when non-empty."""
    hits: list[str] = []
    for section, keys in _UNIT_NAMING_KEYS.items():
        found = unit_keys(rendered, section)
        for key in keys:
            for value in found.get(key, ()):
                for name in value.split():
                    if is_broker_unit(name):
                        hits.append(f"[{section}] {key}={name}")
    return hits


#: Per unit type, the section+key naming what `enable --now <unit>` starts.
_ACTIVATION_KEY = {"timer": ("Timer", "Unit"), "socket": ("Socket", "Service"), "path": ("Path", "Unit")}
#: `[Unit]` keys whose units `start` pulls into the same transaction
#: (Requires/Wants/BindsTo/Upholds) or starts afterwards (OnFailure/
#: OnSuccess). Requisite=/Conflicts=/PartOf=/Before=/After= are conditions
#: and ordering, not starts (Loki 1AEBF250).
_START_KEYS = ("Requires", "Wants", "BindsTo", "Upholds", "OnFailure", "OnSuccess")


def enable_effects(rendered: str, unit_name: str) -> dict:
    """Every unit name ``systemctl enable --now <unit_name>`` will CREATE or
    START from this rendered text, so the envelope's bounds can judge all of
    it (Loki 0B774ED3, 1AEBF250):

    * ``creates``: ``[Install] Alias=`` names (symlinks created) and
      ``Also=`` units (enabled alongside);
    * ``activates``: for a ``.timer``/``.socket``/``.path`` the unit its
      activation key names, last assignment wins as in systemd, or absent
      the ``.service`` on the same stem; ``""`` for any other type;
    * ``starts``: every non-``.target`` name in the ``[Unit]`` start keys
      (:data:`_START_KEYS`) — pulled in by ``start``, for a direct
      ``.target`` install as much as for a service. ``.target`` names are
      ambient (``default.target``, ``network-online.target``) and exempt.

    The service+timer sibling rule of 02195799 is the special case of this.
    """
    install = unit_keys(rendered, "Install")
    creates: list[str] = []
    for key in ("Alias", "Also"):
        for value in install.get(key, ()):
            creates.extend(n for n in value.split() if n)
    activates = ""
    suffix = unit_name.rsplit(".", 1)[-1] if "." in unit_name else ""
    if suffix in _ACTIVATION_KEY:
        section, key = _ACTIVATION_KEY[suffix]
        values = unit_keys(rendered, section).get(key, [])
        if values and values[-1].strip():
            activates = values[-1].strip()
        else:
            activates = unit_name[: -len(suffix) - 1] + ".service"
    section_unit = unit_keys(rendered, "Unit")
    starts: list[str] = []
    for key in _START_KEYS:
        for value in section_unit.get(key, ()):
            for name in value.split():
                if name and not name.endswith(".target") and name not in starts:
                    starts.append(name)
    return {"creates": creates, "activates": activates, "starts": starts}


def timer_activates(timer_rendered: str, timer_name: str) -> str:
    """Kept for readers of 02195799's fix; :func:`enable_effects` is the rule."""
    return enable_effects(timer_rendered, timer_name)["activates"]


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
    from .envelopes import EnvelopeAuthority, governing_envelopes

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

    # Everything `enable --now` will CREATE or START, for the installed unit
    # and its sibling, is judged: an activation target that is not the
    # installed service (or the sibling pair's own service) is ENAME naming
    # both, and every created/enabled name rides in the cited bounds below
    # (Loki 02195799 for the service->timer pair; 0B774ED3 generalised it to
    # direct .timer/.socket/.path installs and [Install] Alias=/Also=).
    effects = enable_effects(rendered, unit)
    activates = effects["activates"]
    if activates and activates != unit:
        # A direct .timer/.socket/.path install: its target must be the
        # same-stem service it ships for — the only unit the bounds could
        # have meant by naming this one.
        stem_service = unit.rsplit(".", 1)[0] + ".service"
        if activates != stem_service:
            return _refuse(
                "ENAME",
                f"{unit!r} activates {activates!r}, not {stem_service!r} — a "
                f"{unit.rsplit('.', 1)[-1]} installs only for the service it ships with",
                declared=activates, activates=activates,
            )
    creates = list(effects["creates"])
    starts = list(effects["starts"])
    if timer_src is not None:
        timer_effects = enable_effects(timer_rendered, timer_name)
        activates = timer_effects["activates"]
        if activates != unit:
            return _refuse(
                "ENAME",
                f"timer {timer_name!r} activates {activates!r}, not {unit!r} — a timer "
                f"installs only beside the service it schedules",
                declared=activates, timer=timer_name, activates=activates,
            )
        creates.extend(timer_effects["creates"])
        starts.extend(n for n in timer_effects["starts"] if n not in starts)

    if ledger is None:
        return _refuse(
            "EAMBIG",
            "no governance ledger: an install that cannot be cited is not performed",
        )

    # The cited call names everything the enable will write, create, enable
    # or start — the unit, its sibling, every Alias=/Also= name, the
    # activation target, and every [Unit] start-dependency — so the
    # envelope's bounds judge all of it. An activation target equal to the
    # installed unit adds nothing; a direct timer/socket/path's same-stem
    # service does ride along.
    judged: list[str] = [unit]
    for name in ([timer_name] if timer_name else []) + creates + ([activates] if activates else []) + starts:
        if name and name not in judged:
            judged.append(name)
    call_args = {"units": judged, "sources": [source]}
    try:
        rows = governing_envelopes(VERB, app_id)
    except (OSError, ValueError) as exc:
        return _refuse("EAMBIG", f"envelope registry unreadable: {exc}")
    matches = [row["id"] for row in rows]
    if envelope_id:
        if envelope_id not in matches:
            result = _refuse(
                "ENOENT", f"envelope {envelope_id!r} does not govern {VERB} "
                          f"for {app_id!r}", envelope_ids=matches,
            )
            result["ask"] = _file_ask(app_id, units=judged, source=source, errno="ENOENT",
                                      reason=result["reason"], fields=None,
                                      task_id=task_id, store=store)
            return result
        matches = [envelope_id]
    if not matches:
        result = _refuse("ENOENT", f"no active {VERB} envelope governs {app_id!r}")
        result["ask"] = _file_ask(app_id, units=judged, source=source, errno="ENOENT",
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
        reason = result.get("reason", "")
        fields = result.get("fields")
        # A bounds miss names the VALUE, not only the field: the offending
        # unit is usually an Also=/Wants=/activation extra, not `unit`
        # itself, and an ask proposing `units=[unit]` would refuse again on
        # the same name (Loki 1AEBF250).
        outside = _outside_bounds(rows, matches[0], judged=judged, source=source)
        if fields and outside:
            reason = f"{reason}: {'; '.join(outside)}"
        out = _refuse(errno, reason, envelope_id=matches[0],
                      citation_id=result.get("citation_id"), fields=fields)
        if errno in _ASKABLE:
            out["ask"] = _file_ask(app_id, units=judged, source=source, errno=errno,
                                   reason=out["reason"], fields=fields,
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
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    targets: list[tuple[Path, str]] = [(root / unit, rendered)]
    if timer_src is not None:
        targets.append((root / timer_name, timer_rendered))
    replaced = (root / unit).is_file()
    previous_digest = _digest((root / unit).read_text(encoding="utf-8")) if replaced else ""
    backups: list[tuple[Path, Path]] = []
    written: list[str] = []
    for target, body in targets:
        if target.is_file():
            keep = _fresh_backup_path(target, stamp)
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
    pruned: list[str] = []
    unrecognised: list[str] = []
    for target, _ in targets:
        p, u = _prune_backups(target)
        pruned.extend(p)
        unrecognised.extend(u)

    receipt_out = {
        "ok": True, "installed": True, "unit": unit, "source": source,
        "repo": repo, "path": rel, "head": head_sha, "remote_refs": clone_info["remote_refs"],
        "template_digest": _digest(src["text"]), "rendered_digest": _digest(rendered),
        "timer_template_digest": _digest(timer_src["text"]) if timer_src else "",
        "replaced": replaced, "previous_digest": previous_digest,
        "previous_kept": [str(k) for _, k in backups], "pruned": pruned,
        "unrecognised_backups": unrecognised,
        "timer": timer_name, "activates": activates, "creates": creates,
        "starts": starts, "judged_units": judged, "enabled": enable_target,
        "written": written,
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
            "previous_kept": receipt_out["previous_kept"], "pruned": pruned,
            "unrecognised_backups": unrecognised,
            "timer": timer_name, "activates": activates, "creates": creates,
            "starts": starts, "judged_units": judged, "enabled": enable_target,
            "active_state_after": state_after.get("ActiveState"),
            "active_enter_after": state_after.get("ActiveEnterTimestamp"),
            "session": session, "citation_id": result.get("citation_id"),
        })
        receipt_out["receipt_id"] = rec
    except Exception as exc:  # noqa: BLE001 — the install happened; the receipt failing is reported, not hidden
        receipt_out["receipt_error"] = f"{type(exc).__name__}: {exc}"
    return receipt_out
