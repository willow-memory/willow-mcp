"""willow_mcp/package_upgrade_executor.py — an offline install of a tagged
fleet release into a broker-managed venv; nobody types.

Verb 25, ``package.upgrade``. Row 25 is UNSEALED — see the row's own note
in ``syscall-table.json``; ratifying an envelope against ``package.upgrade``
still needs the operator's seal (verb 12, ``envelope.issue``) before any
citation can ever be granted.

History: 28D6C18E -> CD187906 -> 15773FE5 -> C7138BBA -> CACC28EB ->
Loki's re-check 3CBE8D7E (BLOCKERS R1, R2, R3) -> this rework, dispatch
C2EB023A. Records ``f8de1fcb``, ``5db480c7`` are stale; add a THIRD stale
pair here once one is drafted against rework 2 (CACC28EB @ 778c60f).

**R1 — nothing the broker trusts sits where Kart can write it.** Rework 2's
verifier compared the wheel against a reference under
``<willow-mcp checkout>/worktrees/.wheels/<sha>`` — Kart-writable (the
editable install's own checkout, ``bound_rw`` in the live sandbox). The
untrusted build process (the tag's own build hooks, running inside Kart)
could rewrite that reference AND the wheel together and still pass. Fix:

* :func:`_resolve_tag_from_origin` resolves the tag's commit sha with
  ``git ls-remote`` against the clone's own remote URL — using the SAME
  App-token fetch config :mod:`pull_executor` uses (a broker act, no
  lease) — never from the local clone's ``refs/tags/*``/
  ``refs/remotes/origin/*``, which are Kart-writable (only
  ``.git/config``/``.git/hooks`` are read-only bound). A local tag that
  disagrees with origin is refused, never silently overridden. The
  reachability check no longer needs the local clone AT ALL: the resolved
  sha and origin's default branch are fetched into a fresh, throwaway,
  BROKER-PRIVATE bare mirror and the ancestry check runs there.
* Everything the broker verifies, installs, or restores from lives under
  :func:`_private_root` — ``$WILLOW_HOME/package_upgrade/<sha>/`` — which
  Kart cannot see: the sandbox binds ``$WILLOW_HOME`` children BY NAME
  (``store``, ``dispatch``, ``handoffs``, ``mcp_apps``, ``constitutional``,
  ``venvs/*``, …), never the whole vault, so an unlisted child is simply
  absent from every Kart task's view — confirmed against the live sandbox
  manifest this dispatch measured (no ``package_upgrade`` entry anywhere in
  ``bound_ro``/``bound_rw``). The ONLY Kart-writable handoff left is the
  build task's own output wheel, and it is treated as untrusted input from
  the moment it exists.
* The wheel is copied into the private dir, hashed there, verified there,
  re-hashed immediately before ``pip install`` (refusing on any mismatch —
  closes the TOCTOU between verify and install), and that exact private
  copy is what gets installed. Nothing is re-read from the Kart-writable
  build output after the copy.
* Backups live under ``<private_root>/backup`` — never under the
  Kart-writable build root — so a Kart task can no longer choose what the
  broker restores into its own venv on rollback.

The Kart build still gets its OWN copy of the source (it has to — it needs
something to build), under the ordinary Kart-writable build root; but
verification never looks at that copy again once the private archive
exists.

**R2 — rollback only ever acts on a COMPLETE backup.** Rework 2's
docstring claimed rollback was "a no-op when nothing was backed up yet";
the code recomputed the live entry list FRESH at rollback time and deleted
all of it unconditionally, THEN restored whatever ``backups`` held — so a
failure between "verify" and "the backup finishes" deleted the live
package with nothing to put back. :func:`_backup_entries` now writes a
completion manifest (:func:`_write_backup_manifest`) ONLY after every copy
has succeeded; a partial or missing manifest means :func:`_rollback` (via
:func:`_load_backup_manifest`) does nothing at all — never guesses, never
half-restores. A pre-existing file at a backup slot is handled by clearing
the (broker-private, broker-owned) backup directory before each run,
rather than colliding with it.

**R3 — every act-phase exception is caught, not three classes.** Rework
2's ``except`` list was ``_CitedActFailure``, ``TimeoutExpired``,
``OSError`` — a non-dict ``task_status`` result (``AttributeError``) and a
malformed wheel (``zipfile.BadZipFile``) both escaped uncited. The N3
try/except now ends in a final ``except Exception``, still rolling back
through the same manifest-guarded path and citing a receipt that records
the exception's own type name.

Should-fix, closed here: a partial restart (some units restarted before a
later failure) now names ``restarted`` on the failure receipt too, not
only on success.
"""
from __future__ import annotations

import configparser
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import zipfile
from collections.abc import Callable
from pathlib import Path

from . import paths
from .unit_reload_executor import (
    _SYSTEMCTL_TIMEOUT_S,
    _git,
    is_broker_unit,
    liveness_refusal_after_action,
    sample_restart_loop,
    show_unit,
)

VERB = "package.upgrade"
EVENT = "package_upgrade"

#: Errnos for which an ask is worth filing (same set as rows 15/17).
_ASKABLE = frozenset({"ENOENT", "EAMBIG", "EEXPIRED", "EDQUOT", "ENOGRANTS"})

_REPO_RE = re.compile(r"^[\w.-]+/[\w.-]+$")
_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
_VENV_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_DEP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")
_WORKER_UNIT_RE = re.compile(r"^willow-mcp-worker-([A-Za-z0-9]+)\.service$")

_GIT_TIMEOUT_S = 30
_PIP_TIMEOUT_S = 180
_PYTHON_TIMEOUT_S = 30

#: Bounded wait for the Kart build task (N1) and the poll interval within it.
_BUILD_KART_LANE_DEFAULT = "fast"
_BUILD_KART_TIMEOUT_S = 240.0
_BUILD_POLL_INTERVAL_S = 2.0

#: Per package, what THIS process's own code graph shows importing it at
#: runtime — read from the graph, not assumed.
_PACKAGE_IMPORTERS: dict[str, dict] = {
    "kartikeya": {
        "worker_units": (
            "willow-mcp-worker-fast.service",
            "willow-mcp-worker-batch.service",
        ),
        "serve_imports": True,
        "serve_reason": (
            "willow_mcp.server.task_submit does "
            "`from kartikeya import check_kart_task` at every task_submit — "
            "the running serve process keeps the OLD module object loaded "
            "until it restarts, propose-then-seal through the reloader"
        ),
    },
}

#: [build-system].requires entry -> its importable module name. An entry not
#: listed here is EBUILD by name (B1): this verb never guesses an import
#: path from a requirement string. Purely static — no execution anywhere
#: near this dict.
_BUILD_BACKEND_IMPORT_NAMES = {
    "hatchling": "hatchling",
    "hatch-vcs": "hatch_vcs",
    "setuptools": "setuptools",
    "setuptools-scm": "setuptools_scm",
    "wheel": "wheel",
    "poetry-core": "poetry.core",
    "flit-core": "flit_core",
}

_SCRUBBED_ENV_KEEP = ("PATH", "HOME", "USER", "LANG", "LC_ALL")


def _refuse(errno: str, reason: str, **extra) -> dict:
    return {"ok": False, "error": errno, "upgraded": False, "reason": reason, **extra}


class _CitedActFailure(Exception):
    """N3: every early-return inside the post-citation act phase is now a
    raise of this instead, so the ONE ``except`` in
    :func:`execute_package_upgrade` is the only place that decides to roll
    back and write the cited failure receipt."""

    def __init__(self, errno: str, reason: str, **extra):
        super().__init__(reason)
        self.errno = errno
        self.reason = reason
        self.extra = extra


class _RollbackFailure(Exception):
    """AC918C4D F6: raised by :func:`_rollback_from_manifest` (never left
    to raise a bare OSError/AttributeError/whatever) when the restore
    itself fails partway. Carries exactly what a cited EROLLBACK receipt
    needs to name: which entries were already swapped back into place
    (``restored``) and which still sit staged, their ORIGINAL untouched
    (``staged``) — the whole point of stage-then-swap is that this list
    is never "deleted with nothing to show for it"."""

    def __init__(self, reason: str, *, restored: list[str], staged: list[str]):
        super().__init__(reason)
        self.reason = reason
        self.restored = restored
        self.staged = staged


def _run(argv: list[str], *, runner: Callable | None = None,
         timeout: float, env: dict | None = None) -> subprocess.CompletedProcess:
    run = runner or subprocess.run
    use_env = env if env is not None else {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    return run(argv, capture_output=True, text=True, timeout=timeout, check=False, env=use_env)


def package_name(repo: str) -> str:
    """``org/name`` -> ``name``."""
    return repo.split("/", 1)[1]


def tag_version(tag: str) -> str:
    """``v0.3.4`` -> ``0.3.4``; a tag with no leading ``v`` is its own
    version string."""
    if tag[:1].lower() == "v" and tag[1:2].isdigit():
        return tag[1:]
    return tag


def _resolve_repo_clone(repo: str, *, root: Path | None, runner) -> dict:
    """The verified-by-remote-URL clone of ``repo``. R1: this clone is used
    ONLY to read its own remote URL (to know where origin is) — never
    trusted for its own ``refs/tags/*``/``refs/remotes/origin/*``, both
    Kart-writable."""
    from .pull_executor import resolve_clone_status

    status = resolve_clone_status(repo, root=root, runner=runner)
    clone = status.get("clone")
    if clone is None:
        if status.get("error") == "EAMBIG":
            return _refuse("ENOSRC", f"{repo!r} resolves to more than one clone: "
                                     f"{status.get('candidates')}")
        return _refuse("ENOSRC", f"no verified clone of {repo!r} under the github root")
    return {"ok": True, "clone": Path(clone)}


def _remote_url(clone: Path, *, remote: str = "origin", runner) -> str | None:
    proc = _git(clone, "remote", "get-url", remote, runner=runner)
    if proc.returncode != 0:
        return None
    out = (proc.stdout or "").strip()
    return out or None


def _origin_fetch_cfg(repo: str) -> list[str]:
    """The SAME App-token fetch config :func:`pull_executor.execute_pull`
    uses — a broker act, no lease, the token on one subprocess's argv only,
    never in the remote URL or any config file. Empty (plain fetch) when
    the App does not cover this repo."""
    from . import github_app_credentials as gac
    from .pull_executor import _fetch_config_for_app_token

    auth = gac.mint_installation_token(repo)
    if auth.get("ok") and auth.get("mode") == "app":
        return _fetch_config_for_app_token(auth["token"])
    return []


def _resolve_tag_from_origin(clone: Path, repo: str, tag: str, *, mirror_dir: Path, runner) -> dict:
    """R1: the sha is resolved FROM ORIGIN — ``git ls-remote`` against the
    clone's own remote URL, never from the local clone's Kart-writable
    ``refs/tags/*``. A local tag that disagrees with origin's is refused,
    never silently overridden by either side. Reachability is checked
    against a fresh, broker-private bare mirror fetched from origin — the
    local clone is not consulted for this at all past reading its remote
    URL."""
    tag = (tag or "").strip()
    if not tag or not _TAG_RE.match(tag):
        return _refuse("ENOSRC", f"tag {tag!r} is not a well-formed git tag name")

    remote_url = _remote_url(clone, runner=runner)
    if not remote_url:
        return _refuse("ENOSRC", f"could not read {clone}'s own remote URL")
    cfg = _origin_fetch_cfg(repo)

    ls = _git(clone, *cfg, "ls-remote", remote_url, f"refs/tags/{tag}", runner=runner)
    if ls.returncode != 0 or not (ls.stdout or "").strip():
        return _refuse("ENOSRC", f"tag {tag!r} not found on origin ({remote_url})")
    origin_sha = (ls.stdout or "").strip().split()[0]

    # Informational cross-check ONLY: the local ref is Kart-writable and is
    # never the source of truth, but a local tag naming something ELSE than
    # origin is refused rather than silently ignored.
    local = _git(clone, "rev-parse", "--verify", "--quiet", f"refs/tags/{tag}^{{commit}}", runner=runner)
    if local.returncode == 0:
        local_sha = (local.stdout or "").strip()
        if local_sha and local_sha != origin_sha:
            return _refuse(
                "ENOSRC",
                f"local tag {tag!r} ({local_sha[:12]}) disagrees with origin's "
                f"({origin_sha[:12]}) — origin governs, but a disagreement is "
                f"refused rather than silently overridden",
            )

    symref = _git(clone, *cfg, "ls-remote", "--symref", remote_url, "HEAD", runner=runner)
    default_branch = None
    for line in (symref.stdout or "").splitlines():
        if line.startswith("ref: "):
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("refs/heads/"):
                default_branch = parts[1][len("refs/heads/"):]
            break
    if not default_branch:
        return _refuse("ENOSRC", f"could not resolve origin's default branch for {remote_url}")

    mirror_dir.mkdir(parents=True, exist_ok=True)
    init = _git(mirror_dir, "init", "--bare", "-q", runner=runner)
    if init.returncode != 0:
        return _refuse("ENOSRC", f"could not initialise the broker-private mirror at {mirror_dir}")
    fetched = _git(
        mirror_dir, *cfg, "fetch", "-q", remote_url,
        f"refs/tags/{tag}:refs/tags/{tag}",
        f"refs/heads/{default_branch}:refs/heads/{default_branch}",
        runner=runner,
    )
    if fetched.returncode != 0:
        return _refuse(
            "ENOSRC",
            f"could not fetch {tag!r}/{default_branch!r} from origin into the "
            f"broker-private mirror: {(fetched.stderr or fetched.stdout or '').strip()[-300:]}",
        )
    anc = _git(mirror_dir, "merge-base", "--is-ancestor", origin_sha, default_branch, runner=runner)
    if anc.returncode != 0:
        return _refuse(
            "ENOSRC",
            f"tag {tag!r} ({origin_sha[:12]}) does not point at a commit reachable "
            f"from origin's {default_branch!r} — a package installs only from a "
            f"commit that landed on the tracked default branch",
        )
    return {"ok": True, "sha": origin_sha, "default_ref": default_branch, "mirror": mirror_dir}


def refuse_symlinks_in_tree(clone: Path, sha: str, *, runner) -> dict | None:
    """``None`` when the tree at ``sha`` contains no tracked symlink;
    otherwise ``ENOSRC`` naming every symlinked path (F6). ``clone`` here is
    the broker-private mirror (R1) — it has the object, and reading its
    tree is a plain ``git ls-tree``, no different from any other repo."""
    proc = _git(clone, "ls-tree", "-r", sha, runner=runner)
    if proc.returncode != 0:
        return _refuse("ENOSRC", f"could not read the tree at {sha[:12]}")
    links = []
    for line in (proc.stdout or "").splitlines():
        parts = line.split(None, 3)
        if len(parts) == 4 and parts[0] == "120000":
            links.append(parts[3])
    if links:
        return _refuse(
            "ENOSRC",
            f"tree at {sha[:12]} contains symlink(s), never archived: {links!r}",
            symlinks=links,
        )
    return None


def _resolve_venv(venv: str, *, venvs_root: Path) -> dict:
    name = (venv or "").strip()
    if not name or "/" in name or not _VENV_NAME_RE.match(name):
        return _refuse("EVENV", f"venv {venv!r} must be a bare name under {venvs_root}")
    path = (venvs_root / name)
    try:
        resolved = path.resolve()
        inside = resolved.is_relative_to(venvs_root.resolve())
    except OSError as exc:
        return _refuse("EVENV", f"could not resolve {path}: {exc}")
    if not inside:
        return _refuse("EVENV", f"venv {venv!r} resolves outside {venvs_root}")
    if not path.is_dir():
        return _refuse("EVENV", f"venv {venv!r} does not exist under {venvs_root}")
    python = path / "bin" / "python"
    if not python.is_file():
        return _refuse("EVENV", f"venv {venv!r} has no bin/python — not a real venv")
    return {"ok": True, "path": path, "python": python}


def _check_writable(venv_path: Path) -> dict | None:
    if os.access(venv_path, os.W_OK):
        return None
    try:
        owner_uid = venv_path.stat().st_uid
    except OSError:
        owner_uid = None
    return _refuse(
        "EPERM",
        f"this process cannot write {venv_path} (owner uid {owner_uid!r}) — "
        f"never escalated, regardless of what an envelope's bounds say",
        owner_uid=owner_uid,
    )


def declared_dependencies(clone: Path, ref: str, *, runner) -> list[str]:
    """Bare package names from ``[project] dependencies`` at ``ref``."""
    show = _git(clone, "show", f"{ref}:pyproject.toml", runner=runner)
    if show.returncode != 0 or not (show.stdout or "").strip():
        return []
    doc = _load_toml(show.stdout)
    deps = ((doc.get("project") or {}).get("dependencies")) or []
    return _bare_names(deps)


def declared_build_requires(clone: Path, ref: str, *, runner) -> list[str]:
    """Bare package names from ``[build-system] requires`` at ``ref`` (B1)."""
    show = _git(clone, "show", f"{ref}:pyproject.toml", runner=runner)
    if show.returncode != 0 or not (show.stdout or "").strip():
        return []
    doc = _load_toml(show.stdout)
    requires = ((doc.get("build-system") or {}).get("requires")) or []
    return _bare_names(requires)


def declared_console_scripts(clone: Path, ref: str, *, runner) -> dict[str, str]:
    """``{name: target}`` from ``[project.scripts]`` at ``ref``. 3CBE8D7E
    verifier gap: the wheel's ``entry_points.txt`` must match not only the
    NAMES but the TARGETS too, so a wheel cannot claim ``kart`` while
    pointing it somewhere the source never declared."""
    show = _git(clone, "show", f"{ref}:pyproject.toml", runner=runner)
    if show.returncode != 0 or not (show.stdout or "").strip():
        return {}
    doc = _load_toml(show.stdout)
    scripts = (doc.get("project") or {}).get("scripts") or {}
    return dict(scripts) if isinstance(scripts, dict) else {}


def declared_package_roots(clone: Path, ref: str, *, package: str, runner) -> list[str]:
    """The top-level directory name(s) inside the wheel that are legitimate
    package content — 3CBE8D7E verifier gap: without this, a byte-identical
    repo-root file (``tests/test_x.py``, ``tools/y.py``) matches the source
    tree and is accepted as though it were package content. This verb does
    not parse hatchling/setuptools package-discovery configuration; it uses
    the normalized package name itself as the one recognised root, which is
    correct for every layout this verb has ever built (kartikeya included)
    and refuses anything else rather than guess a discovery rule."""
    return [_normalize_dist_name(package).replace("-", "_")]


def _load_toml(text: str) -> dict:
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover — py<3.11 fallback
        import tomli as tomllib  # type: ignore[no-redef]
    try:
        return tomllib.loads(text)
    except Exception:  # noqa: BLE001 — an unparseable pyproject declares nothing, not an error
        return {}


def _bare_names(reqs: list) -> list[str]:
    names: list[str] = []
    for req in reqs:
        m = _DEP_NAME_RE.match(str(req).strip())
        if m:
            names.append(m.group(0))
    return names


def _venv_version(python: Path, pkg: str, *, runner) -> str | None:
    """The installed version of ``pkg`` read in a FRESH subprocess of
    ``python`` — never this process's own already-imported state."""
    proc = _run(
        [str(python), "-c",
         f"import importlib.metadata as m; print(m.version({pkg!r}))"],
        runner=runner, timeout=_PYTHON_TIMEOUT_S,
    )
    if proc.returncode != 0:
        return None
    out = (proc.stdout or "").strip()
    return out or None


def _unsatisfied_dependencies(python: Path, deps: list[str], *, runner) -> list[str]:
    missing = []
    for dep in deps:
        if _venv_version(python, dep, runner=runner) is None:
            missing.append(dep)
    return missing


def _build_backend_import_name(requirement: str) -> str | None:
    return _BUILD_BACKEND_IMPORT_NAMES.get(requirement.replace("_", "-").lower())


def resolve_build_import_names(requires: list[str]) -> dict:
    """STATIC validation only (N2) — a plain dict lookup, no execution.
    ``EBUILD`` by name for any requirement this verb does not recognise."""
    import_names: list[str] = []
    for req in requires:
        name = _build_backend_import_name(req)
        if name is None:
            return _refuse(
                "EBUILD",
                f"[build-system].requires names {req!r}, which this verb does "
                f"not know how to check — add it to _BUILD_BACKEND_IMPORT_NAMES "
                f"before trusting a build",
                requirement=req,
            )
        import_names.append(name)
    return {"ok": True, "import_names": import_names}


def _build_python_candidates() -> list[str]:
    """Offline build-python candidates, from config ONLY (N2): no
    hard-coded, box-specific path remains in this source."""
    override = os.environ.get("WILLOW_PACKAGE_BUILD_PYTHON", "").strip()
    if override:
        return [override]
    extra = os.environ.get("WILLOW_PACKAGE_BUILD_PYTHONS", "").strip()
    if extra:
        return [p for p in extra.split(":") if p]
    return []


def _default_build_scratch_root() -> Path | None:
    """The Kart-writable scratch root for the BUILD's own copy of the
    source and its output wheel — NEVER used for anything the broker
    verifies or installs from (R1: that lives in :func:`_private_root`
    instead). Derived from this module's own file path; override via
    ``WILLOW_MCP_BUILD_SCRATCH`` or the ``work_dir`` parameter."""
    override = os.environ.get("WILLOW_MCP_BUILD_SCRATCH", "").strip()
    if override:
        return Path(override)
    try:
        repo_root = Path(__file__).resolve().parents[2]
    except IndexError:
        return None
    worktrees = repo_root / "worktrees"
    return worktrees if worktrees.is_dir() else None


def _private_root(sha: str, *, override: Path | None = None) -> Path:
    """R1: ``$WILLOW_HOME/package_upgrade/<sha>/`` — everything the broker
    verifies, installs, or restores from lives here. Kart's sandbox binds
    ``$WILLOW_HOME`` children by NAME (``store``, ``dispatch``,
    ``mcp_apps``, ``constitutional``, ``venvs/*``, …), never the vault as a
    whole, so an unlisted child — this one — is simply absent from every
    Kart task's view. ``override`` is a test seam only (``work_dir``-style);
    production always resolves through :func:`paths.willow_home`."""
    if override is not None:
        return Path(override)
    return paths.willow_home() / "package_upgrade" / sha


def _site_packages(python: Path, *, runner) -> Path | None:
    proc = _run(
        [str(python), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
        runner=runner, timeout=_PYTHON_TIMEOUT_S,
    )
    if proc.returncode != 0:
        return None
    out = (proc.stdout or "").strip()
    return Path(out) if out else None


def _pkg_related_entries(site_packages: Path | None, pkg: str) -> list[Path]:
    """Every entry directly under ``site_packages`` that IS ``pkg``."""
    if site_packages is None or not site_packages.is_dir():
        return []
    norm = re.sub(r"[-_.]+", "-", pkg).lower()
    out: list[Path] = []
    for entry in sorted(site_packages.iterdir()):
        name = entry.name
        lowered = name.lower()
        matched_dist = False
        for suffix in (".dist-info", ".egg-info"):
            if lowered.endswith(suffix):
                base_full = name[: -len(suffix)]
                base = base_full.rsplit("-", 1)[0] if "-" in base_full else base_full
                if re.sub(r"[-_.]+", "-", base).lower() == norm:
                    out.append(entry)
                matched_dist = True
                break
        if matched_dist:
            continue
        stem = name.split(".", 1)[0]
        if re.sub(r"[-_.]+", "-", stem).lower() == norm:
            out.append(entry)
    return out


def console_script_paths(venv_path: Path, scripts: list[str]) -> list[Path]:
    """``<venv>/bin/<name>`` for each console-script entry point (B3: the
    prior rollback missed these — pip rewrites them in place on install)."""
    bin_dir = venv_path / "bin"
    return [bin_dir / s for s in scripts]


def _related_paths(site_packages: Path | None, venv_path: Path, pkg: str,
                    scripts: list[str]) -> list[Path]:
    return [p for p in (_pkg_related_entries(site_packages, pkg)
                        + console_script_paths(venv_path, scripts)) if p.exists()]


_BACKUP_MANIFEST_NAME = "manifest.json"


def _backup_entries(entries: list[Path], backup_dir: Path) -> list[tuple[Path, Path]] | None:
    """Copy each entry into its OWN numbered slot under ``backup_dir``
    (broker-private — R1), and write the completion manifest
    (:func:`_write_backup_manifest`) ONLY after every copy has succeeded.
    Returns ``None`` — never a partial list — on any failure, so a caller
    can never mistake a half-finished backup for a complete one (R2). The
    directory is broker-owned scratch space, cleared at the start of every
    run, so a file pre-planted at a backup slot from an earlier attempt is
    simply removed rather than fought with."""
    if backup_dir.exists():
        shutil.rmtree(backup_dir, ignore_errors=True)
    backup_dir.mkdir(parents=True, exist_ok=True)
    pairs: list[tuple[Path, Path]] = []
    try:
        for i, entry in enumerate(entries):
            slot = backup_dir / str(i)
            slot.mkdir(parents=True, exist_ok=True)
            dest = slot / entry.name
            if entry.is_dir():
                shutil.copytree(entry, dest)
            else:
                shutil.copy2(entry, dest)
            pairs.append((entry, dest))
    except OSError:
        return None
    _write_backup_manifest(backup_dir, pairs)
    return pairs


def _write_backup_manifest(backup_dir: Path, pairs: list[tuple[Path, Path]]) -> None:
    manifest = [[str(o), str(d)] for o, d in pairs]
    (backup_dir / _BACKUP_MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")


def _load_backup_manifest(backup_dir: Path | None) -> list[tuple[Path, Path]] | None:
    """R2: the ONLY thing :func:`_rollback` trusts. Missing, unreadable, or
    malformed -> ``None`` -> rollback does nothing, rather than guessing at
    a live filesystem scan the way rework 2 did."""
    if backup_dir is None:
        return None
    manifest_path = backup_dir / _BACKUP_MANIFEST_NAME
    if not manifest_path.is_file():
        return None
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        return [(Path(o), Path(d)) for o, d in raw]
    except (OSError, ValueError, TypeError):
        return None


def _remove_entries(entries: list[Path]) -> None:
    for entry in entries:
        if entry.is_dir():
            shutil.rmtree(entry, ignore_errors=True)
        else:
            try:
                entry.unlink()
            except OSError:
                pass


def _stage_backup(pairs: list[tuple[Path, Path]]) -> list[tuple[Path, Path]]:
    """AC918C4D F6: copy every backed-up entry into a staging path BESIDE
    its target. Touches NOTHING live — no removal, no replace. A raised
    OSError here means the live venv is EXACTLY as it was when rollback
    started; nothing has been staged is nothing has been removed."""
    staged_pairs: list[tuple[Path, Path]] = []
    for original, backup in pairs:
        if not backup.exists():
            continue
        parent = original.parent
        parent.mkdir(parents=True, exist_ok=True)
        staged = parent / (original.name + ".restoring")
        if staged.exists():
            if staged.is_dir():
                shutil.rmtree(staged, ignore_errors=True)
            else:
                try:
                    staged.unlink()
                except OSError:
                    pass
        if backup.is_dir():
            shutil.copytree(backup, staged)
        else:
            shutil.copy2(backup, staged)
        staged_pairs.append((original, staged))
    return staged_pairs


def _swap_staged_into_place(staged_pairs: list[tuple[Path, Path]]) -> list[str]:
    """AC918C4D F6: swap each ALREADY-STAGED entry into place. Every
    entry has a real, complete staged copy on disk before this function
    is ever called (see :func:`_stage_backup`), so a failure partway
    through only affects the ONE entry mid-swap — every other entry's
    original is either already correctly restored or not yet touched at
    all. The one entry mid-swap is never left empty either: its live
    original is moved ASIDE (not removed) before the staged copy takes
    its place, and put BACK if the replace itself fails."""
    restored: list[str] = []
    remaining = list(staged_pairs)
    try:
        while remaining:
            original, staged = remaining[0]
            aside: Path | None = None
            if original.exists() or original.is_symlink():
                aside = original.parent / (original.name + ".rollback-old")
                if aside.exists() or aside.is_symlink():
                    if aside.is_dir():
                        shutil.rmtree(aside, ignore_errors=True)
                    else:
                        try:
                            aside.unlink()
                        except OSError:
                            pass
                os.replace(original, aside)
            try:
                os.replace(staged, original)
            except OSError:
                if aside is not None:
                    os.replace(aside, original)  # put the live entry BACK — never empty
                raise
            if aside is not None:
                if aside.is_dir():
                    shutil.rmtree(aside, ignore_errors=True)
                else:
                    try:
                        aside.unlink()
                    except OSError:
                        pass
            restored.append(str(original))
            remaining.pop(0)
    except OSError as exc:
        raise _RollbackFailure(
            f"{type(exc).__name__}: {exc}",
            restored=restored, staged=[str(o) for o, _ in remaining],
        ) from exc
    return restored


def _rollback_from_manifest(backup_dir: Path | None, *, site_packages: Path | None = None,
                             venv_path: Path | None = None, pkg: str = "", scripts: list[str] | None = None,
                             python: Path, runner) -> str | None:
    """R2/AC918C4D F6: touch NOTHING unless a COMPLETE backup manifest
    exists (no manifest -> nothing was ever safely backed up -> nothing
    is touched, closing Loki's P1/P2). Once a complete manifest DOES
    exist: STAGE every backed-up entry first (no live mutation at all —
    :func:`_stage_backup`), THEN swap each staged entry into place
    (:func:`_swap_staged_into_place`) — never the reverse. The prior
    rework removed every live related entry BEFORE restoring anything,
    so a failure between the removal and the restore left site-packages
    EMPTY (F6's own repro, rollback_restore_raises). Only once the
    manifest's own entries are safely restored are any EXTRA entries the
    install created afterward (e.g. a differently-named dist-info) swept
    up — after the real restore has already succeeded, never before."""
    pairs = _load_backup_manifest(backup_dir)
    if pairs:
        staged_pairs = _stage_backup(pairs)
        _swap_staged_into_place(staged_pairs)
        if venv_path is not None:
            live_now = _related_paths(site_packages, venv_path, pkg, scripts or [])
            manifest_targets = {o for o, _ in pairs}
            extras = [p for p in live_now if p not in manifest_targets]
            _remove_entries(extras)
    return _venv_version(python, pkg, runner=runner)


def _archive_tag(clone: Path, sha: str, dest: Path, *, runner) -> dict:
    """``git archive`` the tag's resolved SHA — never the tag name (F6).
    ``clone`` here is whichever repo already holds the sha's object: the
    broker-private mirror for the reference copy, a plain copy for the
    Kart build's own working tree."""
    dest.mkdir(parents=True, exist_ok=True)
    archive = dest / "src.tar"
    proc = _run(["git", "-C", str(clone), "archive", sha, "-o", str(archive)],
                runner=runner, timeout=_GIT_TIMEOUT_S)
    if proc.returncode != 0:
        return _refuse(
            "ENOSRC",
            f"git archive {sha[:12]} failed: {(proc.stderr or proc.stdout or '').strip()[-300:]}",
        )
    extract = dest / "src"
    extract.mkdir(parents=True, exist_ok=True)
    tproc = _run(["tar", "-xf", str(archive), "-C", str(extract)],
                 runner=runner, timeout=_GIT_TIMEOUT_S)
    if tproc.returncode != 0:
        return _refuse(
            "ENOSRC",
            f"extracting {sha[:12]} failed: {(tproc.stderr or tproc.stdout or '').strip()[-300:]}",
        )
    return {"ok": True, "path": extract}


def _build_task_script(src_dir: Path, wheel_dir: Path, *, version: str,
                        candidates: list[str], import_names: list[str]) -> str:
    """The exact text submitted as the Kart build task (N1). The scrubbed
    env (``scrub``) is the ONLY environment the picked interpreter and pip
    ever see — never ``os.environ`` (3CBE8D7E M35)."""
    return (
        "set -euo pipefail\n"
        "export PYTHONDONTWRITEBYTECODE=1\n"
        "python3 - <<'PYEOF'\n"
        "import os, subprocess, sys\n"
        f"candidates = {candidates!r}\n"
        f"import_names = {import_names!r}\n"
        f"src = {str(src_dir)!r}\n"
        f"wheel_dir = {str(wheel_dir)!r}\n"
        f"version = {version!r}\n"
        "os.makedirs(wheel_dir, exist_ok=True)\n"
        "scrub = {'PATH': '/usr/bin:/bin', 'HOME': os.environ.get('HOME', '/tmp')}\n"
        "picked = None\n"
        "for c in candidates:\n"
        "    if not os.path.isfile(c):\n"
        "        continue\n"
        "    ok = True\n"
        "    for name in import_names:\n"
        "        r = subprocess.run([c, '-c', 'import ' + name], env=scrub,\n"
        "                            capture_output=True, timeout=30)\n"
        "        if r.returncode != 0:\n"
        "            ok = False\n"
        "            break\n"
        "    if ok:\n"
        "        picked = c\n"
        "        break\n"
        "if picked is None:\n"
        "    print('EBUILD: no offline build python among', candidates,\n"
        "          'has', import_names, 'all importable', file=sys.stderr)\n"
        "    sys.exit(12)\n"
        "env = dict(scrub)\n"
        "env['SETUPTOOLS_SCM_PRETEND_VERSION'] = version\n"
        "env['PIP_NO_INDEX'] = '1'\n"
        "proc = subprocess.run(\n"
        "    [picked, '-m', 'pip', 'wheel', '--no-index', '--no-build-isolation',\n"
        "     '--no-deps', '-w', wheel_dir, src],\n"
        "    env=env, capture_output=True, text=True, timeout=120,\n"
        ")\n"
        "sys.stdout.write(proc.stdout)\n"
        "sys.stderr.write(proc.stderr)\n"
        "print('BUILD_PYTHON:' + picked)\n"
        "sys.exit(proc.returncode)\n"
        "PYEOF\n"
    )


def run_kart_build(app_id: str, src_dir: Path, wheel_dir: Path, *, version: str,
                    import_names: list[str], lane: str = _BUILD_KART_LANE_DEFAULT,
                    submit_fn=None, status_fn=None,
                    sleeper: Callable[[float], None] | None = None,
                    timeout: float = _BUILD_KART_TIMEOUT_S,
                    poll_interval: float = _BUILD_POLL_INTERVAL_S) -> dict:
    """N1: the wheel is built by submitting a REAL Kart task and waiting on
    it. ``submit_fn``/``status_fn`` default to
    ``server.task_submit``/``server.task_status``."""
    if submit_fn is None or status_fn is None:
        from . import server
        submit_fn = submit_fn or server.task_submit
        status_fn = status_fn or server.task_status
    candidates = _build_python_candidates()
    task_text = _build_task_script(src_dir, wheel_dir, version=version,
                                    candidates=candidates, import_names=import_names)
    submitted = submit_fn(app_id=app_id, task=task_text, agent="kart", lane=lane)
    if not isinstance(submitted, dict) or not submitted.get("task_id"):
        return _refuse(
            "EBUILD",
            f"could not submit the wheel build as a Kart task: {submitted!r} — "
            f"the broker has no way to build this wheel without executing "
            f"untrusted code itself, and refuses to invent a bypass",
        )
    kart_task_id = submitted["task_id"]
    sleep = sleeper or time.sleep
    elapsed = 0.0
    status: dict | None = None
    while elapsed < timeout:
        status = status_fn(app_id, kart_task_id)
        if not isinstance(status, dict):
            return _refuse(
                "EBUILD",
                f"Kart build task {kart_task_id} returned a non-dict status: {status!r}",
                task_id=kart_task_id,
            )
        st = status.get("status")
        if st in ("completed", "failed"):
            break
        sleep(poll_interval)
        elapsed += poll_interval
    else:
        return _refuse(
            "ETIMEDOUT",
            f"Kart build task {kart_task_id} did not finish within {timeout}s",
            task_id=kart_task_id,
        )
    result = status.get("result") or {}
    if not isinstance(result, dict) or result.get("returncode") != 0:
        return _refuse(
            "EBUILD",
            f"Kart build task {kart_task_id} failed: "
            f"{(result.get('stderr') or result.get('stdout') or result.get('error') or '')[-500:] if isinstance(result, dict) else result!r}",
            task_id=kart_task_id,
        )
    wheels = sorted(Path(wheel_dir).glob("*.whl"))
    if not wheels:
        return _refuse("EBUILD", f"Kart build task {kart_task_id} exited 0 but produced no .whl",
                        task_id=kart_task_id)
    return {"ok": True, "wheel": wheels[0], "task_id": kart_task_id}


def wheel_metadata_version(wheel: Path) -> str | None:
    try:
        with zipfile.ZipFile(wheel) as zf:
            for name in zf.namelist():
                if name.endswith(".dist-info/METADATA"):
                    for line in zf.read(name).decode("utf-8", "replace").splitlines():
                        if line.startswith("Version:"):
                            return line.split(":", 1)[1].strip()
    except (OSError, zipfile.BadZipFile):
        return None
    return None


def wheel_metadata_name(wheel: Path) -> str | None:
    try:
        with zipfile.ZipFile(wheel) as zf:
            for name in zf.namelist():
                if name.endswith(".dist-info/METADATA"):
                    for line in zf.read(name).decode("utf-8", "replace").splitlines():
                        if line.startswith("Name:"):
                            return line.split(":", 1)[1].strip()
    except (OSError, zipfile.BadZipFile):
        return None
    return None


def wheel_entry_points(wheel: Path) -> dict[str, dict[str, str]]:
    """``{group: {name: target}}`` for EVERY entry-point group in the
    wheel's ``entry_points.txt`` — 3CBE8D7E: rework 2 read only
    ``console_scripts`` KEYS; this reads every group and every target."""
    try:
        with zipfile.ZipFile(wheel) as zf:
            for name in zf.namelist():
                if name.endswith(".dist-info/entry_points.txt"):
                    cp = configparser.ConfigParser()
                    cp.read_string(zf.read(name).decode("utf-8", "replace"))
                    return {sec: dict(cp[sec]) for sec in cp.sections()}
    except (OSError, zipfile.BadZipFile, configparser.Error):
        return {}
    return {}


def wheel_console_scripts(wheel: Path) -> list[str]:
    """Backward-compatible: console_scripts NAMES only."""
    return sorted(wheel_entry_points(wheel).get("console_scripts", {}).keys())


def wheel_record_paths(wheel: Path) -> set[str] | None:
    """The set of file paths RECORD lists (excluding RECORD itself), or
    ``None`` if the wheel has no RECORD (some minimal test fixtures)."""
    try:
        with zipfile.ZipFile(wheel) as zf:
            for name in zf.namelist():
                if name.endswith(".dist-info/RECORD"):
                    paths_: set[str] = set()
                    for line in zf.read(name).decode("utf-8", "replace").splitlines():
                        if not line.strip():
                            continue
                        p = line.split(",", 1)[0]
                        if p and not p.endswith("RECORD"):
                            paths_.add(p)
                    return paths_
    except (OSError, zipfile.BadZipFile, UnicodeDecodeError):
        return None
    return None


def wheel_sha256(wheel: Path) -> str:
    h = hashlib.sha256()
    with open(wheel, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _normalize_dist_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _is_pure_wheel(wheel: Path) -> bool:
    """True iff the wheel's own filename declares platform-independence
    (``-none-any.whl``) AND its ``WHEEL`` metadata says
    ``Root-Is-Purelib: true``."""
    if not wheel.name.endswith("-none-any.whl"):
        return False
    try:
        with zipfile.ZipFile(wheel) as zf:
            for member in zf.namelist():
                if member.endswith(".dist-info/WHEEL"):
                    text = zf.read(member).decode("utf-8", "replace")
                    for line in text.splitlines():
                        if line.strip().lower().startswith("root-is-purelib:"):
                            return line.split(":", 1)[1].strip().lower() == "true"
    except (OSError, zipfile.BadZipFile):
        return False
    return False


def verify_wheel_against_source(wheel: Path, src_dir: Path, *, package: str,
                                 version: str, declared_scripts: dict[str, str],
                                 package_roots: list[str] | None = None) -> dict:
    """N2/3CBE8D7E: the build venv is untrusted, so its OUTPUT is verified
    deterministically against a REFERENCE source tree (the caller must pass
    a broker-private ``src_dir`` — R1) before a single byte of it is
    installed. Refuses:

    * ``ENOTPURE`` — not ``py3-none-any``/``Root-Is-Purelib: true``.
    * ``EVERIFY`` — METADATA name/version mismatch; ANY file under a
      declared package root differs byte-for-byte from source; the source
      package is missing a module the wheel does not carry (omission).
    * ``EBUILD`` — a ``.pth`` file; a ``..`` path component; a path with no
      matching source file under a declared package root; console_scripts
      whose names OR targets do not exactly match ``[project.scripts]``;
      any ``gui_scripts`` entry or any entry-point group other than
      ``console_scripts``; a RECORD that names a file not actually in the
      wheel, or omits one that is.

    A wheel member is compared byte-for-byte ONLY when its top-level path
    segment is one of ``package_roots`` (default: the normalized package
    name) — a byte-identical repo-root file (``tests/x.py``) outside every
    declared root is refused as an unmatched extra, never silently
    accepted as though it were package content.
    """
    if not _is_pure_wheel(wheel):
        return _refuse(
            "ENOTPURE",
            f"{wheel.name} is not a pure-Python (py3-none-any, "
            f"Root-Is-Purelib: true) wheel — refused before it is trusted",
        )
    meta_version = wheel_metadata_version(wheel)
    if meta_version != version:
        return _refuse(
            "EVERIFY",
            f"wheel METADATA version {meta_version!r} != tag version {version!r}",
        )
    meta_name = wheel_metadata_name(wheel)
    if meta_name is None or _normalize_dist_name(meta_name) != _normalize_dist_name(package):
        return _refuse(
            "EVERIFY",
            f"wheel METADATA name {meta_name!r} != package {package!r}",
        )

    entry_points = wheel_entry_points(wheel)
    extra_groups = sorted(g for g in entry_points if g != "console_scripts")
    if extra_groups:
        return _refuse(
            "EBUILD",
            f"wheel declares entry-point group(s) this verb never permits: "
            f"{extra_groups!r} (gui_scripts and every other group are refused)",
            extra_groups=extra_groups,
        )
    actual_scripts = entry_points.get("console_scripts", {})
    if actual_scripts != dict(declared_scripts):
        return _refuse(
            "EBUILD",
            f"wheel console_scripts {actual_scripts!r} != pyproject's declared "
            f"{dict(declared_scripts)!r} at the resolved sha (names AND targets "
            f"must match exactly)",
        )

    roots = list(package_roots) if package_roots else [_normalize_dist_name(package).replace("-", "_")]
    src_roots = [src_dir, src_dir / "src"]
    mismatched: list[str] = []
    extra: list[str] = []
    pth_files: list[str] = []
    traversal: list[str] = []
    wheel_pkg_members: set[str] = set()
    with zipfile.ZipFile(wheel) as zf:
        for member in zf.namelist():
            if member.endswith("/") or ".dist-info/" in member:
                continue
            if ".." in Path(member).parts:
                traversal.append(member)
                continue
            if member.endswith(".pth"):
                pth_files.append(member)
                continue
            top = member.split("/", 1)[0]
            if top not in roots:
                extra.append(member)
                continue
            wheel_pkg_members.add(member)
            found = next((r / member for r in src_roots if (r / member).is_file()), None)
            if found is None:
                extra.append(member)
                continue
            # 3CBE8D7E item 3 / 500FCEFB item 1: EVERY matched file under a
            # declared package root is compared byte-for-byte, not only
            # .py — a package data file (e.g. kartikeya/data/*.json) no
            # longer gets a free pass on content just because it exists.
            if found.read_bytes() != zf.read(member):
                mismatched.append(member)
    if traversal:
        return _refuse("EBUILD", f"wheel carries path(s) with a '..' component: {traversal!r}",
                        traversal=traversal)
    if pth_files:
        return _refuse("EBUILD", f"wheel carries .pth file(s), never legitimate here: "
                                  f"{pth_files!r}", pth_files=pth_files)
    if extra:
        return _refuse("EBUILD", f"wheel carries path(s) with no matching source file "
                                  f"under a declared package root {roots!r}: {extra!r}", extra=extra)
    if mismatched:
        return _refuse("EVERIFY", f"wheel module(s) differ byte-for-byte from the "
                                   f"archived source: {mismatched!r}", mismatched=mismatched)

    omitted: list[str] = []
    for root_name in roots:
        for src_root in src_roots:
            pkg_src = src_root / root_name
            if not pkg_src.is_dir():
                continue
            for py in pkg_src.rglob("*.py"):
                rel = f"{root_name}/{py.relative_to(pkg_src).as_posix()}"
                if rel not in wheel_pkg_members:
                    omitted.append(rel)
            break  # only the first existing src_root for this package root
    if omitted:
        return _refuse("EVERIFY", f"source module(s) missing from the wheel (omission): "
                                   f"{sorted(set(omitted))!r}", omitted=sorted(set(omitted)))

    record_paths = wheel_record_paths(wheel)
    if record_paths is not None:
        with zipfile.ZipFile(wheel) as zf:
            actual = {n for n in zf.namelist() if not n.endswith("/") and not n.endswith(".dist-info/RECORD")}
        missing_from_record = sorted(actual - record_paths)
        extra_in_record = sorted(record_paths - actual)
        if missing_from_record or extra_in_record:
            return _refuse(
                "EBUILD",
                f"wheel RECORD does not match its actual contents — "
                f"missing_from_record={missing_from_record!r} "
                f"extra_in_record={extra_in_record!r}",
                missing_from_record=missing_from_record, extra_in_record=extra_in_record,
            )

    return {"ok": True, "sha256": wheel_sha256(wheel)}


def pip_install_offline_argv(python: Path, wheel: Path) -> list[str]:
    """Installs the WHEEL Kart already built and this verb already verified
    (the broker-private COPY, hash-pinned — R1) — never the source tree, and
    never the Kart-writable path again. ``--isolated``: ignore any
    ``pip.conf``/``PIP_*`` the broker's environment carries (F7)."""
    return [str(python), "-m", "pip", "install", "--no-index", "--no-deps",
            "--isolated", str(wheel)]


def scrubbed_install_env() -> dict[str, str]:
    """The environment the broker's own wheel-install call runs under (F7):
    only PATH/HOME/USER/LANG survive."""
    env = {k: v for k, v in os.environ.items() if k in _SCRUBBED_ENV_KEEP}
    env["PIP_CONFIG_FILE"] = "/dev/null"
    env.setdefault("LC_ALL", "C")
    return env


def _pip_install_wheel(python: Path, wheel: Path, *, runner) -> subprocess.CompletedProcess:
    return _run(pip_install_offline_argv(python, wheel), runner=runner,
                timeout=_PIP_TIMEOUT_S, env=scrubbed_install_env())


def _unit_runs_from_venv(unit: str, venv_path: Path, *, runner) -> bool:
    """True iff ``unit``'s OWN ``ExecStart`` names ``venv_path`` (F8a)."""
    proc = _run(["systemctl", "--user", "show", "-p", "ExecStart", "--value", unit],
                runner=runner, timeout=_SYSTEMCTL_TIMEOUT_S)
    if proc.returncode != 0:
        return False
    return str(venv_path) in (proc.stdout or "")


def _lane_for_unit(unit: str) -> str | None:
    """``willow-mcp-worker-fast.service`` -> ``"fast"``."""
    m = _WORKER_UNIT_RE.match(unit)
    return m.group(1) if m else None


def _lane_busy_refusal(app_id: str, lane: str) -> dict | None:
    """F8d: ``EBUSY`` when a task is ``running`` on ``lane``. Fails CLOSED
    when the queue cannot even be read."""
    from . import server

    running = server._lane_running_task_ids(app_id, "kart", lane)
    if running is None:
        return _refuse(
            "EBUSY",
            f"could not confirm the {lane!r} lane is idle before a restart — "
            f"refused rather than guessed; pass force_restart=True to override",
            lane=lane,
        )
    if running:
        return _refuse(
            "EBUSY",
            f"the {lane!r} lane has running task(s) {running!r} — a restart "
            f"would kill them outright; pass force_restart=True to override",
            lane=lane, running=running,
        )
    return None


def _file_ask(app_id: str, *, repo: str, tag: str, venv: str, errno: str, reason: str,
              fields, task_id: str, store=None) -> dict:
    from . import gate_request

    detail = f"{errno}: {reason}"
    if fields:
        detail += f" (fields: {', '.join(str(f) for f in fields)})"
    summary = (
        f"{app_id or 'an agent'} asked to upgrade {repo!r} to {tag!r} in venv "
        f"{venv!r} and was refused: {detail}. Ratify a package.upgrade "
        f"envelope with bounds (repo={repo!r}, tags=[{tag!r}], venv={venv!r}) "
        f"and the agent can ask again."
    )
    return gate_request.open_request(
        app_id or "", f"package.{venv}@upgrade", task_id=task_id, reason=summary, store=store,
    )


def execute_package_upgrade(
    app_id: str,
    *,
    repo: str,
    tag: str,
    venv: str,
    envelope_id: str = "",
    project: str,
    session: str = "",
    task_id: str = "",
    ledger=None,
    store=None,
    runner: Callable | None = None,
    sleeper: Callable[[float], None] | None = None,
    github_root: Path | None = None,
    venvs_root: Path | None = None,
    work_dir: Path | None = None,
    private_root: Path | None = None,
    force_restart: bool = False,
    build_lane: str = _BUILD_KART_LANE_DEFAULT,
    build_timeout: float = _BUILD_KART_TIMEOUT_S,
    submit_fn=None,
    status_fn=None,
) -> dict:
    """Install ``tag`` of ``repo`` into ``venv`` under the ``package.upgrade``
    envelope that governs ``app_id`` — or refuse before any citation, cite
    the refusal, and file the ask.

    R1: the sha is resolved from origin, and every reference the broker
    trusts (source, wheel, backups) lives under a broker-private directory
    Kart cannot see. R2: rollback only ever acts on a complete backup
    manifest. R3: every act-phase exception is caught, cited, and rolled
    back.
    """
    from .envelopes import EnvelopeAuthority, governing_envelopes

    repo = (repo or "").strip()
    tag = (tag or "").strip()
    venv = (venv or "").strip()
    if not repo or not _REPO_RE.match(repo):
        return _refuse("EINVAL", "repo must be `org/name`")
    if not tag:
        return _refuse("EINVAL", "tag must be a non-empty git tag")
    if not venv:
        return _refuse("EINVAL", "venv must be a non-empty name")

    clone_info = _resolve_repo_clone(repo, root=github_root, runner=runner)
    if not clone_info.get("ok"):
        return clone_info
    clone = clone_info["clone"]

    # The private root is keyed by SHA, which we do not have until the tag
    # resolves — the mirror (needed FOR that resolution) lives at a
    # tag-keyed broker-private location instead. A test override names the
    # whole private tree directly (single-sha scenarios); production uses
    # a dedicated, tag-keyed subtree under $WILLOW_HOME/package_upgrade/.
    if private_root is not None:
        mirror_dir = Path(private_root) / "mirror.git"
    else:
        mirror_parent = paths.willow_home() / "package_upgrade" / "_mirrors"
        mirror_dir = mirror_parent / re.sub(r"[^A-Za-z0-9._-]", "_", f"{repo}-{tag}") / "mirror.git"

    tag_info = _resolve_tag_from_origin(clone, repo, tag, mirror_dir=mirror_dir, runner=runner)
    if not tag_info.get("ok"):
        return tag_info
    sha = tag_info["sha"]
    mirror = tag_info["mirror"]

    symlink_refusal = refuse_symlinks_in_tree(mirror, sha, runner=runner)
    if symlink_refusal is not None:
        return symlink_refusal

    root = Path(venvs_root) if venvs_root is not None else (paths.willow_home() / "venvs")
    venv_info = _resolve_venv(venv, venvs_root=root)
    if not venv_info.get("ok"):
        return venv_info
    venv_path, python = venv_info["path"], venv_info["python"]

    perm_refusal = _check_writable(venv_path)
    if perm_refusal is not None:
        return perm_refusal

    pkg = package_name(repo)
    declared_version = tag_version(tag)

    importers = _PACKAGE_IMPORTERS.get(pkg)
    if importers is None:
        return _refuse(
            "ENOIMPORTERS",
            f"{pkg!r} has no _PACKAGE_IMPORTERS entry — this verb refuses to "
            f"upgrade a package it cannot say what to reload",
        )

    deps = declared_dependencies(mirror, sha, runner=runner)
    missing = _unsatisfied_dependencies(python, deps, runner=runner)
    if missing:
        return _refuse(
            "EDEPS",
            f"declared dependencies not already satisfied in {venv!r}: {missing!r}",
            missing=missing,
        )

    build_requires = declared_build_requires(mirror, sha, runner=runner)
    import_names_result = resolve_build_import_names(build_requires)
    if not import_names_result.get("ok"):
        return import_names_result
    import_names = import_names_result["import_names"]

    if not _build_python_candidates():
        return _refuse(
            "EBUILD",
            "no WILLOW_PACKAGE_BUILD_PYTHON(S) configured for this box — this "
            "verb never guesses a box-specific interpreter path (N2); set "
            "WILLOW_PACKAGE_BUILD_PYTHON or WILLOW_PACKAGE_BUILD_PYTHONS",
        )

    worker_units = [
        u for u in importers.get("worker_units", ())
        if not is_broker_unit(u) and _unit_runs_from_venv(u, venv_path, runner=runner)
    ]
    skipped_units = [
        u for u in importers.get("worker_units", ())
        if not is_broker_unit(u) and u not in worker_units
    ]
    if not force_restart:
        for unit in worker_units:
            lane = _lane_for_unit(unit)
            if lane is None:
                continue
            busy = _lane_busy_refusal(app_id, lane)
            if busy is not None:
                return busy

    # ── R1: the broker-private root (Kart cannot see it) and the
    # Kart-writable build scratch root (the build's OWN copy) — two
    # separate roots from here on, never conflated.
    priv = _private_root(sha, override=private_root)
    if work_dir is not None:
        build_root = Path(work_dir)
    else:
        scratch_root = _default_build_scratch_root()
        if scratch_root is None:
            return _refuse(
                "EBUILDROOT",
                "could not determine a Kart-writable build scratch root under "
                "this checkout's worktrees/ directory — set "
                "WILLOW_MCP_BUILD_SCRATCH or pass work_dir explicitly",
            )
        build_root = scratch_root / ".wheels" / sha

    if ledger is None:
        return _refuse(
            "EAMBIG",
            "no governance ledger: an upgrade that cannot be cited is not performed",
        )

    call_args = {"repo": repo, "tags": [tag], "venv": venv}
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
            result["ask"] = _file_ask(app_id, repo=repo, tag=tag, venv=venv, errno="ENOENT",
                                      reason=result["reason"], fields=None,
                                      task_id=task_id, store=store)
            return result
        matches = [envelope_id]
    if not matches:
        result = _refuse("ENOENT", f"no active {VERB} envelope governs {app_id!r}")
        result["ask"] = _file_ask(app_id, repo=repo, tag=tag, venv=venv, errno="ENOENT",
                                  reason=result["reason"], fields=None,
                                  task_id=task_id, store=store)
        return result
    if len(matches) > 1:
        return _refuse(
            "EAMBIG", f"multiple active {VERB} envelopes govern {app_id!r} — "
                      f"pass envelope_id to name which one to cite",
            envelope_ids=matches,
        )

    result = EnvelopeAuthority(ledger).check(
        matches[0], actor=app_id, verb=VERB, call_args=call_args,
    )
    if not result.get("ok"):
        cited = EnvelopeAuthority(ledger).authorize_and_cite(
            matches[0], actor=app_id, verb=VERB, call_args=call_args,
            project=project, session=session,
        )
        errno = result.get("errno", "EAMBIG")
        reason = result.get("reason", "")
        fields = result.get("fields")
        out = _refuse(errno, reason, envelope_id=matches[0],
                      citation_id=cited.get("citation_id"), fields=fields)
        if errno in _ASKABLE:
            out["ask"] = _file_ask(app_id, repo=repo, tag=tag, venv=venv, errno=errno,
                                   reason=out["reason"], fields=fields,
                                   task_id=task_id, store=store)
        return out

    # ── B2: the ONE grant-spending citation, BEFORE any mutation ──────────
    cited = EnvelopeAuthority(ledger).authorize_and_cite(
        matches[0], actor=app_id, verb=VERB, call_args=call_args,
        project=project, session=session,
    )
    if not cited.get("ok"):
        errno = cited.get("errno", "EAMBIG")
        reason = cited.get("reason", "citation refused")
        out = _refuse(errno, reason, envelope_id=matches[0])
        if errno in _ASKABLE:
            out["ask"] = _file_ask(app_id, repo=repo, tag=tag, venv=venv, errno=errno,
                                   reason=reason, fields=None, task_id=task_id, store=store)
        return out
    citation_id = cited.get("citation_id")

    def _cited_failure(errno: str, reason: str, event_suffix: str, **extra) -> dict:
        out = _refuse(errno, reason, envelope_id=matches[0], citation_id=citation_id, **extra)
        try:
            out["receipt_id"] = ledger.append(project, f"{EVENT}_{event_suffix}", {
                "actor": app_id, "repo": repo, "tag": tag, "venv": venv, "pkg": pkg,
                "errno": errno, "reason": reason, "session": session,
                "citation_id": citation_id,
                **{k: v for k, v in extra.items() if k != "citation_id"},
            })
        except Exception as exc:  # noqa: BLE001 — the failure happened; the receipt failing is reported, not hidden
            out["receipt_error"] = f"{type(exc).__name__}: {exc}"
        return out

    # ── the act, all cited from here, ONE try/except (N3) ──────────────────
    backup_dir: Path | None = None
    site_packages: Path | None = None
    scripts_list: list[str] = []
    before_version: str | None = None
    after_version: str | None = None
    wheel_digest: str | None = None
    private_wheel_path: Path | None = None
    build_task_id: str | None = None
    restarted: list[dict] = []

    def _rollback() -> tuple[str | None, _RollbackFailure | None]:
        """AC918C4D F6: a failure INSIDE rollback itself must never
        escape uncited. Returns ``(rolled_back_to, None)`` on success or
        ``(None, failure)`` — the caller turns a non-None failure into
        its OWN cited EROLLBACK receipt rather than letting the
        exception propagate past the act-phase except that called it."""
        try:
            return _rollback_from_manifest(
                backup_dir, site_packages=site_packages, venv_path=venv_path,
                pkg=pkg, scripts=scripts_list, python=python, runner=runner,
            ), None
        except _RollbackFailure as exc:
            return None, exc
        except Exception as exc:  # noqa: BLE001 — rollback's own escape must be cited too, never bare
            return None, _RollbackFailure(f"{type(exc).__name__}: {exc}", restored=[], staged=[])

    def _finish_with_rollback(errno: str, reason: str, **extra) -> dict:
        """AC918C4D F6: the single place every act-phase except calls
        through. If :func:`_rollback` itself failed, the ORIGINAL
        errno/reason are demoted to ``original_errno``/``original_reason``
        and the cited receipt names EROLLBACK instead — a rollback
        failure is never silently absorbed into the triggering error's
        own (potentially misleading, e.g. 'ETIMEDOUT') receipt."""
        rolled_back_to, rollback_failure = _rollback()
        if rollback_failure is not None:
            return _cited_failure(
                "EROLLBACK", rollback_failure.reason, "act_failed",
                before_version=before_version, build_task_id=build_task_id, restarted=restarted,
                original_errno=errno, original_reason=reason,
                restored=rollback_failure.restored, staged=rollback_failure.staged,
            )
        return _cited_failure(
            errno, reason, "act_failed",
            before_version=before_version, rolled_back_to=rolled_back_to,
            build_task_id=build_task_id, restarted=restarted, **extra,
        )

    try:
        priv.mkdir(parents=True, exist_ok=True)
        build_root.mkdir(parents=True, exist_ok=True)

        # The broker-private reference archive (R1) — verification NEVER
        # looks anywhere else.
        priv_archived = _archive_tag(mirror, sha, priv, runner=runner)
        if not priv_archived.get("ok"):
            raise _CitedActFailure(priv_archived["error"], priv_archived["reason"])
        priv_src_dir = priv_archived["path"]

        # The Kart build's OWN copy — untrusted from the moment it exists;
        # a fresh archive from the SAME private mirror, into the
        # Kart-writable build root, so the build has something to read.
        build_archived = _archive_tag(mirror, sha, build_root, runner=runner)
        if not build_archived.get("ok"):
            raise _CitedActFailure(build_archived["error"], build_archived["reason"])
        kart_src_dir = build_archived["path"]

        wheel_dir = build_root / "wheel"
        built = run_kart_build(
            app_id, kart_src_dir, wheel_dir, version=declared_version,
            import_names=import_names, lane=build_lane, sleeper=sleeper,
            timeout=build_timeout, submit_fn=submit_fn, status_fn=status_fn,
        )
        build_task_id = built.get("task_id")
        if not built.get("ok"):
            raise _CitedActFailure(built["error"], built["reason"])
        kart_wheel_path = built["wheel"]

        # R1: copy the untrusted wheel into the private dir and hash it
        # THERE — nothing is re-read from the Kart-writable path again.
        priv_wheel_dir = priv / "wheel"
        priv_wheel_dir.mkdir(parents=True, exist_ok=True)
        private_wheel_path = priv_wheel_dir / kart_wheel_path.name
        shutil.copy2(kart_wheel_path, private_wheel_path)
        wheel_digest = wheel_sha256(private_wheel_path)

        declared_scripts = declared_console_scripts(mirror, sha, runner=runner)
        package_roots = declared_package_roots(mirror, sha, package=pkg, runner=runner)
        verified = verify_wheel_against_source(
            private_wheel_path, priv_src_dir, package=pkg, version=declared_version,
            declared_scripts=declared_scripts, package_roots=package_roots,
        )
        if not verified.get("ok"):
            raise _CitedActFailure(verified["error"], verified["reason"])
        scripts_list = sorted(declared_scripts.keys())

        site_packages = _site_packages(python, runner=runner)
        before_version = _venv_version(python, pkg, runner=runner)
        related = _related_paths(site_packages, venv_path, pkg, scripts_list)
        backup_dir = priv / "backup"
        backups = _backup_entries(related, backup_dir) if related else []
        if related and backups is None:
            raise _CitedActFailure(
                "EIO", f"could not back up {[str(p) for p in related]!r} before install",
            )

        # R1 (TOCTOU close): re-hash the private copy immediately before
        # install and refuse on any mismatch — nothing but this broker
        # process can have touched it since the copy, but the check costs
        # nothing and is the whole point of pinning the hash at all.
        rehash = wheel_sha256(private_wheel_path)
        if rehash != wheel_digest:
            raise _CitedActFailure(
                "EVERIFY",
                f"private wheel copy's sha256 changed between verify and "
                f"install ({wheel_digest} -> {rehash}) — refused rather than "
                f"installing a file that moved under us",
            )

        proc = _pip_install_wheel(python, private_wheel_path, runner=runner)
        if proc.returncode != 0:
            raise _CitedActFailure(
                "EINSTALL", (proc.stderr or proc.stdout or "").strip()[-300:],
            )

        after_version = _venv_version(python, pkg, runner=runner)
        if after_version != declared_version:
            raise _CitedActFailure(
                "EVERIFY",
                f"installed {pkg} reports version {after_version!r} in a fresh "
                f"subprocess, not the tag's declared {declared_version!r}",
                attempted_version=after_version, declared_version=declared_version,
            )

        for unit in worker_units:
            state_before = show_unit(unit, runner=runner)
            n_before = state_before.get("NRestarts")
            rproc = _run(["systemctl", "--user", "restart", unit],
                         runner=runner, timeout=_SYSTEMCTL_TIMEOUT_S)
            loop_sample = sample_restart_loop(unit, runner=runner, sleeper=sleeper)
            state_after = loop_sample["second"]
            dead = liveness_refusal_after_action(loop_sample)
            restarted.append({
                "unit": unit,
                "restart_ok": rproc.returncode == 0,
                "nrestarts_before": n_before,
                "nrestarts_after": state_after.get("NRestarts"),
                "restart_loop": loop_sample["restart_loop"],
                "live": dead is None,
                "dead_reason": dead,
                "state_after": state_after,
            })
    except _CitedActFailure as exc:
        return _finish_with_rollback(exc.errno, exc.reason, **exc.extra)
    except subprocess.TimeoutExpired as exc:
        return _finish_with_rollback("ETIMEDOUT", f"{exc}")
    except OSError as exc:
        return _finish_with_rollback("EIO", f"{type(exc).__name__}: {exc}")
    except Exception as exc:  # noqa: BLE001 — R3: every remaining exception class is cited, rolled back, and its type recorded, never left to escape uncited
        return _finish_with_rollback(
            "EUNEXPECTED", f"{type(exc).__name__}: {exc}", exception_type=type(exc).__name__,
        )

    any_dead = any(not r["live"] for r in restarted)
    serve_imports = bool(importers.get("serve_imports"))

    receipt_out = {
        "ok": not any_dead, "upgraded": True, "repo": repo, "tag": tag, "venv": venv,
        "pkg": pkg, "before_version": before_version, "after_version": after_version,
        "tag_sha": sha, "wheel": str(private_wheel_path), "wheel_sha256": wheel_digest,
        "build_task_id": build_task_id,
        "restarted": restarted, "skipped_units": skipped_units,
        "serve_reload_required": serve_imports,
        "serve_reload_reason": importers.get("serve_reason", "") if serve_imports else "",
        "envelope_id": matches[0], "citation_id": citation_id,
        "force_restart": force_restart,
    }
    if any_dead:
        receipt_out["error"] = "EDEAD"
        receipt_out["reason"] = (
            f"installed {pkg} {after_version} but the restart left "
            f"{[r['unit'] for r in restarted if not r['live']]!r} not stably live"
        )
    try:
        receipt_out["receipt_id"] = ledger.append(project, EVENT, {
            "actor": app_id, "repo": repo, "tag": tag, "venv": venv, "pkg": pkg,
            "before_version": before_version, "after_version": after_version,
            "tag_sha": sha, "wheel_sha256": wheel_digest, "build_task_id": build_task_id,
            "restarted": restarted, "skipped_units": skipped_units,
            "serve_reload_required": serve_imports,
            "session": session, "citation_id": citation_id, "any_dead": any_dead,
            "force_restart": force_restart,
        })
    except Exception as exc:  # noqa: BLE001 — the install happened; the receipt failing is reported, not hidden
        receipt_out["receipt_error"] = f"{type(exc).__name__}: {exc}"
    return receipt_out
