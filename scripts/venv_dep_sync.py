#!/usr/bin/env python3
"""Do the fleet's two willow-mcp venvs agree on shared RUNTIME deps?

The fleet keeps two willow-mcp venvs, on purpose (operator ruling: keep the
split, do not unify):

  RUNTIME   desk hooks + worker units run from this one. Only base
            dependencies belong here — no test tooling.
  DEV/TEST  the repo's `.venv` symlink; carries the `[test]` extra
            (pytest, ruff, ...) on top of the same base.

Both are editable installs against the SAME repo checkout, so the source
code never drifts between them — but each venv's non-editable third-party
packages are installed and upgraded independently, and those CAN drift.
That already caused a real deploy failure: willow-ratatosk sat at 1.2.9 in
one venv and 1.7.0 in the other until both were bumped by hand, and the
stale one was missing `ratatosk.daemon` that seal_daemon.py imports.

This script is the guard against that happening again silently. It is
deliberately narrow: it flags a version mismatch ONLY for a dependency
named in this repo's base `[project.dependencies]` (the "shared runtime
set") — never for a `[project.optional-dependencies]` extra (e.g. `test`),
which the runtime venv is entitled to lack entirely. The shared-runtime set
is derived from pyproject.toml at every run, not hand-maintained here,
so a new base dependency is covered automatically and an extra never leaks
into the comparison by someone editing a list in two places.

Properties: stdlib-only, deterministic, read-only (never installs or
otherwise mutates a venv), and a missing venv degrades to a clean skip
(exit 0, a note on stdout) rather than a crash — this machine is not the
only place this ever runs, and a laptop with only one of the two venvs
present is a normal, unremarkable state.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import tomllib
from dataclasses import dataclass
from importlib.metadata import Distribution, PathDistribution
from pathlib import Path

# The two venvs this fleet actually runs, overridable for testing and for any
# machine that relocates them. Not read from any config file: this script IS
# the config-free deterministic check the operator asked for.
DEFAULT_RUNTIME_VENV = Path(
    "/home/sean-campbell/sean-data-vault/willow-operator-box/venvs/willow-mcp"
)
DEFAULT_DEV_VENV = Path(
    "/home/sean-campbell/github/willow-memory/.willow/venvs/willow-mcp"
)

RUNTIME_VENV_ENV = "WILLOW_MCP_RUNTIME_VENV"
DEV_VENV_ENV = "WILLOW_MCP_DEV_VENV"

# PEP 508 requirement strings start with a distribution name: letters, digits,
# `.`, `-`, `_`, terminated by whitespace or a version/marker/extra delimiter.
_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def canonicalize(name: str) -> str:
    """PEP 503 normalization: this is the only safe way to compare two
    spellings of the same distribution (willow-ratatosk / willow_ratatosk /
    Willow.Ratatosk are all the same package)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def requirement_name(requirement: str) -> str | None:
    """Pull the bare distribution name off a PEP 508 requirement string,
    ignoring version specifiers, markers, and extras — stdlib-only, no
    `packaging` dependency required for this narrow slice."""
    m = _NAME_RE.match(requirement)
    return canonicalize(m.group(1)) if m else None


def shared_runtime_deps(pyproject_path: Path) -> set[str]:
    """The set this check enforces: names from `[project.dependencies]` only.

    Deliberately excludes `[project.optional-dependencies]` in full — that is
    where `test` (pytest, ruff, ...) and the other opt-in extras (nest, voice,
    gcal, ...) live, and the runtime venv is entitled to lack every one of
    them. Derived fresh from pyproject.toml on every run so this set can never
    itself drift from the real dependency list."""
    data = tomllib.loads(pyproject_path.read_text())
    deps = data.get("project", {}).get("dependencies", [])
    names = {requirement_name(r) for r in deps}
    names.discard(None)
    return names  # type: ignore[return-value]


def _site_packages_dirs(venv: Path) -> list[Path]:
    """Every site-packages directory under a venv, across POSIX and Windows
    layouts and whichever Python minor built it — this script never invokes
    the venv's own interpreter, so it cannot ask it directly."""
    if not venv.is_dir():
        return []
    found = list(venv.glob("lib/python3.*/site-packages"))
    found += list(venv.glob("lib64/python3.*/site-packages"))
    win = venv / "Lib" / "site-packages"
    if win.is_dir():
        found.append(win)
    return [d for d in found if d.is_dir()]


def installed_versions(venv: Path) -> dict[str, str] | None:
    """Canonical dist name -> version, read from on-disk dist-info metadata
    only (importlib.metadata against an explicit path). Returns None if the
    venv (or any site-packages dir inside it) cannot be found at all — the
    caller turns that into a clean skip.

    Read-only: this never imports, executes, or otherwise runs anything from
    the target venv, and never installs or modifies it.
    """
    dirs = _site_packages_dirs(venv)
    if not dirs:
        return None
    versions: dict[str, str] = {}
    for site_dir in dirs:
        for dist in _distributions_in(site_dir):
            name = dist.metadata.get("Name")
            version = dist.version
            if not name or not version:
                continue
            versions[canonicalize(name)] = version
    return versions


def _distributions_in(site_dir: Path):
    """Yield PathDistribution objects for every *.dist-info in one
    site-packages directory. Using PathDistribution directly (rather than
    Distribution.discover, which also consults sys.path) keeps this
    hermetic to the directory under inspection."""
    for entry in sorted(site_dir.iterdir()):
        if entry.name.endswith((".dist-info", ".egg-info")):
            dist: Distribution = PathDistribution(entry)
            try:
                if dist.metadata.get("Name"):
                    yield dist
            except Exception:  # pragma: no cover - malformed metadata is rare
                continue


@dataclass(frozen=True)
class Mismatch:
    name: str
    runtime_version: str
    dev_version: str


@dataclass(frozen=True)
class Report:
    """The outcome of one comparison run."""
    skipped: str | None = None          # non-None => clean skip, this is why
    checked: tuple[str, ...] = ()       # shared-runtime deps present in both
    missing: tuple[str, ...] = ()       # shared-runtime deps in pyproject but
                                         # absent from one or both venvs
    mismatches: tuple[Mismatch, ...] = ()

    @property
    def ok(self) -> bool:
        return self.skipped is None and not self.mismatches


def compare(
    pyproject_path: Path,
    runtime_venv: Path,
    dev_venv: Path,
) -> Report:
    """Read-only comparison. Never raises on a missing venv or a malformed
    dist — those degrade into `skipped` / `missing` respectively."""
    shared = shared_runtime_deps(pyproject_path)

    runtime_versions = installed_versions(runtime_venv)
    if runtime_versions is None:
        return Report(skipped=f"runtime venv not found: {runtime_venv}")

    dev_versions = installed_versions(dev_venv)
    if dev_versions is None:
        return Report(skipped=f"dev venv not found: {dev_venv}")

    checked: list[str] = []
    missing: list[str] = []
    mismatches: list[Mismatch] = []
    for name in sorted(shared):
        rt = runtime_versions.get(name)
        dv = dev_versions.get(name)
        if rt is None or dv is None:
            missing.append(name)
            continue
        checked.append(name)
        if rt != dv:
            mismatches.append(Mismatch(name=name, runtime_version=rt, dev_version=dv))

    return Report(
        checked=tuple(checked),
        missing=tuple(missing),
        mismatches=tuple(mismatches),
    )


def _default_pyproject() -> Path:
    return Path(__file__).resolve().parent.parent / "pyproject.toml"


def _env_path(var: str, default: Path) -> Path:
    override = os.environ.get(var)
    return Path(override) if override else default


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pyproject", type=Path, default=None,
                         help="path to willow-mcp's pyproject.toml")
    parser.add_argument("--runtime-venv", type=Path, default=None)
    parser.add_argument("--dev-venv", type=Path, default=None)
    args = parser.parse_args(argv)

    pyproject_path = args.pyproject or _default_pyproject()
    runtime_venv = args.runtime_venv or _env_path(RUNTIME_VENV_ENV, DEFAULT_RUNTIME_VENV)
    dev_venv = args.dev_venv or _env_path(DEV_VENV_ENV, DEFAULT_DEV_VENV)

    report = compare(pyproject_path, runtime_venv, dev_venv)

    if report.skipped:
        print(f"venv-dep-sync skipped: {report.skipped}")
        return 0

    if report.missing:
        print(
            f"venv-dep-sync note: {len(report.missing)} shared-runtime dep(s) "
            f"missing from one venv (not compared): {', '.join(report.missing)}"
        )

    if not report.mismatches:
        print(
            f"venv-dep-sync ok: {len(report.checked)} shared-runtime dep(s) "
            "match across runtime and dev venvs"
        )
        return 0

    print(
        f"::error title=venv-dep-sync::{len(report.mismatches)} shared-runtime "
        "dependency version(s) diverged between the runtime and dev venvs:"
    )
    for m in report.mismatches:
        print(f"  {m.name}: runtime={m.runtime_version} dev={m.dev_version}")
    print(
        "This is exactly how willow-ratatosk 1.2.9/1.7.0 caused a deploy "
        "failure (ratatosk.daemon missing). Reinstall the stale venv's "
        "dependency to match, then re-run this check."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
