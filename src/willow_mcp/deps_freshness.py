"""Dependency freshness check the bootstrap trusts more than ``pip check``.

``pip check`` validates installed packages against each installed
distribution's RECORDED ``Requires-Dist``. For an *editable* install that
metadata is refreshed only by ``pip install -e .`` — so a pyproject pin bumped
AFTER the last install is invisible to it: a warm container keeps the stale
dependency and ``pip check`` still passes. That is the exact hole B-40's
fast-path re-sync was meant to close and didn't (observed live: kartikeya 0.0.5
sitting under a ``>=0.0.7`` pin, ``pip check`` green, the worker unstartable and
four tests red).

This reads the CURRENT ``pyproject.toml`` and checks each dependency's INSTALLED
version against its specifier directly, so a pin bump is caught regardless of
what the editable metadata records. Exit 0 = every pin satisfied; exit 1 = at
least one is not (offenders named on stderr), which the bootstrap turns into an
``pip install -e .`` re-sync.
"""
from __future__ import annotations

import logging
import sys
import tomllib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from packaging.requirements import Requirement

logger = logging.getLogger("willow_mcp.deps_freshness")


def _pyproject_path() -> Path:
    # src/willow_mcp/deps_freshness.py → repo root is parents[2]. Resolving
    # against __file__ (not cwd) is correct: an editable install points back at
    # this source tree, whose pyproject is the pin set that matters.
    return Path(__file__).resolve().parents[2] / "pyproject.toml"


def unsatisfied(pyproject: Path | None = None) -> list[str]:
    """Return one message per ``[project].dependencies`` entry whose INSTALLED
    version does not satisfy the CURRENT specifier (an absent package counts as
    unsatisfied). A dependency whose environment marker does not apply here is
    skipped — the bootstrap installs the base set, so a marker-gated dep that
    isn't installed is not a staleness signal. An unreadable pyproject yields no
    problems: staleness is not ours to assert when we can't read the source of
    truth (fail toward 'fresh', leaving ``pip check`` as the other guard)."""
    path = pyproject or _pyproject_path()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return []
    deps = (data.get("project") or {}).get("dependencies") or []
    problems: list[str] = []
    for raw in deps:
        try:
            req = Requirement(raw)
        except Exception:
            logger.debug("unparseable requirement: %s", raw, exc_info=True)
            continue
        if req.marker is not None and not req.marker.evaluate():
            continue
        try:
            have = version(req.name)
        except PackageNotFoundError:
            problems.append(f"{req.name}: not installed (needs {req.specifier})")
            continue
        if req.specifier and not req.specifier.contains(have, prereleases=True):
            problems.append(
                f"{req.name}: installed {have} does not satisfy {req.specifier}"
            )
    return problems


def main() -> int:
    problems = unsatisfied()
    for p in problems:
        print(f"deps_freshness: {p}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
