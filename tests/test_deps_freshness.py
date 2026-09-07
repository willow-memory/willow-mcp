"""Dependency freshness check — reads the CURRENT pyproject, not the editable
install's stale recorded Requires-Dist (the pip check hole that let kartikeya
0.0.5 sit under a >=0.0.7 pin on a warm container)."""
from __future__ import annotations

from pathlib import Path

from willow_mcp import deps_freshness as df

_REPO = Path(__file__).resolve().parents[1]


def _write(tmp_path: Path, deps: list[str]) -> Path:
    body = "[project]\ndependencies = [\n" + \
           "".join(f'    "{d}",\n' for d in deps) + "]\n"
    p = tmp_path / "pyproject.toml"
    p.write_text(body)
    return p


def test_repo_pyproject_is_satisfied_by_the_installed_venv():
    """The real repo pins must all be satisfied here — this is the green state
    the bootstrap should reach and then skip re-syncing."""
    assert df.unsatisfied(_REPO / "pyproject.toml") == []


def test_installed_but_below_current_pin_is_flagged(tmp_path):
    """The warm-container bug: a package IS installed, but the current pin wants
    a newer version than what's present."""
    problems = df.unsatisfied(_write(tmp_path, ["kartikeya>=99.0"]))
    assert len(problems) == 1
    assert "kartikeya" in problems[0] and "does not satisfy" in problems[0]


def test_absent_package_is_flagged(tmp_path):
    problems = df.unsatisfied(_write(tmp_path, ["definitely-not-installed-pkg>=1"]))
    assert problems and "not installed" in problems[0]


def test_satisfied_pin_is_silent(tmp_path):
    from importlib.metadata import version

    have = version("kartikeya")
    assert df.unsatisfied(_write(tmp_path, [f"kartikeya>={have}"])) == []


def test_inapplicable_marker_is_skipped(tmp_path):
    """A dependency gated behind a marker that doesn't apply here is not a
    staleness signal — the bootstrap installs the base set."""
    assert df.unsatisfied(
        _write(tmp_path, ['nonexistent-pkg>=1; python_version < "3.0"'])) == []


def test_unreadable_pyproject_fails_toward_fresh(tmp_path):
    assert df.unsatisfied(tmp_path / "does-not-exist.toml") == []
    bad = tmp_path / "pyproject.toml"
    bad.write_text("this is { not valid toml")
    assert df.unsatisfied(bad) == []


def test_main_returns_zero_on_the_real_repo():
    assert df.main() == 0
