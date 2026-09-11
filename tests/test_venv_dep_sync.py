"""The fleet keeps two willow-mcp venvs on purpose (operator ruling: keep the
runtime/dev split, do not unify). scripts/venv_dep_sync.py is the guard
against their shared RUNTIME dependencies drifting apart the way
willow-ratatosk did (1.2.9 vs 1.7.0 -> a real deploy failure, ratatosk.daemon
missing). These tests build fake venv metadata under tmp_path — real
dist-info directories, so the check is exercised against the same on-disk
shape importlib.metadata reads in production, without touching either real
fleet venv.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).resolve().parent.parent / "scripts" / "venv_dep_sync.py"
_spec = importlib.util.spec_from_file_location("venv_dep_sync", _MODULE_PATH)
venv_dep_sync = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = venv_dep_sync
_spec.loader.exec_module(venv_dep_sync)

compare = venv_dep_sync.compare
shared_runtime_deps = venv_dep_sync.shared_runtime_deps
canonicalize = venv_dep_sync.canonicalize
requirement_name = venv_dep_sync.requirement_name

PYPROJECT = """
[project]
name = "willow-mcp"
dependencies = [
    "willow-ratatosk>=1.7.0,<2.0.0",
    "requests>=2.31,<3.0",
]

[project.optional-dependencies]
test = [
    "pytest",
    "ruff==0.15.0",
]
"""


def _make_dist_info(site_dir: Path, name: str, version: str) -> None:
    d = site_dir / f"{name.replace('-', '_')}-{version}.dist-info"
    d.mkdir(parents=True)
    (d / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
    )


def _venv(tmp_path: Path, tag: str, dists: dict[str, str]) -> Path:
    venv = tmp_path / tag
    site = venv / "lib" / "python3.14" / "site-packages"
    site.mkdir(parents=True)
    for name, version in dists.items():
        _make_dist_info(site, name, version)
    return venv


@pytest.fixture
def pyproject(tmp_path: Path) -> Path:
    p = tmp_path / "pyproject.toml"
    p.write_text(PYPROJECT)
    return p


def test_matched_shared_runtime_versions_pass(tmp_path: Path, pyproject: Path):
    runtime = _venv(tmp_path, "runtime", {
        "willow-ratatosk": "1.7.0", "requests": "2.34.2",
    })
    dev = _venv(tmp_path, "dev", {
        "willow-ratatosk": "1.7.0", "requests": "2.34.2", "pytest": "9.1.1",
    })
    report = compare(pyproject, runtime, dev)
    assert report.ok
    assert report.skipped is None
    assert not report.mismatches
    assert "willow-ratatosk" in report.checked
    assert "requests" in report.checked


def test_shared_runtime_mismatch_is_flagged_loud(tmp_path: Path, pyproject: Path):
    # Exactly the real failure: willow-ratatosk 1.2.9 on one venv, 1.7.0 on
    # the other.
    runtime = _venv(tmp_path, "runtime", {
        "willow-ratatosk": "1.2.9", "requests": "2.34.2",
    })
    dev = _venv(tmp_path, "dev", {
        "willow-ratatosk": "1.7.0", "requests": "2.34.2",
    })
    report = compare(pyproject, runtime, dev)
    assert not report.ok
    assert len(report.mismatches) == 1
    m = report.mismatches[0]
    assert m.name == "willow-ratatosk"
    assert m.runtime_version == "1.2.9"
    assert m.dev_version == "1.7.0"


def test_dev_only_extra_is_not_flagged(tmp_path: Path, pyproject: Path):
    # `test` extra (pytest, ruff) legitimately differs — the runtime venv is
    # entitled to lack it entirely. Give it a DIFFERENT pytest version on each
    # side, which would be a mismatch if the check wrongly widened its scope.
    runtime = _venv(tmp_path, "runtime", {
        "willow-ratatosk": "1.7.0", "requests": "2.34.2",
    })
    dev = _venv(tmp_path, "dev", {
        "willow-ratatosk": "1.7.0", "requests": "2.34.2",
        "pytest": "9.1.1", "ruff": "0.15.0",
    })
    report = compare(pyproject, runtime, dev)
    assert report.ok
    assert "pytest" not in report.checked
    assert "ruff" not in report.checked
    assert not any(m.name in ("pytest", "ruff") for m in report.mismatches)


def test_missing_venv_is_a_clean_skip(tmp_path: Path, pyproject: Path):
    dev = _venv(tmp_path, "dev", {"willow-ratatosk": "1.7.0", "requests": "2.34.2"})
    missing_runtime = tmp_path / "does-not-exist"
    report = compare(pyproject, missing_runtime, dev)
    assert report.skipped is not None
    assert "does-not-exist" in report.skipped
    assert report.ok is False  # skip is not "ok" but it is not a mismatch either
    assert not report.mismatches


def test_missing_dev_venv_is_also_a_clean_skip(tmp_path: Path, pyproject: Path):
    runtime = _venv(tmp_path, "runtime", {"willow-ratatosk": "1.7.0", "requests": "2.34.2"})
    missing_dev = tmp_path / "also-missing"
    report = compare(pyproject, runtime, missing_dev)
    assert report.skipped is not None
    assert not report.mismatches


def test_shared_runtime_set_is_derived_from_pyproject_dependencies_only(pyproject: Path):
    names = shared_runtime_deps(pyproject)
    assert names == {"willow-ratatosk", "requests"}
    # The test extra must never leak into the enforced set.
    assert "pytest" not in names
    assert "ruff" not in names


def test_missing_shared_dep_in_one_venv_is_reported_but_not_a_mismatch(
    tmp_path: Path, pyproject: Path
):
    runtime = _venv(tmp_path, "runtime", {"requests": "2.34.2"})  # no ratatosk
    dev = _venv(tmp_path, "dev", {"willow-ratatosk": "1.7.0", "requests": "2.34.2"})
    report = compare(pyproject, runtime, dev)
    assert "willow-ratatosk" in report.missing
    assert not report.mismatches
    assert report.ok  # missing is a note, not a failure this check owns


@pytest.mark.parametrize("raw,expected", [
    ("willow-ratatosk>=1.7.0,<2.0.0", "willow-ratatosk"),
    ("willow_ratatosk", "willow-ratatosk"),
    ("Willow.Ratatosk[extra]==1.0; python_version>='3.11'", "willow-ratatosk"),
    ("requests>=2.31,<3.0", "requests"),
])
def test_requirement_name_extracts_canonical_dist_name(raw: str, expected: str):
    assert requirement_name(raw) == expected


def test_canonicalize_treats_dash_underscore_dot_as_equivalent():
    assert canonicalize("Willow_Ratatosk") == canonicalize("willow-ratatosk")
    assert canonicalize("willow.ratatosk") == canonicalize("willow-ratatosk")
