"""paths.resolve_venv / venv_dir: the D2 venv resolver (docs/design/d2-venvs-move.md)."""

from __future__ import annotations

from pathlib import Path

import pytest

from willow_mcp import paths


def _venv(root: Path, name: str, *, exe: bool = True) -> Path:
    py = root / name / "bin" / "python"
    py.parent.mkdir(parents=True)
    py.write_text("#!/bin/sh\n", encoding="utf-8")
    py.chmod(0o755 if exe else 0o644)
    return root / name


def test_new_home_wins_silently(tmp_path, caplog):
    new = _venv(tmp_path / "willow-bot" / "venvs", "willow-bot")
    _venv(tmp_path / "venvs", "willow-bot")
    with caplog.at_level("WARNING"):
        res = paths.resolve_venv("willow-bot", home=tmp_path)
    assert (res.state, res.path) == ("new", new) and not caplog.records


def test_legacy_fallback_warns_once_naming_the_new_home(tmp_path, caplog):
    old = _venv(tmp_path / "venvs", "willow-mcp")
    with caplog.at_level("WARNING"):
        res = paths.resolve_venv("willow-mcp", home=tmp_path)
    assert (res.state, res.path) == ("legacy", old)
    assert len(caplog.records) == 1
    assert str(tmp_path / "willow-bot" / "venvs" / "willow-mcp") in caplog.records[0].getMessage()


def test_neither_is_absent_not_a_guess(tmp_path):
    res = paths.resolve_venv("willow-bot", home=tmp_path)
    assert res.state == "absent" and res.path is None and res.root is None
    assert paths.venv_dir("willow-bot", home=tmp_path) is None
    detail = paths.venv_absent_detail(res)
    assert str(res.new) in detail and str(res.legacy) in detail


def test_non_executable_new_interpreter_does_not_win(tmp_path):
    _venv(tmp_path / "willow-bot" / "venvs", "x", exe=False)
    old = _venv(tmp_path / "venvs", "x")
    assert paths.venv_dir("x", home=tmp_path) == old


def test_never_newest_wins(tmp_path):
    import os
    old = _venv(tmp_path / "venvs", "x")
    new = _venv(tmp_path / "willow-bot" / "venvs", "x")
    os.utime(old / "bin" / "python", (9_999_999_999, 9_999_999_999))
    assert paths.venv_dir("x", home=tmp_path) == new


def test_probe_is_generic_for_non_python_trees(tmp_path):
    node = tmp_path / "willow-bot" / "venvs" / "node9" / "bin" / "node"
    node.parent.mkdir(parents=True)
    node.write_text("", encoding="utf-8")
    node.chmod(0o755)
    assert paths.venv_dir("node9", home=tmp_path, probe="bin/node") == node.parent.parent
    assert paths.venv_dir("node9", home=tmp_path) is None


@pytest.mark.parametrize("bad", ["", "..", "a/b", "../x", ".hidden"])
def test_bad_names_refused(tmp_path, bad):
    with pytest.raises(ValueError):
        paths.resolve_venv(bad, home=tmp_path)
