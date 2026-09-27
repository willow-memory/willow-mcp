"""node9 shadow mode (sealed a6d054b3, amended node9-shadow-hybrid-ledger-
2026-09-27) — installer tests. Loki 53741054 F5/F11: the installer must
vendor a pinned node + node9-ai (never rely on PATH) and lock the whole
`venvs/node9/` tree read-only afterward, not just the shim file.
"""
from __future__ import annotations

import json
import stat

import pytest

from willow_mcp import node9_shadow


@pytest.fixture(autouse=True)
def _willow_home(tmp_path, monkeypatch):
    home = tmp_path / "willow"
    home.mkdir()
    monkeypatch.setenv("WILLOW_HOME", str(home))
    return home


def _stub_sources(tmp_path):
    src_node = tmp_path / "_src_node"
    src_node.write_text("#!/bin/sh\necho fake-node\n")
    src_node9_ai = tmp_path / "_src_node9_ai"
    (src_node9_ai / "bin").mkdir(parents=True)
    (src_node9_ai / "bin" / "node9.js").write_text("// fake\n")
    (src_node9_ai / "package.json").write_text(json.dumps({"version": "9.9.9-test"}))
    return str(src_node), str(src_node9_ai)


def test_install_shim_requires_explicit_sources(tmp_path):
    with pytest.raises(ValueError):
        node9_shadow.install_shim()


def test_install_shim_vendors_node_and_node9_ai(tmp_path):
    src_node, src_node9_ai = _stub_sources(tmp_path)
    result = node9_shadow.install_shim(source_node=src_node, source_node9_ai=src_node9_ai)

    assert node9_shadow.shim_path().is_file()
    assert node9_shadow.shadow_home_path().is_dir()
    assert node9_shadow.shadow_cwd_path().is_dir()
    assert node9_shadow._node_bin_path().is_file()
    assert node9_shadow._node9_script_path().is_file()
    assert node9_shadow._version_file_path().read_text().strip() == "9.9.9-test"
    assert result["version"] == "9.9.9-test"
    assert result["node_bin"] == str(node9_shadow._node_bin_path())
    assert result["node9_script"] == str(node9_shadow._node9_script_path())


def test_install_shim_locks_the_whole_root_read_only_not_just_the_shim(tmp_path):
    """F11: the original installer left venvs/node9/ itself writable, so the
    shim could be replaced by rename even with its own file chmodded 0555."""
    src_node, src_node9_ai = _stub_sources(tmp_path)
    node9_shadow.install_shim(source_node=src_node, source_node9_ai=src_node9_ai)

    root = node9_shadow._shadow_root()
    mode = stat.S_IMODE(root.stat().st_mode)
    assert mode & 0o222 == 0, "venvs/node9/ itself must be read-only, not just the shim file"
    # a rename-based replacement needs write on the PARENT dir entry — refused
    with pytest.raises(PermissionError):
        (root / "shadow-eval.mjs").rename(root / "shadow-eval.mjs.evil")


def test_install_shim_refuses_to_overwrite_without_force(tmp_path):
    src_node, src_node9_ai = _stub_sources(tmp_path)
    node9_shadow.install_shim(source_node=src_node, source_node9_ai=src_node9_ai)
    with pytest.raises(ValueError):
        node9_shadow.install_shim(source_node=src_node, source_node9_ai=src_node9_ai)


def test_install_shim_force_overwrites(tmp_path):
    src_node, src_node9_ai = _stub_sources(tmp_path)
    node9_shadow.install_shim(source_node=src_node, source_node9_ai=src_node9_ai)
    result = node9_shadow.install_shim(source_node=src_node, source_node9_ai=src_node9_ai, force=True)
    assert node9_shadow.shim_path().is_file()
    assert result["shim_path"]


def test_install_shim_refuses_a_source_node9_ai_missing_the_entry_script(tmp_path):
    src_node, _ = _stub_sources(tmp_path)
    bad_node9_ai = tmp_path / "bad_node9_ai"
    bad_node9_ai.mkdir()
    with pytest.raises(OSError):
        node9_shadow.install_shim(source_node=src_node, source_node9_ai=str(bad_node9_ai))
