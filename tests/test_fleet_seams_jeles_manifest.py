"""scripts/fleet_seams.py provisions the organ's manifest (gap 3cdeb177af78,
willow-mcp half).

CI fleet-seams went red at #617/528ef68 after Jeles#87: the probe co-installs
Jeles master, and jeles/corpus.py's `_manifest_scope` now refuses every
store-backed call (put_nugget, search_nuggets) unless
`$WILLOW_MCP_APPS_ROOT/<JELES_CORPUS_APP_ID>/manifest.json` exists with a
sibling `.sig` that at least looks like an ASCII-armored PGP signature, and
declares `store_scope`/`store_write`. `scripts/fleet_seams.py` is not an
installed package (no `scripts/__init__.py`), so it is loaded here the same
way it loads `recipes/jeles_bridge.py` from a checkout: `importlib.util`
against the file path.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "fleet_seams.py"


def _load_fleet_seams():
    spec = importlib.util.spec_from_file_location("fleet_seams", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def fleet_seams():
    # Fresh module object per test -- the function under test mutates
    # process-wide os.environ, so tests must not share one import.
    return _load_fleet_seams()


def test_provision_sets_app_id_to_the_organs_own_seat_never_the_retired_one(
    fleet_seams, tmp_path, monkeypatch,
):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.delenv("WILLOW_MCP_APPS_ROOT", raising=False)
    monkeypatch.delenv("JELES_CORPUS_APP_ID", raising=False)

    fleet_seams._provision_jeles_corpus_manifest()

    import os
    assert os.environ["JELES_CORPUS_APP_ID"] == "jeles-corpus"
    assert os.environ["JELES_CORPUS_APP_ID"] != "jeles"


def test_provision_defaults_apps_root_under_willow_home(fleet_seams, tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.delenv("WILLOW_MCP_APPS_ROOT", raising=False)
    monkeypatch.delenv("JELES_CORPUS_APP_ID", raising=False)

    fleet_seams._provision_jeles_corpus_manifest()

    import os
    assert os.environ["WILLOW_MCP_APPS_ROOT"] == str(tmp_path / "mcp_apps")


def test_provision_respects_an_existing_apps_root_override(fleet_seams, tmp_path, monkeypatch):
    override = tmp_path / "elsewhere" / "apps"
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(override))
    monkeypatch.delenv("JELES_CORPUS_APP_ID", raising=False)

    fleet_seams._provision_jeles_corpus_manifest()

    import os
    assert os.environ["WILLOW_MCP_APPS_ROOT"] == str(override)
    assert (override / "jeles-corpus" / "manifest.json").is_file()


def test_provision_writes_manifest_at_the_path_manifest_scope_reads(
    fleet_seams, tmp_path, monkeypatch,
):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.delenv("WILLOW_MCP_APPS_ROOT", raising=False)
    monkeypatch.delenv("JELES_CORPUS_APP_ID", raising=False)

    fleet_seams._provision_jeles_corpus_manifest()

    manifest_path = tmp_path / "mcp_apps" / "jeles-corpus" / "manifest.json"
    assert manifest_path.is_file()
    # never under a directory named the retired seat
    assert not (tmp_path / "mcp_apps" / "jeles").exists()

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["store_scope"] == ["ask_jeles_corpus"]
    assert manifest["store_write"] == ["ask_jeles_corpus"]
    # #619 fleet-seams leg, for real: "gate: empty permissions for
    # 'jeles-corpus' (tool='gap_log') — denied" -- willow-mcp's own gate
    # reads "permissions" from this same manifest file.
    assert manifest["permissions"] == ["gap_write"]


def test_provision_manifest_permissions_grant_gap_log_and_nothing_wider():
    """Rework of #619: the fixture must carry the narrowest group that
    includes gap_log (gate.PERMISSION_GROUPS['gap_write']), not full_access
    or some other wider grant."""
    from willow_mcp import gate

    assert "gap_log" in gate.PERMISSION_GROUPS["gap_write"]


def test_provision_writes_a_sibling_sig_that_looks_ascii_armored(
    fleet_seams, tmp_path, monkeypatch,
):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.delenv("WILLOW_MCP_APPS_ROOT", raising=False)
    monkeypatch.delenv("JELES_CORPUS_APP_ID", raising=False)

    fleet_seams._provision_jeles_corpus_manifest()

    sig_path = tmp_path / "mcp_apps" / "jeles-corpus" / "manifest.json.sig"
    assert sig_path.is_file()
    text = sig_path.read_text(encoding="utf-8").strip()
    assert text.startswith("-----BEGIN PGP SIGNATURE-----")
    assert text.endswith("-----END PGP SIGNATURE-----")


def test_sig_fixture_is_a_real_armor_block_not_prose_wearing_the_markers(fleet_seams):
    """Rework of Loki's F5 (23CAD2B4): the prior fixture was a prose string
    between the BEGIN/END markers with no base64 body and no CRC-24 --
    happened to pass jeles' substring shape check, but was not a real armor
    block. Decode the body and verify the CRC-24 checksum line matches, the
    same way a real armor parser would."""
    import base64

    text = fleet_seams._JELES_CORPUS_FIXTURE_SIG.strip()
    lines = text.splitlines()
    assert lines[0] == "-----BEGIN PGP SIGNATURE-----"
    assert lines[-1] == "-----END PGP SIGNATURE-----"
    assert lines[1] == ""  # armor header/body blank-line separator
    checksum_line = lines[-2]
    assert checksum_line.startswith("=")
    body_lines = lines[2:-2]
    assert body_lines  # a real base64 body, not empty
    payload = base64.b64decode("".join(body_lines))
    expected_crc = fleet_seams._crc24(payload)
    actual_crc = int.from_bytes(base64.b64decode(checksum_line[1:]), "big")
    assert actual_crc == expected_crc


def test_sig_fixture_passes_jeles_own_manifest_scope_when_jeles_is_installed(
    fleet_seams, tmp_path, monkeypatch,
):
    """The real proof, through the PUBLIC entry point rather than a named
    private helper: #619's test-matrix leg failed with `AttributeError:
    module 'jeles.corpus' has no attribute '_looks_like_pgp_signature'` --
    CI co-installs jeles fresh from its real current state, which does not
    match either local checkout this repo can read offline, and the
    private shape-check function's exact name is exactly the kind of
    internal detail a refactor is free to change without notice. Testing
    through `_manifest_scope()` -- the function this fixture actually has
    to satisfy, and the one gap 3cdeb177af78's whole design depends on --
    is correct regardless of what it calls internally to judge the `.sig`.
    Skipped when jeles is not installed in this venv -- co-install is a
    separate seam, and this repo does not hard-depend on the sibling
    checkout."""
    corpus = pytest.importorskip("jeles.corpus", reason="jeles not installed in this venv")
    if not hasattr(corpus, "_manifest_scope"):
        pytest.skip("this jeles install predates _manifest_scope (gap 3cdeb177af78 unmerged)")

    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.delenv("WILLOW_MCP_APPS_ROOT", raising=False)
    monkeypatch.delenv("JELES_CORPUS_APP_ID", raising=False)

    fleet_seams._provision_jeles_corpus_manifest()

    scope, write, error = corpus._manifest_scope()
    assert error is None, f"_manifest_scope refused the fixture: {error}"
    assert scope == ["ask_jeles_corpus"]
    assert write == ["ask_jeles_corpus"]


def test_provision_is_idempotent_across_repeated_runs(fleet_seams, tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.delenv("WILLOW_MCP_APPS_ROOT", raising=False)
    monkeypatch.delenv("JELES_CORPUS_APP_ID", raising=False)

    fleet_seams._provision_jeles_corpus_manifest()
    fleet_seams._provision_jeles_corpus_manifest()

    manifest_path = tmp_path / "mcp_apps" / "jeles-corpus" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["store_scope"] == ["ask_jeles_corpus"]


def test_main_calls_the_provisioning_step_before_any_seam(fleet_seams, tmp_path, monkeypatch):
    """`main()` must provision the fixture itself -- a seam function reading
    an unset JELES_CORPUS_APP_ID is exactly #617's failure mode."""
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    monkeypatch.delenv("WILLOW_MCP_APPS_ROOT", raising=False)
    monkeypatch.delenv("JELES_CORPUS_APP_ID", raising=False)
    monkeypatch.setattr(fleet_seams, "SEAMS", [])
    monkeypatch.setattr(sys, "argv", ["fleet_seams.py", "--json"])

    fleet_seams.main()

    manifest_path = tmp_path / "mcp_apps" / "jeles-corpus" / "manifest.json"
    assert manifest_path.is_file()
