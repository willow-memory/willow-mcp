"""D4.5 (Loki D06A0EF3): under a valid trust marker a seat manifest must come
from a trust-owner/root-owned tree and must name its own seat; the app_id
binding holds with or without a marker."""

import json
import logging
import os

import pytest
from willow_mcp import gate, paths, pgp, trust_marker

EUID = os.geteuid()


@pytest.fixture
def tree(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    etc = tmp_path / "etc" / "willow-mcp"
    etc.mkdir(parents=True)
    os.chmod(etc, 0o755)
    os.chmod(etc.parent, 0o755)
    root = h / "mcp_apps"
    root.mkdir()
    os.chmod(root, 0o755)
    monkeypatch.setenv("WILLOW_HOME", str(h))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(root))
    monkeypatch.setattr(trust_marker, "_MARKER_PATH", etc / "trust-provisioned")
    monkeypatch.setattr(trust_marker, "_ROOT_UID", EUID)
    monkeypatch.setattr(trust_marker, "_GOVERNANCE_ROOT_UID", EUID + 9)
    monkeypatch.setattr(paths, "_trust_owner_uid", lambda: EUID)
    monkeypatch.setattr(pgp, "pgp_enabled", lambda: True)
    # every signature in these tests is "genuine": the attack is about WHERE
    # a genuine pair sits, not forging one
    seen = []
    monkeypatch.setattr(
        gate.pgp, "verify_detached", lambda p: (seen.append(p.read_bytes()) or True, "ok")
    )
    trust_marker._logged_levers.clear()
    return root


def marker(root, uid):
    p = trust_marker.marker_path()
    p.write_text(f"willow_home={os.path.realpath(root.parent)}\ntrust_owner_uid={uid}\n")
    os.chmod(p, 0o644)


def seat(root, app_id, body=None, *, dir_mode=0o755, file_mode=0o644, dirname=None):
    d = root / (dirname or app_id)
    d.mkdir(exist_ok=True)
    os.chmod(d, dir_mode)
    m = d / "manifest.json"
    m.write_text(json.dumps(body if body is not None else {"app_id": app_id, "permissions": ["store_read"]}))
    s = d / "manifest.json.sig"
    s.write_text("SIG")
    os.chmod(m, file_mode)
    os.chmod(s, file_mode)
    return d


def broker_is_somebody_else(monkeypatch):
    """trust owner = EUID+1, so everything this runner created is broker-owned"""
    monkeypatch.setattr(paths, "_trust_owner_uid", lambda: EUID + 1)


# ── under the marker ───────────────────────────────────────────────────────

def test_genuine_trust_owned_tree_allowed(tree):
    marker(tree, EUID)
    seat(tree, "alpha")
    assert gate.authorized("alpha") is True
    assert gate.manifest_diagnosis("alpha")[0] == gate.MANIFEST_OK


def test_broker_planted_tree_with_genuine_copies_denied(tree, monkeypatch, caplog):
    broker_is_somebody_else(monkeypatch)
    marker(tree, EUID + 1)
    seat(tree, "alpha")
    with caplog.at_level(logging.ERROR, logger="willow_mcp.gate"):
        assert gate.authorized("alpha") is False
    assert gate.manifest_diagnosis("alpha")[0] == gate.MANIFEST_UNTRUSTED_OWNER
    assert any("D06A0EF3" in r.message for r in caplog.records)


def test_broker_owned_seat_dir_under_trusted_root_denied(tree, monkeypatch):
    marker(tree, EUID)
    seat(tree, "alpha")
    real = paths.provisioned_lstat

    def fake(target, mk, *, want_dir):
        info = real(target, mk, want_dir=want_dir)
        if target.name == "alpha":
            raise PermissionError("broker-owned seat dir")
        return info

    monkeypatch.setattr(paths, "provisioned_lstat", fake)
    assert gate.authorized("alpha") is False
    assert gate.manifest_diagnosis("alpha")[0] == gate.MANIFEST_UNTRUSTED_OWNER


def test_owner_rule_is_per_element(tree, monkeypatch):
    """Root trusted, seat dir not: a uid check keyed on the whole chain."""
    marker(tree, EUID)
    seat(tree, "alpha")
    allowed = {"n": 0}
    real = paths.provisioned_allowed_uids

    def only_root_dir(mk):
        allowed["n"] += 1
        # first call = apps root: trusted; later calls: nobody
        return real(mk) if allowed["n"] == 1 else set()

    monkeypatch.setattr(paths, "provisioned_allowed_uids", only_root_dir)
    assert gate.authorized("alpha") is False


@pytest.mark.parametrize("which", ["root", "seat", "manifest", "sig"])
@pytest.mark.parametrize("bit", [0o020, 0o002])
def test_group_or_other_writable_denied(tree, which, bit):
    marker(tree, EUID)
    d = seat(tree, "alpha")
    target = {"root": tree, "seat": d, "manifest": d / "manifest.json",
              "sig": d / "manifest.json.sig"}[which]
    os.chmod(target, (target.stat().st_mode & 0o7777) | bit)
    assert gate.authorized("alpha") is False
    assert gate.manifest_diagnosis("alpha")[0] == gate.MANIFEST_UNTRUSTED_OWNER


def test_symlinked_manifest_denied(tree, tmp_path):
    marker(tree, EUID)
    d = seat(tree, "alpha")
    real = tmp_path / "elsewhere.json"
    real.write_text(json.dumps({"app_id": "alpha", "permissions": ["full_access"]}))
    os.chmod(real, 0o644)
    (d / "manifest.json").unlink()
    (d / "manifest.json").symlink_to(real)
    assert gate.authorized("alpha") is False
    assert gate.manifest_diagnosis("alpha")[0] == gate.MANIFEST_UNTRUSTED_OWNER


def test_symlinked_sig_denied(tree, tmp_path):
    marker(tree, EUID)
    d = seat(tree, "alpha")
    real = tmp_path / "sig"
    real.write_text("SIG")
    (d / "manifest.json.sig").unlink()
    (d / "manifest.json.sig").symlink_to(real)
    assert gate.authorized("alpha") is False


def test_symlinked_seat_dir_denied(tree, tmp_path):
    marker(tree, EUID)
    elsewhere = tmp_path / "other"
    elsewhere.mkdir()
    os.chmod(elsewhere, 0o755)
    seat(tmp_path, "other", {"app_id": "alpha", "permissions": ["store_read"]})
    (tree / "alpha").symlink_to(tmp_path / "other")
    assert gate.authorized("alpha") is False
    assert gate.manifest_diagnosis("alpha")[0] == gate.MANIFEST_UNTRUSTED_OWNER


def test_symlinked_apps_root_denied(tree, tmp_path):
    marker(tree, EUID)
    seat(tree, "alpha")
    moved = tmp_path / "moved_apps"
    tree.rename(moved)
    tree.symlink_to(moved)
    assert gate.authorized("alpha") is False


def test_invalid_marker_denies(tree):
    marker(tree, EUID)
    os.chmod(trust_marker.marker_path(), 0o666)
    seat(tree, "alpha")
    assert gate.authorized("alpha") is False


def test_signature_is_verified_on_a_private_snapshot_not_the_seat_path(tree, monkeypatch):
    marker(tree, EUID)
    d = seat(tree, "alpha")
    got = []

    def spy(p):
        got.append((p, p.read_bytes(), p.with_name(p.name + ".sig").read_bytes()))
        return True, "ok"

    monkeypatch.setattr(gate.pgp, "verify_detached", spy)
    assert gate.authorized("alpha") is True
    (path, mbytes, sbytes), = got
    assert path != d / "manifest.json" and not str(path).startswith(str(tree))
    assert mbytes == (d / "manifest.json").read_bytes() and sbytes == b"SIG"


def test_no_marker_verifies_the_seat_path_as_before(tree, monkeypatch):
    seat(tree, "alpha")
    got = []
    monkeypatch.setattr(gate.pgp, "verify_detached", lambda p: (got.append(p) or True, "ok"))
    assert gate.authorized("alpha") is True
    assert got == [tree / "alpha" / "manifest.json"]


def test_provisioned_lstat_refuses_non_regular_file(tree):
    marker(tree, EUID)
    fifo = tree / "fifo"
    os.mkfifo(fifo, 0o644)
    with pytest.raises(PermissionError, match="not a plain"):
        paths.provisioned_lstat(fifo, trust_marker.active_marker(), want_dir=False)


def test_pinned_read_refuses_symlink_even_when_inode_matches(tree):
    d = seat(tree, "alpha")
    (d / "link.json").symlink_to(d / "manifest.json")
    info = os.lstat(d / "manifest.json")  # the TARGET's inode: only O_NOFOLLOW stops this
    with pytest.raises(OSError):
        gate._read_pinned(d / "link.json", info)


def test_pinned_read_refuses_swapped_inode(tree):
    d = seat(tree, "alpha")
    info = os.lstat(d / "manifest.json")
    other = d / "other.json"
    other.write_text("{}")  # allocated while the original still holds its inode
    os.replace(other, d / "manifest.json")
    with pytest.raises(PermissionError):
        gate._read_pinned(d / "manifest.json", info)


def test_boot_sweep_reports_planted_tree(tree, monkeypatch, caplog):
    broker_is_somebody_else(monkeypatch)
    marker(tree, EUID + 1)
    seat(tree, "alpha")
    seat(tree, "beta")
    problems = gate.verify_all_manifests()
    assert {(p["app_id"], p["reason"]) for p in problems} == {
        ("alpha", gate.MANIFEST_UNTRUSTED_OWNER), ("beta", gate.MANIFEST_UNTRUSTED_OWNER)}
    with caplog.at_level(logging.ERROR, logger="willow_mcp.gate"):
        assert gate.log_manifest_verify_sweep()
    assert any(gate.MANIFEST_UNTRUSTED_OWNER in r.message for r in caplog.records)


def test_boot_sweep_clean_on_genuine_tree(tree):
    marker(tree, EUID)
    seat(tree, "alpha")
    assert gate.verify_all_manifests() == []


# ── no marker: unchanged ───────────────────────────────────────────────────

def test_no_marker_broker_owned_tree_unchanged(tree, monkeypatch):
    broker_is_somebody_else(monkeypatch)
    seat(tree, "alpha", dir_mode=0o777, file_mode=0o666)
    assert trust_marker.active_marker() is None
    assert gate.authorized("alpha") is True


# ── app_id binding (marker or not) ─────────────────────────────────────────

@pytest.mark.parametrize("with_marker", [False, True])
def test_cross_seat_replay_denied(tree, with_marker):
    if with_marker:
        marker(tree, EUID)
    seat(tree, "alpha", {"app_id": "beta", "permissions": ["full_access"]})
    assert gate.authorized("alpha") is False
    assert gate.manifest_diagnosis("alpha")[0] == gate.MANIFEST_APP_ID_MISMATCH
    assert [p["reason"] for p in gate.verify_all_manifests()] == [gate.MANIFEST_APP_ID_MISMATCH]


@pytest.mark.parametrize("with_marker", [False, True])
def test_matching_app_id_allowed(tree, with_marker):
    if with_marker:
        marker(tree, EUID)
    seat(tree, "alpha", {"app_id": "alpha", "permissions": ["store_read"]})
    assert gate.authorized("alpha") is True


@pytest.mark.parametrize("bad", [None, 5, ["alpha"], "Alpha", "alpha "])
def test_non_string_or_inexact_app_id_denied(tree, bad):
    seat(tree, "alpha", {"app_id": bad, "permissions": ["store_read"]})
    assert gate.authorized("alpha") is False


def test_absent_app_id_field_still_allowed(tree):
    seat(tree, "alpha", {"permissions": ["store_read"]})
    assert gate.authorized("alpha") is True


def test_missing_sig_under_marker_is_unsigned_not_an_ownership_fault(tree):
    marker(tree, EUID)
    d = seat(tree, "alpha")
    (d / "manifest.json.sig").unlink()
    assert gate.authorized("alpha") is False
    assert gate.manifest_diagnosis("alpha")[0] == gate.MANIFEST_UNSIGNED
