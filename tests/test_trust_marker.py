"""D4 -- the root-owned trust-provisioned marker (rename-away hole, Loki
D06A0EF3; docs/design/rename-away-hole.md).

The marker path and the "root" uid are module constants in
``willow_mcp.trust_marker``; tests redirect them by monkeypatching those
constants (never an env var). "root" here is the test runner's own euid, and
the "trust owner" is either the runner (a genuine trust-owner-owned tree) or
runner+1 (so a runner-owned tree stands in for a broker-planted one)."""
from __future__ import annotations

import logging
import os

import pytest

from willow_mcp import envelopes, gate, paths, pgp, trust_marker

_FPR = "9B6F87BEB4AE56E2" + "0" * 24
EUID = os.geteuid()


@pytest.fixture
def box(tmp_path, monkeypatch):
    """tmp $WILLOW_HOME with the marker machinery pointed at tmp."""
    h = tmp_path / "home"
    h.mkdir()
    etc = tmp_path / "etc" / "willow-mcp"
    etc.mkdir(parents=True)
    os.chmod(etc, 0o755)
    os.chmod(etc.parent, 0o755)
    monkeypatch.setenv("WILLOW_HOME", str(h))
    for var in ("WILLOW_PGP_FINGERPRINT", "WILLOW_MCP_APPS_ROOT",
                "WILLOW_CHARTER_REPO", "WILLOW_ENVELOPE_REGISTRY",
                "WILLOW_SYSCALL_TABLE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(trust_marker, "_MARKER_PATH", etc / "trust-provisioned")
    monkeypatch.setattr(trust_marker, "_ROOT_UID", EUID)
    # a runner that is itself root must still be able to model "owned by the
    # broker's own euid": governance root is somebody else here
    monkeypatch.setattr(trust_marker, "_GOVERNANCE_ROOT_UID", EUID + 9)
    monkeypatch.setattr(paths, "_trust_owner_uid", lambda: EUID)
    trust_marker._logged_levers.clear()
    return h


def write_marker(home, uid=EUID, mode=0o644, text=None):
    p = trust_marker.marker_path()
    p.write_text(
        text if text is not None
        else f"willow_home={os.path.realpath(home)}\ntrust_owner_uid={uid}\n"
    )
    os.chmod(p, mode)
    return p


def genuine_tree(home, fingerprint=_FPR):
    d = home / "constitutional"
    d.mkdir(exist_ok=True)
    os.chmod(d, 0o755)
    t = d / "trust.env"
    t.write_text(f"WILLOW_PGP_FINGERPRINT={fingerprint}\n" if fingerprint else "")
    os.chmod(t, 0o644)
    return d


def as_planted(monkeypatch):
    """The trust owner is somebody else: everything the runner created is
    'broker-planted'."""
    monkeypatch.setattr(paths, "_trust_owner_uid", lambda: EUID + 1)


# ── marker absent: today's behaviour, exactly ──────────────────────────────

def test_absent_marker_is_none_and_bootstrap_unchanged(box):
    assert trust_marker.active_marker() is None
    assert pgp.expected_fingerprint() == ""
    assert pgp.pgp_enabled() is False


def test_absent_marker_planted_dir_is_still_bootstrap(box, monkeypatch):
    as_planted(monkeypatch)
    genuine_tree(box, fingerprint="")
    (box / "constitutional" / "trust.env").unlink()
    assert pgp.pgp_enabled() is False


def test_absent_marker_trusted_read_accepts_own_euid(box, tmp_path):
    f = box / "reg.json"
    f.write_text("{}")
    os.chmod(f, 0o644)
    os.chmod(box, 0o755)
    paths.trusted_read(f)


def test_absent_marker_levers_honoured(box, monkeypatch, tmp_path):
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path / "other"))
    monkeypatch.setenv("WILLOW_CHARTER_REPO", str(tmp_path / "charter"))
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(tmp_path / "r.json"))
    assert paths.mcp_apps_root() == tmp_path / "other"
    assert paths.charter_repo() == tmp_path / "charter"
    assert envelopes.registry_path() == tmp_path / "r.json"


# ── marker validation: invalid is fail closed, never "absent" ──────────────

def test_valid_marker_reads(box):
    write_marker(box)
    m = trust_marker.active_marker()
    assert m.trust_owner_uid == EUID
    assert m.willow_home == os.path.realpath(box)


def _invalid_cases():
    return ["symlink", "not_root", "group_writable", "other_writable",
            "parent_group_writable", "grandparent_other_writable",
            "malformed", "no_uid", "relative_home", "directory"]


@pytest.mark.parametrize("case", _invalid_cases())
def test_invalid_marker_raises_everywhere(box, monkeypatch, tmp_path, case):
    p = trust_marker.marker_path()
    if case == "symlink":
        real = tmp_path / "real-marker"
        real.write_text(f"willow_home={os.path.realpath(box)}\ntrust_owner_uid={EUID}\n")
        os.chmod(real, 0o644)
        p.symlink_to(real)
    elif case == "not_root":
        write_marker(box)
        monkeypatch.setattr(trust_marker, "_ROOT_UID", EUID + 1)
    elif case == "group_writable":
        write_marker(box, mode=0o664)
    elif case == "other_writable":
        write_marker(box, mode=0o646)
    elif case == "parent_group_writable":
        write_marker(box)
        os.chmod(p.parent, 0o775)
    elif case == "grandparent_other_writable":
        write_marker(box)
        os.chmod(p.parent.parent, 0o757)
    elif case == "malformed":
        write_marker(box, text="nonsense\n")
    elif case == "no_uid":
        write_marker(box, text=f"willow_home={os.path.realpath(box)}\n")
    elif case == "relative_home":
        write_marker(box, text="willow_home=rel/path\ntrust_owner_uid=1\n")
    elif case == "directory":
        p.mkdir()
    genuine_tree(box)
    with pytest.raises(trust_marker.TrustMarkerError):
        trust_marker.active_marker()
    with pytest.raises(pgp.PgpSourceUnreadable, match="D06A0EF3"):
        pgp.pgp_enabled()
    f = box / "constitutional" / "reg.json"
    f.write_text("{}")
    with pytest.raises(PermissionError):
        paths.trusted_read(f)
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path / "x"))
    with pytest.raises(trust_marker.TrustMarkerError):
        paths.mcp_apps_root()


def test_home_mismatch_refuses_rather_than_runs_unenforced(box, monkeypatch, tmp_path):
    write_marker(box)
    other = tmp_path / "other-home"
    other.mkdir()
    monkeypatch.setenv("WILLOW_HOME", str(other))
    with pytest.raises(pgp.PgpSourceUnreadable, match="binds trust"):
        pgp.pgp_enabled()


def test_home_symlink_alias_is_the_same_home(box, monkeypatch, tmp_path):
    write_marker(box)
    genuine_tree(box)
    alias = tmp_path / "alias"
    alias.symlink_to(box)
    monkeypatch.setenv("WILLOW_HOME", str(alias))
    assert pgp.pgp_enabled() is True


def test_trust_owner_uid_cross_check(box, monkeypatch):
    write_marker(box, uid=EUID)
    genuine_tree(box)
    monkeypatch.setattr(paths, "_trust_owner_uid", lambda: EUID + 5)
    with pytest.raises(pgp.PgpSourceUnreadable, match="trust owner"):
        pgp.pgp_enabled()
    monkeypatch.setattr(paths, "_trust_owner_uid", lambda: None)
    with pytest.raises(pgp.PgpSourceUnreadable):
        pgp.pgp_enabled()


# ── pgp: rename-away becomes a refusal ─────────────────────────────────────

def test_provisioned_genuine_tree_is_enabled(box):
    write_marker(box)
    genuine_tree(box)
    assert pgp.pgp_enabled() is True
    assert pgp.expected_fingerprint() == _FPR


def test_planted_broker_owned_constitutional_raises(box, monkeypatch):
    write_marker(box, uid=EUID + 1)
    as_planted(monkeypatch)
    genuine_tree(box)  # runner-owned == broker-planted
    with pytest.raises(pgp.PgpSourceUnreadable, match="D06A0EF3"):
        pgp.pgp_enabled()


def test_planted_empty_dir_raises_not_bootstrap(box, monkeypatch):
    write_marker(box, uid=EUID + 1)
    as_planted(monkeypatch)
    (box / "constitutional").mkdir()
    with pytest.raises(pgp.PgpSourceUnreadable, match="renamed away"):
        pgp.pgp_enabled()


def test_missing_constitutional_raises(box):
    write_marker(box)
    with pytest.raises(pgp.PgpSourceUnreadable, match="D06A0EF3"):
        pgp.pgp_enabled()


def test_missing_trust_env_raises(box):
    write_marker(box)
    genuine_tree(box)
    (box / "constitutional" / "trust.env").unlink()
    with pytest.raises(pgp.PgpSourceUnreadable, match="missing or unreadable"):
        pgp.expected_fingerprint()


def test_unreadable_trust_env_raises(box):
    write_marker(box)
    genuine_tree(box)
    t = box / "constitutional" / "trust.env"
    t.unlink()
    t.mkdir()  # not a regular file
    with pytest.raises(pgp.PgpSourceUnreadable):
        pgp.pgp_enabled()


def test_empty_fingerprint_raises_even_after_cached(box):
    genuine_tree(box)
    # unprovisioned first: empty/valid file cached as "" ...
    (box / "constitutional" / "trust.env").write_text("WILLOW_PGP_FINGERPRINT=\n")
    assert pgp.expected_fingerprint() == ""
    write_marker(box)
    with pytest.raises(pgp.PgpSourceUnreadable, match="no WILLOW_PGP_FINGERPRINT"):
        pgp.expected_fingerprint()
    with pytest.raises(pgp.PgpSourceUnreadable):
        pgp.pgp_enabled()


def test_constitutional_symlink_raises(box, tmp_path):
    write_marker(box)
    real = tmp_path / "elsewhere"
    real.mkdir()
    (box / "constitutional").symlink_to(real)
    with pytest.raises(pgp.PgpSourceUnreadable):
        pgp.pgp_enabled()


# ── gate / broker boot ─────────────────────────────────────────────────────

def _manifest(box):
    d = box / "mcp_apps" / "seat"
    d.mkdir(parents=True)
    (d / "manifest.json").write_text('{"app_id": "seat", "permissions": ["all"]}')


def test_gate_accepts_forged_manifest_without_marker_hole_baseline(box, monkeypatch):
    as_planted(monkeypatch)
    (box / "constitutional").mkdir()  # planted, empty
    _manifest(box)
    assert gate._load_manifest("seat") is not None  # the hole D4 closes


def test_gate_denies_manifest_when_trust_root_raises(box, monkeypatch):
    # a trust-owner-owned manifest tree (D4.5 passes) but no usable trust root
    write_marker(box)
    (box / "constitutional").mkdir()
    _manifest(box)
    assert gate._load_manifest("seat") is None
    data, reason, detail = gate._read_manifest("seat")
    assert data is None and reason == gate.MANIFEST_UNSIGNED
    assert "trust root" in detail


def test_boot_refuses_to_start_when_trust_root_raises(box, monkeypatch, capsys):
    from willow_mcp import server

    write_marker(box, uid=EUID + 1)
    as_planted(monkeypatch)
    (box / "constitutional").mkdir()
    _manifest(box)
    with pytest.raises(SystemExit) as ei:
        server._boot_manifest_verify_sweep_or_exit()
    assert ei.value.code == 1
    assert "refusing to start" in capsys.readouterr().err


# ── trusted_read ───────────────────────────────────────────────────────────

def _gov_file(box):
    d = box / "constitutional"
    d.mkdir(exist_ok=True)
    os.chmod(d, 0o755)
    f = d / "pre-approved.json"
    f.write_text("{}")
    os.chmod(f, 0o644)
    return f


def test_trusted_read_refuses_own_euid_governance_file_with_marker(box, monkeypatch):
    write_marker(box, uid=EUID + 1)
    as_planted(monkeypatch)
    f = _gov_file(box)
    with pytest.raises(PermissionError, match="trust owner"):
        paths.trusted_read(f)


def test_trusted_read_accepts_own_euid_without_marker(box, monkeypatch):
    as_planted(monkeypatch)
    paths.trusted_read(_gov_file(box))


def test_trusted_read_trust_owner_file_needs_signature_with_marker(box, monkeypatch):
    write_marker(box)
    genuine_tree(box)
    f = _gov_file(box)
    monkeypatch.setattr(pgp, "verify_detached", lambda p, fingerprint="": (False, "bad"))
    with pytest.raises(PermissionError, match="signature"):
        paths.trusted_read(f)
    monkeypatch.setattr(pgp, "verify_detached", lambda p, fingerprint="": (True, ""))
    paths.trusted_read(f)


def test_trusted_read_non_governance_keeps_euid_branch(box, monkeypatch):
    write_marker(box, uid=EUID + 1)
    as_planted(monkeypatch)
    f = box / "fleet.json"
    f.write_text("{}")
    os.chmod(f, 0o644)
    os.chmod(box, 0o755)
    paths.trusted_read(f, governance=False)
    with pytest.raises(PermissionError):
        paths.trusted_read(f)


def test_envelope_load_refuses_broker_planted_register(box, monkeypatch):
    write_marker(box, uid=EUID + 1)
    as_planted(monkeypatch)
    f = _gov_file(box)
    with pytest.raises(PermissionError):
        envelopes._load(f)


# ── env levers (Q37) ───────────────────────────────────────────────────────

def test_levers_ignored_and_logged_once_with_marker(box, monkeypatch, tmp_path, caplog):
    write_marker(box)
    genuine_tree(box)
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path / "evil-apps"))
    monkeypatch.setenv("WILLOW_CHARTER_REPO", str(tmp_path / "evil-charter"))
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(tmp_path / "evil.json"))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(tmp_path / "evil-sys.json"))
    with caplog.at_level(logging.ERROR, logger="willow_mcp.trust_marker"):
        assert paths.mcp_apps_root() == box / "mcp_apps"
        assert paths.mcp_apps_root() == box / "mcp_apps"
        assert gate._apps_root() == box / "mcp_apps"
        assert paths.charter_repo() is None
        assert paths.constitutional_dir() == box / "constitutional"
        assert envelopes.registry_path() == box / "constitutional" / "pre-approved.json"
        assert envelopes.syscall_path() == box / "constitutional" / "syscall-table.json"
    logged = [r.getMessage() for r in caplog.records]
    for var in ("WILLOW_MCP_APPS_ROOT", "WILLOW_CHARTER_REPO",
                "WILLOW_ENVELOPE_REGISTRY", "WILLOW_SYSCALL_TABLE"):
        assert sum(var in m for m in logged) == 1, var


# ── the owner check on its own (a runner cannot chown) ─────────────────────

def test_marker_owner_check_alone_refuses_a_non_root_owned_marker(box, monkeypatch):
    """Parents stay 'root' (the runner); only the marker file itself reports
    another owner, so the file-owner guard is exercised in isolation."""
    p = write_marker(box)
    real_lstat = os.lstat

    def fake(path, *a, **k):
        st = real_lstat(path, *a, **k)
        if str(path) == str(p):
            vals = list(st)
            vals[4] = EUID + 77
            return os.stat_result(vals)
        return st

    monkeypatch.setattr(trust_marker.os, "lstat", fake)
    with pytest.raises(trust_marker.TrustMarkerError, match="not root"):
        trust_marker.read_marker()


def test_fleet_roster_keeps_the_euid_branch_under_a_marker(box, monkeypatch):
    from willow_mcp import fleet_roster

    write_marker(box, uid=EUID + 1)
    as_planted(monkeypatch)
    os.chmod(box, 0o755)
    roster = box / "fleet.json"
    roster.write_text('{"agents": {}}')
    os.chmod(roster, 0o644)
    monkeypatch.setenv("WILLOW_FLEET_ROSTER", str(roster))
    assert fleet_roster.load_roster() == {"agents": {}}
