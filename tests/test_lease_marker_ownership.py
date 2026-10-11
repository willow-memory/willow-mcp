"""F1 (Loki, audit of b725667, MED): under a valid trust-provisioned marker the
egress-lease, build-lease and identity-binding READERS enforce the D4.5
ownership rule that the seat-manifest reader already does.

Before: `lease.read_lease` returned `active` on presence + parse + unexpired
deadline + app_id match -- no ownership check -- so a lease a broker-uid process
planted (or a binding it planted, or a renamed-aside `_net_leases/`) opened
egress / bound an identity. Now, with a valid marker, the apps root, the
`_net_leases` / `_build_leases` / `_identity_bindings` directory and the file
must each be a real (non-symlink) trust-owner/root-owned entry without
group/other write, and the file is read through a pinned O_NOFOLLOW fd. Any
violation is no lease / no binding, loudly, with a status of its own
(`untrusted`). Without a marker nothing changes. The `WILLOW_MCP_APPS_ROOT`
lever is ignored under a marker (Q37) by these readers and their writers.

"Broker-owned" is modelled by reporting a different uid for one path (an
lstat wrapper), so the cases run as any user, root included.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone

import pytest

from willow_mcp import build_lease, identity_binding, lease, paths, trust_marker

EUID = os.geteuid()
BROKER = EUID + 1


# ── fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def box(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    etc = tmp_path / "etc" / "willow-mcp"
    etc.mkdir(parents=True)
    os.chmod(etc, 0o755)
    os.chmod(etc.parent, 0o755)
    apps = h / "mcp_apps"
    apps.mkdir()
    os.chmod(apps, 0o755)
    monkeypatch.setenv("WILLOW_HOME", str(h))
    monkeypatch.delenv("WILLOW_MCP_APPS_ROOT", raising=False)
    monkeypatch.setattr(trust_marker, "_MARKER_PATH", etc / "trust-provisioned")
    monkeypatch.setattr(trust_marker, "_ROOT_UID", EUID)
    monkeypatch.setattr(trust_marker, "_GOVERNANCE_ROOT_UID", EUID + 9)   # root-owned means "not us"
    monkeypatch.setattr(paths, "_trust_owner_uid", lambda: EUID)        # we ARE the trust owner
    trust_marker._logged_levers.clear()
    return type("Box", (), {"home": h, "apps": apps, "tmp": tmp_path})()


def set_marker(box, uid=EUID, home=None):
    p = trust_marker.marker_path()
    p.write_text(f"willow_home={os.path.realpath(home or box.home)}\ntrust_owner_uid={uid}\n")
    os.chmod(p, 0o644)


@pytest.fixture
def owned_by(monkeypatch):
    """owned_by(path, uid): os.lstat reports `uid` as that path's owner."""
    fake: dict[str, int] = {}
    real = os.lstat

    def lstat(p, *a, **k):
        st = real(p, *a, **k)
        key = str(p)
        if key in fake:
            f = list(st)
            f[4] = fake[key]
            return os.stat_result(f)
        return st

    monkeypatch.setattr(os, "lstat", lstat)
    return lambda path, uid: fake.__setitem__(str(path), uid)


def _future(minutes=30):
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()


def _past():
    return (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()


# Each subject: where its records live and how to read the verdict. `ok(box)`
# is True when the reader honours the record (active lease / confirmed binding).

class Lease:
    name, sub, fname = "net lease", "_net_leases", "kart.json"

    @staticmethod
    def record(expires=None):
        return {"app_id": "kart", "granted_at": _past(), "expires_at": expires or _future(),
                "ttl_seconds": 1800, "issuer": "operator", "reason": "t"}

    @staticmethod
    def read():
        return lease.read_lease("kart")

    @staticmethod
    def ok(box):
        return Lease.read()["status"] == "active"

    @staticmethod
    def status():
        return Lease.read()["status"]


class Build:
    name, sub, fname = "build lease", "_build_leases", "workflow.json"

    @staticmethod
    def record(expires=None):
        return {"tool": "workflow", "granted_at": _past(), "expires_at": expires or _future(),
                "ttl_seconds": 1800, "issuer": "operator", "reason": "t"}

    @staticmethod
    def read():
        return build_lease.read_lease("workflow")

    @staticmethod
    def ok(box):
        return Build.read()["status"] == "active"

    @staticmethod
    def status():
        return Build.read()["status"]


class Binding:
    name, sub, fname = "identity binding", "_identity_bindings", "google__sub1.json"

    @staticmethod
    def record(expires=None):
        return {"idp": "google", "subject_id": "sub1", "app_id": "kart", "confirmed": True}

    @staticmethod
    def read():
        return identity_binding.resolve_app_id("google", "sub1")

    @staticmethod
    def ok(box):
        return Binding.read() == "kart"

    @staticmethod
    def status():
        return "bound" if Binding.read() else "unbound"


SUBJECTS = [Lease, Build, Binding]


def plant(box, subj, record=None, *, dir_mode=0o755, file_mode=0o644):
    d = box.apps / subj.sub
    d.mkdir(exist_ok=True)
    os.chmod(d, dir_mode)
    f = d / subj.fname
    f.write_text(json.dumps(record if record is not None else subj.record()))
    os.chmod(f, file_mode)
    return d, f


def log_names_d06(caplog):
    return any("D06A0EF3" in r.getMessage() and r.levelno >= logging.ERROR for r in caplog.records)


# ── a trust-owned tree is honoured ──────────────────────────────────────────

@pytest.mark.parametrize("subj", SUBJECTS, ids=lambda s: s.name)
def test_trust_owned_record_is_honoured(box, subj):
    set_marker(box)
    plant(box, subj)
    assert subj.ok(box)


def test_root_ownership_is_accepted(box, monkeypatch):
    monkeypatch.setattr(paths, "_trust_owner_uid", lambda: EUID + 5)
    set_marker(box, uid=EUID + 5)
    monkeypatch.setattr(trust_marker, "_GOVERNANCE_ROOT_UID", EUID)   # ... but with "root" == us, it is accepted
    plant(box, Lease)
    assert Lease.ok(box)


# ── every ownership / kind / identity violation is no record, loudly ───────

def _expect_refused(box, subj, caplog, why):
    with caplog.at_level(logging.ERROR):
        assert not subj.ok(box)
    assert log_names_d06(caplog), why
    if subj is not Binding:
        r = subj.read()
        assert r["status"] == "untrusted" and r["reason"] == "untrusted_owner" and r["error"], r


@pytest.mark.parametrize("subj", SUBJECTS, ids=lambda s: s.name)
def test_broker_owned_file_is_no_record(box, subj, owned_by, caplog):
    set_marker(box)
    d, f = plant(box, subj)
    owned_by(f, BROKER)
    _expect_refused(box, subj, caplog, "file")


@pytest.mark.parametrize("subj", SUBJECTS, ids=lambda s: s.name)
def test_broker_owned_lease_directory_is_no_record(box, subj, owned_by, caplog):
    set_marker(box)
    d, f = plant(box, subj)
    owned_by(d, BROKER)
    _expect_refused(box, subj, caplog, "directory")


@pytest.mark.parametrize("subj", SUBJECTS, ids=lambda s: s.name)
def test_broker_owned_apps_root_is_no_record(box, subj, owned_by, caplog):
    set_marker(box)
    plant(box, subj)
    owned_by(box.apps, BROKER)
    _expect_refused(box, subj, caplog, "apps root")


@pytest.mark.parametrize("mode", [0o664, 0o646, 0o666])
@pytest.mark.parametrize("subj", SUBJECTS, ids=lambda s: s.name)
def test_group_or_other_writable_file_is_no_record(box, subj, mode, caplog):
    set_marker(box)
    plant(box, subj, file_mode=mode)
    _expect_refused(box, subj, caplog, "file mode")


@pytest.mark.parametrize("mode", [0o775, 0o757, 0o777])
@pytest.mark.parametrize("subj", SUBJECTS, ids=lambda s: s.name)
def test_group_or_other_writable_directory_is_no_record(box, subj, mode, caplog):
    set_marker(box)
    plant(box, subj, dir_mode=mode)
    _expect_refused(box, subj, caplog, "dir mode")


@pytest.mark.parametrize("mode", [0o775, 0o757])
@pytest.mark.parametrize("subj", SUBJECTS, ids=lambda s: s.name)
def test_group_or_other_writable_apps_root_is_no_record(box, subj, mode, caplog):
    set_marker(box)
    plant(box, subj)
    os.chmod(box.apps, mode)
    _expect_refused(box, subj, caplog, "apps root mode")


@pytest.mark.parametrize("subj", SUBJECTS, ids=lambda s: s.name)
def test_symlinked_file_is_no_record(box, subj, caplog):
    set_marker(box)
    d, f = plant(box, subj)
    real = box.tmp / "elsewhere.json"
    f.rename(real)
    f.symlink_to(real)
    _expect_refused(box, subj, caplog, "symlinked file")


@pytest.mark.parametrize("subj", SUBJECTS, ids=lambda s: s.name)
def test_symlinked_lease_directory_is_no_record(box, subj, caplog):
    set_marker(box)
    d, f = plant(box, subj)
    real = box.tmp / "elsewhere"
    d.rename(real)
    d.symlink_to(real)
    _expect_refused(box, subj, caplog, "symlinked directory")


@pytest.mark.parametrize("subj", SUBJECTS, ids=lambda s: s.name)
def test_symlinked_apps_root_is_no_record(box, subj, caplog):
    set_marker(box)
    plant(box, subj)
    real = box.home / "real_apps"
    box.apps.rename(real)
    box.apps.symlink_to(real)
    _expect_refused(box, subj, caplog, "symlinked apps root")


@pytest.mark.parametrize("subj", SUBJECTS, ids=lambda s: s.name)
def test_non_regular_file_is_no_record(box, subj, caplog):
    set_marker(box)
    d, f = plant(box, subj)
    f.unlink()
    os.mkfifo(f, 0o644)
    _expect_refused(box, subj, caplog, "fifo")


@pytest.mark.parametrize("subj", SUBJECTS, ids=lambda s: s.name)
def test_swapped_inode_between_check_and_open_is_no_record(box, subj, monkeypatch, caplog):
    """The file is replaced after the ownership check and before the open: the
    pinned (dev, ino) differs, so the bytes are never trusted."""
    set_marker(box)
    d, f = plant(box, subj)
    real_lstat = paths.provisioned_lstat

    def racing(target, marker, *, want_dir):
        info = real_lstat(target, marker, want_dir=want_dir)
        if not want_dir and target == f:
            other = d / "planted.tmp"
            other.write_text(json.dumps(subj.record()))
            os.replace(other, f)
        return info

    monkeypatch.setattr(paths, "provisioned_lstat", racing)
    _expect_refused(box, subj, caplog, "swapped inode")


@pytest.mark.parametrize("subj", SUBJECTS, ids=lambda s: s.name)
def test_symlink_swapped_in_after_the_check_is_no_record(box, subj, monkeypatch, caplog):
    """O_NOFOLLOW: a symlink dropped in place of the checked file after the lstat."""
    set_marker(box)
    d, f = plant(box, subj)
    real_lstat = paths.provisioned_lstat

    def racing(target, marker, *, want_dir):
        info = real_lstat(target, marker, want_dir=want_dir)
        if not want_dir and target == f:
            evil = box.tmp / "evil.json"
            evil.write_text(json.dumps(subj.record()))
            f.unlink()
            f.symlink_to(evil)
        return info

    monkeypatch.setattr(paths, "provisioned_lstat", racing)
    _expect_refused(box, subj, caplog, "symlink swapped in")


# ── marker states ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("subj", SUBJECTS, ids=lambda s: s.name)
def test_expired_lease_in_a_trusted_tree_is_still_expired(box, subj):
    if subj is Binding:
        pytest.skip("bindings carry no deadline")
    set_marker(box)
    plant(box, subj, subj.record(expires=_past()))
    assert subj.status() == "expired"


@pytest.mark.parametrize("subj", SUBJECTS, ids=lambda s: s.name)
def test_malformed_record_in_a_trusted_tree_keeps_its_own_status(box, subj):
    set_marker(box)
    d, f = plant(box, subj)
    f.write_text("{not json")
    assert not subj.ok(box)
    if subj is not Binding:
        assert subj.read()["status"] == "malformed"


@pytest.mark.parametrize("subj", SUBJECTS, ids=lambda s: s.name)
def test_no_marker_is_unchanged(box, subj, owned_by):
    """Dev boxes and tests: a world-writable, symlinked, broker-owned record is read as always."""
    d, f = plant(box, subj, dir_mode=0o777, file_mode=0o666)
    owned_by(f, BROKER)
    owned_by(d, BROKER)
    assert subj.ok(box)
    real = box.tmp / "elsewhere.json"
    f.rename(real)
    f.symlink_to(real)
    assert subj.ok(box)


@pytest.mark.parametrize("subj", [Lease, Build], ids=lambda s: s.name)
def test_absent_lease_dir_or_file_is_none_under_a_marker(box, subj):
    set_marker(box)
    assert subj.read()["status"] == "none"                  # no directory at all
    (box.apps / subj.sub).mkdir()
    os.chmod(box.apps / subj.sub, 0o755)
    assert subj.read()["status"] == "none"                  # directory, no file


def test_absent_binding_is_unbound_under_a_marker(box):
    set_marker(box)
    assert Binding.read() is None
    assert identity_binding.load_binding("google", "sub1") is None


@pytest.mark.parametrize("subj", SUBJECTS, ids=lambda s: s.name)
def test_unusable_marker_fails_closed(box, subj, caplog):
    set_marker(box)
    plant(box, subj)
    assert subj.ok(box)
    os.chmod(trust_marker.marker_path(), 0o666)            # present but group/other-writable: invalid
    with caplog.at_level(logging.ERROR):
        assert not subj.ok(box)
    assert log_names_d06(caplog)
    if subj is not Binding:
        r = subj.read()
        assert r["status"] == "untrusted" and "marker" in r["error"]


@pytest.mark.parametrize("subj", SUBJECTS, ids=lambda s: s.name)
def test_marker_bound_to_another_home_fails_closed(box, subj):
    elsewhere = box.tmp / "other-home"
    elsewhere.mkdir()
    set_marker(box, home=elsewhere)
    plant(box, subj)
    assert not subj.ok(box)


@pytest.mark.parametrize("subj", SUBJECTS, ids=lambda s: s.name)
def test_marker_with_a_different_trust_owner_fails_closed(box, subj, monkeypatch):
    set_marker(box, uid=EUID + 3)                           # the process resolves EUID
    plant(box, subj)
    assert not subj.ok(box)


# ── the WILLOW_MCP_APPS_ROOT lever ──────────────────────────────────────────

@pytest.fixture
def lever(box, monkeypatch):
    """A second apps root, set through the lever, holding a record for the subject."""
    alt = box.tmp / "alt_apps"
    alt.mkdir()
    os.chmod(alt, 0o755)
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(alt))
    return alt


@pytest.mark.parametrize("subj", SUBJECTS, ids=lambda s: s.name)
def test_lever_is_honoured_without_a_marker(box, lever, subj):
    d = lever / subj.sub
    d.mkdir()
    (d / subj.fname).write_text(json.dumps(subj.record()))
    assert subj.ok(box)


@pytest.mark.parametrize("subj", SUBJECTS, ids=lambda s: s.name)
def test_lever_is_ignored_under_a_marker(box, lever, subj, caplog):
    set_marker(box)
    d = lever / subj.sub
    d.mkdir()
    os.chmod(d, 0o755)
    f = d / subj.fname
    f.write_text(json.dumps(subj.record()))
    os.chmod(f, 0o644)                                       # a perfectly owned tree -- but not the default root
    with caplog.at_level(logging.ERROR):
        assert not subj.ok(box)
    assert any("WILLOW_MCP_APPS_ROOT" in r.getMessage() and "IGNORED" in r.getMessage() for r in caplog.records)
    plant(box, subj)                                         # the default root's record is the one read
    assert subj.ok(box)


@pytest.mark.parametrize("subj", SUBJECTS, ids=lambda s: s.name)
def test_lever_with_an_unusable_marker_fails_closed_without_raising(box, lever, subj):
    set_marker(box)
    os.chmod(trust_marker.marker_path(), 0o666)
    plant(box, subj)
    assert not subj.ok(box)                                  # reader neither raises nor falls back to the lever


def test_writers_use_the_root_the_readers_use_under_a_marker(box, lever):
    set_marker(box)
    assert lease._leases_root(create=True) == box.apps / "_net_leases"
    assert build_lease._leases_root(create=True) == box.apps / "_build_leases"
    assert identity_binding._bindings_root() == box.apps / "_identity_bindings"
    assert not (lever / "_net_leases").exists()


def test_writers_honour_the_lever_without_a_marker(box, lever):
    assert lease._leases_root(create=True) == lever / "_net_leases"
    assert build_lease._leases_root(create=True) == lever / "_build_leases"
    assert identity_binding._bindings_root() == lever / "_identity_bindings"


def test_self_writable_report_follows_the_same_root(box, lever):
    set_marker(box)
    plant(box, Lease)
    (box.apps / "kart").mkdir()
    (box.apps / "kart" / "manifest.json").write_text("{}")
    got = {f["key"]: f["path"] for f in lease.self_writable_trust_paths("kart")}
    assert got.get("manifest", "").startswith(str(box.apps))


# ── what a rejected binding does to its writers ─────────────────────────────

def test_confirm_binding_names_the_trust_violation(box, owned_by):
    set_marker(box)
    d, f = plant(box, Binding, {"idp": "google", "subject_id": "sub1", "app_id": None, "confirmed": False})
    owned_by(f, BROKER)
    with pytest.raises(ValueError, match="not in a trust-owned tree"):
        identity_binding.confirm_binding("google", "sub1", "kart")


def test_propose_binding_never_overwrites_an_untrusted_store(box, owned_by):
    set_marker(box)
    d, f = plant(box, Binding)
    before = f.read_bytes()
    owned_by(f, BROKER)
    rec = identity_binding.propose_binding("google", "sub1", "a@b.c")
    assert f.read_bytes() == before                           # not clobbered
    assert rec["confirmed"] is False and rec["app_id"] is None and rec["untrusted"]


def test_propose_binding_still_writes_a_fresh_one_in_a_trusted_tree(box):
    set_marker(box)
    rec = identity_binding.propose_binding("google", "sub9", "a@b.c")
    assert rec["confirmed"] is False
    assert (box.apps / "_identity_bindings" / "google__sub9.json").exists()
    assert identity_binding.load_binding("google", "sub9")["email"] == "a@b.c"


def test_a_confirmed_round_trip_works_under_a_marker(box):
    """propose -> confirm -> resolve, all in a tree the trust owner owns."""
    set_marker(box)
    identity_binding.propose_binding("google", "sub2", None)
    assert identity_binding.resolve_app_id("google", "sub2") is None
    identity_binding.confirm_binding("google", "sub2", "kart")
    assert identity_binding.resolve_app_id("google", "sub2") == "kart"


def test_lease_grant_round_trip_under_a_marker(box):
    set_marker(box)
    lease.grant("kart", 600, issuer="op", reason="t")
    assert lease.read_lease("kart")["status"] == "active"
    assert lease.revoke("kart") is True
    assert lease.read_lease("kart")["status"] == "none"


def test_list_leases_reports_untrusted_rows(box, owned_by):
    set_marker(box)
    d, f = plant(box, Lease)
    owned_by(f, BROKER)
    rows = lease.list_leases()
    assert [r["status"] for r in rows] == ["untrusted"]


# ── the shared helper ───────────────────────────────────────────────────────

def test_marker_gated_read_states(box, owned_by):
    d = box.apps / "_x"
    d.mkdir()
    os.chmod(d, 0o755)
    f = d / "a.json"
    f.write_text("{}")
    os.chmod(f, 0o644)
    chain = [box.apps, d]
    assert paths.marker_gated_read(chain, f)[0] == paths.READ_UNMARKED
    set_marker(box)
    assert paths.marker_gated_read(chain, f) == (paths.READ_OK, b"{}", "")
    assert paths.marker_gated_read(chain, d / "nope.json")[0] == paths.READ_ABSENT
    assert paths.marker_gated_read([box.apps, box.apps / "nodir"], d / "a.json")[0] == paths.READ_ABSENT
    owned_by(f, BROKER)
    assert paths.marker_gated_read(chain, f)[0] == paths.READ_UNTRUSTED


def test_violation_is_a_permission_error_so_existing_callers_still_catch_it(box):
    assert issubclass(paths.ProvisionedViolation, PermissionError)


# ── the bytes used are the bytes that were checked ──────────────────────────

@pytest.mark.parametrize("subj", SUBJECTS, ids=lambda s: s.name)
def test_the_pinned_bytes_are_what_gets_parsed(box, subj, monkeypatch):
    """The reader parses the bytes `provisioned_read` returned, not a second
    read of the path (which could have been swapped since)."""
    set_marker(box)
    d, f = plant(box, subj)
    f.write_text("{garbage, swapped after the check")
    good = json.dumps(subj.record()).encode()
    monkeypatch.setattr(paths, "provisioned_read", lambda marker, dirs, file: good)
    assert subj.ok(box)


def test_marker_gated_read_maps_other_os_errors_to_untrusted(box, monkeypatch):
    set_marker(box)

    def boom(marker, dirs, file):
        raise OSError(5, "EIO")

    monkeypatch.setattr(paths, "provisioned_read", boom)
    state, data, detail = paths.marker_gated_read([box.apps], box.apps / "x.json")
    assert state == paths.READ_UNTRUSTED and data is None and "EIO" in detail


def test_marker_gated_read_maps_an_os_refusal_to_unreadable(box, monkeypatch):
    set_marker(box)

    def denied(marker, dirs, file):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(paths, "provisioned_read", denied)
    assert paths.marker_gated_read([box.apps], box.apps / "x.json")[0] == paths.READ_UNREADABLE


def test_reader_root_drops_the_lever_when_the_marker_is_unusable(box, lever):
    set_marker(box)
    assert paths.reader_apps_root() == box.apps                    # valid marker: lever ignored
    os.chmod(trust_marker.marker_path(), 0o666)
    assert paths.reader_apps_root() == box.apps                    # unusable marker: still not the lever


def test_a_symlink_swapped_in_after_the_check_is_named_a_symlink(box, monkeypatch):
    set_marker(box)
    d, f = plant(box, Lease)
    real_lstat = paths.provisioned_lstat

    def racing(target, marker, *, want_dir):
        info = real_lstat(target, marker, want_dir=want_dir)
        if not want_dir and target == f:
            evil = box.tmp / "evil.json"
            evil.write_text(json.dumps(Lease.record()))
            f.unlink()
            f.symlink_to(evil)
        return info

    monkeypatch.setattr(paths, "provisioned_lstat", racing)
    assert "is a symlink (refused)" in lease.read_lease("kart")["error"]


# ── the surfaces that report a lease name the new status ────────────────────

def test_blockers_and_the_gates_panel_name_an_untrusted_lease(box, monkeypatch):
    from willow_mcp import blockers, federation_tool_egress, gates_panel

    row = {"app_id": "kart", "status": "untrusted", "path": "/x/kart.json", "error": "uid 1000 owns it",
           "expires_at": None, "remaining_seconds": None}
    monkeypatch.setattr(lease, "read_lease", lambda app_id: dict(row))
    monkeypatch.setattr(federation_tool_egress, "seat_uses_net_egress", lambda app_id: True)
    item = blockers._check_lease("kart")
    assert item is not None and "trust-owned" in str(item) and "uid 1000 owns it" in str(item)
    rows = [r for r in gates_panel._app_rows("kart") if r.id == "lease.kart"]
    assert rows and rows[0].state == "off" and rows[0].detail == "uid 1000 owns it"
