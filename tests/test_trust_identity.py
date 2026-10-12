"""D1 bite 1 -- the trust-identity record reader and the fd-walk helper
(docs/design/d1-trust-dir-identity.md). No caller uses the module yet; the
last test says so and bite 3 removes it on purpose.

"root" and the "trust owner" are the runner's own euid (patched into
``trust_marker._ROOT_UID`` and the marker), so the suite runs as root and
non-root alike; ownership mismatches are modelled by a record that names a
different uid, or a marker whose trust owner is somebody else."""
from __future__ import annotations

import errno
import os
import re
from pathlib import Path

import pytest

from willow_mcp import paths, trust_identity as ti, trust_marker

EUID = os.geteuid()
FPR = "9B6F87BEB4AE56E2" + "0" * 24
SRC = Path(ti.__file__).resolve().parent
TESTS = Path(__file__).resolve().parent


@pytest.fixture
def box(tmp_path, monkeypatch):
    etc = tmp_path / "etc" / "willow-mcp"
    etc.mkdir(parents=True)
    os.chmod(etc, 0o755)
    os.chmod(etc.parent, 0o755)
    home = tmp_path / "home"
    home.mkdir()
    os.chmod(home, 0o755)
    for d in ti.RECORDED_DIRS:
        (home / d).mkdir()
        os.chmod(home / d, 0o755)
    seat = home / "mcp_apps" / "seat"
    seat.mkdir()
    os.chmod(seat, 0o755)
    (seat / "manifest.json").write_text('{"app_id": "seat"}')
    (seat / "manifest.json.sig").write_text("SIG")
    (home / "constitutional" / "trust.env").write_text(f"WILLOW_PGP_FINGERPRINT={FPR}\n")
    for f in (seat / "manifest.json", seat / "manifest.json.sig", home / "constitutional" / "trust.env"):
        os.chmod(f, 0o644)
    monkeypatch.setenv("WILLOW_HOME", str(home))
    monkeypatch.setattr(trust_marker, "_MARKER_PATH", etc / "trust-provisioned")
    monkeypatch.setattr(ti, "_RECORD_PATH", etc / "trust-identity")
    monkeypatch.setattr(trust_marker, "_ROOT_UID", EUID)
    monkeypatch.setattr(trust_marker, "_GOVERNANCE_ROOT_UID", EUID + 9)
    monkeypatch.setattr(paths, "_trust_owner_uid", lambda: EUID)
    trust_marker._logged_levers.clear()
    return home


def write_marker(home, uid=EUID):
    p = trust_marker.marker_path()
    p.write_text(f"willow_home={os.path.realpath(home)}\ntrust_owner_uid={uid}\n")
    os.chmod(p, 0o644)


def own_dir(box_home, monkeypatch):
    """Put the record in its OWN root-owned /etc-like chain, so the record
    reader's directory checks are exercised and not masked by the marker's
    identical checks on the shared directory."""
    d = box_home.parent / "etc2" / "willow-mcp"
    d.mkdir(parents=True)
    os.chmod(d, 0o755)
    os.chmod(d.parent, 0o755)
    monkeypatch.setattr(ti, "_RECORD_PATH", d / "trust-identity")
    return d


def fake_uid(monkeypatch, target, uid):
    real = os.lstat
    def fake(path, *a, **k):
        st = real(path, *a, **k)
        if Path(path) == Path(target):
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, uid, *st[5:]))
        return st
    monkeypatch.setattr(os, "lstat", fake)


def write_record(home, text=None, mode=0o644, marker=True):
    if marker:
        write_marker(home)
    if text is None:
        text = ti.render_record(ti.compute_record(home, trust_fingerprint=FPR))
    p = ti.record_path()
    p.write_text(text)
    os.chmod(p, mode)
    return p


def provisioned(home):
    """(record, marker) read back from disk, the way a caller would."""
    write_record(home)
    return ti.active_record(), trust_marker.active_marker()


def edit(box_home, /, **repl):
    """The record text with `key=...` lines replaced (None removes the key)."""
    lines = ti.render_record(ti.compute_record(box_home, trust_fingerprint=FPR)).splitlines()
    out = []
    for ln in lines:
        k = ln.split("=", 1)[0]
        if k in repl:
            if repl[k] is None:
                continue
            ln = f"{k}={repl[k]}"
        out.append(ln)
    return "\n".join(out) + "\n"


MODES = [False, True]  # reference walk, openat2 attempt


# ── the record: three states ───────────────────────────────────────────────

def test_absent_record_is_none(box):
    assert ti.read_record() is None
    assert ti.active_record() is None


def test_absent_record_ignores_even_a_bad_marker(box):
    ti.record_path()  # no file
    trust_marker.marker_path().write_text("garbage")
    os.chmod(trust_marker.marker_path(), 0o666)
    assert ti.active_record() is None


def test_valid_record_round_trips(box):
    rec, _ = provisioned(box)
    assert rec.willow_home == os.path.realpath(box)
    assert rec.trust_fingerprint == FPR
    assert rec.home.ino == os.stat(box).st_ino
    assert rec.mcp_apps.ino == os.stat(box / "mcp_apps").st_ino
    assert ti.parse_record(ti.render_record(rec)) == rec


def test_record_format_is_exactly_seven_lines(box):
    write_record(box)
    lines = ti.render_record(ti.read_record()).splitlines()
    assert [ln.split("=")[0] for ln in lines] == [
        "version", "willow_home", "home", "dir.constitutional", "dir.mcp_apps",
        "dir.manifest_grants", "trust_fingerprint",
    ]
    assert lines[0] == "version=1"
    assert lines[2].startswith("home=fsid:") and " ino:" in lines[2] and " mode:755" in lines[2]


def test_lowercase_fingerprint_is_accepted_and_normalised(box):
    write_record(box, edit(box, trust_fingerprint=FPR.lower()))
    assert ti.read_record().trust_fingerprint == FPR


@pytest.mark.parametrize("why", [
    "symlink", "nonroot_file", "group_writable", "other_writable", "parent_nonroot",
    "grandparent_nonroot", "parent_wide", "grandparent_wide", "parent_symlink",
    "directory", "not_utf8",
])
def test_invalid_file_shape_raises(box, monkeypatch, why):
    d = own_dir(box, monkeypatch)
    p = write_record(box)
    if why == "symlink":
        real = p.with_name("real-record")
        p.rename(real)
        p.symlink_to(real)
    elif why == "nonroot_file":
        fake_uid(monkeypatch, p, EUID + 1)
    elif why == "group_writable":
        os.chmod(p, 0o664)
    elif why == "other_writable":
        os.chmod(p, 0o646)
    elif why == "parent_nonroot":
        fake_uid(monkeypatch, d, EUID + 1)
    elif why == "grandparent_nonroot":
        fake_uid(monkeypatch, d.parent, EUID + 1)
    elif why == "parent_wide":
        os.chmod(d, 0o777)
    elif why == "grandparent_wide":
        os.chmod(d.parent, 0o775)
    elif why == "parent_symlink":
        os.rename(d, d.with_name("real-dir"))
        d.symlink_to(d.with_name("real-dir"))
    elif why == "directory":
        p.unlink()
        p.mkdir()
    elif why == "not_utf8":
        p.write_bytes(b"\xff\xfe" + p.read_bytes())
    with pytest.raises(ti.TrustIdentityError) as ei:
        ti.read_record()
    if why == "not_utf8":
        assert "UTF-8" in str(ei.value)
    if why in ("symlink", "directory"):
        assert "regular file" in str(ei.value)
    if why == "nonroot_file":
        assert "owned by uid" in str(ei.value) and "parent" not in str(ei.value)
    if why in ("parent_wide", "grandparent_wide", "parent_nonroot", "grandparent_nonroot"):
        assert "parent" in str(ei.value)
    if why == "parent_symlink":
        assert "not a plain directory" in str(ei.value)


def test_oversize_record_raises(box, monkeypatch):
    write_record(box)
    monkeypatch.setattr(ti, "_MAX_RECORD_BYTES", 40)
    with pytest.raises(ti.TrustIdentityError, match="larger than"):
        ti.read_record()


def test_changed_between_stat_and_open_raises(box, monkeypatch):
    p = write_record(box)
    real_open = os.open
    def swap(path, flags, *a, **k):
        if Path(path) == p:
            other = p.with_name("other")
            other.write_text(p.read_text())
            os.chmod(other, 0o644)
            os.replace(other, p)
        return real_open(path, flags, *a, **k)
    monkeypatch.setattr(os, "open", swap)
    with pytest.raises(ti.TrustIdentityError, match="changed between"):
        ti.read_record()


@pytest.mark.parametrize("text", [
    "",
    "version=1",  # no trailing newline
    "version=1\n\n",  # blank line
    "# c\nversion=1\n",  # comment
])
def test_bad_grammar_text(box, text):
    write_record(box, text)
    with pytest.raises(ti.TrustIdentityError):
        ti.read_record()


def test_missing_trailing_newline_is_named(box):
    write_record(box, edit(box).rstrip("\n"))
    with pytest.raises(ti.TrustIdentityError, match="trailing newline"):
        ti.read_record()


def test_duplicate_key_raises(box):
    write_record(box, edit(box) + "version=1\n")
    with pytest.raises(ti.TrustIdentityError, match="duplicate"):
        ti.read_record()


def test_unknown_key_raises(box):
    write_record(box, edit(box) + "extra=1\n")
    with pytest.raises(ti.TrustIdentityError, match="unrecognised"):
        ti.read_record()


def test_spaces_around_equals_raise(box):
    write_record(box, edit(box).replace("version=1", "version = 1"))
    with pytest.raises(ti.TrustIdentityError):
        ti.read_record()


@pytest.mark.parametrize("v", ["2", "0", "1.0", ""])
def test_unknown_version_raises(box, v):
    write_record(box, edit(box, version=v))
    with pytest.raises(ti.TrustIdentityError, match="version"):
        ti.read_record()


@pytest.mark.parametrize("key", ["version", "willow_home", "home", "dir.constitutional",
                                 "dir.mcp_apps", "dir.manifest_grants", "trust_fingerprint"])
def test_missing_key_raises(box, key):
    write_record(box, edit(box, **{key: None}))
    with pytest.raises(ti.TrustIdentityError):
        ti.read_record()


@pytest.mark.parametrize("bad", ["/a/../b", "/a//b", "/trailing/", "/", "/a/./b", "/a\rb"])
def test_bad_willow_home_raises_even_when_the_marker_agrees(box, bad):
    """The marker accepts any absolute path, so a record home that the marker
    shares must be refused by the record's own grammar."""
    p = trust_marker.marker_path()
    p.write_text(f"willow_home={bad}\ntrust_owner_uid={EUID}\n")
    os.chmod(p, 0o644)
    write_record(box, edit(box, willow_home=bad), marker=False)
    with pytest.raises(ti.TrustIdentityError, match="normalised absolute"):
        ti.read_record()


@pytest.mark.parametrize("bad", ["", "relative/path"])
def test_empty_or_relative_willow_home_raises(box, bad):
    write_record(box, edit(box, willow_home=bad))
    with pytest.raises(ti.TrustIdentityError):
        ti.read_record()


@pytest.mark.parametrize("bad", [
    "fsid:zz ino:1 uid:0 mode:755",
    "fsid:1 ino:x uid:0 mode:755",
    "fsid:1 ino:1 uid:-1 mode:755",
    "fsid:1 ino:1 uid:0 mode:758",
    "fsid:1 ino:1 uid:0 mode:755 extra:1",
    "fsid:1  ino:1 uid:0 mode:755",
    "ino:1 fsid:1 uid:0 mode:755",
    "fsid:1 ino:1 uid:0",
    "fsid:1 ino:01 uid:0 mode:755",
    "fsid:1 ino:1 uid:0 mode:755 igen:",
])
def test_bad_dir_line_raises(box, bad):
    write_record(box, edit(box, **{"dir.mcp_apps": bad}))
    with pytest.raises(ti.TrustIdentityError):
        ti.read_record()


@pytest.mark.parametrize("fpr", ["", "ABC", "G" * 40, FPR + "0", FPR[:-1]])
def test_bad_fingerprint_raises(box, fpr):
    write_record(box, edit(box, trust_fingerprint=fpr))
    with pytest.raises(ti.TrustIdentityError, match="fingerprint"):
        ti.read_record()


def test_optional_igen_parses(box):
    write_record(box, edit(box, **{"dir.mcp_apps": "fsid:1f ino:5 uid:0 mode:755 igen:77"}))
    d = ti.read_record().mcp_apps
    assert (d.fsid, d.ino, d.uid, d.mode, d.igen) == (0x1F, 5, 0, 0o755, 77)


def test_record_without_marker_is_invalid(box):
    write_record(box, marker=False)
    with pytest.raises(ti.TrustIdentityError, match="no valid D4"):
        ti.read_record()


def test_record_with_invalid_marker_is_invalid(box):
    write_record(box)
    os.chmod(trust_marker.marker_path(), 0o666)
    with pytest.raises(ti.TrustIdentityError, match="marker"):
        ti.read_record()


def test_home_mismatch_with_marker_is_invalid(box):
    write_record(box, edit(box, willow_home="/somewhere/else"))
    with pytest.raises(ti.TrustIdentityError, match="differs from the marker"):
        ti.read_record()


def test_active_record_rechecks_the_marker_it_got(box, monkeypatch):
    write_record(box)
    monkeypatch.setattr(trust_marker, "active_marker", lambda: None)
    with pytest.raises(ti.TrustIdentityError, match="active D4 marker"):
        ti.active_record()
    monkeypatch.setattr(trust_marker, "active_marker",
                        lambda: trust_marker.TrustMarker("/other", EUID))
    with pytest.raises(ti.TrustIdentityError, match="active D4 marker"):
        ti.active_record()


def test_active_record_refuses_a_different_process_home(box, monkeypatch, tmp_path):
    write_record(box)
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    with pytest.raises(ti.TrustIdentityError, match="does not bind"):
        ti.active_record()


def test_active_record_refuses_a_different_trust_owner(box, monkeypatch):
    write_record(box)
    monkeypatch.setattr(paths, "_trust_owner_uid", lambda: EUID + 1)
    with pytest.raises(ti.TrustIdentityError, match="does not bind"):
        ti.active_record()


def test_record_path_is_a_compiled_in_constant():
    import subprocess
    import sys

    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env.update({"WILLOW_TRUST_IDENTITY": "/tmp/x", "WILLOW_TRUST_IDENTITY_PATH": "/tmp/x",
                "WILLOW_HOME": "/tmp/x", "PYTHONPATH": str(SRC.parent)})
    out = subprocess.run(
        [sys.executable, "-c", "from willow_mcp import trust_identity as t; print(t.record_path())"],
        env=env, capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert out == "/etc/willow-mcp/trust-identity"


# ── the walk: accepts a matching tree ──────────────────────────────────────

@pytest.mark.parametrize("a", MODES)
def test_walk_reads_a_manifest(box, a):
    rec, marker = provisioned(box)
    assert ti.read_trust_bytes(rec, marker, "mcp_apps/seat/manifest.json", use_openat2=a) == b'{"app_id": "seat"}'
    assert ti.read_trust_bytes(rec, marker, "mcp_apps/seat/manifest.json.sig", use_openat2=a) == b"SIG"
    assert FPR.encode() in ti.read_trust_bytes(rec, marker, "constitutional/trust.env", use_openat2=a)


@pytest.mark.parametrize("a", MODES)
def test_walk_opens_home_and_recorded_dirs(box, a):
    rec, marker = provisioned(box)
    for rel in ("", "constitutional", "mcp_apps", "manifest_grants", "mcp_apps/seat"):
        fd = ti.open_trust_dir(rec, marker, rel, use_openat2=a)
        os.close(fd)


@pytest.mark.parametrize("a", MODES)
def test_walk_missing_file_below_recorded_dir_is_file_not_found(box, a):
    rec, marker = provisioned(box)
    with pytest.raises(FileNotFoundError):
        ti.read_trust_bytes(rec, marker, "mcp_apps/seat/nope.json", use_openat2=a)
    with pytest.raises(FileNotFoundError):
        ti.read_trust_bytes(rec, marker, "mcp_apps/nobody/manifest.json", use_openat2=a)


@pytest.mark.parametrize("rel", ["store/x", "/etc/passwd", "mcp_apps/../env", "mcp_apps//x",
                                 "mcp_apps/./x", "mcp_apps\0/x", "env"])
def test_walk_refuses_paths_outside_the_recorded_dirs(box, rel):
    (box / "store").mkdir()  # exists and is a plain dir: only the recorded-dir rule refuses it
    rec, marker = provisioned(box)
    with pytest.raises(ti.TrustIdentityError):
        ti.read_trust_bytes(rec, marker, rel)


def test_walk_refuses_an_unrecorded_top_with_the_right_reason(box):
    (box / "store").mkdir()
    rec, marker = provisioned(box)
    with pytest.raises(ti.TrustIdentityError, match="not under a recorded"):
        ti.open_trust_dir(rec, marker, "store")
    with pytest.raises(ti.TrustIdentityError, match="relative"):
        ti.open_trust_dir(rec, marker, "/etc")


def test_walk_kind_checks_do_not_rely_on_the_open_flags_alone(box, monkeypatch):
    """A file opened as a directory is refused by O_DIRECTORY; with that flag
    gone the explicit kind check must still refuse it (and vice versa)."""
    rec, marker = provisioned(box)
    monkeypatch.setattr(ti, "_DIR_FLAGS", ti._DIR_FLAGS & ~os.O_DIRECTORY)
    with pytest.raises(ti.TrustIdentityError, match="not a plain directory"):
        ti.open_trust_dir(rec, marker, "mcp_apps/seat/manifest.json")


def test_open_error_messages_name_the_cause():
    sym = ti._refuse_open(OSError(errno.ELOOP, "x"), "L", missing_ok=False)
    assert isinstance(sym, ti.TrustIdentityError) and "symlink" in str(sym)
    xd = ti._refuse_open(OSError(errno.EXDEV, "x"), "L", missing_ok=False)
    assert isinstance(xd, ti.TrustIdentityError) and "mount point" in str(xd)
    assert isinstance(ti._refuse_open(OSError(errno.ENOENT, "x"), "L", missing_ok=True), FileNotFoundError)


def test_walk_refuses_a_directory_as_a_file_and_back(box):
    rec, marker = provisioned(box)
    with pytest.raises(ti.TrustIdentityError):
        ti.open_trust_file(rec, marker, "mcp_apps/seat")
    with pytest.raises(ti.TrustIdentityError):
        ti.open_trust_dir(rec, marker, "mcp_apps/seat/manifest.json")
    with pytest.raises(ti.TrustIdentityError):
        ti.open_trust_file(rec, marker, "")


def test_walk_refuses_an_oversize_file(box):
    rec, marker = provisioned(box)
    with pytest.raises(ti.TrustIdentityError, match="larger than"):
        ti.read_trust_bytes(rec, marker, "mcp_apps/seat/manifest.json", max_bytes=3)


# ── the walk: identity mismatches ──────────────────────────────────────────

def _tampered(box, name, field, value):
    """A record whose `name` line (home / dir.x) differs in `field`."""
    rec = ti.compute_record(box, trust_fingerprint=FPR)
    key = "home" if name == "home" else f"dir.{name}"
    d = rec.home if name == "home" else rec.dir_identity(name)
    kw = dict(fsid=d.fsid, ino=d.ino, uid=d.uid, mode=d.mode, igen=d.igen)
    kw[field] = value
    text = ti.render_record(rec).replace(f"{key}={d.render()}", f"{key}={ti.DirIdentity(**kw).render()}")
    write_record(box, text)
    return ti.active_record(), trust_marker.active_marker()


@pytest.mark.parametrize("a", MODES)
@pytest.mark.parametrize("name", ["home", "constitutional", "mcp_apps", "manifest_grants"])
@pytest.mark.parametrize("field,delta", [("fsid", 1), ("ino", 1), ("uid", 1), ("mode", None)])
def test_walk_refuses_any_identity_mismatch(box, a, name, field, delta):
    rec0 = ti.compute_record(box, trust_fingerprint=FPR)
    cur = (rec0.home if name == "home" else rec0.dir_identity(name))
    value = 0o700 if field == "mode" else getattr(cur, field) + delta
    rec, marker = _tampered(box, name, field, value)
    rel = {"home": "mcp_apps/seat/manifest.json"}.get(name, f"{name}/x")
    with pytest.raises(ti.TrustIdentityError, match="not the recorded"):
        ti.open_trust_file(rec, marker, rel, use_openat2=a)


@pytest.mark.parametrize("a", MODES)
def test_walk_refuses_a_planted_renamed_dir(box, a):
    rec, marker = provisioned(box)
    (box / "mcp_apps").rename(box / "mcp_apps.aside")
    planted = box / "mcp_apps"
    (planted / "seat").mkdir(parents=True)
    os.chmod(planted, 0o755)
    os.chmod(planted / "seat", 0o755)
    (planted / "seat" / "manifest.json").write_text('{"app_id": "seat"}')
    with pytest.raises(ti.TrustIdentityError, match="not the recorded"):
        ti.read_trust_bytes(rec, marker, "mcp_apps/seat/manifest.json", use_openat2=a)
    # the genuine tree renamed back: same inode, valid again
    planted_aside = box / "mcp_apps.planted"
    planted.rename(planted_aside)
    (box / "mcp_apps.aside").rename(box / "mcp_apps")
    assert ti.read_trust_bytes(rec, marker, "mcp_apps/seat/manifest.json", use_openat2=a)


@pytest.mark.parametrize("a", MODES)
def test_walk_refuses_a_replaced_home(box, a, tmp_path):
    rec, marker = provisioned(box)
    box.rename(tmp_path / "home.aside")
    box.mkdir()
    with pytest.raises(ti.TrustIdentityError, match="not the recorded"):
        ti.open_trust_dir(rec, marker, "", use_openat2=a)


@pytest.mark.parametrize("a", MODES)
@pytest.mark.parametrize("name", ["constitutional", "mcp_apps", "manifest_grants"])
def test_walk_refuses_a_missing_recorded_dir(box, a, name):
    rec, marker = provisioned(box)
    (box / name).rename(box / (name + ".gone"))
    with pytest.raises(ti.TrustIdentityMissing):
        ti.open_trust_dir(rec, marker, name, use_openat2=a)


def test_walk_refuses_a_missing_home(box, tmp_path):
    rec, marker = provisioned(box)
    box.rename(tmp_path / "gone")
    with pytest.raises(ti.TrustIdentityMissing):
        ti.open_trust_dir(rec, marker, "")


@pytest.mark.parametrize("a", MODES)
@pytest.mark.parametrize("where", ["home", "recorded", "child"])
def test_walk_refuses_a_symlink_at_any_component(box, a, where, tmp_path):
    rec, marker = provisioned(box)
    if where == "home":
        box.rename(tmp_path / "home.real")
        box.symlink_to(tmp_path / "home.real")
        rel = "mcp_apps/seat/manifest.json"
    elif where == "recorded":
        (box / "mcp_apps").rename(tmp_path / "apps.real")
        (box / "mcp_apps").symlink_to(tmp_path / "apps.real")
        rel = "mcp_apps/seat/manifest.json"
    else:
        (box / "mcp_apps" / "seat").rename(tmp_path / "seat.real")
        (box / "mcp_apps" / "seat").symlink_to(tmp_path / "seat.real")
        rel = "mcp_apps/seat/manifest.json"
    with pytest.raises(ti.TrustIdentityError):
        ti.read_trust_bytes(rec, marker, rel, use_openat2=a)


@pytest.mark.parametrize("a", MODES)
def test_walk_refuses_a_symlinked_file(box, a):
    rec, marker = provisioned(box)
    m = box / "mcp_apps" / "seat" / "manifest.json"
    m.rename(m.with_name("real.json"))
    m.symlink_to("real.json")
    with pytest.raises(ti.TrustIdentityError):
        ti.read_trust_bytes(rec, marker, "mcp_apps/seat/manifest.json", use_openat2=a)


def test_walk_refuses_a_symlinked_ancestor_of_home(box, tmp_path):
    rec, marker = provisioned(box)
    (tmp_path / "alias").symlink_to(tmp_path)
    # the record names the realpath; an ancestor swapped for a symlink to a
    # different tree must be refused by O_NOFOLLOW at that component
    outer = tmp_path.parent / (tmp_path.name + "-moved")
    tmp_path.rename(outer)
    tmp_path.symlink_to(outer)
    try:
        with pytest.raises(ti.TrustIdentityError):
            ti.open_trust_dir(rec, marker, "")
    finally:
        tmp_path.unlink()
        outer.rename(tmp_path)


# ── the walk: D4 shape below a recorded directory ──────────────────────────

@pytest.mark.parametrize("a", MODES)
@pytest.mark.parametrize("what", ["file_gw", "file_ow", "dir_gw", "foreign_owner"])
def test_shape_below_governed_dirs(box, a, what, monkeypatch):
    rec, marker = provisioned(box)
    m = box / "mcp_apps" / "seat" / "manifest.json"
    if what == "file_gw":
        os.chmod(m, 0o664)
    elif what == "file_ow":
        os.chmod(m, 0o646)
    elif what == "dir_gw":
        os.chmod(m.parent, 0o775)
    else:
        marker = trust_marker.TrustMarker(marker.willow_home, EUID + 1)
    with pytest.raises(ti.TrustIdentityError, match="untrusted ownership"):
        ti.read_trust_bytes(rec, marker, "mcp_apps/seat/manifest.json", use_openat2=a)


def test_manifest_grants_children_skip_the_owner_shape(box):
    rec, marker = provisioned(box)
    pend = box / "manifest_grants" / "pending"
    pend.mkdir()
    os.chmod(pend, 0o777)  # broker-written area: not a governed read
    (pend / "x").write_text("p")
    marker = trust_marker.TrustMarker(marker.willow_home, EUID + 1)
    assert ti.read_trust_bytes(rec, marker, "manifest_grants/pending/x") == b"p"


def test_other_filesystem_below_home_is_refused(box, monkeypatch):
    rec, marker = provisioned(box)
    real = os.fstat
    def fake(fd):
        st = real(fd)
        if st.st_ino == rec.mcp_apps.ino:
            return os.stat_result((*st[:2], st.st_dev + 1, *st[3:]))
        return st
    monkeypatch.setattr(os, "fstat", fake)
    with pytest.raises(ti.TrustIdentityError, match="different device"):
        ti.open_trust_dir(rec, marker, "mcp_apps")


# ── i_generation ───────────────────────────────────────────────────────────

def test_igen_match_mismatch_absent(box, monkeypatch):
    monkeypatch.setattr(ti, "_get_igen", lambda fd: 7)
    rec, marker = provisioned(box)
    assert rec.mcp_apps.igen == 7
    assert ti.read_trust_bytes(rec, marker, "mcp_apps/seat/manifest.json")
    monkeypatch.setattr(ti, "_get_igen", lambda fd: 8)
    with pytest.raises(ti.TrustIdentityError, match="igen 7 -> 8"):
        ti.read_trust_bytes(rec, marker, "mcp_apps/seat/manifest.json")
    # live ioctl unavailable: the recorded value is not required to match
    monkeypatch.setattr(ti, "_get_igen", lambda fd: None)
    assert ti.read_trust_bytes(rec, marker, "mcp_apps/seat/manifest.json")


def test_igen_absent_in_record_is_never_compared(box, monkeypatch):
    monkeypatch.setattr(ti, "_get_igen", lambda fd: None)
    rec, marker = provisioned(box)
    assert rec.mcp_apps.igen is None
    assert ti.render_record(rec).count("igen:") == 0
    monkeypatch.setattr(ti, "_get_igen", lambda fd: 12345)
    assert ti.read_trust_bytes(rec, marker, "mcp_apps/seat/manifest.json")


def test_igen_home_mismatch_refuses(box, monkeypatch):
    monkeypatch.setattr(ti, "_get_igen", lambda fd: 1)
    rec, marker = provisioned(box)
    monkeypatch.setattr(ti, "_get_igen", lambda fd: 2)
    with pytest.raises(ti.TrustIdentityError, match="igen"):
        ti.open_trust_dir(rec, marker, "")


def test_identity_of_reports_the_real_fsid_and_igen(box):
    import fcntl
    import struct
    fd = os.open(box, os.O_RDONLY)
    try:
        ident = ti.identity_of(fd)
        assert ident.fsid == os.fstatvfs(fd).f_fsid and ident.fsid != 0
        assert ident.ino == os.fstat(fd).st_ino
        try:
            raw = fcntl.ioctl(fd, 0x80007601 | (struct.calcsize("l") << 16), b"\0" * struct.calcsize("l"))
            expected = struct.unpack("l", raw)[0]
        except OSError:
            expected = None
        assert ti._get_igen(fd) == expected
    finally:
        os.close(fd)


def test_get_igen_never_raises(box):
    fd = os.open(box, os.O_RDONLY)
    try:
        v = ti._get_igen(fd)
        assert v is None or isinstance(v, int)
    finally:
        os.close(fd)
    assert ti._get_igen(-1) is None


# ── openat2: probe, parity, fallback ───────────────────────────────────────

def test_openat2_probe_is_cached_and_reports(box, monkeypatch):
    calls = []
    monkeypatch.setattr(ti, "_probe_openat2", lambda: calls.append(1) or True)
    ti.reset_openat2_probe()
    assert ti.openat2_available() and ti.openat2_available()
    assert calls == [1]


@pytest.mark.parametrize("err", [errno.ENOSYS, errno.EPERM, errno.EINVAL, errno.EACCES])
def test_probe_false_on_any_error(box, monkeypatch, err):
    def boom(*a, **k):
        raise OSError(err, "x")
    monkeypatch.setattr(ti, "_openat2", boom)
    ti.reset_openat2_probe()
    assert ti.openat2_available() is False


def test_unknown_architecture_has_no_openat2(box, monkeypatch):
    monkeypatch.setattr(ti.platform, "machine", lambda: "mips64")
    with pytest.raises(OSError) as ei:
        ti._openat2(0, ".", os.O_RDONLY)
    assert ei.value.errno == errno.ENOSYS
    ti.reset_openat2_probe()
    assert ti.openat2_available() is False


def test_openat2_and_walk_give_identical_results(box):
    rec, marker = provisioned(box)
    cases = [
        "mcp_apps/seat/manifest.json", "constitutional/trust.env", "mcp_apps/nobody/x",
        "mcp_apps/seat/nope", "mcp_apps/seat", "manifest_grants", "store/x",
    ]
    def run(rel, a):
        try:
            return ("ok", ti.read_trust_bytes(rec, marker, rel, use_openat2=a))
        except Exception as exc:  # compare type + message
            return (type(exc).__name__, re.sub(r"\(.*\)", "", str(exc)))
    for rel in cases:
        assert run(rel, True) == run(rel, False), rel


@pytest.mark.skipif(not ti.openat2_available(), reason="kernel/sandbox has no openat2")
def test_openat2_really_is_used_when_available(box, monkeypatch):
    rec, marker = provisioned(box)
    seen = []
    real = ti._openat2
    monkeypatch.setattr(ti, "_openat2", lambda *a: seen.append(a[1]) or real(*a))
    ti.reset_openat2_probe()
    seen.clear()
    ti.read_trust_bytes(rec, marker, "mcp_apps/seat/manifest.json")
    assert "seat" in seen and "manifest.json" in seen
    assert "mcp_apps" not in seen  # the recorded dir itself is opened plainly


@pytest.mark.skipif(not ti.openat2_available() or not os.path.isdir("/proc/self"),
                    reason="kernel/sandbox has no openat2 or /proc")
def test_openat2_kernel_refuses_a_mount_crossing():
    root = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(OSError) as e:
            ti._openat2(root, "proc", os.O_RDONLY | os.O_DIRECTORY)
        assert e.value.errno == errno.EXDEV
    finally:
        os.close(root)


@pytest.mark.skipif(not ti.openat2_available(), reason="kernel/sandbox has no openat2")
def test_openat2_kernel_refuses_symlink_and_dotdot(box):
    rec, marker = provisioned(box)
    seat = box / "mcp_apps" / "seat"
    (seat / "ln").symlink_to("manifest.json")
    fd = ti.open_trust_dir(rec, marker, "mcp_apps/seat")
    try:
        with pytest.raises(OSError) as e1:
            ti._openat2(fd, "ln", os.O_RDONLY)
        assert e1.value.errno == errno.ELOOP
        with pytest.raises(OSError) as e2:
            ti._openat2(fd, "../..", os.O_RDONLY | os.O_DIRECTORY)
        assert e2.value.errno == errno.EXDEV
    finally:
        os.close(fd)


@pytest.mark.parametrize("err", [errno.ENOSYS, errno.EPERM, errno.EINVAL])
def test_forced_fallback_after_mid_run_refusal(box, monkeypatch, err):
    rec, marker = provisioned(box)
    def boom(*a, **k):
        raise OSError(err, "filtered")
    monkeypatch.setattr(ti, "_openat2", boom)
    ti._probe_result = True  # probe said yes, the call then fails
    data = ti.read_trust_bytes(rec, marker, "mcp_apps/seat/manifest.json", use_openat2=True)
    assert data == b'{"app_id": "seat"}'
    assert ti.openat2_available() is False  # cached off


def test_other_openat2_errors_are_not_swallowed(box, monkeypatch):
    rec, marker = provisioned(box)
    def boom(*a, **k):
        raise OSError(errno.EIO, "io")
    monkeypatch.setattr(ti, "_openat2", boom)
    with pytest.raises(ti.TrustIdentityError):
        ti.read_trust_bytes(rec, marker, "mcp_apps/seat/manifest.json", use_openat2=True)


# ── the verified fd survives a rename ──────────────────────────────────────

@pytest.mark.parametrize("a", MODES)
def test_verified_fd_survives_rename_away_and_plant(box, a):
    rec, marker = provisioned(box)
    fd = ti.open_trust_file(rec, marker, "mcp_apps/seat/manifest.json", use_openat2=a)
    try:
        (box / "mcp_apps").rename(box / "mcp_apps.aside")
        planted = box / "mcp_apps" / "seat"
        planted.mkdir(parents=True)
        (planted / "manifest.json").write_text("PLANTED")
        assert os.read(fd, 100) == b'{"app_id": "seat"}'
    finally:
        os.close(fd)
    # a fresh walk now refuses the planted tree
    with pytest.raises(ti.TrustIdentityError):
        ti.read_trust_bytes(rec, marker, "mcp_apps/seat/manifest.json", use_openat2=a)


@pytest.mark.parametrize("a", MODES)
def test_rename_of_the_file_between_open_and_read(box, a):
    rec, marker = provisioned(box)
    fd = ti.open_trust_file(rec, marker, "constitutional/trust.env", use_openat2=a)
    try:
        t = box / "constitutional" / "trust.env"
        t.rename(t.with_name("trust.env.old"))
        t.write_text("WILLOW_PGP_FINGERPRINT=" + "A" * 40 + "\n")
        assert FPR.encode() in os.read(fd, 200)
    finally:
        os.close(fd)


def test_no_fd_leak_on_refusal(box, tmp_path):
    rec, marker = provisioned(box)
    bad_home = ti.IdentityRecord(
        rec.willow_home, ti.DirIdentity(rec.home.fsid, rec.home.ino + 1, rec.home.uid, rec.home.mode),
        rec.constitutional, rec.mcp_apps, rec.manifest_grants, rec.trust_fingerprint)
    before = len(os.listdir("/proc/self/fd"))
    for _ in range(20):
        with pytest.raises(ti.TrustIdentityError):
            ti.open_trust_dir(bad_home, marker, "mcp_apps")
        with pytest.raises(ti.TrustIdentityError):
            ti.read_trust_bytes(rec, marker, "store/x")
        with pytest.raises(FileNotFoundError):
            ti.read_trust_bytes(rec, marker, "mcp_apps/seat/nope")
    assert len(os.listdir("/proc/self/fd")) == before


# ── computing a record ─────────────────────────────────────────────────────

def test_compute_record_is_pure_and_matches_the_walk(box):
    before = sorted(p.name for p in box.rglob("*"))
    rec = ti.compute_record(box, trust_fingerprint=FPR)
    assert sorted(p.name for p in box.rglob("*")) == before
    assert not ti.record_path().exists()
    assert ti.diff_records(rec, ti.compute_record(box, trust_fingerprint=FPR)) == []


def test_compute_record_follows_a_symlinked_home_to_its_realpath(box, tmp_path):
    alias = tmp_path / "alias"
    alias.symlink_to(box)
    assert ti.compute_record(alias, trust_fingerprint=FPR).willow_home == os.path.realpath(box)


@pytest.mark.parametrize("name", ["constitutional", "mcp_apps", "manifest_grants"])
def test_compute_record_refuses_missing_and_symlinked_children(box, name, tmp_path):
    (box / name).rename(tmp_path / "moved")
    with pytest.raises(ti.TrustIdentityMissing):
        ti.compute_record(box, trust_fingerprint=FPR)
    (box / name).symlink_to(tmp_path / "moved")
    with pytest.raises(ti.TrustIdentityError):
        ti.compute_record(box, trust_fingerprint=FPR)


def test_compute_record_refuses_a_missing_home_and_bad_fingerprint(box, tmp_path):
    with pytest.raises(ti.TrustIdentityMissing):
        ti.compute_record(tmp_path / "nope", trust_fingerprint=FPR)
    with pytest.raises(ti.TrustIdentityError, match="fingerprint"):
        ti.compute_record(box, trust_fingerprint="xyz")


def test_diff_records_names_what_changed(box):
    a = ti.compute_record(box, trust_fingerprint=FPR)
    (box / "mcp_apps").rename(box / "old")
    (box / "mcp_apps").mkdir()
    b = ti.compute_record(box, trust_fingerprint="B" * 40)
    out = ti.diff_records(a, b)
    assert any(ln.startswith("mcp_apps: ino") for ln in out)
    assert "trust_fingerprint differs" in out


# ── no callers (bite 1) ────────────────────────────────────────────────────

_IMPORT_RE = re.compile(r"(?m)^\s*(?:from\s+(?:willow_mcp)?\.*\s*import\s+[^\n]*\btrust_identity\b"
                        r"|from\s+(?:willow_mcp)?\.*trust_identity\s+import|import\s+willow_mcp\.trust_identity)")


def _modules_importing_trust_identity(roots):
    hits = []
    for root in roots:
        for f in sorted(root.rglob("*.py")):
            # conftest: the autouse isolation fixture; test_trust_identity*: the tests of the module
            if f.name in ("trust_identity.py", "conftest.py") or f.name.startswith("test_trust_identity"):
                continue
            if _IMPORT_RE.search(f.read_text(encoding="utf-8")):
                hits.append(str(f.relative_to(root)))
    return hits


#: The only importers until bite 3 switches the readers: the installer's step
#: (bite 2: writes and checks the record) and trust_root_setup (Q-D1-6: its
#: mkdir sweep refuses to re-create a recorded directory). No READER of the
#: record (paths, pgp, gate, envelopes, constitutional, ...) may import it yet.
_BITE2_IMPORTERS = {"install_steps/trust_identity_record.py", "trust_root_setup.py"}


def test_no_reader_imports_it_yet(tmp_path):
    """Bite 2 adds exactly two importers (the installer step, and the
    trust_root_setup mkdir guard). Bite 3 removes this guard on purpose when
    the first reader is switched over."""
    assert set(_modules_importing_trust_identity([SRC, TESTS])) - {"conftest.py"} <= _BITE2_IMPORTERS
    assert _BITE2_IMPORTERS <= set(_modules_importing_trust_identity([SRC]))
    install = (SRC.parent.parent / "deploy" / "manifest-grant" / "install.sh")
    if install.exists():
        # install.sh reaches the module only through its installer step, run from the pinned venv
        code = "\n".join(ln for ln in install.read_text().splitlines() if not ln.lstrip().startswith("#"))
        assert not re.search(r"willow_mcp\.trust_identity\b", code)  # only the step module ...
        assert "install_steps.trust_identity_record" in code  # ... which is the one entry


def test_the_import_guard_fires_on_a_planted_importer(tmp_path):
    """Planted violation: each import spelling is caught."""
    for i, line in enumerate((
        "from willow_mcp import trust_identity\n",
        "from willow_mcp import paths, trust_identity as ti\n",
        "from . import trust_identity\n",
        "from .trust_identity import read_record\n",
        "from willow_mcp.trust_identity import read_record\n",
        "import willow_mcp.trust_identity\n",
        "    from . import trust_identity\n",
        "from .. import trust_identity as ti\n",
        "    from ..trust_identity import read_record\n",
    )):
        (tmp_path / f"m{i}.py").write_text(line)
    (tmp_path / "ok.py").write_text("from . import trust_marker\n# trust_identity in a comment\n")
    assert len(_modules_importing_trust_identity([tmp_path])) == 9
