"""D4 install side: install.sh writes the root-owned trust-provisioned marker
and `--check` reports it. Shell functions run against tmp trees as an
unprivileged user (the way tests/test_manifest_grant_head_units.py runs the
other mg_* checks); real root and the real /etc are named in INSTALL.md."""
from __future__ import annotations

import os
import subprocess

import pytest
from test_manifest_grant_head_units import _INSTALL_SH, _ME, _Box, _sh


@pytest.fixture
def bx(tmp_path):
    b = _Box(tmp_path)
    b.home = tmp_path / "vaulthome"
    b.home.mkdir()
    b.marker = b.etc / "trust-provisioned"
    return b


def _me():
    return subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip()


def _write(bx):
    return _sh(bx.tmp, f'mg_write_marker "{bx.marker}" "{bx.home}" "{_me()}" "{_me()}" "{_ME}"')


def _problems(bx):
    r = _sh(bx.tmp, f'mg_marker_problems "{bx.marker}" "{bx.home}" "{_me()}" "{_me()}" "{_ME}"')
    assert r.returncode == 0, r.stderr
    return r.stdout


def _report(bx, clone):
    me = _me()
    return _sh(
        bx.tmp,
        f'mg_report "{clone}" "{bx.py}" "{me}" "{bx.home}" "/gn" "{bx.etc}" "{bx.sysd}" '
        f'"{bx.stamp}" "{bx.sha}" "willow_db" "{me}" "{_ME}"',
    )


def test_writer_makes_a_valid_marker_atomically(bx):
    r = _write(bx)
    assert r.returncode == 0, r.stderr
    assert bx.marker.read_text() == (
        f"willow_home={os.path.realpath(bx.home)}\ntrust_owner_uid={os.getuid()}\n"
    )
    assert oct(bx.marker.stat().st_mode & 0o777) == "0o644"
    assert _problems(bx) == ""
    assert [p.name for p in bx.etc.iterdir() if p.name.startswith(".trust-provisioned.")] == []


def test_check_reports_info_when_absent_and_ok_when_valid(bx):
    clone = bx.committed_dir()
    bx.install_into_etc(clone, "willow_db")
    base = _report(bx, clone)
    # the unit text pins the real vault path, which a tmp tree cannot match:
    # compare FAIL counts against this baseline instead of the exit code
    assert "[info] " in base.stdout and "trust-provisioned is absent" in base.stdout
    assert "[FAIL] trust-provisioned" not in base.stdout
    assert _write(bx).returncode == 0
    r = _report(bx, clone)
    assert "[ok]   trust-provisioned marker" in r.stdout
    assert r.stdout.count("[FAIL]") == base.stdout.count("[FAIL]")


def _break(bx, how):
    if how == "symlink":
        real = bx.tmp / "real"
        real.write_text(bx.marker.read_text())
        bx.marker.unlink()
        bx.marker.symlink_to(real)
    elif how == "mode":
        bx.marker.chmod(0o664)
    elif how == "owner":
        pass  # handled via wrong expected owner in the report call
    elif how == "home":
        bx.marker.write_text("willow_home=/elsewhere\ntrust_owner_uid=%d\n" % os.getuid())
        bx.marker.chmod(0o644)
    elif how == "uid":
        bx.marker.write_text(f"willow_home={os.path.realpath(bx.home)}\ntrust_owner_uid=99999\n")
        bx.marker.chmod(0o644)
    elif how == "extra":
        bx.marker.write_text(bx.marker.read_text() + "evil=1\n")
        bx.marker.chmod(0o644)
    elif how == "parent":
        bx.etc.chmod(0o775)


@pytest.mark.parametrize("how", ["symlink", "mode", "home", "uid", "extra", "parent"])
def test_check_fails_on_an_invalid_marker(bx, how):
    clone = bx.committed_dir()
    bx.install_into_etc(clone, "willow_db")
    assert _write(bx).returncode == 0
    _break(bx, how)
    r = _report(bx, clone)
    assert r.returncode == 1, r.stdout
    assert "[FAIL] trust-provisioned marker" in r.stdout
    assert "[ok]   trust-provisioned" not in r.stdout


def test_writer_refuses_and_leaves_nothing_when_it_cannot_validate(bx):
    r = _sh(bx.tmp, f'mg_write_marker "{bx.marker}" "{bx.tmp}/no/such/home" "{_me()}" "{_me()}" "{_ME}"')
    assert r.returncode != 0
    assert not bx.marker.exists()


def test_install_writes_the_marker_after_trust_is_published():
    plain = _INSTALL_SH.split('say "== 6. re-sign everything', 1)[1].split("# ------------------ 6b.", 1)[0]
    assert plain.index("sign_and_publish_trust") < plain.index("write_trust_marker")
    rotate = _INSTALL_SH.split('sign_and_publish_trust "$NEW_FPR" "$OLD_FPR"', 1)[1].split("strip_pgp_pin", 1)[0]
    assert "write_trust_marker" in rotate
    fn = _INSTALL_SH.split("write_trust_marker() {", 1)[1].split("\n}\n", 1)[0]
    assert "40-hex" in fn or "{40}" in fn and fn.index("{40}") < fn.index("mg_write_marker")


def test_problems_name_a_wrongly_owned_parent_and_marker(bx):
    assert _write(bx).returncode == 0
    r = _sh(bx.tmp, f'mg_marker_problems "{bx.marker}" "{bx.home}" "{_me()}" "nobody-such" "{_ME}"')
    assert r.stdout.count("is owned by") == 2  # the parent and the grandparent
    assert "expected nobody-such" in r.stdout


def test_a_failed_rewrite_leaves_the_existing_marker_untouched(bx):
    assert _write(bx).returncode == 0
    before = bx.marker.read_text()
    other = bx.tmp / "other-home"
    other.mkdir()
    bx.etc.chmod(0o775)  # the new marker cannot validate here
    r = _sh(bx.tmp, f'mg_write_marker "{bx.marker}" "{other}" "{_me()}" "{_me()}" "{_ME}"')
    assert r.returncode != 0
    assert bx.marker.read_text() == before
