"""D1 bite 2: install.sh writes and checks the trust-identity record
(docs/design/d1-trust-dir-identity.md section 6); NO runtime reader uses it.

Three layers, in the style of tests/test_trust_marker_install.py and
tests/test_manifest_grant_pinned_head.py:

* the installer step (``willow_mcp.install_steps.trust_identity_record``) run
  in-process against a tmp box: precheck, audit, the atomic writer, rewrite,
  re-record, ``--check`` lines, and the ``trust_root_setup`` mkdir guard;
* the REAL shell functions of install.sh (the ``# BEGIN trust-identity`` block)
  sourced into a harness whose ``$PY`` is a wrapper that runs that same step with
  the compiled-in marker/record paths and "root" uid pointed at the tmp box;
* END-TO-END slices of install.sh itself (the plain-install pre-check through
  step 1's ``chown -R``, and the whole ``--re-record-trust-identity`` branch),
  cut out by marker and run with recording stubs for ``chown``/``setfacl``/
  ``install`` so "chown never ran" is asserted, not assumed.

Real root, real /etc and the real gpg keyring are not exercised here; the
INSTALL.md procedure and the commit report say what a root run showed.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from test_manifest_grant_head_units import _BLOCK, _INSTALL_SH

from willow_mcp import trust_identity as ti
from willow_mcp import trust_marker as tm
from willow_mcp import trust_root_setup as trs
from willow_mcp.install_steps import trust_identity_record as ri

_FPR = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"
_ME_U = subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip()
_ME_G = subprocess.run(["id", "-gn"], capture_output=True, text=True).stdout.strip()
_TI_BLOCK = _INSTALL_SH.split("# BEGIN trust-identity\n", 1)[1].split("# END trust-identity\n", 1)[0]
# the argument defaults, exactly as install.sh declares them before it parses anything
_DEFAULTS = 'CHECK_ONLY=""\n' + _INSTALL_SH.split('CHECK_ONLY=""\n', 1)[1].split("RETIRE_FPRS=()\n", 1)[0]


# ── the tmp box ───────────────────────────────────────────────────────────

class Box:
    """A provisioned-looking box: $H with the three recorded directories, a
    seat, trust.env, a valid D4 marker; /etc stand-in; record ABSENT."""

    def __init__(self, tmp: Path, monkeypatch):
        self.tmp = tmp
        self.etc = tmp / "etc"
        self.etc.mkdir()
        self.etc.chmod(0o755)
        self.home = tmp / "vault" / "box"
        for d in ("constitutional", "mcp_apps/seatA", "manifest_grants/pending", "manifest_grants/done", "manifest_grants/failed"):
            (self.home / d).mkdir(parents=True)
        for d in (self.home, self.home / "constitutional", self.home / "mcp_apps", self.home / "mcp_apps/seatA",
                  self.home / "manifest_grants", self.home / "manifest_grants/pending",
                  self.home / "manifest_grants/done", self.home / "manifest_grants/failed"):
            d.chmod(0o755)
        (self.home / "constitutional/trust.env").write_text(f"WILLOW_PGP_FINGERPRINT={_FPR}\n")
        (self.home / "constitutional/trust.env").chmod(0o644)
        self.manifest = self.home / "mcp_apps/seatA/manifest.json"
        self.manifest.write_text(json.dumps({"app_id": "seatA", "permissions": []}))
        (self.home / "mcp_apps/seatA/manifest.json.sig").write_text("sig")
        for f in (self.manifest, self.manifest.with_name("manifest.json.sig")):
            f.chmod(0o644)
        self.marker = self.etc / "trust-provisioned"
        self.marker.write_text(f"willow_home={os.path.realpath(self.home)}\ntrust_owner_uid={os.getuid()}\n")
        self.marker.chmod(0o644)
        self.record = self.etc / "trust-identity"
        monkeypatch.setattr(tm, "_MARKER_PATH", self.marker)
        monkeypatch.setattr(tm, "_ROOT_UID", os.getuid())
        monkeypatch.setattr(ti, "_RECORD_PATH", self.record)
        monkeypatch.setattr(ri, "_ROOT_GID", os.getgid())
        ti.reset_openat2_probe()

    # one place that models "an attacker planted a copy": a new inode with the same contents
    def plant(self, name: str) -> None:
        d = self.home / name
        aside = self.home / f"{name}.aside"
        d.rename(aside)
        shutil.copytree(aside, d, symlinks=True)

    def run(self, *argv: str) -> int:
        return ri.main(list(argv))

    def first_record(self) -> ti.IdentityRecord:
        rec = ti.compute_record(self.home, trust_fingerprint=_FPR)
        ri.install_record(rec)
        return rec

    def args(self, cmd: str, *more: str, fpr: str = _FPR) -> list[str]:
        return [cmd, "--home", str(self.home), *(["--fingerprint", fpr] if fpr else []), *more]

    def audit_args(self) -> list[str]:
        return self.args("audit", "--trust-owner-uid", str(os.getuid()), "--operator-uid", str(os.getuid()))


@pytest.fixture
def bx(tmp_path, monkeypatch):
    return Box(tmp_path, monkeypatch)


def _out(capsys) -> str:
    c = capsys.readouterr()
    return c.out + c.err


# ── precheck ──────────────────────────────────────────────────────────────

def test_precheck_absent_then_match(bx, capsys):
    assert bx.run(*bx.args("precheck")) == 0
    assert _out(capsys).strip() == "ABSENT"
    bx.first_record()
    assert bx.run(*bx.args("precheck")) == 0
    assert _out(capsys).strip() == "MATCH"


@pytest.mark.parametrize("name", ["constitutional", "mcp_apps", "manifest_grants"])
def test_precheck_stops_on_a_planted_recorded_dir(bx, capsys, name):
    bx.first_record()
    capsys.readouterr()
    bx.plant(name)
    assert bx.run(*bx.args("precheck")) == 10
    out = _out(capsys)
    assert out.startswith("DIFFERS") and f"{name}: ino" in out


def test_precheck_stops_on_a_replaced_home(bx, capsys):
    bx.first_record()
    capsys.readouterr()
    (bx.tmp / "vault" / "box").rename(bx.tmp / "vault" / "box.aside")
    shutil.copytree(bx.tmp / "vault" / "box.aside", bx.tmp / "vault" / "box", symlinks=True)
    assert bx.run(*bx.args("precheck")) == 10
    assert "home: ino" in _out(capsys)


@pytest.mark.parametrize("name", ["constitutional", "mcp_apps", "manifest_grants"])
def test_precheck_stops_on_a_missing_recorded_dir_and_does_not_recreate_it(bx, capsys, name):
    bx.first_record()
    capsys.readouterr()
    shutil.rmtree(bx.home / name)
    assert bx.run(*bx.args("precheck")) == 10
    out = _out(capsys)
    assert "DIFFERS" in out and "does not exist" in out and "not re-created" in out
    assert not (bx.home / name).exists()


def test_precheck_stops_on_a_changed_mode_and_on_a_changed_fingerprint(bx, capsys):
    bx.first_record()
    capsys.readouterr()
    (bx.home / "mcp_apps").chmod(0o750)
    assert bx.run(*bx.args("precheck")) == 10
    assert "mcp_apps: mode 755 -> 750" in _out(capsys)
    (bx.home / "mcp_apps").chmod(0o755)
    assert bx.run(*bx.args("precheck", fpr="B" * 40)) == 10
    assert "trust_fingerprint differs" in _out(capsys)
    # no fingerprint on the command line (trust.env gone): identity only, the recorded one stands in
    assert bx.run(*bx.args("precheck", fpr="")) == 0


@pytest.mark.parametrize("how", ["garbage", "mode", "nomarker", "oldversion"])
def test_precheck_stops_on_an_invalid_record(bx, capsys, how):
    bx.first_record()
    capsys.readouterr()
    if how == "garbage":
        bx.record.write_text("version=1\nnonsense\n")
    elif how == "mode":
        bx.record.chmod(0o666)
    elif how == "nomarker":
        bx.marker.unlink()
    elif how == "oldversion":
        bx.record.write_text(bx.record.read_text().replace("version=1", "version=9"))
    assert bx.run(*bx.args("precheck")) == 11
    assert _out(capsys).startswith("INVALID:")


# ── the audit ─────────────────────────────────────────────────────────────

def test_audit_clean_prints_ok_lines_and_a_snapshot(bx, capsys):
    assert bx.run(*bx.audit_args()) == 0
    out = capsys.readouterr().out
    assert "[FAIL]" not in out and out.count("[ok]") >= 7
    assert re.search(r"(?m)^snapshot=[0-9a-f]{16}$", out)
    for want in ("D4 marker", "$WILLOW_HOME", "constitutional/", "mcp_apps/", "manifest_grants/", "D4.5", "trust.env"):
        assert want in out


def _dirty(bx: Box, how: str) -> None:
    if how == "const_gw":
        (bx.home / "constitutional").chmod(0o775)
    elif how == "apps_ow":
        (bx.home / "mcp_apps").chmod(0o757)
    elif how == "home_gw":
        bx.home.chmod(0o775)
    elif how == "grants_ow":
        (bx.home / "manifest_grants").chmod(0o757)
    elif how == "symlink_in_apps":
        (bx.home / "mcp_apps/seatA/evil").symlink_to("/etc/passwd")
    elif how == "file_gw":
        bx.manifest.chmod(0o664)
    elif how == "appid_mismatch":
        bx.manifest.write_text(json.dumps({"app_id": "seatB"}))
    elif how == "no_sig":
        bx.manifest.with_name("manifest.json.sig").unlink()
    elif how == "bad_json":
        bx.manifest.write_text("{not json")
    elif how == "trust_env_empty":
        (bx.home / "constitutional/trust.env").write_text("WILLOW_PGP_FINGERPRINT=\n")
    elif how == "trust_env_other":
        (bx.home / "constitutional/trust.env").write_text("WILLOW_PGP_FINGERPRINT=" + "C" * 40 + "\n")
    elif how == "const_symlink":
        (bx.home / "constitutional/link").symlink_to("/etc")
    elif how == "governed_gw":
        (bx.home / "constitutional/pre-approved.json").write_text("{}")
        (bx.home / "constitutional/pre-approved.json").chmod(0o666)
    elif how == "no_marker":
        bx.marker.unlink()
    elif how == "pending_symlink":
        (bx.home / "manifest_grants/pending").rmdir()
        (bx.home / "manifest_grants/pending").symlink_to("done")
    else:
        raise AssertionError(how)


@pytest.mark.parametrize("how", [
    "const_gw", "apps_ow", "home_gw", "grants_ow", "symlink_in_apps", "file_gw", "appid_mismatch", "no_sig",
    "bad_json", "trust_env_empty", "trust_env_other", "const_symlink", "governed_gw", "no_marker", "pending_symlink",
])
def test_audit_fails_on_each_dirty_box(bx, capsys, how):
    _dirty(bx, how)
    assert bx.run(*bx.audit_args()) == 1, how
    assert "[FAIL]" in capsys.readouterr().out


def test_audit_allows_the_acl_mask_group_bits_on_manifest_grants(bx, capsys):
    """setfacl u:trust-owner:rwx raises manifest_grants/'s group bits to the ACL mask: only 'other' counts there."""
    (bx.home / "manifest_grants").chmod(0o775)
    assert bx.run(*bx.audit_args()) == 0, capsys.readouterr().out


def test_audit_reports_but_does_not_fail_an_ungoverned_file_in_constitutional(bx, capsys):
    q = bx.home / "constitutional/review_queue.json"
    q.write_text("[]")
    q.chmod(0o666)
    assert bx.run(*bx.audit_args()) == 0
    out = capsys.readouterr().out
    assert "[info] not a governed file" in out and "review_queue.json" in out


def test_audit_notes_a_manifest_without_an_app_id_as_allowed(bx, capsys):
    bx.manifest.write_text(json.dumps({"permissions": []}))
    assert bx.run(*bx.audit_args()) == 0
    assert "declare no app_id" in capsys.readouterr().out


def test_audit_never_opens_the_home_env_file(bx, monkeypatch, capsys):
    (bx.home / "env").write_text("SECRET=1\n")
    real_open, real_scandir = os.open, os.scandir
    seen: list[str] = []
    monkeypatch.setattr(os, "open", lambda p, *a, **k: (seen.append(str(p)), real_open(p, *a, **k))[1])
    monkeypatch.setattr(os, "scandir", lambda p: (seen.append(str(p)), real_scandir(p))[1])
    assert bx.run(*bx.audit_args()) == 0
    assert not [s for s in seen if s.rstrip("/").endswith("/env") or "vault.db" in s or "broker_signing_key" in s], seen


# ── the writer ────────────────────────────────────────────────────────────

def test_first_write_is_root_0644_parses_and_equals_compute_record(bx, capsys):
    assert bx.run(*bx.args("write", "--mode", "first")) == 0
    st = os.lstat(bx.record)
    assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o644 and st.st_uid == tm._ROOT_UID
    text = bx.record.read_text()
    live = ti.compute_record(bx.home, trust_fingerprint=_FPR)
    assert text == ti.render_record(live)  # the exact bytes of render_record
    assert ti.parse_record(text) == live
    assert ti.read_record() == live
    assert [p.name for p in bx.etc.iterdir() if p.name.startswith(".trust-identity")] == []
    assert "wrote" in capsys.readouterr().out


def test_first_write_needs_the_marker_and_leaves_nothing_without_it(bx, capsys):
    bx.marker.unlink()
    assert bx.run(*bx.args("write", "--mode", "first")) == 2
    assert "marker" in _out(capsys)
    assert not bx.record.exists()
    assert [p.name for p in bx.etc.iterdir() if p.name.startswith(".trust-identity")] == []


def test_first_write_refuses_when_a_record_exists_valid_or_not(bx, capsys):
    bx.first_record()
    before = bx.record.read_bytes()
    assert bx.run(*bx.args("write", "--mode", "first")) == 2
    bx.record.write_text("junk\n")
    assert bx.run(*bx.args("write", "--mode", "first")) == 2
    assert "already exists" in _out(capsys)
    assert bx.record.read_text() == "junk\n" and before != b"junk\n"


def test_first_write_refuses_when_the_identity_changed_since_the_audit(bx, capsys):
    assert bx.run(*bx.audit_args()) == 0
    snap = re.search(r"snapshot=(\w+)", capsys.readouterr().out).group(1)
    bx.plant("mcp_apps")  # between the audit and the write
    assert bx.run(*bx.args("write", "--mode", "first", "--expect-snapshot", snap)) == 2
    assert "changed since the audit" in _out(capsys)
    assert not bx.record.exists()


def test_snapshot_ignores_mode_and_uid_but_not_inodes(bx):
    a = ri.snapshot_of(ti.compute_record(bx.home, trust_fingerprint=_FPR))
    (bx.home / "mcp_apps").chmod(0o750)
    assert ri.snapshot_of(ti.compute_record(bx.home, trust_fingerprint=_FPR)) == a
    bx.plant("mcp_apps")
    assert ri.snapshot_of(ti.compute_record(bx.home, trust_fingerprint=_FPR)) != a


def test_writer_restores_the_previous_record_if_the_landed_one_does_not_read_back(bx, monkeypatch):
    rec = bx.first_record()
    old = bx.record.read_bytes()
    other = ti.compute_record(bx.home, trust_fingerprint="B" * 40)
    monkeypatch.setattr(ti, "read_record", lambda: rec)  # claims the old record landed, not `other`
    with pytest.raises(ri.Refused, match="previous record state was restored"):
        ri.install_record(other)
    assert bx.record.read_bytes() == old


def test_writer_unlinks_a_first_record_that_does_not_read_back(bx, monkeypatch):
    monkeypatch.setattr(ti, "read_record", lambda: (_ for _ in ()).throw(ti.TrustIdentityError("nope")))
    with pytest.raises(ri.Refused):
        ri.install_record(ti.compute_record(bx.home, trust_fingerprint=_FPR))
    assert not bx.record.exists()


def test_writer_refuses_a_group_writable_etc_and_leaves_nothing(bx):
    bx.etc.chmod(0o775)
    with pytest.raises(ri.Refused):
        ri.install_record(ti.compute_record(bx.home, trust_fingerprint=_FPR))
    assert list(bx.etc.iterdir()) == [bx.marker]


def test_writer_temp_is_validated_before_it_replaces_anything(bx, monkeypatch):
    rec = bx.first_record()
    old = bx.record.read_bytes()
    monkeypatch.setattr(ti, "parse_record", lambda text: (_ for _ in ()).throw(ti.TrustIdentityError("bad")))
    with pytest.raises(ti.TrustIdentityError):
        ri.install_record(ti.compute_record(bx.home, trust_fingerprint="B" * 40))
    assert bx.record.read_bytes() == old
    assert [p.name for p in bx.etc.iterdir() if p.name.startswith(".trust-identity")] == []
    assert rec


# ── rewrite (a plain install / --rotate keeping the record current) ───────

def test_rewrite_of_an_unchanged_box_writes_nothing(bx, capsys):
    bx.first_record()
    ino = os.stat(bx.record).st_ino
    assert bx.run(*bx.args("write", "--mode", "rewrite")) == 0
    assert "already current" in capsys.readouterr().out
    assert os.stat(bx.record).st_ino == ino


def test_rewrite_refuses_a_changed_identity_and_keeps_the_old_record(bx, capsys):
    bx.first_record()
    old = bx.record.read_bytes()
    bx.plant("mcp_apps")  # planted during the install
    assert bx.run(*bx.args("write", "--mode", "rewrite")) == 2
    assert "differ from the record" in _out(capsys)
    assert bx.record.read_bytes() == old


def test_rewrite_changes_only_the_fingerprint_and_only_when_allowed(bx, capsys):
    bx.first_record()
    assert bx.run(*bx.args("write", "--mode", "rewrite", fpr="B" * 40)) == 2  # a plain install may not change it
    assert "trust_fingerprint" in _out(capsys)
    assert bx.run(*bx.args("write", "--mode", "rewrite", "--allow-fingerprint-change", fpr="B" * 40)) == 0
    assert ti.read_record().trust_fingerprint == "B" * 40
    bx.plant("constitutional")  # a rotate may not absorb a changed inode either
    assert bx.run(*bx.args("write", "--mode", "rewrite", "--allow-fingerprint-change", fpr="C" * 40)) == 2
    assert ti.read_record().trust_fingerprint == "B" * 40


def test_rewrite_needs_a_valid_record(bx, capsys):
    assert bx.run(*bx.args("write", "--mode", "rewrite")) == 2
    bx.first_record()
    bx.record.write_text("junk\n")
    assert bx.run(*bx.args("write", "--mode", "rewrite")) == 2
    assert "invalid" in _out(capsys)


# ── re-record ─────────────────────────────────────────────────────────────

def test_rerecord_needs_an_existing_record(bx, capsys):
    assert bx.run(*bx.args("write", "--mode", "rerecord", "--confirm", "rr-x")) == 2
    assert "no trust-identity record to re-record" in _out(capsys)
    assert not bx.record.exists()


def test_rerecord_wrong_or_absent_confirmation_writes_nothing(bx, capsys, monkeypatch):
    bx.first_record()
    old = bx.record.read_bytes()
    bx.plant("mcp_apps")
    monkeypatch.setattr(ri, "_tty_confirm", lambda token: None)  # no terminal
    assert bx.run(*bx.args("write", "--mode", "rerecord")) == 3
    out = _out(capsys)
    assert "confirmation required" in out and re.search(r"rr-[0-9a-f]{12}", out)
    assert bx.record.read_bytes() == old
    for wrong in ("rr-000000000000", "RE-RECORD", "", "yes"):
        assert bx.run(*bx.args("write", "--mode", "rerecord", "--confirm", wrong)) == 2
        assert bx.record.read_bytes() == old
    monkeypatch.setattr(ri, "_tty_confirm", lambda token: "rr-nope")
    assert bx.run(*bx.args("write", "--mode", "rerecord")) == 2
    assert bx.record.read_bytes() == old


def test_rerecord_with_the_right_token_writes_and_the_token_binds_the_tree(bx, capsys, monkeypatch):
    bx.first_record()
    bx.plant("mcp_apps")
    monkeypatch.setattr(ri, "_tty_confirm", lambda token: None)
    assert bx.run(*bx.args("write", "--mode", "rerecord")) == 3
    token = re.search(r"rr-[0-9a-f]{12}", _out(capsys)).group(0)
    bx.plant("constitutional")  # the tree moved on after the token was shown
    assert bx.run(*bx.args("write", "--mode", "rerecord", "--confirm", token)) == 2
    assert bx.run(*bx.args("write", "--mode", "rerecord")) == 3
    token2 = re.search(r"rr-[0-9a-f]{12}", _out(capsys)).group(0)
    assert token2 != token
    assert bx.run(*bx.args("write", "--mode", "rerecord", "--confirm", token2)) == 0
    assert ti.read_record() == ti.compute_record(bx.home, trust_fingerprint=_FPR)
    assert bx.run(*bx.args("precheck")) == 0


def test_rerecord_prompts_on_the_terminal_and_accepts_the_typed_token(bx, capsys, monkeypatch):
    bx.first_record()
    bx.plant("mcp_apps")
    seen = []
    monkeypatch.setattr(ri, "_tty_confirm", lambda token: (seen.append(token), token)[1])
    assert bx.run(*bx.args("write", "--mode", "rerecord")) == 0
    assert seen and ti.read_record() == ti.compute_record(bx.home, trust_fingerprint=_FPR)


def test_rerecord_repairs_an_invalid_record(bx, capsys, monkeypatch):
    bx.first_record()
    bx.record.write_text("junk\n")
    monkeypatch.setattr(ri, "_tty_confirm", lambda token: token)
    assert bx.run(*bx.args("write", "--mode", "rerecord")) == 0
    assert ti.read_record() is not None


def test_rerecord_of_a_box_with_a_missing_recorded_dir_is_refused(bx, capsys):
    bx.first_record()
    shutil.rmtree(bx.home / "manifest_grants")
    assert bx.run(*bx.args("write", "--mode", "rerecord", "--confirm", "rr-x")) == 2
    assert not (bx.home / "manifest_grants").exists()


def test_diff_shows_old_to_live_or_the_invalidity(bx, capsys):
    bx.first_record()
    capsys.readouterr()
    bx.plant("mcp_apps")
    assert bx.run(*bx.args("diff")) == 0
    out = capsys.readouterr().out
    assert "old record -> live" in out and "mcp_apps: ino" in out and "dir.mcp_apps" in out
    bx.record.write_text("junk\n")
    assert bx.run(*bx.args("diff")) == 0
    assert "old record: INVALID" in capsys.readouterr().out


# ── --check lines ─────────────────────────────────────────────────────────

def test_check_lines(bx, capsys):
    assert bx.run(*bx.args("check")) == 4
    assert capsys.readouterr().out.strip() == "[info] trust-identity record absent (run with --record-trust-identity after the audit)"
    bx.first_record()
    assert bx.run(*bx.args("check")) == 0
    assert capsys.readouterr().out.strip() == "[ok]   trust-identity record valid and matches live"
    bx.plant("mcp_apps")
    assert bx.run(*bx.args("check")) == 1
    out = capsys.readouterr().out
    assert out.startswith("  [FAIL] trust-identity record differs") and "- mcp_apps: ino" in out
    bx.record.write_text("junk\n")
    assert bx.run(*bx.args("check")) == 1
    out = capsys.readouterr().out
    assert out.startswith("  [FAIL] trust-identity record is invalid") and "- " in out


def test_check_names_a_missing_recorded_dir(bx, capsys):
    bx.first_record()
    capsys.readouterr()
    shutil.rmtree(bx.home / "constitutional")
    assert bx.run(*bx.args("check")) == 1
    assert "differs" in capsys.readouterr().out


# ── Q-D1-6: the trust_root_setup sweep ────────────────────────────────────

def test_the_hardening_sweep_does_not_recreate_a_recorded_dir(bx, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(bx.home))
    monkeypatch.delenv("WILLOW_MCP_APPS_ROOT", raising=False)
    monkeypatch.setattr(trs, "resolve_trust_owner", lambda owner: _ME_U)
    monkeypatch.setattr(trs, "_run_privileged", lambda argv, dry_run=False: None)
    bx.first_record()
    shutil.rmtree(bx.home / "mcp_apps")
    with pytest.raises(ti.TrustIdentityMissing, match="recorded trust directory"):
        trs.apply_trust_root_hardening(_ME_U)
    assert not (bx.home / "mcp_apps").exists()


def test_the_hardening_sweep_still_creates_a_missing_dir_when_there_is_no_record(bx, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(bx.home))
    monkeypatch.delenv("WILLOW_MCP_APPS_ROOT", raising=False)
    monkeypatch.setattr(trs, "resolve_trust_owner", lambda owner: _ME_U)
    monkeypatch.setattr(trs, "_run_privileged", lambda argv, dry_run=False: None)
    shutil.rmtree(bx.home / "mcp_apps")
    trs.apply_trust_root_hardening(_ME_U)
    assert (bx.home / "mcp_apps").is_dir()


def test_the_guard_refuses_a_missing_recorded_parent_and_an_invalid_record_but_not_an_existing_dir(bx):
    bx.first_record()
    shutil.rmtree(bx.home / "manifest_grants")
    with pytest.raises(ti.TrustIdentityMissing):
        trs._refuse_recreating_recorded_dir(bx.home / "manifest_grants" / "pending" / "x")
    trs._refuse_recreating_recorded_dir(bx.home / "something_else")  # not a recorded dir
    trs._refuse_recreating_recorded_dir(bx.home / "mcp_apps" / "newseat")  # parent exists
    bx.record.write_text("junk\n")
    with pytest.raises(ti.TrustIdentityError, match="refusing to create"):
        trs._refuse_recreating_recorded_dir(bx.home / "x")


def test_the_repair_sweep_does_not_recreate_a_recorded_dir(bx, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(bx.home))
    bx.first_record()
    shutil.rmtree(bx.home / "manifest_grants")
    monkeypatch.setattr(trs, "runtime_writable_directories", lambda: [bx.home / "manifest_grants" / "pending"])
    monkeypatch.setattr(trs, "runtime_writable_home_children", lambda: [])
    monkeypatch.setattr(trs, "resolve_runtime_user", lambda u: _ME_U)
    with pytest.raises(ti.TrustIdentityMissing):
        trs.repair_runtime_permissions(_ME_U)
    assert not (bx.home / "manifest_grants").exists()


# ── the shell layer: the REAL functions of install.sh's trust-identity block ──

class Sh:
    """A harness that sources the trust-venv-check block (mg_marker_problems,
    mg_write_marker) and the trust-identity block, with ``$PY`` a wrapper that runs
    the same installer step in a python whose marker/record paths and 'root' uid
    point at the tmp box, and ``rotate_resign --check`` a fake that reports
    ``$tmp/sigmode`` (ok | bad)."""

    def __init__(self, bx: Box):
        self.bx = bx
        t = bx.tmp
        (t / "sigmode").write_text("ok")
        (t / "patched_main.py").write_text(f"""
import os, sys
from pathlib import Path
from willow_mcp import trust_identity as ti, trust_marker as tm
from willow_mcp.install_steps import trust_identity_record as ri
tm._MARKER_PATH = Path({str(bx.marker)!r})
ti._RECORD_PATH = Path({str(bx.record)!r})
tm._ROOT_UID = os.getuid()
ri._ROOT_GID = os.getgid()
sys.exit(ri.main(sys.argv[1:]))
""")
        (t / "fake_resign.py").write_text(f"""
import sys
mode = open({str(t / 'sigmode')!r}).read().strip()
files = [a for a in sys.argv[1:] if a.startswith('/')]
for f in files:
    print(f"  {{f}}: " + ("OK — verifies under X" if mode == "ok" else "MISMATCH — signed by Y, expected X"))
sys.exit(0 if mode == "ok" else 1)
""")
        (t / "pywrap").write_text(f"""#!/bin/sh
mod=$3
shift 3
case "$mod" in
  willow_mcp.install_steps.trust_identity_record) exec {sys.executable} -I {t / 'patched_main.py'} "$@" ;;
  willow_mcp.install_steps.rotate_resign) exec {sys.executable} {t / 'fake_resign.py'} "$@" ;;
esac
echo "pywrap: unexpected module $mod" >&2; exit 99
""")
        (t / "pywrap").chmod(0o755)
        self.calls = t / "calls.log"

    def prelude(self) -> str:
        b, t = self.bx, self.bx.tmp
        return f"""set -euo pipefail
say() {{ printf '%s\\n' "$*"; }}
stop() {{ printf 'STOP: %s\\n' "$*" >&2; exit 2; }}
{_BLOCK}
{_DEFAULTS}
{_TI_BLOCK}
H="{b.home}"; ETC="{b.etc}"; TRUST_ENV="$H/constitutional/trust.env"
TRUST_OWNER="{_ME_U}"; OPERATOR_UID={os.getuid()}; PY="{t / 'pywrap'}"
MG_ROOT_USER="{_ME_U}"; MG_ROOT_GROUP="{_ME_G}"
as_op() {{ "$@"; }}
governed_files() {{ find "$H/mcp_apps" -name manifest.json | sort; }}
chown()  {{ echo "chown $*"  >> "{self.calls}"; }}
chmod()  {{ echo "chmod $*"  >> "{self.calls}"; }}
setfacl() {{ echo "setfacl $*" >> "{self.calls}"; }}
install() {{ echo "install $*" >> "{self.calls}"; }}
"""

    def run(self, body: str, *, sigmode: str = "ok") -> subprocess.CompletedProcess:
        (self.bx.tmp / "sigmode").write_text(sigmode)
        script = self.bx.tmp / "_h.sh"
        script.write_text(self.prelude() + body + "\n")
        env = {"PATH": os.environ["PATH"], "LC_ALL": "C", "HOME": str(self.bx.tmp)}
        # no controlling terminal: /dev/tty must not open, so a prompt can never hang a test
        return subprocess.run(["bash", str(script)], capture_output=True, text=True, env=env, start_new_session=True,
                              stdin=subprocess.DEVNULL, timeout=120)

    def called(self) -> list[str]:
        return self.calls.read_text().splitlines() if self.calls.exists() else []


@pytest.fixture
def sh(bx):
    return Sh(bx)


def _ino(p: Path) -> int:
    return os.stat(p).st_ino


# mg_trust_env_fpr

def test_trust_env_fpr_reads_the_one_forty_hex_value(sh, bx):
    te = bx.home / "constitutional/trust.env"
    for text, want in ((f"WILLOW_PGP_FINGERPRINT={_FPR}\n", _FPR), (f"export WILLOW_PGP_FINGERPRINT={_FPR}\n", _FPR),
                       (f"WILLOW_PGP_FINGERPRINT={'1' * 40}\nWILLOW_PGP_FINGERPRINT={_FPR}\n", _FPR)):
        te.write_text(text)
        r = sh.run(f'mg_trust_env_fpr "{te}"')
        assert r.returncode == 0 and r.stdout.strip() == want, (text, r.stderr)
    for text in ("WILLOW_PGP_FINGERPRINT=\n", "WILLOW_PGP_FINGERPRINT=" + "A" * 39 + "\n", "# WILLOW_PGP_FINGERPRINT=" + "A" * 40 + "\n", ""):
        te.write_text(text)
        assert sh.run(f'mg_trust_env_fpr "{te}"').returncode == 1, text
    assert sh.run(f'mg_trust_env_fpr "{bx.tmp}/nope"').returncode == 1


def test_write_trust_marker_still_requires_the_same_fingerprint_shape():
    fn = _INSTALL_SH.split("write_trust_marker() {", 1)[1].split("\n}\n", 1)[0]
    assert 'mg_trust_env_fpr "$TRUST_ENV"' in fn and fn.index("mg_trust_env_fpr") < fn.index("mg_write_marker")
    assert "{40}" in _TI_BLOCK.split("mg_trust_env_fpr() {", 1)[1].split("\n}\n", 1)[0]


# identity_precheck

def test_precheck_absent_and_match_proceed(sh, bx):
    r = sh.run('identity_precheck; echo "STATE=$TI_STATE"')
    assert r.returncode == 0 and "STATE=absent" in r.stdout, r.stderr
    bx.first_record()
    r = sh.run('identity_precheck; echo "STATE=$TI_STATE"')
    assert r.returncode == 0 and "STATE=valid" in r.stdout and "valid and matches" in r.stdout, r.stderr


@pytest.mark.parametrize("name", ["constitutional", "mcp_apps", "manifest_grants"])
def test_precheck_stops_with_the_diff_and_the_recovery_text_on_a_plant(sh, bx, name):
    bx.first_record()
    bx.plant(name)
    r = sh.run('identity_precheck; echo UNREACHED')
    assert r.returncode == 2 and "UNREACHED" not in r.stdout
    assert f"{name}: ino" in r.stderr and "--re-record-trust-identity" in r.stderr
    assert "Never delete" in r.stderr and "rename-away" in r.stderr


def test_precheck_stops_on_a_missing_dir_and_an_invalid_record(sh, bx):
    bx.first_record()
    shutil.rmtree(bx.home / "mcp_apps")
    r = sh.run("identity_precheck")
    assert r.returncode == 2 and "does not exist" in r.stderr and not (bx.home / "mcp_apps").exists()
    (bx.home / "mcp_apps").mkdir()
    bx.record.write_text("junk\n")
    r = sh.run("identity_precheck")
    assert r.returncode == 2 and "is invalid" in r.stderr


# identity_gate_first / write_trust_identity

def test_first_install_without_the_flag_prints_the_audit_and_writes_no_record(sh, bx):
    r = sh.run('identity_precheck; identity_gate_first; write_trust_identity')
    assert r.returncode == 0, r.stderr
    assert "read-only audit" in r.stdout and "[ok]" in r.stdout and "--record-trust-identity" in r.stdout
    assert "[info] no trust-identity record" in r.stdout
    assert not bx.record.exists()


def test_a_dirty_audit_without_the_flag_does_not_stop_the_install_and_never_records(sh, bx):
    (bx.home / "constitutional").chmod(0o775)
    r = sh.run('identity_precheck; identity_gate_first; write_trust_identity')
    assert r.returncode == 0 and "[FAIL]" in r.stdout and not bx.record.exists()


def test_the_flag_with_a_clean_audit_writes_the_first_record(sh, bx):
    r = sh.run('RECORD_FIRST=1; identity_precheck; identity_gate_first; write_trust_identity')
    assert r.returncode == 0, r.stderr
    assert "audit clean" in r.stdout and "wrote" in r.stdout
    st = os.lstat(bx.record)
    assert stat.S_IMODE(st.st_mode) == 0o644 and st.st_uid == os.getuid()
    assert bx.record.read_text() == ti.render_record(ti.compute_record(bx.home, trust_fingerprint=_FPR))


def test_the_flag_with_a_dirty_audit_stops_and_writes_nothing(sh, bx):
    r = sh.run('RECORD_FIRST=1; identity_precheck; identity_gate_first; echo UNREACHED', sigmode="bad")
    assert r.returncode == 2 and "UNREACHED" not in r.stdout
    assert "[FAIL]" in r.stdout and "do not verify" in r.stdout and "NOT written" in r.stderr
    assert not bx.record.exists()
    for how in ("const_gw", "symlink_in_apps", "appid_mismatch"):
        _dirty(bx, how)
        r = sh.run('RECORD_FIRST=1; identity_precheck; identity_gate_first; echo UNREACHED')
        assert r.returncode == 2 and not bx.record.exists(), how
        (bx.home / "constitutional").chmod(0o755)
        (bx.home / "mcp_apps/seatA/evil").unlink(missing_ok=True)
        bx.manifest.write_text(json.dumps({"app_id": "seatA"}))


def test_the_flag_needs_an_already_provisioned_box(sh, bx):
    bx.marker.unlink()
    r = sh.run('RECORD_FIRST=1; identity_precheck; identity_gate_first')
    assert r.returncode == 2 and "already-provisioned" in r.stderr and not bx.record.exists()
    r = sh.run('identity_precheck; identity_gate_first')
    assert r.returncode == 0 and "needs a provisioned box" in r.stdout


def test_the_audit_snapshot_guards_the_window_between_the_gate_and_step_6(sh, bx):
    r = sh.run('RECORD_FIRST=1; identity_precheck; identity_gate_first; mv "$H/mcp_apps" "$H/aside"; cp -a "$H/aside" "$H/mcp_apps"; write_trust_identity; echo UNREACHED')
    assert r.returncode == 2 and "UNREACHED" not in r.stdout and "changed since the audit" in r.stderr
    assert not bx.record.exists()


def test_the_flag_alone_never_writes_without_a_clean_audit_state(sh, bx):
    """write_trust_identity itself re-checks consent: the flag without TI_AUDIT_RC=0 writes nothing."""
    r = sh.run('RECORD_FIRST=1; TI_STATE=absent; TI_AUDIT_RC=1; TI_SNAPSHOT=x; write_trust_identity')
    assert r.returncode == 0 and not bx.record.exists()
    r = sh.run('RECORD_FIRST=""; TI_STATE=absent; TI_AUDIT_RC=0; TI_SNAPSHOT=x; write_trust_identity')
    assert r.returncode == 0 and not bx.record.exists() and "[info] no trust-identity record" in r.stdout


def test_write_trust_identity_keeps_a_valid_record_current_and_rotate_moves_the_fingerprint(sh, bx):
    bx.first_record()
    ino = _ino(bx.record)
    r = sh.run("identity_precheck; write_trust_identity")
    assert r.returncode == 0 and "already current" in r.stdout and _ino(bx.record) == ino
    new = "B" * 40
    (bx.home / "constitutional/trust.env").write_text(f"WILLOW_PGP_FINGERPRINT={new}\n")
    r = sh.run("TI_STATE=valid; write_trust_identity")
    assert r.returncode == 2 and ti.read_record().trust_fingerprint == _FPR  # a plain install does not move it
    r = sh.run("TI_STATE=valid; write_trust_identity rotate")
    assert r.returncode == 0 and ti.read_record().trust_fingerprint == new


def test_write_trust_identity_refuses_to_run_without_a_precheck_and_without_a_fingerprint(sh, bx):
    assert sh.run("write_trust_identity").returncode == 2
    (bx.home / "constitutional/trust.env").write_text("WILLOW_PGP_FINGERPRINT=\n")
    r = sh.run("TI_STATE=absent; write_trust_identity")
    assert r.returncode == 2 and "no 40-hex fingerprint" in r.stderr


def test_identity_no_recreate(sh, bx):
    r = sh.run("TI_STATE=valid; identity_no_recreate; echo OK")
    assert "OK" in r.stdout
    shutil.rmtree(bx.home / "manifest_grants")
    r = sh.run("TI_STATE=valid; identity_no_recreate; echo UNREACHED")
    assert r.returncode == 2 and "refusing to re-create" in r.stderr and "UNREACHED" not in r.stdout
    assert sh.run("TI_STATE=absent; identity_no_recreate").returncode == 0


# identity_check_report

def test_check_report_states(sh, bx):
    r = sh.run("identity_check_report")
    assert r.returncode == 0 and "[info] trust-identity record absent (run with --record-trust-identity after the audit)" in r.stdout
    assert "read-only audit before the first record" in r.stdout
    r = sh.run("identity_check_report", sigmode="bad")
    assert r.returncode == 1 and "[FAIL]" in r.stdout  # an absent record on an unclean box is a FAIL
    bx.first_record()
    r = sh.run("identity_check_report")
    assert r.returncode == 0 and "[ok]   trust-identity record valid and matches live" in r.stdout
    bx.plant("mcp_apps")
    r = sh.run("identity_check_report")
    assert r.returncode == 1 and "[FAIL] trust-identity record differs" in r.stdout and "mcp_apps: ino" in r.stdout
    bx.record.write_text("junk\n")
    r = sh.run("identity_check_report")
    assert r.returncode == 1 and "[FAIL] trust-identity record is invalid" in r.stdout


def test_check_report_skips_the_audit_when_there_is_no_marker(sh, bx):
    bx.marker.unlink()
    r = sh.run("identity_check_report")
    assert r.returncode == 0 and "audit" not in r.stdout.replace("after the audit", "")


# ── end to end: slices of install.sh itself ───────────────────────────────

_PLAIN_FROM = 'say "== trust-identity pre-check (D1)"'
_PLAIN_TO = 'chown -R "$TRUST_OWNER:$TRUST_OWNER" "$H/mcp_apps"\n'
_PLAIN = _PLAIN_FROM + _INSTALL_SH.split(_PLAIN_FROM, 1)[1].split(_PLAIN_TO, 1)[0] + _PLAIN_TO

_RR_FROM = 'if [ -n "$RERECORD" ]; then\n  say "== --re-record-trust-identity'
_RR = _RR_FROM + _INSTALL_SH.split(_RR_FROM, 1)[1].split("\nfi\n", 1)[0] + "\nfi\n"


def _plain(sh: Sh, bx: Box, pre: str = "") -> subprocess.CompletedProcess:
    (bx.home / "env").write_text("WILLOW_PG_DB=x\n")
    (bx.home / "env").chmod(0o600)
    return sh.run(f"{pre}\nOPERATOR={_ME_U}\n{_PLAIN}\necho STEP1_REACHED_CHOWN")


def test_plain_install_matching_record_reaches_step_1(sh, bx):
    bx.first_record()
    r = _plain(sh, bx)
    assert r.returncode == 0 and "STEP1_REACHED_CHOWN" in r.stdout, r.stderr
    assert any(c.startswith("chown -R") for c in sh.called())


@pytest.mark.parametrize("name", ["constitutional", "mcp_apps", "manifest_grants"])
def test_plain_install_stops_before_chown_and_install_d_on_a_planted_tree(sh, bx, name):
    bx.first_record()
    bx.plant(name)
    r = _plain(sh, bx)
    assert r.returncode == 2 and "STEP1_REACHED_CHOWN" not in r.stdout
    assert sh.called() == [], sh.called()  # no chown, no chmod, no setfacl, no install -d
    assert f"{name}: ino" in r.stderr


def test_plain_install_missing_recorded_dir_stops_and_is_not_recreated(sh, bx):
    bx.first_record()
    shutil.rmtree(bx.home / "manifest_grants")
    r = _plain(sh, bx)
    assert r.returncode == 2 and "does not exist" in r.stderr
    assert sh.called() == [] and not (bx.home / "manifest_grants").exists()


def test_plain_install_invalid_record_stops_before_step_1(sh, bx):
    bx.first_record()
    bx.record.write_text("junk\n")
    r = _plain(sh, bx)
    assert r.returncode == 2 and "is invalid" in r.stderr and sh.called() == []


def test_plain_install_without_a_record_runs_step_1_as_before_and_prints_the_audit(sh, bx):
    r = _plain(sh, bx)
    assert r.returncode == 0 and "STEP1_REACHED_CHOWN" in r.stdout and "read-only audit" in r.stdout
    assert not bx.record.exists() and any(c.startswith("chown -R") for c in sh.called())


def test_plain_install_flag_with_a_dirty_audit_stops_before_step_1(sh, bx):
    (bx.home / "mcp_apps").chmod(0o777)
    r = _plain(sh, bx, "RECORD_FIRST=1")
    assert r.returncode == 2 and sh.called() == [] and not bx.record.exists()


def test_plain_install_step_1_does_not_recreate_a_dir_that_vanishes_after_the_precheck(sh, bx):
    bx.first_record()
    r = _plain(sh, bx, 'identity_precheck() { TI_STATE=valid; rm -rf "$H/constitutional"; }')
    assert r.returncode == 2 and "refusing to re-create" in r.stderr and sh.called() == []


# the re-record branch

def _rerecord(sh: Sh, *, confirm: str = "", sigmode: str = "ok") -> subprocess.CompletedProcess:
    c = f'RERECORD_CONFIRM="{confirm}"' if confirm else ""
    return sh.run(f'RERECORD=1; {c}\n{_RR}\necho FELL_THROUGH', sigmode=sigmode)


def _token(r) -> str:
    return r.stdout.split("token is ", 1)[1].split()[0]


def test_rerecord_branch_shows_diff_audit_and_requires_a_confirmation(sh, bx):
    bx.first_record()
    old = bx.record.read_bytes()
    bx.plant("mcp_apps")
    r = _rerecord(sh)
    assert r.returncode == 3 and "FELL_THROUGH" not in r.stdout
    assert "old record -> live" in r.stdout and "mcp_apps: ino" in r.stdout  # the diff
    assert "[ok]" in r.stdout and "every governed file verifies" in r.stdout  # the audit
    assert "confirmation required" in r.stdout and bx.record.read_bytes() == old  # nothing written


def test_rerecord_branch_wrong_confirmation_writes_nothing_and_right_one_writes(sh, bx):
    bx.first_record()
    old = bx.record.read_bytes()
    bx.plant("mcp_apps")
    token = _token(_rerecord(sh))
    for wrong in ("rr-000000000000", "RE-RECORD", "yes"):
        r = _rerecord(sh, confirm=wrong)
        assert r.returncode == 2 and bx.record.read_bytes() == old, wrong
    r = _rerecord(sh, confirm=token)
    assert r.returncode == 0 and "re-recorded" in r.stdout and "FELL_THROUGH" not in r.stdout, r.stderr
    assert ti.read_record() == ti.compute_record(bx.home, trust_fingerprint=_FPR)
    assert sh.run("identity_precheck; echo S=$TI_STATE").stdout.count("S=valid") == 1
    assert sh.called() == []  # a re-record never chowns or installs anything


def test_rerecord_branch_runs_the_audit_and_stops_when_it_is_not_clean(sh, bx):
    bx.first_record()
    old = bx.record.read_bytes()
    bx.plant("mcp_apps")
    r = _rerecord(sh, sigmode="bad")
    assert r.returncode == 2 and "do not verify" in r.stdout and "nothing written" in r.stderr
    (bx.home / "mcp_apps/seatA/evil").symlink_to("/etc")
    r = _rerecord(sh, confirm="rr-whatever")
    assert r.returncode == 2 and bx.record.read_bytes() == old


def test_rerecord_branch_needs_a_record_and_a_valid_marker(sh, bx):
    r = _rerecord(sh, confirm="rr-x")
    assert r.returncode == 2 and "no trust-identity record to re-record" in r.stderr and not bx.record.exists()
    bx.first_record()
    bx.marker.chmod(0o666)
    r = _rerecord(sh, confirm="rr-x")
    assert r.returncode == 2 and "marker" in r.stderr


def test_rerecord_branch_repairs_an_invalid_record_and_refuses_a_gone_dir(sh, bx):
    bx.first_record()
    bx.record.write_text("junk\n")
    token = _token(_rerecord(sh))
    assert _rerecord(sh, confirm=token).returncode == 0
    shutil.rmtree(bx.home / "mcp_apps")
    r = _rerecord(sh, confirm=token)
    assert r.returncode == 2 and not (bx.home / "mcp_apps").exists()


# arguments

_ARGS_FROM = 'CHECK_ONLY=""\nROTATE=""'
_ARGS = _ARGS_FROM + _INSTALL_SH.split(_ARGS_FROM, 1)[1].split("# ---------------------------------------------------------------- preflight", 1)[0]


def _args(tmp_path: Path, *argv: str) -> subprocess.CompletedProcess:
    script = tmp_path / "_a.sh"
    script.write_text(
        "set -euo pipefail\nstop() { printf 'STOP: %s\\n' \"$*\" >&2; exit 2; }\n" + _ARGS
        + '\necho "RF=$RECORD_FIRST RR=$RERECORD CF=$RERECORD_CONFIRM CK=$CHECK_ONLY RT=$ROTATE"\n'
    )
    return subprocess.run(["bash", str(script), *argv], capture_output=True, text=True, env={"PATH": os.environ["PATH"]})


def test_argument_combinations(tmp_path):
    ok = _args(tmp_path, "--expect-head", "a" * 40, "--record-trust-identity")
    assert ok.returncode == 0 and "RF=1 RR= " in ok.stdout
    ok = _args(tmp_path, "--re-record-trust-identity", "--confirm", "rr-0123456789ab", "--expect-head", "a" * 40)
    assert ok.returncode == 0 and "RR=1 CF=rr-0123456789ab" in ok.stdout
    for bad in (["--record-trust-identity", "--rotate"], ["--record-trust-identity", "--check"],
                ["--record-trust-identity", "--check-signatures"], ["--record-trust-identity", "--provision-venv"],
                ["--record-trust-identity", "--re-record-trust-identity"],
                ["--re-record-trust-identity", "--check"], ["--re-record-trust-identity", "--rotate"],
                ["--re-record-trust-identity", "--check-signatures"], ["--re-record-trust-identity", "--provision-venv"],
                ["--confirm", "rr-0123456789ab"], ["--re-record-trust-identity", "--confirm"],
                ["--re-record-trust-identity", "--confirm", "--expect-head", "a" * 40],
                ["--re-record-trust-identity", "--confirm", ""]):
        r = _args(tmp_path, "--expect-head", "a" * 40, *bad)
        assert r.returncode == 2 and r.stderr.startswith("STOP:"), (bad, r.stdout, r.stderr)


# ── ordering and wiring in install.sh itself ──────────────────────────────

def test_marker_is_written_before_the_record_in_plain_step_6_and_in_rotate():
    plain = _INSTALL_SH.split('say "== 6. re-sign everything', 1)[1].split("# ------------------ 6b.", 1)[0]
    assert plain.index("sign_and_publish_trust") < plain.index("write_trust_marker") < plain.index("write_trust_identity")
    rotate = _INSTALL_SH.split('sign_and_publish_trust "$NEW_FPR" "$OLD_FPR"', 1)[1].split("strip_pgp_pin", 1)[0]
    assert rotate.index("write_trust_marker") < rotate.index("write_trust_identity rotate")
    assert re.search(r"(?m)^write_trust_identity$", plain)


def test_the_precheck_runs_before_anything_that_changes_the_trust_tree():
    code = "\n".join(ln for ln in _INSTALL_SH.splitlines() if not ln.lstrip().startswith("#"))
    pre = code.index("identity_precheck\nidentity_gate_first")
    no_recreate = code.index("identity_no_recreate\n", pre)
    mutations = ('chown -R "$TRUST_OWNER:$TRUST_OWNER" "$H/mcp_apps"',
                 'install -d -o "$OPERATOR" -g "$OPERATOR" -m 755 "$H/manifest_grants"',
                 'install -d -o "$TRUST_OWNER" -g "$TRUST_OWNER" -m 755 "$H/constitutional"',
                 'chown "$TRUST_OWNER:$TRUST_OWNER" "$H/constitutional"')
    for m in mutations:
        assert code.count(m) == 1, m
        assert code.index(m) > no_recreate > pre, m
    # rotate: before key generation and re-sign
    rot = code.split('if [ -n "$ROTATE" ]; then', 1)[1]
    assert rot.index("identity_precheck") < rot.index("--quick-gen-key") < rot.index("sign_and_publish_trust")


def test_check_mode_reports_the_record_before_it_decides_to_stop():
    blk = _INSTALL_SH.split('if [ "$CHECK_ONLY" = "--check" ]; then\n  identity_check_report', 1)
    assert len(blk) == 2
    assert blk[1].index("CHECK_FAILED") < blk[1].index("exit 2")


def test_rerecord_is_dispatched_before_rotate_and_after_the_interpreter_is_enforced():
    code = "\n".join(ln for ln in _INSTALL_SH.splitlines() if not ln.lstrip().startswith("#"))
    assert code.index("enforce_trust_interpreter\nfi") < code.index('if [ -n "$RERECORD" ]; then') < code.index('if [ -n "$ROTATE" ]; then')
    assert '[ -n "$ROTATE$CHECK_SIGNATURES$RERECORD" ] || provision_trust_venv' in code  # never builds the venv
    # the typed confirmation precedes the write inside the python step, and the branch ends in exit
    assert _RR.rstrip().endswith("fi") and "exit 0" in _RR and "exit 3" in _RR


def test_the_installer_step_runs_pinned_and_never_reads_from_here():
    block = "\n".join(ln for ln in _TI_BLOCK.splitlines() if not ln.lstrip().startswith("#"))
    assert 'ti_run() { "$PY" -I -m "$TI_STEP" "$@"; }' in block
    assert "$HERE" not in block and "python3" not in block and "$PY -" not in block.replace('"$PY" -I', "")
    assert "git " not in block
    assert not re.search(r"\$H/env|vault\.db|broker_signing_key|GNUPGHOME_TO\b.*cat", block)


def test_nothing_reads_the_record_at_runtime_yet():
    """Bite 2 is write/check only: the readers (paths, pgp, gate, envelopes, ...) do not import it."""
    src = Path(ti.__file__).resolve().parent
    for f in src.glob("*.py"):
        if f.name in ("trust_identity.py", "trust_root_setup.py"):
            continue
        assert "trust_identity" not in re.sub(r"(?m)^\s*#.*$", "", f.read_text(encoding="utf-8")).replace("trust_identity_record", ""), f.name


def test_a_successful_retire_without_a_stale_marker_does_not_end_the_function_with_status_1(tmp_path):
    """Found by the first root run of D1: `[ -f M ] && rm -f M` as the last command of the retire branch returned 1
    when there was no stale-key marker, and `set -e` ended --rotate before the marker and the record were written."""
    fn = _INSTALL_SH.split("sign_and_publish_trust() {", 1)[1].split("\n}\n", 1)[0]
    assert '[ -f "$STALE_KEY_MARKER" ] &&' not in fn
    tail = fn[fn.index('  if [ -n "$old_fpr"'):]
    script = tmp_path / "t.sh"
    script.write_text(
        "set -euo pipefail\n"
        f"STALE_KEY_MARKER={tmp_path}/no-such-marker; GNUPGHOME_TO=x\n"
        "say() { :; }\nas_to() { return 0; }\n"
        f"f() {{\n  local old_fpr=A new_fpr=B\n{tail}\n}}\n"
        "f\necho SURVIVED\n"
    )
    r = subprocess.run(["bash", str(script)], capture_output=True, text=True)
    assert r.returncode == 0 and "SURVIVED" in r.stdout, r.stderr
