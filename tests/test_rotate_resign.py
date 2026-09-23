"""deploy/manifest-grant/rotate_resign.py — batch re-sign with rollback
(dispatch B291C0C7, amending A9BF01A9). install.sh's own step 6 loop
re-signs N files with N independent gpg calls and no rollback: a failure
on file 7 of 12 would leave 1-6 signed under the new key and 7-12 under
the old one. `resign_all` gives the same all-or-nothing discipline
`sync_constitutional.sync_and_sign` already gives syscall-table.json, but
across an arbitrary list rather than one file. The real two-uid gpg
boundary stays untested here (same limit sync_constitutional's own tests
have always had) — every sign_fn/verify_fn here is a fake."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "deploy" / "manifest-grant" / "rotate_resign.py"
)
_spec = importlib.util.spec_from_file_location("rotate_resign", _MODULE_PATH)
rotate_resign = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("rotate_resign", rotate_resign)
_spec.loader.exec_module(rotate_resign)


class _FakeSigner:
    """A sign_fn/verify_fn pair that fails signing on a named path (or
    fails verification of what it just signed), and otherwise mints a
    deterministic "signature" so verify_fn can check it came from THIS
    signer's own sign_fn — exactly the shape a rollback test needs."""

    def __init__(self, fail_signing_for: "set[str] | None" = None,
                 fail_verify_for: "set[str] | None" = None, key: bytes = b"NEWKEY"):
        self.fail_signing_for = fail_signing_for or set()
        self.fail_verify_for = fail_verify_for or set()
        self.key = key
        self.sign_calls: list[str] = []
        self.verify_calls: list[str] = []

    def sign_fn(self, path: Path) -> bytes:
        self.sign_calls.append(str(path))
        if str(path) in self.fail_signing_for:
            raise RuntimeError(f"simulated gpg failure for {path}")
        return self.key + b":" + path.name.encode()

    def verify_fn(self, path: Path, sig_bytes: bytes) -> bool:
        self.verify_calls.append(str(path))
        if str(path) in self.fail_verify_for:
            return False
        return sig_bytes == self.key + b":" + path.name.encode()


def _make_files(tmp_path: Path, names: list[str], with_prior_sig: bool = True) -> list[Path]:
    paths = []
    for name in names:
        p = tmp_path / name
        p.write_text(f"content of {name}\n")
        if with_prior_sig:
            (tmp_path / f"{name}.sig").write_bytes(f"OLDSIG:{name}".encode())
        paths.append(p)
    return paths


def test_resign_all_signs_every_existing_file(tmp_path):
    files = _make_files(tmp_path, ["a.json", "b.json", "c.json"])
    signer = _FakeSigner()
    report = rotate_resign.resign_all(files, signer.sign_fn, signer.verify_fn)
    assert report["signed"] == [str(f) for f in files]
    assert report["skipped_absent"] == []
    for f in files:
        sig = tmp_path / f"{f.name}.sig"
        assert sig.read_bytes() == signer.key + b":" + f.name.encode()


def test_resign_all_preserves_a_previous_sigs_owner_and_mode_on_resign(tmp_path):
    """Loki re-audit 93D0F057, N5: a re-sign used to write the new .sig
    via a root-owned temp file plus os.replace, which does NOT carry the
    REPLACED file's ownership/mode forward -- a trust-owner-owned 0644
    .sig silently became root-owned. Any later in-place re-sign by the
    trust owner (gpg -o <path>.sig, e.g. mcp_federation.ratify) would then
    hit EACCES on a file it no longer owns. resign_all now preserves the
    PREVIOUS .sig's own (uid, gid, mode) on every re-sign -- verified here
    by giving the prior .sig an unusual mode (0640, not the default 0644)
    and confirming the fresh write keeps it."""
    files = _make_files(tmp_path, ["a.json"])
    sig = tmp_path / "a.json.sig"
    import os
    os.chmod(sig, 0o640)
    before_uid, before_gid = sig.stat().st_uid, sig.stat().st_gid
    signer = _FakeSigner()
    rotate_resign.resign_all(files, signer.sign_fn, signer.verify_fn)
    after = sig.stat()
    assert (after.st_mode & 0o777) == 0o640
    assert after.st_uid == before_uid
    assert after.st_gid == before_gid


def test_resign_all_applies_the_owner_argument_to_a_brand_new_sig(tmp_path):
    """The other half of N5: a file with NO previous .sig (first-ever
    sign) has nothing to preserve the ownership of, so it falls back to
    the `owner` argument -- normally the trust owner's (uid, gid, 0o644).
    Only self-chown (uid/gid matching this process) is exercised here,
    since a real chown to another uid needs root."""
    files = _make_files(tmp_path, ["a.json"], with_prior_sig=False)
    signer = _FakeSigner()
    import os
    owner = (os.geteuid(), os.getegid(), 0o644)
    rotate_resign.resign_all(files, signer.sign_fn, signer.verify_fn, owner=owner)
    sig = tmp_path / "a.json.sig"
    assert (sig.stat().st_mode & 0o777) == 0o644


def test_resign_all_skips_absent_paths_without_error(tmp_path):
    files = _make_files(tmp_path, ["a.json"])
    missing = tmp_path / "does-not-exist.json"
    signer = _FakeSigner()
    report = rotate_resign.resign_all([*files, missing], signer.sign_fn, signer.verify_fn)
    assert report["signed"] == [str(files[0])]
    assert report["skipped_absent"] == [str(missing)]


def test_resign_all_rolls_back_every_file_already_signed_this_run_on_a_later_failure(tmp_path):
    """The core discipline: a failure on file 3 of 3 must restore files 1
    and 2 as well, not just leave 3 untouched — one atomic batch."""
    files = _make_files(tmp_path, ["a.json", "b.json", "c.json"])
    signer = _FakeSigner(fail_signing_for={str(files[2])})
    with pytest.raises(rotate_resign.ResignFailed) as excinfo:
        rotate_resign.resign_all(files, signer.sign_fn, signer.verify_fn)
    assert excinfo.value.name == str(files[2])
    for f in files:
        sig = tmp_path / f"{f.name}.sig"
        assert sig.read_bytes() == f"OLDSIG:{f.name}".encode(), f"{f.name}.sig was not restored"


def test_resign_all_rolls_back_on_verify_failure_too(tmp_path):
    files = _make_files(tmp_path, ["a.json", "b.json"])
    signer = _FakeSigner(fail_verify_for={str(files[1])})
    with pytest.raises(rotate_resign.ResignFailed):
        rotate_resign.resign_all(files, signer.sign_fn, signer.verify_fn)
    for f in files:
        sig = tmp_path / f"{f.name}.sig"
        assert sig.read_bytes() == f"OLDSIG:{f.name}".encode()


def test_resign_all_removes_sig_on_rollback_when_none_existed_before(tmp_path):
    files = _make_files(tmp_path, ["a.json", "b.json"], with_prior_sig=False)
    signer = _FakeSigner(fail_signing_for={str(files[1])})
    with pytest.raises(rotate_resign.ResignFailed):
        rotate_resign.resign_all(files, signer.sign_fn, signer.verify_fn)
    for f in files:
        assert not (tmp_path / f"{f.name}.sig").exists()


def test_resign_all_rolls_back_on_keyboardinterrupt_mid_batch(tmp_path):
    """Loki audit A38D41C2, F7: KeyboardInterrupt is not an Exception
    subclass in Python — the first cut's `except Exception` let Ctrl-C
    mid-batch skip rollback entirely (measured: sigs left [NEW, NEW, OLD]).
    `resign_all` now catches BaseException, so the same rollback fires."""
    files = _make_files(tmp_path, ["a.json", "b.json", "c.json"])
    signer = _FakeSigner()

    calls = {"n": 0}
    real_sign = signer.sign_fn

    def sign_fn(path):
        calls["n"] += 1
        if calls["n"] == 3:
            raise KeyboardInterrupt()
        return real_sign(path)

    with pytest.raises(rotate_resign.ResignFailed):
        rotate_resign.resign_all(files, sign_fn, signer.verify_fn)
    for f in files:
        sig = tmp_path / f"{f.name}.sig"
        assert sig.read_bytes() == f"OLDSIG:{f.name}".encode(), (
            f"{f.name}.sig was not restored after a simulated Ctrl-C"
        )


def test_resign_all_rolls_back_on_simulated_sigterm(tmp_path):
    """The other half of F7: a delivered SIGTERM must drive the exact same
    rollback path as Ctrl-C. `_sigterm_trap` installs a handler (for the
    duration of `resign_all`) that raises `_Interrupted` — raised directly
    here rather than via a real `os.kill`/`signal.raise_signal` round trip,
    which would be timing-sensitive under a test runner that may install
    its own signal handling (pytest-timeout)."""
    files = _make_files(tmp_path, ["a.json", "b.json"])
    signer = _FakeSigner()

    calls = {"n": 0}
    real_sign = signer.sign_fn

    def sign_fn(path):
        calls["n"] += 1
        if calls["n"] == 2:
            raise rotate_resign._Interrupted("simulated SIGTERM")
        return real_sign(path)

    with pytest.raises(rotate_resign.ResignFailed):
        rotate_resign.resign_all(files, sign_fn, signer.verify_fn)
    for f in files:
        sig = tmp_path / f"{f.name}.sig"
        assert sig.read_bytes() == f"OLDSIG:{f.name}".encode()


def test_sigterm_trap_installs_and_restores_the_handler(tmp_path):
    """`_sigterm_trap` must restore whatever handler was there before on
    the way out — it should not leave the process with a permanently
    altered SIGTERM handler after `resign_all` returns."""
    import signal

    previous = signal.getsignal(signal.SIGTERM)
    with rotate_resign._sigterm_trap():
        during = signal.getsignal(signal.SIGTERM)
        assert during is not previous
    after = signal.getsignal(signal.SIGTERM)
    assert after is previous


def test_resign_all_leaves_no_temp_files_behind_on_success(tmp_path):
    """The .sig write goes to a sibling temp file and os.replace()s over
    the live path (atomic, and never observable mid-write) — after a
    successful run, no `.tmp-*` sibling should remain."""
    files = _make_files(tmp_path, ["a.json", "b.json"])
    signer = _FakeSigner()
    rotate_resign.resign_all(files, signer.sign_fn, signer.verify_fn)
    leftover = list(tmp_path.glob("*.tmp-*"))
    assert leftover == [], f"temp file(s) left behind: {leftover}"


def test_resign_all_leaves_no_temp_files_behind_on_rollback(tmp_path):
    files = _make_files(tmp_path, ["a.json", "b.json"])
    signer = _FakeSigner(fail_signing_for={str(files[1])})
    with pytest.raises(rotate_resign.ResignFailed):
        rotate_resign.resign_all(files, signer.sign_fn, signer.verify_fn)
    leftover = list(tmp_path.glob("*.tmp-*"))
    assert leftover == [], f"temp file(s) left behind after rollback: {leftover}"


def test_check_all_reports_absent_unsigned_ok_and_mismatch(tmp_path, monkeypatch):
    ok = tmp_path / "ok.json"
    ok.write_text("ok\n")
    unsigned = tmp_path / "unsigned.json"
    unsigned.write_text("unsigned\n")
    mismatch = tmp_path / "mismatch.json"
    mismatch.write_text("mismatch\n")
    absent = tmp_path / "absent.json"

    fpr_map = {str(ok): "AAAA", str(mismatch): "BBBB"}

    def _fake_signer(path):
        return fpr_map.get(str(path))

    monkeypatch.setattr(rotate_resign, "_signer_fingerprint", _fake_signer)
    report = rotate_resign.check_all([ok, unsigned, mismatch, absent], "aaaa")

    states = {row["path"]: row["state"] for row in report["files"]}
    assert states[str(ok)] == "ok"
    assert states[str(unsigned)] == "unsigned_or_unverifiable"
    assert states[str(mismatch)] == "mismatch"
    assert states[str(absent)] == "absent"
    assert report["all_ok"] is False


def test_check_all_ok_when_every_reachable_file_matches(tmp_path, monkeypatch):
    ok = tmp_path / "ok.json"
    ok.write_text("ok\n")
    monkeypatch.setattr(rotate_resign, "_signer_fingerprint", lambda path: "AAAA")
    report = rotate_resign.check_all([ok], "aaaa")
    assert report["all_ok"] is True
