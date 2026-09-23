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
