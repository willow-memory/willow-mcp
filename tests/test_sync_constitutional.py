"""`deploy/manifest-grant/sync_constitutional.py` — the installer's
constitutional-bundle sync (sealed `1bd6fd29`; gap `c1395b307421`).

`constitutional/` holds POLICY (`syscall-table.json`) and LIVE STATE
(`pre-approved.json` — the active envelope register) in the same directory.
The one thing that must not go wrong: a sync that copies the whole
directory destroys the register. These tests treat "pre-approved.json is
byte-identical afterwards" as the test that matters most, per the packet.

This module is plain Python (no root, no uid switch, no systemctl) so the
functional sync/allowlist/idempotency behavior is fully testable here. The
trust-owner ownership-and-signing half of the installer step (`chown`,
`as_to gpg --detach-sign`) is NOT testable in Kart — Kart cannot switch uid
and has no systemctl — and is not exercised by these tests; see the PR body
for which CI leg covers install.sh's shell syntax/shape instead.

Amendment (dispatch A9BF01A9, amending BD5843FD): `sync_and_sign()` is the
fix for the defect the operator's first live run actually measured — sync
and sign used to be two acts, and a signing failure in between left a
replaced-but-unsigned governance file. `sign_fn`/`verify_fn` are injected
callables, so the rollback/verify CONTROL FLOW below is fully exercised
with FAKE signers — never real gpg or a real uid switch (still not
testable in Kart, same limit as always) — including the one case that
matters most: a signing failure restores the file's exact previous bytes
AND its exact previous `.sig`.
"""
from __future__ import annotations

import json

import pytest

from importlib import util as _importlib_util
from pathlib import Path

_MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "deploy" / "manifest-grant" / "sync_constitutional.py"
)
_spec = _importlib_util.spec_from_file_location("sync_constitutional", _MODULE_PATH)
sync_constitutional = _importlib_util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(sync_constitutional)


def _write_syscall_table(path: Path, verb_ids: list[int]) -> None:
    doc = {
        "schema": "syscall-table/v1",
        "verbs": [{"id": i, "verb": f"verb.{i}"} for i in verb_ids],
    }
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")


def _write_register(path: Path, active_ids: list[str]) -> None:
    doc = {"active": [{"id": i} for i in active_ids], "issued_by": "root"}
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")


@pytest.fixture
def bundle_and_box(tmp_path: Path):
    bundle_dir = tmp_path / "bundle" / "constitutional"
    box_dir = tmp_path / "box" / "constitutional"
    bundle_dir.mkdir(parents=True)
    box_dir.mkdir(parents=True)
    return bundle_dir, box_dir


def test_stale_table_is_replaced_with_correct_before_after_counts(bundle_and_box):
    bundle_dir, box_dir = bundle_and_box
    _write_syscall_table(box_dir / "syscall-table.json", list(range(1, 23)))  # stale: 22 rows
    _write_syscall_table(bundle_dir / "syscall-table.json", list(range(1, 24)))  # 23 rows

    report = sync_constitutional.sync(bundle_dir, box_dir)

    assert len(report["written"]) == 1
    entry = report["written"][0]
    assert entry["name"] == "syscall-table.json"
    assert entry["before_count"] == 22
    assert entry["bundle_count"] == 23
    assert entry["after_count"] == 23
    assert entry["changed"] is True

    on_disk = json.loads((box_dir / "syscall-table.json").read_text())
    assert len(on_disk["verbs"]) == 23


def test_non_allowlisted_bundle_file_is_skipped_and_box_copy_is_byte_identical(bundle_and_box):
    bundle_dir, box_dir = bundle_and_box
    _write_syscall_table(bundle_dir / "syscall-table.json", list(range(1, 24)))
    # bundle ships a SEED copy of pre-approved.json, same as the real checkout
    (bundle_dir / "pre-approved.json").write_text(
        json.dumps({"active": [], "seed": True}), encoding="utf-8"
    )
    # box holds the LIVE register — a non-trivial one, exactly what must survive
    _write_register(box_dir / "pre-approved.json", ["env-a", "env-b", "env-c"])
    live_bytes_before = (box_dir / "pre-approved.json").read_bytes()

    report = sync_constitutional.sync(bundle_dir, box_dir)

    assert any(s["name"] == "pre-approved.json" for s in report["skipped"])
    live_bytes_after = (box_dir / "pre-approved.json").read_bytes()
    assert live_bytes_after == live_bytes_before, "the live register must be byte-identical after sync"


def test_allowlisted_file_missing_from_bundle_fails_hard_and_touches_nothing(bundle_and_box):
    bundle_dir, box_dir = bundle_and_box
    # bundle does NOT ship syscall-table.json at all
    _write_register(box_dir / "pre-approved.json", ["env-a"])
    live_before = (box_dir / "pre-approved.json").read_bytes()
    box_had_no_table_before = not (box_dir / "syscall-table.json").exists()

    with pytest.raises(sync_constitutional.AllowlistFileMissing) as exc_info:
        sync_constitutional.sync(bundle_dir, box_dir)
    assert "syscall-table.json" in str(exc_info.value)

    assert (box_dir / "pre-approved.json").read_bytes() == live_before
    assert box_had_no_table_before and not (box_dir / "syscall-table.json").exists()


def test_second_run_is_a_no_op(bundle_and_box):
    bundle_dir, box_dir = bundle_and_box
    _write_syscall_table(bundle_dir / "syscall-table.json", list(range(1, 24)))

    first = sync_constitutional.sync(bundle_dir, box_dir)
    assert len(first["written"]) == 1

    on_disk_mtime_after_first = (box_dir / "syscall-table.json").stat().st_mtime

    second = sync_constitutional.sync(bundle_dir, box_dir)
    assert second["written"] == []
    assert len(second["unchanged"]) == 1
    assert second["unchanged"][0]["name"] == "syscall-table.json"
    # no write happened, so mtime is untouched
    assert (box_dir / "syscall-table.json").stat().st_mtime == on_disk_mtime_after_first


def test_unreadable_bundle_refuses_and_leaves_box_untouched(tmp_path: Path):
    box_dir = tmp_path / "box" / "constitutional"
    box_dir.mkdir(parents=True)
    _write_register(box_dir / "pre-approved.json", ["env-a"])
    live_before = (box_dir / "pre-approved.json").read_bytes()

    absent_bundle = tmp_path / "does-not-exist"
    with pytest.raises(sync_constitutional.BundleAbsent):
        sync_constitutional.sync(absent_bundle, box_dir)
    assert (box_dir / "pre-approved.json").read_bytes() == live_before

    # "unreadable": a plain file where a directory is expected
    not_a_dir = tmp_path / "bundle-is-a-file"
    not_a_dir.write_text("not a directory")
    with pytest.raises(sync_constitutional.BundleUnreadable):
        sync_constitutional.sync(not_a_dir, box_dir)
    assert (box_dir / "pre-approved.json").read_bytes() == live_before


def test_cli_main_reports_stop_and_nonzero_on_missing_allowlist_entry(tmp_path: Path, capsys):
    bundle_dir = tmp_path / "bundle"
    box_dir = tmp_path / "box"
    bundle_dir.mkdir()
    box_dir.mkdir()

    rc = sync_constitutional.main([str(bundle_dir), str(box_dir)])
    assert rc == 2
    captured = capsys.readouterr()
    assert "STOP" in captured.err
    assert "syscall-table.json" in captured.err


def test_cli_main_prints_before_after_counts_on_success(bundle_and_box, capsys):
    bundle_dir, box_dir = bundle_and_box
    _write_syscall_table(box_dir / "syscall-table.json", list(range(1, 23)))
    _write_syscall_table(bundle_dir / "syscall-table.json", list(range(1, 24)))

    rc = sync_constitutional.main([str(bundle_dir), str(box_dir)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "syscall-table.json" in out
    assert "22" in out
    assert "23" in out


# ── sync_and_sign(): sync + sign as ONE act, with rollback on failure ───────


class _FakeSigner:
    """A fake sign_fn/verify_fn pair. `fail_signing`/`fail_verify` let a test
    inject a failure at either point; every call is recorded so a test can
    assert exactly what ran."""

    def __init__(self, *, fail_signing: bool = False, fail_verify: bool = False):
        self.fail_signing = fail_signing
        self.fail_verify = fail_verify
        self.sign_calls: list[str] = []
        self.verify_calls: list[str] = []

    def sign_fn(self, path):
        self.sign_calls.append(path.name)
        if self.fail_signing:
            raise RuntimeError("fake gpg: signing failed")
        return f"SIG-OF:{path.read_bytes().decode()}".encode()

    def verify_fn(self, path, sig_bytes) -> bool:
        self.verify_calls.append(path.name)
        if self.fail_verify:
            return False
        return sig_bytes == f"SIG-OF:{path.read_bytes().decode()}".encode()


def test_sync_and_sign_signs_a_freshly_written_file_and_verifies_it(bundle_and_box):
    bundle_dir, box_dir = bundle_and_box
    _write_syscall_table(bundle_dir / "syscall-table.json", list(range(1, 24)))
    signer = _FakeSigner()

    report = sync_constitutional.sync_and_sign(bundle_dir, box_dir, signer.sign_fn, signer.verify_fn)

    assert report["written"][0]["name"] == "syscall-table.json"
    assert report["signed"] == ["syscall-table.json"]
    assert report["already_signed"] == []
    box_file = box_dir / "syscall-table.json"
    sig_path = box_dir / "syscall-table.json.sig"
    assert sig_path.exists()
    assert sig_path.read_bytes() == f"SIG-OF:{box_file.read_text()}".encode()
    assert signer.sign_calls == ["syscall-table.json"]
    assert signer.verify_calls == ["syscall-table.json"]


def test_sync_and_sign_signing_failure_restores_previous_content_and_signature(bundle_and_box):
    bundle_dir, box_dir = bundle_and_box
    box_file = box_dir / "syscall-table.json"
    sig_file = box_dir / "syscall-table.json.sig"
    _write_syscall_table(box_file, list(range(1, 23)))  # stale: 22 rows, previously signed
    old_bytes = box_file.read_bytes()
    old_sig = b"OLD-SIGNATURE-BYTES"
    sig_file.write_bytes(old_sig)
    _write_syscall_table(bundle_dir / "syscall-table.json", list(range(1, 24)))  # bundle: 23 rows

    signer = _FakeSigner(fail_signing=True)
    with pytest.raises(sync_constitutional.SigningFailed) as exc_info:
        sync_constitutional.sync_and_sign(bundle_dir, box_dir, signer.sign_fn, signer.verify_fn)

    assert exc_info.value.name == "syscall-table.json"
    # the box is exactly as it was BEFORE this run touched anything —
    # sync() had already written the new 23-row content when signing failed;
    # sync_and_sign() must have rolled that back too, not just the .sig.
    assert box_file.read_bytes() == old_bytes
    assert sig_file.read_bytes() == old_sig


def test_sync_and_sign_verify_failure_after_signing_also_rolls_back(bundle_and_box):
    bundle_dir, box_dir = bundle_and_box
    box_file = box_dir / "syscall-table.json"
    _write_syscall_table(box_file, list(range(1, 23)))
    old_bytes = box_file.read_bytes()
    _write_syscall_table(bundle_dir / "syscall-table.json", list(range(1, 24)))

    signer = _FakeSigner(fail_verify=True)
    with pytest.raises(sync_constitutional.SigningFailed):
        sync_constitutional.sync_and_sign(bundle_dir, box_dir, signer.sign_fn, signer.verify_fn)

    assert box_file.read_bytes() == old_bytes
    assert not (box_dir / "syscall-table.json.sig").exists()


def test_sync_and_sign_signing_failure_on_first_install_removes_the_new_file_and_sig(bundle_and_box):
    """No previous copy existed at all (first install) — a signing failure
    must leave the box with NEITHER the new content NOR a signature, not a
    half-applied pair."""
    bundle_dir, box_dir = bundle_and_box
    _write_syscall_table(bundle_dir / "syscall-table.json", list(range(1, 24)))
    signer = _FakeSigner(fail_signing=True)

    with pytest.raises(sync_constitutional.SigningFailed):
        sync_constitutional.sync_and_sign(bundle_dir, box_dir, signer.sign_fn, signer.verify_fn)

    assert not (box_dir / "syscall-table.json").exists()
    assert not (box_dir / "syscall-table.json.sig").exists()


def test_sync_and_sign_unchanged_file_with_a_verifying_signature_is_left_alone(bundle_and_box):
    bundle_dir, box_dir = bundle_and_box
    box_file = box_dir / "syscall-table.json"
    _write_syscall_table(box_file, list(range(1, 24)))
    _write_syscall_table(bundle_dir / "syscall-table.json", list(range(1, 24)))  # identical
    sig_file = box_dir / "syscall-table.json.sig"
    good_sig = f"SIG-OF:{box_file.read_text()}".encode()
    sig_file.write_bytes(good_sig)

    signer = _FakeSigner()
    report = sync_constitutional.sync_and_sign(bundle_dir, box_dir, signer.sign_fn, signer.verify_fn)

    assert report["written"] == []
    assert report["already_signed"] == ["syscall-table.json"]
    assert report["signed"] == []
    assert signer.sign_calls == []  # never re-signed — nothing to fix
    assert sig_file.read_bytes() == good_sig  # untouched


def test_sync_and_sign_unchanged_file_with_a_stale_signature_is_re_signed(bundle_and_box):
    """Content unchanged, but the existing .sig does not verify (e.g. a key
    rotation between runs, or a corrupted .sig) — re-signed anyway, the same
    'never leave a governance file whose signature does not check' rule
    that applies to a fresh write."""
    bundle_dir, box_dir = bundle_and_box
    box_file = box_dir / "syscall-table.json"
    _write_syscall_table(box_file, list(range(1, 24)))
    _write_syscall_table(bundle_dir / "syscall-table.json", list(range(1, 24)))
    sig_file = box_dir / "syscall-table.json.sig"
    sig_file.write_bytes(b"STALE-SIGNATURE-DOES-NOT-VERIFY")

    signer = _FakeSigner()
    report = sync_constitutional.sync_and_sign(bundle_dir, box_dir, signer.sign_fn, signer.verify_fn)

    assert report["written"] == []
    assert report["signed"] == ["syscall-table.json"]
    assert signer.sign_calls == ["syscall-table.json"]
    expected_sig = f"SIG-OF:{box_file.read_text()}".encode()
    assert sig_file.read_bytes() == expected_sig


def test_sync_and_sign_propagates_sync_failures_before_signing_anything(tmp_path):
    """sync()'s own refusals (missing allowlist entry, absent/unreadable
    bundle) propagate untouched — nothing has been written yet, so there is
    nothing for sync_and_sign() to roll back."""
    bundle_dir = tmp_path / "bundle"
    box_dir = tmp_path / "box"
    bundle_dir.mkdir()
    box_dir.mkdir()
    signer = _FakeSigner()

    with pytest.raises(sync_constitutional.AllowlistFileMissing):
        sync_constitutional.sync_and_sign(bundle_dir, box_dir, signer.sign_fn, signer.verify_fn)
    assert signer.sign_calls == []
    assert signer.verify_calls == []
