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
