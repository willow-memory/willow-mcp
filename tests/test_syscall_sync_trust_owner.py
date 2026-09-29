"""Trust-owner apply half for syscall table sync (gap 7b1fee1f2861)."""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from willow_mcp import constitutional
from willow_mcp import manifest_grant_executor as mgx
from willow_mcp import trust_owner_verbs as tov
from tests.test_constitutional import _FakeLedger, _row, _write_table, tables


def _make_unwritable_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o555)


def test_not_writable_live_table_defers_without_mutating(tables, tmp_path):
    live, bundle = tables
    _write_table(live, [_row(1, "git.push")])
    _write_table(bundle, [_row(1, "git.push"), _row(2, "pr.open")])
    _make_unwritable_dir(live.parent)

    before = live.read_text()
    out = constitutional.sync_syscall_table_from_bundle(live_path=live, bundle_path=bundle)
    assert out.get("deferred") is True
    assert out.get("added") == [2]
    assert live.read_text() == before


def test_queue_and_apply_round_trip(tables, tmp_path):
    live, bundle = tables
    _write_table(live, [_row(1, "git.push")])
    _write_table(bundle, [_row(1, "git.push"), _row(2, "pr.open")])
    _make_unwritable_dir(live.parent)

    grants_root = tmp_path / "manifest_grants"
    plan = constitutional.evaluate_syscall_table_sync(live_path=live, bundle_path=bundle)
    assert plan["needs_apply"] is True

    queued = tov.queue_syscall_sync_request(plan, grants_root=grants_root)
    assert queued["ok"] is True
    pending = grants_root / "pending" / f"{queued['pair_id']}.json"
    assert pending.is_file()

    live.parent.chmod(0o755)
    record = json.loads(pending.read_text(encoding="utf-8"))
    ledger = _FakeLedger()
    outcome = tov._apply_syscall_sync(
        record, pending, ledger=ledger, apps_root=tmp_path / "mcp_apps",
        db_path=None, grants_root=grants_root,
    )
    assert outcome["ok"] is True, outcome
    written = json.loads(live.read_text())
    assert {r["id"] for r in written["verbs"]} == {1, 2}
    assert any(r["event_type"] == "constitutional_sync" for r in ledger.rows)
    assert any(r["event_type"] == tov.EVENT_SYSCALL_SYNC_APPLIED for r in ledger.rows)


def test_apply_refuses_when_bundle_digest_mutated(tables, tmp_path):
    live, bundle = tables
    _write_table(live, [_row(1, "a")])
    _write_table(bundle, [_row(1, "a"), _row(2, "b")])
    grants_root = tmp_path / "manifest_grants"
    plan = constitutional.evaluate_syscall_table_sync(live_path=live, bundle_path=bundle)
    queued = tov.queue_syscall_sync_request(plan, grants_root=grants_root)
    pending = grants_root / "pending" / f"{queued['pair_id']}.json"
    record = json.loads(pending.read_text(encoding="utf-8"))
    record["target"]["bundle_digest"] = "0" * 64
    record["broker_sig"] = mgx._sign_request(record, grants_root)
    pending.write_text(json.dumps(record, indent=2), encoding="utf-8")

    live.parent.chmod(0o755)
    outcome = tov._apply_syscall_sync(
        record, pending, ledger=_FakeLedger(), apps_root=tmp_path / "mcp_apps",
        db_path=None, grants_root=grants_root,
    )
    assert outcome["ok"] is False
    assert outcome["error"] == "edrift"
    assert not (grants_root / "done" / f"{queued['pair_id']}.json").is_file()


def test_apply_refuses_when_added_set_drifts(tables, tmp_path):
    live, bundle = tables
    _write_table(live, [_row(1, "a")])
    _write_table(bundle, [_row(1, "a"), _row(2, "b")])
    grants_root = tmp_path / "manifest_grants"
    plan = constitutional.evaluate_syscall_table_sync(live_path=live, bundle_path=bundle)
    queued = tov.queue_syscall_sync_request(plan, grants_root=grants_root)
    pending = grants_root / "pending" / f"{queued['pair_id']}.json"
    record = json.loads(pending.read_text(encoding="utf-8"))
    record["target"]["added"] = [2, 3]
    record["broker_sig"] = mgx._sign_request(record, grants_root)
    pending.write_text(json.dumps(record, indent=2), encoding="utf-8")

    live.parent.chmod(0o755)
    outcome = tov._apply_syscall_sync(
        record, pending, ledger=_FakeLedger(), apps_root=tmp_path / "mcp_apps",
        db_path=None, grants_root=grants_root,
    )
    assert outcome["ok"] is False
    assert outcome["error"] == "edrift"
