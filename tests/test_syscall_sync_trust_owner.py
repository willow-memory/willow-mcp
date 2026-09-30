"""Trust-owner apply half for syscall table sync (gap 7b1fee1f2861)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.test_constitutional import _FakeLedger, _row, _write_table
from willow_mcp import constitutional
from willow_mcp import manifest_grant_executor as mgx
from willow_mcp import paths
from willow_mcp import trust_owner_verbs as tov


@pytest.fixture
def tables(tmp_path, monkeypatch):
    """Same shape as test_constitutional's fixture. It is defined here, not
    imported, because an imported fixture shadows the test argument (F811).

    The two paths are also made the canonical ones -- the configured live
    table and the package bundle -- because apply uses only those (Loki
    A28BD892)."""
    tmp_path.chmod(0o700)
    live = tmp_path / "live" / "syscall-table.json"
    bundle = tmp_path / "bundle" / "syscall-table.json"
    live.parent.mkdir()
    bundle.parent.mkdir()
    monkeypatch.setattr(paths, "syscall_table_path", lambda: live)
    monkeypatch.setattr(constitutional, "_default_bundle_path", lambda: bundle)
    return live, bundle


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


# ── the apply takes no path from the record (Loki A28BD892, gap f265d9b3727b) ─


def _queue_signed(plan, grants_root):
    queued = tov.queue_syscall_sync_request(plan, grants_root=grants_root)
    pending = grants_root / "pending" / f"{queued['pair_id']}.json"
    return json.loads(pending.read_text(encoding="utf-8")), pending


def test_apply_refuses_a_planted_bundle_path(tables, tmp_path):
    """The attack: a correctly signed record whose bundle_path, digest and
    added set all describe a planted table. Every content check passes; the
    path check is what refuses it, and the live table is untouched."""
    live, bundle = tables
    _write_table(live, [_row(1, "git.push")])
    _write_table(bundle, [_row(1, "git.push")])
    plant = tmp_path / "plant" / "syscall-table.json"
    plant.parent.mkdir()
    _write_table(plant, [_row(1, "git.push"), _row(99, "operator.everything")])

    grants_root = tmp_path / "manifest_grants"
    plan = constitutional.evaluate_syscall_table_sync(live_path=live, bundle_path=plant)
    assert plan["needs_apply"] is True
    record, pending = _queue_signed(plan, grants_root)
    assert record["target"]["bundle_path"] == str(plant)

    before = live.read_text()
    outcome = tov._apply_syscall_sync(
        record, pending, ledger=_FakeLedger(), apps_root=tmp_path / "mcp_apps",
        db_path=None, grants_root=grants_root,
    )
    assert outcome["ok"] is False
    assert outcome["error"] == "eforged"
    assert "bundle_path" in outcome["reason"]
    assert live.read_text() == before


def test_apply_refuses_a_redirected_live_path(tables, tmp_path):
    live, bundle = tables
    _write_table(live, [_row(1, "a")])
    _write_table(bundle, [_row(1, "a"), _row(2, "b")])
    elsewhere = tmp_path / "elsewhere" / "syscall-table.json"
    elsewhere.parent.mkdir()
    _write_table(elsewhere, [_row(1, "a")])

    grants_root = tmp_path / "manifest_grants"
    plan = constitutional.evaluate_syscall_table_sync(live_path=elsewhere, bundle_path=bundle)
    record, pending = _queue_signed(plan, grants_root)
    outcome = tov._apply_syscall_sync(
        record, pending, ledger=_FakeLedger(), apps_root=tmp_path / "mcp_apps",
        db_path=None, grants_root=grants_root,
    )
    assert outcome["ok"] is False
    assert outcome["error"] == "eforged"
    assert "live_path" in outcome["reason"]
    assert {r["id"] for r in json.loads(elsewhere.read_text())["verbs"]} == {1}


def test_record_without_paths_applies_the_canonical_ones(tables, tmp_path):
    live, bundle = tables
    _write_table(live, [_row(1, "a")])
    _write_table(bundle, [_row(1, "a"), _row(2, "b")])
    grants_root = tmp_path / "manifest_grants"
    plan = constitutional.evaluate_syscall_table_sync(live_path=live, bundle_path=bundle)
    record, pending = _queue_signed(plan, grants_root)
    record["target"].pop("bundle_path")
    record["target"].pop("live_path")
    record["broker_sig"] = mgx._sign_request(record, grants_root)
    outcome = tov._apply_syscall_sync(
        record, pending, ledger=_FakeLedger(), apps_root=tmp_path / "mcp_apps",
        db_path=None, grants_root=grants_root,
    )
    assert outcome["ok"] is True, outcome
    assert {r["id"] for r in json.loads(live.read_text())["verbs"]} == {1, 2}


class _InklessLedger(_FakeLedger):
    def append(self, project, event_type, content):
        if event_type == tov.EVENT_SYSCALL_SYNC_APPLIED:
            raise OSError("ledger unwritable")
        return super().append(project, event_type, content)


def test_a_lost_apply_receipt_is_said_not_swallowed(tables, tmp_path):
    live, bundle = tables
    _write_table(live, [_row(1, "a")])
    _write_table(bundle, [_row(1, "a"), _row(2, "b")])
    grants_root = tmp_path / "manifest_grants"
    plan = constitutional.evaluate_syscall_table_sync(live_path=live, bundle_path=bundle)
    record, pending = _queue_signed(plan, grants_root)
    outcome = tov._apply_syscall_sync(
        record, pending, ledger=_InklessLedger(), apps_root=tmp_path / "mcp_apps",
        db_path=None, grants_root=grants_root,
    )
    assert outcome["ok"] is True
    assert "ledger unwritable" in outcome["receipt_error"]
    done = json.loads((grants_root / "done" / f"{record['pair_id']}.json").read_text())
    assert "ledger unwritable" in done["result"]["receipt_error"]
