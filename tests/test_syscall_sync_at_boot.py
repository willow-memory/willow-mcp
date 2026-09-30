"""The boot entry ``constitutional.sync_syscall_table_at_boot`` (Loki 4C7B035E).

``server._main`` calls this entry. ``test_syscall_sync_trust_owner`` covers
``from_bundle`` deferral and a manual queue -> apply round trip, not the boot
entry itself. These tests drive the entry: when the live table directory is
unwritable it queues exactly one ``syscall.sync`` request and writes nothing;
when writable it applies locally and queues nothing.
"""

from __future__ import annotations

import json

import pytest

from tests.test_constitutional import _FakeLedger, _row, _write_table
from willow_mcp import constitutional
from willow_mcp import paths
from willow_mcp import trust_owner_verbs as tov


@pytest.fixture
def tables(tmp_path, monkeypatch):
    """Same shape as test_syscall_sync_trust_owner's fixture (defined here for
    the same F811 reason): the two paths are made the canonical ones, since
    the boot entry reads only those."""
    tmp_path.chmod(0o700)
    live = tmp_path / "live" / "syscall-table.json"
    bundle = tmp_path / "bundle" / "syscall-table.json"
    live.parent.mkdir()
    bundle.parent.mkdir()
    monkeypatch.setattr(paths, "syscall_table_path", lambda: live)
    monkeypatch.setattr(constitutional, "_default_bundle_path", lambda: bundle)
    return live, bundle


def _pending(grants_root):
    return sorted((grants_root / "pending").glob("*.json"))


def test_unwritable_live_dir_queues_one_request_and_writes_nothing(tables, tmp_path):
    live, bundle = tables
    _write_table(live, [_row(1, "git.push")])
    _write_table(bundle, [_row(1, "git.push"), _row(2, "pr.open")])
    live.parent.chmod(0o555)
    grants_root = tmp_path / "manifest_grants"
    ledger = _FakeLedger()

    before = live.read_bytes()
    out = constitutional.sync_syscall_table_at_boot(ledger=ledger, grants_root=grants_root)

    assert out["deferred"] is True
    assert out["added"] == [2]
    assert out["queued"]["ok"] is True
    assert out["queued"]["state"] == "queued"
    assert live.read_bytes() == before
    assert ledger.rows == []

    pending = _pending(grants_root)
    assert len(pending) == 1
    assert pending[0].name == f"{out['queued']['pair_id']}.json"
    record = json.loads(pending[0].read_text(encoding="utf-8"))
    assert record["verb"] == tov.VERB_SYSCALL_SYNC
    assert record["trigger"] == "boot"
    assert record["target"]["live_path"] == str(live)
    assert record["target"]["bundle_path"] == str(bundle)
    assert record["target"]["added"] == [2]


def test_second_boot_with_request_pending_does_not_queue_a_duplicate(tables, tmp_path):
    live, bundle = tables
    _write_table(live, [_row(1, "git.push")])
    _write_table(bundle, [_row(1, "git.push"), _row(2, "pr.open")])
    live.parent.chmod(0o555)
    grants_root = tmp_path / "manifest_grants"

    first = constitutional.sync_syscall_table_at_boot(grants_root=grants_root)
    second = constitutional.sync_syscall_table_at_boot(grants_root=grants_root)

    assert first["queued"]["state"] == "queued"
    assert second["deferred"] is True
    assert second["queued"]["state"] == "pending"
    assert second["queued"]["pair_id"] == first["queued"]["pair_id"]
    assert len(_pending(grants_root)) == 1


def test_writable_live_dir_applies_locally_and_queues_nothing(tables, tmp_path):
    live, bundle = tables
    _write_table(live, [_row(1, "git.push")])
    _write_table(bundle, [_row(1, "git.push"), _row(2, "pr.open")])
    grants_root = tmp_path / "manifest_grants"
    ledger = _FakeLedger()

    out = constitutional.sync_syscall_table_at_boot(ledger=ledger, grants_root=grants_root)

    assert out["ok"] is True
    assert out["added"] == [2]
    assert "deferred" not in out and "queued" not in out
    assert {r["id"] for r in json.loads(live.read_text())["verbs"]} == {1, 2}
    assert any(r["event_type"] == "constitutional_sync" for r in ledger.rows)
    assert _pending(grants_root) == []


def test_tables_already_agree_queues_nothing_even_when_unwritable(tables, tmp_path):
    live, bundle = tables
    _write_table(live, [_row(1, "git.push")])
    _write_table(bundle, [_row(1, "git.push")])
    live.parent.chmod(0o555)
    grants_root = tmp_path / "manifest_grants"

    before = live.read_bytes()
    out = constitutional.sync_syscall_table_at_boot(grants_root=grants_root)

    assert out["ok"] is True
    assert out["added"] == []
    assert "deferred" not in out and "queued" not in out
    assert live.read_bytes() == before
    assert _pending(grants_root) == []
