"""syscall.sync carries the sealed amendment in the request (gap 3ecf1ed8326e).

The trust-owner apply uid cannot read SOIL, so the broker puts each needed
amendment's sealed row into the signed request and the apply re-verifies the
seal against its keyring -- never opening SOIL or the Nestor ledger.
"""
from __future__ import annotations

import json

import pytest

from tests.test_constitutional import (
    _FakeGovStore, _FakeLedger, _gov_record, _row, _sealed_amend_pair, _write_table,
)
from willow_mcp import constitutional
from willow_mcp import keyring as keyring_mod
from willow_mcp import manifest_grant_executor as mgx
from willow_mcp import net_authority, paths
from willow_mcp import trust_owner_verbs as tov


@pytest.fixture
def tables(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    live = tmp_path / "live" / "syscall-table.json"
    bundle = tmp_path / "bundle" / "syscall-table.json"
    live.parent.mkdir()
    bundle.parent.mkdir()
    monkeypatch.setattr(paths, "syscall_table_path", lambda: live)
    monkeypatch.setattr(constitutional, "_default_bundle_path", lambda: bundle)
    return live, bundle


@pytest.fixture
def ring(tmp_path):
    with keyring_mod.isolated():
        k = keyring_mod.Keyring(path=str(tmp_path / "keys.json"))
        k.add("sean campbell", kind="ed25519")
        k.save()
        keyring_mod.set_keyring(k)
        try:
            yield k
        finally:
            keyring_mod.set_keyring(None)


def _queued_amendment(tables, tmp_path, ring):
    """Broker side: evaluate with SOIL + ledger readable, queue the request."""
    live, bundle = tables
    row_live = _row(18, "manifest.grant", bounds={"apps": "old description"})
    row_bundle = _row(18, "manifest.grant", bounds={"apps": "new description"})
    _write_table(live, [row_live])
    _write_table(bundle, [row_bundle])
    nestor_db = tmp_path / "nestor.db"
    _sealed_amend_pair(
        nestor_db, ring, "pairABC", row_id=18, verb="manifest.grant",
        from_hash=constitutional._row_hash(row_live),
        to_hash=constitutional._row_hash(row_bundle))
    plan = constitutional.evaluate_syscall_table_sync(
        live_path=live, bundle_path=bundle,
        store=_FakeGovStore([_gov_record(nestor_pair_id="pairABC")]),
        nestor_db_path=nestor_db)
    assert plan["needs_apply"] is True, plan
    grants_root = tmp_path / "manifest_grants"
    queued = tov.queue_syscall_sync_request(plan, grants_root=grants_root)
    pending = grants_root / "pending" / f"{queued['pair_id']}.json"
    record = json.loads(pending.read_text(encoding="utf-8"))
    return record, pending, grants_root


def _soil_unreadable(monkeypatch):
    """The apply uid's world: SOIL and the Nestor ledger both raise."""
    def _boom(*a, **k):
        raise PermissionError("SOIL belongs to the operator uid")

    monkeypatch.setattr(constitutional, "Store", _boom)
    monkeypatch.setattr(net_authority, "read_sealed_pair", _boom)


def _resign(record, pending, grants_root):
    record["broker_sig"] = mgx._sign_request(record, grants_root)
    pending.write_text(json.dumps(record, indent=2), encoding="utf-8")


def _apply(record, pending, grants_root, tmp_path):
    return tov._apply_syscall_sync(
        record, pending, ledger=_FakeLedger(), apps_root=tmp_path / "mcp_apps",
        db_path=None, grants_root=grants_root)


def test_request_carries_the_sealed_row(tables, tmp_path, ring):
    record, _, _ = _queued_amendment(tables, tmp_path, ring)
    seals = record["target"]["amendment_seals"]
    assert [s["pair_id"] for s in seals] == ["pairABC"]
    assert {"source_norm", "target_text", "verifier", "seal_sig", "created_at"} <= set(seals[0])
    assert record["target"]["amended"][0]["pair_id"] == "pairABC"


def test_apply_succeeds_with_soil_unreadable(tables, tmp_path, ring, monkeypatch):
    live, _ = tables
    record, pending, grants_root = _queued_amendment(tables, tmp_path, ring)
    _soil_unreadable(monkeypatch)

    outcome = _apply(record, pending, grants_root, tmp_path)
    assert outcome["ok"] is True, outcome
    assert json.loads(live.read_text())["verbs"][0]["bounds"] == {"apps": "new description"}
    assert outcome["pair_id"] == record["pair_id"]


def test_apply_refuses_a_tampered_seal(tables, tmp_path, ring, monkeypatch):
    live, _ = tables
    record, pending, grants_root = _queued_amendment(tables, tmp_path, ring)
    before = live.read_text()
    # The amend line stays intact; only the signed-over source changes, so the
    # one thing left to refuse it is the seal verification.
    record["target"]["amendment_seals"][0]["source_norm"] = "amend some other row"
    _resign(record, pending, grants_root)

    outcome = _apply(record, pending, grants_root, tmp_path)
    assert outcome["ok"] is False
    assert outcome["error"] == "eseal_mismatch"
    assert live.read_text() == before


def test_apply_refuses_when_the_amendment_is_missing_from_the_request(tables, tmp_path, ring):
    live, _ = tables
    record, pending, grants_root = _queued_amendment(tables, tmp_path, ring)
    before = live.read_text()
    record["target"]["amendment_seals"] = []
    _resign(record, pending, grants_root)

    outcome = _apply(record, pending, grants_root, tmp_path)
    assert outcome["ok"] is False
    assert outcome["error"] == "eseal_mismatch"
    assert live.read_text() == before


def test_a_carried_seal_does_not_bypass_the_request_signature(tables, tmp_path, ring):
    record, pending, grants_root = _queued_amendment(tables, tmp_path, ring)
    record["target"]["amendment_seals"][0]["source_norm"] = "amend some other row"
    # not re-signed: the broker signature no longer matches
    outcome = _apply(record, pending, grants_root, tmp_path)
    assert outcome["ok"] is False
    assert outcome["error"] == "eforged"
