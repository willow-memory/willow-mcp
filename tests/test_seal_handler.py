"""willow_mcp.seal_handler — the consumer side of the seal watch.

Uses a per-test ``Store(store_root=tmp_path)`` passed explicitly via
``on_seal(record, store=...)`` rather than the module-level singleton
pattern elsewhere in this suite (see test_gaps.py's docstring) — this
handler is written to accept an injected store for exactly this reason.
"""
from __future__ import annotations

import sqlite3

import pytest

from willow_mcp import seal_handler
from willow_mcp.db import Store


@pytest.fixture
def store(tmp_path):
    return Store(store_root=str(tmp_path / "store"))


def _gov_record(**overrides):
    record = {
        "title": "Adopt X",
        "status": "proposed",
        "nestor_pair_id": "pair-001",
    }
    record.update(overrides)
    return record


def _seal_record(**overrides):
    record = {
        "ts": "2026-09-11T00:00:00+00:00",
        "prev": "abc123",
        "kind": "seal",
        "pair_id": "pair-001",
        "verifier": "sean",
        "source_lang": "decision",
        "target_lang": "decision",
        "source_sha": "deadbeef",
        "origin": "nestor",
        "upgraded_from": "draft",
    }
    record.update(overrides)
    return record


def _make_nestor_db(path, pair_id="pair-001", seal_sig="s" * 64):
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE tm_pairs (id TEXT PRIMARY KEY, seal_sig TEXT)")
    conn.execute("INSERT INTO tm_pairs (id, seal_sig) VALUES (?, ?)", (pair_id, seal_sig))
    conn.commit()
    conn.close()


def test_upgrade_on_match(store, tmp_path):
    rid, _ = store.put(seal_handler.GOVERNANCE_COLLECTION, _gov_record())
    db_path = tmp_path / "nestor.db"
    _make_nestor_db(db_path, pair_id="pair-001", seal_sig="f" * 64)

    result = seal_handler.on_seal(_seal_record(), store=store, db_path=db_path)

    assert result == "upgraded"
    gov = store.get(seal_handler.GOVERNANCE_COLLECTION, rid)
    assert gov["status"] == "sealed"
    assert gov["nestor_pair_id"] == "pair-001"
    assert gov["nestor_verifier"] == "sean"
    assert gov["sealed_at"] == "2026-09-11T00:00:00+00:00"
    assert gov["nestor_seal_sig_prefix"] == "f" * 16


def test_idempotent_second_call_is_a_clean_noop(store, tmp_path):
    rid, _ = store.put(seal_handler.GOVERNANCE_COLLECTION, _gov_record())
    db_path = tmp_path / "nestor.db"
    _make_nestor_db(db_path)

    first = seal_handler.on_seal(_seal_record(), store=store, db_path=db_path)
    before = store.get(seal_handler.GOVERNANCE_COLLECTION, rid)
    second = seal_handler.on_seal(_seal_record(), store=store, db_path=db_path)
    after = store.get(seal_handler.GOVERNANCE_COLLECTION, rid)

    assert first == "upgraded"
    assert second == "already"
    # No duplicate write: updated_at must not have moved on the no-op call.
    assert before["_updated"] == after["_updated"]
    assert after == before


def test_unmatched_pair_id_does_not_raise(store, tmp_path):
    db_path = tmp_path / "nestor.db"
    _make_nestor_db(db_path, pair_id="some-other-pair")

    result = seal_handler.on_seal(
        _seal_record(pair_id="no-such-pair"), store=store, db_path=db_path
    )

    assert result == "unmatched"


def test_non_decision_seal_is_skipped(store, tmp_path):
    rid, _ = store.put(seal_handler.GOVERNANCE_COLLECTION, _gov_record())
    result = seal_handler.on_seal(
        _seal_record(source_lang="translation"), store=store
    )
    assert result == "skipped"
    gov = store.get(seal_handler.GOVERNANCE_COLLECTION, rid)
    assert gov["status"] == "proposed"


def test_non_seal_kind_is_skipped(store):
    result = seal_handler.on_seal(_seal_record(kind="propose"), store=store)
    assert result == "skipped"


def test_op_only_shaped_record_is_skipped(store):
    """A record using the old/wrong `op` field (no `kind`) must never be
    mistaken for a seal — this is the exact bug shape ground truth calls
    out: `op` is not the real ledger's field."""
    record = {"op": "seal", "pair_id": "pair-001", "source_lang": "decision"}
    result = seal_handler.on_seal(record, store=store)
    assert result == "skipped"


def test_missing_pair_id_is_skipped_not_raised(store):
    record = _seal_record()
    del record["pair_id"]
    assert seal_handler.on_seal(record, store=store) == "skipped"


def test_nestor_db_unreadable_still_upgrades(store, tmp_path):
    rid, _ = store.put(seal_handler.GOVERNANCE_COLLECTION, _gov_record())
    missing_db = tmp_path / "does-not-exist" / "nestor.db"

    result = seal_handler.on_seal(_seal_record(), store=store, db_path=missing_db)

    assert result == "upgraded"
    gov = store.get(seal_handler.GOVERNANCE_COLLECTION, rid)
    assert gov["status"] == "sealed"
    assert gov["nestor_verifier"] == "sean"
    assert "nestor_seal_sig_prefix" not in gov


def test_nestor_db_missing_row_still_upgrades(store, tmp_path):
    rid, _ = store.put(seal_handler.GOVERNANCE_COLLECTION, _gov_record())
    db_path = tmp_path / "nestor.db"
    _make_nestor_db(db_path, pair_id="some-other-pair")

    result = seal_handler.on_seal(_seal_record(), store=store, db_path=db_path)

    assert result == "upgraded"
    gov = store.get(seal_handler.GOVERNANCE_COLLECTION, rid)
    assert gov["status"] == "sealed"
    assert "nestor_seal_sig_prefix" not in gov


def test_broken_store_returns_error_not_raise(tmp_path):
    class ExplodingStore:
        def all(self, collection):
            raise RuntimeError("store is on fire")

    result = seal_handler.on_seal(_seal_record(), store=ExplodingStore())
    assert result == "error"


def test_malformed_record_does_not_raise(store):
    assert seal_handler.on_seal({}, store=store) == "skipped"
    assert seal_handler.on_seal({"kind": "seal"}, store=store) == "skipped"
