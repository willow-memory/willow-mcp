"""Dedicated unit tests for receipts.py — hash-chain integrity, verify(),
record(), since(), distinct_tools(), tail(), and migration backfill.

Uses real SQLite (in-memory via explicit db_path to a temp file) so the chain
and transaction semantics are tested against the actual engine, not a fake.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from willow_mcp.receipts import ReceiptLog, _entry_hash, _GENESIS


@pytest.fixture
def receipt_db(tmp_path):
    db = tmp_path / "test_receipt.db"
    return ReceiptLog(db_path=str(db))


# ── _entry_hash pure function ────────────────────────────────────────────────

def test_entry_hash_deterministic():
    h1 = _entry_hash("prev", "2024-01-01T00:00:00Z", "app", "tool_x", "ok", None)
    h2 = _entry_hash("prev", "2024-01-01T00:00:00Z", "app", "tool_x", "ok", None)
    assert h1 == h2
    assert len(h1) == 64


def test_entry_hash_sensitive_to_prev():
    h1 = _entry_hash("prev1", "ts", "app", "tool", "ok", None)
    h2 = _entry_hash("prev2", "ts", "app", "tool", "ok", None)
    assert h1 != h2


def test_entry_hash_sensitive_to_tool():
    h1 = _entry_hash("p", "ts", "app", "tool_a", "ok", None)
    h2 = _entry_hash("p", "ts", "app", "tool_b", "ok", None)
    assert h1 != h2


def test_entry_hash_sensitive_to_outcome():
    h1 = _entry_hash("p", "ts", "app", "tool", "ok", None)
    h2 = _entry_hash("p", "ts", "app", "tool", "denied", None)
    assert h1 != h2


def test_entry_hash_sensitive_to_detail():
    h1 = _entry_hash("p", "ts", "app", "tool", "ok", None)
    h2 = _entry_hash("p", "ts", "app", "tool", "ok", "extra")
    assert h1 != h2


def test_entry_hash_uses_canonical_json():
    payload = json.dumps(["p", "ts", "app", "tool", "ok", None],
                         ensure_ascii=False, separators=(",", ":"))
    import hashlib
    expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    assert _entry_hash("p", "ts", "app", "tool", "ok", None) == expected


# ── ReceiptLog.record() + verify() chain integrity ──────────────────────────

def test_empty_log_verifies(receipt_db):
    r = receipt_db.verify()
    assert r["ok"] is True
    assert r["count"] == 0
    assert r["head"] == _GENESIS


def test_single_record_verifies(receipt_db):
    receipt_db.record("app1", "tool_x", "ok")
    r = receipt_db.verify()
    assert r["ok"] is True
    assert r["count"] == 1
    assert r["head"] != _GENESIS


def test_multiple_records_chain_correctly(receipt_db):
    for i in range(5):
        receipt_db.record("app1", f"tool_{i}", "ok")
    r = receipt_db.verify()
    assert r["ok"] is True
    assert r["count"] == 5


def test_tampered_entry_hash_detected(receipt_db):
    receipt_db.record("app1", "tool_x", "ok")
    receipt_db.record("app1", "tool_y", "ok")
    receipt_db._conn.execute(
        "UPDATE receipts SET entry_hash = 'tampered' WHERE id = 1")
    r = receipt_db.verify()
    assert r["ok"] is False
    assert r["broken_at"] == 1
    assert r["reason"] == "entry_hash mismatch"


def test_tampered_prev_hash_detected(receipt_db):
    receipt_db.record("app1", "tool_x", "ok")
    receipt_db.record("app1", "tool_y", "ok")
    receipt_db._conn.execute(
        "UPDATE receipts SET prev_hash = 'bogus' WHERE id = 2")
    r = receipt_db.verify()
    assert r["ok"] is False
    assert r["broken_at"] == 2
    assert r["reason"] == "prev_hash linkage"


def test_deleted_row_breaks_chain(receipt_db):
    receipt_db.record("app1", "tool_x", "ok")
    receipt_db.record("app1", "tool_y", "ok")
    receipt_db.record("app1", "tool_z", "ok")
    receipt_db._conn.execute("DELETE FROM receipts WHERE id = 2")
    r = receipt_db.verify()
    assert r["ok"] is False


# ── record() with on_record observer ────────────────────────────────────────

def test_on_record_observer_called(tmp_path):
    calls = []
    db = ReceiptLog(db_path=str(tmp_path / "obs.db"),
                    on_record=lambda *a: calls.append(a))
    db.record("app1", "tool_x", "ok", "detail1")
    assert len(calls) == 1
    assert calls[0] == ("app1", "tool_x", "ok", "detail1")


def test_on_record_observer_failure_swallowed(tmp_path):
    def bad_observer(*a):
        raise RuntimeError("boom")

    db = ReceiptLog(db_path=str(tmp_path / "obs2.db"), on_record=bad_observer)
    db.record("app1", "tool_x", "ok")
    r = db.verify()
    assert r["ok"] is True
    assert r["count"] == 1


# ── tail() ───────────────────────────────────────────────────────────────────

def test_tail_returns_newest_first(receipt_db):
    receipt_db.record("app1", "tool_a", "ok")
    receipt_db.record("app1", "tool_b", "denied")
    receipt_db.record("app1", "tool_c", "ok")
    rows = receipt_db.tail("app1")
    assert len(rows) == 3
    assert rows[0]["tool"] == "tool_c"
    assert rows[2]["tool"] == "tool_a"


def test_tail_scoped_to_app_id(receipt_db):
    receipt_db.record("app1", "tool_a", "ok")
    receipt_db.record("app2", "tool_b", "ok")
    receipt_db.record("app1", "tool_c", "ok")
    rows = receipt_db.tail("app1")
    assert len(rows) == 2
    assert all(r["tool"] in ("tool_a", "tool_c") for r in rows)


def test_tail_respects_limit(receipt_db):
    for i in range(10):
        receipt_db.record("app1", f"tool_{i}", "ok")
    rows = receipt_db.tail("app1", limit=3)
    assert len(rows) == 3


def test_tail_clamps_limit(receipt_db):
    receipt_db.record("app1", "tool_a", "ok")
    rows = receipt_db.tail("app1", limit=0)
    assert len(rows) == 1

    rows = receipt_db.tail("app1", limit=999)
    assert len(rows) == 1


# ── since() ──────────────────────────────────────────────────────────────────

def test_since_returns_oldest_first(receipt_db):
    receipt_db.record("app1", "tool_a", "ok")
    receipt_db.record("app1", "tool_b", "ok")
    rows = receipt_db.since("app1", "2000-01-01T00:00:00Z")
    assert len(rows) == 2
    assert rows[0]["tool"] == "tool_a"


def test_since_scoped_to_app_id(receipt_db):
    receipt_db.record("app1", "tool_a", "ok")
    receipt_db.record("app2", "tool_b", "ok")
    rows = receipt_db.since("app1", "2000-01-01T00:00:00Z")
    assert len(rows) == 1
    assert rows[0]["tool"] == "tool_a"


def test_since_filters_by_outcome(receipt_db):
    receipt_db.record("app1", "tool_a", "ok")
    receipt_db.record("app1", "tool_b", "denied")
    receipt_db.record("app1", "tool_c", "ok")
    rows = receipt_db.since("app1", "2000-01-01T00:00:00Z", outcome="ok")
    assert len(rows) == 2
    assert all(r["outcome"] == "ok" for r in rows)


def test_since_future_timestamp_returns_empty(receipt_db):
    receipt_db.record("app1", "tool_a", "ok")
    rows = receipt_db.since("app1", "2099-01-01T00:00:00Z")
    assert len(rows) == 0


# ── distinct_tools() ────────────────────────────────────────────────────────

def test_distinct_tools_returns_unique_names(receipt_db):
    receipt_db.record("app1", "tool_a", "ok")
    receipt_db.record("app1", "tool_b", "ok")
    receipt_db.record("app1", "tool_a", "denied")
    tools = receipt_db.distinct_tools("app1", "2000-01-01T00:00:00Z")
    assert sorted(tools) == ["tool_a", "tool_b"]


def test_distinct_tools_scoped_to_app(receipt_db):
    receipt_db.record("app1", "tool_a", "ok")
    receipt_db.record("app2", "tool_b", "ok")
    tools = receipt_db.distinct_tools("app1", "2000-01-01T00:00:00Z")
    assert tools == ["tool_a"]


def test_distinct_tools_filters_by_outcome(receipt_db):
    receipt_db.record("app1", "tool_a", "ok")
    receipt_db.record("app1", "tool_b", "denied")
    tools = receipt_db.distinct_tools("app1", "2000-01-01T00:00:00Z", outcome="ok")
    assert tools == ["tool_a"]


# ── migration backfill ──────────────────────────────────────────────────────

def test_backfill_chains_unchained_rows(tmp_path):
    import sqlite3
    db_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE receipts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            app_id TEXT NOT NULL,
            tool TEXT NOT NULL,
            outcome TEXT NOT NULL,
            detail TEXT
        )
    """)
    conn.execute(
        "INSERT INTO receipts (ts, app_id, tool, outcome) VALUES (?, ?, ?, ?)",
        ("2024-01-01T00:00:00Z", "app1", "tool_a", "ok"))
    conn.execute(
        "INSERT INTO receipts (ts, app_id, tool, outcome) VALUES (?, ?, ?, ?)",
        ("2024-01-01T00:00:01Z", "app1", "tool_b", "ok"))
    conn.commit()
    conn.close()

    log = ReceiptLog(db_path=str(db_path))
    r = log.verify()
    assert r["ok"] is True
    assert r["count"] == 2
    assert r["head"] != _GENESIS
