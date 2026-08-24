"""Dedicated unit tests for governance_ledger.py — pure hash functions, chain
verification edge cases, and rechain anchor guards.

The A7 test (test_governance_ledger_a7.py) covers the v1→v2 migration and
project-column tamper detection. This file covers the remaining surface:
decode/payload canonicalization, empty-chain edge cases, expected_head
anchoring, content-tamper and prev-hash-break detection, and the rechain
anchor-status refusal paths.
"""
from __future__ import annotations

import json
from unittest.mock import patch

from willow_mcp.governance_ledger import (
    GovernanceLedger,
    _decode,
    _payload,
    _payload_v2,
    entry_hash,
    entry_hash_v2,
)


# ── _decode ──────────────────────────────────────────────────────────────────

def test_decode_parses_json_string():
    assert _decode('{"a":1}') == {"a": 1}


def test_decode_returns_non_json_string_as_is():
    assert _decode("not json {") == "not json {"


def test_decode_passes_dict_through():
    d = {"key": "val"}
    assert _decode(d) is d


def test_decode_passes_list_through():
    lst = [1, 2, 3]
    assert _decode(lst) is lst


def test_decode_passes_none_through():
    assert _decode(None) is None


# ── _payload / _payload_v2 canonicalization ──────────────────────────────────

def test_payload_sorts_keys():
    result = json.loads(_payload("decision", {"b": 2, "a": 1}))
    assert list(result.keys()) == ["content", "event_type"]
    assert result["content"] == {"a": 1, "b": 2}


def test_payload_decodes_json_string_content():
    result = json.loads(_payload("test", '{"x":1}'))
    assert result["content"] == {"x": 1}


def test_payload_v2_includes_id_and_project():
    result = json.loads(_payload_v2("id-1", "proj-A", "decision", {"v": 1}))
    assert result["id"] == "id-1"
    assert result["project"] == "proj-A"
    assert result["event_type"] == "decision"
    assert result["content"] == {"v": 1}


def test_payload_v2_sorts_keys():
    result = _payload_v2("i", "p", "e", {"z": 1, "a": 2})
    parsed = json.loads(result)
    assert list(parsed.keys()) == ["content", "event_type", "id", "project"]


# ── entry_hash / entry_hash_v2 ──────────────────────────────────────────────

def test_entry_hash_deterministic():
    h1 = entry_hash("prev", "decision", {"k": "v"})
    h2 = entry_hash("prev", "decision", {"k": "v"})
    assert h1 == h2
    assert len(h1) == 64


def test_entry_hash_none_prev():
    h = entry_hash(None, "decision", {"k": "v"})
    assert len(h) == 64


def test_entry_hash_sensitive_to_event_type():
    assert entry_hash("p", "decision", {}) != entry_hash("p", "citation", {})


def test_entry_hash_sensitive_to_content():
    assert entry_hash("p", "decision", {"a": 1}) != entry_hash("p", "decision", {"a": 2})


def test_entry_hash_sensitive_to_prev():
    assert entry_hash("prev1", "d", {}) != entry_hash("prev2", "d", {})


def test_entry_hash_v2_deterministic():
    h1 = entry_hash_v2("prev", "id1", "proj", "evt", {"k": "v"})
    h2 = entry_hash_v2("prev", "id1", "proj", "evt", {"k": "v"})
    assert h1 == h2


def test_v1_and_v2_differ():
    h1 = entry_hash("prev", "decision", {"k": "v"})
    h2 = entry_hash_v2("prev", "id1", "proj", "decision", {"k": "v"})
    assert h1 != h2


def test_entry_hash_content_order_independent():
    h1 = entry_hash("p", "d", {"z": 1, "a": 2})
    h2 = entry_hash("p", "d", {"a": 2, "z": 1})
    assert h1 == h2


# ── FakePg (shared with rechain/verify tests) ───────────────────────────────

class _FakePg:
    def __init__(self, rows):
        self.rows = rows

    def cursor(self):
        return _FakeCursor(self)

    def commit(self):
        pass

    def rollback(self):
        pass


class _FakeCursor:
    def __init__(self, pg):
        self.pg = pg
        self._result = []

    def execute(self, sql, params=None):
        if "pg_advisory" in sql:
            return
        if sql.startswith("UPDATE"):
            prev_hash, new_hash, row_id = params
            for r in self.pg.rows:
                if r["id"] == row_id:
                    r["prev_hash"], r["hash"] = prev_hash, new_hash
            return
        if sql.startswith("INSERT"):
            rid, proj, et, content, prev_hash, new_hash = params
            self.pg.rows.append({
                "id": rid, "project": proj, "event_type": et,
                "content": json.loads(content) if isinstance(content, str) else content,
                "prev_hash": prev_hash, "hash": new_hash,
            })
            return
        if "prev_hash, hash" in sql:
            self._result = [
                (r["id"], r["project"], r["event_type"], r["content"],
                 r["prev_hash"], r["hash"]) for r in self.pg.rows
            ]
        else:
            self._result = [
                (r["id"], r["project"], r["event_type"], r["content"],
                 r["hash"]) for r in self.pg.rows
            ]

    def fetchall(self):
        return list(self._result)

    def fetchone(self):
        return self._result[0] if self._result else None

    def close(self):
        pass


def _v2_chain(entries):
    rows, prev = [], None
    for rid, proj, et, content in entries:
        h = entry_hash_v2(prev, rid, proj, et, content)
        rows.append({"id": rid, "project": proj, "event_type": et,
                     "content": content, "prev_hash": prev, "hash": h})
        prev = h
    return rows


# ── verify() edge cases ─────────────────────────────────────────────────────

def test_verify_empty_chain():
    r = GovernanceLedger(_FakePg([])).verify()
    assert r["valid"] is True
    assert r["count"] == 0
    assert r["head"] is None


def test_verify_single_row_chain():
    rows = _v2_chain([("a", "p", "decision", {"n": 1})])
    r = GovernanceLedger(_FakePg(rows)).verify()
    assert r["valid"] is True
    assert r["count"] == 1
    assert r["head"] == rows[0]["hash"]


def test_verify_content_tamper_detected():
    rows = _v2_chain([
        ("a", "p", "decision", {"n": 1}),
        ("b", "p", "decision", {"n": 2}),
    ])
    rows[0]["content"] = {"n": 999}
    r = GovernanceLedger(_FakePg(rows)).verify()
    assert r["valid"] is False
    assert r["broken_at"] == "a"


def test_verify_prev_hash_break_detected():
    rows = _v2_chain([
        ("a", "p", "decision", {"n": 1}),
        ("b", "p", "decision", {"n": 2}),
    ])
    rows[1]["prev_hash"] = "bogus"
    r = GovernanceLedger(_FakePg(rows)).verify()
    assert r["valid"] is False
    assert r["broken_at"] == "b"


def test_verify_expected_head_match():
    rows = _v2_chain([("a", "p", "d", {"n": 1})])
    head = rows[-1]["hash"]
    r = GovernanceLedger(_FakePg(rows)).verify(expected_head=head)
    assert r["valid"] is True


def test_verify_expected_head_mismatch():
    rows = _v2_chain([("a", "p", "d", {"n": 1})])
    r = GovernanceLedger(_FakePg(rows)).verify(expected_head="wrong_head")
    assert r["valid"] is False
    assert r["broken_at"] is None
    assert r["expected_head"] == "wrong_head"
    assert r["head"] == rows[-1]["hash"]


def test_verify_expected_head_on_empty_chain():
    r = GovernanceLedger(_FakePg([])).verify(expected_head="some_head")
    assert r["valid"] is False
    assert r["head"] is None


# ── rechain() anchor-guard paths ─────────────────────────────────────────────

def test_rechain_refuses_on_head_mismatch():
    rows = _v2_chain([("a", "p", "d", {"n": 1})])
    anchor = {"status": "anchored", "head": "not_the_real_head"}
    with patch("willow_mcp.frank_head_anchor.read_anchor", return_value=anchor):
        r = GovernanceLedger(_FakePg(rows)).rechain()
    assert r["refused"] is True
    assert r["reason"] == "head_mismatch"
    assert r["migrated"] == 0


def test_rechain_refuses_on_untrusted_anchor():
    rows = _v2_chain([("a", "p", "d", {"n": 1})])
    anchor = {"status": "untrusted", "head": None}
    with patch("willow_mcp.frank_head_anchor.read_anchor", return_value=anchor):
        r = GovernanceLedger(_FakePg(rows)).rechain()
    assert r["refused"] is True
    assert r["reason"] == "untrusted"


def test_rechain_refuses_on_unreadable_anchor():
    rows = _v2_chain([("a", "p", "d", {"n": 1})])
    anchor = {"status": "unreadable", "head": None}
    with patch("willow_mcp.frank_head_anchor.read_anchor", return_value=anchor):
        r = GovernanceLedger(_FakePg(rows)).rechain()
    assert r["refused"] is True
    assert r["reason"] == "unreadable"


def test_rechain_proceeds_on_unanchored():
    from willow_mcp.governance_ledger import entry_hash as _eh
    entries = [("a", "p", "d", {"n": 1})]
    rows, prev = [], None
    for rid, proj, et, content in entries:
        h = _eh(prev, et, content)
        rows.append({"id": rid, "project": proj, "event_type": et,
                     "content": content, "prev_hash": prev, "hash": h})
        prev = h
    anchor = {"status": "unanchored", "head": None}
    with patch("willow_mcp.frank_head_anchor.read_anchor", return_value=anchor):
        r = GovernanceLedger(_FakePg(rows)).rechain()
    assert r.get("refused") is not True
    assert r["migrated"] == 1


def test_rechain_force_bypasses_anchor_guard():
    rows = _v2_chain([("a", "p", "d", {"n": 1})])
    r = GovernanceLedger(_FakePg(rows)).rechain(force=True)
    assert r.get("refused") is not True
    assert r["migrated"] == 0


def test_rechain_appends_marker_when_rows_migrated():
    from willow_mcp.governance_ledger import entry_hash as _eh
    entries = [("a", "p", "d", {"n": 1}), ("b", "p", "d", {"n": 2})]
    rows, prev = [], None
    for rid, proj, et, content in entries:
        h = _eh(prev, et, content)
        rows.append({"id": rid, "project": proj, "event_type": et,
                     "content": content, "prev_hash": prev, "hash": h})
        prev = h
    pg = _FakePg(rows)
    led = GovernanceLedger(pg)
    r = led.rechain(force=True)
    assert r["migrated"] == 2
    assert len(pg.rows) == 3
    marker = pg.rows[-1]
    assert marker["event_type"] == "governance.rechain"
    assert marker["content"]["migrated"] == 2
    assert led.verify()["valid"] is True
