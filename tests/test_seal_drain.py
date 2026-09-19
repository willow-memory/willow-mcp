"""willow_mcp.seal_drain — the seal watch as one tick.

Sealed decision 72292afd (2026-09-18): the seal watcher runs on the steward
tick, as a verb, not as its own unit. These tests pin the receipt's three
states, the at-least-once offset discipline, the shared offset file with
seal_daemon, and the gate/tier wiring for ``seal_drain``.

Uses an injected ``on_seal`` (a recorder) for the walk tests and a real
``Store`` for the one end-to-end upgrade, same posture as test_seal_handler.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from willow_mcp import seal_daemon, seal_drain, seal_handler
from willow_mcp.db import Store


def _seal(pair_id, **overrides):
    rec = {
        "ts": "2026-09-18T18:00:00+00:00", "prev": "abc", "kind": "seal",
        "pair_id": pair_id, "verifier": "sean campbell",
        "source_lang": "decision", "target_lang": "decision",
        "source_sha": "deadbeef", "origin": "nestor", "upgraded_from": "draft",
    }
    rec.update(overrides)
    return rec


def _write_ledger(path: Path, records, *, trailing_partial: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        for r in records:
            f.write((r if isinstance(r, str) else json.dumps(r)) + "\n")
        if trailing_partial:
            f.write(trailing_partial)


@pytest.fixture
def paths(tmp_path):
    return tmp_path / "ledger.jsonl", tmp_path / "store" / "seal_watch.offset"


class _Recorder:
    def __init__(self, outcome="upgraded"):
        self.seen = []
        self.outcome = outcome

    def __call__(self, record):
        self.seen.append(record)
        return self.outcome(record) if callable(self.outcome) else self.outcome


# ── three states ─────────────────────────────────────────────────────────────

def test_missing_ledger_is_unreachable_not_empty(paths):
    ledger, offset = paths
    out = seal_drain.drain(ledger_path=ledger, offset_path=offset, on_seal=_Recorder())
    assert out["state"] == "unreachable"
    assert out["reason"] == "ledger_missing"
    assert "drained" not in out


def test_no_new_bytes_is_empty(paths):
    ledger, offset = paths
    _write_ledger(ledger, [_seal("p1")])
    # First run seeds the offset at EOF (seal_daemon posture): nothing to drain.
    out = seal_drain.drain(ledger_path=ledger, offset_path=offset, on_seal=_Recorder())
    assert out["state"] == "empty"
    assert out["drained"] == 0
    assert out["offset_before"] == ledger.stat().st_size


def test_new_seals_are_drained_and_offset_advances(paths):
    ledger, offset = paths
    _write_ledger(ledger, [_seal("old")])
    seal_drain.drain(ledger_path=ledger, offset_path=offset, on_seal=_Recorder())  # seed
    _write_ledger(ledger, [_seal("p1"), {"kind": "seal", "source_lang": "en", "pair_id": "x"},
                           _seal("p2"), {"kind": "passage"}])

    rec = _Recorder(outcome=lambda r: "upgraded" if r["pair_id"] == "p1" else "unmatched")
    out = seal_drain.drain(ledger_path=ledger, offset_path=offset, on_seal=rec)

    assert out["state"] == "populated"
    assert out["drained"] == 4
    assert out["results"] == {"upgraded": 1, "already": 0, "unmatched": 1, "skipped": 2, "error": 0}
    assert out["upgraded"] == ["p1"]
    assert [r["pair_id"] for r in rec.seen] == ["p1", "p2"]     # non-decision rows never reach on_seal
    assert out["offset_after"] == ledger.stat().st_size
    assert int(offset.read_text()) == out["offset_after"]

    again = seal_drain.drain(ledger_path=ledger, offset_path=offset, on_seal=_Recorder())
    assert again["state"] == "empty"


def test_backfill_walks_from_the_start(paths):
    ledger, offset = paths
    _write_ledger(ledger, [_seal("p1"), _seal("p2")])
    rec = _Recorder()
    out = seal_drain.drain(ledger_path=ledger, offset_path=offset, on_seal=rec,
                           seed_at_eof_if_absent=False)
    assert out["state"] == "populated"
    assert out["offset_before"] == 0
    assert [r["pair_id"] for r in rec.seen] == ["p1", "p2"]


# ── at-least-once discipline ─────────────────────────────────────────────────

def test_partial_trailing_line_is_left_for_next_tick(paths):
    ledger, offset = paths
    offset.parent.mkdir(parents=True)
    offset.write_text("0")
    _write_ledger(ledger, [_seal("p1")], trailing_partial='{"kind": "seal", "pair_id": "half')

    rec = _Recorder()
    out = seal_drain.drain(ledger_path=ledger, offset_path=offset, on_seal=rec)

    assert out["drained"] == 1
    assert [r["pair_id"] for r in rec.seen] == ["p1"]
    # Offset stops at the start of the partial line, not EOF.
    assert out["offset_after"] < ledger.stat().st_size
    assert out["offset_after"] == len(json.dumps(_seal("p1"))) + 1

    # Finish the line: next tick picks it up from exactly there.
    with open(ledger, "a", encoding="utf-8") as f:
        f.write('", "source_lang": "decision"}\n')
    rec2 = _Recorder()
    out2 = seal_drain.drain(ledger_path=ledger, offset_path=offset, on_seal=rec2)
    assert out2["drained"] == 1
    assert rec2.seen[0]["pair_id"] == "half"


def test_malformed_lines_are_counted_not_fatal(paths):
    ledger, offset = paths
    offset.parent.mkdir(parents=True)
    offset.write_text("0")
    _write_ledger(ledger, ["not json at all", _seal("p1")])
    rec = _Recorder()
    out = seal_drain.drain(ledger_path=ledger, offset_path=offset, on_seal=rec)
    assert out["state"] == "populated"
    assert out["malformed"] == 1
    assert out["drained"] == 2
    assert [r["pair_id"] for r in rec.seen] == ["p1"]


def test_max_records_bounds_one_tick(paths):
    ledger, offset = paths
    offset.parent.mkdir(parents=True)
    offset.write_text("0")
    _write_ledger(ledger, [_seal(f"p{i}") for i in range(5)])

    out = seal_drain.drain(ledger_path=ledger, offset_path=offset, on_seal=_Recorder(),
                           max_records=3)
    assert out["drained"] == 3 and out["truncated"] is True

    out2 = seal_drain.drain(ledger_path=ledger, offset_path=offset, on_seal=_Recorder(),
                            max_records=3)
    assert out2["drained"] == 2 and out2["truncated"] is False
    assert out2["offset_after"] == ledger.stat().st_size


def test_rotated_ledger_restarts_from_zero_and_says_so(paths):
    ledger, offset = paths
    offset.parent.mkdir(parents=True)
    _write_ledger(ledger, [_seal("p1")])
    offset.write_text(str(ledger.stat().st_size + 10_000))   # offset past EOF
    rec = _Recorder()
    out = seal_drain.drain(ledger_path=ledger, offset_path=offset, on_seal=rec)
    assert out["rotated"] is True
    assert out["offset_before"] == 0
    assert [r["pair_id"] for r in rec.seen] == ["p1"]


def test_unwritable_offset_is_unreachable_with_the_work_reported(paths, monkeypatch):
    ledger, offset = paths
    offset.parent.mkdir(parents=True)
    offset.write_text("0")
    _write_ledger(ledger, [_seal("p1")])

    def _refuse(path, value):
        raise OSError("disk full")
    monkeypatch.setattr(seal_drain, "_write_offset", _refuse)

    out = seal_drain.drain(ledger_path=ledger, offset_path=offset, on_seal=_Recorder())
    assert out["state"] == "unreachable"
    assert out["reason"] == "offset_unwritable"
    assert out["drained"] == 1 and out["upgraded"] == ["p1"]
    assert out["offset_after"] == 0                       # position NOT advanced
    assert offset.read_text() == "0"


def test_handler_surprise_outcome_counts_as_error(paths):
    ledger, offset = paths
    offset.parent.mkdir(parents=True)
    offset.write_text("0")
    _write_ledger(ledger, [_seal("p1")])
    out = seal_drain.drain(ledger_path=ledger, offset_path=offset,
                           on_seal=_Recorder(outcome="???"))
    assert out["results"]["error"] == 1


# ── shares the daemon's paths and predicate ─────────────────────────────────

def test_defaults_are_the_daemons_defaults(monkeypatch, tmp_path):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    monkeypatch.delenv(seal_daemon.NESTOR_LEDGER_ENV, raising=False)
    out = seal_drain.drain(on_seal=_Recorder())
    assert out["ledger"] == str(seal_daemon.default_ledger_path())
    assert out["offset_path"] == str(seal_daemon.default_offset_path())
    assert out["state"] == "unreachable" and out["reason"] == "ledger_missing"


# ── end to end through the real handler and a real store ────────────────────

def test_drain_upgrades_a_real_governance_record(paths, tmp_path, monkeypatch):
    ledger, offset = paths
    offset.parent.mkdir(parents=True)
    offset.write_text("0")
    store = Store(store_root=str(tmp_path / "soil"))
    rid, _ = store.put(seal_handler.GOVERNANCE_COLLECTION,
                       {"title": "Adopt X", "status": "proposed", "nestor_pair_id": "pair-9"})
    _write_ledger(ledger, [_seal("pair-9")])
    missing_db = tmp_path / "nope" / "nestor.db"

    out = seal_drain.drain(
        ledger_path=ledger, offset_path=offset,
        on_seal=lambda r: seal_handler.on_seal(r, store=store, db_path=missing_db),
    )

    assert out["state"] == "populated" and out["upgraded"] == ["pair-9"]
    gov = store.get(seal_handler.GOVERNANCE_COLLECTION, rid)
    assert gov["status"] == "sealed"
    assert gov["nestor_verifier"] == "sean campbell"

    # Replay (crash before the offset write, say) is a clean 'already'.
    offset.write_text("0")
    again = seal_drain.drain(
        ledger_path=ledger, offset_path=offset,
        on_seal=lambda r: seal_handler.on_seal(r, store=store, db_path=missing_db),
    )
    assert again["results"]["already"] == 1 and again["upgraded"] == []


# ── gate + tier wiring ──────────────────────────────────────────────────────

def test_seal_drain_is_gated_and_classed():
    from willow_mcp import gate, tier_policy
    assert "seal_drain" in gate.PERMISSION_GROUPS["governance_sync"]
    assert "seal_drain" in gate.PERMISSION_GROUPS["full_access"]
    assert "seal_drain" not in gate.PERMISSION_GROUPS["governance_propose"]
    assert tier_policy.TOOL_CLASS["seal_drain"] == tier_policy.WRITE


def test_server_verb_threads_args(monkeypatch):
    from willow_mcp import server
    seen = {}
    monkeypatch.setattr(seal_drain, "drain", lambda **kw: seen.update(kw) or {"state": "empty"})
    fn = getattr(server.seal_drain, "__wrapped__", server.seal_drain)
    out = fn(app_id="willow", max_records=7, backfill=True)
    assert out == {"state": "empty"}
    assert seen == {"max_records": 7, "seed_at_eof_if_absent": False}
