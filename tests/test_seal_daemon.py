"""willow_mcp.seal_daemon — the wiring between the ratatosk seal watch and
willow_mcp.seal_handler.on_seal.

Two things this file has to prove independent of whether the real
willow-ratatosk seal-watch daemon (SeatDaemon/JsonlTailWatcher, currently
only on the held feat/ratatosk-listener-daemon branch) is installed:

1. The predicate this module hands the watcher is the RIGHT one for the
   real Nestor ledger (`kind == "seal"` + `source_lang == "decision"`), and
   rejects the WRONG shape (`op == "seal"`, which is what SeatDaemon's own
   hardcoded default uses and which never fires against the real ledger).
2. `build_seal_daemon` fails loudly and clearly, rather than crashing
   obscurely, when the daemon is not available to import.

Test 1 needs no real ratatosk install — `seal_predicate` is a plain
module-level function. Where the wiring construction itself needs to be
exercised (record what JsonlTailWatcher/SeatDaemon were called with), a
minimal stub is monkeypatched in for the two ratatosk names — this checks
the ARGUMENTS willow-mcp passes, not ratatosk's own behavior, which is out
of scope for this repo's suite.
"""
from __future__ import annotations

import pytest

from willow_mcp import seal_daemon


# --- predicate correctness -------------------------------------------------

def test_seal_predicate_matches_a_real_sample_seal_record():
    sample = {
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
    assert seal_daemon.seal_predicate(sample) is True


def test_seal_predicate_rejects_op_only_shape():
    """The exact bug SeatDaemon's own default predicate has: keying off
    `op` instead of `kind`. A predicate written for the wrong field would
    accept this; ours must reject it."""
    op_only = {"op": "seal", "pair_id": "pair-001", "source_lang": "decision"}
    assert seal_daemon.seal_predicate(op_only) is False


def test_seal_predicate_rejects_non_decision_seal():
    non_decision = {"kind": "seal", "pair_id": "p1", "source_lang": "translation"}
    assert seal_daemon.seal_predicate(non_decision) is False


def test_seal_predicate_rejects_non_dict():
    assert seal_daemon.seal_predicate("not-a-record") is False
    assert seal_daemon.seal_predicate(None) is False


# --- first-run offset seeding ----------------------------------------------

def test_seed_offset_at_eof_when_absent(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text('{"kind": "seal"}\n' * 5, encoding="utf-8")
    offset_path = tmp_path / "seal_watch.offset"

    seal_daemon._seed_offset_at_eof_if_absent(ledger, offset_path)

    assert offset_path.exists()
    assert int(offset_path.read_text()) == ledger.stat().st_size


def test_seed_offset_does_not_clobber_existing(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text('{"kind": "seal"}\n' * 5, encoding="utf-8")
    offset_path = tmp_path / "seal_watch.offset"
    offset_path.write_text("3", encoding="utf-8")

    seal_daemon._seed_offset_at_eof_if_absent(ledger, offset_path)

    assert offset_path.read_text() == "3"


def test_seed_offset_handles_missing_ledger(tmp_path):
    ledger = tmp_path / "does-not-exist.jsonl"
    offset_path = tmp_path / "seal_watch.offset"

    seal_daemon._seed_offset_at_eof_if_absent(ledger, offset_path)

    assert int(offset_path.read_text()) == 0


# --- import-guard behavior --------------------------------------------------

def test_build_seal_daemon_raises_clear_importerror_when_ratatosk_absent(monkeypatch):
    monkeypatch.setattr(seal_daemon, "RATATOSK_AVAILABLE", False)
    monkeypatch.setattr(seal_daemon, "SeatDaemon", None)
    monkeypatch.setattr(seal_daemon, "JsonlTailWatcher", None)

    with pytest.raises(ImportError, match="willow-ratatosk"):
        seal_daemon.build_seal_daemon(channel="test-channel")


def test_ratatosk_daemon_is_not_installed_today():
    """Documents the real, current state this branch was built against: the
    released willow-ratatosk (1.2.9) has no `ratatosk.daemon` module — the
    seal-watch daemon lives only on the held feat/ratatosk-listener-daemon
    branch. If this ever flips, the skip above will fire and say so."""
    assert seal_daemon.RATATOSK_AVAILABLE is False


# --- wiring: build_seal_daemon supplies the correct predicate ---------------

class _StubBusListenerBackedSeatDaemon:
    """Records what it was constructed with; stands in for
    ratatosk.daemon.SeatDaemon without needing a real Grove connection."""

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.seal_watcher = None


class _StubJsonlTailWatcher:
    """Records what it was constructed with; stands in for
    ratatosk.daemon.JsonlTailWatcher."""

    def __init__(self, *, ledger_path, op_predicate, callback, offset_store_path):
        self.ledger_path = ledger_path
        self.op_predicate = op_predicate
        self.callback = callback
        self.offset_store_path = offset_store_path


@pytest.fixture
def stubbed_ratatosk(monkeypatch):
    monkeypatch.setattr(seal_daemon, "RATATOSK_AVAILABLE", True)
    monkeypatch.setattr(seal_daemon, "SeatDaemon", _StubBusListenerBackedSeatDaemon)
    monkeypatch.setattr(seal_daemon, "JsonlTailWatcher", _StubJsonlTailWatcher)
    return None


def test_build_seal_daemon_wires_the_kind_seal_predicate(stubbed_ratatosk, tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("", encoding="utf-8")
    offset = tmp_path / "offset"
    seen = []

    daemon = seal_daemon.build_seal_daemon(
        channel="test-channel",
        ledger_path=ledger,
        offset_path=offset,
        on_seal=seen.append,
    )

    assert isinstance(daemon, _StubBusListenerBackedSeatDaemon)
    watcher = daemon.seal_watcher
    assert isinstance(watcher, _StubJsonlTailWatcher)
    watcher.callback({"probe": 1})
    assert seen == [{"probe": 1}]
    assert str(watcher.ledger_path) == str(ledger)

    # The real thing this test exists for: the predicate handed to the
    # watcher matches a real sample seal record and rejects the op-only
    # shape SeatDaemon's own hardcoded default would have accepted.
    real_sample = {
        "kind": "seal", "pair_id": "p1", "source_lang": "decision",
    }
    op_only = {"op": "seal", "pair_id": "p1", "source_lang": "decision"}
    assert watcher.op_predicate(real_sample) is True
    assert watcher.op_predicate(op_only) is False


def test_build_seal_daemon_seeds_offset_at_eof_on_first_run(stubbed_ratatosk, tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text('{"kind": "seal"}\n' * 619, encoding="utf-8")
    offset = tmp_path / "offset"

    seal_daemon.build_seal_daemon(
        channel="test-channel", ledger_path=ledger, offset_path=offset,
    )

    assert int(offset.read_text()) == ledger.stat().st_size
