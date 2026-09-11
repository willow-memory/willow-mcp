"""willow_mcp.seal_daemon — the wiring between the ratatosk seal watch and
willow_mcp.seal_handler.on_seal.

willow-ratatosk 1.7.0 (installed, real) put a ``seal_predicate`` constructor
parameter directly on ``SeatDaemon``, so this module constructs the real
daemon rather than building a bare one and replacing its ``seal_watcher``
after the fact. Two things this file has to prove:

1. The predicate this module hands the daemon is the RIGHT one for the real
   Nestor ledger (`kind == "seal"` + `source_lang == "decision"`), and
   rejects the WRONG shape (`op == "seal"`, which is SeatDaemon's own
   default and which never fires against the real ledger).
2. `build_seal_daemon` constructs the real ``SeatDaemon`` with the ledger
   path, offset path, handler, and predicate wired through its constructor
   — and fails loudly and clearly if ``willow-ratatosk`` is not installed.

Test 1 needs no real ratatosk install — `seal_predicate` is a plain
module-level function. Test 2 exercises the REAL installed ``SeatDaemon``
(RATATOSK_AVAILABLE is True in this environment) so the assertions run
against actual constructor behavior, not a stand-in for it.
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

    with pytest.raises(ImportError, match="willow-ratatosk"):
        seal_daemon.build_seal_daemon(channel="test-channel")


def test_ratatosk_is_installed_with_the_seal_watch_daemon():
    """willow-ratatosk 1.7.0 is published and installed in this environment
    — ``ratatosk.daemon.SeatDaemon`` is importable and real. This branch no
    longer builds against an unreleased daemon; if this ever flips back to
    False, every test below that exercises the real SeatDaemon will fail
    loudly rather than silently skip."""
    assert seal_daemon.RATATOSK_AVAILABLE is True


# --- wiring: build_seal_daemon constructs the real SeatDaemon --------------

def test_build_seal_daemon_constructs_real_seatdaemon_with_wired_predicate(tmp_path):
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

    assert isinstance(daemon, seal_daemon.SeatDaemon)
    watcher = daemon.seal_watcher
    assert watcher is not None
    assert str(watcher.ledger_path) == str(ledger)
    assert str(watcher.offset_store_path) == str(offset)

    # The handler is bound through on_seal, not patched in after the fact.
    watcher.callback({"probe": 1})
    assert seen == [{"probe": 1}]

    # The real thing this test exists for: the predicate handed through the
    # constructor matches a real sample seal record and rejects the op-only
    # shape SeatDaemon's own default predicate would have accepted.
    real_sample = {"kind": "seal", "pair_id": "p1", "source_lang": "decision"}
    op_only = {"op": "seal", "pair_id": "p1", "source_lang": "decision"}
    assert watcher.op_predicate(real_sample) is True
    assert watcher.op_predicate(op_only) is False


def test_build_seal_daemon_seeds_offset_at_eof_on_first_run(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text('{"kind": "seal"}\n' * 619, encoding="utf-8")
    offset = tmp_path / "offset"

    seal_daemon.build_seal_daemon(
        channel="test-channel", ledger_path=ledger, offset_path=offset,
    )

    assert int(offset.read_text()) == ledger.stat().st_size


def test_build_seal_daemon_binds_on_seal_from_seal_handler(tmp_path):
    """Default on_seal is seal_handler.on_seal, not some placeholder."""
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("", encoding="utf-8")
    offset = tmp_path / "offset"

    daemon = seal_daemon.build_seal_daemon(
        channel="test-channel", ledger_path=ledger, offset_path=offset,
    )

    from willow_mcp import seal_handler
    assert daemon.seal_watcher.callback is seal_handler.on_seal
