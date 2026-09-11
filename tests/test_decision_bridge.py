"""willow_mcp.decision_bridge — the propose half of the nestor-propose-bridge.

Mirrors test_seal_handler.py's style: a per-test ``Store(store_root=tmp_path)``
passed explicitly, and a temp nestor.db passed via ``db_path=``.

The end-to-end test (``test_propose_then_seal_closes_the_loop``) is the whole
point of the bridge: propose a SOIL record into a real Nestor draft, then feed
a synthesized seal ledger record for that same pair_id through
``seal_handler.on_seal`` against the same store, and prove the SOIL record
gets upgraded to sealed. Before this bridge existed, a decision recorded via
store_put and a draft proposed by hand (outside any tool) never carried the
same nestor_pair_id, so on_seal's `nestor_pair_id == pair_id` scan never
matched anything — a sealed decision silently upgraded nothing.
"""
from __future__ import annotations

import json

import pytest

from willow_mcp import decision_bridge, seal_handler
from willow_mcp.db import Store


@pytest.fixture
def store(tmp_path):
    return Store(store_root=str(tmp_path / "store"))


@pytest.fixture
def nestor_db_path(tmp_path):
    return tmp_path / "nestor.db"


def _gov_record(**overrides):
    record = {
        "title": "Adopt the bridge",
        "ruling": "Adopt it",
        "rationale": "Closes the propose gap",
        "status": "proposed",
    }
    record.update(overrides)
    return record


def _seal_record(**overrides):
    record = {
        "ts": "2026-09-11T00:00:00+00:00",
        "prev": "abc123",
        "kind": "seal",
        "pair_id": "REPLACE_ME",
        "verifier": "sean",
        "source_lang": "decision",
        "target_lang": "decision",
        "source_sha": "deadbeef",
        "origin": "nestor",
        "upgraded_from": "draft",
    }
    record.update(overrides)
    return record


def test_record_not_found(store, nestor_db_path):
    result = decision_bridge.propose("willow", "no-such-record",
                                      store=store, db_path=nestor_db_path)
    assert result == {"error": "record_not_found"}


def test_nestor_unavailable(store, nestor_db_path, monkeypatch):
    rid, _ = store.put(decision_bridge.GOVERNANCE_COLLECTION, _gov_record())
    monkeypatch.setattr(decision_bridge, "_nestor", lambda: None)

    result = decision_bridge.propose("willow", rid, store=store, db_path=nestor_db_path)

    assert result == {"error": "nestor_unavailable"}
    # Never touched the SOIL record.
    gov = store.get(decision_bridge.GOVERNANCE_COLLECTION, rid)
    assert "nestor_pair_id" not in gov


def test_already_linked_is_idempotent_and_does_not_reach_nestor(store, nestor_db_path, monkeypatch):
    rid, _ = store.put(
        decision_bridge.GOVERNANCE_COLLECTION,
        _gov_record(nestor_pair_id="pair-existing"),
    )

    def _boom():
        raise AssertionError("must not import/touch nestor when already linked")
    monkeypatch.setattr(decision_bridge, "_nestor", _boom)

    result = decision_bridge.propose("willow", rid, store=store, db_path=nestor_db_path)

    assert result == {"pair_id": "pair-existing", "record_id": rid,
                       "status": "already_linked"}


def test_propose_creates_draft_and_stamps_soil_record(store, nestor_db_path):
    if not decision_bridge.available():
        pytest.skip("nestor extra not installed")
    rid, _ = store.put(decision_bridge.GOVERNANCE_COLLECTION, _gov_record())

    result = decision_bridge.propose("willow", rid, store=store, db_path=nestor_db_path)

    assert result["status"] == "draft"
    assert result["record_id"] == rid
    pair_id = result["pair_id"]
    assert pair_id

    gov = store.get(decision_bridge.GOVERNANCE_COLLECTION, rid)
    assert gov["nestor_pair_id"] == pair_id

    # The draft really landed in the temp nestor.db, unsealed, with the
    # SOIL record's title/ruling/rationale as defaults.
    from nestor.sqlite_store import SqliteStore
    nstore = SqliteStore(str(nestor_db_path))
    row = nstore.memory_get(pair_id)
    assert row is not None
    assert row["id"] == pair_id
    assert row["status"] == "draft"
    assert row["source_text"] == "Adopt the bridge"
    assert row["target_text"] == "Adopt it"


def test_propose_second_call_is_idempotent(store, nestor_db_path):
    if not decision_bridge.available():
        pytest.skip("nestor extra not installed")
    rid, _ = store.put(decision_bridge.GOVERNANCE_COLLECTION, _gov_record())

    first = decision_bridge.propose("willow", rid, store=store, db_path=nestor_db_path)
    second = decision_bridge.propose("willow", rid, store=store, db_path=nestor_db_path)

    assert first["status"] == "draft"
    assert second == {"pair_id": first["pair_id"], "record_id": rid,
                       "status": "already_linked"}


def test_explicit_args_override_soil_defaults(store, nestor_db_path):
    if not decision_bridge.available():
        pytest.skip("nestor extra not installed")
    rid, _ = store.put(decision_bridge.GOVERNANCE_COLLECTION, _gov_record())

    result = decision_bridge.propose(
        "willow", rid,
        question="Explicit question", conclusion="Explicit conclusion",
        rationale="Explicit rationale", origin="explicit-origin",
        store=store, db_path=nestor_db_path,
    )

    from nestor.sqlite_store import SqliteStore
    nstore = SqliteStore(str(nestor_db_path))
    row = nstore.memory_get(result["pair_id"])
    assert row["source_text"] == "Explicit question"
    assert row["target_text"] == "Explicit conclusion"
    assert row["reason"] == "Explicit rationale"
    assert row["origin"] == "explicit-origin"


def test_propose_then_seal_closes_the_loop(store, nestor_db_path):
    """The whole point of the bridge: propose stamps nestor_pair_id, and a
    seal ledgered against that same pair_id now correlates and upgrades the
    SOIL record — the exact loop that silently no-op'd before this bridge."""
    if not decision_bridge.available():
        pytest.skip("nestor extra not installed")
    rid, _ = store.put(decision_bridge.GOVERNANCE_COLLECTION, _gov_record())

    proposed = decision_bridge.propose("willow", rid, store=store, db_path=nestor_db_path)
    assert proposed["status"] == "draft"
    pair_id = proposed["pair_id"]

    seal_record = _seal_record(pair_id=pair_id)
    result = seal_handler.on_seal(seal_record, store=store, db_path=nestor_db_path)

    assert result == "upgraded"
    gov = store.get(decision_bridge.GOVERNANCE_COLLECTION, rid)
    assert gov["status"] == "sealed"
    assert gov["nestor_pair_id"] == pair_id
    assert gov["nestor_verifier"] == "sean"


def test_propose_then_REAL_nestor_seal_closes_the_loop(store, nestor_db_path, monkeypatch):
    """Same loop as test_propose_then_seal_closes_the_loop, but the seal side
    is not synthesized: it calls the REAL DecisionMemory.seal on the exact
    draft decision_propose created, reads the REAL ledger entry that seal
    writes, and feeds THAT through seal_handler.on_seal.

    This is the id-continuity claim end to end: nothing here assumes Nestor's
    seal path hands back the same id the draft was proposed under — it proves
    it, against the ledger record production actually consumes. A future
    Nestor change that allocated a fresh id at seal time would fail this test
    (on_seal would return "unmatched") while a synthesized-record test could
    never notice.
    """
    if not decision_bridge.available():
        pytest.skip("nestor extra not installed")
    from nestor import cascade
    from nestor.decision import DecisionMemory
    from nestor.sqlite_store import SqliteStore

    rid, _ = store.put(decision_bridge.GOVERNANCE_COLLECTION, _gov_record())

    proposed = decision_bridge.propose("willow", rid, store=store, db_path=nestor_db_path)
    assert proposed["status"] == "draft"
    pair_id = proposed["pair_id"]

    ledger_path = nestor_db_path.parent / "ledger.jsonl"
    # set_ledger_path mutates cascade's module-level override; restore it via
    # monkeypatch (not a manual finally) so a later test's own
    # set_ledger_path call is never left seeing this test's path as "already
    # current" and skipping its session reset.
    monkeypatch.setattr(cascade, "_LEDGER_OVERRIDE", cascade._LEDGER_OVERRIDE)
    cascade.set_ledger_path(ledger_path)

    nstore = SqliteStore(str(nestor_db_path))
    dm = DecisionMemory(nstore, domain="decision")
    # Same question/commitment decision_propose used (the SOIL record's
    # title/ruling, per _gov_record above) — sealing is also keyed by
    # normalize(question), so this has to match the draft to upgrade it
    # rather than start a second row. seal_sig="" self-signs (Nestor#2's
    # default path: no NESTOR_SEAL_KEY needed against a fresh store with
    # no prior seals by this verifier).
    sealed = dm.seal("Adopt the bridge", "Adopt it", "sean", "")

    assert sealed["id"] == pair_id, (
        "Nestor's real seal path allocated a different id than the draft — "
        "the correlation this whole bridge depends on just broke"
    )

    ledger_lines = ledger_path.read_text().splitlines()
    seal_entries = [json.loads(line) for line in ledger_lines]
    seal_entries = [e for e in seal_entries if e.get("kind") == "seal"]
    assert len(seal_entries) == 1
    real_seal_record = seal_entries[0]
    assert real_seal_record["pair_id"] == pair_id

    result = seal_handler.on_seal(real_seal_record, store=store, db_path=nestor_db_path)

    assert result == "upgraded"
    gov = store.get(decision_bridge.GOVERNANCE_COLLECTION, rid)
    assert gov["status"] == "sealed"
    assert gov["nestor_pair_id"] == pair_id


def test_same_title_same_ruling_is_a_clean_collision_not_a_shared_pair(store, nestor_db_path):
    """Two DISTINCT SOIL records sharing a title (and here, also the same
    ruling) must not both get stamped with the SAME nestor_pair_id — Nestor
    keys a pair by normalize(question), so the second propose call would get
    back the FIRST record's draft, and seal_handler.on_seal only ever
    upgrades the first match it finds, leaving the second unsealable forever
    with no sign anything is wrong. This must surface as a clean error
    instead, and the second record must be left unstamped."""
    if not decision_bridge.available():
        pytest.skip("nestor extra not installed")
    rid1, _ = store.put(decision_bridge.GOVERNANCE_COLLECTION,
                        _gov_record(title="Same title", ruling="Same ruling"))
    rid2, _ = store.put(decision_bridge.GOVERNANCE_COLLECTION,
                        _gov_record(title="Same title", ruling="Same ruling"))

    first = decision_bridge.propose("willow", rid1, store=store, db_path=nestor_db_path)
    assert first["status"] == "draft"

    second = decision_bridge.propose("willow", rid2, store=store, db_path=nestor_db_path)

    assert second["error"] == "title_collision"
    gov2 = store.get(decision_bridge.GOVERNANCE_COLLECTION, rid2)
    assert "nestor_pair_id" not in gov2


def test_same_title_different_ruling_is_a_clean_collision_not_a_traceback(store, nestor_db_path):
    """The other half of the same hazard: a second record with the same
    title but a DIFFERENT ruling makes Nestor raise ConflictingDraftError —
    that must never escape decision_propose as a raw exception."""
    if not decision_bridge.available():
        pytest.skip("nestor extra not installed")
    rid1, _ = store.put(decision_bridge.GOVERNANCE_COLLECTION,
                        _gov_record(title="Same title", ruling="Ruling one"))
    rid2, _ = store.put(decision_bridge.GOVERNANCE_COLLECTION,
                        _gov_record(title="Same title", ruling="Ruling two"))

    first = decision_bridge.propose("willow", rid1, store=store, db_path=nestor_db_path)
    assert first["status"] == "draft"

    second = decision_bridge.propose("willow", rid2, store=store, db_path=nestor_db_path)

    assert second["error"] == "title_collision"
    gov2 = store.get(decision_bridge.GOVERNANCE_COLLECTION, rid2)
    assert "nestor_pair_id" not in gov2
