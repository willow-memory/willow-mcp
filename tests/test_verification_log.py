"""Tests for kb_verify's persistence layer (GAP #3: durable verification log).

Covers: `record_verification` writes a durable, timestamped row;
repeated verifications of the same record_id accumulate (history, not
overwrite); `iter_verification_log` reads them back, filterable by
record_id; `verify_and_record` also emits a matching training_corpus row
that round-trips; and `verify_sources`/`check_health` remain side-effect-free
when called directly.
"""
from unittest.mock import patch

import pytest

from willow_mcp import kb_verify
from willow_mcp.db import Store
from willow_mcp.training_corpus import (
    COLLECTION as TRAINING_COLLECTION,
    SOURCE_KB_VERIFY,
    iter_training_examples,
)


@pytest.fixture
def store(tmp_path):
    return Store(store_root=str(tmp_path))


def _rec(id, content="some content", domain="general", source="agent_seed", tags=None):
    return {"id": id, "content": content, "domain": domain, "source": source, "tags": tags}


def _mock_query(records, unmapped=None):
    return {
        "records": records,
        "present": [f for f in ["id", "content", "domain", "source", "tags"] if f not in (unmapped or [])],
        "unmapped": unmapped or [],
        "total": len(records),
    }


# ---------------------------------------------------------------------------
# record_verification / iter_verification_log
# ---------------------------------------------------------------------------

def test_record_verification_writes_durable_row(store):
    log_id = kb_verify.record_verification(
        store, record_id="rec1", outcome="pass", check_kind="verify_sources",
        evidence={"total": 3},
    )
    rows = store.all(kb_verify.VERIFICATION_LOG_COLLECTION)
    assert len(rows) == 1
    assert rows[0]["_id"] == log_id
    assert rows[0]["record_id"] == "rec1"
    assert rows[0]["outcome"] == "pass"
    assert rows[0]["check_kind"] == "verify_sources"
    assert rows[0]["evidence"] == {"total": 3}
    assert rows[0]["ts"]


def test_record_verification_rejects_bad_outcome(store):
    with pytest.raises(ValueError):
        kb_verify.record_verification(store, record_id="rec1", outcome="bogus",
                                      check_kind="verify_sources")


def test_repeated_verifications_accumulate_history_not_overwrite(store):
    kb_verify.record_verification(store, record_id="rec1", outcome="pass",
                                  check_kind="verify_sources", ts="2026-01-01T00:00:00+00:00")
    kb_verify.record_verification(store, record_id="rec1", outcome="fail",
                                  check_kind="verify_sources", ts="2026-01-02T00:00:00+00:00")
    kb_verify.record_verification(store, record_id="rec1", outcome="warn",
                                  check_kind="verify_sources", ts="2026-01-03T00:00:00+00:00")

    history = kb_verify.iter_verification_log(store, record_id="rec1")
    assert len(history) == 3
    outcomes = [r["outcome"] for r in history]
    assert outcomes == ["pass", "fail", "warn"]


def test_iter_verification_log_filters_by_record_id(store):
    kb_verify.record_verification(store, record_id="rec1", outcome="pass",
                                  check_kind="verify_sources")
    kb_verify.record_verification(store, record_id="rec2", outcome="fail",
                                  check_kind="check_health")

    all_rows = kb_verify.iter_verification_log(store)
    assert len(all_rows) == 2

    rec1_rows = kb_verify.iter_verification_log(store, record_id="rec1")
    assert len(rec1_rows) == 1
    assert rec1_rows[0]["record_id"] == "rec1"


def test_iter_verification_log_empty_is_empty_list(store):
    assert kb_verify.iter_verification_log(store) == []
    assert kb_verify.iter_verification_log(store, record_id="nope") == []


# ---------------------------------------------------------------------------
# verify_and_record
# ---------------------------------------------------------------------------

@patch("willow_mcp.kb_verify._query_records")
def test_verify_and_record_persists_and_returns_verdict(mock_qr, store):
    mock_qr.return_value = _mock_query([_rec("A1"), _rec("A2")])
    result = kb_verify.verify_and_record(None, store, "test_app",
                                         check_kind="verify_sources")

    assert result["outcome"] == "pass"
    assert result["_verification_logged"] is True

    log_rows = kb_verify.iter_verification_log(store)
    assert len(log_rows) == 1
    assert log_rows[0]["outcome"] == "pass"
    assert log_rows[0]["check_kind"] == "verify_sources"


@patch("willow_mcp.kb_verify._query_records")
def test_verify_and_record_emits_training_example_that_roundtrips(mock_qr, store):
    mock_qr.return_value = _mock_query([
        _rec("A1"), _rec("A2", source=""), _rec("A3", source=""),
    ])
    result = kb_verify.verify_and_record(None, store, "test_app",
                                         check_kind="verify_sources", domain="ops")
    assert result["outcome"] in ("warn", "fail")

    examples = iter_training_examples(store, source=SOURCE_KB_VERIFY)
    assert len(examples) == 1
    ex = examples[0]
    assert ex["source"] == SOURCE_KB_VERIFY
    assert ex["label_kind"] == "verification"
    assert ex["large_label"]["outcome"] == result["outcome"]
    assert ex["input"]["check_kind"] == "verify_sources"
    assert ex["input"]["domain"] == "ops"

    # Round-trips through the store collection directly too.
    rows = store.all(TRAINING_COLLECTION)
    assert len(rows) == 1
    assert rows[0]["id"] == ex["id"]


@patch("willow_mcp.kb_verify._query_records")
def test_verify_and_record_check_health_maps_outcome(mock_qr, store):
    mock_qr.return_value = _mock_query([
        _rec("A1", content="content one"), _rec("A2", content="content two"),
    ])
    result = kb_verify.verify_and_record(None, store, "test_app",
                                         check_kind="check_health")
    assert result["_verification_logged"] is True
    log_rows = kb_verify.iter_verification_log(store)
    assert log_rows[0]["check_kind"] == "check_health"
    assert log_rows[0]["outcome"] == "pass"


@patch("willow_mcp.kb_verify._query_records")
def test_verify_and_record_repeated_runs_accumulate(mock_qr, store):
    mock_qr.return_value = _mock_query([_rec("A1")])
    kb_verify.verify_and_record(None, store, "test_app", check_kind="verify_sources",
                                domain="ops")
    kb_verify.verify_and_record(None, store, "test_app", check_kind="verify_sources",
                                domain="ops")

    history = kb_verify.iter_verification_log(store, record_id="test_app:ops")
    assert len(history) == 2


def test_verify_and_record_error_verdict_skips_logging(store):
    with patch("willow_mcp.kb_verify._query_records") as mock_qr:
        mock_qr.return_value = {"error": "schema_unusable", "detail": "no id column"}
        result = kb_verify.verify_and_record(None, store, "test_app",
                                             check_kind="verify_sources")
    assert "error" in result
    assert result["_verification_logged"] is False
    assert kb_verify.iter_verification_log(store) == []


def test_verify_and_record_bad_check_kind_raises(store):
    with pytest.raises(ValueError):
        kb_verify.verify_and_record(None, store, "test_app", check_kind="bogus")


@patch("willow_mcp.kb_verify.record_verification")
@patch("willow_mcp.kb_verify._query_records")
def test_verify_and_record_store_failure_does_not_raise(mock_qr, mock_record, store):
    mock_qr.return_value = _mock_query([_rec("A1")])
    mock_record.side_effect = RuntimeError("store is down")

    result = kb_verify.verify_and_record(None, store, "test_app",
                                         check_kind="verify_sources")
    # The verdict is still returned even though persistence blew up.
    assert result["outcome"] == "pass"
    assert result["_verification_logged"] is False


# ---------------------------------------------------------------------------
# verify_sources / check_health remain side-effect-free
# ---------------------------------------------------------------------------

@patch("willow_mcp.kb_verify._query_records")
def test_verify_sources_direct_call_writes_nothing(mock_qr, store):
    mock_qr.return_value = _mock_query([_rec("A1"), _rec("A2", source="")])
    kb_verify.verify_sources(None, "test_app")

    assert store.all(kb_verify.VERIFICATION_LOG_COLLECTION) == []
    assert store.all(TRAINING_COLLECTION) == []


@patch("willow_mcp.kb_verify._query_records")
def test_check_health_direct_call_writes_nothing(mock_qr, store):
    mock_qr.return_value = _mock_query([_rec("A1"), _rec("A2", source="")])
    kb_verify.check_health(None, "test_app")

    assert store.all(kb_verify.VERIFICATION_LOG_COLLECTION) == []
    assert store.all(TRAINING_COLLECTION) == []
