"""Tests for the unified training-example schema (training_corpus.py)."""
import pytest

from willow_mcp.db import Store
from willow_mcp.training_corpus import (
    COLLECTION,
    SOURCE_FRICTION,
    SOURCE_KB_VERIFY,
    SOURCE_NEST_CLASSIFY,
    TrainingCorpusError,
    TrainingExample,
    append_training_example,
    iter_training_examples,
    make_id,
)


@pytest.fixture
def store(tmp_path):
    return Store(store_root=str(tmp_path))


# --- construction + validation ----------------------------------------------

def test_minimal_construction_defaults():
    ex = TrainingExample(source=SOURCE_NEST_CLASSIFY, input={"filename": "a.pdf"})
    assert ex.label_kind == "none"
    assert ex.weight == 1.0
    assert ex.schema_version == "training/v1"
    assert ex.small_model_output is None
    assert ex.large_label is None
    assert ex.provenance == {}
    assert ex.id.startswith("tex_")
    assert ex.ts  # non-empty ISO-ish timestamp


def test_rejects_empty_source():
    with pytest.raises(TrainingCorpusError):
        TrainingExample(source="", input={})


def test_rejects_non_dict_input():
    with pytest.raises(TrainingCorpusError):
        TrainingExample(source=SOURCE_NEST_CLASSIFY, input="not a dict")


def test_rejects_bad_label_kind():
    with pytest.raises(TrainingCorpusError):
        TrainingExample(source=SOURCE_NEST_CLASSIFY, input={}, label_kind="bogus")


def test_rejects_non_dict_large_label():
    with pytest.raises(TrainingCorpusError):
        TrainingExample(source=SOURCE_NEST_CLASSIFY, input={}, large_label="verdict")


def test_accepts_unknown_forward_compatible_source():
    # Not in SOURCES, but a valid non-empty str — accepted.
    ex = TrainingExample(source="future_source_v2", input={"q": "x"})
    assert ex.source == "future_source_v2"


# --- make_id stability + dedup -----------------------------------------------

def test_make_id_stable_across_key_order():
    id1 = make_id("nest_classify", {"a": 1, "b": 2}, {"verdict": "legal"})
    id2 = make_id("nest_classify", {"b": 2, "a": 1}, {"verdict": "legal"})
    assert id1 == id2


def test_make_id_differs_on_label():
    id1 = make_id("nest_classify", {"a": 1}, {"verdict": "legal"})
    id2 = make_id("nest_classify", {"a": 1}, {"verdict": "financial"})
    assert id1 != id2


def test_same_logical_example_dedups_to_same_id():
    ex1 = TrainingExample(source=SOURCE_NEST_CLASSIFY, input={"a": 1}, large_label={"v": "x"})
    ex2 = TrainingExample(source=SOURCE_NEST_CLASSIFY, input={"a": 1}, large_label={"v": "x"})
    assert ex1.id == ex2.id
    # Even with different provenance/small_model_output/weight — those don't
    # define the logical example.
    ex3 = TrainingExample(
        source=SOURCE_NEST_CLASSIFY, input={"a": 1}, large_label={"v": "x"},
        provenance={"session": "s1"}, small_model_output={"guess": "y"}, weight=0.5,
    )
    assert ex1.id == ex3.id


# --- to_dict / from_dict round-trip ------------------------------------------

def test_round_trip_dict():
    ex = TrainingExample(
        source=SOURCE_KB_VERIFY,
        input={"claim": "the sky is blue"},
        small_model_output={"confidence": 0.6},
        large_label={"verified": True},
        label_kind="verification",
        weight=1.0,
        provenance={"record_id": "kb-1"},
    )
    d = ex.to_dict()
    ex2 = TrainingExample.from_dict(d)
    assert ex2.id == ex.id
    assert ex2.source == ex.source
    assert ex2.large_label == ex.large_label
    assert ex2.label_kind == "verification"


# --- store round trip via append/iter ----------------------------------------

def test_append_and_iter_round_trip(store):
    ex = TrainingExample(source=SOURCE_NEST_CLASSIFY, input={"filename": "x.pdf"},
                          large_label={"track": "legal"}, label_kind="human")
    rid = append_training_example(store, ex)
    assert rid == ex.id

    rows = iter_training_examples(store)
    assert len(rows) == 1
    assert rows[0]["id"] == ex.id
    assert rows[0]["source"] == SOURCE_NEST_CLASSIFY
    assert rows[0]["large_label"] == {"track": "legal"}


def test_append_idempotent_on_same_id(store):
    ex = TrainingExample(source=SOURCE_NEST_CLASSIFY, input={"a": 1}, large_label={"v": "x"})
    append_training_example(store, ex)
    append_training_example(store, ex)  # re-append, same id
    rows = iter_training_examples(store)
    assert len(rows) == 1


# --- source filtering ---------------------------------------------------------

def test_source_filtering(store):
    ex1 = TrainingExample(source=SOURCE_NEST_CLASSIFY, input={"a": 1})
    ex2 = TrainingExample(source=SOURCE_KB_VERIFY, input={"b": 2})
    append_training_example(store, ex1)
    append_training_example(store, ex2)

    nest_rows = iter_training_examples(store, source=SOURCE_NEST_CLASSIFY)
    assert len(nest_rows) == 1
    assert nest_rows[0]["id"] == ex1.id

    kb_rows = iter_training_examples(store, source=SOURCE_KB_VERIFY)
    assert len(kb_rows) == 1
    assert kb_rows[0]["id"] == ex2.id

    assert iter_training_examples(store, source="nonexistent_source") == []


# --- negative-weight correction example --------------------------------------

def test_negative_weight_correction(store):
    # A human correction that demotes a bad small-model call rather than
    # merely recording a fresh positive example.
    ex = TrainingExample(
        source=SOURCE_NEST_CLASSIFY,
        input={"filename": "invoice_2024.pdf"},
        small_model_output={"track": "journal", "confidence": 0.7},
        large_label={"track": "financial"},
        label_kind="human",
        weight=-1.0,
    )
    assert ex.weight == -1.0
    rid = append_training_example(store, ex)
    row = store.get(COLLECTION, rid)
    assert row["weight"] == -1.0
    assert row["label_kind"] == "human"


# --- escalation-shaped example (nest/selflearn.py tier-3 escalations) --------

def test_escalation_shaped_example_representable(store):
    # Shape mirrors nest/selflearn.py's append_escalations row:
    # {ts, hash, excerpt, margin, candidates, verdict, teacher_model, embed_model}
    escalation_row = {
        "hash": "abc123",
        "excerpt": "Please find enclosed the settlement terms...",
        "margin": 0.04,
        "candidates": ["legal", "correspondence"],
        "teacher_model": "teacher-large",
        "embed_model": "embed-small",
    }
    ex = TrainingExample(
        source=SOURCE_NEST_CLASSIFY,
        provenance={
            "model": escalation_row["embed_model"],
            "teacher_model": escalation_row["teacher_model"],
            "hash": escalation_row["hash"],
        },
        input={
            "excerpt": escalation_row["excerpt"],
            "candidates": escalation_row["candidates"],
            "margin": escalation_row["margin"],
        },
        small_model_output={
            "candidates": escalation_row["candidates"],
            "margin": escalation_row["margin"],
        },
        large_label={"verdict": "legal"},
        label_kind="teacher",
    )
    rid = append_training_example(store, ex)
    row = store.get(COLLECTION, rid)
    assert row["input"]["margin"] == 0.04
    assert row["large_label"]["verdict"] == "legal"
    assert row["provenance"]["teacher_model"] == "teacher-large"

    # An escalation where the teacher never answered — verdict None, still
    # logged (append_escalations logs it rather than dropping it).
    ex_unanswered = TrainingExample(
        source=SOURCE_NEST_CLASSIFY,
        input={"excerpt": "other text", "candidates": ["financial"]},
        large_label=None,
        label_kind="none",
    )
    append_training_example(store, ex_unanswered)
    assert len(iter_training_examples(store, source=SOURCE_NEST_CLASSIFY)) == 2


# --- friction-flag-shaped example ---------------------------------------------

def test_friction_shaped_example(store):
    ex = TrainingExample(
        source=SOURCE_FRICTION,
        input={"low_turns": [0, 1, 2], "message": "mirroring during escalation"},
        large_label={"escalation": 0.8, "mean_friction": 0.1},
        label_kind="verification",
        provenance={"session_id": "sess-1"},
    )
    rid = append_training_example(store, ex)
    assert rid == ex.id
    row = store.get(COLLECTION, rid)
    assert row["source"] == SOURCE_FRICTION


# --- empty-store read ----------------------------------------------------------

def test_empty_store_read_returns_empty_list(store):
    assert iter_training_examples(store) == []
    assert iter_training_examples(store, source=SOURCE_NEST_CLASSIFY) == []
