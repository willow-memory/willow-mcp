"""Tests for GAP #2a: the human negative-correction path for the
embedding/tier-3 text classifier.

`nest/selflearn.py`'s learning loop was additive-only: merge_learned filters
and appends confident observations, build_adaptive_centroids folds them in by
incremental mean — there was no way for a human to say "that classification
was wrong" and have it DEMOTE the wrong category. `selflearn.apply_correction`
adds that; `nest/correct.py` wraps it with embedding resolution + a
training_corpus example; `server.nest_correct_classification` is the MCP tool.

Covers: the correction endpoint records a correction; the wrong category is
measurably demoted at decision time; numerical stability under repeated
corrections (never NaN/inf, denominators stay positive); uncorrected additive
learning is unchanged; invalid corrections are rejected without partial
writes; the emitted training_corpus row is label_kind=human, negative weight,
and round-trips.
"""
from __future__ import annotations

import math

import pytest

from willow_mcp.db import Store
from willow_mcp.nest import correct as nest_correct
from willow_mcp.nest import selflearn
from willow_mcp.nest import taxonomy as tax
from willow_mcp.training_corpus import (
    COLLECTION as TRAINING_COLLECTION,
    SOURCE_NEST_CLASSIFY,
    iter_training_examples,
)

MODEL = "test-embed-model"


@pytest.fixture
def store(tmp_path):
    return Store(store_root=str(tmp_path / "soil"))


@pytest.fixture
def nest_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("NEST_CACHE_DIR", str(tmp_path / "cache"))
    return tmp_path / "cache"


@pytest.fixture
def two_categories(monkeypatch, nest_cache):
    """Two orthogonal unit-vector exemplar categories, one exemplar each, so
    the adaptive-centroid mean is easy to hand-verify."""
    monkeypatch.setattr(tax, "EXEMPLARS", {"a": ["exemplar a"], "b": ["exemplar b"]})
    monkeypatch.setattr(tax, "build_centroids",
                        lambda model=None, use_cache=True: {"a": [1.0, 0.0], "b": [0.0, 1.0]})
    return {"a": [1.0, 0.0], "b": [0.0, 1.0]}


def _cos(u, v):
    dot = sum(x * y for x, y in zip(u, v))
    nu = math.sqrt(sum(x * x for x in u))
    nv = math.sqrt(sum(x * x for x in v))
    return dot / (nu * nv) if nu and nv else 0.0


def _all_finite(vec) -> bool:
    return all(math.isfinite(x) for x in vec)


# ── mechanism: apply_correction demotes / promotes ──────────────────────────

def test_apply_correction_retracts_the_offending_vector(two_categories, nest_cache):
    misclassified_vec = [0.9, 0.1]
    selflearn.merge_learned(
        MODEL, [{"category": "a", "vec": misclassified_vec, "margin": 0.5, "hash": "h1"}])

    before = selflearn.build_adaptive_centroids(MODEL)
    # folded with the learned member, "a"'s centroid tilts toward it.
    assert _cos(before["a"], misclassified_vec) > _cos([1.0, 0.0], misclassified_vec)

    result = selflearn.apply_correction(
        MODEL, wrong_category="a", vec=misclassified_vec, record_hash="h1")
    assert result["status"] == "ok"
    assert result["retracted"] == 1

    after = selflearn.build_adaptive_centroids(MODEL, use_cache=False)
    # retracted -> "a" reverts to the bare exemplar centroid, further from the
    # misclassified vector than it was before the correction (measurable demotion).
    assert after["a"] == pytest.approx([1.0, 0.0])
    assert _cos(after["a"], misclassified_vec) < _cos(before["a"], misclassified_vec)


def test_wrong_category_no_longer_confidently_wins_after_correction(two_categories, nest_cache):
    """A doc that WAS classified as 'a' is no longer confidently 'a' once its
    exact learned observation is corrected away."""
    doc_vec = [0.9, 0.1]
    selflearn.merge_learned(
        MODEL, [{"category": "a", "vec": doc_vec, "margin": 0.5, "hash": "h1"}])

    before = selflearn.build_adaptive_centroids(MODEL)
    ranked_before = tax.rank(doc_vec, before)
    margin_before = tax.margin_stats(ranked_before)["margin"]

    selflearn.apply_correction(MODEL, wrong_category="a", vec=doc_vec, record_hash="h1")

    after = selflearn.build_adaptive_centroids(MODEL, use_cache=False)
    ranked_after = tax.rank(doc_vec, after)
    margin_after = tax.margin_stats(ranked_after)["margin"]

    # The correction can only ever move "a" away from doc_vec (or leave it
    # unchanged when nothing was retracted) — here it retracted the exact
    # observation, so a's margin over the pack strictly shrinks.
    assert margin_after < margin_before


def test_correction_promotes_the_correct_category(two_categories, nest_cache):
    doc_vec = [0.9, 0.1]
    selflearn.merge_learned(
        MODEL, [{"category": "a", "vec": doc_vec, "margin": 0.5, "hash": "h1"}])

    result = selflearn.apply_correction(
        MODEL, wrong_category="a", vec=doc_vec, correct_category="b", record_hash="h1")
    assert result["retracted"] == 1
    assert result["promoted"] == 1

    after = selflearn.build_adaptive_centroids(MODEL, use_cache=False)
    # "b"'s centroid should now tilt toward doc_vec, away from the bare [0,1] exemplar.
    assert _cos(after["b"], doc_vec) > _cos([0.0, 1.0], doc_vec)
    # human correction is ground truth: it bypassed LEARN_MIN_MARGIN entirely.
    learned = selflearn.load_learned(MODEL)
    assert any(e["hash"] == "h1" for e in learned["b"])


def test_correction_without_hash_matches_by_near_identical_vector(two_categories, nest_cache):
    vec = [0.9, 0.1]
    selflearn.merge_learned(MODEL, [{"category": "a", "vec": vec, "margin": 0.5, "hash": "h1"}])

    # No record_hash given: retraction falls back to a near-identity cosine match.
    result = selflearn.apply_correction(MODEL, wrong_category="a", vec=list(vec))
    assert result["retracted"] == 1
    assert selflearn.load_learned(MODEL).get("a", []) == []


def test_correction_does_not_retract_an_unrelated_vector(two_categories, nest_cache):
    unrelated = [0.95, 0.31]  # a different, merely nearby-ish, observation
    selflearn.merge_learned(MODEL, [{"category": "a", "vec": unrelated, "margin": 0.5, "hash": "hX"}])

    result = selflearn.apply_correction(MODEL, wrong_category="a", vec=[0.9, 0.1])
    assert result["retracted"] == 0
    assert len(selflearn.load_learned(MODEL)["a"]) == 1


# ── numerical stability ──────────────────────────────────────────────────────

def test_repeated_corrections_never_produce_nan_inf_or_blown_up_centroids(two_categories, nest_cache):
    vec = [0.9, 0.1]
    selflearn.merge_learned(MODEL, [{"category": "a", "vec": vec, "margin": 0.5, "hash": "h1"}])

    for i in range(60):
        # Alternate retract-only and retract+promote, well past LEARN_MAX_PER_CAT
        # (50) so the promote path also exercises the capped-bucket branch.
        correct = "b" if i % 2 == 0 else None
        selflearn.apply_correction(
            MODEL, wrong_category="a", vec=vec, correct_category=correct,
            record_hash=f"h-{i}")
        centroids = selflearn.build_adaptive_centroids(MODEL, use_cache=False)
        for cat, c in centroids.items():
            assert _all_finite(c), f"non-finite centroid for {cat} at iteration {i}: {c}"
            norm = math.sqrt(sum(x * x for x in c))
            assert 0.0 <= norm <= 10.0, f"centroid norm exploded for {cat}: {norm}"

    # The denominator build_adaptive_centroids divides by (n_exemplars +
    # n_learned) never drops below n_exemplars (>=1) and never goes negative —
    # assert directly on the mechanism rather than only its output.
    learned = selflearn.load_learned(MODEL)
    for cat, members in learned.items():
        n_ex = len(tax.EXEMPLARS.get(cat, [])) or 1
        denom = n_ex + len(members)
        assert denom > 0


def test_correction_rejects_nan_inf_and_zero_vectors(two_categories, nest_cache):
    for bad_vec in ([], [float("nan"), 0.1], [float("inf"), 0.0], [0.0, 0.0], ["x", "y"]):
        with pytest.raises(selflearn.CorrectionError):
            selflearn.apply_correction(MODEL, wrong_category="a", vec=bad_vec)
    # Nothing was written by any of the rejected attempts.
    assert selflearn.load_learned(MODEL) == {}


# ── fail-safe: invalid corrections are rejected, not silently applied ───────

def test_unknown_wrong_category_is_rejected(two_categories, nest_cache):
    with pytest.raises(selflearn.CorrectionError):
        selflearn.apply_correction(MODEL, wrong_category="not-a-real-category", vec=[1.0, 0.0])
    assert selflearn.load_learned(MODEL) == {}


def test_unknown_correct_category_is_rejected(two_categories, nest_cache):
    with pytest.raises(selflearn.CorrectionError):
        selflearn.apply_correction(
            MODEL, wrong_category="a", vec=[1.0, 0.0], correct_category="also-not-real")
    assert selflearn.load_learned(MODEL) == {}


def test_correct_equal_to_wrong_is_rejected(two_categories, nest_cache):
    with pytest.raises(selflearn.CorrectionError):
        selflearn.apply_correction(
            MODEL, wrong_category="a", vec=[1.0, 0.0], correct_category="a")


# ── additive learning for uncorrected data is unchanged ─────────────────────

def test_uncorrected_additive_learning_is_unaffected_by_corrections(two_categories, nest_cache):
    # A correction happens on category "a" ...
    selflearn.merge_learned(MODEL, [{"category": "a", "vec": [0.9, 0.1], "margin": 0.5, "hash": "h1"}])
    selflearn.apply_correction(MODEL, wrong_category="a", vec=[0.9, 0.1], record_hash="h1")

    # ... ordinary additive learning for "b" behaves exactly as it always has:
    # below-margin observations are dropped, confident ones are added and
    # deduped/capped the normal way.
    summary = selflearn.merge_learned(MODEL, [
        {"category": "b", "vec": [0.1, 0.9], "margin": 0.02, "hash": "low"},   # below LEARN_MIN_MARGIN
        {"category": "b", "vec": [0.05, 0.95], "margin": 0.5, "hash": "keep"},
    ])
    assert summary["added"] == 1
    learned_b = selflearn.load_learned(MODEL)["b"]
    assert [e["hash"] for e in learned_b] == ["keep"]


# ── nest/correct.py: the persistence wrapper + training_corpus emission ────

def test_record_correction_with_explicit_vec_demotes_and_logs(store, two_categories, nest_cache):
    vec = [0.9, 0.1]
    selflearn.merge_learned(MODEL, [{"category": "a", "vec": vec, "margin": 0.5, "hash": "h1"}])

    result = nest_correct.record_correction(
        store, MODEL, wrong_category="a", vec=vec, correct_category="b",
        record_hash="h1", app_id="tester")

    assert result["status"] == "ok"
    assert result["retracted"] == 1
    assert result["promoted"] == 1
    assert result["training_example_id"]

    rows = iter_training_examples(store, source=SOURCE_NEST_CLASSIFY)
    row = next(r for r in rows if r["id"] == result["training_example_id"])
    assert row["label_kind"] == "human"
    assert row["weight"] < 0
    assert row["small_model_output"] == {"category": "a"}
    assert row["large_label"] == {"category": "b"}


def test_record_correction_embeds_text_when_no_vec_given(store, two_categories, nest_cache, monkeypatch):
    from willow_mcp.nest import embed as _embed

    vec = [0.9, 0.1]
    monkeypatch.setattr(_embed, "embed_document", lambda text, model=None: list(vec))
    selflearn.merge_learned(MODEL, [{"category": "a", "vec": vec, "margin": 0.5, "hash": "h1"}])

    result = nest_correct.record_correction(
        store, MODEL, wrong_category="a", text="some misclassified document",
        record_hash="h1")
    assert result["status"] == "ok"
    assert result["retracted"] == 1


def test_record_correction_without_vec_or_text_is_a_clear_error(store, two_categories, nest_cache):
    result = nest_correct.record_correction(store, MODEL, wrong_category="a")
    assert result["status"] == "error"
    assert "error" in result
    assert iter_training_examples(store, source=SOURCE_NEST_CLASSIFY) == []


def test_record_correction_embedding_unavailable_is_a_clear_error(store, two_categories, nest_cache, monkeypatch):
    from willow_mcp.nest import embed as _embed
    monkeypatch.setattr(_embed, "embed_document", lambda text, model=None: None)

    result = nest_correct.record_correction(
        store, MODEL, wrong_category="a", text="some text")
    assert result["status"] == "error"


def test_record_correction_invalid_category_rejected_without_partial_write(store, two_categories, nest_cache):
    result = nest_correct.record_correction(
        store, MODEL, wrong_category="nonexistent", vec=[1.0, 0.0])
    assert result["status"] == "error"
    assert selflearn.load_learned(MODEL) == {}
    assert iter_training_examples(store, source=SOURCE_NEST_CLASSIFY) == []


def test_training_example_round_trips(store, two_categories, nest_cache):
    vec = [0.9, 0.1]
    selflearn.merge_learned(MODEL, [{"category": "a", "vec": vec, "margin": 0.5, "hash": "h1"}])
    result = nest_correct.record_correction(
        store, MODEL, wrong_category="a", vec=vec, text="misfiled doc",
        correct_category="b", record_hash="h1")

    rows = store.all(TRAINING_COLLECTION)
    row = next(r for r in rows if r["id"] == result["training_example_id"])
    assert row["source"] == SOURCE_NEST_CLASSIFY
    assert row["label_kind"] == "human"
    assert row["weight"] == nest_correct.CORRECTION_WEIGHT
    assert row["input"]["hash"] == "h1"
    assert row["large_label"]["category"] == "b"


# ── MCP tool wiring ──────────────────────────────────────────────────────────

def _tool(**kw):
    from willow_mcp import server
    fn = getattr(server.nest_correct_classification, "__wrapped__", server.nest_correct_classification)
    return fn(**kw)


@pytest.fixture
def default_model_two_categories(monkeypatch, nest_cache):
    """Same fixture as `two_categories`, but keyed under embed.DEFAULT_EMBED_MODEL
    — the model the tool falls back to when `embed_model` isn't passed."""
    from willow_mcp.nest import embed as _embed
    monkeypatch.setattr(tax, "EXEMPLARS", {"a": ["exemplar a"], "b": ["exemplar b"]})
    monkeypatch.setattr(tax, "build_centroids",
                        lambda model=None, use_cache=True: {"a": [1.0, 0.0], "b": [0.0, 1.0]})
    return _embed.DEFAULT_EMBED_MODEL


def test_nest_correct_classification_tool_end_to_end(
        monkeypatch, default_model_two_categories, nest_cache, tmp_path):
    """The MCP tool threads app_id + text through to record_correction, checks
    egress before embedding, and actually demotes the wrong category."""
    from willow_mcp import model_egress
    from willow_mcp import server
    from willow_mcp.nest import embed as _embed

    monkeypatch.setattr(server, "_store", Store(store_root=str(tmp_path / "soil")))
    monkeypatch.setattr(model_egress, "denial", lambda tool: None)

    vec = [0.9, 0.1]
    monkeypatch.setattr(_embed, "embed_document", lambda text, model=None: list(vec))
    model = default_model_two_categories
    selflearn.merge_learned(model, [{"category": "a", "vec": vec, "margin": 0.5, "hash": "h1"}])

    out = _tool(app_id="tester", wrong_category="a", text="a misfiled document",
               correct_category="b", record_hash="h1")

    assert out["status"] == "ok"
    assert out["retracted"] == 1
    assert out["promoted"] == 1
    assert out["training_example_id"]

    rows = iter_training_examples(server._store, source=SOURCE_NEST_CLASSIFY)
    assert any(r["id"] == out["training_example_id"] and r["label_kind"] == "human"
              and r["weight"] < 0 for r in rows)


def test_nest_correct_classification_tool_checks_egress_before_embedding(
        monkeypatch, default_model_two_categories, nest_cache, tmp_path):
    from willow_mcp import model_egress
    from willow_mcp import server

    monkeypatch.setattr(server, "_store", Store(store_root=str(tmp_path / "soil")))

    def _deny(tool):
        return {"error": f"denied: {tool}"}
    monkeypatch.setattr(model_egress, "denial", _deny)

    out = _tool(app_id="tester", wrong_category="a", text="some document")
    assert "error" in out


def test_nest_correct_classification_tool_rejects_unknown_category(
        monkeypatch, default_model_two_categories, nest_cache, tmp_path):
    from willow_mcp import model_egress
    from willow_mcp import server
    from willow_mcp.nest import embed as _embed

    monkeypatch.setattr(server, "_store", Store(store_root=str(tmp_path / "soil")))
    monkeypatch.setattr(model_egress, "denial", lambda tool: None)
    monkeypatch.setattr(_embed, "embed_document", lambda text, model=None: [1.0, 0.0])

    out = _tool(app_id="tester", wrong_category="not-a-category", text="text")
    assert out["status"] == "error"
