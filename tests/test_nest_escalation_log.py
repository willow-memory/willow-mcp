"""Tier-3 escalation log — the distillation corpus for a tier-2.5 student.

Sealed decision c1d6ea35 (2026-09-18): the first local SRM plugs in as tier
2.5 of the Nest cascade and trains on logged (excerpt, margin, top-3, verdict)
escalation pairs. Gap 6445e1ad270c measured that the tuple was computed and
discarded at classify.py's tier-3 call, and that the self-learning loop was
unreachable from nest_scan. These tests pin the fix:

  * every tier-3 call reaches the escalation sink, verdict or not;
  * a confident embedding never escalates, so never logs;
  * the Recorder appends JSONL under NEST_CACHE_DIR;
  * ingest.run reports the log three-state (off / on / unreachable) and logs
    without any --learn flag when the LLM tier is on;
  * nest_scan threads learn / discover / promote to the engine.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from willow_mcp.nest import classify, embed, ingest, llm, ocr, selflearn

# Two orthogonal unit centroids. A doc vector of [1, 0] is confident for "a";
# [1, 1] sits halfway and escalates (margin over the mean is 0 < 0.07).
CENTROIDS = {"a": [1.0, 0.0], "b": [0.0, 1.0]}
CONFIDENT_VEC = [1.0, 0.0]
UNCERTAIN_VEC = [1.0, 1.0]
VERDICT = {"fragment_type": "document", "category": "legal",
           "confidence": "likely", "summary": "a filing"}


@pytest.fixture
def nest_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("NEST_CACHE_DIR", str(tmp_path))
    return tmp_path


def _stub_embed(monkeypatch, vec):
    monkeypatch.setattr(embed, "embed_document", lambda text, model=None: list(vec))


def _tiers(text, sink, *, use_llm=True):
    return classify._classify_text_tiers(
        text, "doc.txt", False, use_llm, True, CENTROIDS,
        text_model="teacher:3b", embed_model="embedder",
        escalation_sink=sink,
    )


# ── the sink fires once per tier-3 call ──────────────────────────────────────

def test_escalation_reaches_sink_with_the_full_tuple(monkeypatch):
    _stub_embed(monkeypatch, UNCERTAIN_VEC)
    seen = []
    monkeypatch.setattr(llm, "classify_text",
                        lambda text, filename="", model=None, candidates=None: dict(VERDICT))

    frag = _tiers("some uncertain text", seen.append)

    assert frag is not None and frag.label == "legal"
    assert len(seen) == 1
    row = seen[0]
    assert row["excerpt"] == "some uncertain text"
    assert sorted(row["candidates"]) == ["a", "b"]   # the same top-3 the LLM saw (tied cosines)
    assert row["embed_best"] in CENTROIDS
    assert row["margin"] < classify.MARGIN_CONFIDENT
    assert row["verdict"] == VERDICT
    assert row["teacher_model"] == "teacher:3b"
    assert row["embed_model"] == "embedder"


def test_unanswered_teacher_is_logged_not_dropped(monkeypatch):
    """'Asked, no answer' must be distinguishable from 'never asked'."""
    _stub_embed(monkeypatch, UNCERTAIN_VEC)
    seen = []
    monkeypatch.setattr(llm, "classify_text",
                        lambda text, filename="", model=None, candidates=None: None)

    frag = _tiers("text the teacher will not answer", seen.append)

    assert len(seen) == 1
    assert seen[0]["verdict"] is None
    # And the cascade still degrades the way it always did.
    assert frag is not None
    assert frag.confidence in ("uncertain", "speculative")


def test_confident_embedding_never_escalates(monkeypatch):
    _stub_embed(monkeypatch, CONFIDENT_VEC)
    seen = []

    def _boom(*a, **k):
        raise AssertionError("tier 3 must not run on a confident margin")
    monkeypatch.setattr(llm, "classify_text", _boom)

    frag = _tiers("clearly category a", seen.append)
    assert frag is not None and frag.label == "a"
    assert seen == []


def test_llm_off_never_calls_sink(monkeypatch):
    _stub_embed(monkeypatch, UNCERTAIN_VEC)
    seen = []
    _tiers("uncertain but llm off", seen.append, use_llm=False)
    assert seen == []


def test_sink_absent_is_a_no_op(monkeypatch):
    """The default path (no sink) is byte-for-byte the old behaviour."""
    _stub_embed(monkeypatch, UNCERTAIN_VEC)
    monkeypatch.setattr(llm, "classify_text",
                        lambda text, filename="", model=None, candidates=None: dict(VERDICT))
    frag = _tiers("no sink given", None)
    assert frag is not None and frag.label == "legal"


# ── the Recorder writes JSONL ────────────────────────────────────────────────

def test_recorder_appends_jsonl_under_cache_dir(nest_cache):
    rec = selflearn.Recorder()
    sink = rec.escalation_sink_for(key="abc123")
    sink({"excerpt": "x", "margin": 0.01, "candidates": ["a", "b"],
          "verdict": dict(VERDICT), "teacher_model": "t", "embed_model": "e"})
    sink({"excerpt": "y", "margin": 0.02, "candidates": ["b", "a"],
          "verdict": None, "teacher_model": "t", "embed_model": "e"})

    out = rec.flush_escalations("teacher:3b")

    assert out == {"logged": 2, "path": str(nest_cache / "escalations_teacher_3b.jsonl")}
    lines = Path(out["path"]).read_text().splitlines()
    assert len(lines) == 2
    rows = [json.loads(line) for line in lines]
    assert all(r["hash"] == "abc123" for r in rows)
    assert all("ts" in r for r in rows)
    assert rows[0]["verdict"]["category"] == "legal"
    assert rows[1]["verdict"] is None

    # Append-only: a second flush adds, never rewrites.
    rec2 = selflearn.Recorder()
    rec2.escalation_sink_for(key="def456")({"excerpt": "z", "margin": 0.0,
                                            "candidates": [], "verdict": None,
                                            "teacher_model": "t", "embed_model": "e"})
    rec2.flush_escalations("teacher:3b")
    assert len(Path(out["path"]).read_text().splitlines()) == 3


def test_flush_with_nothing_logs_nothing(nest_cache):
    out = selflearn.Recorder().flush_escalations("teacher:3b")
    assert out["logged"] == 0
    assert not Path(out["path"]).exists()


def test_unwritable_log_is_reported_not_raised(nest_cache, monkeypatch):
    # A regular file where the cache dir should be: mkdir(parents=True) raises
    # FileExistsError, an OSError, without touching builtins.
    (nest_cache / "blocker").write_text("")
    monkeypatch.setattr(selflearn, "_escalation_path",
                        lambda model: nest_cache / "blocker" / "escalations.jsonl")
    rec = selflearn.Recorder()
    rec.escalation_sink_for(key="k")({"excerpt": "x", "margin": 0.0, "candidates": [],
                                      "verdict": None, "teacher_model": "t",
                                      "embed_model": "e"})
    out = rec.flush_escalations("teacher:3b")
    assert out["logged"] == 0
    assert "error" in out and out["error"]


# ── ingest.run reports three-state and logs without --learn ─────────────────

@pytest.fixture
def drop_folder(tmp_path):
    folder = tmp_path / "drop"
    folder.mkdir()
    (folder / "one.txt").write_text("first uncertain document")
    (folder / "two.txt").write_text("second uncertain document")
    return folder


@pytest.fixture
def stub_engine(monkeypatch):
    """No OCR, no Ollama: text files read straight through, every doc sits
    exactly between the two centroids so every doc escalates."""
    monkeypatch.setattr(ocr, "supported_suffixes", lambda: {".txt"})
    monkeypatch.setattr(ocr, "extract", lambda p: (Path(p).read_text(), "text"))
    monkeypatch.setattr(selflearn, "build_adaptive_centroids", lambda model: dict(CENTROIDS))
    _stub_embed(monkeypatch, UNCERTAIN_VEC)


def test_ingest_logs_escalations_with_llm_on_and_no_learn_flag(
        nest_cache, drop_folder, stub_engine, monkeypatch):
    monkeypatch.setattr(llm, "classify_text",
                        lambda text, filename="", model=None, candidates=None: dict(VERDICT))

    counts = ingest.run(drop_folder, nest_cache / "nest.db", owner="t",
                        dry_run=True, use_llm=True, text_model="teacher:3b")

    esc = counts["escalations"]
    assert esc["state"] == "on"
    assert esc["escalated"] == 2
    assert esc["unanswered"] == 0
    assert esc["logged"] == 2
    assert Path(esc["path"]).name == "escalations_teacher_3b.jsonl"
    assert len(Path(esc["path"]).read_text().splitlines()) == 2
    # No --learn was passed: the learned store must not have been touched.
    assert "learned" not in counts


def test_ingest_counts_unanswered_teacher(nest_cache, drop_folder, stub_engine, monkeypatch):
    monkeypatch.setattr(llm, "classify_text",
                        lambda text, filename="", model=None, candidates=None: None)
    counts = ingest.run(drop_folder, nest_cache / "nest.db", owner="t",
                        dry_run=True, use_llm=True, text_model="teacher:3b")
    esc = counts["escalations"]
    assert esc["state"] == "on"
    assert esc["escalated"] == 2 and esc["unanswered"] == 2 and esc["logged"] == 2


def test_ingest_reports_off_when_llm_tier_not_requested(
        nest_cache, drop_folder, stub_engine):
    counts = ingest.run(drop_folder, nest_cache / "nest.db", owner="t",
                        dry_run=True, use_llm=False)
    assert counts["escalations"] == {"state": "off", "escalated": 0, "logged": 0}
    assert not list(nest_cache.glob("escalations_*.jsonl"))


def test_ingest_reports_unreachable_when_log_cannot_be_written(
        nest_cache, drop_folder, stub_engine, monkeypatch):
    monkeypatch.setattr(llm, "classify_text",
                        lambda text, filename="", model=None, candidates=None: dict(VERDICT))
    monkeypatch.setattr(selflearn, "append_escalations",
                        lambda model, rows: {"logged": 0, "path": "/nope",
                                             "error": "OSError: denied"})
    counts = ingest.run(drop_folder, nest_cache / "nest.db", owner="t",
                        dry_run=True, use_llm=True)
    esc = counts["escalations"]
    assert esc["state"] == "unreachable"
    assert esc["escalated"] == 2 and esc["logged"] == 0
    assert esc["error"] == "OSError: denied"


# ── durable per row, bounded per call (gap 0c062b3c83c3) ────────────────────

def test_rows_are_on_disk_before_the_run_ends(nest_cache, drop_folder, stub_engine, monkeypatch):
    """A run killed after the first escalation must have logged it. Simulate
    the kill: the teacher answers once, then the second call raises out of
    ingest.run entirely."""
    calls = {"n": 0}

    def _teacher(text, filename="", model=None, candidates=None):
        calls["n"] += 1
        if calls["n"] == 2:
            raise KeyboardInterrupt("client timeout / broker restart")
        return dict(VERDICT)
    monkeypatch.setattr(llm, "classify_text", _teacher)

    with pytest.raises(KeyboardInterrupt):
        ingest.run(drop_folder, nest_cache / "nest.db", owner="t",
                   dry_run=True, use_llm=True, text_model="teacher:3b")

    log = nest_cache / "escalations_teacher_3b.jsonl"
    assert log.exists()
    rows = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(rows) == 1 and rows[0]["verdict"]["category"] == "legal"


def test_recorder_with_a_model_appends_at_sink_time(nest_cache):
    rec = selflearn.Recorder(escalation_model="teacher:3b")
    sink = rec.escalation_sink_for(key="k1")
    sink({"excerpt": "x", "margin": 0.0, "candidates": [], "verdict": None,
          "teacher_model": "t", "embed_model": "e"})
    log = nest_cache / "escalations_teacher_3b.jsonl"
    assert len(log.read_text().splitlines()) == 1          # before any flush
    assert rec.escalations_logged == 1
    out = rec.flush_escalations("teacher:3b")
    assert out == {"logged": 1, "path": str(log)}
    assert len(log.read_text().splitlines()) == 1          # flush did not re-append


def test_recorder_with_a_model_reports_a_write_error(nest_cache, monkeypatch):
    (nest_cache / "blocker").write_text("")
    monkeypatch.setattr(selflearn, "_escalation_path",
                        lambda model: nest_cache / "blocker" / "escalations.jsonl")
    rec = selflearn.Recorder(escalation_model="teacher:3b")
    rec.escalation_sink_for(key="k")({"excerpt": "x", "margin": 0.0, "candidates": [],
                                      "verdict": None, "teacher_model": "t",
                                      "embed_model": "e"})
    out = rec.flush_escalations("teacher:3b")
    assert out["logged"] == 0 and out["errors"] == 1 and out["error"]


def test_window_bounds_one_call_and_names_the_next(nest_cache, drop_folder, stub_engine, monkeypatch):
    monkeypatch.setattr(llm, "classify_text",
                        lambda text, filename="", model=None, candidates=None: dict(VERDICT))
    for i in range(3):
        (drop_folder / f"more-{i}.txt").write_text(f"more uncertain document {i}")
    # 5 files total: one.txt, two.txt, more-0..2 (sorted: more-0, more-1, more-2, one, two)

    first = ingest.run(drop_folder, nest_cache / "nest.db", owner="t", dry_run=True,
                       use_llm=True, text_model="teacher:3b", max_files=2)
    assert first["files"] == 2
    assert first["window"] == {"total": 5, "skip": 0, "max_files": 2, "seen": 2, "next_skip": 2}
    assert first["escalations"]["escalated"] == 2

    second = ingest.run(drop_folder, nest_cache / "nest.db", owner="t", dry_run=True,
                        use_llm=True, text_model="teacher:3b", max_files=2, skip=2)
    assert second["window"]["next_skip"] == 4

    last = ingest.run(drop_folder, nest_cache / "nest.db", owner="t", dry_run=True,
                      use_llm=True, text_model="teacher:3b", max_files=2, skip=4)
    assert last["files"] == 1
    assert last["window"]["next_skip"] is None

    # The three ticks together logged every escalation once.
    log = nest_cache / "escalations_teacher_3b.jsonl"
    assert len(log.read_text().splitlines()) == 5


def test_no_window_walks_everything(nest_cache, drop_folder, stub_engine):
    counts = ingest.run(drop_folder, nest_cache / "nest.db", owner="t", dry_run=True)
    assert counts["window"] == {"total": 2, "skip": 0, "max_files": 0, "seen": 2, "next_skip": None}


def test_skip_past_the_end_is_an_empty_window(nest_cache, drop_folder, stub_engine):
    counts = ingest.run(drop_folder, nest_cache / "nest.db", owner="t", dry_run=True, skip=99)
    assert counts["files"] == 0
    assert counts["window"]["seen"] == 0 and counts["window"]["next_skip"] is None


# ── nest_scan threads the loop flags to the engine ──────────────────────────

@pytest.fixture
def scan_seam(home, monkeypatch):
    """The engine replaced by a recorder of its kwargs; loopback, so no egress
    question to answer. Yields the dict the engine was called with."""
    from willow_mcp import model_egress

    (home / "drop").mkdir()
    seen = {}
    monkeypatch.setattr(ingest, "run", lambda **kw: seen.update(kw) or {"files": 0})
    monkeypatch.setattr(model_egress, "denial", lambda tool: None)
    return seen


def _scan(**kw):
    from willow_mcp import server
    fn = getattr(server.nest_scan, "__wrapped__", server.nest_scan)
    return fn(**kw)


def test_nest_scan_threads_learn_discover_promote(home, scan_seam):
    out = _scan(app_id="willow", folder=str(home / "drop"), dry_run=True,
                use_llm=True, learn=True, discover=4, promote=True,
                max_files=50, skip=100)

    assert out["status"] == "ok"
    assert scan_seam["use_llm"] is True
    assert scan_seam["learn"] is True
    assert scan_seam["discover"] == 4
    assert scan_seam["promote"] is True
    assert scan_seam["max_files"] == 50 and scan_seam["skip"] == 100


def test_nest_scan_defaults_leave_the_loop_off(home, scan_seam):
    _scan(app_id="willow", folder=str(home / "drop"))

    assert scan_seam["learn"] is False
    assert scan_seam["discover"] == 0
    assert scan_seam["promote"] is False
