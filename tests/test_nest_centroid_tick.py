"""nest-centroid-tick: warm taxonomy centroids without a live Ollama."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from willow_mcp.nest import centroid_tick, embed, taxonomy


@pytest.fixture
def nest_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("NEST_CACHE_DIR", str(tmp_path))
    return tmp_path


@pytest.fixture
def stub_embed(monkeypatch):
    monkeypatch.setattr(embed, "available", lambda model="nomic-embed-text": True)

    def _doc(text, model="nomic-embed-text"):
        # Distinct unit-ish vectors from text length so centroid is non-empty.
        n = max(1, len(text) % 7 + 1)
        return [float(n)] * 8

    monkeypatch.setattr(embed, "embed_document", _doc)
    monkeypatch.setattr(embed, "centroid",
                        lambda vecs: [sum(c) / len(c) for c in zip(*[v for v in vecs if v])]
                        if any(vecs) else None)


def test_tick_ok_then_empty(nest_cache, stub_embed):
    r1 = centroid_tick.run_centroid_tick()
    assert r1["status"] == "ok"
    assert r1["categories"] > 0
    assert Path(r1["cache_path"]).exists()

    r2 = centroid_tick.run_centroid_tick()
    assert r2["status"] == "empty"
    assert r2["categories"] == r1["categories"]


def test_tick_unreachable(nest_cache, monkeypatch):
    monkeypatch.setattr(embed, "available", lambda model="nomic-embed-text": False)
    r = centroid_tick.run_centroid_tick()
    assert r["status"] == "unreachable"
    assert "Ollama" in r["reason"]


def test_force_rebuilds(nest_cache, stub_embed):
    assert centroid_tick.run_centroid_tick()["status"] == "ok"
    r = centroid_tick.run_centroid_tick(force=True)
    assert r["status"] == "ok"
    assert r["force"] is True
    data = json.loads(Path(r["cache_path"]).read_text())
    assert set(data) == set(taxonomy.EXEMPLARS)
