"""
nest-seed/embed.py — local semantic embeddings via Ollama (nomic-embed-text).

Pure stdlib. The text tier of the classifier: turn a document into a vector so
classification can be done by *meaning* (cosine distance to category centroids)
rather than keyword matching. If Ollama or the model is unavailable, every
function returns None and the caller falls back to the regex/LLM paths.

nomic-embed-text REQUIRES task prefixes — without them embeddings barely
separate (cosine bunches ~0.45 with near-zero gaps). We embed documents with
`search_document: ` and category prototypes / queries with `search_query: `.
This asymmetry roughly doubles the usable separation.
"""
from __future__ import annotations

import json
import math
import os
import urllib.error
import urllib.request

DEFAULT_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_EMBED_MODEL = os.environ.get("NEST_EMBED_MODEL", "nomic-embed-text")

DOC_PREFIX = "search_document: "
QUERY_PREFIX = "search_query: "

# Char cap before embedding; on a 500 (usually transient/memory) we retry smaller.
_CAPS = (4000, 2000, 1000)
_TIMEOUT = float(os.environ.get("NEST_EMBED_TIMEOUT", "60"))

_installed: set[str] | None = None


def installed_models() -> set[str]:
    global _installed
    if _installed is not None:
        return _installed
    try:
        with urllib.request.urlopen(f"{DEFAULT_HOST}/api/tags", timeout=5) as resp:
            tags = json.loads(resp.read().decode("utf-8"))
        _installed = {m.get("name", "") for m in tags.get("models", [])}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        _installed = set()
    return _installed


def available(model: str = DEFAULT_EMBED_MODEL) -> bool:
    models = installed_models()
    if not models:
        return False
    base = model.split(":", 1)[0]
    return model in models or any(m.split(":", 1)[0] == base for m in models)


def _resolve(model: str) -> str | None:
    models = installed_models()
    if model in models:
        return model
    base = model.split(":", 1)[0]
    for m in models:
        if m.split(":", 1)[0] == base:
            return m
    return None


def _post(prompt: str, model: str) -> list[float] | None:
    data = json.dumps({"model": model, "prompt": prompt}).encode("utf-8")
    req = urllib.request.Request(f"{DEFAULT_HOST}/api/embeddings", data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8")).get("embedding")


def _embed(text: str, prefix: str, model: str = DEFAULT_EMBED_MODEL) -> list[float] | None:
    tag = _resolve(model)
    if not tag or not text.strip():
        return None
    for cap in _CAPS:
        try:
            vec = _post(f"{prefix}{text[:cap]}", tag)
            if vec:
                return vec
        except urllib.error.HTTPError:
            continue  # 500 — retry at a smaller cap
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            return None
    return None


def embed_document(text: str, model: str = DEFAULT_EMBED_MODEL) -> list[float] | None:
    """Embed a file's content for classification (search_document prefix)."""
    return _embed(text, DOC_PREFIX, model)


def embed_query(text: str, model: str = DEFAULT_EMBED_MODEL) -> list[float] | None:
    """Embed a category prototype / seed phrase (search_query prefix)."""
    return _embed(text, QUERY_PREFIX, model)


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def centroid(vectors: list[list[float]]) -> list[float] | None:
    vs = [v for v in vectors if v]
    if not vs:
        return None
    dim = len(vs[0])
    return [sum(v[i] for v in vs) / len(vs) for i in range(dim)]
