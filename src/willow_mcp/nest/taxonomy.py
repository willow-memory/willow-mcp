"""
nest-seed/taxonomy.py — semantic category prototypes for the embedding tier.

Each category is defined by a few short *exemplar documents* — text that looks
like the real thing, not a description of it. We embed the exemplars (with the
document prefix, same as the files being classified) and average them into a
centroid. Document-to-document comparison separates far better than the earlier
description-to-document approach, where every file sat ~0.55-0.74 from every
category with near-zero margin.

A document is classified by cosine similarity to the nearest centroid. Because
absolute cosine is not discriminative (nomic rates everything moderately
similar), confidence is judged by the **margin over the mean** similarity
across all categories — how much the winner stands out from the field — not by
the absolute score or a fixed floor.

Centroids are deterministic for a given (model, exemplars) pair, so they're
cached to disk — embedding the exemplars once instead of every run. Over time
these can be augmented with the user's own confirmed files (self-learning).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

try:  # works both as a package (apps.nest_seed) and as a plain script dir
    from . import embed as _embed
except ImportError:
    import embed as _embed

# Exemplar documents per category — short but realistic, document-shaped text.
# Keep them distinct: overlap here is what collapses the margin at runtime.
EXEMPLARS: dict[str, list[str]] = {
    "legal": [
        "IN THE CIRCUIT COURT. This Settlement Agreement is entered into between "
        "Petitioner and Respondent to resolve all claims. Each party releases the "
        "other from liability. Signed and notarized this day before a notary public.",
        "Re: Custody modification. Counsel for the parties has reviewed the parenting "
        "plan and proposed schedule. Please find enclosed the motion and supporting "
        "affidavit filed with the court regarding the workers compensation claim.",
    ],
    "journal": [
        "Today I refactored the parser and felt good about the progress. Tomorrow I "
        "want to tackle the retry logic. Reflecting on a productive week — slow start "
        "but momentum is building. Note to self: rest more.",
        "Session notes: spent the morning chasing a bug, found it after lunch. Mood "
        "steady. What I learned today and what I want to remember going forward.",
    ],
    "knowledge": [
        "Overview. This document explains how the system works and why each component "
        "exists. We first describe the architecture, then walk through the data flow, "
        "and finally analyze the trade-offs involved in the design.",
        "A brief explanation of the concept: the key idea is that structure determines "
        "behavior. The following sections cover background, mechanism, and implications.",
    ],
    "narrative": [
        "She stepped off the train into the cold morning, not knowing the city would "
        "change her. The streets were empty and the sky was the color of old paper. "
        "He had promised to wait, and she wondered if he still would.",
        "Once, in a village at the edge of the forest, there lived a clockmaker who "
        "could hear time slipping. This is the story of the night the clocks stopped.",
    ],
    "specs": [
        "Specification. Status: Approved. This document defines the requirements and "
        "design for the feature. Goals, non-goals, the proposed architecture, the data "
        "model, and the rollout plan are described in the sections below.",
        "Design doc: the component must accept input X, validate it, and emit Y. "
        "Requirements: latency under 200ms, idempotent writes, graceful degradation.",
    ],
    "code": [
        "import os\nimport sys\nfrom pathlib import Path\n\nclass Handler:\n    def "
        "process(self, request):\n        return self.dispatch(request)\n\ndef main():\n"
        "    for item in queue:\n        handle(item)\n\nif __name__ == '__main__':\n    main()",
        "def fib(n):\n    a, b = 0, 1\n    for _ in range(n):\n        a, b = b, a + b\n"
        "    return a\n\n# helper: walk the tree and collect results\nresults = "
        "[x for x in items if x.valid]",
    ],
    "correspondence": [
        "Hi Sarah,\n\nThanks for getting back to me. I wanted to follow up on our "
        "conversation from last week. Let me know if Tuesday works for a call.\n\n"
        "Best,\nAlex",
        "Dear Mr. Johnson,\n\nI am writing to inform you of the changes to your account. "
        "Please reply at your earliest convenience.\n\nRegards,\nThe Team",
    ],
    "financial": [
        "SUPERMART\nQty 2  Milk      $3.50\nQty 1  Bread     $2.00\nSubtotal     $5.50\n"
        "Tax          $0.44\nTotal        $5.94\nPaid: cash   Change: $4.06",
        "INVOICE #4821\nDescription            Amount\nConsulting services   $1,200.00\n"
        "Tax (8%)                 $96.00\nAmount due           $1,296.00  Due net 30",
    ],
    "education": [
        "Lesson Plan — Grade 5 Science. Learning objective: students will understand "
        "simple machines. Materials: levers, pulleys. Activity: build a lever and "
        "measure force. Assessment: worksheet and class discussion.",
        "Curriculum unit: Introduction to fractions. By the end of this unit, students "
        "will be able to add and compare fractions. Includes warm-up, guided practice, "
        "and homework.",
    ],
    "config": [
        '{\n  "theme": "dark",\n  "timeout": 30,\n  "retries": 3,\n  "plugins": '
        '["auth", "cache"],\n  "endpoint": "http://localhost:8080"\n}',
        "# settings.yaml\ndebug: false\nworkers: 4\ndatabase:\n  host: localhost\n  "
        "port: 5432\nfeature_flags:\n  new_ui: true",
    ],
    "data": [
        "model,score,tools,date\nopus,183.7,88,2026-05-30\nsonnet,118.0,118,2026-05-29\n"
        "cursor,58.8,677,2026-05-28\nllama,42.1,40,2026-05-27",
        "Results table: mean=0.651, median=0.66, n=192, stddev=0.04. Distribution of "
        "scores by bucket: 0.55-0.60: 33, 0.60-0.65: 58, 0.65-0.70: 76, 0.70-0.75: 25.",
    ],
    "personal": [
        "Medical history: patient reports mild symptoms since last visit. Family "
        "contacts and emergency information updated. Notes about the children's "
        "schedules and the upcoming family gathering.",
        "Personal notes about my relationship with my parents and the things I want "
        "to remember about home. Private, not for sharing.",
    ],
}

# Category → structural fragment_type stored alongside the topical label.
CATEGORY_FRAGMENT_TYPE = {
    "financial": "receipt",
    "correspondence": "note",
    "journal": "note",
    "narrative": "note",
}


def _seeds_hash() -> str:
    blob = json.dumps(EXEMPLARS, sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()[:12]


def _cache_path(model: str) -> Path:
    base = Path(os.environ.get("NEST_CACHE_DIR", Path.home() / ".cache" / "nest-seed"))
    safe_model = model.replace("/", "_").replace(":", "_")
    return base / f"centroids_{safe_model}_{_seeds_hash()}.json"


def build_centroids(model: str = _embed.DEFAULT_EMBED_MODEL,
                    use_cache: bool = True) -> dict[str, list[float]] | None:
    """Return {category: centroid_vector}, or None if embeddings are unavailable.

    Exemplars are embedded as *documents* (same prefix as the files being
    classified) so the comparison is document-to-document. Cached to disk keyed
    by (model, exemplar hash) — recomputed only when exemplars or model change.
    """
    cache = _cache_path(model)
    if use_cache and cache.exists():
        try:
            return json.loads(cache.read_text())
        except (OSError, ValueError):
            pass

    if not _embed.available(model):
        return None

    centroids: dict[str, list[float]] = {}
    for cat, docs in EXEMPLARS.items():
        vecs = [_embed.embed_document(d, model=model) for d in docs]
        c = _embed.centroid(vecs)
        if c is None:
            return None  # partial failure → don't cache a broken set
        centroids[cat] = c

    if use_cache:
        try:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(centroids))
        except OSError:
            pass
    return centroids


def rank(doc_vec: list[float], centroids: dict[str, list[float]]) -> list[tuple[float, str]]:
    """Cosine-rank a document vector against all centroids, best first."""
    sims = [(_embed.cosine(doc_vec, c), cat) for cat, c in centroids.items()]
    sims.sort(reverse=True)
    return sims


def margin_stats(ranked: list[tuple[float, str]]) -> dict:
    """Relative-confidence stats for a ranked similarity list.

    margin = how far the winner stands out from the average category — the
    discriminative signal when absolute cosine is uniformly high.
    """
    scores = [s for s, _ in ranked]
    top = scores[0]
    mean = sum(scores) / len(scores)
    runner = scores[1] if len(scores) > 1 else 0.0
    return {
        "top": top,
        "cat": ranked[0][1],
        "mean": mean,
        "margin": top - mean,   # primary confidence signal
        "gap": top - runner,    # secondary (top-2 separation)
    }
