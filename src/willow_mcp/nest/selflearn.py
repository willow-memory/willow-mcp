"""
nest-seed/selflearn.py — self-learning centroids + clustering discovery.

taxonomy.py builds *static* category centroids from curated exemplars. This
module is the "adapts to your data" layer the taxonomy docstring promises: the
user's own confidently-classified documents are folded back into the centroids
so the Nest learns what *their* legal filings, journals, and receipts actually
look like.

Two capabilities, both pure-stdlib (no numpy) and degrading gracefully:

  build_adaptive_centroids(model)
      Exemplar centroids + the learned-member store, combined by an exact mean:
          combined = (exemplar_centroid * n_exemplars + Σ learned) / (n_ex + n_learned)
      This needs only the cached exemplar centroid and the exemplar count, so it
      never re-embeds the exemplars. Cached to disk keyed by
      (model, exemplar-hash, learned-hash) — recomputed only when either changes.
      With no learned members it returns the plain exemplar centroids unchanged,
      so it is a safe drop-in for taxonomy.build_centroids().

  discover(items, k)
      Spherical k-means over (vector, snippet) pairs — clusters the low-margin /
      unknown tail to surface categories the exemplars are missing. Report-only.

Learning is deliberately conservative: only `confirmed`-band classifications
(margin ≥ 0.10) are recorded, deduped by source hash, and capped per category
(highest-margin kept). This limits the confirmation-bias risk of a classifier
learning from its own least-certain guesses.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

try:  # works both as a package (apps.nest_seed) and as a plain script dir
    from . import embed as _embed
    from . import taxonomy as _tax
except ImportError:
    import embed as _embed
    import taxonomy as _tax

# Only the most confident band feeds the centroids (see module docstring).
LEARN_MIN_MARGIN = float(os.environ.get("NEST_LEARN_MIN_MARGIN", "0.10"))
LEARN_MAX_PER_CAT = int(os.environ.get("NEST_LEARN_MAX_PER_CAT", "50"))

# Cluster-promotion gates (phase 2b). A discovered cluster becomes a new category
# only when it is big enough, internally cohesive, and genuinely novel — i.e. its
# centroid does NOT rank confidently into any existing category (margin-over-mean
# below PROMOTE_MAX_MARGIN, the same discriminative signal classify() uses).
PROMOTE_MIN_SIZE = int(os.environ.get("NEST_PROMOTE_MIN_SIZE", "4"))
PROMOTE_MAX_MARGIN = float(os.environ.get("NEST_PROMOTE_MAX_MARGIN", "0.06"))
PROMOTE_MIN_COHESION = float(os.environ.get("NEST_PROMOTE_MIN_COHESION", "0.50"))
PROMOTE_MAX_NEW = int(os.environ.get("NEST_PROMOTE_MAX_NEW", "5"))
DISCOVERED_PREFIX = "auto:"

# Type of the per-doc hook classify() calls: (category, vec, margin, confidence).
LearnSink = Callable[[str, list, float, str], None]

# Type of the tier-3 hook classify() calls once per LLM escalation. The dict is
# the (excerpt, margin, candidates, verdict, teacher_model) tuple the cascade
# already computes — the distillation corpus for a future tier-2.5 student.
EscalationSink = Callable[[dict], None]


# --- learned-member store ---------------------------------------------------

def _cache_dir() -> Path:
    return Path(os.environ.get("NEST_CACHE_DIR", Path.home() / ".cache" / "nest-seed"))


def _learned_path(model: str) -> Path:
    safe = model.replace("/", "_").replace(":", "_")
    return _cache_dir() / f"learned_{safe}.json"


def _escalation_path(model: str) -> Path:
    safe = model.replace("/", "_").replace(":", "_")
    return _cache_dir() / f"escalations_{safe}.jsonl"


def append_escalations(model: str, rows: list[dict]) -> dict:
    """Append tier-3 escalation rows to the JSONL log for `model` (the teacher).

    One line per escalation: {ts, hash, excerpt, margin, candidates, verdict,
    teacher_model, embed_model}. `verdict` is None when the teacher was asked
    and did not answer — logged, not dropped, so an unreachable teacher reads
    as unreachable rather than as "nothing escalated". Append-only; never
    rewrites. Returns {logged, path} or {logged: 0, error} on an OS failure.
    """
    if not rows:
        return {"logged": 0, "path": str(_escalation_path(model))}
    p = _escalation_path(model)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, sort_keys=True) + "\n")
    except OSError as e:
        return {"logged": 0, "path": str(p), "error": f"{type(e).__name__}: {e}"}
    return {"logged": len(rows), "path": str(p)}


def load_learned(model: str) -> dict[str, list[dict]]:
    """Return {category: [{"vec":[...], "hash":str, "margin":float}, ...]}."""
    p = _learned_path(model)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_learned(model: str, store: dict[str, list[dict]]) -> None:
    p = _learned_path(model)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=p.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps(store))
            os.replace(tmp, p)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError:
        pass


def learned_hash(model: str) -> str:
    """Stable fingerprint of the learned store — part of the centroid cache key."""
    store = load_learned(model)
    sig = {cat: sorted(e.get("hash", "") for e in entries)
           for cat, entries in store.items()}
    return hashlib.sha256(json.dumps(sig, sort_keys=True).encode()).hexdigest()[:12]


def merge_learned(model: str, observations: list[dict], *,
                  min_margin: float | None = None,
                  max_per_cat: int | None = None) -> dict:
    """Fold new confident observations into the learned store on disk.

    observations: [{"category","vec","margin","hash"}]. Deduped by hash within a
    category; each category capped to the highest-margin `max_per_cat`.
    Returns a summary {added, per_category, total}.

    Defaults are resolved at call time from the module globals (which honour the
    NEST_LEARN_* env vars), not bound at import.
    """
    if min_margin is None:
        min_margin = LEARN_MIN_MARGIN
    if max_per_cat is None:
        max_per_cat = LEARN_MAX_PER_CAT
    store = load_learned(model)
    added = 0
    for obs in observations:
        if obs.get("margin", 0.0) < min_margin or not obs.get("vec"):
            continue
        cat = obs["category"]
        bucket = store.setdefault(cat, [])
        h = obs.get("hash", "")
        existing = next((e for e in bucket if e.get("hash") == h), None) if h else None
        if existing:
            existing["margin"] = max(existing.get("margin", 0.0), obs["margin"])
            continue
        bucket.append({"vec": obs["vec"], "hash": h, "margin": obs["margin"]})
        added += 1

    # cap each category to the strongest members
    for cat, bucket in store.items():
        if len(bucket) > max_per_cat:
            bucket.sort(key=lambda e: e.get("margin", 0.0), reverse=True)
            store[cat] = bucket[:max_per_cat]

    save_learned(model, store)
    return {
        "added": added,
        "total": sum(len(v) for v in store.values()),
        "per_category": {c: len(v) for c, v in store.items()},
    }


# --- adaptive centroids -----------------------------------------------------

def _adaptive_cache_path(model: str) -> Path:
    safe = model.replace("/", "_").replace(":", "_")
    return (_cache_dir() /
            f"centroids_adaptive_{safe}_{_tax._seeds_hash()}"
            f"_{learned_hash(model)}_{discovered_hash(model)}.json")


def build_adaptive_centroids(model: str = _embed.DEFAULT_EMBED_MODEL,
                             use_cache: bool = True) -> Optional[dict[str, list[float]]]:
    """Exemplar centroids folded with learned members and discovered categories.

    Drop-in for taxonomy.build_centroids(): identical result when nothing has
    been learned or discovered yet. Returns None only if exemplar embeddings are
    unavailable.
    """
    base = _tax.build_centroids(model=model, use_cache=use_cache)
    if base is None:
        return None
    learned = load_learned(model)
    discovered = load_discovered(model)
    if not learned and not discovered:
        return base

    cache = _adaptive_cache_path(model)
    if use_cache and cache.exists():
        try:
            return json.loads(cache.read_text())
        except (OSError, ValueError):
            pass

    out: dict[str, list[float]] = {}
    # exemplar categories, each folded with its learned members
    for cat, centroid in base.items():
        members = [e["vec"] for e in learned.get(cat, []) if e.get("vec")]
        n_ex = len(_tax.EXEMPLARS.get(cat, [])) or 1
        if not members:
            out[cat] = centroid
            continue
        dim = len(centroid)
        n_total = n_ex + len(members)
        # exact mean of (exemplars + learned): exemplar sum = centroid * n_ex
        out[cat] = [
            (centroid[i] * n_ex + sum(v[i] for v in members)) / n_total
            for i in range(dim)
        ]
    # discovered categories enter as standalone centroids
    for name, entry in discovered.items():
        if entry.get("vec") and name not in out:
            out[name] = entry["vec"]

    if use_cache:
        try:
            cache.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=cache.parent, suffix=".tmp")
            try:
                with os.fdopen(fd, "w") as f:
                    f.write(json.dumps(out))
                os.replace(tmp, cache)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
        except OSError:
            pass
    return out


# --- human correction (GAP #2a): negative feedback into the learned store --
#
# merge_learned/build_adaptive_centroids above are additive-only: there is no
# path for a human to say "that classification was wrong" and have it demote
# the wrong category. This section adds one.
#
# Mechanism, chosen for numerical stability over raw negative weighting:
# RETRACT the offending vector from the wrong category's learned store (so
# build_adaptive_centroids's exact mean over exemplars+learned no longer
# includes it — the denominator only ever shrinks toward n_exemplars, never
# toward or past zero, and the centroid arithmetic never sees a negative
# weight at all), and, optionally, PROMOTE the same vector into the correct
# category via the ordinary (positive) merge_learned() path. A human
# correction is ground truth, so the promotion bypasses LEARN_MIN_MARGIN
# entirely rather than being subject to the same confidence gate a machine
# observation is.

# A vector already in the learned store this close (cosine) to the corrected
# one is treated as "the same observation" for retraction when no exact hash
# is given — near-1.0 so an unrelated-but-similar document is never retracted
# by mistake.
CORRECTION_MATCH_COSINE = 0.999


class CorrectionError(ValueError):
    """A malformed or unresolvable human correction — rejected, not applied."""


def _cosine(a: list[float], b: list[float]) -> float:
    if len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


def _validate_correction_vec(vec) -> list[float]:
    """Reject a malformed vector before it can reach any centroid arithmetic."""
    if not isinstance(vec, (list, tuple)) or not vec:
        raise CorrectionError("vec must be a non-empty list of numbers")
    try:
        out = [float(x) for x in vec]
    except (TypeError, ValueError):
        raise CorrectionError("vec must contain only numbers") from None
    if any(math.isnan(x) or math.isinf(x) for x in out):
        raise CorrectionError("vec must not contain NaN/inf")
    if all(x == 0.0 for x in out):
        raise CorrectionError("vec must not be the all-zero vector")
    return out


def known_categories(model: str) -> set[str]:
    """Every category name the classifier could plausibly have produced:
    curated exemplar categories, learned members, and promoted `auto:`
    discoveries. A correction naming anything outside this set is rejected
    (fail-safe) rather than silently creating a new, unvetted category."""
    return set(_tax.EXEMPLARS) | set(load_learned(model)) | set(load_discovered(model))


def apply_correction(model: str, *, wrong_category: str, vec: list,
                     correct_category: str | None = None,
                     record_hash: str | None = None,
                     max_per_cat: int | None = None) -> dict:
    """Demote `wrong_category` for `vec` and, optionally, promote `correct_category`.

    Raises CorrectionError (nothing written) for: an unknown wrong/correct
    category, `correct_category == wrong_category`, or a malformed `vec`
    (empty, non-numeric, NaN/inf, or the zero vector).

    Returns {status, wrong_category, retracted, correct_category, promoted}.
    `retracted` is the number of learned entries removed from
    `wrong_category` (0 or 1 in the normal case; a hash match is exact, a
    vector match is by near-identity cosine — see CORRECTION_MATCH_COSINE).
    `promoted` is 1 iff a `correct_category` was given and the vector was
    added to it (0 if it was already present, deduped by hash as usual).
    """
    if max_per_cat is None:
        max_per_cat = LEARN_MAX_PER_CAT
    vec = _validate_correction_vec(vec)

    if not wrong_category or not isinstance(wrong_category, str):
        raise CorrectionError("wrong_category must be a non-empty str")
    known = known_categories(model)
    if wrong_category not in known:
        raise CorrectionError(f"unknown category {wrong_category!r}")
    if correct_category is not None:
        if not isinstance(correct_category, str) or not correct_category:
            raise CorrectionError("correct_category must be a non-empty str or None")
        if correct_category == wrong_category:
            raise CorrectionError("correct_category must differ from wrong_category")
        if correct_category not in known:
            raise CorrectionError(f"unknown category {correct_category!r}")

    # --- retract from the wrong category ------------------------------------
    store = load_learned(model)
    bucket = store.get(wrong_category, [])
    before = len(bucket)
    if record_hash:
        kept = [e for e in bucket if e.get("hash") != record_hash]
    else:
        kept = [e for e in bucket
                if not e.get("vec") or _cosine(e["vec"], vec) < CORRECTION_MATCH_COSINE]
    retracted = before - len(kept)
    if retracted:
        if kept:
            store[wrong_category] = kept
        else:
            del store[wrong_category]
        save_learned(model, store)

    # --- promote the correct category (human ground truth, no margin gate) --
    promoted = 0
    if correct_category is not None:
        h = record_hash or ("correction:" + hashlib.sha256(
            json.dumps(vec, sort_keys=True).encode()).hexdigest()[:16])
        summary = merge_learned(
            model,
            [{"category": correct_category, "vec": vec, "margin": 1.0, "hash": h}],
            min_margin=0.0,
            max_per_cat=max_per_cat,
        )
        promoted = summary["added"]

    return {
        "status": "ok",
        "wrong_category": wrong_category,
        "retracted": retracted,
        "correct_category": correct_category,
        "promoted": promoted,
    }


# --- per-run observation collector ------------------------------------------

class Recorder:
    """Collects classify()'s per-doc observations during an ingest run.

    `confident` feeds the learned store; `tail` (uncertain/speculative/unknown)
    feeds clustering discovery. Both reuse the embedding classify already
    computed — no extra model calls.
    """

    def __init__(self, *, escalation_model: str | None = None) -> None:
        self.confident: list[dict] = []
        self.tail: list[dict] = []
        # Every tier-3 escalation this run, verdict or not (see EscalationSink).
        self.escalations: list[dict] = []
        # When a teacher model is named, each escalation is appended to that
        # model's JSONL log AT SINK TIME — durable per row, so a run killed
        # mid-way (client timeout, broker restart, the laptop dying hard) keeps
        # every row it paid the teacher for (gap 0c062b3c83c3). Without a
        # model the rows only buffer and flush_escalations() writes them, the
        # pre-#568 posture. The learned-centroid merge stays end-of-run: it is
        # a fold, not a log.
        self.escalation_model = escalation_model
        self.escalations_logged = 0
        self.escalation_errors: list[str] = []

    def sink_for(self, *, key: str, snippet: str) -> LearnSink:
        """A per-file hook bound to this file's hash + snippet."""
        def _sink(category: str, vec: list, margin: float, confidence: str) -> None:
            if confidence == "confirmed":
                self.confident.append(
                    {"category": category, "vec": vec, "margin": margin, "hash": key})
            elif confidence in ("uncertain", "speculative"):
                self.tail.append({"vec": vec, "snippet": snippet, "category": category})
        return _sink

    def escalation_sink_for(self, *, key: str) -> EscalationSink:
        """A per-file hook that records each tier-3 escalation under this file's hash."""
        def _sink(row: dict) -> None:
            full = {
                "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "hash": key,
                **row,
            }
            self.escalations.append(full)
            if self.escalation_model:
                out = append_escalations(self.escalation_model, [full])
                self.escalations_logged += out.get("logged", 0)
                if out.get("error"):
                    self.escalation_errors.append(out["error"])
        return _sink

    def flush_learned(self, model: str) -> dict:
        return merge_learned(model, self.confident)

    def flush_escalations(self, teacher_model: str) -> dict:
        """Report the escalation log for this run.

        With an `escalation_model` the rows are already on disk; this only
        totals them (and carries the first write error, if any). Without one,
        this is the write.
        """
        if self.escalation_model:
            out = {"logged": self.escalations_logged,
                   "path": str(_escalation_path(self.escalation_model))}
            if self.escalation_errors:
                out["error"] = self.escalation_errors[0]
                out["errors"] = len(self.escalation_errors)
            return out
        return append_escalations(teacher_model, self.escalations)


# --- clustering discovery (pure-python spherical k-means) -------------------

def _normalize(v: list[float]) -> list[float]:
    n = math.sqrt(sum(x * x for x in v))
    return [x / n for x in v] if n else v


def _dot(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def _kmeans(vecs: list[list[float]], k: int, iters: int = 25) -> tuple[list[int], list[list[float]]]:
    """Spherical k-means over already-normalized vectors. Deterministic init."""
    step = max(1, len(vecs) // k)
    centers = [vecs[i * step][:] for i in range(k)]
    labels = [0] * len(vecs)
    for _ in range(iters):
        changed = False
        for i, v in enumerate(vecs):
            best = max(range(k), key=lambda c: _dot(v, centers[c]))
            if best != labels[i]:
                labels[i] = best
                changed = True
        for c in range(k):
            members = [v for v, lab in zip(vecs, labels) if lab == c]
            if members:
                dim = len(members[0])
                centers[c] = _normalize(
                    [sum(m[i] for m in members) / len(members) for i in range(dim)])
        if not changed:
            break
    return labels, centers


def discover(items: list[dict], k: int = 6, iters: int = 25) -> dict:
    """Cluster (vec, snippet) items into k groups by spherical k-means.

    items: [{"vec":[...], "snippet":str}]. Report-only — surfaces candidate
    categories the exemplars don't cover. Deterministic (fixed init).
    """
    pts = [(_normalize(it["vec"]), it.get("snippet", "")) for it in items if it.get("vec")]
    if len(pts) < k:
        return {"status": "noop", "reason": f"only {len(pts)} items for k={k}"}

    vecs = [v for v, _s in pts]
    labels, centers = _kmeans(vecs, k, iters)

    clusters = []
    for c in range(k):
        idx = [i for i, lab in enumerate(labels) if lab == c]
        if not idx:
            continue
        rep_i = max(idx, key=lambda i: _dot(pts[i][0], centers[c]))
        clusters.append({"size": len(idx), "representative": pts[rep_i][1][:140]})
    clusters.sort(key=lambda c: c["size"], reverse=True)
    return {"status": "ok", "n_items": len(pts), "clusters": clusters}


# --- cluster promotion (phase 2b): clusters → new categories -----------------

def _discovered_path(model: str) -> Path:
    safe = model.replace("/", "_").replace(":", "_")
    return _cache_dir() / f"discovered_{safe}.json"


def load_discovered(model: str) -> dict[str, dict]:
    """Return {category_name: {"vec","label","size","cohesion"}}."""
    p = _discovered_path(model)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_discovered(model: str, store: dict[str, dict]) -> None:
    p = _discovered_path(model)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=p.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps(store))
            os.replace(tmp, p)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError:
        pass


def discovered_hash(model: str) -> str:
    store = load_discovered(model)
    sig = {name: e.get("size", 0) for name, e in store.items()}
    return hashlib.sha256(json.dumps(sig, sort_keys=True).encode()).hexdigest()[:12]


def _slug(text: str, used: set[str]) -> str:
    words = [w for w in "".join(c.lower() if c.isalnum() else " " for c in text).split()][:4]
    base = DISCOVERED_PREFIX + ("-".join(words) or "cluster")
    name, n = base, 2
    while name in used:
        name = f"{base}-{n}"
        n += 1
    return name


def promote_clusters(model: str, items: list[dict], *, k: int = 8, iters: int = 25,
                     min_size: int | None = None, max_margin: float | None = None,
                     min_cohesion: float | None = None, max_new: int | None = None) -> dict:
    """Cluster the uncertain tail and persist qualifying clusters as new categories.

    A cluster is promoted when it is (a) at least `min_size` documents, (b)
    internally cohesive (mean member→centroid cosine ≥ `min_cohesion`), and (c)
    novel — its centroid does not rank confidently into any existing category
    (margin-over-mean < `max_margin`). Rejections are returned with reasons; the
    strongest `max_new` qualifying clusters are kept. Returns a summary dict.
    """
    if min_size is None:
        min_size = PROMOTE_MIN_SIZE
    if max_margin is None:
        max_margin = PROMOTE_MAX_MARGIN
    if min_cohesion is None:
        min_cohesion = PROMOTE_MIN_COHESION
    if max_new is None:
        max_new = PROMOTE_MAX_NEW

    pts = [(_normalize(it["vec"]), it.get("snippet", "")) for it in items if it.get("vec")]
    if len(pts) < k:
        return {"status": "noop", "reason": f"only {len(pts)} tail items for k={k}"}

    base = _tax.build_centroids(model=model)
    if base is None:
        return {"status": "skipped", "reason": "exemplar centroids unavailable"}

    vecs = [v for v, _s in pts]
    labels, centers = _kmeans(vecs, k, iters)

    existing = load_discovered(model)
    used = set(base) | set(existing)
    candidates = []  # (cohesion, size, name, centroid, rep)
    rejected = []
    for c in range(k):
        idx = [i for i, lab in enumerate(labels) if lab == c]
        if not idx:
            continue
        size = len(idx)
        centroid = centers[c]
        cohesion = sum(_dot(vecs[i], centroid) for i in idx) / size
        novelty = _tax.margin_stats(_tax.rank(centroid, base))["margin"]
        rep = pts[max(idx, key=lambda i: _dot(vecs[i], centroid))][1]
        if size < min_size:
            rejected.append({"size": size, "reason": "too_small"})
            continue
        if cohesion < min_cohesion:
            rejected.append({"size": size, "reason": f"incoherent({cohesion:.2f})"})
            continue
        if novelty >= max_margin:
            rejected.append({"size": size, "reason": f"matches_existing(margin={novelty:.2f})"})
            continue
        candidates.append((cohesion, size, centroid, rep))

    # keep the strongest (most cohesive) clusters, capped
    candidates.sort(key=lambda t: (t[0], t[1]), reverse=True)
    promoted = []
    for cohesion, size, centroid, rep in candidates[:max_new]:
        name = _slug(rep, used)
        used.add(name)
        existing[name] = {"vec": centroid, "label": rep[:140],
                          "size": size, "cohesion": round(cohesion, 4)}
        promoted.append({"name": name, "size": size, "cohesion": round(cohesion, 4),
                         "representative": rep[:80]})

    if promoted:
        save_discovered(model, existing)
    capped = len(candidates) - len(candidates[:max_new])
    return {
        "status": "ok",
        "tail_items": len(pts),
        "promoted": promoted,
        "rejected": rejected,
        "capped_out": capped if capped > 0 else 0,
        "total_discovered": len(existing),
    }
