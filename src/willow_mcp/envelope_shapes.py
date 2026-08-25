"""willow_mcp.envelope_shapes — precedent recall for envelope proposals.

PR7 of the envelope-accrual plan. The piece that makes the accrual actually
reduce authoring cost: given a proposed envelope shape (verb + grantee +
bounds), surface the operator's prior ratifications for similar shapes so
the ratify UX becomes "confirm precedents X, Y or override" instead of
"author from scratch."

The similarity metric composes three checks, in this order:

1. **Verb match — mandatory.** Different verbs are unrelated envelopes;
   dispatch_send precedents don't inform knowledge_ingest proposals.
2. **Grantee overlap — mandatory.** A precedent granted to hanuman does not
   precede a proposal for loki. The registry allows glob grantees ("hanuman_*")
   and grantee lists; overlap is checked via :func:`_grantee_matches` from
   envelope_authoring (same shape :func:`envelopes._granted` uses).
3. **Bounds similarity — scored per field.** Exact equality is 1.0; fnmatch
   equivalence for glob-shaped bounds is 0.8; longest-common-prefix for
   path-shaped bounds decays from 0.5; numeric bounds decay by ratio.
   Missing keys score 0. Overall score is the mean.

Why this shape rather than a semantic-vector embedding: envelope bounds are
short, structured, and the operator's judgment about "is this the same
shape" is discrete (path prefix, quota tier, timeout budget). Semantic
similarity would be over-engineered for the domain and would introduce a
dependency this module doesn't need.

Precedents come from ``envelope_authoring.list_active`` for PR7 — the
currently-in-force envelopes. A follow-on could extend this to walk the
FRANK ``envelope_ratified`` event stream so ratified-then-superseded shapes
also count as precedent; that requires a Postgres connection this module
does not want to hold and is left for a later PR.

The output shape is stable:
    [
        {
            "envelope_id": "env-...",
            "score": 0.87,
            "matching_bounds": ["field1", "field3"],   # score 1.0 fields
            "differing_bounds": ["field2"],            # score < 1.0 fields
            "precedent_bounds": {...},
        },
        ...
    ]
Sorted descending by score. Callers (``envelope_authoring.propose``) take
the top N ids to populate the proposal's ``precedent_ids`` list.
"""
from __future__ import annotations

import fnmatch
import os
from typing import Iterable, Optional

from . import envelope_authoring as _ea


# Score thresholds — tunable but pinned so tests can assert on stable values.
_SCORE_EXACT = 1.0
_SCORE_FNMATCH_EQUIV = 0.8
_SCORE_PATH_PREFIX_MAX = 0.5  # scaled by prefix_len / max(len(a), len(b))
_SCORE_MISSING = 0.0


def _looks_glob(s: str) -> bool:
    """A string is glob-shaped if it contains at least one shell wildcard."""
    return isinstance(s, str) and any(c in s for c in "*?[")


def _looks_path(s: str) -> bool:
    """A string is path-shaped if it contains a slash. Same heuristic Nestor's
    matcher uses for the `paths` domain — no filesystem check, purely a
    lexical test."""
    return isinstance(s, str) and ("/" in s or "\\" in s)


def _field_similarity(a, b) -> float:
    """Score two per-field bounds values in [0.0, 1.0].

    Mirrors Nestor's approach: exact match wins; structural equivalence gets
    a fixed weight; lexical overlap decays with length; missing/mismatched
    types are 0.
    """
    if a == b:
        return _SCORE_EXACT

    # Both string-shaped
    if isinstance(a, str) and isinstance(b, str):
        # Glob equivalence — do they cover overlapping sets of strings?
        # Cheap approximation: does one match the other as a pattern?
        if _looks_glob(a) or _looks_glob(b):
            if _looks_glob(a) and fnmatch.fnmatchcase(b, a):
                return _SCORE_FNMATCH_EQUIV
            if _looks_glob(b) and fnmatch.fnmatchcase(a, b):
                return _SCORE_FNMATCH_EQUIV
        # Path prefix — for path-shaped strings, longest common prefix
        # gets a decaying score.
        if _looks_path(a) and _looks_path(b):
            common = os.path.commonprefix([a, b])
            if common:
                longest = max(len(a), len(b))
                # Slash-boundary alignment: an operator granting "docs/" and
                # a proposal for "docs-drafts/" share a lexical prefix but
                # not a directory prefix — decay the score in that case.
                clean = common.rsplit("/", 1)[0] + "/" if "/" in common else common
                return _SCORE_PATH_PREFIX_MAX * len(clean) / longest
        return _SCORE_MISSING

    # Both numeric
    if isinstance(a, (int, float)) and not isinstance(a, bool) \
       and isinstance(b, (int, float)) and not isinstance(b, bool):
        if a == 0 and b == 0:
            return _SCORE_EXACT  # already caught by a == b above, defensive
        if a == 0 or b == 0:
            return _SCORE_MISSING
        # Same sign; ratio of smaller / larger. 1.0 when equal, decays
        # symmetrically. Negative values ignored — bounds are quotas/sizes.
        if (a > 0) != (b > 0):
            return _SCORE_MISSING
        ratio = min(abs(a), abs(b)) / max(abs(a), abs(b))
        return float(ratio)

    return _SCORE_MISSING


def similar_precedents(
    verb: str,
    grantee: str,
    bounds: dict,
    *,
    active_envelopes: Optional[Iterable[dict]] = None,
    min_score: float = 0.0,
) -> list[dict]:
    """Rank active envelopes as precedents for a proposed (verb, grantee,
    bounds) shape.

    Only envelopes matching both ``verb`` (exactly) and ``grantee`` (via
    :func:`envelope_authoring._grantee_matches`) are considered. Bounds
    similarity is computed per-field via :func:`_field_similarity` and the
    overall score is the mean.

    Returns a list of ``{envelope_id, score, matching_bounds, differing_bounds,
    precedent_bounds}`` dicts, sorted descending by score. Optionally
    filtered by ``min_score`` — the caller may want to hide near-zero
    matches from the operator ratify surface.

    ``active_envelopes`` accepts a caller-supplied iterable (test injection)
    and defaults to :func:`envelope_authoring.list_active` filtered by
    ``verb``. The verb filter is applied twice — once by ``list_active`` for
    speed, once here for defense — cheap and lets a test pass in
    unfiltered rows.
    """
    if active_envelopes is None:
        active_envelopes = _ea.list_active(verb=verb)

    out: list[dict] = []
    for row in active_envelopes:
        if row.get("verb") != verb:
            continue
        if not _ea._grantee_matches(row.get("grantee"), grantee):
            continue
        prec_bounds = row.get("bounds") or {}
        if not isinstance(prec_bounds, dict) or not bounds:
            continue
        matching: list[str] = []
        differing: list[str] = []
        scores: list[float] = []
        # Union of keys so a precedent with EXTRA fields still scores
        # (extras contribute 0 for missing-in-proposal, which is right —
        # a precedent that granted MORE than this proposal asks for is
        # still relevant, and the operator sees the extras in
        # precedent_bounds).
        all_keys = set(bounds) | set(prec_bounds)
        for key in all_keys:
            if key in bounds and key in prec_bounds:
                sim = _field_similarity(bounds[key], prec_bounds[key])
            else:
                sim = _SCORE_MISSING
            scores.append(sim)
            if sim >= _SCORE_EXACT:
                matching.append(key)
            else:
                differing.append(key)
        if not scores:
            continue
        score = sum(scores) / len(scores)
        if score < min_score:
            continue
        out.append({
            "envelope_id": row.get("id"),
            "score": round(score, 4),
            "matching_bounds": sorted(matching),
            "differing_bounds": sorted(differing),
            "precedent_bounds": prec_bounds,
        })
    out.sort(key=lambda p: p["score"], reverse=True)
    return out


def top_precedent_ids(
    verb: str,
    grantee: str,
    bounds: dict,
    *,
    limit: int = 5,
    min_score: float = 0.1,
) -> list[str]:
    """Convenience: just the top-N envelope ids for embedding on a
    proposal row's ``precedent_ids`` field. Filters below ``min_score`` by
    default (0.1 keeps out near-zero matches that would just be noise on
    the operator ratify surface)."""
    ranked = similar_precedents(verb, grantee, bounds, min_score=min_score)
    return [p["envelope_id"] for p in ranked[:limit] if p["envelope_id"]]
