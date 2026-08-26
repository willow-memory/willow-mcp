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

Precedents come from BOTH ``envelope_authoring.list_active`` (currently
in force) AND ``envelope_authoring.list_archived`` (PR11: today, the
operator's rejected proposals with reopen_when). Score is
polarity-blind — a rejected match scores the same as a ratified one;
the ``precedent_status`` field on each result tells the surface how to
render it. This mirrors Nestor's ``reject_match``: a "no with a
reopen_when" is a precedent about the shape, not a lesser signal.

Historical precedents from the FRANK ledger itself remain out of
scope — ``envelope_ratified`` events store ``bounds_digest``, not
bounds, so the ledger walk can identify prior envelope_ids but not
score them. That would need either a wire change (bounds inline in
the event) or a separate bounds-history store, neither of which are
tractable here.

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
    archived_envelopes: Optional[Iterable[dict]] = None,
    include_archived: bool = True,
    min_score: float = 0.0,
) -> list[dict]:
    """Rank active + archived envelopes as precedents for a proposed
    (verb, grantee, bounds) shape.

    Only envelopes matching both ``verb`` (exactly) and ``grantee`` (via
    :func:`envelope_authoring._grantee_matches`) are considered. Bounds
    similarity is computed per-field via :func:`_field_similarity` and the
    overall score is the mean.

    Returns a list of ``{envelope_id, score, precedent_status,
    matching_bounds, differing_bounds, precedent_bounds}`` dicts, sorted
    descending by score. ``precedent_status`` is ``"active"`` for a
    currently-active envelope; for an archived row (PR11) it reflects the
    stored status (today: ``"rejected"``). A rejected precedent also
    carries ``reopen_when`` in the result so the ratify surface can show
    "you already said no to this shape; condition to reopen: X."

    Score is polarity-blind — a rejected match scores the same as a
    ratified one; the ``precedent_status`` field tells the surface how
    to render it. This mirrors Nestor's ``reject_match``: a "no with a
    reopen_when" is a precedent about the shape, not a lesser signal.

    Optionally filtered by ``min_score``. ``include_archived=False``
    reverts to PR7-era behavior (active only).

    ``active_envelopes`` / ``archived_envelopes`` accept caller-supplied
    iterables for test injection; the defaults come from
    :func:`envelope_authoring.list_active` / :func:`.list_archived`,
    verb-filtered for speed. Verb filter re-applied here as defense so
    an unfiltered iterable still gets narrowed.
    """
    # Default-fetch pairs: if the caller injected active_envelopes but
    # didn't touch archived_envelopes, we treat archived as empty rather
    # than reaching for the registry (a test that pins verb-mismatch on
    # an in-memory list shouldn't need a registry on disk). Callers who
    # want the auto-fetch on both leave both as None.
    caller_supplied_active = active_envelopes is not None
    if active_envelopes is None:
        active_envelopes = _ea.list_active(verb=verb)
    if not include_archived:
        archived_envelopes = ()
    elif archived_envelopes is None and not caller_supplied_active:
        # Best-effort: an unreadable registry (missing, unowned, hand-
        # deleted) shouldn't turn precedent recall into a crash. Same
        # discipline the propose() call site already uses when wrapping
        # top_precedent_ids in a try/except.
        try:
            archived_envelopes = _ea.list_archived(verb=verb)
        except Exception:
            archived_envelopes = ()
    elif archived_envelopes is None:
        archived_envelopes = ()

    def _score_row(row: dict, status_default: str) -> Optional[dict]:
        if row.get("verb") != verb:
            return None
        if not _ea._grantee_matches(row.get("grantee"), grantee):
            return None
        prec_bounds = row.get("bounds") or {}
        if not isinstance(prec_bounds, dict) or not bounds:
            return None
        matching: list[str] = []
        differing: list[str] = []
        scores: list[float] = []
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
            return None
        score = sum(scores) / len(scores)
        if score < min_score:
            return None
        out = {
            "envelope_id": row.get("id"),
            "score": round(score, 4),
            "precedent_status": row.get("status") or status_default,
            "matching_bounds": sorted(matching),
            "differing_bounds": sorted(differing),
            "precedent_bounds": prec_bounds,
        }
        # PR11: preserve the reopen-condition on a rejected precedent so
        # the operator surface can name it.
        if row.get("status") == "rejected":
            out["reopen_when"] = row.get("reopen_when") or ""
        return out

    out: list[dict] = []
    for row in active_envelopes:
        scored = _score_row(row, "active")
        if scored is not None:
            out.append(scored)
    for row in archived_envelopes or ():
        scored = _score_row(row, "archived")
        if scored is not None:
            out.append(scored)
    out.sort(key=lambda p: p["score"], reverse=True)
    return out


def top_precedent_ids(
    verb: str,
    grantee: str,
    bounds: dict,
    *,
    limit: int = 5,
    min_score: float = 0.1,
    include_archived: bool = True,
) -> list[str]:
    """Convenience: just the top-N envelope ids for embedding on a
    proposal row's ``precedent_ids`` field. Filters below ``min_score`` by
    default (0.1 keeps out near-zero matches that would just be noise on
    the operator ratify surface).

    PR11: ``include_archived`` defaults True so the ids include the
    operator's prior "no with reopen_when" alongside active envelopes.
    :func:`envelope_authoring.list_pending` (PR10 expansion) resolves
    each id back to the full row with its ``precedent_status`` so the
    surface can render active vs rejected differently."""
    ranked = similar_precedents(
        verb, grantee, bounds,
        min_score=min_score, include_archived=include_archived,
    )
    return [p["envelope_id"] for p in ranked[:limit] if p["envelope_id"]]
