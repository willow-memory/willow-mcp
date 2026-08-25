"""PR7: envelope_shapes — precedent recall for envelope proposals.

Pins the load-bearing invariants:
* Verb match is mandatory (different verbs are unrelated).
* Grantee overlap is mandatory (glob and list forms handled).
* Bounds scored per field: exact = 1.0, fnmatch equivalence = 0.8, path
  prefix decays from 0.5, numeric decays by ratio, missing = 0.0.
* Overall score is the mean; results sorted desc.
* propose() populates precedent_ids from top_precedent_ids when the
  caller didn't supply one explicitly.
* Caller-supplied precedent_ids wins over auto-recall (explicit override).
* Recall failure inside propose is swallowed — propose still writes the
  proposal (recall is best-effort).
"""
from __future__ import annotations

import json
import os
from unittest import mock

import pytest

from willow_mcp import (
    envelope_authoring as ea,
    envelope_shapes as es,
    human_session,
    keyring as keyring_mod,
)


# --- fixtures --------------------------------------------------------------


@pytest.fixture
def ring_with_rita(tmp_path):
    human_session.clear_attribution_cache()
    with keyring_mod.isolated():
        k = keyring_mod.Keyring(path=str(tmp_path / "keys.json"))
        k.add("rita")
        k.save()
        keyring_mod.set_keyring(k)
        human_session._remember_attributed("s-orch-shapes")
        try:
            yield k
        finally:
            keyring_mod.set_keyring(None)
            human_session.clear_attribution_cache()


@pytest.fixture
def registry_with_paths_verb(tmp_path, monkeypatch):
    """Registry + syscall table with a 'demo_paths' verb whose bounds are
    {path_pattern, max_bytes} — same shape earlier fixtures use, hoisted
    here so the tests below don't conflict on same-app-id session records
    from other test files."""
    registry_path = tmp_path / "pre-approved.json"
    syscall_path = tmp_path / "syscall-table.json"
    registry_path.write_text(
        json.dumps({
            "schema": "envelope-registry/v1.1",
            "active": [], "proposals": [],
        }, indent=2), encoding="utf-8",
    )
    syscall_path.write_text(
        json.dumps({
            "verbs": [
                {"id": 900, "verb": "demo_paths",
                 "bounds": {"path_pattern": "", "max_bytes": 0}},
                {"id": 901, "verb": "demo_other",
                 "bounds": {"path_pattern": "", "max_bytes": 0}},
            ]
        }, indent=2), encoding="utf-8",
    )
    os.chmod(str(registry_path), 0o600)
    os.chmod(str(syscall_path), 0o600)
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(registry_path))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(syscall_path))
    return registry_path


def _envelope(id_, verb, grantee, bounds):
    return {
        "id": id_,
        "verb": verb,
        "grantee": grantee,
        "bounds": bounds,
        "status": "active",
    }


# --- _field_similarity ---------------------------------------------------


def test_exact_equality_scores_1():
    assert es._field_similarity("docs/", "docs/") == 1.0
    assert es._field_similarity(1024, 1024) == 1.0
    assert es._field_similarity(True, True) == 1.0


def test_fnmatch_glob_equivalence_scores_0_8():
    # A concrete value matched by a glob pattern
    assert es._field_similarity("docs/**", "docs/README.md") == 0.8
    assert es._field_similarity("docs/README.md", "docs/**") == 0.8


def test_path_prefix_decays_from_0_5():
    # commonprefix "docs/" of length 5 vs "docs/README.md" length 14 → 0.5 * 5/14
    score = es._field_similarity("docs/README.md", "docs/CHANGELOG.md")
    assert 0.0 < score <= 0.5
    # Exactly-equal prefix + short strings
    score2 = es._field_similarity("src/", "src/")
    assert score2 == 1.0  # exact equality wins the fast path


def test_non_overlapping_strings_score_0():
    assert es._field_similarity("docs/foo", "src/bar") == 0.0


def test_numeric_ratio_decays():
    assert es._field_similarity(1024, 1024) == 1.0
    assert es._field_similarity(1000, 2000) == 0.5
    # Sign mismatch → 0
    assert es._field_similarity(100, -100) == 0.0
    # Zero handling
    assert es._field_similarity(0, 100) == 0.0


def test_type_mismatch_scores_0():
    assert es._field_similarity("docs/", 1024) == 0.0
    assert es._field_similarity({"a": 1}, ["a", 1]) == 0.0


# --- similar_precedents --------------------------------------------------


def test_precedent_requires_verb_match():
    precedents = [
        _envelope("env-1", "demo_paths", "hanuman", {"path_pattern": "docs/**", "max_bytes": 1024}),
    ]
    got = es.similar_precedents(
        "demo_other", "hanuman", {"path_pattern": "docs/**", "max_bytes": 1024},
        active_envelopes=precedents,
    )
    assert got == [], "different verb → no precedents"


def test_precedent_requires_grantee_overlap():
    precedents = [
        _envelope("env-1", "demo_paths", "hanuman", {"path_pattern": "docs/**", "max_bytes": 1024}),
    ]
    got = es.similar_precedents(
        "demo_paths", "loki", {"path_pattern": "docs/**", "max_bytes": 1024},
        active_envelopes=precedents,
    )
    assert got == [], "different grantee → no precedents"


def test_grantee_list_overlap():
    """The registry allows grantee = list of app_ids. Membership counts."""
    precedents = [
        _envelope("env-1", "demo_paths", ["hanuman", "loki"], {"path_pattern": "docs/**", "max_bytes": 1024}),
    ]
    got = es.similar_precedents(
        "demo_paths", "loki", {"path_pattern": "docs/**", "max_bytes": 1024},
        active_envelopes=precedents,
    )
    assert len(got) == 1
    assert got[0]["envelope_id"] == "env-1"


def test_exact_match_scores_1():
    precedents = [
        _envelope("env-a", "demo_paths", "hanuman", {"path_pattern": "docs/**", "max_bytes": 1024}),
    ]
    got = es.similar_precedents(
        "demo_paths", "hanuman", {"path_pattern": "docs/**", "max_bytes": 1024},
        active_envelopes=precedents,
    )
    assert len(got) == 1
    assert got[0]["score"] == 1.0
    assert got[0]["matching_bounds"] == ["max_bytes", "path_pattern"]
    assert got[0]["differing_bounds"] == []


def test_partial_match_scores_between_0_and_1():
    """Same path_pattern (1.0) + different max_bytes (ratio-based) → mean is between."""
    precedents = [
        _envelope("env-p", "demo_paths", "hanuman", {"path_pattern": "docs/**", "max_bytes": 1024}),
    ]
    got = es.similar_precedents(
        "demo_paths", "hanuman", {"path_pattern": "docs/**", "max_bytes": 2048},
        active_envelopes=precedents,
    )
    assert len(got) == 1
    # (1.0 + 0.5) / 2 = 0.75
    assert 0.7 < got[0]["score"] < 0.8
    assert got[0]["matching_bounds"] == ["path_pattern"]
    assert got[0]["differing_bounds"] == ["max_bytes"]


def test_results_sorted_descending_by_score():
    precedents = [
        # closest (fnmatch on path — 0.8; exact max_bytes — 1.0; mean 0.9)
        _envelope("env-close", "demo_paths", "hanuman",
                  {"path_pattern": "docs/**", "max_bytes": 1024}),
        # medium (path prefix — decays; different max_bytes — ratio)
        _envelope("env-medium", "demo_paths", "hanuman",
                  {"path_pattern": "docs/notes/README.md", "max_bytes": 512}),
        # distant (no overlap)
        _envelope("env-far", "demo_paths", "hanuman",
                  {"path_pattern": "src/**", "max_bytes": 1}),
    ]
    got = es.similar_precedents(
        "demo_paths", "hanuman",
        {"path_pattern": "docs/README.md", "max_bytes": 1024},
        active_envelopes=precedents,
    )
    ids = [p["envelope_id"] for p in got]
    assert ids == ["env-close", "env-medium", "env-far"] or ids[0] == "env-close", (
        f"env-close must be at top; got order {ids}"
    )
    # Strictly descending
    scores = [p["score"] for p in got]
    assert scores == sorted(scores, reverse=True)


def test_min_score_filter_hides_near_zero():
    precedents = [
        _envelope("env-close", "demo_paths", "hanuman",
                  {"path_pattern": "docs/**", "max_bytes": 1024}),
        _envelope("env-noise", "demo_paths", "hanuman",
                  {"path_pattern": "totally-different", "max_bytes": 999999}),
    ]
    got = es.similar_precedents(
        "demo_paths", "hanuman",
        {"path_pattern": "docs/**", "max_bytes": 1024},
        active_envelopes=precedents, min_score=0.5,
    )
    ids = [p["envelope_id"] for p in got]
    assert "env-close" in ids
    assert "env-noise" not in ids, "min_score should filter near-zero matches"


def test_precedent_with_extra_bounds_key_still_scored():
    """A precedent that granted MORE fields than this proposal asks for is
    still relevant — the extras contribute 0 for missing-in-proposal, but
    the precedent shows up so the operator can see them."""
    precedents = [
        _envelope("env-extras", "demo_paths", "hanuman",
                  {"path_pattern": "docs/**", "max_bytes": 1024, "extra_field": "x"}),
    ]
    got = es.similar_precedents(
        "demo_paths", "hanuman",
        {"path_pattern": "docs/**", "max_bytes": 1024},
        active_envelopes=precedents,
    )
    assert len(got) == 1
    # 2 exact matches + 1 missing → mean = 2/3
    assert 0.6 < got[0]["score"] < 0.7
    assert "extra_field" in got[0]["differing_bounds"]
    # Full precedent bounds surface so operator sees the extras
    assert got[0]["precedent_bounds"]["extra_field"] == "x"


# --- top_precedent_ids ---------------------------------------------------


def test_top_precedent_ids_returns_ids_only():
    precedents = [
        _envelope("env-a", "demo_paths", "hanuman",
                  {"path_pattern": "docs/**", "max_bytes": 1024}),
        _envelope("env-b", "demo_paths", "hanuman",
                  {"path_pattern": "docs/README.md", "max_bytes": 1024}),
    ]
    with mock.patch.object(ea, "list_active", return_value=precedents):
        ids = es.top_precedent_ids(
            "demo_paths", "hanuman",
            {"path_pattern": "docs/**", "max_bytes": 1024},
        )
    assert "env-a" in ids  # exact match at top
    assert isinstance(ids, list)
    assert all(isinstance(x, str) for x in ids)


def test_top_precedent_ids_respects_limit():
    precedents = [
        _envelope(f"env-{i}", "demo_paths", "hanuman",
                  {"path_pattern": f"docs/file{i}.md", "max_bytes": 1024})
        for i in range(10)
    ]
    with mock.patch.object(ea, "list_active", return_value=precedents):
        ids = es.top_precedent_ids(
            "demo_paths", "hanuman",
            {"path_pattern": "docs/target.md", "max_bytes": 1024},
            limit=3,
        )
    assert len(ids) <= 3


# --- propose() integration -----------------------------------------------


def test_propose_populates_precedent_ids_from_recall(
    ring_with_rita, registry_with_paths_verb
):
    """propose() with precedent_ids=None (default) should auto-populate
    from top_precedent_ids."""
    # Seed an active envelope by proposing + ratifying one first
    p1 = ea.propose(
        verb="demo_paths", grantee="hanuman",
        bounds={"path_pattern": "docs/**", "max_bytes": 1024},
        reason="baseline", verifier="rita", session_id="s-orch-shapes",
    )
    ratified = ea.ratify(p1["id"], verifier="rita")
    assert ratified["status"] == "active"

    # Now propose a similar shape — precedent recall should pick up p1
    p2 = ea.propose(
        verb="demo_paths", grantee="hanuman",
        bounds={"path_pattern": "docs/README.md", "max_bytes": 1024},
        reason="second", verifier="rita", session_id="s-orch-shapes",
    )
    assert ratified["id"] in p2["precedent_ids"], (
        f"precedent recall didn't find the active envelope; "
        f"got precedent_ids={p2['precedent_ids']!r}"
    )


def test_propose_precedent_ids_explicit_wins(
    ring_with_rita, registry_with_paths_verb
):
    """Caller-supplied precedent_ids overrides auto-recall."""
    p = ea.propose(
        verb="demo_paths", grantee="hanuman",
        bounds={"path_pattern": "docs/**", "max_bytes": 1024},
        reason="explicit", verifier="rita", session_id="s-orch-shapes",
        precedent_ids=["env-caller-supplied-1", "env-caller-supplied-2"],
    )
    assert p["precedent_ids"] == ["env-caller-supplied-1", "env-caller-supplied-2"]


def test_propose_precedent_recall_failure_is_swallowed(
    ring_with_rita, registry_with_paths_verb
):
    """If envelope_shapes.top_precedent_ids raises, propose still succeeds
    with an empty precedent_ids list. Recall is best-effort — never blocks
    propose."""
    with mock.patch.object(
        es, "top_precedent_ids", side_effect=RuntimeError("recall broken")
    ):
        p = ea.propose(
            verb="demo_paths", grantee="hanuman",
            bounds={"path_pattern": "docs/**", "max_bytes": 1024},
            reason="recall-fails-gracefully",
            verifier="rita", session_id="s-orch-shapes",
        )
    assert p["precedent_ids"] == []
    assert p["status"] == "proposed"  # write still landed


def test_propose_precedent_ids_empty_when_no_active_envelopes(
    ring_with_rita, registry_with_paths_verb
):
    """A first-of-its-kind proposal has no precedents."""
    p = ea.propose(
        verb="demo_paths", grantee="hanuman",
        bounds={"path_pattern": "docs/**", "max_bytes": 1024},
        reason="first", verifier="rita", session_id="s-orch-shapes",
    )
    assert p["precedent_ids"] == []
