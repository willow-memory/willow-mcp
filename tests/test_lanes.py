"""Lanes are mutually sealed; a crossing is the only way through, and it must
be forgeable in none of the obvious ways.

This suite exists because the marking was already there and enforced nowhere.
`kb_ingest` has taken `sensitivity` since it was written, defaulting to
`"sensitive"`. Measured on the live store 2026-08-28: 10,975 rows `sensitive`,
10,939 `open`, and `knowledge_search` mentions the field zero times. Every row
carried its classification and nothing ever read it.

So the tests that matter are not "does a Crossing hold its fields" — they are
the ways a crossing could be made to permit something nobody signed for.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from willow_mcp.lanes import (
    Crossing,
    CrossingError,
    Lane,
    permits,
    refusal,
    response_lane,
)

NOW = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)
LATER = NOW + timedelta(hours=1)


def _crossing(**kw) -> Crossing:
    base = dict(
        from_lane=Lane.SYSTEM,
        to_lane=Lane.PERSONAL,
        purpose="reconcile the household ledger against the fleet's task log",
        signed_by="sean",
        signed_at=NOW,
        expires_at=LATER,
    )
    base.update(kw)
    return Crossing(**base)


# ── lane membership ────────────────────────────────────────────────────────

def test_the_existing_sensitivity_vocabulary_maps_to_lanes():
    """The mapping is read off what the store holds, not imposed on it."""
    assert Lane.of("open") == Lane.SYSTEM
    assert Lane.of("sensitive") == Lane.PERSONAL


@pytest.mark.parametrize("value", [None, "", "   ", "unknown", "SENSITIVE-ish", "0"])
def test_an_unclassified_row_is_personal_not_open(value):
    """Fail closed. An unmarked row is not a row proven open — it is a row
    nobody classified, and the two mistakes do not cost the same."""
    assert Lane.of(value) == Lane.PERSONAL


def test_case_and_whitespace_do_not_change_a_lane():
    assert Lane.of("  OPEN  ") == Lane.SYSTEM
    assert Lane.of("Sensitive") == Lane.PERSONAL


def test_lanes_cannot_be_ordered():
    """Rule 14, ported: personal is not *more* than system, it is *other* than
    system, so an ordering operator must not answer at all.

    This test caught a real defect in the first draft, which used two bare
    module-level strings — `"system" < "personal"` is valid Python and answers
    alphabetically, silently. An Enum refuses instead.
    """
    with pytest.raises(TypeError):
        Lane.SYSTEM < Lane.PERSONAL
    with pytest.raises(TypeError):
        Lane.SYSTEM > Lane.PERSONAL
    with pytest.raises(TypeError):
        Lane.SYSTEM <= Lane.PERSONAL
    with pytest.raises(TypeError):
        sorted([Lane.PERSONAL, Lane.SYSTEM])
    assert Lane.SYSTEM is not Lane.PERSONAL


# ── the ways a crossing must refuse to exist ───────────────────────────────

def test_a_crossing_must_name_both_lanes():
    with pytest.raises(CrossingError, match="both lanes"):
        _crossing(to_lane="")


def test_a_crossing_naming_one_lane_twice_is_not_a_crossing():
    with pytest.raises(CrossingError, match="one lane twice"):
        _crossing(from_lane=Lane.PERSONAL, to_lane=Lane.PERSONAL)


def test_a_crossing_to_an_unknown_lane_is_refused():
    with pytest.raises(CrossingError, match="unknown lane"):
        _crossing(to_lane="secret")


@pytest.mark.parametrize("purpose", ["", "   ", "\n\t "])
def test_a_crossing_without_a_purpose_is_refused(purpose):
    with pytest.raises(CrossingError, match="purpose"):
        _crossing(purpose=purpose)


@pytest.mark.parametrize(
    "signer",
    ["system", "agent", "guardian", "the director", "operator", "willow",
     "claude", "bot", "MCP", "  Automation  ", ""],
)
def test_a_role_cannot_sign_a_crossing(signer):
    """The point of a guardian's signature is that it is not the system
    granting itself passage. Case and padding must not smuggle one through."""
    with pytest.raises(CrossingError, match="not a guardian's signature"):
        _crossing(signed_by=signer)


def test_a_person_can_sign():
    assert _crossing(signed_by="sean").signed_by == "sean"


@pytest.mark.parametrize("delta", [timedelta(0), timedelta(seconds=-1), timedelta(days=-1)])
def test_a_crossing_without_a_future_expiry_is_a_standing_grant(delta):
    with pytest.raises(CrossingError, match="standing grant"):
        _crossing(expires_at=NOW + delta)


def test_a_crossing_is_frozen():
    c = _crossing()
    with pytest.raises(Exception):
        c.purpose = "something else"  # type: ignore[misc]


# ── permits(): direction and liveness ──────────────────────────────────────

def test_a_live_crossing_permits_its_own_direction():
    c = _crossing()
    assert permits([c], from_lane=Lane.SYSTEM, to_lane=Lane.PERSONAL, at=NOW) is c


def test_a_crossing_does_not_permit_the_reverse_direction():
    """One signature must never open two seals."""
    c = _crossing(from_lane=Lane.SYSTEM, to_lane=Lane.PERSONAL)
    assert permits([c], from_lane=Lane.PERSONAL, to_lane=Lane.SYSTEM, at=NOW) is None


def test_an_expired_crossing_does_not_permit():
    c = _crossing()
    assert permits([c], from_lane=Lane.SYSTEM, to_lane=Lane.PERSONAL,
                   at=LATER + timedelta(seconds=1)) is None


def test_a_crossing_is_not_live_before_it_was_signed():
    c = _crossing()
    assert permits([c], from_lane=Lane.SYSTEM, to_lane=Lane.PERSONAL,
                   at=NOW - timedelta(seconds=1)) is None


def test_expiry_is_exclusive_at_the_instant_it_expires():
    c = _crossing()
    assert permits([c], from_lane=Lane.SYSTEM, to_lane=Lane.PERSONAL, at=LATER) is None


def test_no_crossings_permits_nothing():
    assert permits([], from_lane=Lane.SYSTEM, to_lane=Lane.PERSONAL, at=NOW) is None


# ── I-12: a response is scored whole, not per row ──────────────────────────

def test_a_response_holding_any_personal_row_is_personal():
    """The hole a per-row check leaves open: one personal row ranks into a
    semantic search's neighbours and the crossing happens unsigned."""
    assert response_lane(["open", "open", "sensitive"]) == Lane.PERSONAL
    assert response_lane(["open", "open"]) == Lane.SYSTEM


def test_an_unmarked_row_makes_the_whole_response_personal():
    assert response_lane(["open", None]) == Lane.PERSONAL


def test_an_empty_response_is_system():
    """Nothing withheld, nothing to seal."""
    assert response_lane([]) == Lane.SYSTEM


# ── refusal(): the recorded negative ───────────────────────────────────────

def test_same_lane_needs_no_crossing():
    assert refusal(rows_sensitivity=["open", "open"], reader_lane=Lane.SYSTEM) is None


def test_reading_personal_from_system_without_a_crossing_is_refused():
    r = refusal(rows_sensitivity=["open", "sensitive"], reader_lane=Lane.SYSTEM, at=NOW)
    assert r is not None
    assert r["refused"] is True
    # serialized as plain strings, because a refusal crosses the MCP wire
    assert r["holding_lane"] == Lane.PERSONAL.value == "personal"
    assert r["reader_lane"] == Lane.SYSTEM.value == "system"


def test_a_refusal_says_what_would_permit_it():
    """A refusal that teaches beats one that merely blocks — the same reason
    nestor names SEAL_AUTHORITY fields apart instead of silently dropping them."""
    r = refusal(rows_sensitivity=["sensitive"], reader_lane=Lane.SYSTEM, at=NOW)
    assert "guardian-signed" in r["what_would_permit"]
    assert "expiry" in r["what_would_permit"]


def test_a_live_crossing_lifts_the_refusal():
    r = refusal(rows_sensitivity=["sensitive"], reader_lane=Lane.SYSTEM,
                crossings=[_crossing()], at=NOW)
    assert r is None


def test_an_expired_crossing_does_not_lift_the_refusal():
    r = refusal(rows_sensitivity=["sensitive"], reader_lane=Lane.SYSTEM,
                crossings=[_crossing()], at=LATER + timedelta(seconds=1))
    assert r is not None


def test_a_crossing_in_the_wrong_direction_does_not_lift_the_refusal():
    wrong = _crossing(from_lane=Lane.PERSONAL, to_lane=Lane.SYSTEM)
    r = refusal(rows_sensitivity=["sensitive"], reader_lane=Lane.SYSTEM,
                crossings=[wrong], at=NOW)
    assert r is not None


def test_the_guard_can_fail():
    """Prove-it-can-fail: a gate that cannot refuse is not a gate. If refusal()
    were rewritten to always return None, every assertion above that expects a
    refusal would break — this one names the property directly."""
    unguarded = refusal(rows_sensitivity=["sensitive"], reader_lane=Lane.SYSTEM,
                        crossings=[], at=NOW)
    assert unguarded is not None, (
        "an unmarked personal row with no crossing must refuse; a gate that "
        "always permits is decorative, which is the defect this module fixes"
    )
