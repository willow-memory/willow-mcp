"""willow-gate is a dependency, taken the way forge-play was (#419).

The gate's trust ladder is the fleet's one ladder. Until 2026-09-03 willow-mcp
kept two hand-written twins of it (session_binder.TRUST_LEVELS, the logging
view; tier_policy._TIER_CLASSES, the enforcement ceiling), pinned to the gate
only by a golden vector in both repos' tests/test_trust_ladder_canonical.py.
These tests pin the take itself: the twins are now derived from
`willow_gate.TRUST_LEVELS` — the same object, read in each caller's shape —
and importing the gate never pulls willow_mcp in (the arrow points one way).
The golden-vector test is kept beside these as the independent check.
"""
from __future__ import annotations

import importlib.metadata as metadata
import sys

import pytest

willow_gate = pytest.importorskip("willow_gate", reason="willow-gate is a declared runtime dependency")

from willow_mcp import session_binder, tier_policy  # noqa: E402


def test_willow_gate_is_installed_within_the_declared_range():
    v = metadata.version("willow-gate")
    assert int(v.split(".")[0]) < 1, f"willow-gate {v} is outside the <1.0.0 range this tree declares"


def test_session_binder_ladder_is_the_gates():
    assert session_binder._GATE_LEVELS is willow_gate.TRUST_LEVELS
    assert session_binder.TRUST_LEVELS == {
        n: (tl.name, tl.read_only) for n, tl in willow_gate.TRUST_LEVELS.items()
    }


def test_tier_policy_ceiling_is_the_gates_allowed_tools_plus_query_as_read():
    assert tier_policy._GATE_LEVELS is willow_gate.TRUST_LEVELS
    for n, tl in willow_gate.TRUST_LEVELS.items():
        expected = set(tl.allowed_tools)
        if "read" in expected:
            expected.add("query")
        assert tier_policy._TIER_CLASSES[n] == frozenset(expected), n
    assert tier_policy._READ_ONLY_LEVELS == frozenset(
        n for n, tl in willow_gate.TRUST_LEVELS.items() if tl.read_only
    )


def test_the_ladder_still_reads_as_it_did():
    # The shape every caller already relied on — unchanged by the take.
    assert session_binder.TRUST_LEVELS == {
        0: ("Exiled", True), 1: ("Rookie", True), 2: ("Steady", False),
        3: ("Veteran", False), 4: ("Elder", False),
    }
    assert tier_policy._READ_ONLY_LEVELS == frozenset({0, 1})
    assert tier_policy.tier_permits(1, "store_get") and not tier_policy.tier_permits(1, "store_put")


def test_the_gate_never_imports_willow_mcp():
    before = {m for m in sys.modules if m.startswith("willow_mcp")}
    import willow_gate.custody, willow_gate.message_integrity, willow_gate.friction_floor, willow_gate.trust_scale  # noqa: F401,E401
    after = {m for m in sys.modules if m.startswith("willow_mcp")}
    assert after == before, "importing willow_gate pulled in willow_mcp — the arrow points one way"
