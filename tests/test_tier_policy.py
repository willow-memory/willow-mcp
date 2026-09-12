"""Trust-tier ceiling (willow-gate seam Phase 3 / H2, D1) as tested code.

The manifest ACL says what an app *may* hold; tier_policy says what its *bound
trust level* may exercise. These tests pin the D1 table and — critically — that
the classification stays COMPLETE: a @_guarded tool added without a class would
silently escape (or over-restrict) the ceiling.
"""
import re
from pathlib import Path

import pytest

from willow_mcp import tier_policy as tp

_SERVER = Path(__file__).resolve().parents[1] / "src" / "willow_mcp" / "server.py"


_GUARDED_NAME_RE = re.compile(r"""@_guarded\(\s*['"]([a-zA-Z0-9_]+)['"]""")
_GUARDED_ANY_RE = re.compile(r"@_guarded\(")


def _guarded_tools() -> set[str]:
    """Every tool the server funnels through @_guarded — the exact set the tier
    ceiling must classify, read straight from source so it can't drift. Accepts
    either quote style."""
    src = _SERVER.read_text(encoding="utf-8")
    return set(_GUARDED_NAME_RE.findall(src))


def test_every_guarded_decorator_uses_a_string_literal_name():
    """The completeness check below rests on reading the tool name from the
    decorator source. If a @_guarded(...) ever used a variable/f-string/constant
    instead of a plain string literal, its name would not be extracted — the tool
    would silently escape BOTH this test and the tier ceiling (tier_permits waves
    through anything unclassified). Assert every @_guarded( is a literal form."""
    src = _SERVER.read_text(encoding="utf-8")
    assert len(_GUARDED_ANY_RE.findall(src)) == len(_GUARDED_NAME_RE.findall(src))


# ── completeness: the ceiling must classify every gated tool ──────────────────

def test_every_guarded_tool_has_a_class():
    missing = _guarded_tools() - set(tp.TOOL_CLASS)
    assert not missing, f"tier_policy.TOOL_CLASS is missing: {sorted(missing)}"


def test_no_stale_class_for_a_removed_tool():
    stale = set(tp.TOOL_CLASS) - _guarded_tools()
    assert not stale, f"tier_policy.TOOL_CLASS classifies non-guarded tools: {sorted(stale)}"


def test_every_class_is_a_known_rung():
    assert set(tp.TOOL_CLASS.values()) <= {tp.READ, tp.QUERY, tp.WRITE, tp.EXECUTE, tp.ADMIN}


# ── the cumulative ladder ─────────────────────────────────────────────────────

def test_ladder_is_monotone():
    prev = tp.unlocked_tools(0)
    for level in (1, 2, 3, 4):
        cur = tp.unlocked_tools(level)
        assert prev <= cur, f"level {level} is not a superset of {level - 1}"
        prev = cur


def test_exiled_unlocks_nothing():
    assert tp.unlocked_tools(0) == frozenset()


@pytest.mark.parametrize("level,tool,allowed", [
    # Rookie(1): read only
    (1, "store_get", True), (1, "store_put", False), (1, "task_submit", False),
    (1, "schema_confirm_mapping", False), (1, "session_bind", True),
    # Steady(2): + write
    (2, "store_put", True), (2, "lineage_record", True), (2, "task_submit", False),
    (2, "integration_call", False), (2, "gap_promote", False),
    # Veteran(3): + execute (incl. egress tool, non-read-only)
    (3, "task_submit", True), (3, "integration_call", True), (3, "agent_route", True),
    (3, "schema_confirm_mapping", False), (3, "gap_purge_topic", False),
    # Elder(4): + admin
    (4, "schema_confirm_mapping", True), (4, "gap_promote", True),
    (4, "gap_purge_topic", True), (4, "integration_call", True),
])
def test_tier_permits_matrix(level, tool, allowed):
    assert tp.tier_permits(level, tool) is allowed


# ── egress double-gate and read-only strip ────────────────────────────────────

def test_egress_tool_denied_on_a_read_only_tier_even_if_execute():
    # A read-only override must strip an egress tool regardless of level number.
    assert tp.tier_permits(3, "integration_call", read_only=True) is False
    assert tp.tier_permits(3, "integration_call", read_only=False) is True


def test_read_only_override_strips_write_and_execute():
    assert tp.tier_permits(4, "store_put", read_only=True) is False
    assert tp.tier_permits(4, "task_submit", read_only=True) is False
    assert tp.tier_permits(4, "store_get", read_only=True) is True


# ── tools the ceiling does not govern ─────────────────────────────────────────

def test_unclassified_tool_is_left_to_the_manifest():
    # whoami / diagnostic_summary aren't @_guarded — the ceiling waves them through.
    assert tp.classify("whoami") is None
    assert tp.tier_permits(0, "whoami") is True
    assert tp.tier_permits(4, "whoami") is True


def test_store_purge_stays_write_not_admin():
    # D1 edge call: reversible + confirm-guarded, so Steady may use it.
    assert tp.TOOL_CLASS["store_purge_collection"] == tp.WRITE
    assert tp.tier_permits(2, "store_purge_collection") is True


def test_bad_trust_level_fails_closed():
    assert tp.tier_permits("nonsense", "store_get") is False
    assert tp.tier_permits(None, "store_get") is False


def test_the_guarded_tool_scan_catches_a_planted_decorator(tmp_path, monkeypatch):
    """Planted: a server with two literal-named `@_guarded` decorators in the
    two quote styles, and one that names its tool through a constant — the
    exact escape `test_every_guarded_decorator_uses_a_string_literal_name`
    exists to catch. `_guarded_tools` must return the two literals and not the
    escapee, and the two patterns must disagree on the planted file."""
    planted = tmp_path / "server.py"
    planted.write_text(
        '@_guarded("store_put")\n'
        "def store_put(): ...\n"
        "@_guarded('planted_tool')\n"
        "def planted_tool(): ...\n"
        "@_guarded(TOOL_NAME)\n"
        "def escapes_the_scan(): ...\n",
        encoding="utf-8",
    )
    monkeypatch.setitem(globals(), "_SERVER", planted)
    assert _guarded_tools() == {"store_put", "planted_tool"}
    src = planted.read_text(encoding="utf-8")
    assert len(_GUARDED_ANY_RE.findall(src)) == 3
    assert len(_GUARDED_NAME_RE.findall(src)) == 2
