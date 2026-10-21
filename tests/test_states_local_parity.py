"""``states_local`` held to the one script's ``states.py`` (flatten-2, "2 carry copies").

An installed willow-mcp with no willow-bot beside must keep working, and
trust-owner code never reaches the one script (operator rulings 2026-10-21), so
willow-mcp carries ``states_local``. This file lives OUTSIDE the trust path: it reaches
the one script and holds the copy to it.

It FAILS, never skips, when the one script is not beside (CI checks willow-bot
out; ``ONESCRIPT_HOME`` names it): a parity test that skips is no test.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from willow_mcp import onescript_reach, states_local


@pytest.fixture(scope="module")
def one():
    try:
        return onescript_reach.module("states")
    except onescript_reach.Unreachable as e:  # fail, do not skip
        pytest.fail(f"the one script's states is not beside (set ONESCRIPT_HOME): {e}")


def test_the_copy_is_the_one_scripts_bytes(one):
    assert Path(states_local.__file__).read_bytes() == Path(one.__file__).read_bytes()


def test_every_public_name_has_the_same_value(one):
    names = [n for n in vars(one) if n.isupper()]
    assert names, "the one script's states has no constants?"
    for n in names:
        assert getattr(states_local, n) == getattr(one, n), n


@pytest.mark.parametrize("rows", [None, [], [1], (), "x"])
def test_state_of_agrees(one, rows):
    assert states_local.state_of(rows) == one.state_of(rows)


@pytest.mark.parametrize("word", ["populated", "empty", "unreachable", "ranked", "held", "none", "escalated:cold_start", "", None, 3])
def test_checked_and_base_of_agree(one, word):
    assert states_local.checked(word) == one.checked(word)
    assert states_local.base_of(word) == one.base_of(word)


def test_the_words_the_trust_closure_writes_are_the_persisted_bytes():
    assert (states_local.POPULATED, states_local.EMPTY, states_local.UNREACHABLE) == (
        "populated", "empty", "unreachable")
    assert states_local.REPORT_KEYS == ("populated", "empty", "unreachable")
