"""``canon_local`` held to the one script's ``canon.py`` (flatten-2, "2 carry copies").

An installed willow-mcp with no willow-bot beside must keep working, and
trust-owner code never reaches the one script (operator rulings 2026-10-21), so
willow-mcp carries ``canon_local``. This file lives OUTSIDE the trust path: it reaches
the one script and holds the copy to it.

It FAILS, never skips, when the one script is not beside (CI checks willow-bot
out; ``ONESCRIPT_HOME`` names it): a parity test that skips is no test.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from willow_mcp import onescript_reach, canon_local


@pytest.fixture(scope="module")
def one():
    try:
        return onescript_reach.module("canon")
    except onescript_reach.Unreachable as e:  # fail, do not skip
        pytest.fail(f"the one script's canon is not beside (set ONESCRIPT_HOME): {e}")


OBJS = [{"b": 1, "a": "é"}, ["x", 1, None, True, 1.5], {"k": {"z": [1, 2], "a": "\u2603"}}, "plain", 7]


def test_the_copy_is_the_one_scripts_bytes(one):
    assert Path(canon_local.__file__).read_bytes() == Path(one.__file__).read_bytes()


def _try(fn, obj):
    try:
        return fn(obj)
    except Exception as e:  # noqa: BLE001 - a refusal must be the same refusal
        return type(e).__name__


def test_every_encoding_gives_the_same_bytes_and_the_same_refusals(one):
    assert list(canon_local.ENCODINGS) == list(one.ENCODINGS)
    for n, theirs in one.ENCODINGS.items():
        mine = canon_local.ENCODINGS[n]
        assert (mine.name, mine.version, mine.families, mine.persisted) == (
            theirs.name, theirs.version, theirs.families, theirs.persisted), n
        for obj in OBJS + [float("nan"), {"a": float("inf")}]:
            assert _try(mine.bytes, obj) == _try(theirs.bytes, obj), (n, obj)
            assert _try(mine, obj) == _try(theirs, obj), (n, obj)


@pytest.mark.parametrize("name", ["sorted_compact_utf8", "wgrv-canon-b/v1", "compact_utf8", "nope"])
def test_get_agrees(one, name):
    try:
        theirs = one.get(name)
    except Exception as e:  # noqa: BLE001
        with pytest.raises(type(e)):
            canon_local.get(name)
        return
    assert canon_local.get(name).name == theirs.name
