"""``clock_local`` held to the one script's ``clock.py`` (flatten-2, "2 carry copies").

An installed willow-mcp with no willow-bot beside must keep working, and
trust-owner code never reaches the one script (operator rulings 2026-10-21), so
willow-mcp carries ``clock_local``. This file lives OUTSIDE the trust path: it reaches
the one script and holds the copy to it.

It FAILS, never skips, when the one script is not beside (CI checks willow-bot
out; ``ONESCRIPT_HOME`` names it): a parity test that skips is no test.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from willow_mcp import onescript_reach, clock_local


@pytest.fixture(scope="module")
def one():
    try:
        return onescript_reach.module("clock")
    except onescript_reach.Unreachable as e:  # fail, do not skip
        pytest.fail(f"the one script's clock is not beside (set ONESCRIPT_HOME): {e}")


PIN = "2026-10-20T12:00:00.123456Z"


def test_the_copy_is_the_one_scripts_bytes(one):
    assert Path(clock_local.__file__).read_bytes() == Path(one.__file__).read_bytes()


def test_pinned_formats_agree(one, monkeypatch):
    monkeypatch.setenv("ONESCRIPT_NOW", PIN)
    assert clock_local.now() == one.now()
    for fn in ("seconds_z", "isoformat_utc", "isoformat_seconds_utc"):
        assert getattr(clock_local, fn)() == getattr(one, fn)(), fn
    assert clock_local.pinned() == one.pinned()


@pytest.mark.parametrize("text", ["2026-10-20T05:00:00-07:00", "2026-01-02T03:04:05.5Z"])
def test_parse_pin_agrees(one, text):
    assert clock_local.parse_pin(text) == one.parse_pin(text)
