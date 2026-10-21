"""``sign_local`` held to the one script's ``sign.py`` (flatten-2, "2 carry copies").

An installed willow-mcp with no willow-bot beside must keep working, and
trust-owner code never reaches the one script (operator rulings 2026-10-21), so
willow-mcp carries ``sign_local``. This file lives OUTSIDE the trust path: it reaches
the one script and holds the copy to it.

It FAILS, never skips, when the one script is not beside (CI checks willow-bot
out; ``ONESCRIPT_HOME`` names it): a parity test that skips is no test.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from willow_mcp import onescript_reach, sign_local


@pytest.fixture(scope="module")
def one():
    try:
        return onescript_reach.module("sign")
    except onescript_reach.Unreachable as e:  # fail, do not skip
        pytest.fail(f"the one script's sign is not beside (set ONESCRIPT_HOME): {e}")


KEY = b"k" * 32


def test_the_copy_is_the_one_scripts_bytes_but_for_the_canon_line(one):
    mine = Path(sign_local.__file__).read_text(encoding="utf-8")
    theirs = Path(one.__file__).read_text(encoding="utf-8")
    assert mine.count("from . import canon_local as canon\n") == 1
    assert mine.replace("from . import canon_local as canon\n", "from . import canon\n") == theirs


def test_public_functions_are_the_same_set(one):
    pub = lambda m: sorted(n for n, v in vars(m).items() if callable(v) and not n.startswith("_") and getattr(v, "__module__", "") == m.__name__)  # noqa: E731
    assert pub(sign_local) == pub(one)


def test_hmac_and_seal_message_agree(one):
    assert sign_local.hmac_hex(KEY, b"msg") == one.hmac_hex(KEY, b"msg")
    sig = one.hmac_hex(KEY, b"msg")
    assert sign_local.hmac_equal(sig, sig) is True and sign_local.hmac_equal(sig, "0" * 64) is False
    assert sign_local.seal_message("src", "target", "ver") == one.seal_message("src", "target", "ver")
