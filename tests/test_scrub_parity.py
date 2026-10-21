"""``scrub_local`` held to the one script's ``scrub.py`` (flatten-2, trust closure).

Trust-owner code never reaches the one script (operator ruling 2026-10-21, "1 yes"),
and ``secret_scan`` / ``push_executor`` sit in that closure, so willow-mcp carries
``scrub_local``, a byte copy of ``onescript/scrub.py`` ("2 carry copies"). This file
lives OUTSIDE the trust path: it reaches the one script and holds the copy to it,
source byte for byte, then every named set and the ordered apply value for value.

It FAILS, never skips, when the one script is not beside (CI checks willow-bot out;
``ONESCRIPT_HOME`` names it): a parity test that skips is no test.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from willow_mcp import onescript_reach, scrub_local

SAMPLES = [
    "wrapAKIA" + "Q" * 16 + "wrap",
    "ghp_" + "a" * 36 + " and AIza" + "b" * 35 + "tail",
    "Authorization: Bearer abc.def.ghi\nnext line",
    "postgres://u:p@ss@host/db  DB_PASSWORD=hunter2  primary_key=True",
    "api_key = abcdefghijklmnop1234  gsk_" + "Z" * 24 + " csk-" + "Y" * 22,
    "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n",
    "seed: deadbeefdeadbeefdeadbeefdeadbeef  " + "f" * 64,
    "/home/x/.willow/vault/key",
    "task-" + "a1" * 10 + " nothing here",
]
ALL_SETS = tuple(scrub_local.SETS)


@pytest.fixture(scope="module")
def one():
    try:
        return onescript_reach.module("scrub")
    except onescript_reach.Unreachable as e:  # fail, do not skip
        pytest.fail(f"the one script's scrub is not beside (set ONESCRIPT_HOME): {e}")


def test_the_copy_is_the_one_scripts_bytes(one):
    assert Path(scrub_local.__file__).read_bytes() == Path(one.__file__).read_bytes()


def test_every_set_has_the_same_patterns(one):
    assert list(scrub_local.SETS) == list(one.SETS)
    for name in one.SETS:
        mine, theirs = scrub_local.SETS[name], one.SETS[name]
        assert len(mine) == len(theirs), name
        for a, b in zip(mine, theirs):
            assert (a.kind, a.whole, a.group, a.inside) == (b.kind, b.whole, b.group, b.inside)
            for x, y in ((a.rx, b.rx), (a.reject, b.reject)):
                assert (x is None) == (y is None)
                if x is not None:
                    assert (x.pattern, x.flags) == (y.pattern, y.flags), (name, a.kind)


def test_sensitive_key_pattern_is_the_same(one):
    assert (scrub_local.SENSITIVE_KEY.pattern, scrub_local.SENSITIVE_KEY.flags) == (
        one.SENSITIVE_KEY.pattern,
        one.SENSITIVE_KEY.flags,
    )


@pytest.mark.parametrize("text", SAMPLES)
def test_apply_and_find_give_the_same_values(one, text):
    for sets in (ALL_SETS, ("credentials",), ("git_trace", "credentials"),
                 ("credentials", "journal_kv"), ("secret_path", "credentials")):
        mine_found, their_found = set(), set()
        assert scrub_local.apply(text, sets, found=mine_found) == one.apply(
            text, sets, found=their_found
        )
        assert mine_found == their_found
    assert scrub_local.find(text, ("credentials_bounded", "assigned_credential")) == one.find(
        text, ("credentials_bounded", "assigned_credential")
    )
    assert scrub_local.found_kinds(text, ALL_SETS) == one.found_kinds(text, ALL_SETS)


def test_keys_and_urls_agree(one):
    for k in ("api_key", "filename", "Cookie", "dsn"):
        assert scrub_local.sensitive_key(k) == one.sensitive_key(k)
    for u in ("http://[::1]:9000/webhook", "https://u:p@smee.io/AbC123?x=1", "nope"):
        assert scrub_local.redact_url(u) == one.redact_url(u)

