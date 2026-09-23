"""pgp.expected_fingerprint() — one source of truth (dispatch B291C0C7,
amending A9BF01A9). $WILLOW_HOME/env is the one place
WILLOW_PGP_FINGERPRINT lives; the process environment is consulted only to
catch a leftover pin that disagrees with it. Three states: unset, set
(one source, or both agree), conflicting (raises rather than picking one
silently) — the exact lockout measured 2026-09-23 on the box."""
from __future__ import annotations

import pytest

from willow_mcp import pgp

_FPR_A = "9B6F87BEB4AE56E2" + "0" * 24
_FPR_B = "DEE471967EBCFA46" + "1" * 24


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    # pgp.py caches the $WILLOW_HOME/env read by (path, mtime, size); a
    # fresh tmp_path per test is a distinct path, so the cache never
    # leaks a value across tests without needing an explicit clear.
    yield


def _write_home_env(tmp_path, fingerprint: "str | None") -> None:
    text = f"WILLOW_PGP_FINGERPRINT={fingerprint}\n" if fingerprint else ""
    (tmp_path / "env").write_text(text, encoding="utf-8")


def test_unset_when_neither_source_has_a_value(tmp_path):
    assert pgp.expected_fingerprint() == ""


def test_set_from_home_env_alone(tmp_path):
    _write_home_env(tmp_path, _FPR_A)
    assert pgp.expected_fingerprint() == _FPR_A


def test_set_from_process_env_alone_home_env_absent(tmp_path):
    import os
    os.environ["WILLOW_PGP_FINGERPRINT"] = _FPR_A
    try:
        assert pgp.expected_fingerprint() == _FPR_A
    finally:
        del os.environ["WILLOW_PGP_FINGERPRINT"]


def test_set_when_both_sources_agree(tmp_path):
    import os
    _write_home_env(tmp_path, _FPR_A)
    os.environ["WILLOW_PGP_FINGERPRINT"] = _FPR_A
    try:
        assert pgp.expected_fingerprint() == _FPR_A
    finally:
        del os.environ["WILLOW_PGP_FINGERPRINT"]


def test_conflicting_raises_naming_both_values_and_home_env_path(tmp_path):
    import os
    _write_home_env(tmp_path, _FPR_A)
    os.environ["WILLOW_PGP_FINGERPRINT"] = _FPR_B
    try:
        with pytest.raises(pgp.PgpFingerprintConflict) as excinfo:
            pgp.expected_fingerprint()
    finally:
        del os.environ["WILLOW_PGP_FINGERPRINT"]
    message = str(excinfo.value)
    assert _FPR_A in message
    assert _FPR_B in message
    assert str(tmp_path / "env") in message


def test_never_silently_prefers_either_side_on_conflict(tmp_path):
    """The exact failure mode this dispatch closes: neither the process
    env's pin nor the file's value is trusted over the other when they
    disagree — both a repeated call and a differently-ordered write still
    refuse, never settle on one by chance."""
    import os
    _write_home_env(tmp_path, _FPR_B)
    os.environ["WILLOW_PGP_FINGERPRINT"] = _FPR_A
    try:
        for _ in range(3):
            with pytest.raises(pgp.PgpFingerprintConflict):
                pgp.expected_fingerprint()
    finally:
        del os.environ["WILLOW_PGP_FINGERPRINT"]


def test_case_and_whitespace_insensitive_comparison(tmp_path):
    """A file written lowercase and a process env set uppercase (or with
    incidental whitespace) must still be recognized as agreeing — this is
    a value comparison, not a byte comparison."""
    import os
    (tmp_path / "env").write_text(f"WILLOW_PGP_FINGERPRINT= {_FPR_A.lower()} \n", encoding="utf-8")
    os.environ["WILLOW_PGP_FINGERPRINT"] = _FPR_A
    try:
        assert pgp.expected_fingerprint() == _FPR_A
    finally:
        del os.environ["WILLOW_PGP_FINGERPRINT"]


def test_home_env_read_is_cached_until_the_file_changes(tmp_path):
    """Hot path (pgp.py's own docstring: expected_fingerprint() is called
    on every trust-owner-owned read) — the file is cached by
    (path, mtime, size) so an unrelated caller does not pay a fresh
    stat+read+parse every time. Editing the file (which changes its mtime
    and/or size) must still be picked up on the very next call, though."""
    _write_home_env(tmp_path, _FPR_A)
    assert pgp.expected_fingerprint() == _FPR_A
    _write_home_env(tmp_path, _FPR_B)
    assert pgp.expected_fingerprint() == _FPR_B


def test_home_env_ignores_comments_and_blank_lines(tmp_path):
    (tmp_path / "env").write_text(
        "\n# a comment\nOTHER_KEY=x\nWILLOW_PGP_FINGERPRINT=" + _FPR_A + "\n",
        encoding="utf-8",
    )
    assert pgp.expected_fingerprint() == _FPR_A


def test_home_env_missing_file_is_unset_not_an_error(tmp_path):
    assert not (tmp_path / "env").exists()
    assert pgp.expected_fingerprint() == ""
