"""pgp.expected_fingerprint() — one source of truth (dispatch B291C0C7,
amending A9BF01A9; reworked by E29CCFC7/0CB0C85C per Loki audit A38D41C2).

The one source of truth is $WILLOW_HOME/constitutional/trust.env —
trust-owner-owned, world-readable (0CB0C85C: a fingerprint is public, only
a key's private half is a secret, so it does not belong in $WILLOW_HOME/env
beside every provider API key). The process environment is consulted only
to catch a leftover pin that disagrees with it.

Three states, never collapsed (Loki A38D41C2, F4 — "unreachable is not
empty"): unset (neither source has a value, OR the file genuinely does not
exist — legitimate bootstrap), set (one source has it, or both agree),
conflicting (raises rather than picking one silently). A FOURTH state this
module must never collapse into "unset": the file EXISTS but cannot be
trusted (unreadable, wrong ownership, or a malformed value) — that raises
PgpSourceUnreadable, distinct from PgpFingerprintConflict."""
from __future__ import annotations

import os

import pytest

from willow_mcp import pgp

_FPR_A = "9B6F87BEB4AE56E2" + "0" * 24
_FPR_B = "DEE471967EBCFA46" + "1" * 24


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    yield


def _trust_dir(tmp_path):
    d = tmp_path / "constitutional"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _write_trust_env(tmp_path, fingerprint: "str | None") -> None:
    d = _trust_dir(tmp_path)
    text = f"WILLOW_PGP_FINGERPRINT={fingerprint}\n" if fingerprint else ""
    (d / "trust.env").write_text(text, encoding="utf-8")


# ── the three (plus one) states ─────────────────────────────────────────

def test_unset_when_neither_source_has_a_value(tmp_path):
    assert pgp.expected_fingerprint() == ""


def test_unset_when_the_file_does_not_exist_at_all_legitimate_bootstrap(tmp_path):
    """A box that has never configured PGP at all has no constitutional/
    directory, let alone trust.env — this must still resolve to unset, not
    raise. Distinguishing "never configured" from "configured but now
    broken" is the whole point of F4; conflating them the other way
    (treating a legitimately-absent file as an error) would be its own
    bug — a fresh install could never boot with PGP off at all."""
    assert not (tmp_path / "constitutional").exists()
    assert pgp.expected_fingerprint() == ""


def test_set_from_trust_env_alone(tmp_path):
    _write_trust_env(tmp_path, _FPR_A)
    assert pgp.expected_fingerprint() == _FPR_A


def test_set_from_process_env_alone_trust_env_absent(tmp_path):
    os.environ["WILLOW_PGP_FINGERPRINT"] = _FPR_A
    try:
        assert pgp.expected_fingerprint() == _FPR_A
    finally:
        del os.environ["WILLOW_PGP_FINGERPRINT"]


def test_set_when_both_sources_agree(tmp_path):
    _write_trust_env(tmp_path, _FPR_A)
    os.environ["WILLOW_PGP_FINGERPRINT"] = _FPR_A
    try:
        assert pgp.expected_fingerprint() == _FPR_A
    finally:
        del os.environ["WILLOW_PGP_FINGERPRINT"]


def test_conflicting_raises_naming_both_values_and_trust_env_path(tmp_path):
    _write_trust_env(tmp_path, _FPR_A)
    os.environ["WILLOW_PGP_FINGERPRINT"] = _FPR_B
    try:
        with pytest.raises(pgp.PgpFingerprintConflict) as excinfo:
            pgp.expected_fingerprint()
    finally:
        del os.environ["WILLOW_PGP_FINGERPRINT"]
    message = str(excinfo.value)
    assert _FPR_A in message
    assert _FPR_B in message
    assert str(tmp_path / "constitutional" / "trust.env") in message


def test_never_silently_prefers_either_side_on_conflict(tmp_path):
    _write_trust_env(tmp_path, _FPR_B)
    os.environ["WILLOW_PGP_FINGERPRINT"] = _FPR_A
    try:
        for _ in range(3):
            with pytest.raises(pgp.PgpFingerprintConflict):
                pgp.expected_fingerprint()
    finally:
        del os.environ["WILLOW_PGP_FINGERPRINT"]


def test_case_and_whitespace_insensitive_comparison(tmp_path):
    d = _trust_dir(tmp_path)
    (d / "trust.env").write_text(f"WILLOW_PGP_FINGERPRINT= {_FPR_A.lower()} \n", encoding="utf-8")
    os.environ["WILLOW_PGP_FINGERPRINT"] = _FPR_A
    try:
        assert pgp.expected_fingerprint() == _FPR_A
    finally:
        del os.environ["WILLOW_PGP_FINGERPRINT"]


def test_trust_env_read_is_cached_until_the_file_changes(tmp_path):
    _write_trust_env(tmp_path, _FPR_A)
    assert pgp.expected_fingerprint() == _FPR_A
    _write_trust_env(tmp_path, _FPR_B)
    assert pgp.expected_fingerprint() == _FPR_B


def test_trust_env_ignores_comments_and_blank_lines(tmp_path):
    d = _trust_dir(tmp_path)
    (d / "trust.env").write_text(
        "\n# a comment\nOTHER_KEY=x\nWILLOW_PGP_FINGERPRINT=" + _FPR_A + "\n",
        encoding="utf-8",
    )
    assert pgp.expected_fingerprint() == _FPR_A


def test_trust_env_missing_file_is_unset_not_an_error(tmp_path):
    _trust_dir(tmp_path)  # directory exists, file does not
    assert not (tmp_path / "constitutional" / "trust.env").exists()
    assert pgp.expected_fingerprint() == ""


def test_trust_env_empty_value_line_is_legitimately_unset(tmp_path):
    """The template shape before a key is first generated
    (`WILLOW_PGP_FINGERPRINT=` with nothing after the `=`) is not a parse
    failure — it is the box saying explicitly "no key yet.\""""
    _write_trust_env(tmp_path, None)
    assert pgp.expected_fingerprint() == ""


# ── F4: unreachable is not empty ────────────────────────────────────────

def test_export_prefixed_line_parses_correctly_not_silently_missed(tmp_path):
    """Loki A38D41C2, F4: the box's own env files already use `export
    NAME=value` lines; the pre-rework parser silently missed the key
    entirely (name became "export WILLOW_PGP_FINGERPRINT", never matching),
    resolving to unset instead of the configured value — a fail-open bug,
    not intended lenience."""
    d = _trust_dir(tmp_path)
    (d / "trust.env").write_text(f"export WILLOW_PGP_FINGERPRINT={_FPR_A}\n", encoding="utf-8")
    assert pgp.expected_fingerprint() == _FPR_A


def test_malformed_value_raises_rather_than_silently_disabling(tmp_path):
    """An inline '# comment' glued onto the value (systemd's
    EnvironmentFile= grammar has no inline-comment syntax after `=` — the
    whole rest of the line is the literal value) used to produce a
    non-hex value that pgp_enabled()'s own regex check quietly rejected,
    turning enforcement off with no signal. Now raises."""
    d = _trust_dir(tmp_path)
    (d / "trust.env").write_text(
        f"WILLOW_PGP_FINGERPRINT={_FPR_A} # some comment\n", encoding="utf-8"
    )
    with pytest.raises(pgp.PgpSourceUnreadable):
        pgp.expected_fingerprint()


def test_unreadable_existing_file_raises_never_silently_unset(tmp_path):
    d = _trust_dir(tmp_path)
    p = d / "trust.env"
    p.write_text(f"WILLOW_PGP_FINGERPRINT={_FPR_A}\n", encoding="utf-8")
    os.chmod(p, 0o000)
    try:
        with pytest.raises(pgp.PgpSourceUnreadable):
            pgp.expected_fingerprint()
    finally:
        os.chmod(p, 0o644)  # so tmp_path cleanup can remove it


def test_group_writable_file_is_refused_as_unreadable(tmp_path):
    """A trust-config file anyone but its owner could rewrite must never
    be trusted, even if its content currently parses fine — the whole
    point of a trust root is that only the trust owner can decide what it
    says."""
    d = _trust_dir(tmp_path)
    p = d / "trust.env"
    p.write_text(f"WILLOW_PGP_FINGERPRINT={_FPR_A}\n", encoding="utf-8")
    os.chmod(p, 0o664)  # group-writable
    try:
        with pytest.raises(pgp.PgpSourceUnreadable):
            pgp.expected_fingerprint()
    finally:
        os.chmod(p, 0o644)


def test_group_writable_parent_directory_is_refused_as_unreadable(tmp_path):
    d = _trust_dir(tmp_path)
    p = d / "trust.env"
    p.write_text(f"WILLOW_PGP_FINGERPRINT={_FPR_A}\n", encoding="utf-8")
    os.chmod(d, 0o775)  # group-writable directory
    try:
        with pytest.raises(pgp.PgpSourceUnreadable):
            pgp.expected_fingerprint()
    finally:
        os.chmod(d, 0o755)


# ── F9: cache staleness on a same-mtime rewrite ─────────────────────────

def test_cache_picks_up_a_same_size_rewrite(tmp_path):
    """The old cache key was (path, float mtime, size) — a same-size
    rewrite landing within one float-mtime tick (or reusing an inode)
    could serve a stale fingerprint. FPR_A and FPR_B are both 40 hex
    chars (same byte length); the ino/mtime_ns-keyed cache must still
    pick up the change."""
    _write_trust_env(tmp_path, _FPR_A)
    assert pgp.expected_fingerprint() == _FPR_A
    assert len(_FPR_A) == len(_FPR_B)
    _write_trust_env(tmp_path, _FPR_B)
    assert pgp.expected_fingerprint() == _FPR_B
