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

from willow_mcp import paths, pgp

_FPR_A = "9B6F87BEB4AE56E2" + "0" * 24
_FPR_B = "DEE471967EBCFA46" + "1" * 24


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    # Most of this file tests parsing/caching/conflict logic, not the N2
    # ownership-strictness rule specifically (which has its own dedicated
    # tests below, each overriding this back to a real uid). Kart's own
    # sandbox happens to have a real `willow-operator` account, so without
    # this override every self-created trust.env in this file would be
    # rejected by the N2 fix before the test ever got to what it means to
    # test.
    monkeypatch.setattr(paths, "_trust_owner_uid", lambda: None)
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


# ── Loki re-audit 93D0F057, N2: enforcement may be off only because the
# trust owner wrote that down, never because trust.env is missing,
# unreadable, malformed, or owned by the wrong uid. ────────────────────

def test_self_owned_trust_env_is_refused_when_a_real_trust_owner_exists(tmp_path, monkeypatch):
    """The core N2 fix: a trust-config file owned by THIS PROCESS's own
    euid used to be accepted unconditionally. That is exactly what would
    let the broker create its own trust.env and have it trusted. When a
    real trust owner uid is resolvable, only THAT uid is acceptable —
    self-ownership is no longer a substitute, even though the file here
    literally is self-owned (the test process created it)."""
    _write_trust_env(tmp_path, _FPR_A)
    monkeypatch.setattr(paths, "_trust_owner_uid", lambda: os.geteuid() + 1)
    with pytest.raises(pgp.PgpSourceUnreadable, match="not the trust owner"):
        pgp.expected_fingerprint()


def test_self_owned_trust_env_is_accepted_when_no_trust_owner_exists(tmp_path, monkeypatch):
    """The carve-out: on a box with NO resolvable trust-owner identity at
    all (Kart, dev, anything that never ran trust_root_setup), there is no
    "someone else" to require, so self-ownership is the only option and
    is accepted — matching paths.trusted_read's own carve-out for this
    case."""
    _write_trust_env(tmp_path, _FPR_A)
    monkeypatch.setattr(paths, "_trust_owner_uid", lambda: None)
    assert pgp.expected_fingerprint() == _FPR_A


def test_missing_trust_env_raises_when_constitutional_dir_already_provisioned(tmp_path, monkeypatch):
    """N2's other half: on a $WILLOW_HOME whose constitutional/ directory
    is ALREADY trust-owner-owned (install's step 1 has provisioned trust
    here), trust.env simply not existing must no longer resolve as
    legitimate "unset" — a completed install always writes this file, so
    its absence means either install stopped partway through, or
    something removed it (the broker owns $WILLOW_HOME and can rename
    constitutional/ away — see the module docstring for why that specific
    attack is not fully closeable here). Refuse rather than silently
    disable. A real chown to the trust owner needs root, so this
    monkeypatches the provisioned-signal function directly rather than
    the underlying stat."""
    assert not (tmp_path / "constitutional").exists()
    monkeypatch.setattr(pgp, "_trust_config_dir_already_provisioned", lambda d: True)
    with pytest.raises(pgp.PgpSourceUnreadable, match="does not exist"):
        pgp.expected_fingerprint()


def test_missing_trust_env_is_still_unset_when_constitutional_dir_never_provisioned(tmp_path):
    """The far more common legitimate "off because absent" case: this
    $WILLOW_HOME has never been through install's trust provisioning at
    all (a fresh checkout, a dev sandbox, most of this test suite's own
    fixtures) — nothing could ever have written this file down as
    configured or explicitly off, so unset is correct."""
    assert not (tmp_path / "constitutional").exists()
    assert pgp.expected_fingerprint() == ""


def test_provisioned_signal_is_keyed_to_this_willow_home_not_the_host_account(tmp_path, monkeypatch):
    """The bug this design avoids: a real trust-owner account can exist
    SOMEWHERE on the host (or a sandbox mirroring one) without this
    specific $WILLOW_HOME/constitutional/ ever having been provisioned —
    that must still resolve as legitimate unset, not a refusal. This is
    exactly what broke the very first version of this fix against Kart's
    own sandbox, which does carry a real willow-operator account."""
    monkeypatch.setattr(paths, "_trust_owner_uid", lambda: 994)
    assert not (tmp_path / "constitutional").exists()
    assert pgp.expected_fingerprint() == ""


def test_missing_trust_env_raised_even_with_a_matching_process_env_pin(tmp_path, monkeypatch):
    """A process-env pin does not rescue a missing trust-config file on a
    $WILLOW_HOME that should have one — the file itself must exist and
    say so."""
    monkeypatch.setattr(pgp, "_trust_config_dir_already_provisioned", lambda d: True)
    os.environ["WILLOW_PGP_FINGERPRINT"] = _FPR_A
    try:
        with pytest.raises(pgp.PgpSourceUnreadable):
            pgp.expected_fingerprint()
    finally:
        del os.environ["WILLOW_PGP_FINGERPRINT"]


# ── Loki re-audit 93D0F057, N6: a malformed PROCESS-env value must also
# raise, not merely a malformed file value. ─────────────────────────────

def test_malformed_process_env_value_raises_rather_than_silently_disabling(tmp_path):
    """WILLOW_PGP_FINGERPRINT='<fpr>  # x' in the process environment
    (no trust.env at all) used to return the raw non-hex string;
    pgp_enabled()'s own regex check then silently rejected it, turning
    enforcement off with nothing raised anywhere. F4's malformed-value
    fix covered the FILE only — this is the same rule applied to the
    process environment."""
    os.environ["WILLOW_PGP_FINGERPRINT"] = f"{_FPR_A}  # stray comment"
    try:
        with pytest.raises(pgp.PgpSourceUnreadable):
            pgp.expected_fingerprint()
    finally:
        del os.environ["WILLOW_PGP_FINGERPRINT"]


def test_malformed_process_env_value_raises_even_when_pgp_enabled_is_called(tmp_path):
    os.environ["WILLOW_PGP_FINGERPRINT"] = "not-a-fingerprint-at-all"
    try:
        with pytest.raises(pgp.PgpSourceUnreadable):
            pgp.pgp_enabled()
    finally:
        del os.environ["WILLOW_PGP_FINGERPRINT"]


# ── Rework #3 (dispatch FA4F79AC): the vault, not a bare $WILLOW_HOME ─────
#
# Operator ruling, verbatim: "it should be in the vault with the rest of
# the keys." paths.trust_config_path() = operator_secrets_root() /
# "constitutional" / "trust.env" -- a MODULE-LEVEL function, redirected in
# tests by monkeypatching WILLOW_HOME/WILLOW_VAULT_BOX (paths' own env
# resolution) or the function itself, never by an env var the broker could
# set to steer pgp.py specifically.

def test_trust_config_path_defaults_to_willow_home_when_vault_box_unset(tmp_path, monkeypatch):
    monkeypatch.delenv("WILLOW_VAULT_BOX", raising=False)
    assert paths.trust_config_path() == tmp_path / "constitutional" / "trust.env"


def test_trust_config_path_moves_under_vault_box_when_configured(tmp_path, monkeypatch):
    """The whole point of the location work: when the operator has
    configured a real vault separate from $WILLOW_HOME, trust.env follows
    it there -- beside dispatch_signing.key/vault.key/vault.db (all
    resolved from the same operator_secrets_root()), in its own
    constitutional/ subdirectory, never at the vault's own top level (see
    the function's own docstring for why: the vault's top level holds the
    BROKER's own secrets and must stay broker-writable)."""
    vault = tmp_path / "vault"
    monkeypatch.setenv("WILLOW_VAULT_BOX", str(vault))
    assert paths.trust_config_path() == vault / "constitutional" / "trust.env"
    assert paths.dispatch_signing_key_path() == vault / "dispatch_signing.key"


def test_expected_fingerprint_reads_from_the_vault_box_location(tmp_path, monkeypatch):
    """Functional, not just a path-resolution check: pgp.py actually reads
    trust.env from wherever paths.trust_config_path() resolves to, once a
    vault is configured -- not from $WILLOW_HOME/constitutional regardless."""
    vault = tmp_path / "vault"
    monkeypatch.setenv("WILLOW_VAULT_BOX", str(vault))
    vault_const = vault / "constitutional"
    vault_const.mkdir(parents=True)
    (vault_const / "trust.env").write_text(f"WILLOW_PGP_FINGERPRINT={_FPR_A}\n", encoding="utf-8")
    # nothing at the OLD (pre-rework) $WILLOW_HOME/constitutional/trust.env location
    assert not (tmp_path / "constitutional" / "trust.env").exists()
    assert pgp.expected_fingerprint() == _FPR_A
