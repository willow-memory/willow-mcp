"""`deploy/manifest-grant/seed_envelope_ratify.py` — the installer's
bootstrap seed for the `envelope.ratify` envelope itself (gap
`18affe49e198`; dispatch A9BF01A9 amending BD5843FD).

Points `envelopes.registry_path()`/`envelopes.syscall_path()` at a
throwaway registry via `WILLOW_ENVELOPE_REGISTRY`/`WILLOW_SYSCALL_TABLE`
(the same override `tests/test_trust_owner_verbs.py`'s own `_charter()`
fixture uses) — no `WILLOW_HOME`, no root, no uid switch needed. PGP
enforcement stays OFF (`WILLOW_PGP_FINGERPRINT` unset) so `_save_active`
writes the register unsigned, per its own documented posture — this module
tests the row-insertion/idempotency logic, not gpg (see
test_sync_constitutional.py and install.sh's own comments for why the
two-uid signing boundary itself is not testable in Kart).
"""
from __future__ import annotations

import json
import sys
from importlib import util as _importlib_util
from pathlib import Path

import pytest

_MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "deploy" / "manifest-grant" / "seed_envelope_ratify.py"
)
_spec = _importlib_util.spec_from_file_location("seed_envelope_ratify", _MODULE_PATH)
seed_envelope_ratify = _importlib_util.module_from_spec(_spec)
assert _spec.loader is not None
sys.modules["seed_envelope_ratify"] = seed_envelope_ratify
_spec.loader.exec_module(seed_envelope_ratify)

from willow_mcp import envelope_authoring, envelopes  # noqa: E402


VERB_ID = 24
VERB = "envelope.ratify"


@pytest.fixture
def registry(tmp_path: Path, monkeypatch):
    """A throwaway registry + syscall table carrying exactly row 24
    (envelope.ratify), no pre-existing active grant for it — the state the
    installer meets on a box that just got row 24 synced (step 1c) but has
    never seeded this envelope before.

    `ratify_proposal_row` refuses `EREGISTRY` unless the resolved registry
    IS `$WILLOW_HOME/constitutional/pre-approved.json` (`registry_mismatch`)
    — so `WILLOW_HOME` is pointed at this throwaway dir and the files live
    at their real relative path under it, rather than steering with
    `WILLOW_ENVELOPE_REGISTRY`/`WILLOW_SYSCALL_TABLE` alone (which would
    disagree with `WILLOW_HOME` and trip that exact guard)."""
    home = tmp_path / "home"
    const_dir = home / "constitutional"
    const_dir.mkdir(parents=True)
    home.chmod(0o700)
    const_dir.chmod(0o700)
    reg = const_dir / "pre-approved.json"
    tab = const_dir / "syscall-table.json"
    reg.write_text(json.dumps({"active": []}))
    tab.write_text(json.dumps({
        "verbs": [{"id": VERB_ID, "verb": VERB, "bounds": {"proposal_ids": "list[proposal_id]"}}]
    }))
    reg.chmod(0o600)
    tab.chmod(0o600)
    monkeypatch.setenv("WILLOW_HOME", str(home))
    monkeypatch.delenv("WILLOW_ENVELOPE_REGISTRY", raising=False)
    monkeypatch.delenv("WILLOW_SYSCALL_TABLE", raising=False)
    monkeypatch.delenv("WILLOW_CHARTER_REPO", raising=False)
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    return reg


@pytest.fixture
def fresh_registry(tmp_path: Path, monkeypatch):
    """F-A (dispatch 10F9E837, Loki audit 23DE8AA9): a TRULY fresh box —
    constitutional/ exists (install step 1 has run) and carries row 24
    (step 1c has synced the syscall table), but NO pre-approved.json has
    EVER been written, not even an empty one. This is the state `hanuman`'s
    own first M1 reproduction (dispatch FA4F79AC, Kart E1JRW3RN) missed —
    it pre-created an empty register, which Loki's re-audit caught was not
    actually "fresh." Returns the register PATH (which must not exist yet)
    rather than the fixture from `registry` above, which pre-creates it."""
    home = tmp_path / "fresh_home"
    const_dir = home / "constitutional"
    const_dir.mkdir(parents=True)
    home.chmod(0o700)
    const_dir.chmod(0o700)
    tab = const_dir / "syscall-table.json"
    tab.write_text(json.dumps({
        "verbs": [{"id": VERB_ID, "verb": VERB, "bounds": {"proposal_ids": "list[proposal_id]"}}]
    }))
    tab.chmod(0o600)
    reg = const_dir / "pre-approved.json"
    assert not reg.exists()  # the whole point: nothing has ever written this
    monkeypatch.setenv("WILLOW_HOME", str(home))
    monkeypatch.delenv("WILLOW_ENVELOPE_REGISTRY", raising=False)
    monkeypatch.delenv("WILLOW_SYSCALL_TABLE", raising=False)
    monkeypatch.delenv("WILLOW_CHARTER_REPO", raising=False)
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    return reg


def _active_rows(reg_path: Path) -> list[dict]:
    return json.loads(reg_path.read_text())["active"]


def test_seed_writes_one_active_unbounded_grant_for_willow(registry):
    report = seed_envelope_ratify.seed(envelope_authoring, envelopes)

    assert report["seeded"] is True
    assert report["envelope_id"] == seed_envelope_ratify.ENVELOPE_ID

    active = _active_rows(registry)
    assert len(active) == 1
    row = active[0]
    assert row["verb"] == "envelope.ratify"
    assert row["verb_id"] == VERB_ID
    assert row["grantee"] == "willow"
    assert row["bounds"] == {"proposal_ids": ["*"]}
    assert row["status"] == "active"
    assert row["issued_by"] == "root"
    assert row["ratified_by"] == "install.sh (sealed 1bd6fd29)"
    assert "18affe49e198" in row["ratified_via"]


def test_seed_bounds_signature_matches_the_syscall_table_row(registry):
    """The seeded bounds' KEY SET must equal row 24's own declared bounds
    signature — envelope_authoring._validate_bounds_signature is the same
    check the real propose()/ratify() path enforces; a mismatch here would
    mean this script and the syscall table have drifted."""
    report = seed_envelope_ratify.seed(envelope_authoring, envelopes)
    assert report["seeded"] is True

    verbs_by_id = envelope_authoring._load_syscall_table()
    # Raises InvalidBoundsSignatureError if this ever drifts.
    envelope_authoring._validate_bounds_signature(
        seed_envelope_ratify.VERB, seed_envelope_ratify.BOUNDS, verbs_by_id
    )


def test_seed_is_idempotent_second_run_is_a_no_op(registry):
    first = seed_envelope_ratify.seed(envelope_authoring, envelopes)
    assert first["seeded"] is True
    active_after_first = _active_rows(registry)

    second = seed_envelope_ratify.seed(envelope_authoring, envelopes)

    assert second["seeded"] is False
    assert second["envelope_id"] == first["envelope_id"]
    assert second["reason"] == "already active"
    assert _active_rows(registry) == active_after_first  # byte-for-byte unchanged shape


def test_seed_does_not_disturb_other_active_envelopes(registry):
    other = {
        "id": "env-manifest.create-5b8920363112", "verb_id": 22, "verb": "manifest.create",
        "grantee": "willow", "bounds": {"seat_ids": ["jeles-corpus"]}, "issued_by": "root",
        "issued_at": "2026-09-20T00:00:00+00:00", "status": "active",
        "expires_at": None, "max_count": None, "use_count_source": "frank",
    }
    doc = json.loads(registry.read_text())
    doc["active"] = [other]
    registry.write_text(json.dumps(doc))

    report = seed_envelope_ratify.seed(envelope_authoring, envelopes)

    assert report["seeded"] is True
    active = _active_rows(registry)
    assert len(active) == 2
    assert other in active
    seeded = [r for r in active if r["id"] == seed_envelope_ratify.ENVELOPE_ID]
    assert len(seeded) == 1


def test_seed_recognizes_a_pre_existing_grant_seeded_under_a_different_id(registry):
    """find_active_grant() matches on (verb, grantee, status), not a fixed
    id — a grant hand-ratified through the normal path (or seeded by a
    prior version of this script under a different id) is recognized just
    as well as this script's own id."""
    hand_ratified = {
        "id": "env-envelope.ratify-hand-ratified", "verb_id": VERB_ID, "verb": VERB,
        "grantee": "willow", "bounds": {"proposal_ids": ["*"]}, "issued_by": "root",
        "issued_at": "2026-09-22T00:00:00+00:00", "status": "active",
        "expires_at": None, "max_count": None, "use_count_source": "frank",
    }
    doc = json.loads(registry.read_text())
    doc["active"] = [hand_ratified]
    registry.write_text(json.dumps(doc))

    report = seed_envelope_ratify.seed(envelope_authoring, envelopes)

    assert report["seeded"] is False
    assert report["envelope_id"] == "env-envelope.ratify-hand-ratified"
    assert len(_active_rows(registry)) == 1  # nothing added


def test_find_active_grant_ignores_a_revoked_or_inactive_row():
    revoked = {"verb": VERB, "grantee": "willow", "status": "active", "revoked": True}
    inactive = {"verb": VERB, "grantee": "willow", "status": "revoked"}
    wrong_grantee = {"verb": VERB, "grantee": "someone-else", "status": "active"}
    wrong_verb = {"verb": "manifest.create", "grantee": "willow", "status": "active"}

    assert seed_envelope_ratify.find_active_grant([revoked]) is None
    assert seed_envelope_ratify.find_active_grant([inactive]) is None
    assert seed_envelope_ratify.find_active_grant([wrong_grantee]) is None
    assert seed_envelope_ratify.find_active_grant([wrong_verb]) is None

    good = {"verb": VERB, "grantee": "willow", "status": "active", "id": "env-x"}
    assert seed_envelope_ratify.find_active_grant([revoked, good]) == good


def test_main_seeded_and_no_op_output(registry, capsys):
    rc = seed_envelope_ratify.main([])
    assert rc == 0
    out = capsys.readouterr().out
    assert "seeded" in out
    assert seed_envelope_ratify.ENVELOPE_ID in out

    rc2 = seed_envelope_ratify.main([])
    assert rc2 == 0
    out2 = capsys.readouterr().out
    assert "no-op" in out2


def test_main_refuses_unexpected_arguments():
    rc = seed_envelope_ratify.main(["--bogus"])
    assert rc == 2


# ── M1 (dispatch FA4F79AC): the install deadlock and its fix ──────────────
#
# Loki audit D06A0EF3: step 1 (a PRIOR install run) leaves constitutional/
# already trust-owner-owned -- "provisioned" -- before THIS run's step 1d
# (this seed) has a trust.env to read (only written at step 6, much later).
# _save_active's `if pgp.pgp_enabled():` branch called
# pgp.expected_fingerprint(), which raised PgpSourceUnreadable
# unconditionally on a provisioned-but-missing-trust.env box -- every fresh
# install, forever, since trust.env is never written until AFTER this exact
# call would need to succeed.

def test_seed_without_sign_as_still_hits_the_deadlock_pgp_pgp_enabled_path(registry, monkeypatch):
    """Reproduction: with no sign_as (the shape every OTHER caller of
    ratify_proposal_row uses, and the shape this script itself used before
    the fix), a provisioned-but-missing-trust.env box raises exactly as
    Loki measured -- proving the deadlock is real for that path, and that
    the fix below is not simply "the check never fires anymore.\""""
    from willow_mcp import pgp

    monkeypatch.setattr(pgp, "_trust_config_dir_already_provisioned", lambda d: True)
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    with pytest.raises(pgp.PgpSourceUnreadable):
        seed_envelope_ratify.seed(envelope_authoring, envelopes)


def test_seed_with_sign_as_bypasses_the_deadlock_entirely(registry, monkeypatch):
    """The fix: sign_as threads straight through to _save_active, which
    signs unconditionally under it and never calls
    pgp.pgp_enabled()/pgp.expected_fingerprint() at all -- proven by making
    both raise if reached. sign_detached is faked (Kart cannot exercise
    real two-uid gpg signing -- same limit every signing step in this
    codebase has; see rotate_resign.py's own tests for the precedent) but
    still WRITES the .sig content _save_active's rename step needs, so the
    write completes for real, on a provisioned-but-missing-trust.env box
    that would otherwise deadlock (previous test)."""
    from willow_mcp import pgp

    def _raise(*a, **k):
        raise AssertionError("pgp.expected_fingerprint()/pgp_enabled() must not be "
                              "called when sign_as is given")

    monkeypatch.setattr(pgp, "expected_fingerprint", _raise)
    monkeypatch.setattr(pgp, "pgp_enabled", _raise)
    monkeypatch.setattr(pgp, "_trust_config_dir_already_provisioned", lambda d: True)
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)

    def _fake_sign_detached(path, local_user=""):
        sig_path = path.parent / f"{path.name}.sig"
        sig_path.write_text("fake-detached-signature\n", encoding="utf-8")
        return True, str(sig_path)

    monkeypatch.setattr(pgp, "sign_detached", _fake_sign_detached)

    report = seed_envelope_ratify.seed(envelope_authoring, envelopes, sign_as="A" * 40)

    assert report["seeded"] is True
    active = _active_rows(registry)
    assert len(active) == 1
    assert active[0]["verb"] == "envelope.ratify"
    # the register's own .sig now exists, signed under the explicit fingerprint
    assert (registry.parent / f"{registry.name}.sig").is_file()


def test_main_reads_sign_as_from_the_process_environment(registry, monkeypatch):
    """install.sh passes WILLOW_PGP_FINGERPRINT=$FPR in this ONE process's
    own env (deploy/manifest-grant/install.sh's `as_to ... WILLOW_PGP_
    FINGERPRINT="$FPR"` call at step 1d) -- main() reads it as sign_as
    directly, never through pgp.expected_fingerprint()."""
    from willow_mcp import pgp

    def _raise(*a, **k):
        raise AssertionError("must not consult trust.env when the env carries a valid fingerprint")

    monkeypatch.setattr(pgp, "expected_fingerprint", _raise)
    monkeypatch.setattr(pgp, "pgp_enabled", _raise)
    monkeypatch.setattr(pgp, "_trust_config_dir_already_provisioned", lambda d: True)

    def _fake_sign_detached(path, local_user=""):
        assert local_user == "A" * 40
        sig_path = path.parent / f"{path.name}.sig"
        sig_path.write_text("fake\n", encoding="utf-8")
        return True, str(sig_path)

    monkeypatch.setattr(pgp, "sign_detached", _fake_sign_detached)
    monkeypatch.setenv("WILLOW_PGP_FINGERPRINT", "A" * 40)

    rc = seed_envelope_ratify.main([])
    assert rc == 0


# ── F-A (dispatch 10F9E837, Loki audit 23DE8AA9): a TRULY fresh install,
# no register at all -- the gap M1's fix (sign_as) did not close, because
# hanuman's own first reproduction pre-created an empty register.

def test_seed_on_a_truly_fresh_box_with_sign_as_no_longer_raises(fresh_registry, monkeypatch):
    """Reproduction and fix in one: no pre-approved.json exists at all
    (fresh_registry asserts this). Before the fix, envelopes._load ->
    paths.trusted_read raised PermissionError('source path missing') from
    inside _load_active_register, regardless of sign_as. Now it must
    succeed, creating the register for the first time."""
    from willow_mcp import pgp

    def _fake_sign_detached(path, local_user=""):
        sig_path = path.parent / f"{path.name}.sig"
        sig_path.write_text("fake-detached-signature\n", encoding="utf-8")
        return True, str(sig_path)

    monkeypatch.setattr(pgp, "sign_detached", _fake_sign_detached)
    assert not fresh_registry.exists()

    report = seed_envelope_ratify.seed(envelope_authoring, envelopes, sign_as="B" * 40)

    assert report["seeded"] is True
    assert fresh_registry.is_file()  # the register now exists, created by this call
    active = _active_rows(fresh_registry)
    assert len(active) == 1
    assert active[0]["verb"] == "envelope.ratify"


def test_seed_on_a_truly_fresh_box_without_sign_as_also_succeeds(fresh_registry):
    """The read-side fix (envelope_authoring._load_active_register and
    seed()'s own preliminary read both treating a missing register as
    {"active": []}) is independent of sign_as/M1 -- it also fixes the
    ordinary case where PGP enforcement is off (no WILLOW_PGP_FINGERPRINT
    configured at all, this fixture's default), which writes the register
    unsigned per _save_active's normal posture. Confirms F-A is a
    read-side fix, not merely a side effect of the M1 write-side one."""
    report = seed_envelope_ratify.seed(envelope_authoring, envelopes)
    assert report["seeded"] is True
    assert fresh_registry.is_file()
    active = _active_rows(fresh_registry)
    assert len(active) == 1
    assert not (fresh_registry.parent / f"{fresh_registry.name}.sig").exists()


def test_load_active_register_treats_a_missing_file_as_empty(fresh_registry):
    """Direct unit test of envelope_authoring's own fix."""
    assert not fresh_registry.exists()
    assert envelope_authoring._load_active_register() == {"active": []}


def test_main_with_no_env_fingerprint_falls_back_to_normal_unsigned_path(registry):
    """No WILLOW_PGP_FINGERPRINT at all (the registry fixture's own default
    state) must not be treated as sign_as -- falls back to the pre-existing
    pgp.pgp_enabled()-gated behavior (enforcement off here, unsigned
    write), exactly as every test above this M1 section already exercises
    through seed() directly."""
    rc = seed_envelope_ratify.main([])
    assert rc == 0
    active = _active_rows(registry)
    assert len(active) == 1
    assert not (registry.parent / f"{registry.name}.sig").exists()
