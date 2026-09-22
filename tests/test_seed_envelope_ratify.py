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
