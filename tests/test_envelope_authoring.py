"""PR5: envelope_authoring — propose/ratify/reject/list.

Pins the load-bearing invariants:
* propose refuses without keyring attribution (verifier + session in
  attribution cache).
* propose refuses on invalid bounds signature or unknown verb.
* ratify refuses without a keyring-known, non-compromised verifier.
* ratify moves proposal → active with issued_by="root".
* reject records reopen_when (NEVER vs NOT YET).
* list_active / list_pending are read-only and filter correctly.
* bounds_digest is deterministic across runs.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from unittest import mock

import pytest

from willow_mcp import (
    envelope_authoring as ea,
    envelopes as _envelopes,
    human_session,
    keyring as keyring_mod,
    paths,
)


# --- fixtures --------------------------------------------------------------


@pytest.fixture
def ring_with_rita(tmp_path, monkeypatch):
    """A keyring with 'rita' active; the calling session s-orch is added to
    the attribution cache to satisfy propose's guard."""
    human_session.clear_attribution_cache()
    with keyring_mod.isolated():
        k = keyring_mod.Keyring(path=str(tmp_path / "keys.json"))
        k.add("rita")
        k.save()
        keyring_mod.set_keyring(k)
        human_session._remember_attributed("s-orch")
        try:
            yield k
        finally:
            keyring_mod.set_keyring(None)
            human_session.clear_attribution_cache()


@pytest.fixture
def fresh_registry(tmp_path, monkeypatch):
    """Point the envelope registry + syscall table at throwaway tmp files with
    a known verb ('demo_verb') available for proposals."""
    registry_path = tmp_path / "pre-approved.json"
    syscall_path = tmp_path / "syscall-table.json"
    registry_path.write_text(
        json.dumps({
            "schema": "envelope-registry/v1.1",
            "active": [],
            "proposals": [],
        }, indent=2),
        encoding="utf-8",
    )
    syscall_path.write_text(
        json.dumps({
            "verbs": [
                {
                    "id": 999,
                    "verb": "demo_verb",
                    "bounds": {"path_pattern": "", "max_bytes": 0},
                },
                {
                    "id": 1000,
                    "verb": "demo_no_bounds",
                    "bounds": {},
                },
            ]
        }, indent=2),
        encoding="utf-8",
    )
    # Force os.stat's owner-only check to pass — trusted_read insists on it.
    os.chmod(str(registry_path), 0o600)
    os.chmod(str(syscall_path), 0o600)
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(registry_path))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(syscall_path))
    return registry_path, syscall_path


# --- propose ---------------------------------------------------------------


def test_propose_refuses_without_keyring(fresh_registry, monkeypatch):
    """No keyring at all → attribution rail off → propose skips it (but
    would still write). This test pins the OTHER branch: no keyring →
    proposals proceed without the attribution check."""
    keyring_mod.set_keyring(None)
    monkeypatch.delenv("WILLOW_KEYRING", raising=False)
    monkeypatch.setattr(keyring_mod, "_from_env", None)
    monkeypatch.setattr(keyring_mod, "_loaded_from", None)

    row = ea.propose(
        verb="demo_verb", grantee="hanuman",
        bounds={"path_pattern": "docs/**", "max_bytes": 1024},
        reason="test", verifier="", session_id="",
    )
    assert row["status"] == "proposed"
    assert row["notes"] == "test"


def test_propose_refuses_unattributed_session(ring_with_rita, fresh_registry):
    """With keyring on: session_id not in attribution cache → refuse."""
    with pytest.raises(ea.UnattributedSessionError, match="not in the attribution cache"):
        ea.propose(
            verb="demo_verb", grantee="hanuman",
            bounds={"path_pattern": "*", "max_bytes": 1},
            reason="test",
            verifier="rita",
            session_id="s-unknown",  # not in cache
        )


def test_propose_refuses_unknown_verifier(ring_with_rita, fresh_registry):
    with pytest.raises(ea.UnattributedSessionError, match="unknown"):
        ea.propose(
            verb="demo_verb", grantee="hanuman",
            bounds={"path_pattern": "*", "max_bytes": 1},
            reason="test",
            verifier="mallory",
            session_id="s-orch",
        )


def test_propose_refuses_empty_verifier(ring_with_rita, fresh_registry):
    with pytest.raises(ea.UnattributedSessionError, match="requires a verifier"):
        ea.propose(
            verb="demo_verb", grantee="hanuman",
            bounds={"path_pattern": "*", "max_bytes": 1},
            reason="test",
            verifier="",
            session_id="s-orch",
        )


def test_propose_refuses_unknown_verb(ring_with_rita, fresh_registry):
    with pytest.raises(ea.UnknownVerbError, match="not in the syscall table"):
        ea.propose(
            verb="fictional_verb", grantee="hanuman",
            bounds={"x": 1},
            reason="test",
            verifier="rita", session_id="s-orch",
        )


def test_propose_refuses_bounds_signature_mismatch(ring_with_rita, fresh_registry):
    with pytest.raises(ea.InvalidBoundsSignatureError, match="bounds signature mismatch"):
        ea.propose(
            verb="demo_verb", grantee="hanuman",
            bounds={"wrong_key": "value"},  # demo_verb wants path_pattern + max_bytes
            reason="test",
            verifier="rita", session_id="s-orch",
        )


def test_propose_writes_a_proposal_row(ring_with_rita, fresh_registry):
    registry_path, _ = fresh_registry
    row = ea.propose(
        verb="demo_verb", grantee="hanuman",
        bounds={"path_pattern": "docs/**", "max_bytes": 4096},
        reason="specialist needs to write docs",
        verifier="rita", session_id="s-orch",
    )
    assert row["status"] == "proposed"
    assert row["verb"] == "demo_verb"
    assert row["grantee"] == "hanuman"
    assert row["notes"] == "specialist needs to write docs"
    assert row["proposed_by"]["verifier"] == "rita"
    assert row["proposed_by"]["session_id"] == "s-orch"
    assert row["issued_by"] == ""  # not ratified yet
    assert row["issued_at"] == ""

    # And it landed in the file
    on_disk = json.loads(registry_path.read_text(encoding="utf-8"))
    assert len(on_disk["proposals"]) == 1
    assert on_disk["proposals"][0]["id"] == row["id"]


def test_propose_appends_to_ledger_when_provided(ring_with_rita, fresh_registry):
    """The ledger is optional; when provided, propose calls .append()."""
    fake_ledger = mock.Mock()
    fake_ledger.append.return_value = "record-uuid-xyz"

    row = ea.propose(
        verb="demo_verb", grantee="hanuman",
        bounds={"path_pattern": "*", "max_bytes": 1},
        reason="test",
        verifier="rita", session_id="s-orch",
        ledger=fake_ledger,
    )

    fake_ledger.append.assert_called_once()
    call_args = fake_ledger.append.call_args
    assert call_args.args[1] == "envelope_proposed"
    payload = call_args.args[2]
    assert payload["envelope_id"] == row["id"]
    assert payload["verifier"] == "rita"
    assert payload["verb"] == "demo_verb"
    assert row["_ledger_record_id"] == "record-uuid-xyz"


# --- ratify ----------------------------------------------------------------


def test_ratify_refuses_unknown_verifier(ring_with_rita, fresh_registry):
    proposal = ea.propose(
        verb="demo_verb", grantee="hanuman",
        bounds={"path_pattern": "*", "max_bytes": 1}, reason="t",
        verifier="rita", session_id="s-orch",
    )
    with pytest.raises(ea.OperatorVerifierRequired):
        ea.ratify(proposal["id"], verifier="mallory")


def test_ratify_refuses_compromised_verifier(ring_with_rita, fresh_registry):
    proposal = ea.propose(
        verb="demo_verb", grantee="hanuman",
        bounds={"path_pattern": "*", "max_bytes": 1}, reason="t",
        verifier="rita", session_id="s-orch",
    )
    ring_with_rita.revoke("rita", reason="stolen", compromised=True)
    ring_with_rita.save()
    with pytest.raises(ea.OperatorVerifierRequired):
        ea.ratify(proposal["id"], verifier="rita")


def test_ratify_refuses_unknown_proposal(ring_with_rita, fresh_registry):
    with pytest.raises(ea.ProposalNotFoundError):
        ea.ratify("env-does-not-exist", verifier="rita")


def test_ratify_moves_proposal_to_active_with_issued_by_root(
    ring_with_rita, fresh_registry
):
    registry_path, _ = fresh_registry
    proposal = ea.propose(
        verb="demo_verb", grantee="hanuman",
        bounds={"path_pattern": "docs/**", "max_bytes": 1024}, reason="t",
        verifier="rita", session_id="s-orch",
    )
    ratified = ea.ratify(proposal["id"], verifier="rita")
    assert ratified["status"] == "active"
    assert ratified["issued_by"] == "root", (
        "invariant preserved: ratified envelopes are always issued_by='root'"
    )
    assert ratified["issued_at"]  # non-empty
    assert "keyring verifier rita" in ratified["ratified_via"]

    on_disk = json.loads(registry_path.read_text(encoding="utf-8"))
    assert len(on_disk["proposals"]) == 0, "proposal removed from queue"
    assert len(on_disk["active"]) == 1, "envelope landed in active"
    assert on_disk["active"][0]["id"] == proposal["id"]
    assert on_disk["active"][0]["issued_by"] == "root"


# --- reject ----------------------------------------------------------------


def test_reject_refuses_unknown_verifier(ring_with_rita, fresh_registry):
    proposal = ea.propose(
        verb="demo_verb", grantee="hanuman",
        bounds={"path_pattern": "*", "max_bytes": 1}, reason="t",
        verifier="rita", session_id="s-orch",
    )
    with pytest.raises(ea.OperatorVerifierRequired):
        ea.reject(proposal["id"], reason="nope", verifier="mallory")


def test_reject_records_reopen_when(ring_with_rita, fresh_registry):
    proposal = ea.propose(
        verb="demo_verb", grantee="hanuman",
        bounds={"path_pattern": "*", "max_bytes": 1}, reason="t",
        verifier="rita", session_id="s-orch",
    )
    row = ea.reject(
        proposal["id"], reason="too broad", verifier="rita",
        reopen_when="hanuman gets audited by loki",
    )
    assert row["reason"] == "too broad"
    assert row["reopen_when"] == "hanuman gets audited by loki"


def test_reject_default_reopen_when_is_never(ring_with_rita, fresh_registry):
    proposal = ea.propose(
        verb="demo_verb", grantee="hanuman",
        bounds={"path_pattern": "*", "max_bytes": 1}, reason="t",
        verifier="rita", session_id="s-orch",
    )
    row = ea.reject(proposal["id"], reason="dangerous", verifier="rita")
    assert row["reopen_when"] == "", "empty means NEVER"


def test_reject_removes_proposal_from_queue(ring_with_rita, fresh_registry):
    registry_path, _ = fresh_registry
    proposal = ea.propose(
        verb="demo_verb", grantee="hanuman",
        bounds={"path_pattern": "*", "max_bytes": 1}, reason="t",
        verifier="rita", session_id="s-orch",
    )
    ea.reject(proposal["id"], reason="test", verifier="rita")
    on_disk = json.loads(registry_path.read_text(encoding="utf-8"))
    assert on_disk["proposals"] == []
    assert on_disk["active"] == []


# --- list_active + list_pending -------------------------------------------


def test_list_active_returns_empty_when_none(ring_with_rita, fresh_registry):
    assert ea.list_active() == []


def test_list_active_returns_ratified_envelopes(ring_with_rita, fresh_registry):
    p1 = ea.propose(verb="demo_verb", grantee="hanuman",
                    bounds={"path_pattern": "docs/**", "max_bytes": 1},
                    reason="t", verifier="rita", session_id="s-orch")
    p2 = ea.propose(verb="demo_no_bounds", grantee="loki",
                    bounds={}, reason="t2",
                    verifier="rita", session_id="s-orch")
    ea.ratify(p1["id"], verifier="rita")
    ea.ratify(p2["id"], verifier="rita")

    all_active = ea.list_active()
    assert {r["id"] for r in all_active} == {p1["id"], p2["id"]}

    hanuman_only = ea.list_active(grantee="hanuman")
    assert [r["id"] for r in hanuman_only] == [p1["id"]]

    demo_verb_only = ea.list_active(verb="demo_verb")
    assert [r["id"] for r in demo_verb_only] == [p1["id"]]


def test_list_pending_returns_oldest_first(ring_with_rita, fresh_registry):
    """oldest_first=True is the operator's default — drain FIFO.

    proposed_at is second-precision in the current _now_iso; force distinct
    timestamps by injecting them explicitly so the ordering assertion isn't
    sensitive to how long two calls take on a fast machine (same second =
    same key, order preserved rather than reversed)."""
    p1 = ea.propose(verb="demo_verb", grantee="hanuman",
                    bounds={"path_pattern": "a", "max_bytes": 1},
                    reason="first", verifier="rita", session_id="s-orch")
    p2 = ea.propose(verb="demo_verb", grantee="hanuman",
                    bounds={"path_pattern": "b", "max_bytes": 1},
                    reason="second", verifier="rita", session_id="s-orch")

    # Ensure distinct timestamps on disk so the sort key is well-ordered
    registry_path, _ = fresh_registry
    doc = json.loads(registry_path.read_text(encoding="utf-8"))
    doc["proposals"][0]["proposed_at"] = "2026-08-25T10:00:00Z"
    doc["proposals"][1]["proposed_at"] = "2026-08-25T10:00:01Z"
    registry_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    os.chmod(str(registry_path), 0o600)

    pending = ea.list_pending(oldest_first=True)
    assert [r["id"] for r in pending] == [p1["id"], p2["id"]]

    newest_first = ea.list_pending(oldest_first=False)
    assert [r["id"] for r in newest_first] == [p2["id"], p1["id"]]


def test_list_pending_respects_limit(ring_with_rita, fresh_registry):
    for i in range(5):
        ea.propose(verb="demo_verb", grantee="hanuman",
                   bounds={"path_pattern": f"path{i}", "max_bytes": 1},
                   reason=f"r{i}", verifier="rita", session_id="s-orch")
    assert len(ea.list_pending(limit=3)) == 3
    assert len(ea.list_pending(limit=100)) == 5


# --- bounds_digest (frozen wire piece for FRANK events) --------------------


def test_bounds_digest_is_deterministic():
    a = ea._bounds_digest({"path_pattern": "docs/**", "max_bytes": 1024})
    b = ea._bounds_digest({"max_bytes": 1024, "path_pattern": "docs/**"})
    assert a == b, "sort_keys=True makes the digest key-order-independent"


def test_bounds_digest_changes_on_tamper():
    a = ea._bounds_digest({"path_pattern": "docs/**", "max_bytes": 1024})
    b = ea._bounds_digest({"path_pattern": "docs/**", "max_bytes": 2048})
    assert a != b, "value tamper must change the digest"
