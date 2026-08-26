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
from unittest import mock

import pytest

from willow_mcp import (
    envelope_authoring as ea,
    human_session,
    keyring as keyring_mod,
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


# --- PR11: rejected proposals move to archived[] with bounds intact -------


def test_reject_moves_to_archived_with_bounds_and_reopen_when(
    ring_with_rita, fresh_registry,
):
    """PR11: the whole point. Rejected rows survive in archived[] with
    the fields shape-scoring needs (bounds, verb, grantee, reopen_when,
    reject_reason, rejected_by, status)."""
    registry_path, _ = fresh_registry
    proposal = ea.propose(
        verb="demo_verb", grantee="hanuman",
        bounds={"path_pattern": "docs/**", "max_bytes": 4096},
        reason="draft", verifier="rita", session_id="s-orch",
    )
    ea.reject(
        proposal["id"], reason="too broad",
        reopen_when="hanuman gets audited by loki",
        verifier="rita",
    )
    on_disk = json.loads(registry_path.read_text(encoding="utf-8"))
    assert len(on_disk["archived"]) == 1
    arch = on_disk["archived"][0]
    assert arch["id"] == proposal["id"]
    assert arch["verb"] == "demo_verb"
    assert arch["grantee"] == "hanuman"
    assert arch["bounds"] == {"path_pattern": "docs/**", "max_bytes": 4096}
    assert arch["status"] == "rejected"
    assert arch["reject_reason"] == "too broad"
    assert arch["reopen_when"] == "hanuman gets audited by loki"
    assert arch["rejected_by"] == "rita"
    assert arch["archived_at"].endswith("Z")
    assert arch["rejected_at"] == arch["archived_at"]


def test_list_archived_reads_the_archive(ring_with_rita, fresh_registry):
    for i in range(3):
        p = ea.propose(
            verb="demo_verb", grantee="hanuman",
            bounds={"path_pattern": f"p{i}", "max_bytes": 1}, reason="t",
            verifier="rita", session_id="s-orch",
        )
        ea.reject(p["id"], reason=f"r{i}", verifier="rita")
    rows = ea.list_archived()
    assert len(rows) == 3
    assert {r["status"] for r in rows} == {"rejected"}


def test_list_archived_filters_by_grantee_verb_status(
    ring_with_rita, fresh_registry,
):
    p1 = ea.propose(verb="demo_verb", grantee="hanuman",
                    bounds={"path_pattern": "a", "max_bytes": 1},
                    reason="t", verifier="rita", session_id="s-orch")
    p2 = ea.propose(verb="demo_no_bounds", grantee="loki", bounds={},
                    reason="t2", verifier="rita", session_id="s-orch")
    ea.reject(p1["id"], reason="r", verifier="rita")
    ea.reject(p2["id"], reason="r", verifier="rita")

    assert len(ea.list_archived(grantee="hanuman")) == 1
    assert len(ea.list_archived(verb="demo_no_bounds")) == 1
    assert len(ea.list_archived(status="rejected")) == 2
    assert ea.list_archived(status="superseded") == []


def test_list_pending_precedent_expansion_includes_archived(
    ring_with_rita, fresh_registry,
):
    """PR11 + PR10 interop: an archived precedent id resolves in the
    expansion, decorated with precedent_status='rejected' so the ratify
    surface shows the polarity."""
    # First: a proposal, then reject it — becomes archived
    p_prior = ea.propose(
        verb="demo_verb", grantee="hanuman",
        bounds={"path_pattern": "docs/**", "max_bytes": 1024},
        reason="prior", verifier="rita", session_id="s-orch",
    )
    ea.reject(
        p_prior["id"], reason="too broad",
        reopen_when="see audit", verifier="rita",
    )
    # Now: a new proposal that references the archived id
    ea.propose(
        verb="demo_verb", grantee="hanuman",
        bounds={"path_pattern": "docs/**", "max_bytes": 2048},
        reason="widen", verifier="rita", session_id="s-orch",
        precedent_ids=[p_prior["id"]],
    )
    row = ea.list_pending()[0]
    assert len(row["precedents_expanded"]) == 1
    exp = row["precedents_expanded"][0]
    assert exp["id"] == p_prior["id"]
    assert exp["precedent_status"] == "rejected"
    assert exp["reopen_when"] == "see audit"


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


# --- PR10: precedents expanded inline in list_pending ---------------------


def _seed_active_envelope(registry_path, *, envelope_id, verb, grantee, bounds):
    """Plant an entry in the registry's active[] list without going through
    envelope_ratify — the pending precedent expansion is a pure read
    against active[], so we don't need the FRANK path for this test."""
    doc = json.loads(registry_path.read_text(encoding="utf-8"))
    doc.setdefault("active", []).append({
        "id": envelope_id,
        "verb": verb,
        "grantee": grantee,
        "bounds": bounds,
        "issued_by": "root",
        "issued_at": "2026-08-01T00:00:00Z",
    })
    registry_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    os.chmod(str(registry_path), 0o600)


def test_list_pending_expands_precedents_by_default(ring_with_rita, fresh_registry):
    """PR10: a pending row's precedent_ids resolve to the full active
    envelope rows inline so the ratify UX is one glance."""
    registry_path, _ = fresh_registry
    _seed_active_envelope(
        registry_path, envelope_id="ENV-PRIOR-1",
        verb="demo_verb", grantee="hanuman",
        bounds={"path_pattern": "docs/**", "max_bytes": 1024},
    )
    # Propose with an explicit precedent_ids so we don't depend on
    # shape-scoring finding it (that's tested in test_envelope_shapes.py).
    prop = ea.propose(
        verb="demo_verb", grantee="hanuman",
        bounds={"path_pattern": "docs/**", "max_bytes": 2048},
        reason="widen the quota", verifier="rita", session_id="s-orch",
        precedent_ids=["ENV-PRIOR-1"],
    )
    assert prop["precedent_ids"] == ["ENV-PRIOR-1"]

    pending = ea.list_pending()
    assert len(pending) == 1
    row = pending[0]
    assert row["precedent_ids"] == ["ENV-PRIOR-1"]
    exp = row["precedents_expanded"]
    assert len(exp) == 1
    assert exp[0]["id"] == "ENV-PRIOR-1"
    assert exp[0]["bounds"]["max_bytes"] == 1024


def test_list_pending_drops_unresolvable_precedent_from_expansion(
    ring_with_rita, fresh_registry,
):
    """A precedent_id that no longer resolves to active[] silently drops
    from the expansion. precedent_ids itself stays intact — the operator
    sees "one glance" info, the id list preserves the paper trail."""
    ea.propose(
        verb="demo_verb", grantee="hanuman",
        bounds={"path_pattern": "docs/**", "max_bytes": 2048},
        reason="widen the quota", verifier="rita", session_id="s-orch",
        precedent_ids=["ENV-REVOKED"],
    )
    row = ea.list_pending()[0]
    assert row["precedent_ids"] == ["ENV-REVOKED"]
    assert row["precedents_expanded"] == []


def test_list_pending_include_precedents_false_skips_expansion(
    ring_with_rita, fresh_registry,
):
    """The low-level caller who just wants the raw rows can opt out. The
    key must NOT be present when opted out — a caller keying off
    presence-of-precedents_expanded must see a real absence, not a
    misleading empty list."""
    registry_path, _ = fresh_registry
    _seed_active_envelope(
        registry_path, envelope_id="ENV-P",
        verb="demo_verb", grantee="hanuman",
        bounds={"path_pattern": "docs/**", "max_bytes": 1024},
    )
    ea.propose(
        verb="demo_verb", grantee="hanuman",
        bounds={"path_pattern": "docs/**", "max_bytes": 2048},
        reason="widen", verifier="rita", session_id="s-orch",
        precedent_ids=["ENV-P"],
    )
    row = ea.list_pending(include_precedents=False)[0]
    assert "precedents_expanded" not in row
    assert row["precedent_ids"] == ["ENV-P"]


def test_list_pending_expands_multiple_precedents(
    ring_with_rita, fresh_registry,
):
    registry_path, _ = fresh_registry
    for eid in ("ENV-A", "ENV-B", "ENV-C"):
        _seed_active_envelope(
            registry_path, envelope_id=eid,
            verb="demo_verb", grantee="hanuman",
            bounds={"path_pattern": f"pat-{eid}", "max_bytes": 1},
        )
    ea.propose(
        verb="demo_verb", grantee="hanuman",
        bounds={"path_pattern": "pat-new", "max_bytes": 1},
        reason="wider", verifier="rita", session_id="s-orch",
        precedent_ids=["ENV-A", "ENV-B", "ENV-C"],
    )
    row = ea.list_pending()[0]
    assert [e["id"] for e in row["precedents_expanded"]] == \
        ["ENV-A", "ENV-B", "ENV-C"]


# --- bounds_digest (frozen wire piece for FRANK events) --------------------


def test_bounds_digest_is_deterministic():
    a = ea._bounds_digest({"path_pattern": "docs/**", "max_bytes": 1024})
    b = ea._bounds_digest({"max_bytes": 1024, "path_pattern": "docs/**"})
    assert a == b, "sort_keys=True makes the digest key-order-independent"


def test_bounds_digest_changes_on_tamper():
    a = ea._bounds_digest({"path_pattern": "docs/**", "max_bytes": 1024})
    b = ea._bounds_digest({"path_pattern": "docs/**", "max_bytes": 2048})
    assert a != b, "value tamper must change the digest"
