"""PR6: _enveloped_verb_gate auto-writes a proposal on gate misses.

Invariants:
* Fires when the current session is a keyring-attributed orchestrator
  session with a verifier on record.
* Does NOT fire when keyring is disabled.
* Does NOT fire when the session is not in the attribution cache.
* Does NOT fire when the session record has no verifier.
* Captures the actual call_args as bounds.
* Deduplicates by (session, verb, bounds_digest) — repeat calls with the
  same shape produce ONE proposal, not N.
* Different bounds for the same (session, verb) produce distinct proposals.
* Does NOT block or alter the gate's original return path — auto-propose
  is a side-effect on both permissive-ENOGRANTS and refusal paths.
"""
from __future__ import annotations

import json
import os

import pytest

from willow_mcp import (
    dispatch,
    envelope_authoring as ea,
    human_session,
    keyring as keyring_mod,
    server,
)


@pytest.fixture
def ring_with_rita(tmp_path):
    human_session.clear_attribution_cache()
    server.clear_auto_propose_cache()
    with keyring_mod.isolated():
        k = keyring_mod.Keyring(path=str(tmp_path / "keys.json"))
        k.add("rita")
        k.save()
        keyring_mod.set_keyring(k)
        try:
            yield k
        finally:
            keyring_mod.set_keyring(None)
            human_session.clear_attribution_cache()
            server.clear_auto_propose_cache()


@pytest.fixture
def registry_with_demo_verb(tmp_path, monkeypatch):
    """Point the envelope registry + syscall table at throwaway files with
    'demo_verb' declared."""
    registry_path = tmp_path / "pre-approved.json"
    syscall_path = tmp_path / "syscall-table.json"
    registry_path.write_text(
        json.dumps({
            "schema": "envelope-registry/v1.1",
            "active": [], "proposals": [],
        }, indent=2), encoding="utf-8",
    )
    syscall_path.write_text(
        json.dumps({
            "verbs": [{
                "id": 999, "verb": "demo_verb",
                "bounds": {"path_pattern": "", "max_bytes": 0},
            }]
        }, indent=2), encoding="utf-8",
    )
    os.chmod(str(registry_path), 0o600)
    os.chmod(str(syscall_path), 0o600)
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(registry_path))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(syscall_path))
    return registry_path


@pytest.fixture
def attributed_orchestrator_session(ring_with_rita):
    """A session_enter'd orchestrator session with rita as verifier, in
    the attribution cache. Returns the session_id."""
    sid = "s-orch-auto-propose"
    # Write the session record with a verifier field, then add to cache
    dispatch.session_bind("willow", sid, "", "idle", verifier="rita")
    human_session._remember_attributed(sid)
    return sid


def _call_args(**kw):
    return {"path_pattern": kw.get("path_pattern", "docs/**"),
            "max_bytes": kw.get("max_bytes", 1024)}


# --- fires when attribution is in place ------------------------------------


def test_gate_miss_writes_proposal_when_attributed(
    ring_with_rita, registry_with_demo_verb, attributed_orchestrator_session
):
    sid = attributed_orchestrator_session
    server._auto_propose_on_gate_miss(
        "willow", "demo_verb", _call_args(), sid
    )
    pending = ea.list_pending()
    assert len(pending) == 1
    assert pending[0]["verb"] == "demo_verb"
    assert pending[0]["grantee"] == "willow"
    assert pending[0]["bounds"] == _call_args()
    assert "auto-proposed from gate miss" in pending[0]["notes"]
    assert pending[0]["proposed_by"]["verifier"] == "rita"
    assert pending[0]["proposed_by"]["session_id"] == sid


# --- does NOT fire without keyring / attribution / verifier --------------


def test_no_propose_when_keyring_disabled(
    registry_with_demo_verb, monkeypatch
):
    keyring_mod.set_keyring(None)
    monkeypatch.delenv("WILLOW_KEYRING", raising=False)
    monkeypatch.setattr(keyring_mod, "_from_env", None)
    monkeypatch.setattr(keyring_mod, "_loaded_from", None)
    dispatch.session_bind("willow", "s-autopropose-nokey", "", "idle", verifier="")

    server._auto_propose_on_gate_miss(
        "willow", "demo_verb", _call_args(), "s-autopropose-nokey"
    )
    assert ea.list_pending() == []


def test_no_propose_when_session_not_in_cache(
    ring_with_rita, registry_with_demo_verb
):
    dispatch.session_bind("willow", "s-autopropose-not-cached", "", "idle", verifier="rita")
    # Deliberately NOT calling _remember_attributed — cache miss
    server._auto_propose_on_gate_miss(
        "willow", "demo_verb", _call_args(), "s-autopropose-not-cached"
    )
    assert ea.list_pending() == []


def test_no_propose_when_session_record_has_no_verifier(
    ring_with_rita, registry_with_demo_verb
):
    sid = "s-autopropose-no-verifier"
    dispatch.session_bind("willow", sid, "", "idle", verifier="")
    human_session._remember_attributed(sid)
    server._auto_propose_on_gate_miss(
        "willow", "demo_verb", _call_args(), sid
    )
    assert ea.list_pending() == []


def test_no_propose_when_session_id_empty(
    ring_with_rita, registry_with_demo_verb
):
    server._auto_propose_on_gate_miss("willow", "demo_verb", _call_args(), "")
    assert ea.list_pending() == []


# --- dedup by (session, verb, bounds_digest) ------------------------------


def test_dedup_same_shape_produces_one_proposal(
    ring_with_rita, registry_with_demo_verb, attributed_orchestrator_session
):
    sid = attributed_orchestrator_session
    for _ in range(5):
        server._auto_propose_on_gate_miss(
            "willow", "demo_verb", _call_args(), sid
        )
    assert len(ea.list_pending()) == 1


def test_different_bounds_produce_distinct_proposals(
    ring_with_rita, registry_with_demo_verb, attributed_orchestrator_session
):
    sid = attributed_orchestrator_session
    server._auto_propose_on_gate_miss(
        "willow", "demo_verb", _call_args(path_pattern="docs/**"), sid
    )
    server._auto_propose_on_gate_miss(
        "willow", "demo_verb", _call_args(path_pattern="src/**"), sid
    )
    server._auto_propose_on_gate_miss(
        "willow", "demo_verb",
        _call_args(path_pattern="docs/**", max_bytes=4096), sid
    )
    assert len(ea.list_pending()) == 3


def test_different_verbs_produce_distinct_proposals(
    ring_with_rita, registry_with_demo_verb, attributed_orchestrator_session
):
    """Add a second verb so the test isn't restricted to demo_verb."""
    sid = attributed_orchestrator_session
    # Extend the syscall table with a second verb
    syscall = json.loads(
        os.environ["WILLOW_SYSCALL_TABLE"] and
        open(os.environ["WILLOW_SYSCALL_TABLE"]).read()
    )
    syscall["verbs"].append({
        "id": 1000, "verb": "second_verb",
        "bounds": {"path_pattern": "", "max_bytes": 0},
    })
    with open(os.environ["WILLOW_SYSCALL_TABLE"], "w") as fh:
        fh.write(json.dumps(syscall, indent=2))
    os.chmod(os.environ["WILLOW_SYSCALL_TABLE"], 0o600)

    server._auto_propose_on_gate_miss("willow", "demo_verb", _call_args(), sid)
    server._auto_propose_on_gate_miss("willow", "second_verb", _call_args(), sid)
    assert len(ea.list_pending()) == 2


def test_dedup_cache_clears_on_clear_auto_propose_cache(
    ring_with_rita, registry_with_demo_verb, attributed_orchestrator_session
):
    """Post-restart / test-fixture use: clearing the cache lets a repeat
    shape re-propose (which is fine — proposals[] itself is idempotent
    only by design; a cache clear followed by another call is treated as
    a legitimate re-attempt)."""
    sid = attributed_orchestrator_session
    server._auto_propose_on_gate_miss("willow", "demo_verb", _call_args(), sid)
    assert len(ea.list_pending()) == 1

    server.clear_auto_propose_cache()

    # After a cache clear, the same shape can propose again
    server._auto_propose_on_gate_miss("willow", "demo_verb", _call_args(), sid)
    assert len(ea.list_pending()) == 2, (
        "after clear_auto_propose_cache(), a repeat shape does re-propose"
    )


def test_clear_cache_specific_session_leaves_others(
    ring_with_rita, registry_with_demo_verb
):
    dispatch.session_bind("willow", "s-autopropose-a", "", "idle", verifier="rita")
    dispatch.session_bind("willow", "s-autopropose-b", "", "idle", verifier="rita")
    human_session._remember_attributed("s-autopropose-a")
    human_session._remember_attributed("s-autopropose-b")
    server._auto_propose_on_gate_miss("willow", "demo_verb", _call_args(), "s-autopropose-a")
    server._auto_propose_on_gate_miss("willow", "demo_verb", _call_args(), "s-autopropose-b")

    server.clear_auto_propose_cache("s-autopropose-a")  # only drop s-a

    server._auto_propose_on_gate_miss("willow", "demo_verb", _call_args(), "s-autopropose-a")
    server._auto_propose_on_gate_miss("willow", "demo_verb", _call_args(), "s-autopropose-b")
    # s-a re-proposed; s-b was still in cache so no re-propose
    pending_by_session = {}
    for row in ea.list_pending():
        sid = row["proposed_by"]["session_id"]
        pending_by_session.setdefault(sid, 0)
        pending_by_session[sid] += 1
    assert pending_by_session.get("s-autopropose-a") == 2
    assert pending_by_session.get("s-autopropose-b") == 1


# --- silent failure — never masks the gate's real return -----------------


def test_unknown_verb_is_silent(
    ring_with_rita, registry_with_demo_verb, attributed_orchestrator_session
):
    """A verb not in the syscall table means propose refuses inside the
    auto-propose path. Must silently swallow — the gate's real behavior
    (proceed or refuse) is unchanged."""
    sid = attributed_orchestrator_session
    # No exception raised
    server._auto_propose_on_gate_miss(
        "willow", "verb_not_in_table", _call_args(), sid
    )
    assert ea.list_pending() == []  # nothing landed


def test_invalid_bounds_is_silent(
    ring_with_rita, registry_with_demo_verb, attributed_orchestrator_session
):
    """call_args with wrong bounds signature means propose refuses. Must
    swallow silently."""
    sid = attributed_orchestrator_session
    server._auto_propose_on_gate_miss(
        "willow", "demo_verb", {"wrong_key": "value"}, sid
    )
    assert ea.list_pending() == []
