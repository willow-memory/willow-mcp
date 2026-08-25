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


# --- discard-residue walk (Nestor two-walk pattern) ----------------------
#
# Silent-on-write is fine for _auto_propose_on_gate_miss (the specialist
# still gets its real errno from _enveloped_verb_gate); silent OVERALL is
# the failure. These tests pin the second walk: what got swallowed lands
# in _auto_propose_discards with enough context to diagnose, per Nestor's
# ledger.entries() + ledger.unreadable() prior.


def test_unknown_verb_records_discard(
    ring_with_rita, registry_with_demo_verb, attributed_orchestrator_session
):
    sid = attributed_orchestrator_session
    server._auto_propose_on_gate_miss(
        "willow", "verb_not_in_table", _call_args(), sid
    )
    discards = server.list_auto_propose_discards()
    assert len(discards) == 1
    d = discards[0]
    assert d["verb"] == "verb_not_in_table"
    assert d["session_id"] == sid
    assert d["verifier"] == "rita"
    assert d["app_id"] == "willow"
    assert d["error_class"] == "UnknownVerbError"
    assert d["bounds"] == _call_args()
    assert d["at"].endswith("Z")


def test_invalid_bounds_records_discard(
    ring_with_rita, registry_with_demo_verb, attributed_orchestrator_session
):
    sid = attributed_orchestrator_session
    server._auto_propose_on_gate_miss(
        "willow", "demo_verb", {"wrong_key": "value"}, sid
    )
    discards = server.list_auto_propose_discards()
    assert len(discards) == 1
    assert discards[0]["error_class"] == "InvalidBoundsSignatureError"
    assert discards[0]["bounds"] == {"wrong_key": "value"}


def test_successful_propose_leaves_no_discard(
    ring_with_rita, registry_with_demo_verb, attributed_orchestrator_session
):
    """The residue walk counts only what got swallowed. A successful
    propose lands in pending[], not in discards[]."""
    sid = attributed_orchestrator_session
    server._auto_propose_on_gate_miss("willow", "demo_verb", _call_args(), sid)
    assert len(ea.list_pending()) == 1
    assert server.list_auto_propose_discards() == []


def test_list_discards_filters_by_session(
    ring_with_rita, registry_with_demo_verb
):
    dispatch.session_bind("willow", "s-discard-a", "", "idle", verifier="rita")
    dispatch.session_bind("willow", "s-discard-b", "", "idle", verifier="rita")
    human_session._remember_attributed("s-discard-a")
    human_session._remember_attributed("s-discard-b")
    server._auto_propose_on_gate_miss(
        "willow", "verb_not_in_table", _call_args(), "s-discard-a"
    )
    server._auto_propose_on_gate_miss(
        "willow", "demo_verb", {"wrong_key": "x"}, "s-discard-b"
    )
    all_ = server.list_auto_propose_discards()
    assert len(all_) == 2
    only_a = server.list_auto_propose_discards("s-discard-a")
    assert len(only_a) == 1 and only_a[0]["session_id"] == "s-discard-a"
    only_b = server.list_auto_propose_discards("s-discard-b")
    assert len(only_b) == 1 and only_b[0]["session_id"] == "s-discard-b"


def test_clear_cache_global_clears_discards(
    ring_with_rita, registry_with_demo_verb, attributed_orchestrator_session
):
    sid = attributed_orchestrator_session
    server._auto_propose_on_gate_miss(
        "willow", "verb_not_in_table", _call_args(), sid
    )
    assert len(server.list_auto_propose_discards()) == 1
    server.clear_auto_propose_cache()
    assert server.list_auto_propose_discards() == []


def test_clear_cache_session_scoped_leaves_other_discards(
    ring_with_rita, registry_with_demo_verb
):
    dispatch.session_bind("willow", "s-discard-c", "", "idle", verifier="rita")
    dispatch.session_bind("willow", "s-discard-d", "", "idle", verifier="rita")
    human_session._remember_attributed("s-discard-c")
    human_session._remember_attributed("s-discard-d")
    server._auto_propose_on_gate_miss(
        "willow", "verb_not_in_table", _call_args(), "s-discard-c"
    )
    server._auto_propose_on_gate_miss(
        "willow", "verb_not_in_table", _call_args(), "s-discard-d"
    )
    server.clear_auto_propose_cache("s-discard-c")
    remaining = server.list_auto_propose_discards()
    assert len(remaining) == 1
    assert remaining[0]["session_id"] == "s-discard-d"


def _willow_manifest(tmp_path, monkeypatch):
    """Minimal manifest so session_enter (guarded) doesn't get denied by
    the manifest gate."""
    root = tmp_path / "mcp_apps"
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(root))
    path = root / "willow" / "manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "permissions": ["orchestrator", "full_access"],
        "store_scope": ["projects_willow_*", "willow_*"],
    }))


def test_session_enter_orient_surfaces_discard_count(
    ring_with_rita, registry_with_demo_verb, monkeypatch, tmp_path
):
    """The orient block on an orchestrator session_enter surfaces the
    discard count so the operator sees residue at seat-open — the count
    is not silently kept in a process-local variable no one reads."""
    _willow_manifest(tmp_path, monkeypatch)
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    sid = "s-orient-discards"
    dispatch.session_bind("willow", sid, "", "idle", verifier="rita")
    human_session._remember_attributed(sid)
    # Seed one discard
    server._auto_propose_on_gate_miss(
        "willow", "verb_not_in_table", _call_args(), sid
    )
    # Re-enter the orchestrator session — orient should carry the count
    result = server.session_enter(
        app_id="willow", session_id=sid, project="", workspace="",
    )
    orient = result.get("orientation") or {}
    discard_block = orient.get("envelope_auto_propose_discards")
    assert discard_block is not None
    assert discard_block["count"] == 1
    assert discard_block["latest_error_class"] == "UnknownVerbError"


def test_session_enter_orient_zero_when_none(
    ring_with_rita, registry_with_demo_verb,
    attributed_orchestrator_session, monkeypatch, tmp_path,
):
    """No discards → count 0, latest_error_class None. Present on every
    orchestrator orient, not conditionally hidden."""
    _willow_manifest(tmp_path, monkeypatch)
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    sid = attributed_orchestrator_session
    result = server.session_enter(
        app_id="willow", session_id=sid, project="", workspace="",
    )
    orient = result.get("orientation") or {}
    discard_block = orient.get("envelope_auto_propose_discards")
    assert discard_block is not None
    assert discard_block["count"] == 0
    assert discard_block["latest_error_class"] is None


def test_envelope_read_discards_tool_reads_residue(
    ring_with_rita, registry_with_demo_verb, monkeypatch, tmp_path,
):
    """The MCP READ tool returns the same list list_auto_propose_discards
    exposes internally, wrapped in {'discards': [...]}."""
    _willow_manifest(tmp_path, monkeypatch)
    sid = "s-read-discards-tool"
    dispatch.session_bind("willow", sid, "", "idle", verifier="rita")
    human_session._remember_attributed(sid)
    server._auto_propose_on_gate_miss(
        "willow", "verb_not_in_table", _call_args(), sid
    )
    result = server.envelope_read_discards()
    assert "discards" in result
    assert len(result["discards"]) == 1
    assert result["discards"][0]["error_class"] == "UnknownVerbError"

    result_scoped = server.envelope_read_discards(session_id=sid)
    assert len(result_scoped["discards"]) == 1
    result_empty = server.envelope_read_discards(session_id="s-does-not-exist")
    assert result_empty["discards"] == []
