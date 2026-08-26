"""PR9 (envelope-accrual): dispatch packet carries operator identity.

Kart-boundary silence, part A — the "specialist as its own MCP client"
case. A specialist that inherits the orchestrator's verifier through
the dispatch packet can now auto-propose from its own gate misses,
attributed back to the human who dispatched it. Previously silent:
`_auto_propose_on_gate_miss` short-circuited on
`is_session_attributed=False` for every specialist.

Invariants pinned:

* dispatch_send writes ``from_verifier`` + ``from_session`` into
  meta.json when the calling orchestrator's session is attributed.
* Both fields are covered by the HMAC signature — tampering with
  either invalidates the packet.
* Empty when the orchestrator's session is unattested — the
  no-attribution-to-carry case stays no-attribution-in-the-packet.
* dispatch_accept lifts ``from_verifier`` onto the specialist's session
  record via ``session_bind(..., verifier=...)`` AND adds the specialist
  session to the in-process attribution cache.
* session_enter's specialist re-entry branch (packet already accepted)
  does the same lift on every re-entry.
* Once attributed, the specialist's own `_auto_propose_on_gate_miss`
  fires and produces a proposal whose ``proposed_by.verifier`` is the
  ORCHESTRATOR's verifier — the operator's queue view names them, not
  the specialist that generated the miss.
* An unattributed dispatch packet (from_verifier="") does NOT attribute
  the specialist — the silence is preserved rather than laundered.
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


# --- fixtures --------------------------------------------------------------


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


def _send(from_verifier: str = "rita", from_session: str = "s-orch"):
    """Dispatch a packet from willow to hanuman, optionally attributed."""
    return dispatch.dispatch_send(
        from_app="willow",
        to_app="hanuman",
        assignment_md="do the thing",
        role="build",
        from_verifier=from_verifier,
        from_session=from_session,
    )


# --- meta.json shape -------------------------------------------------------


def test_dispatch_send_writes_from_verifier_and_from_session(ring_with_rita):
    out = _send(from_verifier="rita", from_session="s-orch")
    did = out["dispatch_id"]
    pkt = dispatch.dispatch_read(did)
    assert pkt["meta"]["from_verifier"] == "rita"
    assert pkt["meta"]["from_session"] == "s-orch"


def test_dispatch_send_leaves_empty_when_unattributed(ring_with_rita):
    out = _send(from_verifier="", from_session="")
    pkt = dispatch.dispatch_read(out["dispatch_id"])
    assert pkt["meta"]["from_verifier"] == ""
    assert pkt["meta"]["from_session"] == ""


def test_signature_covers_from_verifier(ring_with_rita, tmp_path, monkeypatch):
    """Tamper with from_verifier post-write → dispatch_read refuses.
    Same HMAC coverage as every other meta field."""
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    out = _send(from_verifier="rita", from_session="s-orch")
    did = out["dispatch_id"]
    meta_path = dispatch.dispatch_dir(did) / "meta.json"
    meta = json.loads(meta_path.read_text())
    meta["from_verifier"] = "mallory"
    meta_path.write_text(json.dumps(meta))
    pkt = dispatch.dispatch_read(did)
    assert pkt.get("error") == "invalid_signature"


def test_signature_covers_from_session(ring_with_rita, tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    out = _send(from_verifier="rita", from_session="s-orch")
    did = out["dispatch_id"]
    meta_path = dispatch.dispatch_dir(did) / "meta.json"
    meta = json.loads(meta_path.read_text())
    meta["from_session"] = "s-forgery"
    meta_path.write_text(json.dumps(meta))
    pkt = dispatch.dispatch_read(did)
    assert pkt.get("error") == "invalid_signature"


# --- dispatch_accept lifts attribution ------------------------------------


def test_dispatch_accept_lifts_verifier_onto_session_record(ring_with_rita):
    out = _send()
    did = out["dispatch_id"]
    dispatch.dispatch_accept(did, "hanuman", "s-hanu-accepting")
    rec = dispatch.session_read("hanuman", "s-hanu-accepting")
    assert rec.get("verifier") == "rita"


def test_dispatch_accept_remembers_specialist_in_attribution_cache(
    ring_with_rita
):
    out = _send()
    dispatch.dispatch_accept(
        out["dispatch_id"], "hanuman", "s-hanu-attributed"
    )
    assert human_session.is_session_attributed("s-hanu-attributed")


def test_dispatch_accept_unattributed_packet_does_not_attribute(
    ring_with_rita
):
    """The whole guardrail: an unattributed dispatch does not
    silently promote its specialist to attributed."""
    out = _send(from_verifier="", from_session="")
    dispatch.dispatch_accept(
        out["dispatch_id"], "hanuman", "s-hanu-still-unattributed"
    )
    assert not human_session.is_session_attributed(
        "s-hanu-still-unattributed"
    )
    rec = dispatch.session_read("hanuman", "s-hanu-still-unattributed")
    assert rec.get("verifier") == ""


# --- session_enter re-entry branch ---------------------------------------


def test_session_enter_reentry_lifts_verifier(
    ring_with_rita, tmp_path, monkeypatch
):
    """A specialist reconnecting to an already-accepted packet
    (dispatch_accept ran earlier, cur='working') still has the
    attribution lifted onto its session on re-entry."""
    out = _send()
    did = out["dispatch_id"]
    # First accept — packet moves to working.
    dispatch.dispatch_accept(did, "hanuman", "s-hanu-first")
    human_session.clear_attribution_cache()  # simulate process restart
    # Re-enter same packet under a different session.
    _minimal_project(tmp_path, monkeypatch)
    dispatch.session_enter(
        app_id="hanuman", session_id="s-hanu-reentry",
        project="", workspace="", dispatch_id=did,
    )
    rec = dispatch.session_read("hanuman", "s-hanu-reentry")
    assert rec.get("verifier") == "rita"
    assert human_session.is_session_attributed("s-hanu-reentry")


def _minimal_project(tmp_path, monkeypatch):
    """Give session_enter a project it doesn't refuse."""
    project = tmp_path / "repo"
    project.mkdir(exist_ok=True)


# --- E2E: specialist gate miss produces attributed proposal --------------


def test_specialist_gate_miss_auto_proposes_as_orchestrator(
    ring_with_rita, registry_with_demo_verb, tmp_path, monkeypatch,
):
    """The end-to-end story: rita opens a session, dispatches to hanuman,
    hanuman inherits rita's attribution via the packet, hanuman hits
    ENOGRANTS on demo_verb → a proposal appears attributed to rita,
    not to hanuman-with-no-verifier."""
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    # rita opens her orchestrator session
    dispatch.session_bind("willow", "s-orch", "", "idle", verifier="rita")
    human_session._remember_attributed("s-orch")

    # rita dispatches to hanuman, packet carries her attribution
    out = _send(from_verifier="rita", from_session="s-orch")
    did = out["dispatch_id"]

    # hanuman accepts — attribution lifted onto s-hanu
    dispatch.dispatch_accept(did, "hanuman", "s-hanu")

    # hanuman hits ENOGRANTS on demo_verb (verb defined but no envelope
    # grants it to hanuman). Auto-propose is called from the gate miss
    # with the specialist's session as attribution source.
    server._auto_propose_on_gate_miss(
        "hanuman", "demo_verb",
        {"path_pattern": "docs/**", "max_bytes": 1024},
        "s-hanu",
    )

    pending = ea.list_pending()
    assert len(pending) == 1
    p = pending[0]
    assert p["grantee"] == "hanuman"  # the grantee is the specialist
    assert p["verb"] == "demo_verb"
    # The proposer of record: rita, via her hanuman-side session. That's
    # the whole point — the operator's queue names the human, not
    # "hanuman with no keyring identity."
    assert p["proposed_by"]["verifier"] == "rita"
    assert p["proposed_by"]["session_id"] == "s-hanu"


def test_specialist_without_inherited_attribution_stays_silent(
    ring_with_rita, registry_with_demo_verb, tmp_path, monkeypatch,
):
    """Guardrail: hanuman dispatched by an UNATTRIBUTED orchestrator
    still can't auto-propose. This is the case dispatch_accept must
    not launder — silence preserved when there's nothing to inherit."""
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    # No verifier on the orchestrator side
    out = _send(from_verifier="", from_session="")
    dispatch.dispatch_accept(
        out["dispatch_id"], "hanuman", "s-hanu-silent"
    )
    server._auto_propose_on_gate_miss(
        "hanuman", "demo_verb",
        {"path_pattern": "docs/**", "max_bytes": 1024},
        "s-hanu-silent",
    )
    assert ea.list_pending() == []
