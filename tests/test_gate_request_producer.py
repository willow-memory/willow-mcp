"""The ask half of the approval broker: something in a running server makes one.

`gates_panel` could render a gate request and `gates_actions` could approve one,
but `encode_request` had no caller outside the tests — so in a running server
the queue never held a request row for any prefix. The seam was built from the
operator's end inward and stopped one step short of the agent.

These tests hold the two halves of what `gate_request` is allowed to be: it
must actually produce a row (the gap), and it must produce nothing else (the
sudo invariant — an agent may REQUEST, never CONFIRM).
"""
from __future__ import annotations

import pytest

from willow_mcp import gate_request, gates_actions, gates_panel
from willow_mcp.db import Store


@pytest.fixture()
def store(tmp_path):
    # `store_root`, not WILLOW_HOME: the same isolation the other gate-request
    # tests use. A Store built without it is shared, and these tests assert on
    # queue contents, so a leaked row from a neighbour reads as a real result.
    return Store(store_root=str(tmp_path / "store"))


# ── it produces a row ────────────────────────────────────────────────────────

def test_a_lease_request_reaches_the_panel(store):
    """The whole point: an ask made here renders as a pressable row there."""
    result = gate_request.request_lease("kart", task_id="T1", store=store)
    assert result["queued"] is True

    rows = [r for r in gates_panel._request_rows(store) if r.scope == "lease.kart"]
    assert len(rows) == 1
    assert gates_actions.describe(rows[0]).kind == "request_grant"


def test_the_request_decodes_to_what_was_asked_for(store):
    gate_request.open_request("kart", "lease.kart", task_id="T7", store=store)

    items = gates_panel.open_requests(store)
    assert len(items) == 1
    req = items[0]["request"]
    assert req["gate_id"] == "lease.kart"
    assert req["task_id"] == "T7"
    assert req["nonce"] and req["expires_at"]


def test_ttl_is_capped_at_the_lease_ceiling(store):
    """"TTL: 3 hours maximum, matching lease.max_ttl_seconds" (operator,
    2026-07-29). A request that outlived the grant it asks for would be an ask
    the operator could answer with a lease that had already expired."""
    from willow_mcp import lease

    assert gate_request.max_ttl_seconds() == lease.MAX_TTL_SECONDS

    gate_request.open_request("kart", "lease.kart", ttl_seconds=10 ** 6, store=store)
    req = gates_panel.open_requests(store)[0]["request"]
    left = gates_panel._expiry_seconds(req["expires_at"])
    assert 0 < left <= lease.MAX_TTL_SECONDS


# ── it produces nothing else ─────────────────────────────────────────────────

def test_never_requestable_groups_are_refused(store):
    """`PERM_NEVER_REQUESTABLE` exists so the queue cannot become a phishing
    surface — an agent must not be able to put "grant me full_access" in front
    of a tired operator at the top of a list. The producer honours it, so such
    a row is never written rather than written-and-unpressable."""
    for group in ("full_access", "orchestrator", "binding"):
        result = gate_request.open_request("kart", f"perm.kart.{group}", store=store)
        assert result["queued"] is False, group
        assert group in result["reason"]

    assert gates_panel.open_requests(store) == []


def test_a_gate_outside_the_allowlist_is_refused(store):
    result = gate_request.open_request("kart", "sudo.kart", store=store)
    assert result["queued"] is False
    assert "names no requestable gate" in result["reason"]
    assert gates_panel.open_requests(store) == []


def test_an_empty_gate_is_refused(store):
    assert gate_request.open_request("kart", "", store=store)["queued"] is False
    assert gate_request.open_request("kart", "   ", store=store)["queued"] is False


def test_a_malformed_perm_gate_is_refused(store):
    result = gate_request.open_request("kart", "perm.kart", store=store)
    assert result["queued"] is False
    assert gates_panel.open_requests(store) == []


def test_requesting_grants_nothing(store, tmp_path, monkeypatch):
    """The invariant in one assertion: after the ask, the gate is still shut.

    A dedicated WILLOW_HOME and an app_id nothing else names, so this asserts
    on the ask's own effect rather than on whatever leases the host running
    the suite happens to hold.
    """
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path / "home"))
    from willow_mcp import lease

    app_id = "app-that-holds-nothing"
    assert lease.read_lease(app_id)["status"] != "active"

    result = gate_request.request_lease(app_id, store=store)
    assert result["queued"] is True
    assert lease.read_lease(app_id)["status"] != "active"


# ── it does not flood the queue ──────────────────────────────────────────────

def test_the_same_task_retrying_makes_one_row(store):
    """A denial inside a retry loop would otherwise enqueue a row per attempt,
    and a queue the operator is meant to watch becomes one they learn to
    ignore."""
    first = gate_request.request_lease("kart", task_id="T1", store=store)
    second = gate_request.request_lease("kart", task_id="T1", store=store)

    assert first["queued"] is True
    assert second["queued"] is False
    assert second["duplicate_of"] == first["id"]
    assert len(gates_panel.open_requests(store)) == 1


def test_two_tasks_are_two_asks(store):
    """"The request names the exact task, not the app" — so two tasks needing
    the same lease are two asks, even though the gate id is identical."""
    gate_request.request_lease("kart", task_id="T1", store=store)
    gate_request.request_lease("kart", task_id="T2", store=store)

    assert len(gates_panel.open_requests(store)) == 2


# ── it fails closed ──────────────────────────────────────────────────────────

def test_enqueue_failure_is_reported_not_raised(store, monkeypatch):
    """"A request mechanism that swallows its own failure and proceeds is worse
    than none" — but it is the CALLER that must still refuse, and the caller is
    mid-denial. So this reports, and never raises into that path."""
    def _boom(*_a, **_k):
        raise RuntimeError("queue is on fire")

    monkeypatch.setattr(gate_request_human_loop(), "enqueue", _boom)

    result = gate_request.open_request("kart", "lease.kart", store=store)
    assert result["queued"] is False
    assert "queue is on fire" in result["reason"]


def test_the_denial_note_is_empty_when_nothing_was_queued(store, monkeypatch):
    """A failed enqueue must not put a claim in the operator's face that no row
    backs. Silence is the honest suffix."""
    def _boom(*_a, **_k):
        raise RuntimeError("nope")

    monkeypatch.setattr(gate_request_human_loop(), "enqueue", _boom)
    assert gate_request.note_for_lease_denial("kart", store=store) == ""


def gate_request_human_loop():
    from willow_mcp import human_loop

    return human_loop
