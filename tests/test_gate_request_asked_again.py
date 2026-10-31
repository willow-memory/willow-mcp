"""An ask that expired unanswered is dismissed when the same gate and task is
asked again, and the new ask says how many times it has been asked.

The dedup (`_open_duplicate`) only ever matched an unexpired ask, and nothing
took an expired one out of the queue. So every denial after the 3-hour TTL
filed a fresh row beside the dead ones: 86 open asks in 45 (gate, task) pairs
on the operator's box on 2026-10-31, `lease.willow` alone twelve times. The
panel's own advice for an expired row is "dismiss it and ask again"; the
denial that asks again now does the dismissing.
"""
from __future__ import annotations

import pytest

from willow_mcp import gate_request, gates_panel, human_loop
from willow_mcp.db import Store


@pytest.fixture()
def store(tmp_path):
    return Store(store_root=str(tmp_path / "store"))


@pytest.fixture()
def expire(monkeypatch):
    """expire(result): the ask `result` names reads as past its expiry."""
    gone: set[str] = set()
    real = gates_panel._expiry_seconds

    def _expiry_seconds(expires_at):
        return -1.0 if expires_at in gone else real(expires_at)

    monkeypatch.setattr(gates_panel, "_expiry_seconds", _expiry_seconds)
    return lambda result: gone.add(result["expires_at"])


def _row(store, item_id):
    return next(i for i in human_loop.list_queue(store, status="", limit=500) if i["id"] == item_id)


def test_asking_again_after_expiry_dismisses_the_expired_ask(store, expire):
    first = gate_request.request_lease("kart", task_id="T1", store=store)
    expire(first)
    second = gate_request.request_lease("kart", task_id="T1", store=store)
    assert second["queued"] is True and second["dismissed_expired"] == [first["id"]]
    old = _row(store, first["id"])
    assert old["status"] == "dismissed" and old["resolved_by"] == "willow-mcp"
    assert old["note"] == f"expired unanswered; asked again as {second['id']}"
    assert [i["id"] for i in gates_panel.open_requests(store)] == [second["id"]]


def test_the_new_ask_says_it_is_a_repeat_and_carries_the_count(store, expire):
    asks = [gate_request.request_lease("kart", task_id="T1", store=store)]
    for _ in range(3):
        expire(asks[-1])
        asks.append(gate_request.request_lease("kart", task_id="T1", store=store))
    first_day = _row(store, asks[0]["id"])["created_at"][:10]
    assert "(asked" not in _row(store, asks[0]["id"])["summary"]
    assert _row(store, asks[1]["id"])["summary"].endswith(
        f"(asked 2 times since {first_day}; earlier asks expired unanswered)")
    assert f"(asked 4 times since {first_day};" in _row(store, asks[3]["id"])["summary"]
    assert len(gates_panel.open_requests(store)) == 1


def test_every_expired_ask_for_the_pair_goes_at_once(store):
    """Rows left from before the fix: several expired asks for one pair."""
    rows = []
    for n in range(3):  # what the build before this one left: one row per expiry
        rows.append(human_loop.enqueue(
            store, kind=gates_panel.REQUEST_QUEUE_KIND, title="Request: lease.kart",
            summary="kart was refused for want of lease.kart", source_agent="kart",
            source_ref=gates_panel.encode_request(gate_id="lease.kart", task_id="T1",
                                                  nonce=f"{n:016x}", expires_at=f"2026-09-2{n}T00:00:00Z")))
    assert len(gates_panel.open_requests(store)) == 3
    new = gate_request.request_lease("kart", task_id="T1", store=store)
    assert sorted(new["dismissed_expired"]) == sorted(r["id"] for r in rows)
    assert [i["id"] for i in gates_panel.open_requests(store)] == [new["id"]]


def test_an_unexpired_ask_is_still_the_one_row(store):
    first = gate_request.request_lease("kart", task_id="T1", store=store)
    second = gate_request.request_lease("kart", task_id="T1", store=store)
    assert second["queued"] is False and second["duplicate_of"] == first["id"]
    assert "dismissed_expired" not in second and _row(store, first["id"])["status"] == "open"


def test_another_task_or_gate_is_never_dismissed(store, expire):
    other_task = gate_request.request_lease("kart", task_id="T2", store=store)
    other_gate = gate_request.open_request("kart", "perm.kart.fleet_read", task_id="T1", store=store)
    expire(other_task)
    expire(other_gate)
    new = gate_request.request_lease("kart", task_id="T1", store=store)
    assert "dismissed_expired" not in new
    assert _row(store, other_task["id"])["status"] == "open"
    assert _row(store, other_gate["id"])["status"] == "open"


def test_a_failed_enqueue_dismisses_nothing(store, expire, monkeypatch):
    first = gate_request.request_lease("kart", task_id="T1", store=store)
    expire(first)

    def _boom(*_a, **_k):
        raise RuntimeError("queue is on fire")

    monkeypatch.setattr(human_loop, "enqueue", _boom)
    result = gate_request.request_lease("kart", task_id="T1", store=store)
    assert result["queued"] is False and "queue is on fire" in result["reason"]
    assert _row(store, first["id"])["status"] == "open"


def test_a_failed_dismissal_still_queues_the_new_ask(store, expire, monkeypatch):
    first = gate_request.request_lease("kart", task_id="T1", store=store)
    expire(first)

    def _boom(*_a, **_k):
        raise RuntimeError("store busy")

    monkeypatch.setattr(human_loop, "resolve", _boom)
    second = gate_request.request_lease("kart", task_id="T1", store=store)
    assert second["queued"] is True and "dismissed_expired" not in second
    assert _row(store, first["id"])["status"] == "open"
