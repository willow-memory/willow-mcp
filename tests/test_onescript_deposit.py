"""onescript_deposit — the pooled set becomes governance drafts, never seals.

The pooled read and Nestor are stubbed: what is asserted is what the deposit
wrote (one record + one propose per subject), that a second run adds nothing,
and that no seal path is ever reached.
"""
from __future__ import annotations

import json

import pytest

from willow_mcp import decision_bridge, gate
from willow_mcp import onescript_deposit as dep
from willow_mcp import onescript_executor as ox
from willow_mcp import seal_drain, seal_handler, server, tool_oracle
from willow_mcp.db import Store


def _pair(n: int) -> dict:
    return {"subject": f"proposal:{n:016x}", "path": f"p/{n}", "data": {"n": n},
            "cites": [f"c{n}"], "claim": f"claim {n}\nmore"}


def _pooled(*pairs) -> dict:
    return {"ok": True, "ran": True, "step": "pooled", "state": "populated", "exit": 0,
            "stdout_json": {"pooled": list(pairs), "count": len(pairs)}, "receipt_id": "rec-p"}


class _Ledger:
    def __init__(self):
        self.rows = []

    def append(self, project, event_type, content):
        self.rows.append({"project": project, "event_type": event_type, "content": content})
        return f"rec-{len(self.rows)}"


class World:
    """A throwaway SOIL store + a stub propose that stamps like the real one."""

    def __init__(self, tmp_path, monkeypatch):
        self.store = Store(str(tmp_path / "store"))
        self.puts = 0
        self.proposed: list[str] = []
        self.steps: list[str] = []
        self.ledger = _Ledger()
        self.pool = _pooled(_pair(1), _pair(2))

        real_put = self.store.put

        def counting_put(*a, **k):
            self.puts += 1
            return real_put(*a, **k)

        monkeypatch.setattr(self.store, "put", counting_put)

        def fake_propose(app_id, record_id, *, store=None, **kw):
            rec = store.get(decision_bridge.GOVERNANCE_COLLECTION, record_id)
            if rec is None:
                return {"error": "record_not_found"}
            if rec.get("nestor_pair_id"):
                return {"pair_id": rec["nestor_pair_id"], "record_id": record_id,
                        "status": "already_linked"}
            self.proposed.append(record_id)
            pair_id = f"pair-{len(self.proposed)}"
            updated = seal_handler._strip_meta(rec)
            updated["nestor_pair_id"] = pair_id
            store.update(decision_bridge.GOVERNANCE_COLLECTION, record_id, updated)
            return {"pair_id": pair_id, "record_id": record_id, "status": "draft"}

        monkeypatch.setattr(decision_bridge, "propose", fake_propose)

        def fake_step(app_id, step, args=None, **kw):
            self.steps.append(step)
            return self.pool

        monkeypatch.setattr(ox, "execute_step", fake_step)

        def boom(*a, **k):
            raise AssertionError("a seal path was called")

        monkeypatch.setattr(seal_drain, "drain", boom)
        monkeypatch.setattr(tool_oracle, "seal", boom)
        monkeypatch.setattr(seal_handler, "on_seal", boom)

    def run(self):
        return dep.deposit("hanuman", project="t", session="s", ledger=self.ledger, store=self.store)


@pytest.fixture
def world(tmp_path, monkeypatch):
    return World(tmp_path, monkeypatch)


def test_one_put_and_one_propose_per_subject(world):
    out = world.run()
    assert out["state"] == "populated" and out["count"] == 2
    assert world.puts == 2 and len(world.proposed) == 2
    assert [d["status"] for d in out["deposited"]] == ["draft", "draft"]
    assert {d["subject"] for d in out["deposited"]} == {_pair(1)["subject"], _pair(2)["subject"]}
    assert all(d["record_id"] and d["pair_id"] for d in out["deposited"])
    assert world.steps == ["pooled"]


def test_the_record_is_a_governance_decision_carrying_its_subject(world):
    out = world.run()
    rec = world.store.get(decision_bridge.GOVERNANCE_COLLECTION, out["deposited"][0]["record_id"])
    assert rec["subject"] == _pair(1)["subject"]
    assert rec["title"] == "claim 1"
    assert rec["ruling"].startswith("claim 1\nmore") and "c1" in rec["ruling"] and '"n": 1' in rec["ruling"]
    assert rec["origin"] == "willow:hanuman:onescript_deposit"


def test_a_second_run_deposits_no_duplicates(world):
    first = world.run()
    second = world.run()
    assert world.puts == 2 and len(world.proposed) == 2  # nothing new on the re-run
    assert [d["status"] for d in second["deposited"]] == ["already_linked", "already_linked"]
    assert [d["record_id"] for d in second["deposited"]] == [d["record_id"] for d in first["deposited"]]
    assert [d["pair_id"] for d in second["deposited"]] == [d["pair_id"] for d in first["deposited"]]
    assert len(world.store.all(decision_bridge.GOVERNANCE_COLLECTION)) == 2


def test_a_repeated_subject_in_one_pool_is_one_record(world):
    world.pool = _pooled(_pair(1), _pair(1))
    out = world.run()
    assert world.puts == 1 and len(world.proposed) == 1
    assert out["deposited"][1]["status"] == "already_linked"


def test_no_seal_path_is_ever_called(world):
    # seal_drain.drain / tool_oracle.seal / seal_handler.on_seal raise if reached,
    # and the only executor step ever run is the pure `pooled` read.
    world.run()
    world.run()
    assert set(world.steps) == {"pooled"}


@pytest.mark.parametrize("state", ["empty", "unreachable"])
def test_empty_and_unreachable_deposit_nothing(world, state):
    world.pool = {"ok": False, "state": state, "reason": f"why {state}", "exit": 0}
    out = world.run()
    assert out["state"] == state and out["count"] == 0 and out["deposited"] == []
    assert out["reason"] == f"why {state}"
    assert world.puts == 0 and world.proposed == [] and world.ledger.rows == []


def test_a_bad_subject_is_reported_not_dropped(world):
    bad = dict(_pair(1), subject="serve:" + "ab" * 16)
    world.pool = _pooled(bad, _pair(2))
    out = world.run()
    assert out["deposited"][0]["status"] == "error" and out["deposited"][0]["record_id"] is None
    assert out["deposited"][1]["status"] == "draft"
    assert world.puts == 1


def test_a_propose_failure_is_listed_with_its_error(world, monkeypatch):
    monkeypatch.setattr(decision_bridge, "propose",
                        lambda *a, **k: {"error": "title_collision", "detail": "d"})
    out = world.run()
    assert [d["status"] for d in out["deposited"]] == ["error", "error"]
    assert out["deposited"][0]["error"] == "title_collision"


def test_one_frank_receipt_for_the_act(world):
    out = world.run()
    [row] = world.ledger.rows
    assert row["event_type"] == "onescript_deposit" and out["receipt_id"] == "rec-1"
    assert row["content"]["count"] == 2 and row["content"]["actor"] == "hanuman"
    assert row["content"]["subjects"] == [_pair(1)["subject"], _pair(2)["subject"]]


# ── the gate ─────────────────────────────────────────────────────────────────

def test_tool_is_gated_on_its_own_name_orchestrator_only():
    assert server._gate_tool_catalogue()["onescript_deposit"] == "onescript_deposit"
    holders = {g for g, names in gate.PERMISSION_GROUPS.items() if "onescript_deposit" in names}
    assert holders == {"orchestrator"}, holders


def test_the_tool_body_never_runs_for_a_seat_without_the_name(tmp_path, monkeypatch):
    root = tmp_path / "mcp_apps"
    (root / "seat-x").mkdir(parents=True)
    (root / "seat-x" / "manifest.json").write_text(json.dumps({"permissions": ["steward_sweep"]}))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(root))
    called = []
    monkeypatch.setattr(dep, "deposit", lambda *a, **k: called.append(a) or {"ok": True})
    out = server.onescript_deposit(app_id="seat-x")
    assert called == [] and out.get("ok") is not True
