"""Tests for GAP #5 (routing-lane logging) + GAP #6 (dispatch outcome-quality).

`agent_route` writes a routing_decisions row recording the final target agent
but, before this change, nothing about which of the 8 routing-ladder lanes
produced that target. `agent_dispatch_result` closed the loop with only a
coarse done/failed status, no outcome-quality signal. Both gaps are closed by
OPTIONAL parameters carried inside the existing `decision` jsonb column (no
migration — see the design note atop the agent-dispatch-tools section in
server.py), so every existing caller that omits them keeps today's exact
behavior.

Uses a small in-memory fake Postgres connection (same idiom as
test_dispatch_pg_mirror.py's `_FakePg`) that actually implements the
INSERT / `decision || %s::jsonb` UPDATE / SELECT this table's three call
sites issue, rather than mocking schema_profile introspection (routing_decisions
has fixed columns, no schema-adapted mapping — see docs/schema/routing_decisions.postgres.sql).
"""
from __future__ import annotations

import json

import pytest

from willow_mcp import server
from willow_mcp.db import Store
from willow_mcp.training_corpus import SOURCE_DISPATCH_ROUTE, iter_training_examples


class _FakeRoutingCursor:
    def __init__(self, conn):
        self._conn = conn
        self._result: list = []

    def execute(self, sql, params=None):
        params = params or ()
        flat = " ".join(sql.split())
        if flat.startswith("INSERT INTO routing_decisions"):
            (rid, prompt_hash, session_id, rule_id, confidence, decision_json) = params
            self._conn.rows[rid] = {
                "id": rid,
                "prompt_hash": prompt_hash,
                "session_id": session_id,
                "rule_id": rule_id,
                "confidence": confidence,
                "decision": json.loads(decision_json),
                "kind": "agent_route",
            }
            self._conn.order.append(rid)
            self._result = []
        elif flat.startswith("UPDATE routing_decisions"):
            payload_json, rid = params
            row = self._conn.rows.get(rid)
            if row is None:
                self._result = []
                self._rowcount = 0
            else:
                row["decision"].update(json.loads(payload_json))
                self._rowcount = 1
            self._result = []
        elif flat.startswith("SELECT decision FROM routing_decisions WHERE id"):
            (rid,) = params
            row = self._conn.rows.get(rid)
            self._result = [(row["decision"],)] if row else []
        elif flat.startswith("SELECT id, decision FROM routing_decisions"):
            # list_routing_decisions_by_lane: emulate the WHERE lane filter and
            # ORDER BY created_at DESC (== reverse insertion order here).
            lane = None
            limit = params[-1]
            if "decision->>'lane' = %s" in flat:
                lane = params[0]
            matched = []
            for rid in reversed(self._conn.order):
                row = self._conn.rows[rid]
                d = row["decision"]
                if d.get("lane") is None:
                    continue
                if lane is not None and d.get("lane") != lane:
                    continue
                matched.append((rid, d))
            self._result = matched[:limit]
        else:
            raise AssertionError(f"unexpected SQL in fake cursor: {sql!r}")

    def fetchall(self):
        return list(self._result)

    def fetchone(self):
        return self._result[0] if self._result else None

    @property
    def rowcount(self):
        return getattr(self, "_rowcount", len(self._result))

    def close(self):
        pass


class _FakeRoutingPg:
    def __init__(self):
        self.rows: dict = {}
        self.order: list = []

    def cursor(self):
        return _FakeRoutingCursor(self)


@pytest.fixture(autouse=True)
def _fresh_rate_buckets():
    """_buckets is a module-global keyed by app_id string, shared with every
    other test module that reuses "testapp" — reset it so accumulated rate
    limiting from another file's run never makes an agent_route/
    agent_dispatch_result call here spuriously denied."""
    server._buckets.clear()
    yield
    server._buckets.clear()


@pytest.fixture
def app_id(tmp_path, monkeypatch):
    apps_root = tmp_path / "mcp_apps"
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / "testapp"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(json.dumps({"permissions": ["full_access"]}))
    return "testapp"


@pytest.fixture
def fake_pg(monkeypatch):
    fake = _FakeRoutingPg()
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    return fake


@pytest.fixture(autouse=True)
def _isolated_store(tmp_path, monkeypatch):
    """agent_dispatch_result writes to the module-level `_store`; point it at
    a throwaway Store for the duration of each test so training_corpus rows
    from one test never bleed into another."""
    monkeypatch.setattr(server, "_store", Store(store_root=str(tmp_path / "soil")))
    return server._store


# ── GAP #5: routing-lane capture ─────────────────────────────────────────────

def test_agent_route_without_lane_is_backward_compatible(app_id, fake_pg):
    out = server.agent_route(app_id=app_id, task="do the thing", target_agent="hanuman")
    assert out["status"] == "routed"
    assert "lane" not in out
    row = fake_pg.rows[out["routing_id"]]
    assert "lane" not in row["decision"]


def test_agent_route_with_lane_is_persisted_and_read_back(app_id, fake_pg):
    out = server.agent_route(
        app_id=app_id, task="check a sealed fact", target_agent="willow", lane="sealed_fact",
    )
    assert out["lane"] == "sealed_fact"
    row = fake_pg.rows[out["routing_id"]]
    assert row["decision"]["lane"] == "sealed_fact"


def test_agent_route_rejects_unknown_lane(app_id, fake_pg):
    out = server.agent_route(
        app_id=app_id, task="x", target_agent="willow", lane="astrology",
    )
    assert "error" in out
    assert "unknown_lane" in out["error"]
    assert not fake_pg.rows  # nothing was inserted for a rejected lane


def test_list_routing_decisions_by_lane_filters(app_id, fake_pg):
    r1 = server.agent_route(app_id=app_id, task="t1", target_agent="a", lane="corpus")
    r2 = server.agent_route(app_id=app_id, task="t2", target_agent="b", lane="tool_oracle")
    server.agent_route(app_id=app_id, task="t3", target_agent="c")  # untagged

    all_tagged = server.list_routing_decisions_by_lane(fake_pg)
    assert all_tagged["count"] == 2
    ids = {d["routing_id"] for d in all_tagged["decisions"]}
    assert ids == {r1["routing_id"], r2["routing_id"]}

    only_corpus = server.list_routing_decisions_by_lane(fake_pg, lane="corpus")
    assert only_corpus["count"] == 1
    assert only_corpus["decisions"][0]["routing_id"] == r1["routing_id"]


def test_list_routing_decisions_by_lane_rejects_unknown_lane(fake_pg):
    out = server.list_routing_decisions_by_lane(fake_pg, lane="not_a_lane")
    assert "error" in out


def test_list_routing_decisions_by_lane_no_pg():
    out = server.list_routing_decisions_by_lane(None)
    assert out["error"] == "postgres_unavailable"


# ── GAP #6: dispatch outcome-quality ─────────────────────────────────────────

def test_agent_dispatch_result_without_quality_is_backward_compatible(app_id, fake_pg):
    routed = server.agent_route(app_id=app_id, task="t", target_agent="a")
    out = server.agent_dispatch_result(
        app_id=app_id, routing_id=routed["routing_id"], result="ok", status="done",
    )
    assert out == {"routing_id": routed["routing_id"], "status": "done"}
    decision = fake_pg.rows[routed["routing_id"]]["decision"]
    assert decision["result"] == "ok"
    assert decision["dispatch_status"] == "done"
    assert "quality_score" not in decision
    assert "quality_note" not in decision


def test_agent_dispatch_result_with_quality_persists_and_reads_back(app_id, fake_pg):
    routed = server.agent_route(app_id=app_id, task="t", target_agent="a", lane="local_draft")
    out = server.agent_dispatch_result(
        app_id=app_id, routing_id=routed["routing_id"], result="ok", status="done",
        quality_score=0.85, quality_note="clean output, minor formatting nit",
    )
    assert out["quality_score"] == 0.85
    decision = fake_pg.rows[routed["routing_id"]]["decision"]
    assert decision["quality_score"] == 0.85
    assert decision["quality_note"] == "clean output, minor formatting nit"


def test_agent_dispatch_result_rejects_out_of_bounds_quality_score(app_id, fake_pg):
    routed = server.agent_route(app_id=app_id, task="t", target_agent="a")
    out = server.agent_dispatch_result(
        app_id=app_id, routing_id=routed["routing_id"], result="ok", quality_score=1.5,
    )
    assert "error" in out
    assert "invalid_quality_score" in out["error"]
    # rejected before the row was touched
    assert "result" not in fake_pg.rows[routed["routing_id"]]["decision"]


def test_agent_dispatch_result_not_found(app_id, fake_pg):
    out = server.agent_dispatch_result(app_id=app_id, routing_id="NOPE1234", result="x")
    assert out == {"error": "not_found"}


# ── training_corpus emission (best-effort) ──────────────────────────────────

def test_dispatch_result_emits_training_example_with_quality(app_id, fake_pg, _isolated_store):
    routed = server.agent_route(
        app_id=app_id, task="do the thing", target_agent="hanuman", lane="mcp_read",
    )
    server.agent_dispatch_result(
        app_id=app_id, routing_id=routed["routing_id"], result="done well",
        status="done", quality_score=0.9,
    )
    rows = iter_training_examples(_isolated_store, source=SOURCE_DISPATCH_ROUTE)
    assert len(rows) == 1
    row = rows[0]
    assert row["input"]["lane"] == "mcp_read"
    assert row["small_model_output"]["target"] == "hanuman"
    assert row["small_model_output"]["lane"] == "mcp_read"
    assert row["large_label"]["status"] == "done"
    assert row["large_label"]["quality_score"] == 0.9
    assert row["label_kind"] == "verification"


def test_dispatch_result_emits_training_example_without_quality(app_id, fake_pg, _isolated_store):
    routed = server.agent_route(app_id=app_id, task="t", target_agent="a")
    server.agent_dispatch_result(
        app_id=app_id, routing_id=routed["routing_id"], result="ok", status="failed",
    )
    rows = iter_training_examples(_isolated_store, source=SOURCE_DISPATCH_ROUTE)
    assert len(rows) == 1
    assert rows[0]["large_label"]["status"] == "failed"
    assert rows[0]["label_kind"] == "none"
    assert "quality_score" not in rows[0]["large_label"]


def test_dispatch_result_training_write_failure_is_swallowed(app_id, fake_pg, monkeypatch):
    """A broken training_corpus store must never turn a successful
    dispatch-result call into a failed one (best-effort, per GAP #5/#6 spec)."""
    routed = server.agent_route(app_id=app_id, task="t", target_agent="a")

    monkeypatch.setattr(server, "_store", _Boomer())
    out = server.agent_dispatch_result(
        app_id=app_id, routing_id=routed["routing_id"], result="ok", quality_score=0.5,
    )
    assert out["routing_id"] == routed["routing_id"]
    assert out["status"] == "done"
    assert out["quality_score"] == 0.5
    # the routing_decisions row itself was still updated despite the training
    # corpus write blowing up afterward
    assert fake_pg.rows[routed["routing_id"]]["decision"]["result"] == "ok"


class _Boomer:
    """A store double whose .put always raises, to exercise the best-effort
    try/except around the training_corpus emission."""

    def put(self, *a, **kw):
        raise RuntimeError("simulated store fault")
