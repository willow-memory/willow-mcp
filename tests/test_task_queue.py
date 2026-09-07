"""Tests for the willow-mcp <-> kartikeya task-queue bridge.

kartikeya is a hard dependency (B-22 close-out), so these run unconditionally.
The Postgres backend is exercised against a fake connection that records SQL —
the same style as tests/test_server.py — with the schema mapping stubbed, so no
live DB is touched.
"""
import json
import os
import socket

import pytest

from kartikeya import QueueStats, TaskRow

from willow_mcp import heartbeat as hb
from willow_mcp import task_queue as tq


class _FakeCursor:
    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql, params=None):
        self._conn.executed.append((sql, params))
        self._conn._last = list(self._conn.next_rows)
        self.rowcount = self._conn.next_rowcount

    def fetchall(self):
        return list(self._conn._last)

    def close(self):
        pass


class _FakePg:
    def __init__(self):
        self.executed = []
        self.next_rows = []
        self.commits = 0
        self._last = []
        self.next_rowcount = 0

    def cursor(self):
        return _FakeCursor(self)

    def commit(self):
        self.commits += 1


def _mapping(result_type="jsonb", **overrides):
    fields = {f: {"column": f, "data_type": "text"} for f in tq._TASK_FIELDS}
    fields["result"]["data_type"] = result_type
    for k, v in overrides.items():
        fields[k] = v
    return {"confirmed": True, "fields": fields}


@pytest.fixture
def pg():
    return _FakePg()


@pytest.fixture
def queue(pg, monkeypatch):
    monkeypatch.setattr(tq.sp, "resolve", lambda *a, **k: _mapping())
    return tq.WillowMcpTaskQueue(pg, "app")


# ── construction guards ────────────────────────────────────────────────────

def test_construct_raises_on_unconfirmed_mapping(pg, monkeypatch):
    monkeypatch.setattr(tq.sp, "resolve", lambda *a, **k: {"confirmed": False, "fields": {}})
    with pytest.raises(RuntimeError, match="not confirmed"):
        tq.WillowMcpTaskQueue(pg, "app")


def test_construct_raises_on_resolve_error(pg, monkeypatch):
    monkeypatch.setattr(tq.sp, "resolve", lambda *a, **k: {"error": "table_not_found"})
    with pytest.raises(RuntimeError, match="table_not_found"):
        tq.WillowMcpTaskQueue(pg, "app")


def test_construct_refuses_schema_that_cannot_honor_lanes(pg, monkeypatch):
    monkeypatch.setattr(
        tq.sp,
        "resolve",
        lambda *a, **k: _mapping(lane={"column": None, "data_type": None}),
    )
    with pytest.raises(RuntimeError, match="worker-production fields: lane"):
        tq.WillowMcpTaskQueue(pg, "app")


# ── claim_pending ──────────────────────────────────────────────────────────

def test_claim_pending_atomic_sql_and_rows(queue, pg):
    pg.next_rows = [
        ("T1", "echo hi", "kart", "willow", ""),
        ("T2", "curl x\n# allow_net", "kart", "willow", '{"signed":true}'),
    ]
    rows = queue.claim_pending("kart", 5, lane="fast")
    sql, params = pg.executed[-1]
    assert "FOR UPDATE SKIP LOCKED" in sql
    assert "UPDATE tasks SET" in sql and "'running'" in sql
    assert "RETURNING" in sql
    assert '"lane" = %s' in sql
    assert '"claim_owner" = %s' in sql
    assert '"claimed_at" = now()' in sql
    assert params == (queue.claim_owner, "kart", "fast", 5)
    assert pg.commits == 1
    assert [r.task_id for r in rows] == ["T1", "T2"]
    assert all(isinstance(r, TaskRow) for r in rows)
    assert rows[0].submitted_by == "willow"
    assert rows[1].network_authorization == '{"signed":true}'


def test_fast_and_batch_workers_claim_only_their_lane(queue, pg):
    queue.claim_pending("kart", 2, lane="fast")
    fast_sql, fast_params = pg.executed[-1]
    queue.claim_pending("kart", 2, lane="batch")
    batch_sql, batch_params = pg.executed[-1]
    assert fast_sql == batch_sql
    assert '"lane" = %s' in fast_sql
    assert fast_params[2] == "fast"
    assert batch_params[2] == "batch"


def test_concurrent_claim_contract_prevents_double_execution(queue, pg):
    queue.claim_pending("kart", 1, lane="fast")
    sql, _ = pg.executed[-1]
    assert "FOR UPDATE SKIP LOCKED" in sql
    assert ') AND "status" = \'pending\'' in sql
    assert '"claim_owner" = %s' in sql


def test_claim_rejects_unknown_lane(queue):
    with pytest.raises(ValueError, match="fast\\|batch"):
        queue.claim_pending("kart", 1, lane="priority")


def test_legacy_postgres_mapping_does_not_invent_network_authority(
    pg, monkeypatch
):
    monkeypatch.setattr(
        tq.sp,
        "resolve",
        lambda *a, **k: _mapping(
            network_authorization={"column": None, "data_type": None}
        ),
    )
    queue = tq.WillowMcpTaskQueue(pg, "app")
    pg.next_rows = [("OLD", "curl x\n# allow_net", "kart", "legacy")]
    row = queue.claim_pending("kart", 1)[0]
    assert row.submitted_by == "legacy"
    assert row.network_authorization == ""


# ── mark_done ──────────────────────────────────────────────────────────────

def test_mark_done_wraps_jsonb_result_and_stamps_completed(queue, pg):
    queue.mark_done("T1", status="completed", result=json.dumps({"stdout": "hi"}))
    sql, params = pg.executed[-1]
    assert sql.startswith("UPDATE tasks SET")
    assert "now()" in sql  # completed_at stamped
    assert params[0] == "completed"
    # jsonb column -> psycopg2 Json wrapper, not a raw string
    assert type(params[2]).__name__ == "Json"
    assert params[-2:] == ("T1", queue.claim_owner)
    assert '"completed_at" = CASE' in sql
    assert '"claim_owner" = NULL' in sql
    assert pg.commits == 1


def test_mark_done_plain_text_result_when_column_not_jsonb(pg, monkeypatch):
    monkeypatch.setattr(tq.sp, "resolve", lambda *a, **k: _mapping(result_type="text"))
    q = tq.WillowMcpTaskQueue(pg, "app")
    q.mark_done("T1", status="failed", result="boom")
    sql, params = pg.executed[-1]
    assert params[2] == "boom"  # stored as-is, no Json wrapper
    assert "THEN 'pending' ELSE %s END" in sql
    assert '"retry_at" = CASE' in sql


def test_mark_done_rejects_unknown_terminal_state(queue):
    with pytest.raises(ValueError, match="completed\\|failed"):
        queue.mark_done("T1", status="running", result="")


def test_reap_stale_recovers_a_dead_owner(queue, pg, monkeypatch):
    # A candidate held by a worker with no live heartbeat and no live pid is
    # reclaimed. The recovery UPDATE targets it by id and re-applies the stale
    # guard so a claim renewed mid-probe cannot be stolen.
    monkeypatch.setattr(hb, "live_worker_keys", lambda *a, **k: set())
    monkeypatch.setattr(hb, "_pid_alive", lambda pid: False)
    pg.next_rows = [("T1", "deadhost:99999:abc")]
    pg.next_rowcount = 1
    assert queue.reap_stale() == 1
    select_sql, select_params = pg.executed[-2]
    assert '"status" = \'running\'' in select_sql
    assert '"claimed_at" <' in select_sql
    assert select_params == (queue.stale_after_seconds,)
    update_sql, update_params = pg.executed[-1]
    assert '"task_id" = ANY(%s)' in update_sql
    assert '"claimed_at" <' in update_sql  # race guard re-applied on the write
    assert "THEN 'failed' ELSE 'pending'" in update_sql
    assert update_params == (["T1"], queue.stale_after_seconds)


def test_reap_stale_spares_a_live_owner_by_heartbeat(queue, pg, monkeypatch):
    # THE anti-double-execution invariant (Loki §2.1): a slow worker still
    # publishing a fresh heartbeat keeps its claim, so its long task is never
    # re-dispatched. No recovery UPDATE is issued at all.
    monkeypatch.setattr(hb, "live_worker_keys", lambda *a, **k: {("livehost", 1234)})
    monkeypatch.setattr(hb, "_pid_alive", lambda pid: False)
    pg.next_rows = [("T1", "livehost:1234:abc")]
    pg.next_rowcount = 1
    assert queue.reap_stale() == 0
    assert not any("ANY(%s)" in sql for sql, _ in pg.executed)


def test_reap_stale_spares_a_live_local_pid(queue, pg, monkeypatch):
    # Even with no heartbeat file, a live process on this host holding the claim
    # is not reaped — a missing telemetry file is not proof of death.
    monkeypatch.setattr(hb, "live_worker_keys", lambda *a, **k: set())
    owner = f"{socket.gethostname()}:{os.getpid()}:abc"
    pg.next_rows = [("T1", owner)]
    pg.next_rowcount = 1
    assert queue.reap_stale() == 0
    assert not any("ANY(%s)" in sql for sql, _ in pg.executed)


def test_reap_stale_with_no_candidates_issues_no_update(queue, pg):
    pg.next_rows = []
    assert queue.reap_stale() == 0
    assert all("ANY(%s)" not in sql for sql, _ in pg.executed)


def test_parse_claim_owner_recovers_host_and_pid_or_none():
    assert tq._parse_claim_owner("host-a:4242:deadbeef") == ("host-a", 4242)
    assert tq._parse_claim_owner("") is None
    assert tq._parse_claim_owner("garbage") is None
    assert tq._parse_claim_owner("host:notapid:nonce") is None


# ── stats ──────────────────────────────────────────────────────────────────

def test_stats_groups_by_status(queue, pg):
    pg.next_rows = [("pending", 3), ("running", 1), ("completed", 10), ("failed", 2)]
    s = queue.stats()
    assert isinstance(s, QueueStats)
    assert (s.pending, s.running, s.completed, s.failed) == (3, 1, 10, 2)
    assert s.total == 16


# ── factory: SQLite fallback when no Postgres ──────────────────────────────

def test_factory_falls_back_to_sqlite_without_postgres(tmp_path, monkeypatch):
    monkeypatch.setattr(tq, "get_pg", lambda: None)
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path))
    q = tq.build_task_queue("app")
    from kartikeya import SqliteTaskQueue
    assert isinstance(q, SqliteTaskQueue)
    # and it actually works as a queue
    q.submit("F1", "echo hi")
    assert [r.task_id for r in q.claim_pending("kart", 5)] == ["F1"]


def test_managed_worker_refuses_lane_agnostic_sqlite_fallback(
    monkeypatch
):
    monkeypatch.setattr(tq, "get_pg", lambda: None)
    with pytest.raises(RuntimeError, match="Postgres is required"):
        tq.build_task_queue("app", require_postgres=True)


def test_factory_uses_postgres_when_available(monkeypatch):
    from kartikeya.queue import TaskQueue

    fake = _FakePg()
    monkeypatch.setattr(tq, "get_pg", lambda: fake)
    monkeypatch.setattr(tq.sp, "resolve", lambda *a, **k: _mapping())
    q = tq.build_task_queue("app")
    assert isinstance(q, tq.PgTaskQueue)
    assert isinstance(q, TaskQueue)


# ── connection recovery across a Postgres restart ──────────────────────────

def test_live_connection_is_reused_not_re_resolved(queue, pg, monkeypatch):
    from willow_mcp import db

    monkeypatch.setattr(
        db, "get_pg", lambda: pytest.fail("get_pg called for a live connection")
    )
    assert queue._pg is pg


def test_closed_connection_is_re_resolved(queue, pg, monkeypatch):
    """The 2026-09-05 outage: Postgres restarted, the cached handle stayed
    closed forever, and every claim raised for 43 hours."""
    from willow_mcp import db

    fresh = _FakePg()
    pg.closed = 1
    monkeypatch.setattr(db, "get_pg", lambda: fresh)

    assert queue._pg is fresh
    # and it is cached, not re-resolved on every access
    monkeypatch.setattr(
        db, "get_pg", lambda: pytest.fail("re-resolved an already-healthy connection")
    )
    assert queue._pg is fresh


def test_claim_recovers_on_the_first_tick_after_the_database_returns(
    queue, pg, monkeypatch
):
    """The property that makes the worker self-healing: no restart needed."""
    from willow_mcp import db

    fresh = _FakePg()
    fresh.next_rows = [("t1", "echo hi", "kart")]
    pg.closed = 1
    monkeypatch.setattr(db, "get_pg", lambda: fresh)

    rows = queue.claim_pending("kart", 1, lane="fast")

    assert [r.task_id for r in rows] == ["t1"]
    assert fresh.executed, "the claim ran on the replacement connection"
    assert not pg.executed, "nothing ran on the dead one"


def test_unavailable_database_raises_rather_than_returning_a_dead_handle(
    queue, pg, monkeypatch
):
    from willow_mcp import db

    pg.closed = 1
    monkeypatch.setattr(db, "get_pg", lambda: None)

    with pytest.raises(RuntimeError, match="postgres unavailable"):
        queue._pg
