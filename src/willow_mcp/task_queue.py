"""Task-queue backends bridging willow-mcp to the `kartikeya` worker.

`kartikeya` (the extracted Kart engine) owns the sandbox + worker loop and is
written against a small `TaskQueue` seam. This module supplies that seam over
willow-mcp's *adopted* `tasks` table (Postgres, via the schema-adaptation layer)
and, when no Postgres is configured, falls back to kartikeya's bundled
`SqliteTaskQueue` — so `willow-mcp worker` runs tasks with or without a DB.

`kartikeya` is a HARD dependency (B-22 close-out — see `pyproject.toml`), so a
base `pip install willow-mcp` ships a working drainer. The worker executes tasks
via kartikeya's `sandbox.run_shell` (resource caps on by default).
"""
from __future__ import annotations

import json
import os
import socket
from uuid import uuid4

from kartikeya.queue import QueueStats, TaskQueue, TaskRow
from psycopg2.extras import Json

from . import schema_profile as sp
from .db import get_pg

_TASK_FIELDS = [
    "task_id",
    "task",
    "submitted_by",
    "network_authorization",
    "agent",
    "lane",
    "status",
    "result",
    "steps",
    "created_at",
    "completed_at",
    "claim_owner",
    "claimed_at",
    "attempts",
    "max_attempts",
    "retry_at",
]


def _parse_claim_owner(owner: str) -> tuple[str, int] | None:
    """Recover ``(host, pid)`` from a ``host:pid:nonce`` claim owner.

    Claim owners are minted as ``f"{hostname}:{pid}:{uuid4().hex[:12]}"``; the
    nonce and pid are the last two ``:``-delimited fields, so hostnames that
    themselves contain ``:`` still parse. Anything that does not match (a legacy
    or externally-set owner) returns ``None`` and is treated as not-live, so it
    is still recoverable once past the stale window.
    """
    if not owner:
        return None
    parts = owner.rsplit(":", 2)
    if len(parts) != 3:
        return None
    host, pid_str, _nonce = parts
    try:
        return host, int(pid_str)
    except ValueError:
        return None


def _require_kartikeya():
    try:
        import kartikeya  # noqa: F401
        return kartikeya
    except ModuleNotFoundError as e:  # pragma: no cover - exercised where absent
        raise RuntimeError(
            "the task worker requires the 'kartikeya' package, which willow-mcp "
            "depends on — reinstall with `pip install willow-mcp`, or "
            "`pip install -e .` from a source checkout"
        ) from e


class PgTaskQueue(TaskQueue):
    """kartikeya.TaskQueue over willow-mcp's adopted Postgres `tasks` table.

    Resolves the confirmed column mapping once, then speaks the seam's methods in
    the host's real column names. Claim is atomic across concurrent workers via
    `FOR UPDATE SKIP LOCKED`. Drained by `willow-mcp worker` → kartikeya
    `run_worker` → `sandbox.run_shell` (cgroup caps on by default).
    """

    def __init__(
        self,
        pg,
        app_id: str,
        *,
        claim_owner: str = "",
        retry_delay_seconds: int = 5,
        stale_after_seconds: int | None = None,
    ):
        self._pg_conn = pg
        self.claim_owner = claim_owner or (
            f"{socket.gethostname()}:{os.getpid()}:{uuid4().hex[:12]}"
        )
        self.retry_delay_seconds = max(0, int(retry_delay_seconds))
        configured_stale = os.environ.get(
            "WILLOW_WORKER_STALE_SECONDS", "1800"
        )
        self.stale_after_seconds = (
            int(configured_stale)
            if stale_after_seconds is None
            else int(stale_after_seconds)
        )
        mapping = sp.resolve(pg, app_id, "tasks", _TASK_FIELDS)
        if "error" in mapping:
            raise RuntimeError(mapping["error"])
        if not mapping.get("confirmed"):
            raise RuntimeError(
                "tasks schema mapping is not confirmed — run schema_confirm_mapping "
                "for the 'tasks' table before starting a worker"
            )
        fields = mapping["fields"]
        self._col = {k: fields[k]["column"] for k in _TASK_FIELDS}
        self._result_jsonb = fields["result"].get("data_type") in ("jsonb", "json")
        for req in ("task_id", "task", "agent", "status"):
            if not self._col[req]:
                raise RuntimeError(f"tasks table has no mappable '{req}' column")
        production_fields = (
            "lane",
            "claim_owner",
            "claimed_at",
            "attempts",
            "max_attempts",
            "retry_at",
            "completed_at",
        )
        missing = [field for field in production_fields if not self._col[field]]
        if missing:
            raise RuntimeError(
                "tasks schema is missing worker-production fields: "
                + ", ".join(missing)
                + " — apply the reviewed worker migration and reconfirm the mapping"
            )

    @property
    def _pg(self):
        """The live connection, re-resolved if the cached one has died.

        A worker process outlives the database. When Postgres restarts, the
        connection handed in at construction is closed forever, and every
        query on it raises "connection already closed" — for the life of the
        process, because nothing here ever asked for another one. That is not
        theoretical: a fast-lane worker spent 43 hours failing every claim
        that way after the 2026-09-05 crash, while still publishing a healthy
        heartbeat.

        ``db.get_pg()`` already owns the recovery logic — it checks ``closed``,
        reconnects, revalidates with ``SELECT 1``, and can bring a downed
        server back via ``postgres_lifecycle``. So ask it again instead of
        holding a handle. The worker then heals on the first tick after the
        database returns, with no operator in the loop.

        ``getattr`` rather than ``.closed`` directly: this class is also
        constructed over test doubles and any DB-API connection, not only
        psycopg2's.
        """
        conn = self._pg_conn
        if conn is not None and not getattr(conn, "closed", 0):
            return conn
        from .db import get_pg
        fresh = get_pg()
        if fresh is None:
            raise RuntimeError(
                "postgres unavailable: the task queue's connection is closed "
                "and could not be re-established"
            )
        self._pg_conn = fresh
        return fresh

    def _q(self, field: str) -> str:
        return f'"{self._col[field]}"'

    def claim_pending(self, agent: str, limit: int, lane: str | None = None):
        lane = (lane or "fast").strip().lower()
        if lane not in ("fast", "batch"):
            raise ValueError(f"lane must be fast|batch, got {lane!r}")
        c = self._col
        order = c["created_at"] or c["task_id"]
        ret_fields = ["task_id", "task", "agent"]
        for optional in ("submitted_by", "network_authorization"):
            if c[optional]:
                ret_fields.append(optional)
        ret = [c[field] for field in ret_fields]
        ret_cols = ", ".join(f'"{x}"' for x in ret)
        sql = (
            f'UPDATE tasks SET {self._q("status")} = \'running\', '  # nosec B608 - self._q() resolves a fixed field name through self._col (schema_confirm_mapping-confirmed, never request input); values are bound params
            f'{self._q("claim_owner")} = %s, {self._q("claimed_at")} = now(), '
            f'{self._q("attempts")} = COALESCE({self._q("attempts")}, 0) + 1 '
            f'WHERE {self._q("task_id")} IN ('
            f'  SELECT {self._q("task_id")} FROM tasks '
            f'  WHERE {self._q("status")} = \'pending\' AND {self._q("agent")} = %s '
            f'  AND {self._q("lane")} = %s '
            f'  AND ({self._q("retry_at")} IS NULL OR {self._q("retry_at")} <= now()) '
            f'  AND COALESCE({self._q("attempts")}, 0) < '
            f'      COALESCE({self._q("max_attempts")}, 3) '
            f'  ORDER BY "{order}" LIMIT %s FOR UPDATE SKIP LOCKED'
            f') AND {self._q("status")} = \'pending\' RETURNING {ret_cols}'
        )
        cur = self._pg.cursor()
        cur.execute(sql, (self.claim_owner, agent, lane, limit))
        rows = cur.fetchall()
        cur.close()
        self._pg.commit()
        out = []
        for r in rows:
            values = dict(zip(ret_fields, r))
            out.append(
                TaskRow(
                    task_id=values["task_id"],
                    task=values["task"] or "",
                    agent=values["agent"] or agent,
                    submitted_by=values.get("submitted_by") or "",
                    network_authorization=values.get("network_authorization") or "",
                    status="running",
                )
            )
        return out

    def mark_running(self, task_id: str) -> None:
        cur = self._pg.cursor()
        cur.execute(
            f'UPDATE tasks SET {self._q("status")} = \'running\', '  # nosec B608 - self._q() resolves a fixed field name through self._col (schema_confirm_mapping-confirmed, never request input); values are bound params
            f'{self._q("claim_owner")} = %s, '
            f'{self._q("claimed_at")} = COALESCE({self._q("claimed_at")}, now()) '
            f'WHERE {self._q("task_id")} = %s AND {self._q("status")} <> \'running\'',
            (self.claim_owner, task_id),
        )
        cur.close()
        self._pg.commit()

    def mark_done(self, task_id: str, *, status: str, result: str) -> None:
        if status not in ("completed", "failed"):
            raise ValueError(
                f"terminal status must be completed|failed, got {status!r}"
            )
        if self._result_jsonb:
            try:
                stored = Json(json.loads(result))
            except (TypeError, json.JSONDecodeError):
                stored = Json(result)
        else:
            stored = result
        retrying = (
            f"%s = 'failed' AND COALESCE({self._q('attempts')}, 0) "
            f"< COALESCE({self._q('max_attempts')}, 3)"
        )
        sets = [
            f"{self._q('status')} = CASE WHEN {retrying} "
            f"THEN 'pending' ELSE %s END",
            f'{self._q("result")} = %s',
            f"{self._q('retry_at')} = CASE WHEN {retrying} "
            f"THEN now() + (%s * GREATEST(COALESCE({self._q('attempts')}, 1), 1)) "
            f"* INTERVAL '1 second' ELSE NULL END",
            f"{self._q('completed_at')} = CASE WHEN {retrying} "
            f"THEN NULL ELSE now() END",
            f'{self._q("claim_owner")} = NULL',
            f'{self._q("claimed_at")} = NULL',
        ]
        params = [
            status,
            status,
            stored,
            status,
            self.retry_delay_seconds,
            status,
        ]
        cur = self._pg.cursor()
        cur.execute(
            f'UPDATE tasks SET {", ".join(sets)} '  # nosec B608 - `sets` is built from self._q() field names (schema_confirm_mapping-confirmed, never request input); all values are bound params
            f'WHERE {self._q("task_id")} = %s '
            f'AND {self._q("status")} = \'running\' '
            f'AND {self._q("claim_owner")} = %s',
            (*params, task_id, self.claim_owner),
        )
        cur.close()
        self._pg.commit()

    def reap_stale(self) -> int:
        """Recover claims held by *dead* workers, exhausting rows at max_attempts.

        Liveness-aware (Loki DD0114E5 §2.1). A fixed age is not evidence a worker
        died: kartikeya runs each task in a thread pool while the main loop keeps
        ticking `on_heartbeat` every ~5s, so a worker draining a task for longer
        than `stale_after_seconds` is still alive and still publishing liveness.
        Reclaiming its row on age alone would re-dispatch live work and execute it
        twice. So a candidate (running past the stale window) is reclaimed only
        when its owning worker is gone — absent from the heartbeat's live set and,
        for a same-host owner, holding no live pid. The `claimed_at` guard is
        re-applied in the UPDATE so a claim renewed between the probe and the
        write is never stolen.
        """
        from . import heartbeat

        cur = self._pg.cursor()
        cur.execute(
            f'SELECT {self._q("task_id")}, {self._q("claim_owner")} FROM tasks '  # nosec B608 - self._q() resolves fixed field names through self._col (schema_confirm_mapping-confirmed, never request input); values are bound params
            f'WHERE {self._q("status")} = \'running\' '
            f'AND {self._q("claimed_at")} < '
            f"now() - (%s * INTERVAL '1 second')",
            (self.stale_after_seconds,),
        )
        candidates = cur.fetchall()
        cur.close()
        if not candidates:
            self._pg.commit()
            return 0

        alive_keys = heartbeat.live_worker_keys()
        this_host = socket.gethostname()
        dead_ids = []
        for task_id, owner in candidates:
            parsed = _parse_claim_owner(owner or "")
            if parsed is not None:
                host, pid = parsed
                if (host, pid) in alive_keys:
                    continue  # a fresh heartbeat proves this owner is alive
                if host == this_host and heartbeat._pid_alive(pid):
                    continue  # live local pid, even if its heartbeat file is gone
            dead_ids.append(task_id)

        if not dead_ids:
            self._pg.commit()
            return 0

        cur = self._pg.cursor()
        cur.execute(
            f'UPDATE tasks SET {self._q("status")} = CASE '  # nosec B608 - self._q() resolves fixed field names through self._col (schema_confirm_mapping-confirmed, never request input); values are bound params
            f'WHEN COALESCE({self._q("attempts")}, 0) >= '
            f'COALESCE({self._q("max_attempts")}, 3) '
            f"THEN 'failed' ELSE 'pending' END, "
            f'{self._q("completed_at")} = CASE '
            f'WHEN COALESCE({self._q("attempts")}, 0) >= '
            f'COALESCE({self._q("max_attempts")}, 3) '
            f"THEN now() ELSE NULL END, "
            f'{self._q("retry_at")} = NULL, '
            f'{self._q("claim_owner")} = NULL, '
            f'{self._q("claimed_at")} = NULL '
            f'WHERE {self._q("task_id")} = ANY(%s) '
            f'AND {self._q("status")} = \'running\' '
            f'AND {self._q("claimed_at")} < '
            f"now() - (%s * INTERVAL '1 second')",
            (dead_ids, self.stale_after_seconds),
        )
        changed = max(int(cur.rowcount), 0)
        cur.close()
        self._pg.commit()
        return changed

    def stats(self) -> QueueStats:
        cur = self._pg.cursor()
        cur.execute(f'SELECT {self._q("status")}, COUNT(*) FROM tasks GROUP BY {self._q("status")}')  # nosec B608 - self._q() resolves fixed field names through self._col (schema_confirm_mapping-confirmed, never request input)
        rows = cur.fetchall()
        cur.close()
        by = {r[0]: r[1] for r in rows}
        return QueueStats(
            pending=by.get("pending", 0),
            running=by.get("running", 0),
            completed=by.get("completed", 0),
            failed=by.get("failed", 0),
        )


# Backward-compatible alias used across docs and older tests.
WillowMcpTaskQueue = PgTaskQueue


def build_task_queue(app_id: str, *, require_postgres: bool = False) -> TaskQueue:
    """Pick a backend: Postgres (adopted `tasks` table) if reachable, else
    kartikeya's bundled SqliteTaskQueue under WILLOW_STORE_ROOT."""
    pg = get_pg()
    if pg is not None:
        return PgTaskQueue(pg, app_id)
    if require_postgres:
        raise RuntimeError(
            "Postgres is required for managed lane workers; refusing the "
            "lane-agnostic SQLite fallback"
        )
    k = _require_kartikeya()
    from .paths import store_root

    db_path = store_root().expanduser() / "kart.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return k.SqliteTaskQueue(str(db_path))
