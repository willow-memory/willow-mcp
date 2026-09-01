"""Postgres witness tests for egress row gate (dispatch 5D9A379D close-out).

Exercises ``_row_blocks_net_authorization`` and ``_consume_row_net_authorization``
against real ``tasks`` rows — no mocks on those helpers. Skips when Postgres is
unreachable (``get_pg()`` returns None).

The row-gate code is schema-adapted: it resolves column names through the
mapping layer, so it must hold on BOTH layouts willow-mcp serves — the repo's
own DDL (``docs/schema/tasks.postgres.sql``, primary key ``task_id``) and the
adopted fleet layout (``willow_20``, primary key ``id``). Every test here is
parametrized over both (#167): the fixture builds a layout-specific ``tasks``
table inside a dedicated schema and points ``search_path`` at it, so the
unqualified ``FROM tasks`` in the code under test resolves to the fixture's
table — never to (and never wiping) a live ``public.tasks``.
"""
from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from kartikeya import TaskRow
from psycopg2.extras import Json

from willow_mcp import db, egress_authorization as auth, task_queue as tq
from test_egress_authorization import _signed

# Layout name → primary-key column. "repo" is docs/schema/tasks.postgres.sql;
# "fleet" is the adopted willow_20 shape the schema-adaptation layer maps.
_LAYOUTS = {"repo-task-id": "task_id", "fleet-id": "id"}

_TEST_SCHEMA = "pytest_egress_row_gate"


def _tasks_ddl(pk: str) -> str:
    """The repo DDL's column set with the pk named per layout (no trigger —
    these tests set completed_at explicitly and mark_done writes it itself)."""
    return f"""
    CREATE TABLE tasks (
        {pk}          text PRIMARY KEY,
        task          text NOT NULL,
        submitted_by  text NOT NULL DEFAULT '',
        network_authorization text NOT NULL DEFAULT '',
        agent         text NOT NULL DEFAULT 'kart',
        lane          text NOT NULL DEFAULT 'fast',
        status        text NOT NULL DEFAULT 'pending',
        result        jsonb,
        steps         integer,
        created_at    timestamptz NOT NULL DEFAULT now(),
        completed_at  timestamptz,
        claim_owner   text,
        claimed_at    timestamptz,
        attempts      integer NOT NULL DEFAULT 0,
        max_attempts  integer NOT NULL DEFAULT 3,
        retry_at      timestamptz
    )
    """


@pytest.fixture
def keys(tmp_path):
    private = Ed25519PrivateKey.generate()
    private_path = tmp_path / "operator-private.pem"
    public_path = tmp_path / "operator-public.pem"
    private_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)
    public_path.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path


def _task_columns(pk: str):
    return {
        "task_id": pk,
        "status": "status",
        "completed_at": "completed_at",
        "result": "result",
    }


def _task_mapping(pk: str):
    fields = {
        name: {"column": name, "data_type": "text" if name != "result" else "jsonb"}
        for name in tq._TASK_FIELDS
    }
    fields["task_id"] = {"column": pk, "data_type": "text"}
    fields["result"]["data_type"] = "jsonb"
    return {"confirmed": True, "fields": fields}


@pytest.fixture(params=sorted(_LAYOUTS))
def pk_col(request):
    return _LAYOUTS[request.param]


@pytest.fixture
def pg_live(monkeypatch, pk_col):
    db._pg_conn = None
    pg = db.get_pg()
    if pg is None:
        pytest.skip("postgres unavailable via get_pg()")
    monkeypatch.setattr(auth, "_task_table_columns", lambda: _task_columns(pk_col))
    monkeypatch.setattr(tq.sp, "resolve", lambda *a, **k: _task_mapping(pk_col))
    cur = pg.cursor()
    cur.execute(f"DROP SCHEMA IF EXISTS {_TEST_SCHEMA} CASCADE")
    cur.execute(f"CREATE SCHEMA {_TEST_SCHEMA}")
    cur.execute(f"SET search_path TO {_TEST_SCHEMA}")
    cur.execute(_tasks_ddl(pk_col))
    pg.commit()
    cur.close()
    yield pg
    cur = pg.cursor()
    cur.execute('SET search_path TO "$user", public')
    cur.execute(f"DROP SCHEMA IF EXISTS {_TEST_SCHEMA} CASCADE")
    pg.commit()
    cur.close()
    db._pg_conn = None


@pytest.fixture
def queue(pg_live):
    return tq.WillowMcpTaskQueue(pg_live, "witness-worker")


def _insert_task(
    pg,
    pk: str,
    task_id: str,
    *,
    status: str = "pending",
    result=None,
    completed_at=None,
    attempts: int = 0,
    max_attempts: int = 3,
    submitted_by: str = "caller",
    task: str = "curl https://example.com\n# allow_net",
):
    cur = pg.cursor()
    cur.execute(
        f"""
        INSERT INTO tasks (
            "{pk}", task, submitted_by, agent, status, result,
            completed_at, attempts, max_attempts, claim_owner, claimed_at,
            network_authorization
        ) VALUES (%s, %s, %s, 'kart', %s, %s, %s, %s, %s, NULL, NULL, '')
        """,
        (
            task_id,
            task,
            submitted_by,
            status,
            Json(result) if result is not None else None,
            completed_at,
            attempts,
            max_attempts,
        ),
    )
    cur.close()
    pg.commit()


def _permit_row_gate_policy(monkeypatch, keys):
    """Execution policy without mocking row-gate helpers."""
    import os

    monkeypatch.setattr(auth.gate, "permitted", lambda *_: True)
    monkeypatch.setattr(auth.consent, "internet_permitted", lambda: True)
    monkeypatch.setattr(auth.lease, "active", lambda *_: True)
    monkeypatch.setattr(auth.lease, "strict_trust_root", lambda: True)
    monkeypatch.setattr(auth.lease, "self_writable_trust_paths", lambda *_: [])
    monkeypatch.setattr(
        auth.lease, "path_is_self_writable_or_replaceable", lambda *_: False
    )
    monkeypatch.setenv("WILLOW_MCP_EGRESS_PUBLIC_KEY", str(keys[1]))
    real_access = os.access
    monkeypatch.setattr(
        auth.os,
        "access",
        lambda path, mode: False if str(path) == str(keys[1]) else real_access(path, mode),
    )


def _fetch_result(pg, pk: str, task_id: str):
    cur = pg.cursor()
    cur.execute(f'SELECT result FROM tasks WHERE "{pk}" = %s', (task_id,))
    row = cur.fetchone()
    cur.close()
    return row[0] if row else None


@pytest.mark.parametrize("status", ["completed", "failed"])
def test_terminal_row_denies_via_row_blocks(pg_live, pk_col, keys, monkeypatch, status):
    _permit_row_gate_policy(monkeypatch, keys)
    _insert_task(pg_live, pk_col, "TERM0001", status=status, result={"done": True})
    assert auth._row_blocks_net_authorization("TERM0001") == "task row is terminal"

    authorizer = auth.ExecutorNetworkAuthorizer()
    row = TaskRow(
        task_id="TERM0001",
        task="curl https://example.com\n# allow_net",
        submitted_by="caller",
        network_authorization=_signed(keys, task_id="TERM0001"),
    )
    assert authorizer(row, row.network_authorization) is False
    assert authorizer.last_error == "task row is terminal"


def test_completed_at_denies_even_when_status_running(pg_live, pk_col, keys, monkeypatch):
    _permit_row_gate_policy(monkeypatch, keys)
    _insert_task(
        pg_live,
        pk_col,
        "CMPD0001",
        status="running",
        completed_at="2026-07-21T00:00:00+00:00",
    )
    assert auth._row_blocks_net_authorization("CMPD0001") == "task row already completed"


def test_first_allow_consumes_marker_second_denies(pg_live, pk_col, keys, monkeypatch):
    _permit_row_gate_policy(monkeypatch, keys)
    _insert_task(pg_live, pk_col, "CONS0001", status="running", result=None)

    row = TaskRow(
        task_id="CONS0001",
        task="curl https://example.com\n# allow_net",
        submitted_by="caller",
        network_authorization=_signed(keys, task_id="CONS0001"),
    )
    authorizer = auth.ExecutorNetworkAuthorizer()
    assert authorizer(row, row.network_authorization) is True
    stored = _fetch_result(pg_live, pk_col, "CONS0001")
    assert stored.get(auth._NET_AUTHORITY_CONSUMED_KEY) is True

    authorizer2 = auth.ExecutorNetworkAuthorizer()
    assert authorizer2(row, row.network_authorization) is False
    assert authorizer2.last_error == "network authorization already consumed for row"


def test_retry_path_clears_consumed_marker(pg_live, pk_col, queue, keys, monkeypatch):
    _permit_row_gate_policy(monkeypatch, keys)

    task_id = "RETRY001"
    _insert_task(pg_live, pk_col, task_id, status="running", result=None, attempts=0)
    cur = pg_live.cursor()
    cur.execute(
        f'UPDATE tasks SET claim_owner = %s, claimed_at = now() WHERE "{pk_col}" = %s',
        (queue.claim_owner, task_id),
    )
    cur.close()
    pg_live.commit()

    row = TaskRow(
        task_id=task_id,
        task="curl https://example.com\n# allow_net",
        submitted_by="caller",
        network_authorization=_signed(keys, task_id=task_id),
    )
    authorizer = auth.ExecutorNetworkAuthorizer()
    assert authorizer(row, row.network_authorization) is True
    assert _fetch_result(pg_live, pk_col, task_id).get(auth._NET_AUTHORITY_CONSUMED_KEY) is True

    queue.mark_done(task_id, status="failed", result=json.dumps({"error": "timeout"}))
    cur = pg_live.cursor()
    cur.execute(f'SELECT status, result FROM tasks WHERE "{pk_col}" = %s', (task_id,))
    status, result = cur.fetchone()
    cur.close()
    assert status == "pending"
    assert not (result or {}).get(auth._NET_AUTHORITY_CONSUMED_KEY)

    cur = pg_live.cursor()
    cur.execute(
        f"UPDATE tasks SET status = 'running', claim_owner = %s, claimed_at = now() "
        f'WHERE "{pk_col}" = %s',
        (queue.claim_owner, task_id),
    )
    cur.close()
    pg_live.commit()

    authorizer2 = auth.ExecutorNetworkAuthorizer()
    assert authorizer2(row, row.network_authorization) is True
    assert authorizer2.last_error == ""


def test_terminal_row_denied_before_shell_launch(pg_live, pk_col, keys, monkeypatch):
    from kartikeya import execute as kexec

    _permit_row_gate_policy(monkeypatch, keys)
    _insert_task(pg_live, pk_col, "RECL0001", status="completed", result={"ok": True})
    launched = []
    monkeypatch.setattr(
        kexec,
        "run_shell_task",
        lambda *_a, **_k: launched.append(True) or ("completed", {}),
    )
    row = TaskRow(
        task_id="RECL0001",
        task="curl https://example.com\n# allow_net",
        submitted_by="caller",
        network_authorization=_signed(keys, task_id="RECL0001"),
    )
    status, result = kexec.execute_task_row(
        row, network_authorizer=auth.ExecutorNetworkAuthorizer()
    )
    assert status == "failed"
    assert "verifier refused" in result["error"]
    assert "task row is terminal" in result["error"]
    assert launched == []
