"""get_pg must not throw away why it failed.

`get_pg` returns Optional, so every caller sees one bit: None. It also used to
swallow the exception with a bare `except Exception`, while the shared
"postgres_unavailable" responses ASSERTED a cause — "unix socket connection
failed" — that nothing had checked.

On 2026-09-07 the real fault was a caller spawning the server without
`WILLOW_PG_DB`, so it fell back to dbname "willow" and Postgres answered
`database "willow" does not exist`. The socket was healthy. The reported cause
was false, and it sent the reader an hour in the wrong direction. These tests
pin that a failure carries its own diagnosis.
"""
import psycopg2
import pytest

from willow_mcp import db


@pytest.fixture(autouse=True)
def _reset():
    db._pg_conn = None
    db._pg_last_error = None
    yield
    db._pg_conn = None
    db._pg_last_error = None


def _fail_with(monkeypatch, exc, *, recover=False):
    def boom(*a, **k):
        raise exc
    monkeypatch.setattr(db.psycopg2, "connect", boom)
    monkeypatch.setattr(db.postgres_lifecycle, "ensure_enabled", lambda: recover)
    monkeypatch.setattr(db.postgres_lifecycle, "try_recover", lambda: recover)


def test_the_contract_is_unchanged_none_on_failure(monkeypatch):
    """Callers rely on falsy-means-degraded at 100+ sites. Raising here would
    turn a degraded fleet into a dead one."""
    _fail_with(monkeypatch, psycopg2.OperationalError("boom"))
    assert db.get_pg() is None


def test_the_real_reason_is_kept(monkeypatch):
    _fail_with(monkeypatch, psycopg2.OperationalError(
        'connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" '
        'failed: FATAL:  database "willow" does not exist'))
    db.get_pg()
    reason = db.last_pg_error()
    assert 'database "willow" does not exist' in reason
    assert "OperationalError" in reason


def test_the_reason_names_the_resolved_dbname_and_user(monkeypatch):
    """An environment fault should be legible without guessing which variable
    was missing — that is the whole failure mode this fixes."""
    monkeypatch.setenv("WILLOW_PG_DB", "willow_20")
    monkeypatch.setenv("WILLOW_PG_USER", "sean-campbell")
    _fail_with(monkeypatch, psycopg2.OperationalError("nope"))
    db.get_pg()
    assert "'willow_20'" in db.last_pg_error()
    assert "'sean-campbell'" in db.last_pg_error()


def test_a_multiline_error_is_flattened(monkeypatch):
    _fail_with(monkeypatch, psycopg2.OperationalError("line one\n\nline  two\n"))
    db.get_pg()
    assert "\n" not in db.last_pg_error()
    assert "line one line two" in db.last_pg_error()


def test_a_recovery_that_also_fails_keeps_the_first_diagnosis(monkeypatch):
    """The first failure is why we could not connect; the second is about the
    restart. Losing the first would lose the diagnosis."""
    _fail_with(monkeypatch, psycopg2.OperationalError(
        'FATAL:  database "willow" does not exist'), recover=True)
    db.get_pg()
    reason = db.last_pg_error()
    assert 'database "willow" does not exist' in reason
    assert "after a recovery restart it still failed" in reason


def test_success_clears_a_stale_reason(monkeypatch):
    _fail_with(monkeypatch, psycopg2.OperationalError("transient"))
    db.get_pg()
    assert db.last_pg_error()

    class _Cur:
        def execute(self, *a):
            return None

    class _Conn:
        closed = False
        autocommit = False

        def cursor(self):
            return _Cur()

    monkeypatch.setattr(db.psycopg2, "connect", lambda *a, **k: _Conn())
    assert db.get_pg() is not None
    assert db.last_pg_error() is None


def test_no_attempt_yet_is_not_reported_as_a_failure():
    assert db.last_pg_error() is None


# ── the reporters must carry it, not assert a cause of their own ────────────

def test_every_reporter_carries_the_recorded_reason(monkeypatch):
    from willow_mcp import grove_tools, resources, server
    _fail_with(monkeypatch, psycopg2.OperationalError(
        'FATAL:  database "willow" does not exist'))
    db.get_pg()
    for fn in (server._postgres_unavailable, resources._postgres_unavailable,
               grove_tools._pg_unavailable):
        out = fn()
        assert out["error"] == "postgres_unavailable", fn
        assert 'database "willow" does not exist' in out["reason"], fn
        # the cause it never checked must be gone from the asserted text
        assert "unix socket connection failed" not in out["detail"], fn


def test_reporters_say_so_when_nothing_was_recorded():
    from willow_mcp import grove_tools, resources, server
    for fn in (server._postgres_unavailable, resources._postgres_unavailable,
               grove_tools._pg_unavailable):
        assert "no reason recorded" in fn()["reason"], fn
