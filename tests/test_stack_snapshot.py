import json

from willow_mcp import stack_snapshot as ss
from willow_mcp.db import Store


def _manifest(tmp_path, monkeypatch, app="willow", scope=None):
    root = tmp_path / "mcp_apps"
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(root))
    path = root / app / "manifest.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "permissions": ["orchestrator", "full_access"],
                "store_scope": scope or ["projects_willow_*", "willow_*"],
                "collection_aliases": {"stack": "projects_willow_stack"},
            }
        )
    )


def test_write_and_read_stack_snapshot(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    monkeypatch.setenv("WILLOW_PG_DB", "nonexistent_db_for_test")
    out = ss.write_stack_snapshot("hanuman", "sess-1", project="willow-mcp")
    assert out.get("ok") is True
    snap = ss.read_stack_snapshot("hanuman")
    assert snap.get("session_id") == "sess-1"
    assert snap.get("agent") == "hanuman"
    assert "written_at" in snap


def test_session_enter_orientation_includes_snapshot(tmp_path, monkeypatch):
    from willow_mcp import server

    _manifest(tmp_path, monkeypatch)
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    store = Store(tmp_path / "store")
    store.put(
        ss.stack_collection("willow"),
        {
            "session_id": "prior",
            "open_tasks": [{"id": "t1", "title": "finish gate", "status": "pending"}],
            "written_at": "2026-08-06T00:00:00Z",
        },
        record_id="current",
    )
    monkeypatch.setattr(server, "_store", store)
    assert ss.read_stack_snapshot("willow").get("session_id") == "prior"
    project = tmp_path / "repo"
    project.mkdir()
    entered = server.session_enter(
        app_id="willow",
        session_id="fresh",
        project="repo",
        workspace=str(project),
    )
    snap = entered["orientation"]["stack_snapshot"]
    assert snap.get("session_id") == "prior"
    assert snap["open_tasks"][0]["title"] == "finish gate"


class _FakeCursor:
    def __init__(self, sink):
        self.sink = sink

    def execute(self, sql, params=None):
        self.sink.append((sql, params))

    def fetchall(self):
        return [("T1", "mine", "pending")]

    def close(self):
        pass


class _FakeConn:
    def __init__(self, sink):
        self.sink = sink

    def cursor(self):
        return _FakeCursor(self.sink)


def _stub_pg(monkeypatch, columns):
    """Point _fetch_pending_tasks at a fake queue with `columns` as the mapping."""
    from willow_mcp import schema_profile

    sink: list = []
    monkeypatch.setattr(ss, "get_pg", lambda: _FakeConn(sink))
    monkeypatch.setattr(
        schema_profile, "resolve",
        lambda conn, app_id, table, fields: {
            "fields": {name: {"column": columns.get(name)} for name in fields}})
    return sink


def test_pending_tasks_are_scoped_to_the_app_that_submitted_them(tmp_path, monkeypatch):
    """The snapshot is per-app, so its task query must be too.

    An unfiltered `WHERE status = 'pending'` would put every agent's queued work
    into every agent's SessionStart INDEX. `task_submit` writes `app_id` into
    `submitted_by`, and that is the column that makes the query's scope match the
    collection's.
    """
    sink = _stub_pg(monkeypatch, {
        "task_id": "task_id", "task": "task", "status": "status",
        "submitted_by": "submitted_by", "created_at": "created_at"})

    rows = ss._fetch_pending_tasks("hanuman")

    assert rows == [{"id": "T1", "title": "mine", "status": "pending"}]
    sql, params = sink[0]
    assert '"submitted_by" = %s' in sql
    assert params[0] == "hanuman"


def test_task_query_uses_resolved_columns_not_hardcoded_names(tmp_path, monkeypatch):
    """`tasks` column names are discovered per install — see schema_profile.

    Hardcoding them raises UndefinedColumn on an install that named them
    otherwise, and the caller's `except` renders that as "no open tasks" rather
    than as "could not tell".
    """
    sink = _stub_pg(monkeypatch, {
        "task_id": "id", "task": "body", "status": "state",
        "submitted_by": "origin_app", "created_at": "queued_at"})

    ss._fetch_pending_tasks("hanuman")

    sql, _ = sink[0]
    for column in ("id", "body", "state", "origin_app", "queued_at"):
        assert f'"{column}"' in sql, f"resolved column {column!r} missing from {sql!r}"


def test_unmappable_submitted_by_yields_nothing_rather_than_everything(monkeypatch):
    """Fail closed: no scope column means no scoped answer, so answer nothing.

    Falling back to the unfiltered query would show one agent another agent's
    stack — worse than showing none.
    """
    sink = _stub_pg(monkeypatch, {
        "task_id": "task_id", "task": "task", "status": "status",
        "submitted_by": None, "created_at": "created_at"})

    assert ss._fetch_pending_tasks("hanuman") == []
    assert sink == [], "no query should have been issued at all"


def test_a_non_text_task_column_does_not_raise_in_a_hook(monkeypatch):
    """Columns are discovered, so `task` is not guaranteed to be text."""
    assert ss.parse_task_rows({"pending": [{"task_id": "T1", "task": 42,
                                            "status": "pending"}]}) == [
        {"id": "T1", "title": "42", "status": "pending"}]


def test_session_stop_hook_writes_snapshot(tmp_path, monkeypatch):
    import io

    from willow_mcp import session_stop_hook as stop

    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    monkeypatch.setenv("WILLOW_APP_ID", "hanuman")
    monkeypatch.setattr(stop.sys, "stdin", io.StringIO(json.dumps({"session_id": "end-1"})))
    stop.main()
    snap = ss.read_stack_snapshot("hanuman")
    assert snap.get("session_id") == "end-1"
