"""MCP-wrapper-level tests for the 8 tools identified in W-02 as having zero
tool-level coverage. Each tool's underlying logic has its own unit tests
(test_lineage.py, test_friction.py, test_kb_verify.py); these tests exercise
the MCP wrapper layer — @_guarded gate, permission denials, collection checks,
and argument plumbing from tool signature to library call.

Prioritized highest-risk first: lineage_*, friction_scan, knowledge_check.
"""

import json

import pytest

from willow_mcp import server


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _fresh_rate_buckets():
    server._buckets.clear()
    yield
    server._buckets.clear()


@pytest.fixture
def app_id(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    apps_root = tmp_path / "mcp_apps"
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / "testapp"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(
        json.dumps({"permissions": ["full_access"]})
    )
    return "testapp"


@pytest.fixture
def readonly_app_id(tmp_path, monkeypatch):
    """App with only read permissions — writes should be denied."""
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    apps_root = tmp_path / "mcp_apps"
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / "reader"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(
        json.dumps({"permissions": ["lineage_read", "friction_read", "knowledge_read"]})
    )
    return "reader"


@pytest.fixture
def knowledge_app_id(tmp_path, monkeypatch):
    """App with knowledge_read (covers knowledge_verify/knowledge_check)
    plus knowledge_write and agent_dispatch."""
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    apps_root = tmp_path / "mcp_apps"
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / "kbapp"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(
        json.dumps({"permissions": ["knowledge_read", "knowledge_write",
                                     "agent_dispatch"]})
    )
    return "kbapp"


# ── Fake Postgres (reusable for knowledge/dispatch tools) ────────────────────

class _FakePgCursor:
    def __init__(self, conn):
        self._conn = conn
        self._result: list = []

    def execute(self, sql, params=None):
        self._conn.executed.append((sql, params))
        if self._conn.raise_on_execute:
            raise RuntimeError("fake pg error")
        self._result = list(self._conn.canned_rows)

    def fetchall(self):
        return list(self._result)

    def fetchone(self):
        return self._result[0] if self._result else None

    @property
    def rowcount(self):
        return len(self._result)

    def close(self):
        pass


class _FakePg:
    def __init__(self, canned_rows=None, raise_on_execute=False):
        self.canned_rows = canned_rows or []
        self.raise_on_execute = raise_on_execute
        self.executed: list = []

    def cursor(self):
        return _FakePgCursor(self)

    def get_dsn_parameters(self):
        return {"host": "test-host", "dbname": "test-db"}


# ── helper: seed a lineage atom through the MCP tool ─────────────────────────

def _seed_atom(app_id, atom_id="alpha", title="Alpha", rationale="why",
               evidence=None):
    return server.lineage_record(
        app_id=app_id, id=atom_id, title=title, rationale=rationale,
        evidence=evidence or ["commit abc"],
    )


# ══════════════════════════════════════════════════════════════════════════════
# lineage_link
# ══════════════════════════════════════════════════════════════════════════════

class TestLineageLink:
    def test_happy_path_adds_edge(self, app_id):
        _seed_atom(app_id, "a", "A", "r", ["c"])
        _seed_atom(app_id, "b", "B", "r", ["c"])
        result = server.lineage_link(
            app_id=app_id, from_id="b", to_id="a", relation="supersedes",
        )
        assert "error" not in result
        why = server.lineage_why(app_id=app_id, query="a")
        assert "b" in why.get("superseded_by", [])

    def test_gate_denies_unpermitted_app(self):
        result = server.lineage_link(
            app_id="nosuchapp", from_id="x", to_id="y", relation="supersedes",
        )
        assert "error" in result
        assert "denied" in result["error"]

    def test_gate_denies_write_for_read_only_app(self, readonly_app_id):
        result = server.lineage_link(
            app_id=readonly_app_id, from_id="x", to_id="y",
            relation="supersedes",
        )
        assert "error" in result
        assert "denied" in result["error"]

    def test_validation_propagates(self, app_id):
        result = server.lineage_link(
            app_id=app_id, from_id="", to_id="a", relation="supersedes",
        )
        assert result.get("error") == "from_to_relation_required"


# ══════════════════════════════════════════════════════════════════════════════
# lineage_why
# ══════════════════════════════════════════════════════════════════════════════

class TestLineageWhy:
    def test_happy_path_returns_answer(self, app_id):
        _seed_atom(app_id, "alpha", "Alpha atom", "it needed to exist", ["commit"])
        result = server.lineage_why(app_id=app_id, query="alpha")
        assert result["matched"] == "alpha"
        assert "answer" in result

    def test_miss_is_honest(self, app_id):
        result = server.lineage_why(app_id=app_id, query="nonexistent")
        assert result["matched"] is None

    def test_gate_denies_unpermitted_app(self):
        result = server.lineage_why(app_id="nosuchapp", query="anything")
        assert "error" in result
        assert "denied" in result["error"]

    def test_empty_query_returns_error(self, app_id):
        result = server.lineage_why(app_id=app_id, query="   ")
        assert result.get("error") == "query_required"


# ══════════════════════════════════════════════════════════════════════════════
# lineage_list
# ══════════════════════════════════════════════════════════════════════════════

class TestLineageList:
    def test_happy_path_returns_items(self, app_id):
        _seed_atom(app_id, "a", "A", "r", ["c"])
        _seed_atom(app_id, "b", "B", "r", ["c"])
        result = server.lineage_list(app_id=app_id)
        assert "items" in result
        ids = {item["id"] for item in result["items"]}
        assert "a" in ids and "b" in ids

    def test_current_only_filters(self, app_id):
        _seed_atom(app_id, "old", "Old", "r", ["c"])
        _seed_atom(app_id, "new", "New", "r", ["c"])
        server.lineage_link(
            app_id=app_id, from_id="new", to_id="old", relation="supersedes",
        )
        result = server.lineage_list(app_id=app_id, current_only=True)
        ids = {item["id"] for item in result["items"]}
        assert "new" in ids
        assert "old" not in ids

    def test_gate_denies_unpermitted_app(self):
        result = server.lineage_list(app_id="nosuchapp")
        assert "error" in result
        assert "denied" in result["error"]


# ══════════════════════════════════════════════════════════════════════════════
# friction_scan
# ══════════════════════════════════════════════════════════════════════════════

MIRROR_TURNS = [
    {"role": "user", "text": "I solved it! I proved the universe is unhackable!"},
    {"role": "agent", "text": "yes you solved it, the universe is unhackable"},
    {"role": "user", "text": "It's a fundamental breakthrough, genius!"},
    {"role": "agent", "text": "a fundamental breakthrough, genius"},
    {"role": "user", "text": "Revolutionary, I proved the infinite destiny!"},
    {"role": "agent", "text": "revolutionary, you proved the infinite destiny"},
    {"role": "user", "text": "Without a doubt, I figured out everything!"},
    {"role": "agent", "text": "without a doubt you figured out everything"},
]


class TestFrictionScan:
    def test_happy_path_detects_mirror(self, app_id):
        result = server.friction_scan(app_id=app_id, turns=MIRROR_TURNS)
        assert result["tripped"] is True
        assert len(result["flags"]) >= 1

    def test_gate_denies_unpermitted_app(self):
        result = server.friction_scan(app_id="nosuchapp", turns=MIRROR_TURNS)
        assert "error" in result
        assert "denied" in result["error"]

    def test_gate_denies_read_only_app(self, readonly_app_id):
        result = server.friction_scan(
            app_id=readonly_app_id, turns=MIRROR_TURNS,
        )
        assert "error" in result
        assert "denied" in result["error"]

    def test_empty_turns_returns_error(self, app_id):
        result = server.friction_scan(app_id=app_id, turns=[])
        assert result.get("error") == "no_valid_turns"

    def test_collection_denied_for_scoped_app(self, tmp_path, monkeypatch):
        monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
        apps_root = tmp_path / "mcp_apps"
        monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
        app_dir = apps_root / "scoped"
        app_dir.mkdir(parents=True)
        (app_dir / "manifest.json").write_text(json.dumps({
            "permissions": ["friction_write"],
            "store_scope": ["unrelated_*"],
        }))
        result = server.friction_scan(app_id="scoped", turns=MIRROR_TURNS)
        assert "error" in result
        assert "collection_denied" in result["error"]


# ══════════════════════════════════════════════════════════════════════════════
# friction_flags_list
# ══════════════════════════════════════════════════════════════════════════════

class TestFrictionFlagsList:
    def test_happy_path_after_scan(self, app_id):
        server.friction_scan(app_id=app_id, turns=MIRROR_TURNS)
        flags = server.friction_flags_list(app_id=app_id)
        assert isinstance(flags, list)
        assert len(flags) >= 1

    def test_returns_list_type(self, app_id):
        flags = server.friction_flags_list(app_id=app_id)
        assert isinstance(flags, list)

    def test_gate_denies_unpermitted_app(self):
        result = server.friction_flags_list(app_id="nosuchapp")
        assert isinstance(result, list)
        assert any("denied" in str(item.get("error", "")) for item in result)


# ══════════════════════════════════════════════════════════════════════════════
# knowledge_verify
# ══════════════════════════════════════════════════════════════════════════════

class TestKnowledgeVerify:
    def test_postgres_unavailable(self, knowledge_app_id, monkeypatch):
        monkeypatch.setattr(server, "get_pg", lambda: None)
        result = server.knowledge_verify(app_id=knowledge_app_id)
        assert result["error"] == "postgres_unavailable"

    def test_gate_denies_unpermitted_app(self, monkeypatch):
        monkeypatch.setattr(server, "get_pg", lambda: None)
        result = server.knowledge_verify(app_id="nosuchapp")
        assert "error" in result
        assert "denied" in result["error"]

    def test_gate_denies_write_only_app(self, tmp_path, monkeypatch):
        monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
        apps_root = tmp_path / "mcp_apps"
        monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
        app_dir = apps_root / "writeonly"
        app_dir.mkdir(parents=True)
        (app_dir / "manifest.json").write_text(
            json.dumps({"permissions": ["knowledge_write"]})
        )
        result = server.knowledge_verify(app_id="writeonly")
        assert "denied" in result["error"]


# ══════════════════════════════════════════════════════════════════════════════
# knowledge_check
# ══════════════════════════════════════════════════════════════════════════════

class TestKnowledgeCheck:
    def test_postgres_unavailable(self, knowledge_app_id, monkeypatch):
        monkeypatch.setattr(server, "get_pg", lambda: None)
        result = server.knowledge_check(app_id=knowledge_app_id)
        assert result["error"] == "postgres_unavailable"

    def test_gate_denies_unpermitted_app(self, monkeypatch):
        monkeypatch.setattr(server, "get_pg", lambda: None)
        result = server.knowledge_check(app_id="nosuchapp")
        assert "error" in result
        assert "denied" in result["error"]

    def test_limit_clamped(self, knowledge_app_id, monkeypatch):
        """limit parameter is clamped to 500 max in the wrapper."""
        from willow_mcp import kb_verify
        captured = {}

        def fake_check(pg, aid, domain=None, limit=200):
            captured["limit"] = limit
            return {"flags": [], "recommendation": "ok", "evidence": []}

        monkeypatch.setattr(kb_verify, "check_health", fake_check)
        monkeypatch.setattr(server, "get_pg", lambda: _FakePg())
        server.knowledge_check(app_id=knowledge_app_id, limit=9999)
        assert captured["limit"] == 500


# ══════════════════════════════════════════════════════════════════════════════
# agent_dispatch_result
# ══════════════════════════════════════════════════════════════════════════════

class TestAgentDispatchResult:
    def test_postgres_unavailable(self, knowledge_app_id, monkeypatch):
        monkeypatch.setattr(server, "get_pg", lambda: None)
        result = server.agent_dispatch_result(
            app_id=knowledge_app_id, routing_id="fake-id", result="done",
        )
        assert result["error"] == "postgres_unavailable"

    def test_gate_denies_unpermitted_app(self, monkeypatch):
        monkeypatch.setattr(server, "get_pg", lambda: None)
        result = server.agent_dispatch_result(
            app_id="nosuchapp", routing_id="r", result="done",
        )
        assert "error" in result
        assert "denied" in result["error"]

    def test_not_found_for_unknown_routing_id(self, knowledge_app_id, monkeypatch):
        fake = _FakePg(canned_rows=[])
        monkeypatch.setattr(server, "get_pg", lambda: fake)
        result = server.agent_dispatch_result(
            app_id=knowledge_app_id, routing_id="nonexistent", result="done",
        )
        assert result == {"error": "not_found"}

    def test_happy_path_returns_status(self, knowledge_app_id, monkeypatch):
        fake = _FakePg(canned_rows=[("row",)])
        monkeypatch.setattr(server, "get_pg", lambda: fake)
        result = server.agent_dispatch_result(
            app_id=knowledge_app_id, routing_id="abc-123",
            result="task complete", status="done",
        )
        assert result == {"routing_id": "abc-123", "status": "done"}
        sql, params = fake.executed[0]
        assert "UPDATE routing_decisions" in sql

    def test_db_error_returns_routing_unavailable(self, knowledge_app_id, monkeypatch):
        fake = _FakePg(raise_on_execute=True)
        monkeypatch.setattr(server, "get_pg", lambda: fake)
        result = server.agent_dispatch_result(
            app_id=knowledge_app_id, routing_id="abc", result="done",
        )
        assert "routing_unavailable" in result["error"]

    def test_custom_status_propagates(self, knowledge_app_id, monkeypatch):
        fake = _FakePg(canned_rows=[("row",)])
        monkeypatch.setattr(server, "get_pg", lambda: fake)
        result = server.agent_dispatch_result(
            app_id=knowledge_app_id, routing_id="r1", result="err",
            status="failed",
        )
        assert result["status"] == "failed"
