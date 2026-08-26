"""Tests for gates_serve.py — the live local HTML dashboard's HTTP surface.

Uses Starlette's in-process TestClient rather than a real socket: exercises
the exact same routes/handlers `willow-mcp gates --serve` runs, without
needing a real port or a browser. The browser-driven path (a real click
through the rendered page) is covered manually, not in this suite, since it
needs a headless browser; this file pins the API contract the page's JS
depends on.
"""

import pytest

from willow_mcp import gates_serve, lease, manifest_admin


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path / "mcp_apps"))
    monkeypatch.delenv("WILLOW_MCP_STRICT_TRUST_ROOT", raising=False)
    return tmp_path


@pytest.fixture
def client(home):
    from starlette.testclient import TestClient

    manifest_admin.set_permission("testapp", "store_read", True)
    app = gates_serve.build_app(default_app_id="testapp")
    return TestClient(app)


def test_index_serves_html_with_embedded_default_app_id(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert 'const APP_ID = "testapp";' in res.text


def test_index_embeds_empty_string_for_no_default(home):
    from starlette.testclient import TestClient

    app = gates_serve.build_app()  # no default_app_id
    res = TestClient(app).get("/")
    assert 'const APP_ID = "";' in res.text


def test_state_defaults_to_server_app_id_when_no_query_param(client):
    res = client.get("/api/state")
    assert res.status_code == 200
    rows = res.json()
    scopes = {r["scope"] for r in rows}
    # {"global", "testapp"} are the app-vs-global axis this test locks in;
    # build-lease rows add a third axis (scope=<tool family>, one per earn-
    # first roster entry), which is legitimate distinct state and not the
    # subject of this test. Subset, not equality — matches the sibling
    # test's shape below.
    assert {"global", "testapp"} <= scopes


def test_state_query_param_overrides_default(client, home):
    manifest_admin.set_permission("otherapp", "store_read", True)
    res = client.get("/api/state?app_id=otherapp")
    scopes = {r["scope"] for r in res.json()}
    assert "otherapp" in scopes
    assert "testapp" not in scopes


def test_describe_unknown_row_is_404(client):
    res = client.get("/api/describe?row_id=nope.nonexistent")
    assert res.status_code == 404


def test_describe_permission_row(client):
    res = client.get("/api/describe?row_id=perm.testapp.store_write")
    assert res.status_code == 200
    assert res.json()["kind"] == "toggle_permission"


def test_describe_lease_row_lists_needed_fields(client):
    res = client.get("/api/describe?row_id=lease.testapp")
    body = res.json()
    assert body["kind"] == "lease_grant"
    assert set(body["needs"]) == {"ttl", "reason"}


def test_action_toggles_permission_and_persists(client, home):
    res = client.post("/api/action", json={"row_id": "perm.testapp.store_write", "inputs": {}})
    assert res.status_code == 200
    body = res.json()
    assert body["ok"] is True
    assert "store_write" in manifest_admin.read_manifest("testapp")["permissions"]


def test_action_grants_lease_via_inputs(client, home):
    res = client.post("/api/action", json={
        "row_id": "lease.testapp",
        "inputs": {"ttl": "5m", "reason": "server test"},
    })
    assert res.status_code == 200
    assert res.json()["ok"] is True
    st = lease.read_lease("testapp")
    assert st["status"] == "active"
    assert st["reason"] == "server test"


def test_action_bad_ttl_reports_error_without_granting(client, home):
    res = client.post("/api/action", json={
        "row_id": "lease.testapp",
        "inputs": {"ttl": "garbage"},
    })
    body = res.json()
    assert body["ok"] is False
    assert lease.read_lease("testapp")["status"] == "none"


def test_action_unknown_row_is_404(client):
    res = client.post("/api/action", json={"row_id": "perm.testapp.not_a_real_group"})
    assert res.status_code == 404


def test_action_malformed_body_is_400(client):
    res = client.post("/api/action", content="not json",
                       headers={"Content-Type": "application/json"})
    assert res.status_code == 400


def test_action_respects_query_param_app_id_scope(client, home):
    """Regression: an action must act on the app the row actually belongs
    to (row.scope), verified here via the query-param override path too —
    not the server's fixed default_app_id. (The `client` fixture already
    grants testapp `store_read`, so this checks a *different* permission
    doesn't leak onto testapp from an action explicitly scoped to otherapp.)"""
    manifest_admin.set_permission("otherapp", "audit", True)
    testapp_before = manifest_admin.read_manifest("testapp")["permissions"]

    res = client.post(
        "/api/action?app_id=otherapp",
        json={"row_id": "perm.otherapp.gap_promote", "inputs": {}},
    )
    assert res.json()["ok"] is True
    assert "gap_promote" in manifest_admin.read_manifest("otherapp")["permissions"]
    assert manifest_admin.read_manifest("testapp")["permissions"] == testapp_before
