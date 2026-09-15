"""S1 authority_check PDP — unit tests (dispatch E5F2D78B)."""
import json

import pytest

from willow_mcp import authority, gate, server


def _manifest(tmp_path, monkeypatch, app_id: str, permissions, **extra):
    apps_root = tmp_path / "mcp_apps"
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / app_id
    app_dir.mkdir(parents=True)
    body = {"permissions": permissions, **extra}
    (app_dir / "manifest.json").write_text(json.dumps(body))
    return app_id


def _charter(tmp_path, monkeypatch, *, maximum=2):
    registry = {
        "active": [{
            "id": "env-dispatch",
            "verb_id": 11,
            "verb": "dispatch",
            "grantee": "willow",
            "bounds": {"to_agents": ["hanuman"], "task_class": ["build"]},
            "issued_by": "root",
            "issued_at": "2026-01-01",
            "expires_at": "2027-01-01",
            "max_count": maximum,
            "use_count_source": "frank",
            "status": "active",
        }]
    }
    table = {
        "verbs": [{
            "id": 11,
            "verb": "dispatch",
            "bounds": {"to_agents": "list", "task_class": "string"},
        }]
    }
    registry_path = tmp_path / "pre-approved.json"
    syscall_path = tmp_path / "syscall-table.json"
    tmp_path.chmod(0o700)
    registry_path.write_text(json.dumps(registry))
    syscall_path.write_text(json.dumps(table))
    registry_path.chmod(0o600)
    syscall_path.chmod(0o600)
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(registry_path))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(syscall_path))


def test_allow_with_citation_via_permission_group(tmp_path, monkeypatch):
    app_id = _manifest(tmp_path, monkeypatch, "scribe", ["store_read"])
    decision = authority.authority_check(
        app_id, authority.ACTION_MCP_TOOL, "store_get", {}
    )
    assert decision.allowed is True
    assert decision.citation == "store_read"
    assert decision.missing_authority is None


def test_allow_with_literal_permission_citation(tmp_path, monkeypatch):
    app_id = _manifest(tmp_path, monkeypatch, "custom", ["store_get"])
    decision = authority.authority_check(
        app_id, authority.ACTION_MCP_TOOL, "store_get", {}
    )
    assert decision.allowed is True
    assert decision.citation == "store_get"


def test_deny_by_omission_names_missing_tool(tmp_path, monkeypatch):
    app_id = _manifest(tmp_path, monkeypatch, "readonly", ["store_read"])
    decision = authority.authority_check(
        app_id, authority.ACTION_MCP_TOOL, "store_put", {}
    )
    assert decision.allowed is False
    assert decision.missing_authority == "store_put"
    assert "store_put" in decision.reason


def test_deny_on_missing_manifest(tmp_path, monkeypatch):
    apps_root = tmp_path / "mcp_apps"
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    decision = authority.authority_check(
        "ghost", authority.ACTION_MCP_TOOL, "store_get", {}
    )
    assert decision.allowed is False
    assert decision.missing_authority == "manifest"


def test_deny_on_malformed_manifest_permissions(tmp_path, monkeypatch):
    apps_root = tmp_path / "mcp_apps"
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / "broken"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(json.dumps({"permissions": "full_access"}))
    decision = authority.authority_check(
        "broken", authority.ACTION_MCP_TOOL, "store_get", {}
    )
    assert decision.allowed is False
    assert decision.missing_authority == "permissions"


def test_deny_tools_blocks_even_when_group_grants(tmp_path, monkeypatch):
    app_id = _manifest(
        tmp_path, monkeypatch, "denied", ["full_access"], deny_tools=["store_put"]
    )
    decision = authority.authority_check(
        app_id, authority.ACTION_MCP_TOOL, "store_put", {}
    )
    assert decision.allowed is False
    assert decision.missing_authority == "deny_tools:store_put"


def test_envelope_allow_with_citation(tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    decision = authority.authority_check(
        "willow",
        "dispatch",
        "env-dispatch",
        {"call_args": {"to_agents": "hanuman", "task_class": "build"}},
    )
    assert decision.allowed is True
    assert decision.citation == "env-dispatch"


def test_envelope_bounds_mismatch_is_void(tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    decision = authority.authority_check(
        "willow",
        "dispatch",
        "env-dispatch",
        {"call_args": {"to_agents": "opus", "task_class": "build"}},
    )
    assert decision.allowed is False
    assert decision.missing_authority is not None


def test_envelope_bounds_signature_mismatch_denies(tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    registry_path = tmp_path / "pre-approved.json"
    data = json.loads(registry_path.read_text())
    data["active"][0]["bounds"]["extra"] = "surprise"
    registry_path.write_text(json.dumps(data))
    decision = authority.authority_check(
        "willow",
        "dispatch",
        "env-dispatch",
        {"call_args": {"to_agents": "hanuman", "task_class": "build"}},
    )
    assert decision.allowed is False


def test_authority_check_matches_gate_permitted(tmp_path, monkeypatch):
    """PDP manifest path must agree with gate.permitted for allow/deny parity."""
    cases = [
        ("allowed", ["full_access"], "store_get", True),
        ("readonly", ["store_read"], "store_put", False),
        ("literal", ["store_get"], "store_get", True),
    ]
    for app_id, perms, tool, expected in cases:
        _manifest(tmp_path, monkeypatch, app_id, perms)
        decision = authority.authority_check(
            app_id, authority.ACTION_MCP_TOOL, tool, {}
        )
        assert decision.allowed is expected
        assert gate.permitted(app_id, tool) is expected


@pytest.mark.parametrize(
    ("app_id", "permissions", "tool", "expected_missing"),
    [
        ("denied", ["full_access"], "store_put", "deny_tools:store_put"),
        ("broken", "full_access", "store_get", "permissions"),
        ("empty", [], "store_get", "permissions"),
        ("ghost", None, "store_get", "manifest"),
    ],
)
def test_authority_parity_matrix_special_cases(
    tmp_path, monkeypatch, app_id, permissions, tool, expected_missing
):
    apps_root = tmp_path / "mcp_apps"
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / app_id
    if permissions is not None:
        app_dir.mkdir(parents=True)
        body = {"permissions": permissions}
        if app_id == "denied":
            body["deny_tools"] = ["store_put"]
        (app_dir / "manifest.json").write_text(json.dumps(body))

    decision = authority.authority_check(
        app_id, authority.ACTION_MCP_TOOL, tool, {}
    )
    assert decision.allowed is False
    assert decision.missing_authority == expected_missing
    assert gate.permitted(app_id, tool) is False


@pytest.fixture(autouse=True)
def _fresh_rate_buckets():
    server._buckets.clear()
    yield
    server._buckets.clear()


def test_flag_off_gate_behavior_unchanged(tmp_path, monkeypatch):
    """Regression: WILLOW_MCP_AUTHORITY_CHECK off ⇒ legacy permitted() path."""
    monkeypatch.delenv("WILLOW_MCP_AUTHORITY_CHECK", raising=False)
    apps_root = tmp_path / "mcp_apps"
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / "readonly"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(json.dumps({"permissions": ["store_read"]}))

    called = {"n": 0}
    original = authority.authority_check

    def _boom(*a, **kw):
        called["n"] += 1
        return original(*a, **kw)

    monkeypatch.setattr(authority, "authority_check", _boom)
    result = server.store_put(app_id="readonly", collection="c", record={"v": 1})
    assert "denied" in result["error"]
    assert called["n"] == 0


def test_flag_on_uses_authority_check(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_MCP_AUTHORITY_CHECK", "1")
    apps_root = tmp_path / "mcp_apps"
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / "readonly"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(json.dumps({"permissions": ["store_read"]}))

    result = server.store_put(app_id="readonly", collection="c", record={"v": 1})
    assert "authority denied" in result["error"]
    assert "store_put" in result["error"]


def test_authority_denied_files_a_perm_ask_and_appends_the_sentence(
    tmp_path, monkeypatch
):
    """Gap `5ecb87cfdf56` follow-up (authority-branch producer): the
    authority-check path files the same `perm.*` ask its sister branch
    (`permitted()` miss) files. Trigger is the ordinary "not granted"
    outcome — `missing_authority == tool_name` — nothing else, since the
    other failure modes name conditions no ask can satisfy."""
    from willow_mcp import gates_panel
    from willow_mcp.db import Store

    monkeypatch.setenv("WILLOW_MCP_AUTHORITY_CHECK", "1")
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    apps_root = tmp_path / "mcp_apps"
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / "readonly"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(
        json.dumps({"permissions": ["store_read"]}))

    effective, err = server._gate("readonly", "store_put")
    assert effective is None
    # The original refusal is preserved verbatim above the appended sentence.
    assert "authority denied" in err["error"]
    assert "store_put" in err["error"]
    # And the ask sentence is appended.
    assert "queued for the operator as request" in err["error"]
    assert "willow-mcp gates" in err["error"]

    items = gates_panel.open_requests(Store(store_root=str(tmp_path / "store")))
    assert len(items) == 1
    assert items[0]["request"]["gate_id"] == "perm.readonly.store_write"


def test_authority_denied_files_no_ask_for_missing_manifest(
    tmp_path, monkeypatch
):
    """A principal with no manifest at all names a condition no `perm.*`
    ask can satisfy — the app does not exist, so nobody is asking for its
    permission. The denial says why; no queue row backs a claim of
    'someone asked'."""
    from willow_mcp import gates_panel
    from willow_mcp.db import Store

    monkeypatch.setenv("WILLOW_MCP_AUTHORITY_CHECK", "1")
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    apps_root = tmp_path / "mcp_apps"
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    apps_root.mkdir(parents=True)  # empty — no manifest

    effective, err = server._gate("unknownapp", "store_put")
    assert effective is None
    assert "authority denied" in err["error"]
    assert "queued for the operator" not in err["error"]

    assert gates_panel.open_requests(
        Store(store_root=str(tmp_path / "store"))) == []


def test_authority_denied_files_no_ask_for_explicit_deny_tools(
    tmp_path, monkeypatch
):
    """`deny_tools:<tool>` names a tool the operator explicitly denied. An
    ask would be a request to un-deny — but the operator's ordinary path
    for that is to edit `deny_tools`, not press a `perm.*` row. Filing an
    ask here would teach the queue to render presses that do nothing."""
    from willow_mcp import gates_panel
    from willow_mcp.db import Store

    monkeypatch.setenv("WILLOW_MCP_AUTHORITY_CHECK", "1")
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    apps_root = tmp_path / "mcp_apps"
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / "readonly"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(json.dumps({
        "permissions": ["full_access"],
        "deny_tools": ["store_put"],
    }))

    effective, err = server._gate("readonly", "store_put")
    assert effective is None
    assert "authority denied" in err["error"]
    assert "queued for the operator" not in err["error"]

    assert gates_panel.open_requests(
        Store(store_root=str(tmp_path / "store"))) == []
