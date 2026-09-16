"""Desk-core advertise surface — discovery subset, not call ACL."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from willow_mcp import advertise, request_context, server


@pytest.fixture
def apps_root(tmp_path, monkeypatch):
    root = tmp_path / "mcp_apps"
    root.mkdir()
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(root))
    monkeypatch.delenv(advertise.ADVERTISE_ENV, raising=False)
    return root


def _write_manifest(apps_root: Path, app_id: str, body: dict) -> None:
    d = apps_root / app_id
    d.mkdir(parents=True)
    (d / "manifest.json").write_text(json.dumps(body), encoding="utf-8")


def test_desk_core_size_cap():
    assert len(advertise.DESK_CORE) <= 50


def test_willow_defaults_to_desk_core(apps_root):
    _write_manifest(
        apps_root,
        "willow",
        {"permissions": ["full_access"], "human_only": True},
    )
    catalogue = {
        name: name
        for name in list(advertise.DESK_CORE) + ["store_purge_collection", "lineage_why"]
    }
    names, mode = advertise.advertised_tools("willow", catalogue)
    assert mode == "desk_core"
    assert len(names) <= 50
    assert "dispatch_send" in names
    assert "store_purge_collection" not in names
    assert "lineage_why" not in names


def test_env_full_skips_desk_core(apps_root, monkeypatch):
    _write_manifest(apps_root, "willow", {"permissions": ["full_access"]})
    monkeypatch.setenv(advertise.ADVERTISE_ENV, "full")
    names, mode = advertise.advertised_tools("willow", {"dispatch_send": "dispatch_send"})
    assert mode == "full"
    assert names == []


def test_manifest_advertise_full(apps_root):
    _write_manifest(
        apps_root,
        "willow",
        {"permissions": ["full_access"], "advertise": "full"},
    )
    names, mode = advertise.advertised_tools("willow", {"gap_list": "gap_list"})
    assert mode == "full"
    assert names == []


def test_specialist_defaults_to_manifest_acl(apps_root):
    _write_manifest(
        apps_root,
        "hanuman",
        {"permissions": ["store_read", "gap_read"]},
    )
    catalogue = {
        "store_get": "store_get",
        "store_search": "store_search",
        "gap_list": "gap_list",
        "dispatch_send": "dispatch_send",
    }
    names, mode = advertise.advertised_tools("hanuman", catalogue)
    assert mode == "manifest"
    assert "store_get" in names
    assert "gap_list" in names
    assert "dispatch_send" not in names


def test_desk_core_intersects_visible_tools(apps_root):
    _write_manifest(
        apps_root,
        "willow",
        {"permissions": ["orchestrator"]},  # no task_queue
    )
    catalogue = {n: n for n in advertise.DESK_CORE}
    names, mode = advertise.advertised_tools("willow", catalogue)
    assert mode == "desk_core"
    assert "dispatch_send" in names
    assert "task_submit" not in names  # not in orchestrator group


def test_filter_tool_iterable_keeps_named():
    class T:
        def __init__(self, name):
            self.name = name

    tools = [T("a"), T("b"), {"name": "c"}]
    kept = advertise.filter_tool_iterable(tools, {"a", "c"})
    names = []
    for t in kept:
        names.append(t.name if hasattr(t, "name") else t["name"])
    assert names == ["a", "c"]


def test_middleware_desk_core_filters_list(apps_root, monkeypatch):
    _write_manifest(apps_root, "willow", {"permissions": ["full_access"]})
    monkeypatch.setenv("WILLOW_APP_ID", "willow")
    monkeypatch.setattr(server, "_serve_mode", lambda: False)

    class Tool:
        def __init__(self, name):
            self.name = name

    class Result:
        def __init__(self, tools):
            self.tools = tools

        def model_copy(self, *, update):
            return Result(update["tools"])

    class Ctx:
        method = "tools/list"

    full = Result(
        [
            Tool("dispatch_send"),
            Tool("store_purge_collection"),
            Tool("whoami"),
        ]
    )

    async def call_next(_ctx):
        return full

    monkeypatch.setattr(
        server,
        "_gate_tool_catalogue",
        lambda: {
            "dispatch_send": "dispatch_send",
            "store_purge_collection": "store_purge_collection",
        },
    )
    import asyncio

    out = asyncio.run(
        request_context.AdvertiseFilterMiddleware()(Ctx(), call_next)
    )
    names = [t.name for t in out.tools]
    assert "dispatch_send" in names
    assert "whoami" in names  # ungated desk_core member
    assert "store_purge_collection" not in names


def test_middleware_full_passes_through(apps_root, monkeypatch):
    _write_manifest(apps_root, "willow", {"permissions": ["full_access"]})
    monkeypatch.setenv("WILLOW_APP_ID", "willow")
    monkeypatch.setenv(advertise.ADVERTISE_ENV, "full")
    monkeypatch.setattr(server, "_serve_mode", lambda: False)

    class Tool:
        def __init__(self, name):
            self.name = name

    class Result:
        def __init__(self, tools):
            self.tools = tools

    class Ctx:
        method = "tools/list"

    full = Result([Tool("store_purge_collection"), Tool("dispatch_send")])

    async def call_next(_ctx):
        return full

    import asyncio

    out = asyncio.run(
        request_context.AdvertiseFilterMiddleware()(Ctx(), call_next)
    )
    assert [t.name for t in out.tools] == [
        "store_purge_collection",
        "dispatch_send",
    ]
