"""End-to-end tests for mcp_federation_client against a real stdio MCP
server subprocess (tests/fixtures/echo_mcp_server.py) — the actual round
trip a ratified downstream server would get, not a mock.
"""
import json
import sys
from pathlib import Path

import pytest

from willow_mcp import mcp_federation_client as mfc

_FIXTURE = Path(__file__).parent / "fixtures" / "echo_mcp_server.py"


@pytest.fixture
def echo_entry(monkeypatch):
    """Point mcp_federation.get_ratified at a fake in-memory entry for the
    fixture server, without touching the real ratified-registry file."""
    entry = {
        "id": "echo-fixture", "name": "echo", "command": sys.executable,
        "args": [str(_FIXTURE)], "env_keys": [], "transport": "stdio",
    }
    monkeypatch.setattr("willow_mcp.mcp_federation.get_ratified",
                        lambda server_id: entry if server_id == "echo-fixture" else None)
    yield "echo-fixture"
    mfc.shutdown_all()


def test_connect_returns_a_guarded_tool_listing(echo_entry):
    tools = mfc.connect_server(echo_entry)
    names = {t["name"] for t in tools}
    assert names == {"echo", "suspicious", "corpus_hits"}
    for t in tools:
        assert "guard_verdict" in t and "guard_hits" in t


def test_listing_time_guard_flags_a_malicious_tool_description(echo_entry):
    """Decision 4(c): tool names/descriptions are untrusted input, scanned at
    listing time, before anything is spliced into a caller's context."""
    tools = mfc.connect_server(echo_entry)
    by_name = {t["name"]: t for t in tools}
    assert by_name["echo"]["guard_verdict"] == "CLEAN"
    assert by_name["suspicious"]["guard_verdict"] == "BLOCKED"
    # The flagged description is sandwich-wrapped, never spliced in verbatim.
    assert "EXTERNAL DATA START" in by_name["suspicious"]["description"]


def test_call_tool_round_trips_a_clean_result(echo_entry):
    result = mfc.call_tool(echo_entry, "echo", {"text": "hello federation"})
    assert result["is_error"] is False
    assert result["content_text"] == "hello federation"
    assert result["guard_verdict"] == "CLEAN"


def test_call_tool_result_is_guarded_and_sandwiched_when_flagged(echo_entry):
    result = mfc.call_tool(echo_entry, "suspicious", {})
    assert result["guard_verdict"] == "BLOCKED"
    assert "EXTERNAL DATA START" in result["content_text"]
    assert result["guard_hits"]


def test_call_tool_connects_lazily_without_an_explicit_connect_first(echo_entry):
    result = mfc.call_tool(echo_entry, "echo", {"text": "lazy"})
    assert result["content_text"] == "lazy"


def test_disconnect_then_reconnect_gets_a_fresh_working_session(echo_entry):
    mfc.connect_server(echo_entry)
    assert mfc.disconnect_server(echo_entry) is True
    # A second disconnect of an already-gone connection is a clean no-op,
    # not an error.
    assert mfc.disconnect_server(echo_entry) is False
    tools = mfc.connect_server(echo_entry)
    assert {t["name"] for t in tools} == {"echo", "suspicious", "corpus_hits"}
    result = mfc.call_tool(echo_entry, "echo", {"text": "after reconnect"})
    assert result["content_text"] == "after reconnect"


def test_list_server_tools_refresh_reissues_list_tools(echo_entry):
    first = mfc.list_server_tools(echo_entry)
    refreshed = mfc.list_server_tools(echo_entry, refresh=True)
    assert {t["name"] for t in first} == {t["name"] for t in refreshed}


def test_shutdown_all_clears_every_connection(echo_entry):
    mfc.connect_server(echo_entry)
    assert echo_entry in mfc._connections
    mfc.shutdown_all()
    assert mfc._connections == {}


def test_call_tool_refuses_a_server_that_is_not_ratified(monkeypatch):
    monkeypatch.setattr("willow_mcp.mcp_federation.get_ratified", lambda server_id: None)
    with pytest.raises(mfc.FederationClientError):
        mfc.call_tool("ghost-server", "echo", {})


def test_unsupported_transport_is_reported_not_silently_ignored(monkeypatch):
    """`http` used to be the example of an unsupported transport here; it is now
    routed to the streamable-HTTP client (see test_mcp_federation_client_http.py),
    so the case this test exists for needs a transport that really is unknown.
    The property under test is unchanged: an entry this client cannot honour
    fails loudly rather than connecting to nothing."""
    entry = {"id": "pigeon", "name": "carrier-pigeon", "command": "",
             "transport": "carrier-pigeon", "url": "https://example.invalid",
             "env_keys": []}
    monkeypatch.setattr("willow_mcp.mcp_federation.get_ratified",
                        lambda server_id: entry if server_id == "pigeon" else None)
    with pytest.raises(mfc.FederationClientError, match="not supported"):
        mfc.connect_server("pigeon")
    mfc.shutdown_all()


# ── Exposure filter (sealed ae23d366 clause 3) ────────────────────────────


def test_filter_by_visibility_keeps_only_the_internal_row_for_an_internal_caller():
    parsed = {"hits": [
        {"id": "a", "visibility": "internal"},
        {"id": "b", "visibility": "serve"},
        {"id": "c", "visibility": "public"},
        {"id": "d"},  # no visibility marker -> treated as internal
    ]}
    filtered, dropped = mfc._filter_by_visibility(parsed, "internal")
    assert [r["id"] for r in filtered["hits"]] == ["a", "d"]
    assert dropped == 2


def test_filter_by_visibility_keeps_the_external_pool_for_a_serve_caller():
    parsed = {"hits": [
        {"id": "a", "visibility": "internal"},
        {"id": "b", "visibility": "serve"},
        {"id": "c", "visibility": "public"},
    ]}
    filtered, dropped = mfc._filter_by_visibility(parsed, "serve")
    assert [r["id"] for r in filtered["hits"]] == ["b", "c"]
    assert dropped == 1


def test_filter_by_visibility_never_rewrites_a_surviving_row():
    row = {"id": "a", "visibility": "internal", "text": "verbatim"}
    parsed = {"hits": [row]}
    filtered, dropped = mfc._filter_by_visibility(parsed, "internal")
    assert filtered["hits"][0] is row
    assert dropped == 0


def test_filter_by_visibility_ignores_non_row_shaped_values():
    parsed = {"hits": [{"id": "a", "visibility": "internal"}], "note": "not a row list",
              "count": 1, "empty": []}
    filtered, dropped = mfc._filter_by_visibility(parsed, "internal")
    assert filtered["note"] == "not a row list"
    assert filtered["count"] == 1
    assert dropped == 0


def test_filter_by_visibility_on_a_non_dict_is_a_no_op():
    assert mfc._filter_by_visibility(["not", "a", "dict"], "internal") == (["not", "a", "dict"], 0)


def test_call_tool_filters_corpus_hits_end_to_end_for_an_internal_caller(echo_entry):
    result = mfc.call_tool(echo_entry, "corpus_hits", {}, app_id="")
    assert result["visibility_tier"] == "internal"
    # nugget-1 (internal) and nugget-4 (no marker -> treated as internal)
    # survive; nugget-2 (serve) and nugget-3 (public) are dropped.
    assert result["visibility_dropped"] == 2
    body = json.loads(result["content_text"])
    ids = {r["id"] for r in body["hits"]}
    assert ids == {"nugget-1", "nugget-4"}


def test_call_tool_filters_corpus_hits_end_to_end_for_a_serve_caller(echo_entry, home):
    from willow_mcp import exposure as exp
    from willow_mcp import home_init as hi
    from willow_mcp import paths

    hi.ensure_home_layout()
    cfg = exp.load_exposure_config()
    cfg["agents"]["caller"] = {"defaults": {"federation_call": "serve"}}
    paths.exposure_config_path().write_text(json.dumps(cfg), encoding="utf-8")

    result = mfc.call_tool(echo_entry, "corpus_hits", {}, app_id="caller")
    assert result["visibility_tier"] == "serve"
    assert result["visibility_dropped"] == 2  # internal + the no-marker row
    body = json.loads(result["content_text"])
    ids = {r["id"] for r in body["hits"]}
    assert ids == {"nugget-2", "nugget-3"}


def test_call_tool_reports_zero_dropped_and_leaves_content_text_alone_when_nothing_matches_visibility(echo_entry):
    """echo/suspicious never carry visibility rows at all — the filter must
    be a no-op for them (same content_text as before this feature)."""
    result = mfc.call_tool(echo_entry, "echo", {"text": "plain"}, app_id="")
    assert result["content_text"] == "plain"
    assert result["visibility_dropped"] == 0
