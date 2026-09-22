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
    assert names == {"echo", "suspicious", "corpus_hits", "corpus_search"}
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
    assert {t["name"] for t in tools} == {"echo", "suspicious", "corpus_hits", "corpus_search"}
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


# Ceiling model (Loki 8AA7CBE7, HIGH rework): public < serve < internal;
# a caller at tier T sees every row at or below T's rank.

def test_filter_by_visibility_internal_caller_sees_every_tier():
    parsed = {"hits": [
        {"id": "a", "visibility": "internal"},
        {"id": "b", "visibility": "serve"},
        {"id": "c", "visibility": "public"},
        {"id": "d"},  # no visibility marker -> treated as internal, still visible to internal
    ]}
    filtered, dropped = mfc._filter_by_visibility(parsed, "internal")
    assert [r["id"] for r in filtered["hits"]] == ["a", "b", "c", "d"]
    assert dropped == 0


def test_filter_by_visibility_keeps_the_external_pool_for_a_serve_caller():
    parsed = {"hits": [
        {"id": "a", "visibility": "internal"},
        {"id": "b", "visibility": "serve"},
        {"id": "c", "visibility": "public"},
    ]}
    filtered, dropped = mfc._filter_by_visibility(parsed, "serve")
    assert [r["id"] for r in filtered["hits"]] == ["b", "c"]
    assert dropped == 1


def test_filter_by_visibility_public_caller_sees_public_only():
    parsed = {"hits": [
        {"id": "a", "visibility": "internal"},
        {"id": "b", "visibility": "serve"},
        {"id": "c", "visibility": "public"},
        {"id": "d"},  # no marker -> internal, hidden from a public caller
    ]}
    filtered, dropped = mfc._filter_by_visibility(parsed, "public")
    assert [r["id"] for r in filtered["hits"]] == ["c"]
    assert dropped == 3


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


def test_filter_by_visibility_recurses_into_a_nested_result_wrapper():
    """Loki 8AA7CBE7, MEDIUM: the original pass only looked at parsed's own
    top-level values, so `{"result": {"hits": [...]}}` went through
    unfiltered. This shape (a downstream boxing its rows under a nested
    key) must be filtered exactly like a top-level list."""
    parsed = {"result": {"hits": [
        {"id": "a", "visibility": "internal"},
        {"id": "b", "visibility": "public"},
    ]}}
    filtered, dropped = mfc._filter_by_visibility(parsed, "public")
    assert [r["id"] for r in filtered["result"]["hits"]] == ["b"]
    assert dropped == 1


def test_filter_by_visibility_withholds_a_singleton_row_dict_that_carries_visibility():
    """A single dict value (not wrapped in a list with siblings — a
    corpus's top-hit shape) is still withheld when it explicitly carries a
    `visibility` key the caller's tier does not clear; never rewritten,
    replaced with a `{"withheld": tier}` marker (Loki 24242675, finding 4)
    rather than a `None` a caller could index into."""
    row = {"id": "top", "visibility": "internal", "text": "verbatim"}
    parsed = {"nugget": row, "candidates": []}
    filtered, dropped = mfc._filter_by_visibility(parsed, "public")
    assert filtered["nugget"] == {"withheld": "internal"}
    assert dropped == 1

    kept, dropped2 = mfc._filter_by_visibility(parsed, "internal")
    assert kept["nugget"] is row
    assert dropped2 == 0


def test_filter_by_visibility_a_singleton_dict_without_a_visibility_key_or_sibling_row_list_is_not_treated_as_a_row():
    """A bare wrapper/metadata dict with NOTHING nearby to say it is a row
    (no `visibility` key of its own, no sibling row-list under the same
    parent) must never be read as an unmarked row. Otherwise the whole
    result envelope could be wiped for a narrow caller."""
    parsed = {"found": True, "meta": {"source": "jeles"}}
    filtered, dropped = mfc._filter_by_visibility(parsed, "public")
    assert filtered == parsed
    assert dropped == 0


def test_filter_by_visibility_an_unmarked_singleton_sharing_a_parent_with_a_row_list_is_a_row_too():
    """Loki 24242675, finding 1 — jeles's REAL top-hit shape: a `nugget`
    singleton with NO `visibility` key of its own, sibling to a
    `candidates` row-list that does carry markers. The first rework
    required an explicit `visibility` key to treat a singleton as a row,
    so this exact unmarked shape escaped to a "public" caller — the row
    most likely to be quoted was the one built to skip the check. One
    rule now: a sibling row-list is enough to mark "nugget" as a row too,
    missing-visibility defaulting to "internal" same as any list row."""
    parsed = {
        "found": True,
        "nugget": {"id": "top-hit", "text": "unmarked, but a row"},
        "candidates": [
            {"id": "alt-1", "visibility": "serve", "text": "x"},
            {"id": "alt-2", "visibility": "public", "text": "y"},
        ],
    }
    filtered, dropped = mfc._filter_by_visibility(parsed, "public")
    assert filtered["nugget"] == {"withheld": "internal"}
    assert [r["id"] for r in filtered["candidates"]] == ["alt-2"]
    assert dropped == 2  # the unmarked nugget + alt-1 (serve)

    kept, dropped2 = mfc._filter_by_visibility(parsed, "internal")
    assert kept["nugget"] == {"id": "top-hit", "text": "unmarked, but a row"}
    assert [r["id"] for r in kept["candidates"]] == ["alt-1", "alt-2"]
    assert dropped2 == 0


def test_call_tool_filters_corpus_hits_end_to_end_for_the_default_stdio_caller(echo_entry):
    """REWORK 2 (Loki 24242675, finding 2): an unconfigured/omitted-app_id
    caller over stdio (the default transport) is NOT "public" -- its tier
    IS the transport ceiling, "internal". Nothing is dropped; the caller
    sees its own corpus."""
    result = mfc.call_tool(echo_entry, "corpus_hits", {}, app_id="")
    assert result["visibility_tier"] == "internal"
    assert result["visibility_dropped"] == 0
    body = json.loads(result["content_text"])
    ids = {r["id"] for r in body["hits"]}
    assert ids == {"nugget-1", "nugget-2", "nugget-3", "nugget-4"}


def test_call_tool_filters_corpus_hits_end_to_end_for_the_default_serve_mode_caller(echo_entry):
    """Same unconfigured caller, but this call arrived over a serve/OAuth
    process (Loki 24242675, finding 2 + 8AA7CBE7 finding 3 together): the
    tier IS the transport ceiling, which for serve_mode is "serve", not
    "internal" and not "public"."""
    result = mfc.call_tool(echo_entry, "corpus_hits", {}, app_id="", serve_mode=True)
    assert result["visibility_tier"] == "serve"
    assert result["visibility_dropped"] == 2  # internal + the no-marker row
    body = json.loads(result["content_text"])
    ids = {r["id"] for r in body["hits"]}
    assert ids == {"nugget-2", "nugget-3"}


def test_call_tool_filters_corpus_hits_end_to_end_for_an_explicit_public_override(echo_entry, home):
    """A caller CAN still narrow itself to "public" explicitly, via a
    per-agent override -- the ceiling model enforces that request even
    over trusted stdio."""
    from willow_mcp import exposure as exp
    from willow_mcp import home_init as hi
    from willow_mcp import paths

    hi.ensure_home_layout()
    cfg = exp.load_exposure_config()
    cfg["agents"]["caller"] = {"defaults": {"federation_call": "public"}}
    paths.exposure_config_path().write_text(json.dumps(cfg), encoding="utf-8")

    result = mfc.call_tool(echo_entry, "corpus_hits", {}, app_id="caller")
    assert result["visibility_tier"] == "public"
    assert result["visibility_dropped"] == 3
    body = json.loads(result["content_text"])
    ids = {r["id"] for r in body["hits"]}
    assert ids == {"nugget-3"}


def test_call_tool_filters_corpus_search_end_to_end_withholding_the_unmarked_nugget_for_a_public_override(echo_entry, home):
    """Loki 24242675, finding 1, against the REAL jeles-shaped tool
    (corpus_search): the unmarked singleton `nugget` must be withheld for
    a caller narrower than "internal", exactly like a list row would be."""
    from willow_mcp import exposure as exp
    from willow_mcp import home_init as hi
    from willow_mcp import paths

    hi.ensure_home_layout()
    cfg = exp.load_exposure_config()
    cfg["agents"]["caller"] = {"defaults": {"federation_call": "public"}}
    paths.exposure_config_path().write_text(json.dumps(cfg), encoding="utf-8")

    result = mfc.call_tool(echo_entry, "corpus_search", {}, app_id="caller")
    assert result["visibility_tier"] == "public"
    body = json.loads(result["content_text"])
    assert body["nugget"] == {"withheld": "internal"}
    assert [r["id"] for r in body["candidates"]] == ["alt-2"]

    everything = mfc.call_tool(echo_entry, "corpus_search", {}, app_id="")
    assert everything["visibility_tier"] == "internal"
    body2 = json.loads(everything["content_text"])
    assert body2["nugget"]["id"] == "top-hit"
    assert {r["id"] for r in body2["candidates"]} == {"alt-1", "alt-2"}


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


def test_call_tool_filters_corpus_hits_end_to_end_for_an_internal_caller_over_stdio(echo_entry, home):
    from willow_mcp import exposure as exp
    from willow_mcp import home_init as hi
    from willow_mcp import paths

    hi.ensure_home_layout()
    cfg = exp.load_exposure_config()
    cfg["agents"]["caller"] = {"defaults": {"federation_call": "internal"}}
    paths.exposure_config_path().write_text(json.dumps(cfg), encoding="utf-8")

    result = mfc.call_tool(echo_entry, "corpus_hits", {}, app_id="caller", serve_mode=False)
    assert result["visibility_tier"] == "internal"
    assert result["visibility_dropped"] == 0
    body = json.loads(result["content_text"])
    ids = {r["id"] for r in body["hits"]}
    assert ids == {"nugget-1", "nugget-2", "nugget-3", "nugget-4"}


def test_call_tool_caps_an_internal_override_at_serve_when_the_transport_is_serve_mode(echo_entry, home):
    """Loki 8AA7CBE7, finding 3: a caller configured for "internal" must
    still cap at "serve" when this call arrived over a serve/OAuth process
    -- the transport ceiling wins even over an explicit per-agent override."""
    from willow_mcp import exposure as exp
    from willow_mcp import home_init as hi
    from willow_mcp import paths

    hi.ensure_home_layout()
    cfg = exp.load_exposure_config()
    cfg["agents"]["caller"] = {"defaults": {"federation_call": "internal"}}
    paths.exposure_config_path().write_text(json.dumps(cfg), encoding="utf-8")

    result = mfc.call_tool(echo_entry, "corpus_hits", {}, app_id="caller", serve_mode=True)
    assert result["visibility_tier"] == "serve"
    assert result["visibility_dropped"] == 2
    body = json.loads(result["content_text"])
    ids = {r["id"] for r in body["hits"]}
    assert ids == {"nugget-2", "nugget-3"}


def test_call_tool_reports_zero_dropped_and_leaves_content_text_alone_when_nothing_matches_visibility(echo_entry):
    """echo/suspicious never carry visibility rows at all — the filter must
    be a no-op for them (same content_text as before this feature)."""
    result = mfc.call_tool(echo_entry, "echo", {"text": "plain"}, app_id="")
    assert result["content_text"] == "plain"
    assert result["visibility_dropped"] == 0
