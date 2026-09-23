"""End-to-end tests for the three federation_* MCP tools in server.py: the
gate, the ratified-registry ceiling, and a real downstream round trip,
wired together the way an actual caller would exercise them.
"""
import json
import sys
from pathlib import Path

import pytest

from willow_mcp import gate, mcp_federation as mf, mcp_federation_client as mfc, server

_FIXTURE = Path(__file__).parent / "fixtures" / "echo_mcp_server.py"


def _manifest(home, app_id, permissions):
    apps = home / "mcp_apps" / app_id
    apps.mkdir(parents=True, exist_ok=True)
    (apps / "manifest.json").write_text(json.dumps({"permissions": permissions}))


def _ratify_echo_fixture(home):
    spec = mf.McpServerSpec(
        id="echo-fixture", name="echo", command=sys.executable,
        args=(str(_FIXTURE),), env_keys=(),
    )
    mf.ratify(spec, ratified_by="operator", reason="test fixture")
    return spec.id


@pytest.fixture(autouse=True)
def _cleanup_client():
    yield
    mfc.shutdown_all()


def test_federation_discover_denied_without_federation_read(home):
    _manifest(home, "caller", [])
    out = server.federation_discover(app_id="caller")
    assert "error" in out


def test_federation_discover_finds_an_unratified_mcp_json(home, tmp_path):
    _manifest(home, "caller", ["federation_read"])
    proj = tmp_path / "someproject"
    proj.mkdir()
    (proj / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"svc": {"command": "true"}}}))
    out = server.federation_discover(app_id="caller", root=str(proj))
    assert str(proj / ".mcp.json") in out["unregistered"]


def test_federation_list_servers_reports_the_ratified_registry(home):
    _manifest(home, "caller", ["federation_read"])
    server_id = _ratify_echo_fixture(home)
    out = server.federation_list_servers(app_id="caller")
    ids = {s["id"] for s in out["servers"]}
    assert server_id in ids


def test_federation_call_denied_without_any_grant(home):
    _manifest(home, "caller", [])
    out = server.federation_call(app_id="caller", server_id="whatever",
                                 tool="echo", arguments={})
    assert "error" in out


def test_federation_call_denied_when_server_unratified_even_with_full_grants(home, monkeypatch):
    from willow_mcp import lease
    perm = gate.federated_tool_permission("never-ratified", "echo")
    _manifest(home, "caller", [gate.MCP_FEDERATION_PERMISSION, perm, "federation_call"])
    monkeypatch.setattr("willow_mcp.consent.federation_permitted", lambda: True)
    lease.grant("caller", 1800, issuer="operator", reason="test")
    out = server.federation_call(app_id="caller", server_id="never-ratified",
                                 tool="echo", arguments={})
    assert "error" in out
    assert "server_denied" in out["error"]


def test_federation_call_full_round_trip(home, monkeypatch):
    """Every key held at once: manifest capability, namespaced tool grant,
    ratified server, standing consent, live lease — a real subprocess round
    trip through the guarded MCP tool."""
    from willow_mcp import lease

    server_id = _ratify_echo_fixture(home)
    perm = gate.federated_tool_permission(server_id, "echo")
    _manifest(home, "caller", [gate.MCP_FEDERATION_PERMISSION, perm, "federation_call",
                               "receipts_tail"])
    monkeypatch.setattr("willow_mcp.consent.federation_permitted", lambda: True)
    lease.grant("caller", 1800, issuer="operator", reason="test")

    out = server.federation_call(app_id="caller", server_id=server_id,
                                 tool="echo", arguments={"text": "hello from a test"})
    assert "error" not in out
    assert out["content_text"] == "hello from a test"
    assert out["server_id"] == server_id
    assert out["tool"] == "echo"

    receipts = server.receipts_tail(app_id="caller", limit=10)["receipts"]
    detail_blob = " ".join(r.get("detail") or "" for r in receipts)
    assert server_id in detail_blob and "tool=echo" in detail_blob


def test_federation_call_unconfigured_stdio_caller_sees_its_own_corpus_and_says_so_in_the_receipt(
    home, monkeypatch
):
    """Sealed ae23d366 clause 3, end to end through the guarded MCP tool.
    REWORK 2 (Loki 24242675, finding 2): an unconfigured caller over stdio
    (this test's default transport — federation_call's own _serve_mode()
    is not stubbed here) is NOT "public" — its tier IS the transport
    ceiling, "internal". Nothing is dropped; receipts_tail says so."""
    from willow_mcp import lease

    server_id = _ratify_echo_fixture(home)
    perm = gate.federated_tool_permission(server_id, "corpus_hits")
    _manifest(home, "caller", [gate.MCP_FEDERATION_PERMISSION, perm, "federation_call",
                               "receipts_tail"])
    monkeypatch.setattr("willow_mcp.consent.federation_permitted", lambda: True)
    lease.grant("caller", 1800, issuer="operator", reason="test")

    out = server.federation_call(app_id="caller", server_id=server_id,
                                 tool="corpus_hits", arguments={})
    assert "error" not in out
    assert out["visibility_tier"] == "internal"
    assert out["visibility_dropped"] == 0
    body = json.loads(out["content_text"])
    ids = {r["id"] for r in body["hits"]}
    assert ids == {"nugget-1", "nugget-2", "nugget-3", "nugget-4"}

    receipts = server.receipts_tail(app_id="caller", limit=10)["receipts"]
    detail_blob = " ".join(r.get("detail") or "" for r in receipts)
    assert "visibility_tier=internal" in detail_blob
    assert "visibility_dropped=0" in detail_blob


def test_federation_call_an_explicit_public_override_drops_rows_above_public_and_says_so_in_the_receipt(
    home, monkeypatch
):
    """A caller can still narrow itself explicitly to "public" via a
    per-agent override — the ceiling model still enforces that request
    even over trusted stdio, end to end through the guarded MCP tool."""
    from willow_mcp import exposure as exp
    from willow_mcp import home_init as hi
    from willow_mcp import lease
    from willow_mcp import paths

    hi.ensure_home_layout()
    cfg = exp.load_exposure_config()
    cfg["agents"]["caller"] = {"defaults": {"federation_call": "public"}}
    paths.exposure_config_path().write_text(json.dumps(cfg), encoding="utf-8")

    server_id = _ratify_echo_fixture(home)
    perm = gate.federated_tool_permission(server_id, "corpus_hits")
    _manifest(home, "caller", [gate.MCP_FEDERATION_PERMISSION, perm, "federation_call",
                               "receipts_tail"])
    monkeypatch.setattr("willow_mcp.consent.federation_permitted", lambda: True)
    lease.grant("caller", 1800, issuer="operator", reason="test")

    out = server.federation_call(app_id="caller", server_id=server_id,
                                 tool="corpus_hits", arguments={})
    assert "error" not in out
    assert out["visibility_tier"] == "public"
    assert out["visibility_dropped"] == 3
    body = json.loads(out["content_text"])
    ids = {r["id"] for r in body["hits"]}
    assert ids == {"nugget-3"}

    receipts = server.receipts_tail(app_id="caller", limit=10)["receipts"]
    detail_blob = " ".join(r.get("detail") or "" for r in receipts)
    assert "visibility_tier=public" in detail_blob
    assert "visibility_dropped=3" in detail_blob


def test_federation_call_caps_an_internal_override_at_serve_when_this_process_is_serve_mode(
    home, monkeypatch
):
    """Loki 8AA7CBE7, finding 3: the transport is the stronger signal for
    "is this call remote" than the caller's own exposure.json. A caller
    explicitly configured for "internal" must still cap at "serve" when
    THIS PROCESS is running in serve mode (`server._serve_mode()`), proven
    end to end through the guarded federation_call tool, not just the
    exposure/mcp_federation_client unit tests."""
    from willow_mcp import exposure as exp
    from willow_mcp import home_init as hi
    from willow_mcp import lease
    from willow_mcp import paths

    hi.ensure_home_layout()
    cfg = exp.load_exposure_config()
    cfg["agents"]["caller"] = {"defaults": {"federation_call": "internal"}}
    paths.exposure_config_path().write_text(json.dumps(cfg), encoding="utf-8")

    server_id = _ratify_echo_fixture(home)
    perm = gate.federated_tool_permission(server_id, "corpus_hits")
    _manifest(home, "caller", [gate.MCP_FEDERATION_PERMISSION, perm, "federation_call",
                               "receipts_tail"])
    monkeypatch.setattr("willow_mcp.consent.federation_permitted", lambda: True)
    monkeypatch.setattr(server, "_serve_mode", lambda: True)
    # The serve arm of `_gate` resolves identity from a real OAuth session
    # (test_serve_mode_gate.py covers that seam on its own); this test's
    # subject is the exposure-tier transport ceiling, not OAuth binding, so
    # the bound identity is stubbed directly rather than standing up a
    # signed_in() contextvar + confirm-binding round trip.
    monkeypatch.setattr(server, "_resolve_serve_identity", lambda: ("caller", None))
    lease.grant("caller", 1800, issuer="operator", reason="test")

    out = server.federation_call(app_id="caller", server_id=server_id,
                                 tool="corpus_hits", arguments={})
    assert "error" not in out
    assert out["visibility_tier"] == "serve"
    assert out["visibility_dropped"] == 2
    body = json.loads(out["content_text"])
    ids = {r["id"] for r in body["hits"]}
    assert ids == {"nugget-2", "nugget-3"}


def test_federation_call_loopback_tool_without_lease(home, monkeypatch):
    """Classified loopback stdio tools reach the downstream without grant-net."""
    server_id = _ratify_echo_fixture(home)
    perm = gate.federated_tool_permission(server_id, "corpus_search")
    _manifest(home, "caller", [gate.MCP_FEDERATION_PERMISSION, perm, "federation_call"])
    monkeypatch.setattr("willow_mcp.consent.federation_permitted", lambda: True)

    out = server.federation_call(app_id="caller", server_id=server_id,
                                 tool="corpus_search", arguments={})
    assert "error" not in out
    assert "lease_denied" not in str(out)


def test_federation_call_unknown_stdio_tool_still_needs_lease(home, monkeypatch):
    server_id = _ratify_echo_fixture(home)
    perm = gate.federated_tool_permission(server_id, "echo")
    _manifest(home, "caller", [gate.MCP_FEDERATION_PERMISSION, perm, "federation_call"])
    monkeypatch.setattr("willow_mcp.consent.federation_permitted", lambda: True)

    out = server.federation_call(app_id="caller", server_id=server_id,
                                 tool="echo", arguments={"text": "x"})
    assert "error" in out
    assert "lease_denied" in out["error"]


def test_federation_call_grant_on_one_tool_does_not_reach_another(home, monkeypatch):
    """Decision 1, exercised end to end: a grant for `echo` must not let the
    same caller reach `suspicious` on the same ratified server."""
    from willow_mcp import lease

    server_id = _ratify_echo_fixture(home)
    perm = gate.federated_tool_permission(server_id, "echo")
    _manifest(home, "caller", [gate.MCP_FEDERATION_PERMISSION, perm, "federation_call"])
    monkeypatch.setattr("willow_mcp.consent.federation_permitted", lambda: True)
    lease.grant("caller", 1800, issuer="operator", reason="test")

    ok = server.federation_call(app_id="caller", server_id=server_id, tool="echo",
                                arguments={"text": "x"})
    assert "error" not in ok
    denied = server.federation_call(app_id="caller", server_id=server_id,
                                    tool="suspicious", arguments={})
    assert "error" in denied
    # Back-to-back calls may hit federation rate limit before tool gate is evaluated.
    assert denied["error"] in ("tool_denied", "rate_limited")
