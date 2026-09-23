"""Tests for federation_egress — the gate a federated MCP call must clear.

Mirrors tests/test_web_egress.py's shape, extended with the two checks that
lane does not need: the namespaced per-downstream-tool grant, and the
operator-ratified server ceiling (docs/design/federated-mcp-gating.md
Decision 2).
"""
import json

from willow_mcp import federation_egress, gate, mcp_federation as mf


SERVER_ID = "srv0000001"


def _manifest(home, app_id, permissions):
    apps = home / "mcp_apps" / app_id
    apps.mkdir(parents=True, exist_ok=True)
    (apps / "manifest.json").write_text(json.dumps({"permissions": permissions}))


def _ratify(server_id=SERVER_ID):
    spec = mf.McpServerSpec(id=server_id, name="svc", command="true")
    return mf.ratify(spec, ratified_by="operator", reason="test")


def test_denied_without_mcp_federation_capability(home):
    _manifest(home, "caller", [gate.federated_tool_permission(SERVER_ID, "echo")])
    denial = federation_egress.egress_denial("caller", SERVER_ID, "echo")
    assert denial is not None
    assert "net_denied" in denial["error"]


def test_denied_without_namespaced_tool_grant(home):
    """Holding the bare capability is not enough — Decision 1: gate per
    downstream tool, never per call."""
    _manifest(home, "caller", [gate.MCP_FEDERATION_PERMISSION])
    denial = federation_egress.egress_denial("caller", SERVER_ID, "echo")
    assert denial is not None
    assert "tool_denied" in denial["error"]


def test_full_access_alone_never_reaches_a_federated_tool(home):
    """A full_access holder must not gain unbounded new surface the instant a
    server appears on disk — Decision 2's caller-grant-alone failure mode."""
    _manifest(home, "caller", ["full_access"])
    denial = federation_egress.egress_denial("caller", SERVER_ID, "echo")
    assert denial is not None
    assert "net_denied" in denial["error"] or "tool_denied" in denial["error"]


def test_denied_when_server_is_not_ratified(home):
    """The manifest grant alone is never sufficient — the operator's
    ratification ceiling must also agree (Decision 2)."""
    _manifest(home, "caller", [
        gate.MCP_FEDERATION_PERMISSION,
        gate.federated_tool_permission(SERVER_ID, "echo"),
    ])
    denial = federation_egress.egress_denial("caller", SERVER_ID, "echo")
    assert denial is not None
    assert "server_denied" in denial["error"]


def test_denied_without_consent_federation(home, monkeypatch):
    _ratify()
    _manifest(home, "caller", [
        gate.MCP_FEDERATION_PERMISSION,
        gate.federated_tool_permission(SERVER_ID, "echo"),
    ])
    denial = federation_egress.egress_denial("caller", SERVER_ID, "echo")
    assert denial is not None
    assert "consent_denied" in denial["error"]


def test_denied_without_lease(home, monkeypatch):
    """Unknown stdio tools stay lease-gated (fail closed)."""
    _ratify()
    _manifest(home, "caller", [
        gate.MCP_FEDERATION_PERMISSION,
        gate.federated_tool_permission(SERVER_ID, "echo"),
    ])
    monkeypatch.setattr("willow_mcp.consent.federation_permitted", lambda: True)
    denial = federation_egress.egress_denial("caller", SERVER_ID, "echo")
    assert denial is not None
    assert "lease_denied" in denial["error"]


def test_loopback_stdio_tool_granted_without_lease(home, monkeypatch):
    _ratify()
    _manifest(home, "caller", [
        gate.MCP_FEDERATION_PERMISSION,
        gate.federated_tool_permission(SERVER_ID, "corpus_host_card"),
    ])
    monkeypatch.setattr("willow_mcp.consent.federation_permitted", lambda: True)
    assert federation_egress.egress_denial(
        "caller", SERVER_ID, "corpus_host_card") is None


def test_net_bearing_stdio_tool_denied_without_lease(home, monkeypatch):
    _ratify()
    _manifest(home, "caller", [
        gate.MCP_FEDERATION_PERMISSION,
        gate.federated_tool_permission(SERVER_ID, "corpus_web_search"),
    ])
    monkeypatch.setattr("willow_mcp.consent.federation_permitted", lambda: True)
    denial = federation_egress.egress_denial(
        "caller", SERVER_ID, "corpus_web_search")
    assert denial is not None
    assert "lease_denied" in denial["error"]
    assert "leaves the box" in denial["error"]


def test_http_downstream_denied_without_lease(home, monkeypatch):
    spec = mf.McpServerSpec(
        id="remote-srv", name="remote", command="",
        transport="streamable-http", url="https://example.com/mcp",
    )
    mf.ratify(spec, ratified_by="operator", reason="test")
    remote_id = spec.id
    _manifest(home, "caller", [
        gate.MCP_FEDERATION_PERMISSION,
        gate.federated_tool_permission(remote_id, "echo"),
    ])
    monkeypatch.setattr("willow_mcp.consent.federation_permitted", lambda: True)
    denial = federation_egress.egress_denial("caller", remote_id, "echo")
    assert denial is not None
    assert "lease_denied" in denial["error"]


def test_granted_when_every_key_holds(home, monkeypatch):
    from willow_mcp import lease

    _ratify()
    _manifest(home, "caller", [
        gate.MCP_FEDERATION_PERMISSION,
        gate.federated_tool_permission(SERVER_ID, "echo"),
    ])
    monkeypatch.setattr("willow_mcp.consent.federation_permitted", lambda: True)
    lease.grant("caller", 1800, issuer="operator", reason="test")
    assert federation_egress.egress_denial("caller", SERVER_ID, "echo") is None


def test_loopback_stdio_granted_without_lease_even_when_net_tool_also_granted(
    home, monkeypatch,
):
    _ratify()
    _manifest(home, "caller", [
        gate.MCP_FEDERATION_PERMISSION,
        gate.federated_tool_permission(SERVER_ID, "corpus_search"),
        gate.federated_tool_permission(SERVER_ID, "corpus_web_search"),
    ])
    monkeypatch.setattr("willow_mcp.consent.federation_permitted", lambda: True)
    assert federation_egress.egress_denial(
        "caller", SERVER_ID, "corpus_search") is None


def test_granting_one_tool_does_not_grant_another_on_the_same_server(home, monkeypatch):
    from willow_mcp import lease

    _ratify()
    _manifest(home, "caller", [
        gate.MCP_FEDERATION_PERMISSION,
        gate.federated_tool_permission(SERVER_ID, "echo"),
    ])
    monkeypatch.setattr("willow_mcp.consent.federation_permitted", lambda: True)
    lease.grant("caller", 1800, issuer="operator", reason="test")
    assert federation_egress.egress_denial("caller", SERVER_ID, "echo") is None
    denial = federation_egress.egress_denial("caller", SERVER_ID, "delete_everything")
    assert denial is not None
    assert "tool_denied" in denial["error"]


def test_strict_trust_root_forgeable_denies_even_with_other_keys_granted(home, monkeypatch):
    from willow_mcp import lease

    _ratify()
    _manifest(home, "caller", [
        gate.MCP_FEDERATION_PERMISSION,
        gate.federated_tool_permission(SERVER_ID, "echo"),
    ])
    monkeypatch.setattr("willow_mcp.consent.federation_permitted", lambda: True)
    lease.grant("caller", 1800, issuer="operator", reason="test")
    monkeypatch.setattr("willow_mcp.lease.strict_trust_root", lambda: True)
    monkeypatch.setattr(
        "willow_mcp.lease.self_writable_trust_paths",
        lambda app_id="": [{"key": "manifest", "path": "/wherever"}],
    )
    denial = federation_egress.egress_denial("caller", SERVER_ID, "echo")
    assert denial is not None
    assert "trust_root_denied" in denial["error"]


def test_mcp_federation_permission_is_own_line_never_a_group_member():
    """Structural pin, complementing tests/test_authority_surface.py's
    generic own-line assertion: the constant this module keys on really is
    outside every permission group."""
    for group, tools in gate.PERMISSION_GROUPS.items():
        assert gate.MCP_FEDERATION_PERMISSION not in tools, group
