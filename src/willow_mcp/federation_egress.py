"""Egress gate for a federated MCP call — willow-mcp calling a tool on a
downstream MCP server it spawns itself.

Mirrors `web_egress.egress_denial`, keyed on `mcp_federation` instead of
`web_net`, plus the two checks that lane does not need: the caller's
per-downstream-tool grant, and the operator's ratification ceiling
(docs/design/federated-mcp-gating.md Decision 2 — a federated call is
authorized only at the intersection of BOTH: the caller's manifest grant
alone would let a `full_access` holder gain unbounded new surface the instant
a server appears on disk, and the ratified server's advertised tools alone
would make willow-mcp a confused deputy laundering its own uid into a call the
caller could never make directly). Every check reads from disk at call time,
never a value cached from `connect_server` — the same "a lease on disk owned
elsewhere is a fact; a cached decision is a claim" doctrine `web_fetch.
validate_hop` and `core/egress_authority.py` already apply to redirects and
task submission (Decision 5).
"""

from __future__ import annotations

from typing import Optional


def egress_denial(app_id: str, server_id: str, tool: str) -> Optional[dict]:
    """None if all checks pass; otherwise a denial dict naming the first
    closed lock, in the order an operator would want to fix them."""
    from . import consent, gate, lease, mcp_federation

    if not gate.permitted(app_id, gate.MCP_FEDERATION_PERMISSION):
        return {"error": (
            f"net_denied: federated MCP calls require the "
            f"'{gate.MCP_FEDERATION_PERMISSION}' permission in this app's "
            f"manifest ($WILLOW_HOME/mcp_apps/{app_id or '<app_id>'}/"
            "manifest.json). It is not granted by 'task_net', "
            "'integration_net', 'web_net', 'federation_call', or "
            "'full_access' — spawning a downstream MCP server is a fourth "
            "egress class, granted on its own line.")}

    perm = gate.federated_tool_permission(server_id, tool)
    if not gate.permitted(app_id, perm):
        return {"error": (
            f"tool_denied: this app's manifest does not grant {perm!r}. A "
            f"federated call is gated per downstream tool, not per server — "
            f"holding '{gate.MCP_FEDERATION_PERMISSION}' authorizes spawning "
            "a server, not calling any tool it happens to advertise. Add the "
            "namespaced permission to grant this specific tool.")}

    if not mcp_federation.is_ratified(server_id):
        return {"error": (
            f"server_denied: server_id {server_id!r} is not in the ratified "
            f"registry ({mcp_federation.registry_path()}). Discovery is "
            "inventory-only; connecting requires an operator to ratify the "
            "server first (mcp_federation.ratify — CLI/operator only, no MCP "
            "tool can do this). A caller's manifest grant alone is never "
            "sufficient — the operator's ceiling must agree too.")}

    if not consent.federation_permitted():
        return {"error": (
            "consent_denied: federated MCP calls also require the operator's "
            f"standing 'consent.federation' in {consent.settings_path()}. "
            f"This app holds '{gate.MCP_FEDERATION_PERMISSION}' and a grant "
            "for this tool, but egress is switched off (or the consent "
            "policy could not be read, which denies).")}

    lease_state = lease.read_lease(app_id)
    if lease_state["status"] != "active":
        from . import gate_request

        return {"error": (
            f"lease_denied: federated MCP calls require an unexpired egress "
            f"lease for '{app_id}' (status: {lease_state['status']}"
            + (f" — {lease_state['error']}" if lease_state.get("error") else "")
            + "). Leases are issued only by the operator via `willow-mcp "
            f"grant-net {app_id or '<app_id>'} --ttl 30m --reason ...` and "
            "they expire. No MCP tool can mint one."
            + gate_request.note_for_lease_denial(
                app_id, reason="federated MCP calls were refused for want of a lease"))}

    if lease.strict_trust_root():
        forgeable = lease.self_writable_trust_paths(app_id)
        if forgeable:
            return {"error": (
                "trust_root_denied: WILLOW_MCP_STRICT_TRUST_ROOT is set, but "
                "this process can write the very keys that authorize it: "
                + ", ".join(f"{f['key']} ({f['path']})" for f in forgeable)
                + ". Chown these to a uid the agent does not run as.")}
    return None
