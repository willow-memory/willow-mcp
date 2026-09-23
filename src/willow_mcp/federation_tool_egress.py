"""Which federated MCP tools need the app-keyed egress lease.

Stdio downstream servers are local organs (same-box subprocess). Only tools that
fan out to the open web / institutional backends, and HTTP federated peers,
reuse ``lease.read_lease`` — see docs/design/federated-mcp-gating.md Decision 3
addendum. The tool list for jeles-corpus must stay aligned with outward hops in
Jeles ``corpus_server.py``; willow-mcp does not import Jeles at runtime.
"""

from __future__ import annotations

from . import gate, mcp_federation

#: Downstream tool names that perform outbound network I/O on a stdio organ.
FEDERATION_NET_BEARING_TOOLS: frozenset[str] = frozenset({
    "corpus_web_search",
    "corpus_institutional_search",
    "corpus_verify_claim",
    "corpus_search_status",
})

#: Stdio tools classified as same-box / SOIL-local — no egress lease. Any other
#: stdio tool name requires a lease until added here (fail closed).
FEDERATION_LOOPBACK_STDIO_TOOLS: frozenset[str] = frozenset({
    "corpus_ask",
    "corpus_search",
    "corpus_get",
    "corpus_list",
    "corpus_put",
    "corpus_gaps",
    "corpus_resolve_gap",
    "corpus_sources",
    "corpus_host_card",
    "corpus_fleet_status",
})


def is_federation_net_bearing_tool(tool: str) -> bool:
    return tool in FEDERATION_NET_BEARING_TOOLS


def federated_call_requires_net_lease(server_id: str, tool: str) -> bool:
    """True when ``federation_egress`` must consult ``lease.read_lease``."""
    entry = mcp_federation.get_ratified(server_id)
    if not entry:
        return True
    spec = mcp_federation.McpServerSpec.from_dict(entry)
    if mcp_federation.is_http_transport(spec.transport):
        return True
    if spec.transport == "stdio":
        return tool not in FEDERATION_LOOPBACK_STDIO_TOOLS
    # Future transports: require a lease until classified.
    return True


def seat_uses_net_egress(app_id: str) -> bool:
    """Whether an inactive lease should surface as a boot blocker for this seat."""
    manifest = gate._load_manifest(app_id)
    if manifest is None:
        return True
    perms: list = manifest.get("permissions") or []
    if not perms:
        return True
    net_caps = {
        gate.NET_PERMISSION,
        gate.INTEGRATION_NET_PERMISSION,
        gate.WEB_NET_PERMISSION,
    }
    for perm in perms:
        if perm in net_caps or perm == "web_read":
            return True
        if not isinstance(perm, str) or not perm.startswith(gate.FEDERATED_PERMISSION_PREFIX):
            continue
        parts = perm.split(":", 2)
        if len(parts) == 3 and is_federation_net_bearing_tool(parts[2]):
            return True
    return False
