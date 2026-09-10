"""Egress gate for willow_web_search / willow_web_fetch (server-process HTTP)."""

from __future__ import annotations

from typing import Optional


def egress_denial(app_id: str) -> Optional[dict]:
    """Three-key check keyed on web_net — mirror of integrations.egress_denial."""
    from . import consent, gate, lease

    if not gate.permitted(app_id, gate.WEB_NET_PERMISSION):
        return {"error": (
            f"net_denied: open-web tools require the '{gate.WEB_NET_PERMISSION}' "
            f"permission in this app's manifest ($WILLOW_HOME/mcp_apps/"
            f"{app_id or '<app_id>'}/manifest.json). It is not granted by "
            f"'{gate.NET_PERMISSION}', '{gate.INTEGRATION_NET_PERMISSION}', "
            "integration_call, or full_access — egress is granted on its own line.")}

    if not consent.internet_permitted():
        return {"error": (
            "consent_denied: open-web tools also require the operator's standing "
            f"'consent.internet' in {consent.settings_path()}. This app holds "
            f"'{gate.WEB_NET_PERMISSION}', but egress is switched off (or the "
            "consent policy could not be read, which denies).")}

    lease_state = lease.read_lease(app_id)
    if lease_state["status"] != "active":
        from . import gate_request

        return {"error": (
            f"lease_denied: open-web tools require an unexpired egress lease for "
            f"'{app_id}' (status: {lease_state['status']}"
            + (f" — {lease_state['error']}" if lease_state.get("error") else "")
            + "). Leases are issued only by the operator via `willow-mcp grant-net "
            f"{app_id or '<app_id>'} --ttl 30m --reason ...` and they expire. "
            "No MCP tool can mint one."
            + gate_request.note_for_lease_denial(
                app_id, reason="open-web tools were refused for want of a lease"))}

    if lease.strict_trust_root():
        forgeable = lease.self_writable_trust_paths(app_id)
        if forgeable:
            return {"error": (
                "trust_root_denied: WILLOW_MCP_STRICT_TRUST_ROOT is set, but this "
                "process can write the very keys that authorize it: "
                + ", ".join(f"{f['key']} ({f['path']})" for f in forgeable)
                + ". Chown these to a uid the agent does not run as.")}
    return None


def egress_status(app_id: str) -> dict:
    """Read-only diagnostic: all four keys of the web_net egress gate (#287).

    `egress_denial` above stops at the first closed lock — the right shape for
    a gate, wrong shape for a diagnostic, where an operator debugging "why is
    egress still denied" wants every key at once instead of fixing one and
    re-running to discover the next. This reads the exact same primitives
    `egress_denial` checks (`gate.permitted`, `consent.internet_permitted`,
    `lease.read_lease`, `lease.strict_trust_root`) in the same order, so the
    two can never silently drift apart — a key `egress_denial` would deny is
    always the same key this reports ungranted.

    Purely a read: it authorizes nothing and writes nothing. Never raises —
    every sub-check it calls is itself fail-closed and exception-free.
    """
    from . import consent, gate, lease

    manifest_granted = gate.permitted(app_id, gate.WEB_NET_PERMISSION)
    consent_granted = consent.internet_permitted()
    lease_state = lease.read_lease(app_id)
    lease_granted = lease_state["status"] == "active"
    strict = lease.strict_trust_root()
    forgeable = lease.self_writable_trust_paths(app_id)
    # Strict mode off ⇒ this key never blocks (it is informational until an
    # operator opts in). Strict mode on ⇒ it only blocks if the keys it would
    # check are actually forgeable by this process — mirrors egress_denial.
    trust_root_ok = not (strict and forgeable)

    return {
        "app_id": app_id,
        "egress_permitted": (
            manifest_granted and consent_granted and lease_granted and trust_root_ok
        ),
        "keys": {
            "manifest_permission": {
                "granted": manifest_granted,
                "permission": gate.WEB_NET_PERMISSION,
                "path": f"mcp_apps/{app_id}/manifest.json",
                "cli": f"willow-mcp allow-permission {app_id} {gate.WEB_NET_PERMISSION}",
            },
            "operator_consent": {
                "granted": consent_granted,
                "path": str(consent.settings_path()),
                "cli": "willow-mcp consent set internet true",
            },
            "egress_lease": {
                "granted": lease_granted,
                "status": lease_state["status"],
                "expires_at": lease_state.get("expires_at"),
                "remaining_seconds": lease_state.get("remaining_seconds"),
                "error": lease_state.get("error"),
                "cli": f"willow-mcp grant-net {app_id} --ttl 30m --reason ...",
            },
            "strict_trust_root": {
                "enabled": strict,
                "ok": trust_root_ok,
                "forgeable": forgeable,
                "cli": "willow-mcp harden-trust-root" if forgeable else None,
            },
        },
    }
