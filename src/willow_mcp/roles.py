"""Canonical fleet roles — loader for specialist registry.

Identity, mandate, permissions: docs/design/specialist-registry.md
Tool policy: docs/design/permissions-matrix.md
"""

from __future__ import annotations

from .registry import iter_registry_rows, load_registry

VALID_STATUSES = frozenset({
    "pending", "working", "complete", "verified", "cleared", "closed", "failed",
    # Terminal: the orchestrator retired the packet (dispatch_withdraw, gap
    # afa515539c0a). Never accepted, never closed, never listed as pending.
    "withdrawn",
})


def _row_as_role_info(row: dict) -> dict:
    return {
        "title": row.get("display_name") or row.get("agent_id", ""),
        "job": row.get("job", ""),
        "not": row.get("not_job", ""),
        "allow_tools": list(row.get("permissions") or []),
        "deny_tools": list(row.get("deny_tools") or []),
    }


def role_info(role: str) -> dict | None:
    """Lookup by agent_id or primary role tag."""
    key = (role or "").strip().lower()
    if not key:
        return None
    for row in iter_registry_rows(load_registry()):
        agent_id = str(row.get("agent_id", "")).lower()
        primary = str(row.get("role", "")).lower()
        roles = [str(r).lower() for r in (row.get("roles") or [])]
        if key in (agent_id, primary) or key in roles:
            return _row_as_role_info(row)
    return None
