"""Advertised MCP tool surface — discovery, not call ACL.

``tools/list`` historically returned every registered tool. Manifest /
``gate.permitted`` only constrained *calls*, so a willow desk with
``full_access`` advertised ~130 verbs an agent cannot usefully hold.

This module owns the Glama-shaped **desk core** preset and the resolver
that ``AdvertiseFilterMiddleware`` uses to shrink ``tools/list``. Calling a
non-advertised but permitted tool still succeeds (advertise ≠ ACL). Escape
hatches: ``WILLOW_MCP_ADVERTISE=full``, or manifest ``\"advertise\": \"full\"``.
"""

from __future__ import annotations

import logging
import os
from typing import Iterable, Optional

from . import gate

logger = logging.getLogger(__name__)

#: Env override. ``full`` forces the honest call-ACL listing for any seat.
ADVERTISE_ENV = "WILLOW_MCP_ADVERTISE"

#: Manifest key: ``desk_core`` | ``full`` | ``manifest`` (default per seat).
ADVERTISE_MANIFEST_KEY = "advertise"

#: Curated desk discovery set — target ≤50. Seeded for the human
#: orchestrator seat; intersected with ``visible_tools`` so a denied tool
#: never appears just because it is named here.
DESK_CORE: frozenset[str] = frozenset(
    {
        # session / dispatch / handoff
        "session_enter",
        "session_handoff_write",
        "session_read",
        "dispatch_list",
        "dispatch_read",
        "dispatch_send",
        "handoff_read",
        "handoff_write_v4",
        "verify_handoff",
        "agent_clear",
        "specialist_list",
        "specialist_get",
        # fleet / frank
        "fleet_health",
        "fleet_status",
        "frank_read",
        "frank_verify",
        # knowledge / store
        "knowledge_search",
        "kb_ingest",
        "kb_at",
        "store_get",
        "store_search",
        "store_put",
        "store_list",
        "store_update",
        # backlog / human loop / tasks
        "gap_list",
        "gap_log",
        "human_required_list",
        "human_required_resolve",
        "task_submit",
        "task_status",
        "task_list",
        # governance authoring
        "decision_propose",
        "envelope_list",
        "envelope_pending_read",
        "envelope_propose",
        "envelope_ratify",
        "envelope_reject",
        # nest / tool oracle / diagnostics
        "nest_intake_queue",
        "nest_status",
        "nestor_tool_route",
        "nestor_tool_pending",
        "diagnostic_summary",
        "env_check",
        "receipts_tail",
        "whoami",
        # web (MCP path; native web tools redirect here)
        "willow_web_search",
        "willow_web_fetch",
        # brokered git (willows-bot) — desk initiates; broker holds the key
        "git_push_execute",
        "pr_open_execute",
    }
)

assert len(DESK_CORE) <= 50, f"DESK_CORE has {len(DESK_CORE)} tools; Glama target is ≤50"


def _env_advertise_mode() -> Optional[str]:
    raw = (os.environ.get(ADVERTISE_ENV) or "").strip().lower()
    return raw or None


def _manifest_advertise_mode(app_id: str) -> Optional[str]:
    manifest = gate._load_manifest(app_id)
    if not manifest:
        return None
    raw = manifest.get(ADVERTISE_MANIFEST_KEY)
    if raw is None:
        return None
    if not isinstance(raw, str):
        logger.warning(
            "advertise: malformed %r for %r — ignoring", ADVERTISE_MANIFEST_KEY, app_id
        )
        return None
    return raw.strip().lower() or None


def resolve_advertise_mode(app_id: str) -> str:
    """Return ``full``, ``desk_core``, or ``manifest``.

    Precedence: ``WILLOW_MCP_ADVERTISE`` env → manifest ``advertise`` →
    default ``desk_core`` for ``willow``, else ``manifest`` (honest ACL).
    """
    env_mode = _env_advertise_mode()
    if env_mode in ("full", "desk_core", "manifest"):
        return env_mode
    man_mode = _manifest_advertise_mode(app_id)
    if man_mode in ("full", "desk_core", "manifest"):
        return man_mode
    if (app_id or "").strip().lower() == "willow":
        return "desk_core"
    return "manifest"


def advertised_tools(
    app_id: str, tool_gate_names: dict[str, str]
) -> tuple[list[str], str]:
    """``(sorted tool names to advertise, mode used)``.

    For ``desk_core``, the set is ``DESK_CORE ∩ visible_tools`` plus any
    ``DESK_CORE`` name absent from the gate catalogue (ungated tools such as
    ``whoami`` / ``diagnostic_summary``).

    For ``full``, returns an empty list and mode ``full`` — the middleware
    skips filtering (advertise the entire registered surface).

    For ``manifest``, returns ``visible_tools`` (honest call ACL); the
    middleware also keeps ungated tools that are not in the catalogue.
    """
    mode = resolve_advertise_mode(app_id)
    if mode == "full":
        return [], "full"
    allowed, _orphans = gate.visible_tools(app_id, tool_gate_names)
    if mode == "manifest":
        return list(allowed), "manifest"
    core: set[str] = set(DESK_CORE.intersection(allowed))
    for name in DESK_CORE:
        if name not in tool_gate_names:
            core.add(name)
    return sorted(core), "desk_core"


def filter_tool_iterable(
    tools: Iterable[object], allowed_names: set[str]
) -> list[object]:
    """Keep tools whose ``.name`` (or ``[\"name\"]``) is in ``allowed_names``."""
    kept: list[object] = []
    for tool in tools:
        name = getattr(tool, "name", None)
        if name is None and isinstance(tool, dict):
            name = tool.get("name")
        if name in allowed_names:
            kept.append(tool)
    return kept
