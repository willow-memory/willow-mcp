"""
willow_mcp/grove_tools.py — Grove MCP tools: the fleet's voice for agents.

willow-2.0's `sap/grove_tools.py` gave AI agents a messaging path into Grove
(the fleet's `grove.*` Postgres tables) by importing `grove_db`/`grove_reader`
over PYTHONPATH from the sibling grove repo. As willow-2.0 is decommissioned,
this module is the agent-side successor: the same 17 tools canonical Grove
exposed to agents (`safe-app-willow-grove/grove/mcp_local.py`), plus 3
fleet-awareness reads (`grove_agents`, `grove_fleet_status`,
`grove_human_required`) that repo also carries — 20 total, 13 read + 7 write.

Register all tools on a FastMCP instance by calling `register(mcp)`, the same
pattern `willow_mcp.mai.tools` uses: every tool takes `app_id` and checks the
manifest gate itself before doing anything (`grove_read`/`grove_write` in
`gate.PERMISSION_GROUPS`) — registration only decides the tools exist,
authorization is per-app, exactly like mai's `#161` posture.

Data access is `willow_mcp.grove` (self-contained, ported from the canonical
`grove_db.py`/`grove_reader.py` — see that module's header for what changed
and why, including the DB-name trap: grove lives in `willow_20`, not
willow-mcp's default `willow` database).

`sender` for every write tool defaults to the calling agent's `grove_sender`
resolved from the specialist registry (`willow_mcp.registry.specialist_row`),
never the literal "Auto" the canonical tools defaulted to — an agent posts as
itself. An empty/omitted `sender` falls through to the registry lookup, and
an app_id with no registry row falls through to the app_id itself.

Posting as a *different* identity than the caller's own resolved
`grove_sender` — e.g. an orchestrator relaying on a specialist's behalf — now
requires the `grove_relay` capability (`gate.GROVE_RELAY_PERMISSION`) in the
caller's manifest. Without it, a mismatched `sender` is refused before any
DB write: every write tool returns `{"error": "sender_forbidden", "detail":
...}` instead of silently posting as the requested identity. `grove_write`
alone never confers relay — it is granted on its own line, deliberately kept
out of `grove_write`/`full_access`, so any app_id can be impersonated only by
an app a human operator has explicitly trusted to relay.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Optional

from . import gate
from . import grove
from .db import get_pg

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer


# MCP tool annotations — shared definition in annotations.py.
from willow_mcp.annotations import ANNO_READ as _ANNO_READ, ANNO_WRITE as _ANNO_WRITE


# ── gate + identity helpers ──────────────────────────────────────────────────

def _gate_denied(app_id: str, tool_name: str) -> Optional[str]:
    """Manifest-gate check for the Grove surface. Fail-closed: a missing or
    empty app_id denies — these tools reach the fleet's shared Postgres, so
    an anonymous call is exactly the hole every other willow-mcp tool closes
    via `app_id` + manifest."""
    if not app_id:
        return (f"gate denied: {tool_name} requires app_id — Grove tools are "
                "manifest-gated (grove_read/grove_write)")
    if not gate.permitted(app_id, tool_name):
        return (f"gate denied: '{app_id}' not permitted for '{tool_name}'. "
                "Grant grove_read/grove_write in the app manifest.")
    return None


def resolve_grove_sender(app_id: str) -> str:
    """The calling agent's Grove display name: registry `grove_sender` if a
    specialist row exists for `app_id`, else the row's own `agent_id`, else
    `app_id` itself. Never "Auto" — see module docstring."""
    try:
        from . import registry as specialist_registry
        row = specialist_registry.specialist_row(app_id)
    except Exception:
        row = None
    if row:
        name = str(row.get("grove_sender") or row.get("agent_id") or "").strip()
        if name:
            return name
    return app_id


def _sender_forbidden(sender: str, caller: str) -> dict:
    return {
        "error": "sender_forbidden",
        "detail": (
            f"posting as '{sender}' requires the grove_relay permission; "
            f"you are '{caller}'"
        ),
    }


def _resolve_sender_checked(app_id: str, sender: str = "") -> tuple[Optional[str], Optional[dict]]:
    """Resolve the Grove identity a write should post as, enforcing the
    sender lock (FIX 1, docs/design/permissions-matrix.md).

    A caller always gets to post as itself for free: an empty/omitted
    `sender`, or one that already equals the caller's own resolved
    `grove_sender`, resolves with no extra check. Posting as a genuinely
    different identity is allowed only when the app manifest holds the
    `grove_relay` capability (`gate.GROVE_RELAY_PERMISSION`); otherwise it is
    forbidden.

    Returns `(resolved_sender, None)` on success, or `(None, error_dict)`
    when the override is forbidden. Every write tool must check the error
    BEFORE issuing any DB write — this function never writes anything
    itself, it only decides who is allowed to write as whom.
    """
    caller = resolve_grove_sender(app_id)
    explicit = (sender or "").strip()
    if not explicit or explicit == caller:
        return caller, None
    if gate.grove_relay_permitted(app_id):
        return explicit, None
    return None, _sender_forbidden(explicit, caller)


def _pg_unavailable() -> dict:
    from .db import last_pg_error
    return {
        "error": "postgres_unavailable",
        "detail": (
            "Postgres is not reachable — grove_* tools degrade until it's "
            "back. Run diagnostic_summary for current status, or start your "
            "Postgres cluster and retry."
        ),
        # What the attempt actually said, rather than a guess at it.
        "reason": last_pg_error() or "no reason recorded (no connection attempt this process)",
    }


def _grove_error(exc: "grove.GroveUnavailable") -> dict:
    return {"error": "grove_unavailable", "detail": exc.detail}


def _msgs_to_dicts(msgs: list[dict]) -> list[dict]:
    return [
        {
            "id": m["id"],
            "sender": m["sender"],
            "content": m["content"],
            "reply_to_id": m.get("reply_to_id"),
            "to_agent": m.get("to_agent", grove.BUS_BROADCAST),
            "bus_type": m.get("bus_type", "EVENT"),
            "priority": m.get("priority", 3),
            "correlation_id": m.get("correlation_id"),
            "created_at": grove.jsonify(m.get("created_at")),
            **({"depth": m["depth"]} if "depth" in m else {}),
        }
        for m in msgs
    ]


# ── Activation rail: post a dispatch wake ───────────────────────────────────
#
# Grove activation rail, slice 1 (surface-only): dispatch_send writes a
# packet to disk but has never told the target seat's Grove bus listener
# (ratatosk's BusListener/SeatDaemon) that a packet is waiting — a dispatched
# seat only ever noticed by polling. This is the in-process poster
# dispatch.dispatch_send calls after the packet write: it builds a real
# ratatosk Intent.WAKE envelope and posts it to the target's own Grove
# channel, the SAME channel convention grove_tools/grove_listen already use
# for a seat's dedicated inbox (`#<agent>` — see grove_inbox's docstring and
# grove_listen.classify's INBOX branch). A per-seat SeatDaemon (willow_mcp's
# seat_daemon.py, built with node=<that app_id>) polls exactly that channel,
# so an envelope addressed `to=<to_app>` on channel `<to_app>` is picked up
# on the next poll tick and handed to BusListener.validate_envelope, which
# this shape is built to satisfy: v=PROTOCOL_VERSION, a non-empty prompt,
# `to` matching the seat's node (case-insensitively), a fresh nonce (minted
# by build_envelope), an unexpired `expires_at`, and WAKE is not a
# HIGH_RISK_INTENT so no `requires_confirm` is demanded.
#
# Best-effort, exactly like dispatch._pg_mirror_upsert: this NEVER raises.
# ratatosk missing, the gate denying the sender, Postgres being unreachable,
# or any other failure is reported back as `{"posted": False, "reason": ...}`
# for logging, and dispatch_send's return contract is unaffected either way
# — the filesystem packet is already written and stays canonical.
def post_wake_envelope(
    from_app: str,
    to_app: str,
    *,
    dispatch_id: str,
    summary: str = "",
    reply_to: str = "",
    trace_id: str = "",
) -> dict:
    """Post an Intent.WAKE envelope to `to_app`'s Grove channel.

    `trace_id` defaults to a value derived from `dispatch_id` so a wake's
    trace can be tied back to the packet even when the caller does not pass
    one explicitly — `activation.build_activate` logs this trace verbatim.
    `reply_to` (typically the dispatch's own `reply_to` field, e.g. the
    orchestrator) decides which channel the seat's BusListener posts its
    activation acknowledgement to; it defaults to the dispatching app's own
    channel when omitted.
    """
    try:
        from ratatosk.protocol.envelope import build_envelope, Capability, Intent
    except ImportError as exc:
        return {"posted": False, "reason": f"ratatosk unavailable: {exc}"}

    # Cheap check first — no DB connection is opened for a sender the
    # manifest gate would refuse anyway.
    if not gate.permitted(from_app, "grove_bus_send"):
        return {"posted": False, "reason": "gate denied grove_bus_send for sender"}

    pg = get_pg()
    if not pg:
        return {"posted": False, "reason": "postgres unavailable"}

    who = resolve_grove_sender(from_app)
    target_channel = grove.normalize_channel_name(to_app)
    reply_channel = grove.normalize_channel_name(reply_to or from_app)
    envelope = build_envelope(
        to=to_app,
        prompt=(summary or "").strip() or f"dispatch {dispatch_id} is waiting for you",
        from_agent=who,
        intent=Intent.WAKE.value,
        reply_channel=reply_channel,
        capabilities=[Capability.WAKE.value],
        trace_id=trace_id or f"tr-{dispatch_id.lower()}",
        extra={"dispatch_id": dispatch_id},
    )
    try:
        channels = grove.list_channels(pg)
        ch = grove.find_channel_in(channels, target_channel)
        if not ch:
            ch = grove.create_channel(pg, name=target_channel, channel_type="group")
        msg = grove.bus_send(
            pg,
            channel_id=ch["id"],
            sender=who,
            content=envelope.to_json(),
            to_agent=to_app,
            bus_type="COMMAND",
            priority=1,
        )
    except grove.GroveUnavailable as e:
        return {"posted": False, "reason": f"grove unavailable: {e.detail}"}
    except Exception as exc:  # noqa: BLE001 - best-effort, must never raise
        return {"posted": False, "reason": str(exc)}
    return {
        "posted": True,
        "channel": ch["name"],
        "message_id": msg["id"],
        "trace_id": envelope.trace_id,
    }


# ── Activation rail: the in-process mcp_call shim ───────────────────────────
#
# ratatosk's BusListener/SeatDaemon are written against an `mcp_call(name,
# params) -> result` transport — normally a real MCP round-trip out to a
# *separate* willow-mcp server process. willow_mcp.seat_daemon runs a
# SeatDaemon INSIDE willow-mcp's own process, so there is no second
# transport to round-trip through: this shim answers the same four tool
# calls BusListener/SeatDaemon actually make (`grove_get_history`,
# `grove_heartbeat`, `grove_send_message`, `grove_ack` — see
# `ratatosk.listener.BusListener.fetch_messages`/`emit_heartbeat`/
# `process_message`/`run_once`) by calling straight through to the same
# `grove.py` functions and gate checks the registered MCP tools above use,
# for ONE fixed `app_id` baked in at build time.
def _shim_resolve_sender(app_id: str, raw_sender: str) -> tuple[Optional[str], Optional[dict]]:
    """Resolve the identity the SHIM's own automated posts (heartbeat,
    wake-ack, any chat reply `BusListener`'s default handlers produce) are
    stored under.

    This is deliberately NOT `_resolve_sender_checked` + `resolve_grove_sender`
    (the friendly persona display name a REAL, live agent session's own
    Grove tool call resolves to). Two identities are in play here that a
    naive "always show the nice name" rule conflates:

    * `node` — `willow_mcp.seat_daemon.build_full_seat_daemon` sets this to
      the seat's raw `app_id`. It is what `validate_envelope` checks a
      WAKE's `to` field against, what casual `"app_id: message"` chat
      addressing resolves to, AND — the part that matters here — what
      ratatosk's own `BusListener.is_own_post` compares a fetched message's
      stored `sender` against, to decide "is this my own post talking to
      itself".
    * the resolved `grove_sender` persona name — what a live human/agent
      MCP session's OWN tool calls post as, via the registered
      `grove_send_message`/`grove_heartbeat` tools below (unchanged by this
      function).

    An earlier fix made this shim's automated posts resolve to the persona
    name too (to stop them being refused as `sender_forbidden` — a real
    seat's persona differs from its `app_id` in the normal case). That
    closed one bug and opened a worse one: once the persona-named reply
    landed on the bus, it no longer matched `node` (`app_id`), so
    `is_own_post` stopped recognizing it — the seat started answering its
    own posts, with no error and no natural stop (nonce-based replay
    detection cannot catch a self-authored reply either; it mints a fresh
    nonce on every parse). See docs/design/grove-activation-rail.md's
    "self-post loop closure" section.

    The fix that closes BOTH bugs at once: this shim's own automated posts
    are stored under `app_id` (matching `node`) — not the persona, and not
    refused either. A sender that is empty or already equals `app_id` is
    free (no `grove_relay` needed) and resolves to `app_id` itself. A
    genuinely different sender still requires `grove_relay`, exactly like
    `_resolve_sender_checked`, and — unlike the self case — is passed
    through UNRESOLVED: relaying on someone else's behalf is not this
    shim's identity to rename.
    """
    explicit = (raw_sender or "").strip()
    if not explicit or explicit.lower() == app_id.strip().lower():
        return app_id, None
    if gate.grove_relay_permitted(app_id):
        return explicit, None
    return None, _sender_forbidden(explicit, app_id)


def build_mcp_call(app_id: str) -> Callable[[str, dict], Any]:
    """Build an in-process `mcp_call` for `app_id`'s SeatDaemon.

    `params["app_id"]`, if a caller sets it, is ignored — this shim always
    acts as the `app_id` it was built for, never whatever a message
    payload claims. That is the same posture as every real Grove tool:
    identity comes from the manifest-checked caller, never from request
    data.
    """

    def _call(tool_name: str, params: Optional[dict] = None) -> Any:
        params = params or {}

        if tool_name == "grove_get_history":
            denied = _gate_denied(app_id, "grove_get_history")
            if denied:
                return {"error": denied}
            pg = get_pg()
            if not pg:
                return _pg_unavailable()
            try:
                channels = grove.list_channels(pg)
                ch = grove.find_channel_in(channels, str(params.get("channel_name", "")))
                if not ch:
                    return []
                limit = min(int(params.get("limit") or 50), 200)
                msgs = grove.get_history(pg, ch["id"], limit=limit)
                return _msgs_to_dicts(list(reversed(msgs)))
            except grove.GroveUnavailable as e:
                return _grove_error(e)

        if tool_name == "grove_heartbeat":
            denied = _gate_denied(app_id, "grove_heartbeat")
            if denied:
                return {"error": denied}
            pg = get_pg()
            if not pg:
                return _pg_unavailable()
            who, sender_err = _shim_resolve_sender(app_id, str(params.get("sender", "")))
            if sender_err:
                return sender_err
            try:
                channels = grove.list_channels(pg)
                ch = grove.find_channel_in(channels, "general")
                if not ch:
                    ch = grove.create_channel(pg, name="general", channel_type="group")
                msg = grove.bus_send(
                    pg, channel_id=ch["id"], sender=who, content=f"{who} online",
                    bus_type="HEARTBEAT", priority=6, to_agent=grove.BUS_BROADCAST,
                )
            except grove.GroveUnavailable as e:
                return _grove_error(e)
            return {"id": msg["id"], "sender": who, "bus_type": "HEARTBEAT"}

        if tool_name == "grove_send_message":
            denied = _gate_denied(app_id, "grove_send_message")
            if denied:
                return {"error": denied}
            pg = get_pg()
            if not pg:
                return _pg_unavailable()
            who, sender_err = _shim_resolve_sender(app_id, str(params.get("sender", "")))
            if sender_err:
                return sender_err
            try:
                channel_name = str(params.get("channel_name", ""))
                channels = grove.list_channels(pg)
                ch = grove.find_channel_in(channels, channel_name)
                if not ch:
                    ch = grove.create_channel(pg, name=channel_name, channel_type="group")
                msg = grove.send_message(
                    pg, channel_id=ch["id"], sender=who, content=str(params.get("content", "")),
                )
                if "error" in msg:
                    return msg
            except grove.GroveUnavailable as e:
                return _grove_error(e)
            return {"id": msg["id"], "channel": ch["name"], "sent": True}

        if tool_name == "grove_ack":
            denied = _gate_denied(app_id, "grove_ack")
            if denied:
                return {"error": denied}
            pg = get_pg()
            if not pg:
                return _pg_unavailable()
            try:
                message_id = int(params.get("message_id") or 0)
                grove.clear_flag(pg, message_id=message_id, sender="__system__", flag="needs-reply")
            except grove.GroveUnavailable as e:
                return _grove_error(e)
            return {"acked": message_id}

        return {"error": f"unsupported tool for in-process shim: {tool_name!r}"}

    return _call


# ── Tool registration ─────────────────────────────────────────────────────────

def register(mcp: "MCPServer") -> None:
    """Register all 20 Grove tools on the provided FastMCP instance."""

    # ── Reads (13) ──────────────────────────────────────────────────────────

    @mcp.tool(annotations=_ANNO_READ)
    def grove_list_channels(app_id: str = "") -> list[dict]:
        """List all active Grove channels (name, type, description). Requires
        grove_read."""
        denied = _gate_denied(app_id, "grove_list_channels")
        if denied:
            return [{"error": denied}]
        pg = get_pg()
        if not pg:
            return [_pg_unavailable()]
        try:
            rows = grove.list_channels(pg)
        except grove.GroveUnavailable as e:
            return [_grove_error(e)]
        return [
            {"id": r["id"], "name": r["name"], "type": r["channel_type"],
             "description": r.get("description")}
            for r in rows
        ]

    @mcp.tool(annotations=_ANNO_READ)
    def grove_get_history(channel_name: str, app_id: str = "",
                           limit: int = 50, since_id: int = 0) -> list[dict]:
        """
        Get message history from a Grove channel. Requires grove_read.

        Args:
            channel_name: Exact channel name (use grove_list_channels to find names).
            limit: Number of messages to return (max 200, default 50).
            since_id: If > 0, return only messages with id greater than this value,
                      oldest first. Use the last returned message's id as your next
                      since_id to poll for new messages without re-fetching history.
        """
        denied = _gate_denied(app_id, "grove_get_history")
        if denied:
            return [{"error": denied}]
        pg = get_pg()
        if not pg:
            return [_pg_unavailable()]
        try:
            channels = grove.list_channels(pg)
            ch = grove.find_channel_in(channels, channel_name)
            if not ch:
                return []
            if since_id > 0:
                msgs = grove.get_history(pg, ch["id"], limit=min(limit, 200), since_id=since_id)
            else:
                msgs = grove.get_history(pg, ch["id"], limit=min(limit, 200))
                msgs = list(reversed(msgs))
        except grove.GroveUnavailable as e:
            return [_grove_error(e)]
        return [
            {"id": m["id"], "sender": m["sender"], "content": m["content"],
             "reply_to_id": m.get("reply_to_id"),
             "reply_count": m.get("reply_count", 0),
             "created_at": grove.jsonify(m.get("created_at"))}
            for m in msgs
        ]

    @mcp.tool(annotations=_ANNO_READ)
    def grove_search(query: str, app_id: str = "", channel_name: str = "") -> list[dict]:
        """
        Search Grove messages by content. Requires grove_read.

        Args:
            query: Search term (case-insensitive substring match).
            channel_name: Optional channel to restrict search to.
        """
        denied = _gate_denied(app_id, "grove_search")
        if denied:
            return [{"error": denied}]
        pg = get_pg()
        if not pg:
            return [_pg_unavailable()]
        try:
            channel_id = None
            if channel_name:
                channels = grove.list_channels(pg)
                ch = grove.find_channel_in(channels, channel_name)
                channel_id = ch["id"] if ch else None
            msgs = grove.search_messages(pg, query, channel_id=channel_id)
        except grove.GroveUnavailable as e:
            return [_grove_error(e)]
        return [
            {"sender": m["sender"], "content": m["content"],
             "created_at": grove.jsonify(m.get("created_at"))}
            for m in msgs[:50]
        ]

    @mcp.tool(annotations=_ANNO_READ)
    def grove_watch(channel_name: str, since_id: int, app_id: str = "") -> list[dict]:
        """
        Return any new messages in a channel since since_id. Non-blocking.
        Requires grove_read.

        Args:
            channel_name: Channel to check.
            since_id: Return messages with id greater than this value.
        """
        denied = _gate_denied(app_id, "grove_watch")
        if denied:
            return [{"error": denied}]
        pg = get_pg()
        if not pg:
            return [_pg_unavailable()]
        try:
            channels = grove.list_channels(pg)
            ch = grove.find_channel_in(channels, channel_name)
            if not ch:
                return []
            msgs = grove.get_history(pg, ch["id"], limit=50, since_id=since_id)
        except grove.GroveUnavailable as e:
            return [_grove_error(e)]
        return _msgs_to_dicts(msgs)

    @mcp.tool(annotations=_ANNO_READ)
    def grove_watch_all(cursors: dict, app_id: str = "") -> dict:
        """
        Check multiple channels at once for new messages. Non-blocking.
        Requires grove_read.

        Args:
            cursors: Dict mapping channel_name -> since_id, e.g. {"general": 6, "github": 10}

        Returns a dict mapping channel_name -> list of new messages. Only
        channels with new messages appear in the result.
        """
        denied = _gate_denied(app_id, "grove_watch_all")
        if denied:
            return {"error": denied}
        pg = get_pg()
        if not pg:
            return _pg_unavailable()
        try:
            all_channels = grove.list_channels(pg)
            results: dict[str, Any] = {}
            for ch in all_channels:
                name = ch["name"]
                if name not in cursors:
                    continue
                msgs = grove.get_history(pg, ch["id"], limit=50, since_id=cursors[name])
                if msgs:
                    results[name] = _msgs_to_dicts(msgs)
        except grove.GroveUnavailable as e:
            return _grove_error(e)
        return results

    @mcp.tool(annotations=_ANNO_READ)
    def grove_get_thread(message_id: int, app_id: str = "") -> dict:
        """
        Get a message and all its replies. Requires grove_read.

        Args:
            message_id: ID of the parent message.
        """
        denied = _gate_denied(app_id, "grove_get_thread")
        if denied:
            return {"error": denied}
        pg = get_pg()
        if not pg:
            return _pg_unavailable()
        try:
            parent = grove.get_message(pg, message_id)
            if not parent:
                return {"error": "message not found"}
            replies = grove.get_thread(pg, message_id)
            flags = grove.get_flags(pg, message_id)
        except grove.GroveUnavailable as e:
            return _grove_error(e)
        return {
            "parent": _msgs_to_dicts([parent])[0],
            "flags": grove.jsonify(flags),
            "replies": _msgs_to_dicts(replies),
        }

    @mcp.tool(annotations=_ANNO_READ)
    def grove_bus_receive(agent: str, app_id: str = "", channel_name: str = "",
                           since_id: int = 0) -> list[dict]:
        """
        Fetch bus messages addressed to this agent (or broadcast), ordered by
        priority. Requires grove_read.

        Args:
            agent: Your agent name — receives messages addressed to you or '__all__'.
            channel_name: Optional — restrict to one channel.
            since_id: Only return messages with id greater than this cursor.
        """
        denied = _gate_denied(app_id, "grove_bus_receive")
        if denied:
            return [{"error": denied}]
        pg = get_pg()
        if not pg:
            return [_pg_unavailable()]
        try:
            if channel_name:
                channels = grove.list_channels(pg)
                ch = grove.find_channel_in(channels, channel_name)
                if not ch:
                    return []
                msgs = grove.bus_receive(pg, agent=agent, since_id=since_id)
                msgs = [m for m in msgs if m.get("channel_id") == ch["id"]]
            else:
                msgs = grove.bus_receive(pg, agent=agent, since_id=since_id)
        except grove.GroveUnavailable as e:
            return [_grove_error(e)]
        return _msgs_to_dicts(msgs)

    @mcp.tool(annotations=_ANNO_READ)
    def grove_inbox(app_id: str = "", agent: str = "", since_id: int = 0,
                     limit: int = 35) -> list[dict]:
        """
        Fleet inbox: @mentions plus messages bus-addressed directly to this
        agent, plus the agent's dedicated #<agent> channel. Requires
        grove_read.

        Args:
            agent: Recipient identity; defaults to your resolved grove_sender.
            since_id: Only messages with id greater than this (cursor for polling).
            limit: Merge cap after dedupe-by-id newest-first.
        """
        denied = _gate_denied(app_id, "grove_inbox")
        if denied:
            return [{"error": denied}]
        pg = get_pg()
        if not pg:
            return [_pg_unavailable()]
        who = agent.strip() if agent.strip() else resolve_grove_sender(app_id)
        cap = max(5, min(int(limit), 80))
        try:
            rows = grove.inbox_bundle(pg, who, since_id=max(0, int(since_id)), merge_limit=cap)
        except grove.GroveUnavailable as e:
            return [_grove_error(e)]
        return grove.jsonify(rows)

    @mcp.tool(annotations=_ANNO_READ)
    def grove_flagged(flag: str, app_id: str = "", channel_name: str = "") -> list[dict]:
        """
        List messages carrying a given flag across all channels (or one
        channel). Requires grove_read.

        Args:
            flag: One of: needs-reply, starred, read, urgent, resolved.
            channel_name: Optional — restrict to one channel.
        """
        denied = _gate_denied(app_id, "grove_flagged")
        if denied:
            return [{"error": denied}]
        pg = get_pg()
        if not pg:
            return [_pg_unavailable()]
        try:
            channel_id = None
            if channel_name:
                channels = grove.list_channels(pg)
                ch = grove.find_channel_in(channels, channel_name)
                channel_id = ch["id"] if ch else None
            msgs = grove.get_flagged(pg, flag=flag, channel_id=channel_id)
        except grove.GroveUnavailable as e:
            return [_grove_error(e)]
        return _msgs_to_dicts(msgs)

    @mcp.tool(annotations=_ANNO_READ)
    def grove_get_identity(app_id: str = "") -> dict:
        """
        This agent's own Grove identity, resolved from the specialist
        registry. Requires grove_read.

        Unlike canonical Grove's human/dashboard `grove_get_identity` (which
        returns a u2u LAN address + public key for the human-facing side),
        this is the agent-side identity: your app_id, your resolved
        grove_sender (what you post as), and your registered role/display
        name, if any.
        """
        denied = _gate_denied(app_id, "grove_get_identity")
        if denied:
            return {"error": denied}
        try:
            from . import registry as specialist_registry
            row = specialist_registry.get_specialist(app_id, include_permissions=False)
        except Exception:
            row = None
        return {
            "app_id": app_id,
            "grove_sender": resolve_grove_sender(app_id),
            "display_name": (row or {}).get("display_name", ""),
            "role": (row or {}).get("role", ""),
        }

    @mcp.tool(annotations=_ANNO_READ)
    def grove_agents(app_id: str = "") -> list[dict]:
        """
        List fleet agents by most-recent HEARTBEAT, newest first. Requires
        grove_read.

        Each entry: {sender, last_seen_at (ISO), age_secs}. Use this to see
        who is currently alive in the fleet before addressing or
        coordinating with them.
        """
        denied = _gate_denied(app_id, "grove_agents")
        if denied:
            return [{"error": denied}]
        pg = get_pg()
        if not pg:
            return [_pg_unavailable()]
        try:
            rows = grove.agents(pg)
        except grove.GroveUnavailable as e:
            return [_grove_error(e)]
        return grove.jsonify(rows)

    @mcp.tool(annotations=_ANNO_READ)
    def grove_fleet_status(app_id: str = "", limit: int = 50) -> list[dict]:
        """
        Rich fleet status rows — presence plus what each agent is doing.
        Requires grove_read.

        Each row: {sender, last_seen_at (ISO), age_secs, ui_state, peek,
        blocked, reply_to_message_id, correlation_id}.

        Args:
            limit: Max agents to return (clamped 1..100).
        """
        denied = _gate_denied(app_id, "grove_fleet_status")
        if denied:
            return [{"error": denied}]
        pg = get_pg()
        if not pg:
            return [_pg_unavailable()]
        cap = max(1, min(int(limit), 100))
        try:
            rows = grove.agent_fleet_rows(pg, limit=cap)
        except grove.GroveUnavailable as e:
            return [_grove_error(e)]
        return grove.jsonify(rows)

    @mcp.tool(annotations=_ANNO_READ)
    def grove_human_required(app_id: str = "", limit: int = 30,
                              open_only: bool = True) -> list[dict]:
        """
        The human-required queue — work that pauses automation until a
        person acts (consent, attestation, review, onboarding). Requires
        grove_read.

        Priority-first, then newest. Poll this to see what needs the
        operator before the fleet can proceed.

        Args:
            limit: Max items to return (clamped 1..100).
            open_only: When true (default) only items with status='open'.
        """
        denied = _gate_denied(app_id, "grove_human_required")
        if denied:
            return [{"error": denied}]
        pg = get_pg()
        if not pg:
            return [_pg_unavailable()]
        cap = max(1, min(int(limit), 100))
        try:
            rows = grove.human_required_queue(pg, limit=cap, open_only=bool(open_only))
        except grove.GroveUnavailable as e:
            return [_grove_error(e)]
        return grove.jsonify(rows)

    # ── Writes (7) ──────────────────────────────────────────────────────────

    @mcp.tool(annotations=_ANNO_WRITE)
    def grove_send_message(channel_name: str, content: str, app_id: str = "",
                            sender: str = "") -> dict:
        """
        Send a message to a Grove channel. Creates the channel if it doesn't
        exist. Requires grove_write.

        Args:
            channel_name: Target channel name.
            content: Message body.
            sender: Display name for the sender. Defaults to your resolved
                grove_sender (never a literal "Auto"). Passing a DIFFERENT
                identity requires the grove_relay permission — otherwise
                returns sender_forbidden.
        """
        denied = _gate_denied(app_id, "grove_send_message")
        if denied:
            return {"error": denied}
        pg = get_pg()
        if not pg:
            return _pg_unavailable()
        who, sender_err = _resolve_sender_checked(app_id, sender)
        if sender_err:
            return sender_err
        try:
            channels = grove.list_channels(pg)
            ch = grove.find_channel_in(channels, channel_name)
            if not ch:
                ch = grove.create_channel(pg, name=channel_name, channel_type="group")
            msg = grove.send_message(pg, channel_id=ch["id"], sender=who, content=content)
            if "error" in msg:
                return msg
        except grove.GroveUnavailable as e:
            return _grove_error(e)
        return {"id": msg["id"], "channel": ch["name"], "sent": True}

    @mcp.tool(annotations=_ANNO_WRITE)
    def grove_reply(channel_name: str, content: str, reply_to_id: int,
                     app_id: str = "", sender: str = "") -> dict:
        """
        Reply to a message in a thread. Requires grove_write.

        Args:
            channel_name: Channel containing the parent message.
            content: Reply body.
            reply_to_id: ID of the message being replied to.
            sender: Display name for the sender. Defaults to your resolved
                grove_sender. A different identity requires grove_relay.
        """
        denied = _gate_denied(app_id, "grove_reply")
        if denied:
            return {"error": denied}
        pg = get_pg()
        if not pg:
            return _pg_unavailable()
        who, sender_err = _resolve_sender_checked(app_id, sender)
        if sender_err:
            return sender_err
        try:
            channels = grove.list_channels(pg)
            ch = grove.find_channel_in(channels, channel_name)
            if not ch:
                return {"error": f"channel '{channel_name}' not found"}
            msg = grove.send_message(pg, channel_id=ch["id"], sender=who,
                                      content=content, reply_to_id=reply_to_id)
            if "error" in msg:
                return msg
            grove.clear_flag(pg, message_id=reply_to_id, sender="__system__", flag="needs-reply")
        except grove.GroveUnavailable as e:
            return _grove_error(e)
        return {"id": msg["id"], "channel": channel_name, "reply_to_id": reply_to_id, "sent": True}

    @mcp.tool(annotations=_ANNO_WRITE)
    def grove_flag(message_id: int, flag: str, app_id: str = "", sender: str = "") -> dict:
        """
        Set a flag on a message. Requires grove_write.

        Args:
            message_id: ID of the message to flag.
            flag: One of: needs-reply, starred, read, urgent, resolved.
            sender: Who is setting the flag. Defaults to your resolved
                grove_sender. A different identity requires grove_relay.
        """
        denied = _gate_denied(app_id, "grove_flag")
        if denied:
            return {"error": denied}
        pg = get_pg()
        if not pg:
            return _pg_unavailable()
        who, sender_err = _resolve_sender_checked(app_id, sender)
        if sender_err:
            return sender_err
        try:
            grove.set_flag(pg, message_id=message_id, sender=who, flag=flag)
        except ValueError as e:
            return {"error": str(e)}
        except grove.GroveUnavailable as e:
            return _grove_error(e)
        return {"message_id": message_id, "flag": flag, "set": True}

    @mcp.tool(annotations=_ANNO_WRITE)
    def grove_unflag(message_id: int, flag: str, app_id: str = "", sender: str = "") -> dict:
        """
        Clear a flag from a message. Requires grove_write.

        Args:
            message_id: ID of the message to unflag.
            flag: Flag to clear.
            sender: Who is clearing the flag. Defaults to your resolved
                grove_sender. A different identity requires grove_relay.
        """
        denied = _gate_denied(app_id, "grove_unflag")
        if denied:
            return {"error": denied}
        pg = get_pg()
        if not pg:
            return _pg_unavailable()
        who, sender_err = _resolve_sender_checked(app_id, sender)
        if sender_err:
            return sender_err
        try:
            cleared = grove.clear_flag(pg, message_id=message_id, sender=who, flag=flag)
        except grove.GroveUnavailable as e:
            return _grove_error(e)
        return {"message_id": message_id, "flag": flag, "cleared": cleared}

    @mcp.tool(annotations=_ANNO_WRITE)
    def grove_bus_send(channel_name: str, content: str, app_id: str = "",
                        sender: str = "", to_agent: str = "__all__",
                        bus_type: str = "EVENT", priority: int = 3,
                        correlation_id: str = "", ttl: int = 0) -> dict:
        """
        Send a structured bus message — addressed, typed, and prioritized.
        Requires grove_write.

        Args:
            channel_name: Channel to post to.
            content: Message body.
            sender: Sending agent name. Defaults to your resolved
                grove_sender. A different identity requires grove_relay.
            to_agent: Recipient agent name, or '__all__' for broadcast.
            bus_type: COMMAND, RESPONSE, EVENT, INTERRUPT, HEARTBEAT, ACK, DATA, SYNC.
            priority: 0=INTERRUPT, 3=NORMAL, 6=HEARTBEAT, 7=DEBUG.
            correlation_id: Pair requests with responses. Leave empty for new messages.
            ttl: Seconds until message expires. 0 = never.
        """
        denied = _gate_denied(app_id, "grove_bus_send")
        if denied:
            return {"error": denied}
        pg = get_pg()
        if not pg:
            return _pg_unavailable()
        who, sender_err = _resolve_sender_checked(app_id, sender)
        if sender_err:
            return sender_err
        try:
            channels = grove.list_channels(pg)
            ch = grove.find_channel_in(channels, channel_name)
            if not ch:
                ch = grove.create_channel(pg, name=channel_name, channel_type="group")
            msg = grove.bus_send(
                pg, channel_id=ch["id"], sender=who, content=content,
                to_agent=to_agent or grove.BUS_BROADCAST,
                bus_type=bus_type, priority=priority,
                correlation_id=correlation_id or None,
                ttl=ttl or None,
            )
            if bus_type in ("COMMAND", "INTERRUPT"):
                grove.set_flag(pg, message_id=msg["id"], sender="__system__", flag="needs-reply")
        except ValueError as e:
            return {"error": str(e)}
        except grove.GroveUnavailable as e:
            return _grove_error(e)
        return {
            "id": msg["id"], "channel": ch["name"], "to_agent": to_agent,
            "bus_type": bus_type, "priority": priority,
            "correlation_id": correlation_id or None, "sent": True,
        }

    @mcp.tool(annotations=_ANNO_WRITE)
    def grove_ack(channel_name: str, correlation_id: str, original_id: int,
                  app_id: str = "", sender: str = "") -> dict:
        """
        Acknowledge a received message. Clears needs-reply flag on the
        original. Requires grove_write.

        Args:
            channel_name: Channel of the original message.
            correlation_id: The correlation_id from the message you're acking.
            original_id: The id of the message being acknowledged.
            sender: Your agent name. Defaults to your resolved grove_sender.
                A different identity requires grove_relay.
        """
        denied = _gate_denied(app_id, "grove_ack")
        if denied:
            return {"error": denied}
        pg = get_pg()
        if not pg:
            return _pg_unavailable()
        who, sender_err = _resolve_sender_checked(app_id, sender)
        if sender_err:
            return sender_err
        try:
            channels = grove.list_channels(pg)
            ch = grove.find_channel_in(channels, channel_name)
            if not ch:
                return {"error": f"channel '{channel_name}' not found"}
            msg = grove.bus_send(
                pg, channel_id=ch["id"], sender=who,
                content=f"ACK {correlation_id}",
                bus_type="ACK", priority=2,
                correlation_id=correlation_id,
            )
            grove.clear_flag(pg, message_id=original_id, sender="__system__", flag="needs-reply")
            grove.set_flag(pg, message_id=original_id, sender=who, flag="read")
        except grove.GroveUnavailable as e:
            return _grove_error(e)
        return {"id": msg["id"], "acked": original_id, "correlation_id": correlation_id}

    @mcp.tool(annotations=_ANNO_WRITE)
    def grove_heartbeat(app_id: str = "", sender: str = "") -> dict:
        """
        Broadcast a heartbeat — I am alive and on the bus. Requires
        grove_write.

        Args:
            sender: Your agent name. Defaults to your resolved grove_sender.
                A different identity requires grove_relay.
        """
        denied = _gate_denied(app_id, "grove_heartbeat")
        if denied:
            return {"error": denied}
        pg = get_pg()
        if not pg:
            return _pg_unavailable()
        who, sender_err = _resolve_sender_checked(app_id, sender)
        if sender_err:
            return sender_err
        try:
            channels = grove.list_channels(pg)
            ch = grove.find_channel_in(channels, "general")
            if not ch:
                ch = grove.create_channel(pg, name="general", channel_type="group")
            msg = grove.bus_send(
                pg, channel_id=ch["id"], sender=who,
                content=f"{who} online",
                bus_type="HEARTBEAT", priority=6,
                to_agent=grove.BUS_BROADCAST,
            )
        except grove.GroveUnavailable as e:
            return _grove_error(e)
        return {"id": msg["id"], "sender": who, "bus_type": "HEARTBEAT"}
