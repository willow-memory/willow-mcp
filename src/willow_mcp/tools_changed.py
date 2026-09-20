"""willow_mcp/tools_changed.py — `notifications/tools/list_changed`, sent and inked.

Decision ``ab9b55dd`` (operator, 2026-09-18; Nestor pair
``ab9b55dd-a685-49bd-b5da-6363bdabcae1``; gap ``2451a10a19a3`` half a):

    The willow-mcp server emits the MCP protocol notification
    ``notifications/tools/list_changed`` whenever its registered or advertised
    tool set changes — after a constitutional sync lands a new syscall-table
    row, after a manifest re-sign, and after an advertise-mode change
    (DESK_CORE vs full). The server declares ``tools.listChanged: true`` in
    its initialize capabilities so a conforming client re-lists on receipt.
    Emission is logged as a receipt so a client that did not refresh is
    distinguishable from a server that did not notify.

Measured 2026-09-16: two ``/mcp`` reconnects were needed before ``tools/list``
showed a merged verb. The protocol defines the notification; the server never
sent it, and never said it would.

What the installed SDK (``mcp`` 2.0.0) actually offers, read from its source
rather than remembered (file:line under ``site-packages/mcp/``):

* **Capability.** ``Server.get_capabilities`` (``server/lowlevel/server.py``
  :584-606) has two eras. Handshake era: ``tools.listChanged`` comes from
  ``NotificationOptions.tools_changed`` — and ``MCPServer.run_stdio_async``
  (``server/mcpserver/server.py``:1024) calls
  ``create_initialization_options()`` with none, so the flag was ``False``.
  Modern 2026-07-28 era: the flag derives from ``subscriptions/listen`` being
  served, which ``MCPServer`` always registers. :func:`declare_capability`
  closes the handshake-era half.
* **What middleware sees.** A ``ServerRequestContext`` (``server/context.py``
  :30-49): ``session`` (a per-request ``ServerSession``), ``protocol_version``,
  ``method`` … and no ``connection``. The durable per-client object is the
  ``Connection`` the session proxies (``server/session.py``:47-55); the SDK
  keeps no registry of them, so :class:`ToolsChangedMiddleware` remembers
  each one it sees, weakly, and lets the SDK's own lifetime prune it.
* **Delivery, and what "delivered" can honestly mean.** ``Connection.notify``
  (``server/connection.py``:401-410) never raises: with no standalone channel
  (``_NoChannelOutbound``, :149-150) or on a modern-era connection
  (``NotifyOnlyOutbound``, :174-181 — list_changed is dropped by design) the
  notification is debug-logged and discarded, and a closed stream is
  swallowed the same way. So a send that returned is NOT a send that
  arrived. This module decides deliverability BEFORE sending — handshake era
  AND ``has_standalone_channel`` (:321-331) — and reports every other
  connection under its own count (``modern``, ``no_channel``) rather than as
  ``sent``. Modern-era delivery is the subscription bus:
  ``MCPServer._subscriptions.publish(ToolsListChanged())`` reaches only the
  ``subscriptions/listen`` streams a client opened; the in-memory bus's
  listener count (``server/subscriptions.py``:100) is read so a publish with
  nobody listening is ``bus_listeners=0``, never ``sent``.

The three triggers the seal names, and what each honestly is on this server:

1. **Constitutional sync** runs at process start (``server.main``), before a
   client can have connected. There is no session to notify at that moment —
   the receipt is written with ``state=empty``, which is the truth, and the
   client that connects afterwards gets the new table on its first
   ``tools/list``. The middleware ALSO watches the live table's CONTENT, so a
   sync performed by another process while this one serves is caught on the
   next request.
2. **Manifest re-sign.** ``gate._read_manifest`` re-reads and re-verifies the
   manifest on every call — there is no cache to invalidate. The middleware
   fingerprints the manifest and its ``.sig`` by content hash (a ``stat`` of
   mtime+size gates the read, so an unchanged file costs three stats per
   request and no I/O; a ``touch``, a checkout, or a byte-identical re-sign
   re-hashes once and stays quiet).
3. **Advertise-mode change.** ``WILLOW_MCP_ADVERTISE`` is process
   environment and cannot change under a running server; the manifest
   ``advertise`` key can (case 2 covers the file). For the env, the honest
   trigger is at startup: :func:`startup_check` compares the resolved mode
   against the last one receipted for this seat under the store.

Only sends and startup differences leave FRANK ink (event
``tools_list_changed``, beside ``constitutional_sync``); a request that found
nothing changed writes nothing.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import weakref
from pathlib import Path
from typing import Any, Optional

from . import paths

logger = logging.getLogger(__name__)

EVENT = "tools_list_changed"
METHOD = "notifications/tools/list_changed"
PROJECT = "fleet"
ACTOR = "willow-mcp"

#: Where the last-receipted surface per seat lives — the store, not the
#: home root, matching ``seal_daemon``'s offset files.
_STATE_FILENAME = "tools_surface.json"

#: Upper bound on remembered connections; a serve process that has seen more
#: distinct clients than this since boot keeps the newest.
_MAX_CONNECTIONS = 256

_lock = threading.Lock()
#: Live connections seen by the middleware. Weak values: when the SDK's
#: serve loop drops a connection (clean close or crash) the entry vanishes
#: with it, and a reused ``id()`` can never resolve to a dead peer.
_connections: "weakref.WeakValueDictionary[int, Any]" = weakref.WeakValueDictionary()
#: Connections that cannot be weakly referenced (a double with ``__slots__``),
#: held strongly under the same bound.
_strong: dict[int, Any] = {}
#: Insertion order for the bound above (WeakValueDictionary keeps none).
_order: list[int] = []
#: Last fingerprint observed per app_id, in-process.
_fingerprints: dict[str, dict] = {}
#: Stat gate: ``{path: (mtime_ns, size, sha256)}`` so an unchanged file is
#: never re-read.
_hash_cache: dict[str, tuple[Optional[int], Optional[int], Optional[str]]] = {}
#: Reasons queued by sync code (``mark_changed``) for the next flush.
_pending: list[tuple[str, str]] = []
#: The ``MCPServer`` this module notifies for (its subscription bus); bound
#: once by ``server.py``.
_server: Any = None
#: Test seam: a callable returning a ledger, or None for the live FRANK.
_ledger_factory: Any = None


# ── capability ────────────────────────────────────────────────────────────────

def declare_capability(server: Any) -> None:
    """Make the handshake-era ``initialize`` result say ``tools.listChanged: true``.

    ``MCPServer`` builds its ``InitializationOptions`` from
    ``self._lowlevel_server.create_initialization_options()`` with no
    ``NotificationOptions`` (SDK TODO(L53) at lowlevel/server.py:522 admits
    the API is upside down). Wrapping that one method so a missing
    ``notification_options`` defaults to ``tools_changed=True`` is the
    smallest honest change; the modern era needs nothing because
    ``subscriptions/listen`` is served. Fails loudly at startup if the SDK
    moves the seam — never a quiet ``False`` on the wire.
    """
    from mcp.server.lowlevel.server import NotificationOptions

    low = getattr(server, "_lowlevel_server", None)
    original = getattr(low, "create_initialization_options", None)
    if low is None or not callable(original):
        raise RuntimeError(
            "tools_changed: MCPServer no longer exposes _lowlevel_server."
            "create_initialization_options — the listChanged capability seam moved"
        )
    if getattr(original, "_willow_tools_changed", False):
        return

    def create_initialization_options(notification_options=None, *args, **kwargs):
        if notification_options is None:
            notification_options = NotificationOptions(tools_changed=True)
        else:
            notification_options.tools_changed = True
        return original(notification_options, *args, **kwargs)

    create_initialization_options._willow_tools_changed = True  # type: ignore[attr-defined]
    low.create_initialization_options = create_initialization_options


def bind(server: Any) -> None:
    """Remember the server whose subscription bus carries modern-era events,
    and declare the capability on it."""
    global _server
    _server = server
    declare_capability(server)


# ── fingerprint ───────────────────────────────────────────────────────────────

def _content_hash(path: Path) -> Optional[str]:
    """sha256 of ``path``, or ``None`` when absent/unreadable. A ``stat``
    (mtime_ns, size) gates the read: unchanged stat → cached hash, no I/O."""
    key = str(path)
    try:
        st = path.stat()
        gate = (st.st_mtime_ns, st.st_size)
    except OSError:
        _hash_cache[key] = (None, None, None)
        return None
    cached = _hash_cache.get(key)
    if cached is not None and cached[0] == gate[0] and cached[1] == gate[1]:
        return cached[2]
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        digest = None
    _hash_cache[key] = (gate[0], gate[1], digest)
    return digest


def _resolve_mode(app_id: str) -> str:
    """``advertise.resolve_advertise_mode`` is the one source of truth; it is
    called from here only."""
    from . import advertise as _advertise

    return _advertise.resolve_advertise_mode(app_id)


def fingerprint(app_id: str) -> dict:
    """What the advertised surface for ``app_id`` depends on: the manifest
    and its ``.sig`` (content), the live syscall table (content), and the
    resolved advertise mode. Content, not mtime: a ``touch`` or a checkout
    that rewrote identical bytes is not a change and must not wake the
    client. Cost on an unchanged request: three ``stat`` calls and one
    advertise-mode resolution (the gate already reads the manifest on every
    call; this adds no second verify beyond that read)."""
    from . import gate as _gate

    manifest = _gate._apps_root() / app_id / "manifest.json"
    return {
        "manifest_sha256": _content_hash(manifest),
        "manifest_sig_sha256": _content_hash(manifest.with_name(manifest.name + ".sig")),
        "syscall_table_sha256": _content_hash(paths.syscall_table_path()),
        "advertise_mode": _resolve_mode(app_id),
    }


def _diff(before: Optional[dict], after: dict) -> list[str]:
    if before is None:
        return []
    return sorted(k for k in after if before.get(k) != after.get(k))


def _reason_for(changed: list[str]) -> tuple[str, str]:
    """``(trigger, reason)`` naming which of the seal's three cases moved."""
    if "syscall_table_sha256" in changed:
        return "constitutional_sync", "live syscall table changed"
    if "advertise_mode" in changed:
        return "advertise_mode", "advertise mode changed"
    return "manifest_resign", "manifest or its signature changed"


# ── persisted last-receipted surface ──────────────────────────────────────────

def _state_path() -> Path:
    return paths.store_root() / _STATE_FILENAME


def _read_state() -> dict:
    try:
        data = json.loads(_state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_state(state: dict) -> None:
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


# ── ink ───────────────────────────────────────────────────────────────────────

def _ledger():
    if _ledger_factory is not None:
        return _ledger_factory()
    from .db import get_pg
    from .governance_ledger import GovernanceLedger

    pg = get_pg()
    return GovernanceLedger(pg) if pg else None


def _ink(content: dict, ledger=None) -> dict:
    """Append the ``tools_list_changed`` row. Returns ``{"receipt_id"}`` or
    ``{"receipt_error"}`` — the send happened either way; a receipt failing is
    reported, not hidden (same clause every executor in this package carries)."""
    led = ledger if ledger is not None else _ledger()
    if led is None:
        return {"receipt_error": "no governance ledger (postgres unavailable)"}
    try:
        return {"receipt_id": led.append(PROJECT, EVENT, content)}
    except Exception as exc:  # noqa: BLE001 — the notification went out; the receipt failing is reported, not hidden
        return {"receipt_error": f"{type(exc).__name__}: {exc}"}


def _tool_count(app_id: str) -> Optional[int]:
    """Only computed on a notification (rare), never per request — it walks
    the registered tool catalogue."""
    try:
        from . import advertise as _advertise
        from . import server as _server_mod

        catalogue = _server_mod._gate_tool_catalogue()
        names, mode = _advertise.advertised_tools(app_id, catalogue)
        return len(catalogue) if mode == "full" else len(names)
    except Exception:  # noqa: BLE001 — a count is decoration on the receipt, never a reason to skip it
        return None


# ── connections ───────────────────────────────────────────────────────────────

def connection_of(ctx: Any) -> Optional[Any]:
    """The durable ``Connection`` behind a middleware ``ctx``.

    ``ServerRequestContext.session`` is a per-request ``ServerSession`` whose
    ``_connection`` is the per-client ``Connection`` (session.py:47-55); the
    SDK exposes no public accessor for it from the context. The private name
    is read deliberately; if the SDK renames it this returns ``None`` and a
    live desk's receipt shows ``sessions_seen=0`` — loud, not a silently
    wrong count."""
    session = getattr(ctx, "session", None)
    conn = getattr(session, "_connection", None)
    if conn is None or not callable(getattr(conn, "send_tool_list_changed", None)):
        return None
    return conn


def remember_connection(connection: Any) -> None:
    if connection is None:
        return
    key = id(connection)
    with _lock:
        if _connections.get(key) is connection or _strong.get(key) is connection:
            return
        try:
            _connections[key] = connection
        except TypeError:
            _strong[key] = connection
        _order.append(key)
        while len(_order) > _MAX_CONNECTIONS:
            old = _order.pop(0)
            _connections.pop(old, None)
            _strong.pop(old, None)


def forget_connection(connection: Any) -> None:
    key = id(connection)
    with _lock:
        _connections.pop(key, None)
        _strong.pop(key, None)
        if key in _order:
            _order.remove(key)


def live_connections() -> list[Any]:
    with _lock:
        return list(_connections.values()) + list(_strong.values())


def _era(connection: Any) -> str:
    """``handshake`` or ``modern`` by the connection's own protocol version."""
    from mcp_types.version import MODERN_PROTOCOL_VERSIONS

    return "modern" if getattr(connection, "protocol_version", "") in MODERN_PROTOCOL_VERSIONS else "handshake"


def _bus_listeners(bus: Any) -> Optional[int]:
    """Listener count for the in-memory bus (``_listeners``, subscriptions.py
    :100); ``None`` for a custom bus that does not expose one."""
    listeners = getattr(bus, "_listeners", None)
    return len(listeners) if isinstance(listeners, dict) else None


# ── the act ───────────────────────────────────────────────────────────────────

async def notify(reason: str, *, trigger: str, app_id: str = "", ledger=None,
                 server: Any = None) -> dict:
    """Send ``notifications/tools/list_changed`` every way the SDK can carry
    it, counting only what could have arrived, then ink one receipt.

    Per remembered connection: handshake era with a standalone channel →
    ``send_tool_list_changed()``, counted in ``sessions_notified``; modern
    era → ``sessions_modern`` (the SDK drops the channel copy by design;
    those clients are reached by the bus, if they listen); no standalone
    channel → ``sessions_no_channel``. A send that raises is
    ``sessions_unreachable`` and pruned. The bus publish is judged by its
    listeners: ``bus_listeners`` is the number of open listen streams, or
    ``None`` for a bus that cannot say.

    ``state``: ``sent`` when at least one handshake send went out or the bus
    had a listener (or an unknowable bus had modern peers); ``empty`` when
    nothing could be reached; ``unreachable`` when every attempt raised.
    """
    srv = server if server is not None else _server
    sent = modern = no_channel = 0
    unreachable: list[str] = []
    for conn in live_connections():
        if not getattr(conn, "has_standalone_channel", True):
            no_channel += 1
            continue
        if _era(conn) == "modern":
            modern += 1
            continue
        try:
            await conn.send_tool_list_changed()
            sent += 1
        except Exception as exc:  # noqa: BLE001 — one dead pipe must not stop the others, and is reported by name
            forget_connection(conn)
            unreachable.append(f"{type(exc).__name__}: {exc}")

    bus_published = False
    bus_listeners: Optional[int] = None
    bus_error = False
    bus = getattr(srv, "_subscriptions", None) if srv is not None else None
    if bus is not None:
        bus_listeners = _bus_listeners(bus)
        try:
            from mcp.shared.subscriptions import ToolsListChanged

            await bus.publish(ToolsListChanged())
            bus_published = True
        except Exception as exc:  # noqa: BLE001 — same clause: named, counted, not hidden
            bus_error = True
            unreachable.append(f"bus: {type(exc).__name__}: {exc}")

    conn_failures = len(unreachable) - (1 if bus_error else 0)
    if bus_listeners is None:
        # A custom bus that cannot count: the modern peers we saw are the
        # best evidence anyone was on the other end.
        reached_by_bus = bus_published and modern > 0
    else:
        reached_by_bus = bus_published and bus_listeners > 0
    attempts = sent + conn_failures + (1 if bus is not None else 0)
    if sent or reached_by_bus:
        state = "sent"
    elif attempts and len(unreachable) == attempts:
        state = "unreachable"
    else:
        state = "empty"
    if unreachable:
        logger.warning("tools_changed: %d send(s) failed: %s", len(unreachable), "; ".join(unreachable)[:400])

    content = {
        "actor": ACTOR, "method": METHOD, "reason": reason, "trigger": trigger,
        "app_id": app_id, "state": state,
        "sessions_seen": sent + modern + no_channel + conn_failures,
        "sessions_notified": sent, "sessions_modern": modern, "sessions_no_channel": no_channel,
        "sessions_unreachable": conn_failures,
        "bus_published": bus_published, "bus_listeners": bus_listeners,
    }
    if app_id:
        content["advertise_mode"] = _resolve_mode(app_id)
        content["tool_count"] = _tool_count(app_id)
    out = {"ok": True, **content, "unreachable": unreachable}
    out.update(_ink(content, ledger=ledger))
    return out


def mark_changed(reason: str, *, trigger: str) -> None:
    """Queue a notification from sync code (a tool body, a CLI path). The
    middleware flushes it on the event loop after the current request."""
    with _lock:
        _pending.append((reason, trigger))


async def flush(app_id: str = "", ledger=None) -> list[dict]:
    with _lock:
        queued, _pending[:] = list(_pending), []
    return [await notify(reason, trigger=trigger, app_id=app_id, ledger=ledger) for reason, trigger in queued]


# ── observe ───────────────────────────────────────────────────────────────────

async def observe(app_id: str, ctx: Any = None, *, ledger=None) -> Optional[dict]:
    """One request's worth of watching: remember the request's connection,
    fingerprint the seat's surface, and notify if it moved since the last
    request. The first observation for a seat seeds the fingerprint silently
    — that is what :func:`startup_check` inks against the persisted one."""
    remember_connection(connection_of(ctx))
    if not app_id:
        return None
    now = fingerprint(app_id)
    with _lock:
        before = _fingerprints.get(app_id)
        _fingerprints[app_id] = now
    changed = _diff(before, now)
    if not changed:
        return None
    trigger, reason = _reason_for(changed)
    result = await notify(f"{reason}: {', '.join(changed)}", trigger=trigger, app_id=app_id, ledger=ledger)
    state = _read_state()
    state[app_id] = now
    _write_state(state)
    return result


_EMPTY_COUNTS = {
    "sessions_seen": 0, "sessions_notified": 0, "sessions_modern": 0,
    "sessions_no_channel": 0, "sessions_unreachable": 0,
    "bus_published": False, "bus_listeners": 0,
}


def startup_check(app_id: str, *, sync_result: Optional[dict] = None, ledger=None) -> list[dict]:
    """Run once from ``server.main`` after the constitutional sync and before
    the transport is up. No client exists yet, so nothing is sent; what is
    inked is (a) the sync having added rows and (b) this seat's surface
    differing from the last one receipted — both ``state=empty``, which is
    the honest word for "the change is real and nobody was listening."
    """
    receipts: list[dict] = []
    if sync_result and sync_result.get("added"):
        content = {
            "actor": ACTOR, "method": METHOD, "trigger": "constitutional_sync",
            "reason": f"syscall table gained verb id(s) {sync_result['added']} at startup",
            "app_id": app_id, "state": "empty", **_EMPTY_COUNTS,
            "sync_receipt_id": sync_result.get("receipt_id"),
        }
        receipts.append({**content, **_ink(content, ledger=ledger)})
    if not app_id:
        return receipts
    now = fingerprint(app_id)
    with _lock:
        _fingerprints[app_id] = now
    state = _read_state()
    last = state.get(app_id)
    if isinstance(last, dict) and last.get("advertise_mode") != now.get("advertise_mode"):
        content = {
            "actor": ACTOR, "method": METHOD, "trigger": "advertise_mode",
            "reason": f"advertise mode {last.get('advertise_mode')!r} -> {now['advertise_mode']!r} at startup",
            "app_id": app_id, "state": "empty", **_EMPTY_COUNTS,
            "advertise_mode": now["advertise_mode"], "tool_count": _tool_count(app_id),
        }
        receipts.append({**content, **_ink(content, ledger=ledger)})
    if last != now:
        state[app_id] = now
        _write_state(state)
    return receipts


# ── middleware ────────────────────────────────────────────────────────────────

class ToolsChangedMiddleware:
    """Registered inside ``RequestContextMiddleware``: after every request,
    watch the seat's surface and flush anything sync code queued. Runs on the
    event loop, which is the only place the SDK's async sends can be awaited.
    Never fails a request: a broken watch is logged, the response still
    returns."""

    async def __call__(self, ctx: Any, call_next: Any) -> Any:
        result = await call_next(ctx)
        try:
            from .request_context import _list_identity_app_id

            app_id = _list_identity_app_id() or ""
            await observe(app_id, ctx)
            if _pending:
                await flush(app_id)
        except Exception:  # noqa: BLE001 — the request succeeded; the watch failing must not turn it into an error
            logger.exception("tools_changed: watch failed after %s", getattr(ctx, "method", "?"))
        return result


def _reset_for_tests() -> None:
    global _server, _ledger_factory
    with _lock:
        _connections.clear()
        _strong.clear()
        _order.clear()
        _fingerprints.clear()
        _hash_cache.clear()
        _pending.clear()
    _server = None
    _ledger_factory = None
