"""`notifications/tools/list_changed` (decision `ab9b55dd`, gap `2451a10a19a3`
half a): the server says it will notify, notifies every way the SDK can carry
it, counts only what could have arrived, and inks each send so a client that
did not refresh is distinguishable from a server that did not notify.

The connection under test is the SDK's own `Connection` (handshake and
modern eras), wrapped in the SDK's own `ServerSession` and
`ServerRequestContext` — the object the middleware actually receives. Only
the wire is a recorder; the ledger is a list; nothing opens a socket.
"""
from __future__ import annotations

import asyncio
import gc
import json
import os
import time
import types

import pytest
from mcp.server.connection import Connection, NotifyOnlyOutbound
from mcp.server.context import ServerRequestContext
from mcp.server.session import ServerSession
from mcp.server.subscriptions import InMemorySubscriptionBus
from mcp_types.version import LATEST_HANDSHAKE_VERSION, MODERN_PROTOCOL_VERSIONS

from willow_mcp import tools_changed as tc

MODERN = sorted(MODERN_PROTOCOL_VERSIONS)[-1]


# ── the wire ──────────────────────────────────────────────────────────────────

class _Wire:
    """A standalone-channel `Outbound` that records what the SDK put on it."""

    def __init__(self, *, fail=False):
        self.notifications: list[tuple[str, object]] = []
        self.fail = fail

    async def notify(self, method, params, opts=None):
        if self.fail:
            raise ConnectionError("pipe closed")
        self.notifications.append((method, params))

    async def send_raw_request(self, method, params, opts=None):
        raise AssertionError("no server-initiated requests in this test")

    @property
    def can_send_request(self):
        return False


def _handshake_connection(wire=None) -> Connection:
    return Connection.for_loop(wire or _Wire(), protocol_version_hint=LATEST_HANDSHAKE_VERSION)


def _modern_connection(wire=None) -> Connection:
    return Connection.from_envelope(MODERN, None, None, outbound=NotifyOnlyOutbound(wire or _Wire()))


def _ctx(connection: Connection, method="tools/call") -> ServerRequestContext:
    """What the middleware really receives: a ServerRequestContext whose
    `session` proxies the connection (context.py:30-49, session.py:47-55)."""
    dctx = types.SimpleNamespace(request_id=1, can_send_request=False)
    session = ServerSession(dctx, connection)
    return ServerRequestContext(session=session, lifespan_context={}, protocol_version=connection.protocol_version,
                                method=method, request_id=1)


class _Server:
    def __init__(self, bus=None):
        self._subscriptions = bus


class _Ledger:
    def __init__(self):
        self.rows = []

    def append(self, project, event_type, content):
        self.rows.append((project, event_type, content))
        return f"receipt-{len(self.rows)}"


@pytest.fixture(autouse=True)
def _clean():
    tc._reset_for_tests()
    yield
    tc._reset_for_tests()


@pytest.fixture
def seat(home, monkeypatch):
    """A `willow` seat with a manifest on disk and a live syscall table."""
    apps = home / "mcp_apps" / "willow"
    apps.mkdir(parents=True)
    (apps / "manifest.json").write_text(json.dumps({"app_id": "willow", "permissions": ["full_access"]}))
    (apps / "manifest.json.sig").write_text("sig-v1")
    const = home / "constitutional"
    const.mkdir()
    (const / "syscall-table.json").write_text(json.dumps({"verbs": []}))
    monkeypatch.setenv("WILLOW_APP_ID", "willow")
    monkeypatch.delenv("WILLOW_MCP_ADVERTISE", raising=False)
    return apps


def _touch(path):
    now = time.time_ns() + 2_000_000_000
    os.utime(path, ns=(now, now))


def _rewrite(path, text):
    path.write_text(text)
    _touch(path)


# ── capability ────────────────────────────────────────────────────────────────

def test_declare_capability_sets_list_changed_on_the_handshake_path():
    from mcp.server.mcpserver import MCPServer

    server = MCPServer("t")
    before = server._lowlevel_server.create_initialization_options()
    assert not before.capabilities.tools.list_changed, "SDK default is False; the test would prove nothing"
    tc.declare_capability(server)
    after = server._lowlevel_server.create_initialization_options()
    assert after.capabilities.tools.list_changed is True


def test_declare_capability_is_idempotent_and_honours_explicit_options():
    from mcp.server.lowlevel.server import NotificationOptions
    from mcp.server.mcpserver import MCPServer

    server = MCPServer("t")
    tc.declare_capability(server)
    tc.declare_capability(server)
    opts = server._lowlevel_server.create_initialization_options(NotificationOptions(prompts_changed=True))
    assert opts.capabilities.tools.list_changed is True
    assert opts.capabilities.prompts.list_changed is True


def test_modern_era_capability_derives_from_the_listen_handler():
    from mcp.server.mcpserver import MCPServer

    server = MCPServer("t")
    caps = server._lowlevel_server.get_capabilities(protocol_version=MODERN)
    assert caps.tools.list_changed is True


def test_declare_capability_fails_loudly_when_the_seam_is_gone():
    with pytest.raises(RuntimeError, match="listChanged capability seam"):
        tc.declare_capability(types.SimpleNamespace())


def test_the_real_server_declares_it(home, monkeypatch):
    monkeypatch.setenv("WILLOW_APP_ID", "willow")
    from willow_mcp import server as srv

    assert srv.mcp._lowlevel_server.create_initialization_options().capabilities.tools.list_changed is True
    assert any(isinstance(m, tc.ToolsChangedMiddleware) for m in srv.mcp.middleware)


# ── the SDK connection, read off the real context ─────────────────────────────

def test_connection_is_reached_through_the_sessions_private_connection():
    conn = _handshake_connection()
    assert tc.connection_of(_ctx(conn)) is conn
    assert tc.connection_of(types.SimpleNamespace(connection=conn)) is None, "middleware ctx has no .connection"
    assert tc.connection_of(None) is None


def test_handshake_send_lands_on_the_standalone_channel():
    wire = _Wire()
    conn = _handshake_connection(wire)
    tc.remember_connection(conn)
    out = asyncio.run(tc.notify("r", trigger="manifest_resign", ledger=_Ledger(), server=_Server(None)))
    assert wire.notifications == [("notifications/tools/list_changed", None)]
    assert out["state"] == "sent" and out["sessions_notified"] == 1 and out["sessions_seen"] == 1


def test_modern_connection_is_not_counted_as_sent_because_the_sdk_drops_it():
    """NotifyOnlyOutbound.notify (connection.py:174-181) discards list_changed
    at the 2026-07-28 era and returns None — a returned send is not a
    delivered one."""
    wire = _Wire()
    conn = _modern_connection(wire)
    tc.remember_connection(conn)
    out = asyncio.run(tc.notify("r", trigger="manifest_resign", ledger=_Ledger(), server=_Server(None)))
    assert wire.notifications == []
    assert out["state"] == "empty" and out["sessions_notified"] == 0 and out["sessions_modern"] == 1


def test_no_channel_connection_is_counted_apart():
    conn = Connection.from_envelope(MODERN, None, None)  # single-exchange HTTP: no standalone channel
    assert not conn.has_standalone_channel
    tc.remember_connection(conn)
    out = asyncio.run(tc.notify("r", trigger="manifest_resign", ledger=_Ledger(), server=_Server(None)))
    assert out["state"] == "empty" and out["sessions_no_channel"] == 1 and out["sessions_notified"] == 0


def test_modern_peer_with_a_listen_stream_is_sent_via_the_bus():
    bus = InMemorySubscriptionBus()
    got = []
    bus.subscribe(got.append)
    held = _modern_connection()
    tc.remember_connection(held)
    out = asyncio.run(tc.notify("r", trigger="manifest_resign", ledger=_Ledger(), server=_Server(bus)))
    assert out["state"] == "sent" and out["bus_published"] and out["bus_listeners"] == 1
    assert out["sessions_modern"] == 1 and out["sessions_notified"] == 0
    assert type(got[0]).__name__ == "ToolsListChanged"


def test_bus_publish_with_no_listener_is_not_sent():
    """Finding 3: a publish nobody subscribed to reached nobody."""
    out = asyncio.run(tc.notify("r", trigger="advertise_mode", ledger=_Ledger(),
                                server=_Server(InMemorySubscriptionBus())))
    assert out["bus_published"] and out["bus_listeners"] == 0 and out["state"] == "empty"


def test_custom_bus_without_a_count_is_reported_as_unknown():
    class _Opaque:
        async def publish(self, event):
            pass

    held = _modern_connection()  # weak registry: the peer must still be alive, as it is on a real loop
    tc.remember_connection(held)
    out = asyncio.run(tc.notify("r", trigger="advertise_mode", ledger=_Ledger(), server=_Server(_Opaque())))
    assert out["bus_listeners"] is None and out["state"] == "sent", "unknowable bus + modern peer: best evidence"
    tc._reset_for_tests()
    out = asyncio.run(tc.notify("r", trigger="advertise_mode", ledger=_Ledger(), server=_Server(_Opaque())))
    assert out["bus_listeners"] is None and out["state"] == "empty"


def test_nothing_live_is_empty_not_a_failure():
    ledger = _Ledger()
    out = asyncio.run(tc.notify("r", trigger="advertise_mode", ledger=ledger, server=_Server(None)))
    assert out["state"] == "empty" and out["sessions_seen"] == 0
    assert ledger.rows[0][2]["state"] == "empty"


class _Raising:
    protocol_version = LATEST_HANDSHAKE_VERSION
    has_standalone_channel = True

    async def send_tool_list_changed(self):
        raise ConnectionError("pipe closed")


def test_raising_send_is_unreachable_named_and_pruned():
    dead, live_wire = _Raising(), _Wire()
    live = _handshake_connection(live_wire)
    tc.remember_connection(dead)
    tc.remember_connection(live)
    out = asyncio.run(tc.notify("r", trigger="manifest_resign", ledger=_Ledger(), server=_Server(None)))
    assert out["state"] == "sent" and out["sessions_notified"] == 1 and out["sessions_unreachable"] == 1
    assert "ConnectionError" in out["unreachable"][0]
    assert dead not in tc.live_connections()


def test_every_attempt_raising_is_unreachable():
    class _BrokenBus:
        _listeners = {"x": 1}

        async def publish(self, event):
            raise RuntimeError("bus down")

    dead = _Raising()
    tc.remember_connection(dead)
    out = asyncio.run(tc.notify("r", trigger="manifest_resign", ledger=_Ledger(), server=_Server(_BrokenBus())))
    assert out["state"] == "unreachable" and len(out["unreachable"]) == 2


def test_receipt_shape_and_receipt_failure():
    class _Broken:
        def append(self, *a):
            raise OSError("ledger offline")

    ledger = _Ledger()
    held = _handshake_connection()
    tc.remember_connection(held)
    out = asyncio.run(tc.notify("r", trigger="manifest_resign", ledger=ledger, server=_Server(None)))
    project, event, content = ledger.rows[0]
    assert (project, event) == ("fleet", tc.EVENT)
    for key in ("method", "reason", "trigger", "state", "sessions_seen", "sessions_notified",
                "sessions_modern", "sessions_no_channel", "sessions_unreachable", "bus_published", "bus_listeners"):
        assert key in content
    assert out["receipt_id"] == "receipt-1"
    out = asyncio.run(tc.notify("r", trigger="manifest_resign", ledger=_Broken(), server=_Server(None)))
    assert out["state"] == "sent" and "OSError" in out["receipt_error"]


# ── connection lifetime (finding 4) ───────────────────────────────────────────

def test_closed_connection_is_forgotten_when_the_sdk_drops_it():
    conn = _handshake_connection()
    tc.remember_connection(conn)
    assert tc.live_connections() == [conn]
    del conn
    gc.collect()
    assert tc.live_connections() == []


def test_remembering_the_same_connection_twice_is_one_entry():
    conn = _handshake_connection()
    tc.remember_connection(conn)
    tc.remember_connection(conn)
    assert len(tc.live_connections()) == 1


def test_registry_is_bounded():
    keep = [_handshake_connection() for _ in range(tc._MAX_CONNECTIONS + 5)]
    for c in keep:
        tc.remember_connection(c)
    assert len(tc.live_connections()) == tc._MAX_CONNECTIONS
    assert keep[-1] in tc.live_connections() and keep[0] not in tc.live_connections()


# ── the triggers, observed at runtime (finding 5: content, not mtime) ─────────

def test_first_observation_seeds_silently(seat):
    ledger = _Ledger()
    assert asyncio.run(tc.observe("willow", _ctx(_handshake_connection()), ledger=ledger)) is None
    assert ledger.rows == []


def test_touch_and_byte_identical_resign_are_quiet(seat):
    ledger, wire = _Ledger(), _Wire()
    ctx = _ctx(_handshake_connection(wire))
    asyncio.run(tc.observe("willow", ctx, ledger=ledger))
    _touch(seat / "manifest.json.sig")
    _touch(seat / "manifest.json")
    _rewrite(seat / "manifest.json.sig", "sig-v1")  # same bytes, new inode times
    assert asyncio.run(tc.observe("willow", ctx, ledger=ledger)) is None
    assert ledger.rows == [] and wire.notifications == []


def test_manifest_resign_is_noticed_on_the_next_request(seat):
    ledger, wire = _Ledger(), _Wire()
    ctx = _ctx(_handshake_connection(wire))
    asyncio.run(tc.observe("willow", ctx, ledger=ledger))
    _rewrite(seat / "manifest.json.sig", "sig-v2")
    out = asyncio.run(tc.observe("willow", ctx, ledger=ledger))
    assert out["trigger"] == "manifest_resign" and out["state"] == "sent"
    assert wire.notifications == [("notifications/tools/list_changed", None)]
    persisted = json.loads(tc._state_path().read_text())
    assert persisted["willow"]["manifest_sig_sha256"] == tc.fingerprint("willow")["manifest_sig_sha256"]


def test_live_table_change_is_the_constitutional_trigger(seat, home):
    ledger = _Ledger()
    ctx = _ctx(_handshake_connection())
    asyncio.run(tc.observe("willow", ctx, ledger=ledger))
    _rewrite(home / "constitutional" / "syscall-table.json", json.dumps({"verbs": [{"id": 17}]}))
    assert asyncio.run(tc.observe("willow", ctx, ledger=ledger))["trigger"] == "constitutional_sync"


def test_advertise_mode_change_via_manifest_key(seat):
    ledger = _Ledger()
    ctx = _ctx(_handshake_connection())
    asyncio.run(tc.observe("willow", ctx, ledger=ledger))
    _rewrite(seat / "manifest.json", json.dumps({"app_id": "willow", "advertise": "full"}))
    out = asyncio.run(tc.observe("willow", ctx, ledger=ledger))
    assert out["trigger"] == "advertise_mode" and out["advertise_mode"] == "full"


def test_unchanged_surface_costs_no_reads(seat, monkeypatch):
    ctx = _ctx(_handshake_connection())
    asyncio.run(tc.observe("willow", ctx))
    reads = []
    real = tc.Path.read_bytes

    def counting(self):
        reads.append(self)
        return real(self)

    monkeypatch.setattr(tc.Path, "read_bytes", counting)
    assert asyncio.run(tc.observe("willow", ctx)) is None
    assert reads == []


def test_mark_changed_is_flushed_on_the_loop():
    wire, ledger = _Wire(), _Ledger()
    held = _handshake_connection(wire)
    tc.remember_connection(held)
    tc.mark_changed("a tool body changed the table", trigger="constitutional_sync")
    outs = asyncio.run(tc.flush("willow", ledger=ledger))
    assert len(outs) == 1 and len(wire.notifications) == 1 and outs[0]["trigger"] == "constitutional_sync"
    assert asyncio.run(tc.flush("willow", ledger=ledger)) == []


# ── startup ───────────────────────────────────────────────────────────────────

def test_startup_inks_sync_rows_as_empty(seat):
    ledger = _Ledger()
    out = tc.startup_check("willow", sync_result={"added": [17], "receipt_id": "sync-1"}, ledger=ledger)
    assert len(out) == 1
    row = ledger.rows[0][2]
    assert row["trigger"] == "constitutional_sync" and row["state"] == "empty"
    assert row["sessions_notified"] == 0 and row["sync_receipt_id"] == "sync-1"


def test_startup_inks_advertise_mode_drift_against_the_persisted_surface(seat, monkeypatch):
    ledger = _Ledger()
    assert tc.startup_check("willow", ledger=ledger) == []
    monkeypatch.setenv("WILLOW_MCP_ADVERTISE", "full")
    out = tc.startup_check("willow", ledger=ledger)
    assert len(out) == 1 and out[0]["trigger"] == "advertise_mode" and out[0]["state"] == "empty"
    assert "'desk_core' -> 'full'" in out[0]["reason"]
    assert json.loads(tc._state_path().read_text())["willow"]["advertise_mode"] == "full"


def test_startup_with_no_seat_only_inks_the_sync(seat):
    ledger = _Ledger()
    assert tc.startup_check("", sync_result={"added": []}, ledger=ledger) == []
    assert tc.startup_check("", sync_result={"added": [3]}, ledger=ledger)[0]["trigger"] == "constitutional_sync"


# ── middleware, on the real context ───────────────────────────────────────────

def test_middleware_remembers_the_real_connection_and_notifies_after_the_call(seat):
    wire, ledger = _Wire(), _Ledger()
    tc._ledger_factory = lambda: ledger
    conn = _handshake_connection(wire)

    async def handler(c):
        return "result"

    mw = tc.ToolsChangedMiddleware()
    assert asyncio.run(mw(_ctx(conn), handler)) == "result"
    assert tc.live_connections() == [conn]
    _rewrite(seat / "manifest.json.sig", "sig-v2")
    assert asyncio.run(mw(_ctx(conn), handler)) == "result"
    assert wire.notifications == [("notifications/tools/list_changed", None)]
    assert ledger.rows[0][2]["trigger"] == "manifest_resign" and ledger.rows[0][2]["sessions_notified"] == 1


def test_middleware_never_fails_the_request(seat, monkeypatch):
    ctx = _ctx(_handshake_connection())

    async def handler(c):
        return "result"

    def boom(*a, **k):
        raise RuntimeError("fingerprint exploded")

    monkeypatch.setattr(tc, "fingerprint", boom)
    assert asyncio.run(tc.ToolsChangedMiddleware()(ctx, handler)) == "result"
