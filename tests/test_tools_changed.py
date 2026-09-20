"""`notifications/tools/list_changed` (decision `ab9b55dd`, gap `2451a10a19a3`
half a): the server says it will notify, notifies every way the SDK can carry
it, and inks each send so a client that did not refresh is distinguishable
from a server that did not notify. The SDK connection is a recorder; the
ledger is a list; nothing here opens a socket.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
import types

import pytest

from willow_mcp import tools_changed as tc


# ── fakes ─────────────────────────────────────────────────────────────────────

class _Conn:
    def __init__(self, *, fail=False):
        self.sent = 0
        self.fail = fail

    async def send_tool_list_changed(self):
        if self.fail:
            raise ConnectionError("pipe closed")
        self.sent += 1


class _Bus:
    def __init__(self, *, fail=False):
        self.events = []
        self.fail = fail

    async def publish(self, event):
        if self.fail:
            raise RuntimeError("bus down")
        self.events.append(event)


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
    (apps / "manifest.json.sig").write_text("sig")
    const = home / "constitutional"
    const.mkdir()
    (const / "syscall-table.json").write_text(json.dumps({"verbs": []}))
    monkeypatch.setenv("WILLOW_APP_ID", "willow")
    monkeypatch.delenv("WILLOW_MCP_ADVERTISE", raising=False)
    return apps


def _touch(path):
    # mtime_ns must move even on coarse filesystems.
    now = time.time_ns() + 2_000_000_000
    os.utime(path, ns=(now, now))


# ── capability ────────────────────────────────────────────────────────────────

def test_declare_capability_sets_list_changed_on_the_handshake_path():
    from mcp.server.mcpserver import MCPServer

    server = MCPServer("t")
    before = server._lowlevel_server.create_initialization_options()
    assert before.capabilities.tools is not None
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


def test_modern_era_serves_subscriptions_listen():
    """At 2026-07-28+ the flag derives from the listen handler, which
    MCPServer registers itself — pinned so a future SDK that stops doing so
    is caught here rather than on the wire."""
    from mcp.server.mcpserver import MCPServer

    server = MCPServer("t")
    assert "subscriptions/listen" in server._lowlevel_server._request_handlers


def test_declare_capability_fails_loudly_when_the_seam_is_gone():
    with pytest.raises(RuntimeError, match="listChanged capability seam"):
        tc.declare_capability(types.SimpleNamespace())


def test_the_real_server_declares_it(home, monkeypatch):
    monkeypatch.setenv("WILLOW_APP_ID", "willow")
    from willow_mcp import server as srv

    opts = srv.mcp._lowlevel_server.create_initialization_options()
    assert opts.capabilities.tools.list_changed is True
    assert any(isinstance(m, tc.ToolsChangedMiddleware) for m in srv.mcp.middleware)


# ── the send, three states ────────────────────────────────────────────────────

def test_notify_sends_to_every_connection_and_the_bus_and_inks(seat):
    a, b, bus, ledger = _Conn(), _Conn(), _Bus(), _Ledger()
    tc.remember_connection(a)
    tc.remember_connection(b)
    out = asyncio.run(tc.notify("r", trigger="manifest_resign", app_id="willow",
                                ledger=ledger, server=_Server(bus)))
    assert out["state"] == "sent" and out["sessions_notified"] == 2 and out["bus_published"]
    assert a.sent == 1 and b.sent == 1 and len(bus.events) == 1
    assert type(bus.events[0]).__name__ == "ToolsListChanged"
    project, event, content = ledger.rows[0]
    assert (project, event) == ("fleet", tc.EVENT)
    assert content["method"] == "notifications/tools/list_changed"
    assert content["trigger"] == "manifest_resign" and content["app_id"] == "willow"
    assert content["advertise_mode"] == "desk_core"
    assert out["receipt_id"] == "receipt-1"


def test_notify_with_nothing_live_is_empty_not_a_failure():
    ledger = _Ledger()
    out = asyncio.run(tc.notify("r", trigger="advertise_mode", ledger=ledger, server=_Server(None)))
    assert out["state"] == "empty" and out["sessions_notified"] == 0 and not out["bus_published"]
    assert ledger.rows[0][2]["state"] == "empty"


def test_dead_connection_is_pruned_named_and_the_rest_still_sent():
    dead, live, ledger = _Conn(fail=True), _Conn(), _Ledger()
    tc.remember_connection(dead)
    tc.remember_connection(live)
    out = asyncio.run(tc.notify("r", trigger="manifest_resign", ledger=ledger, server=_Server(None)))
    assert out["state"] == "sent" and out["sessions_notified"] == 1
    assert out["sessions_unreachable"] == 1 and "ConnectionError" in out["unreachable"][0]
    assert tc.live_connections() == [live]


def test_every_path_raising_is_unreachable_not_empty():
    tc.remember_connection(_Conn(fail=True))
    out = asyncio.run(tc.notify("r", trigger="manifest_resign", ledger=_Ledger(), server=_Server(_Bus(fail=True))))
    assert out["state"] == "unreachable" and out["sessions_unreachable"] == 2


def test_receipt_failure_is_reported_beside_the_send():
    class _Broken:
        def append(self, *a):
            raise OSError("ledger offline")

    tc.remember_connection(_Conn())
    out = asyncio.run(tc.notify("r", trigger="manifest_resign", ledger=_Broken(), server=_Server(None)))
    assert out["state"] == "sent" and "OSError" in out["receipt_error"]


def test_no_ledger_is_named_not_silent():
    out = asyncio.run(tc.notify("r", trigger="manifest_resign", server=_Server(None), ledger=None))
    assert "receipt_error" in out or "receipt_id" in out


# ── the triggers, observed at runtime ─────────────────────────────────────────

def test_first_observation_seeds_silently(seat):
    ledger = _Ledger()
    assert asyncio.run(tc.observe("willow", _Conn(), ledger=ledger)) is None
    assert ledger.rows == []


def test_manifest_resign_is_noticed_on_the_next_request(seat):
    ledger, conn = _Ledger(), _Conn()
    asyncio.run(tc.observe("willow", conn, ledger=ledger))
    _touch(seat / "manifest.json.sig")
    out = asyncio.run(tc.observe("willow", conn, ledger=ledger))
    assert out["trigger"] == "manifest_resign" and out["state"] == "sent"
    assert conn.sent == 1 and ledger.rows[0][2]["trigger"] == "manifest_resign"
    # The surface is persisted so the next process can compare against it.
    persisted = json.loads((tc._state_path()).read_text())
    assert persisted["willow"]["manifest_sig_mtime_ns"] == tc.fingerprint("willow")["manifest_sig_mtime_ns"]


def test_live_table_change_is_the_constitutional_trigger(seat, home):
    ledger, conn = _Ledger(), _Conn()
    asyncio.run(tc.observe("willow", conn, ledger=ledger))
    _touch(home / "constitutional" / "syscall-table.json")
    out = asyncio.run(tc.observe("willow", conn, ledger=ledger))
    assert out["trigger"] == "constitutional_sync"


def test_advertise_mode_change_via_manifest_key(seat):
    ledger, conn = _Ledger(), _Conn()
    asyncio.run(tc.observe("willow", conn, ledger=ledger))
    (seat / "manifest.json").write_text(json.dumps({"app_id": "willow", "advertise": "full"}))
    _touch(seat / "manifest.json")
    out = asyncio.run(tc.observe("willow", conn, ledger=ledger))
    # Both the file and the mode moved; the mode is the more specific reason.
    assert out["trigger"] == "advertise_mode" and out["advertise_mode"] == "full"


def test_unchanged_surface_is_quiet(seat):
    ledger, conn = _Ledger(), _Conn()
    asyncio.run(tc.observe("willow", conn, ledger=ledger))
    assert asyncio.run(tc.observe("willow", conn, ledger=ledger)) is None
    assert ledger.rows == [] and conn.sent == 0


def test_mark_changed_is_flushed_on_the_loop():
    conn, ledger = _Conn(), _Ledger()
    tc.remember_connection(conn)
    tc.mark_changed("a tool body changed the table", trigger="constitutional_sync")
    outs = asyncio.run(tc.flush("willow", ledger=ledger))
    assert len(outs) == 1 and conn.sent == 1 and outs[0]["trigger"] == "constitutional_sync"
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
    assert tc.startup_check("willow", ledger=ledger) == []  # first boot seeds
    monkeypatch.setenv("WILLOW_MCP_ADVERTISE", "full")
    out = tc.startup_check("willow", ledger=ledger)
    assert len(out) == 1 and out[0]["trigger"] == "advertise_mode" and out[0]["state"] == "empty"
    assert "'desk_core' -> 'full'" in out[0]["reason"]
    assert json.loads(tc._state_path().read_text())["willow"]["advertise_mode"] == "full"


def test_startup_with_no_seat_only_inks_the_sync(seat):
    ledger = _Ledger()
    assert tc.startup_check("", sync_result={"added": []}, ledger=ledger) == []
    assert tc.startup_check("", sync_result={"added": [3]}, ledger=ledger)[0]["trigger"] == "constitutional_sync"


# ── middleware ────────────────────────────────────────────────────────────────

def test_middleware_watches_after_the_call_and_never_fails_the_request(seat, monkeypatch):
    conn, ledger = _Conn(), _Ledger()
    tc._ledger_factory = lambda: ledger
    ctx = types.SimpleNamespace(method="tools/call", connection=conn, meta=None)

    async def handler(c):
        return "result"

    mw = tc.ToolsChangedMiddleware()
    assert asyncio.run(mw(ctx, handler)) == "result"
    assert tc.live_connections() == [conn]
    _touch(seat / "manifest.json.sig")
    assert asyncio.run(mw(ctx, handler)) == "result"
    assert conn.sent == 1 and ledger.rows[0][2]["trigger"] == "manifest_resign"

    def boom(*a, **k):
        raise RuntimeError("fingerprint exploded")

    monkeypatch.setattr(tc, "fingerprint", boom)
    assert asyncio.run(mw(ctx, handler)) == "result"
