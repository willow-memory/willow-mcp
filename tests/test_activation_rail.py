"""Tests for the Grove activation rail, slice 1 (surface-only):

1. dispatch.dispatch_send posts a Grove Intent.WAKE envelope after writing
   the packet (grove_tools.post_wake_envelope), best-effort like the PG
   mirror.
2. activation.build_activate — the real surface-only wake handler: appends
   a line to the seat's grove-listen log, spawns nothing.
3. grove_tools.build_mcp_call — the in-process mcp_call shim a per-seat
   SeatDaemon uses to poll/post/ack Grove without a second MCP transport.
4. willow_mcp.seat_daemon — the full per-seat daemon (bus + seal watch +
   activate) built from the pieces above.

Fake-pg pattern borrowed from tests/test_grove_tools.py.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from willow_mcp import activation, dispatch, grove, grove_tools, seal_daemon, seat_daemon


# ── shared fake pg (tests/test_grove_tools.py's pattern) ───────────────────

class _FakeCursor:
    def __init__(self, conn):
        self._conn = conn
        self.description = None
        self._rows = []
        self.rowcount = 0

    def execute(self, sql, params=None):
        self._conn.calls.append((sql, params))
        cols, rows = self._conn._pop_response()
        self.description = [(c,) for c in cols] if cols is not None else None
        self._rows = list(rows or [])
        self.rowcount = 1

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def close(self):
        pass


class _FakePg:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def cursor(self):
        return _FakeCursor(self)

    def _pop_response(self):
        if not self._responses:
            return (None, [])
        return self._responses.pop(0)


def _now():
    return datetime(2026, 9, 11, 12, 0, 0, tzinfo=timezone.utc)


_CH_COLS = ["id", "name", "channel_type", "description", "created_at",
            "updated_at", "is_archived", "agent_name"]
_MSG_COLS = ["id", "channel_id", "sender", "content", "to_agent", "bus_type",
             "priority", "correlation_id", "ttl", "created_at"]


def _grant(tmp_path, monkeypatch, app_id, permissions):
    apps_root = tmp_path / "mcp_apps"
    app_dir = apps_root / app_id
    app_dir.mkdir(parents=True, exist_ok=True)
    (app_dir / "manifest.json").write_text(json.dumps({"permissions": list(permissions)}))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))


# ── 1. grove_tools.post_wake_envelope ───────────────────────────────────────

def test_post_wake_envelope_denied_without_grove_write(tmp_path, monkeypatch):
    _grant(tmp_path, monkeypatch, "willow", ["grove_read"])  # no grove_write
    out = grove_tools.post_wake_envelope("willow", "hanuman", dispatch_id="ABCD1234")
    assert out["posted"] is False
    assert "gate denied" in out["reason"]


def test_post_wake_envelope_reports_postgres_unavailable(tmp_path, monkeypatch):
    _grant(tmp_path, monkeypatch, "willow", ["grove_write"])
    monkeypatch.setattr(grove_tools, "get_pg", lambda: None)
    out = grove_tools.post_wake_envelope("willow", "hanuman", dispatch_id="ABCD1234")
    assert out["posted"] is False
    assert "postgres" in out["reason"]


def test_post_wake_envelope_posts_a_valid_wake_envelope(tmp_path, monkeypatch):
    """The envelope this posts must be one BusListener.validate_envelope
    accepts for the RECEIVING seat's own node — that's the actual contract,
    not just "some JSON got posted"."""
    _grant(tmp_path, monkeypatch, "willow", ["grove_write"])
    pg = _FakePg([
        (_CH_COLS, []),  # list_channels: no "hanuman" channel yet
        (_CH_COLS, [(9, "hanuman", "group", None, _now(), _now(), False, None)]),  # create_channel
        (_MSG_COLS, [(42, 9, "willow", "envelope-json", "hanuman", "COMMAND", 1, None, None, _now())]),
    ])
    monkeypatch.setattr(grove_tools, "get_pg", lambda: pg)

    out = grove_tools.post_wake_envelope(
        "willow", "hanuman", dispatch_id="ABCD1234", summary="go build the thing",
        reply_to="willow",
    )

    assert out["posted"] is True
    assert out["channel"] == "hanuman"
    assert out["message_id"] == 42

    # Recover the actual content posted and validate it the way BusListener
    # would for the receiving seat (node="hanuman").
    insert_sql, insert_params = pg.calls[-1]
    assert "INSERT INTO grove.messages" in insert_sql
    content = insert_params[2]  # (channel_id, sender, content, to_agent, ...)
    posted = json.loads(content)
    assert posted["intent"] == "wake"
    assert posted["to"] == "hanuman"
    assert posted["dispatch_id"] == "ABCD1234"

    from ratatosk.protocol.envelope import validate_envelope, clear_nonce_cache
    clear_nonce_cache()
    msg = {"content": content, "sender": "willow"}
    from ratatosk.protocol.envelope import parse_grove_message
    env = parse_grove_message(msg, default_node="hanuman")
    assert env is not None
    result = validate_envelope(env, node="hanuman")
    assert result.ok, result.errors
    assert env.intent == "wake"
    assert env.extra.get("dispatch_id") == "ABCD1234"


def test_post_wake_envelope_never_raises_on_grove_failure(tmp_path, monkeypatch):
    _grant(tmp_path, monkeypatch, "willow", ["grove_write"])

    class _BoomPg(_FakePg):
        def cursor(self):
            raise RuntimeError("boom")

    monkeypatch.setattr(grove_tools, "get_pg", lambda: _BoomPg([]))
    out = grove_tools.post_wake_envelope("willow", "hanuman", dispatch_id="ABCD1234")
    assert out["posted"] is False
    assert "boom" in out["reason"]


# ── dispatch_send integration: best-effort, never breaks the packet write ──

def test_dispatch_send_calls_post_wake_envelope_with_packet_fields(home, monkeypatch):
    seen = {}

    def fake_post(from_app, to_app, *, dispatch_id, summary="", reply_to="", trace_id=""):
        seen.update(from_app=from_app, to_app=to_app, dispatch_id=dispatch_id,
                    summary=summary, reply_to=reply_to)
        return {"posted": True}

    monkeypatch.setattr(grove_tools, "post_wake_envelope", fake_post)
    out = dispatch.dispatch_send("willow", "hanuman", "# Task\n\ndo it",
                                 dispatch_id="ABCD1234", summary="do it",
                                 reply_to="willow")
    assert out["status"] == "pending"
    assert seen == {"from_app": "willow", "to_app": "hanuman", "dispatch_id": "ABCD1234",
                     "summary": "do it", "reply_to": "willow"}


def test_dispatch_send_survives_wake_post_raising(home, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("bus is on fire")

    monkeypatch.setattr(grove_tools, "post_wake_envelope", boom)
    out = dispatch.dispatch_send("willow", "hanuman", "# Task\n\ndo it",
                                 dispatch_id="EFGH5678")
    assert out["status"] == "pending"  # filesystem write succeeded regardless


def test_dispatch_send_with_no_grove_manifest_still_succeeds(home):
    """No manifest anywhere in this $WILLOW_HOME — the wake post's own gate
    check denies it, and dispatch_send must not even notice."""
    out = dispatch.dispatch_send("willow", "hanuman", "# Task\n\ndo it",
                                 dispatch_id="IJKL9012")
    assert out["status"] == "pending"
    assert out["dispatch_id"] == "IJKL9012"


# ── 2. activation.build_activate ────────────────────────────────────────────

def _wake_envelope(**overrides):
    from ratatosk.protocol.envelope import build_envelope, Intent, Capability
    kwargs = dict(
        to="hanuman", prompt="a packet is waiting for you", from_agent="willow",
        intent=Intent.WAKE.value, reply_channel="willow",
        capabilities=[Capability.WAKE.value], trace_id="tr-testtrace",
        extra={"dispatch_id": "ABCD1234"},
    )
    kwargs.update(overrides)
    return build_envelope(**kwargs)


def test_build_activate_writes_a_wake_line_to_the_grove_listen_log(tmp_path):
    log_path = tmp_path / "logs" / "grove-listen-hanuman.log"
    activate = activation.build_activate("hanuman", log_path=log_path)
    env = _wake_envelope()

    trace = activate(env)

    assert "tr-testtrace" in trace
    assert log_path.exists()
    line = log_path.read_text(encoding="utf-8").strip()
    assert line.startswith("[WAKE]")
    assert "trace=tr-testtrace" in line
    assert "willow -> hanuman" in line
    assert "dispatch=ABCD1234" in line
    assert "a packet is waiting for you" in line


def test_build_activate_uses_grove_listen_default_log_path(monkeypatch, tmp_path):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    from willow_mcp import grove_listen
    expected = grove_listen.default_log_path("hanuman")

    activate = activation.build_activate("hanuman")
    activate(_wake_envelope())

    assert expected.exists()


def test_build_activate_appends_multiple_wakes(tmp_path):
    log_path = tmp_path / "wake.log"
    activate = activation.build_activate("hanuman", log_path=log_path)
    activate(_wake_envelope(trace_id="tr-one"))
    activate(_wake_envelope(trace_id="tr-two"))
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert "tr-one" in lines[0]
    assert "tr-two" in lines[1]


def test_build_activate_never_raises_on_write_failure(tmp_path, caplog):
    # Point the log "directory" at a path that is actually a file, so
    # mkdir(parents=True) raises NotADirectoryError/FileExistsError (an
    # OSError) instead of ever opening a real log file.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    log_path = blocker / "grove-listen-hanuman.log"
    activate = activation.build_activate("hanuman", log_path=log_path)

    with caplog.at_level(logging.ERROR, logger="willow_mcp.activation"):
        trace = activate(_wake_envelope())

    assert "log write failed" in trace
    assert any(r.exc_info for r in caplog.records if r.levelno >= logging.ERROR)


def test_build_activate_spawns_nothing(tmp_path, monkeypatch):
    """Surface-only: no subprocess, no Popen, anywhere in the activate path."""
    def boom(*a, **k):
        raise AssertionError("activate must never spawn a process")

    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(os, "fork", boom, raising=False)
    log_path = tmp_path / "wake.log"
    activate = activation.build_activate("hanuman", log_path=log_path)
    activate(_wake_envelope())
    assert log_path.exists()


# ── 3. grove_tools.build_mcp_call ───────────────────────────────────────────

def test_mcp_call_shim_denies_without_grove_read(tmp_path, monkeypatch):
    _grant(tmp_path, monkeypatch, "hanuman", ["store_read"])
    call = grove_tools.build_mcp_call("hanuman")
    out = call("grove_get_history", {"channel_name": "hanuman", "limit": 20})
    # A dict carrying "error" — exactly the shape ratatosk's own
    # `_as_messages` treats as "no messages" (`result.get("error")` short
    # circuits to `[]`), so this denial degrades the same way a real
    # gate-denied MCP round-trip would for BusListener.fetch_messages.
    assert "error" in out
    assert "gate denied" in out["error"]


def test_mcp_call_shim_get_history_returns_oldest_first(tmp_path, monkeypatch):
    _grant(tmp_path, monkeypatch, "hanuman", ["grove_read", "grove_write"])
    pg = _FakePg([
        (_CH_COLS, [(9, "hanuman", "group", None, _now(), _now(), False, None)]),
        (_MSG_COLS, [
            (2, 9, "willow", "second", "hanuman", "COMMAND", 1, None, None, _now()),
            (1, 9, "willow", "first", "hanuman", "COMMAND", 1, None, None, _now()),
        ]),
    ])
    monkeypatch.setattr(grove_tools, "get_pg", lambda: pg)
    call = grove_tools.build_mcp_call("hanuman")
    out = call("grove_get_history", {"channel_name": "hanuman", "limit": 20})
    assert [m["id"] for m in out] == [1, 2]


def test_mcp_call_shim_heartbeat_posts_to_general(tmp_path, monkeypatch):
    _grant(tmp_path, monkeypatch, "hanuman", ["grove_read", "grove_write"])
    pg = _FakePg([
        (_CH_COLS, [(1, "general", "group", None, _now(), _now(), False, None)]),
        (_MSG_COLS, [(5, 1, "hanuman", "hanuman online", "__all__", "HEARTBEAT", 6, None, None, _now())]),
    ])
    monkeypatch.setattr(grove_tools, "get_pg", lambda: pg)
    call = grove_tools.build_mcp_call("hanuman")
    out = call("grove_heartbeat", {"agent": "hanuman", "channel": "hanuman"})
    assert out["sender"] == "hanuman"
    assert out["bus_type"] == "HEARTBEAT"


def test_mcp_call_shim_send_message_posts_reply(tmp_path, monkeypatch):
    _grant(tmp_path, monkeypatch, "hanuman", ["grove_read", "grove_write"])
    pg = _FakePg([
        (_CH_COLS, [(2, "willow", "group", None, _now(), _now(), False, None)]),
        (_MSG_COLS, [(6, 2, "hanuman", "reply text", "__all__", "EVENT", 3, None, None, _now())]),
    ])
    monkeypatch.setattr(grove_tools, "get_pg", lambda: pg)
    call = grove_tools.build_mcp_call("hanuman")
    out = call("grove_send_message", {"channel_name": "willow", "content": "reply text",
                                       "sender": "hanuman"})
    assert out["sent"] is True
    assert out["id"] == 6


def test_mcp_call_shim_ack_clears_needs_reply(tmp_path, monkeypatch):
    _grant(tmp_path, monkeypatch, "hanuman", ["grove_read", "grove_write"])
    pg = _FakePg([(None, [])])  # clear_flag's UPDATE
    monkeypatch.setattr(grove_tools, "get_pg", lambda: pg)
    call = grove_tools.build_mcp_call("hanuman")
    out = call("grove_ack", {"message_id": 7})
    assert out == {"acked": 7}


def test_mcp_call_shim_unsupported_tool(tmp_path, monkeypatch):
    _grant(tmp_path, monkeypatch, "hanuman", ["grove_read", "grove_write"])
    call = grove_tools.build_mcp_call("hanuman")
    out = call("some_other_tool", {})
    assert "error" in out


def test_mcp_call_shim_heartbeat_posts_as_app_id_even_with_a_different_persona(tmp_path, monkeypatch):
    """FINDING 2 regression (corrected): BusListener.emit_heartbeat posts
    with `agent=self.node` — the seat's RAW app_id, since
    `SeatDaemon(node=app_id, ...)`. This must not be refused (the original
    FINDING 2 bug) — but it must also NOT be resolved to the seat's persona
    display name even when the registry maps one (the regression a first
    attempt at this fix introduced — see the NEW FINDING in
    docs/design/grove-activation-rail.md's "self-post loop closure"
    section): the shim's own automated posts have to stay under `app_id`,
    matching `node`, or `BusListener.is_own_post` stops recognizing them."""
    _grant(tmp_path, monkeypatch, "hanuman", ["grove_read", "grove_write"])
    monkeypatch.setattr(
        grove_tools, "resolve_grove_sender",
        lambda app_id: "Hanuman-of-the-Forge" if app_id == "hanuman" else app_id,
    )
    pg = _FakePg([
        (_CH_COLS, [(1, "general", "group", None, _now(), _now(), False, None)]),
        (_MSG_COLS, [(5, 1, "hanuman", "hanuman online",
                      "__all__", "HEARTBEAT", 6, None, None, _now())]),
    ])
    monkeypatch.setattr(grove_tools, "get_pg", lambda: pg)
    call = grove_tools.build_mcp_call("hanuman")

    out = call("grove_heartbeat", {"agent": "hanuman", "channel": "hanuman"})

    assert "error" not in out
    assert out["sender"] == "hanuman"  # app_id, NOT "Hanuman-of-the-Forge"


def test_mcp_call_shim_send_message_posts_as_app_id_even_with_a_different_persona(tmp_path, monkeypatch):
    """Same corrected FINDING 2 regression, for the wake-ack/reply path
    (`process_message`'s `grove_send_message` call, `sender=self.node`)."""
    _grant(tmp_path, monkeypatch, "hanuman", ["grove_read", "grove_write"])
    monkeypatch.setattr(
        grove_tools, "resolve_grove_sender",
        lambda app_id: "Hanuman-of-the-Forge" if app_id == "hanuman" else app_id,
    )
    pg = _FakePg([
        (_CH_COLS, [(2, "willow", "group", None, _now(), _now(), False, None)]),
        (_MSG_COLS, [(6, 2, "hanuman", "reply text", "__all__", "EVENT",
                      3, None, None, _now())]),
    ])
    monkeypatch.setattr(grove_tools, "get_pg", lambda: pg)
    call = grove_tools.build_mcp_call("hanuman")

    out = call("grove_send_message", {"channel_name": "willow", "content": "reply text",
                                       "sender": "hanuman"})  # raw node

    assert "error" not in out
    assert out["sent"] is True
    # The INSERT actually carried "hanuman" as sender, not the persona —
    # recover it from the fake pg's own call log rather than trusting only
    # the tool's echoed response.
    insert_sql, insert_params = pg.calls[-1]
    assert "INSERT INTO grove.messages" in insert_sql
    assert insert_params[1] == "hanuman"


def test_mcp_call_shim_still_refuses_a_genuine_third_party_sender(tmp_path, monkeypatch):
    """The FINDING 2 fix only reconciles the seat's OWN raw node name — a
    request to post as some genuinely different identity must still be
    refused without grove_relay.

    `grove_send_message`'s shim branch checks the gate, THEN opens a
    Postgres connection, THEN checks the sender — same order the real
    registered `grove_send_message` MCP tool uses (see `_gate_denied` ->
    `get_pg()` -> `_resolve_sender_checked` in `register()` above), which
    this shim deliberately mirrors rather than diverging from. That means
    this assertion is reachable only past a truthy `get_pg()` — patched
    here to a dummy in-memory connection, same DB-isolation discipline
    every other shim test in this file already follows, so the outcome
    never depends on whether a live Postgres happens to be reachable as
    the OS user. Without this, the test passed locally by accident (peer
    auth trusts the dev box's own user) and failed in CI (the Postgres
    service only knows `postgres`, not the runner's OS user, so `get_pg()`
    itself failed auth and the shim returned `postgres_unavailable` before
    ever reaching the sender check it exists to exercise) — a real
    local-vs-CI parity gap, not a flake. The fake is never actually
    queried: the sender check short-circuits before any cursor use."""
    _grant(tmp_path, monkeypatch, "hanuman", ["grove_read", "grove_write"])
    monkeypatch.setattr(
        grove_tools, "resolve_grove_sender",
        lambda app_id: "Hanuman-of-the-Forge" if app_id == "hanuman" else app_id,
    )
    monkeypatch.setattr(grove_tools, "get_pg", lambda: _FakePg([]))
    call = grove_tools.build_mcp_call("hanuman")
    out = call("grove_send_message", {"channel_name": "willow", "content": "hi",
                                       "sender": "someone-else"})
    assert out.get("error") == "sender_forbidden"


def test_shim_resolve_sender_helper_never_resolves_to_the_persona():
    assert grove_tools._shim_resolve_sender("hanuman", "hanuman") == ("hanuman", None)
    assert grove_tools._shim_resolve_sender("hanuman", "HANUMAN") == ("hanuman", None)
    assert grove_tools._shim_resolve_sender("hanuman", "") == ("hanuman", None)
    who, err = grove_tools._shim_resolve_sender("hanuman", "someone-else")
    assert who is None
    assert err["error"] == "sender_forbidden"


def test_mcp_call_shim_ignores_a_forged_app_id_in_params(tmp_path, monkeypatch):
    """The shim always acts as the app_id it was built for — a caller
    stuffing a different app_id into params must not change identity."""
    _grant(tmp_path, monkeypatch, "hanuman", ["grove_read", "grove_write"])
    pg = _FakePg([
        (_CH_COLS, [(1, "general", "group", None, _now(), _now(), False, None)]),
        (_MSG_COLS, [(5, 1, "hanuman", "hanuman online", "__all__", "HEARTBEAT", 6, None, None, _now())]),
    ])
    monkeypatch.setattr(grove_tools, "get_pg", lambda: pg)
    call = grove_tools.build_mcp_call("hanuman")
    out = call("grove_heartbeat", {"app_id": "willow"})
    assert out["sender"] == "hanuman"


# ── 4. willow_mcp.seat_daemon ────────────────────────────────────────────────

def test_build_full_seat_daemon_wires_node_channel_seal_and_activate(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("", encoding="utf-8")
    offset = tmp_path / "offset"
    log_path = tmp_path / "wake.log"

    daemon = seat_daemon.build_full_seat_daemon(
        "hanuman", ledger_path=ledger, offset_path=offset, log_path=log_path,
    )

    assert isinstance(daemon, seal_daemon.SeatDaemon)
    assert daemon.node == "hanuman"
    assert daemon.channel == "hanuman"
    assert daemon.seal_watcher is not None

    # The real activate is wired, not the ratatosk default no-op.
    env = _wake_envelope(to="hanuman")
    result = daemon.listener.activate(env)
    assert "noticed" in result
    assert log_path.exists()


def test_build_full_seat_daemon_mcp_call_is_the_in_process_shim(tmp_path, monkeypatch):
    _grant(tmp_path, monkeypatch, "hanuman", ["grove_read", "grove_write"])
    monkeypatch.setattr(grove_tools, "get_pg", lambda: None)  # force no-DB path deterministically
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("", encoding="utf-8")
    offset = tmp_path / "offset"

    daemon = seat_daemon.build_full_seat_daemon(
        "hanuman", ledger_path=ledger, offset_path=offset,
    )
    out = daemon.listener.mcp_call("grove_ack", {"message_id": 1})
    # Reached the real shim (denied cleanly, not an AttributeError/None-call).
    assert out["error"] == "postgres_unavailable"


def test_main_exits_promptly_and_cleanly_on_sigterm(tmp_path):
    ledger_home = tmp_path
    src_dir = str(Path(__file__).resolve().parents[1] / "src")
    env = os.environ.copy()
    env["WILLOW_HOME"] = str(ledger_home)
    env["PYTHONPATH"] = src_dir + os.pathsep + env.get("PYTHONPATH", "")

    proc = subprocess.Popen(
        [sys.executable, "-m", "willow_mcp.seat_daemon", "--app-id", "hanuman",
         "--poll-interval", "0.1"],
        cwd=src_dir,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        time.sleep(0.5)
        start = time.monotonic()
        proc.terminate()
        try:
            out, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate(timeout=5)
            pytest.fail(f"process did not exit within 5s on SIGTERM; output:\n{out}")
        elapsed = time.monotonic() - start
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate()

    assert elapsed < 3, f"SIGTERM took too long to take effect ({elapsed:.2f}s)"
    assert proc.returncode == 0
    assert "listening on hanuman" in out
    assert "stopped" in out


# ── 5. FINDING 3: the real seam, end to end ─────────────────────────────────
#
# Every leg above is tested in isolation. This drives the actual seam:
#   post_wake_envelope -> [shared fake Postgres] -> build_mcp_call
#   ('grove_get_history') -> BusListener.run_once -> parse_grove_message ->
#   validate_envelope -> CapabilityGate -> _handle_wake -> activate ->
#   (reply posted back through the SAME shim's grove_send_message)
# with nothing stubbed in the middle — a STATEFUL fake Postgres shared by
# both the poster and the receiving shim, so a message one side inserts is
# what the other side actually reads back, the same way a real Postgres
# connection would. This is what would have caught FINDING 1 (had the shim
# been pointed at the wrong "database") and FINDING 2 (the sender-identity
# mismatch on the wake-ack) as a single regression instead of requiring an
# adversarial audit to notice the seam was never actually driven together.

class _MiniGroveCursor:
    def __init__(self, conn):
        self.conn = conn
        self._rows = []
        self.description = None
        self.rowcount = 0

    def close(self):
        pass

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def execute(self, sql, params=None):
        s = " ".join(sql.split())
        params = params or ()

        if s.startswith("SELECT") and "FROM grove.channels" in s:
            cols = ["id", "name", "channel_type", "description", "created_at",
                    "updated_at", "is_archived", "agent_name"]
            self._rows = [tuple(c.get(col) for col in cols) for c in self.conn.channels]
            self.description = [(c,) for c in cols]
            return

        if s.startswith("INSERT INTO grove.channels"):
            name, channel_type, description = params
            now = _now()
            row = {"id": self.conn._next_channel_id, "name": name,
                   "channel_type": channel_type, "description": description,
                   "created_at": now, "updated_at": now, "is_archived": False,
                   "agent_name": None}
            self.conn._next_channel_id += 1
            self.conn.channels.append(row)
            cols = ["id", "name", "channel_type", "description", "created_at",
                    "updated_at", "is_archived"]
            self._rows = [tuple(row[c] for c in cols)]
            self.description = [(c,) for c in cols]
            return

        if s.startswith("SELECT") and "FROM grove.messages m" in s:
            # get_history's default (no since_id/before_id) branch: (channel_id, limit)
            channel_id, limit = params
            cols = ["id", "channel_id", "sender", "content", "message_type",
                    "reply_to_id", "to_agent", "bus_type", "priority",
                    "correlation_id", "ttl", "willow_indexed_at", "created_at",
                    "is_deleted", "reply_count"]
            rows = [m for m in self.conn.messages if m["channel_id"] == channel_id]
            rows = sorted(rows, key=lambda m: m["created_at"], reverse=True)[:limit]
            self._rows = [
                tuple(m[c] if c != "reply_count" else 0 for c in cols) for m in rows
            ]
            self.description = [(c,) for c in cols]
            return

        if s.startswith("INSERT INTO grove.messages") and len(params) == 8:
            # bus_send — distinguished from send_message's 5-param INSERT by
            # param count, not by substring match: send_message's own
            # RETURNING clause (_MSG_COLUMNS) also contains the literal text
            # "to_agent", so a substring check on the SQL text alone cannot
            # tell the two INSERTs apart.
            channel_id, sender, content, to_agent, bus_type, priority, correlation_id, ttl = params
            now = _now()
            row = {"id": self.conn._next_message_id, "channel_id": channel_id,
                   "sender": sender, "content": content, "message_type": "text",
                   "reply_to_id": None, "to_agent": to_agent, "bus_type": bus_type,
                   "priority": priority, "correlation_id": correlation_id, "ttl": ttl,
                   "willow_indexed_at": None, "created_at": now, "is_deleted": 0}
            self.conn._next_message_id += 1
            self.conn.messages.append(row)
            cols = ["id", "channel_id", "sender", "content", "to_agent", "bus_type",
                    "priority", "correlation_id", "ttl", "created_at"]
            self._rows = [tuple(row[c] for c in cols)]
            self.description = [(c,) for c in cols]
            return

        if s.startswith("INSERT INTO grove.messages"):
            # send_message (the reply-post path)
            channel_id, sender, content, message_type, reply_to_id = params
            now = _now()
            row = {"id": self.conn._next_message_id, "channel_id": channel_id,
                   "sender": sender, "content": content, "message_type": message_type,
                   "reply_to_id": reply_to_id, "to_agent": grove.BUS_BROADCAST,
                   "bus_type": "EVENT", "priority": 3, "correlation_id": None,
                   "ttl": None, "willow_indexed_at": None, "created_at": now,
                   "is_deleted": 0}
            self.conn._next_message_id += 1
            self.conn.messages.append(row)
            cols = ["id", "channel_id", "sender", "content", "message_type",
                    "reply_to_id", "to_agent", "bus_type", "priority",
                    "correlation_id", "ttl", "willow_indexed_at", "created_at",
                    "is_deleted"]
            self._rows = [tuple(row[c] for c in cols)]
            self.description = [(c,) for c in cols]
            return

        if s.startswith("DELETE FROM grove.message_flags"):
            self.rowcount = 1
            self._rows = []
            self.description = None
            return

        raise AssertionError(f"unhandled SQL in fake grove pg: {s[:160]}")


class _MiniGrovePg:
    """A minimal but STATEFUL in-memory stand-in for Postgres — real enough
    that channels/messages inserted by one call are what a later call reads
    back, unlike tests/test_grove_tools.py's canned-response `_FakePg`."""

    def __init__(self):
        self.channels: list[dict] = []
        self.messages: list[dict] = []
        self._next_channel_id = 1
        self._next_message_id = 1

    def cursor(self):
        return _MiniGroveCursor(self)


def test_wake_seam_end_to_end_dispatch_to_notice(tmp_path, monkeypatch):
    """The whole rail, driven for real, against one shared fake Postgres:

    1. willow posts a wake to hanuman (post_wake_envelope).
    2. hanuman's own SeatDaemon/BusListener polls Grove through the SAME
       in-process shim (build_mcp_call) a real deployment would use.
    3. The polled envelope validates and classifies as WAKE.
    4. activate() fires — the real, surface-only handler — and logs the
       [WAKE] line.
    5. BusListener posts hanuman's own wake-ack back to willow's channel,
       using hanuman's RAW node name as sender (exactly like the real
       ratatosk code does) while hanuman's registry maps to a DIFFERENT
       persona display name — this is where FINDING 2 would resurface if
       the shim's sender-identity fix ever regressed, and where the
       self-post-loop regression (a corrected version of that same fix)
       would resurface too: the ack must land under "hanuman" (matching
       `node`), NOT under the persona.
    """
    _grant(tmp_path, monkeypatch, "willow", ["grove_write"])
    _grant(tmp_path, monkeypatch, "hanuman", ["grove_read", "grove_write"])
    monkeypatch.setattr(
        grove_tools, "resolve_grove_sender",
        lambda app_id: "Hanuman-of-the-Forge" if app_id == "hanuman" else app_id,
    )
    pg = _MiniGrovePg()
    monkeypatch.setattr(grove_tools, "get_pg", lambda: pg)

    # 1. willow dispatches and wakes hanuman.
    posted = grove_tools.post_wake_envelope(
        "willow", "hanuman", dispatch_id="SEAM0001", summary="build the thing",
        reply_to="willow",
    )
    assert posted["posted"] is True
    assert len(pg.messages) == 1
    assert pg.messages[0]["to_agent"] == "hanuman"

    # 2/3/4. hanuman's own daemon polls, validates, and activates —
    # through the exact production wiring (build_full_seat_daemon).
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("", encoding="utf-8")
    offset = tmp_path / "offset"
    log_path = tmp_path / "grove-listen-hanuman.log"

    daemon = seat_daemon.build_full_seat_daemon(
        "hanuman", ledger_path=ledger, offset_path=offset, log_path=log_path,
    )
    outputs = daemon.listener.run_once()

    assert log_path.exists(), "activate must have appended a [WAKE] line"
    wake_line = log_path.read_text(encoding="utf-8").strip()
    assert wake_line.startswith("[WAKE]")
    assert "SEAM0001" in wake_line
    assert daemon.listener.state.cursor == pg.messages[0]["id"]  # message consumed

    # 5. FINDING 2: the wake-ack must actually have been posted (not refused
    # with sender_forbidden) — AND under "hanuman" (app_id, matching
    # `node`), never the persona, or is_own_post silently stops recognizing
    # the seat's own traffic (the follow-up self-post-loop finding).
    assert not any(o for o in outputs if "sender_forbidden" in o or "not delivered" in o), outputs
    ack_messages = [m for m in pg.messages if m["sender"] == "hanuman"]
    assert ack_messages, f"no ack posted as app_id; outputs={outputs!r} messages={pg.messages}"
    assert ack_messages[0]["content"] and "noticed" in ack_messages[0]["content"]
    assert not any(m["sender"] == "Hanuman-of-the-Forge" for m in pg.messages), (
        "the ack must never post under the resolved persona name"
    )

    # FINDING 1's shape, made visible here too: had the shim been pointed at
    # the wrong "database" (an empty fake, or one raising GroveUnavailable),
    # `run_once` would have seen zero messages and produced no output at
    # all — silently dark, exactly the failing scenario described. Assert
    # the positive: something real came back.
    assert outputs


# ── 6. NEW FINDING: self-post loop closure ─────────────────────────────────
#
# is_own_post (ratatosk.listener.BusListener) is the ONLY thing standing
# between a seat and re-processing its own posts forever — nonce-based
# replay detection cannot help, because parse_grove_message mints a fresh
# nonce on every parse of raw/self-authored content (its own docstring says
# so). is_own_post compares a fetched message's `sender` against `self.node`
# — this daemon's raw app_id. A shim that stores its own automated posts
# under the RESOLVED PERSONA instead of app_id breaks that comparison
# silently. These two tests drive the real two-tick failure the auditor
# reproduced, against the shared stateful fake Postgres, with a persona
# mapping in place so the bug WOULD reappear if the fix regressed.

def _ollama_unavailable(monkeypatch):
    import ratatosk.ollama as ollama_module
    monkeypatch.setattr(ollama_module, "is_available", lambda: False)


def test_seat_does_not_reprocess_its_own_reply_on_its_own_channel(tmp_path, monkeypatch):
    """The INFINITE sub-case: an inbound chat envelope asks to be answered
    on the seat's OWN channel (`reply_channel="hanuman"` — an entirely
    ordinary "reply where you were asked" request, not even the
    empty-reply_channel edge case). Two ticks: tick 1 answers it and posts
    the reply as "hanuman" (app_id) on #hanuman; tick 2 must recognize that
    reply as its own post (is_own_post: sender == node == "hanuman") and do
    nothing — not answer itself again, and NOT do so forever."""
    _ollama_unavailable(monkeypatch)
    _grant(tmp_path, monkeypatch, "willow", ["grove_write"])
    _grant(tmp_path, monkeypatch, "hanuman", ["grove_read", "grove_write"])
    monkeypatch.setattr(
        grove_tools, "resolve_grove_sender",
        lambda app_id: "Hanuman-of-the-Forge" if app_id == "hanuman" else app_id,
    )
    pg = _MiniGrovePg()
    monkeypatch.setattr(grove_tools, "get_pg", lambda: pg)

    from ratatosk.protocol.envelope import build_envelope, Intent

    ch = grove.create_channel(pg, name="hanuman", channel_type="group")
    inbound = build_envelope(
        to="hanuman", from_agent="willow", prompt="hi there",
        intent=Intent.CHAT.value, reply_channel="hanuman",
    )
    grove.bus_send(pg, channel_id=ch["id"], sender="willow", content=inbound.to_json(),
                    to_agent="hanuman", bus_type="COMMAND", priority=3)

    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("", encoding="utf-8")
    offset = tmp_path / "offset"

    daemon = seat_daemon.build_full_seat_daemon(
        "hanuman", ledger_path=ledger, offset_path=offset,
    )

    # tick 1: answers the inbound chat, posts its own reply to #hanuman.
    outputs_1 = daemon.listener.run_once()
    assert outputs_1  # the chat WAS handled
    assert len(pg.messages) == 2
    assert pg.messages[-1]["sender"] == "hanuman"  # app_id, not the persona

    # tick 2: must NOT treat its own reply as fresh inbound.
    outputs_2 = daemon.listener.run_once()
    assert outputs_2 == [], f"seat re-processed its own reply: {outputs_2}"
    assert len(pg.messages) == 2, "no third message — the loop did not fire"

    # tick 3, for good measure: still nothing. Not just "not yet".
    outputs_3 = daemon.listener.run_once()
    assert outputs_3 == []
    assert len(pg.messages) == 2


def test_seat_plain_text_reply_spills_to_general_but_does_not_loop(tmp_path, monkeypatch):
    """The CONTAINED sub-case: a plain, non-JSON inbound message on
    #hanuman (ratatosk's `"agent: text"` address-style parse) always
    replies on a HARDCODED #general — a different channel from the one
    this daemon polls. One extra ("spilled") post happens, but since this
    daemon only watches #hanuman, tick 2 must see nothing new on ITS OWN
    channel and must not loop — and the spilled reply itself must be under
    "hanuman" (app_id), not the persona, so a DIFFERENT seat that DOES
    watch #general would also recognize it correctly as not-its-own but
    also not silently misattributed."""
    _ollama_unavailable(monkeypatch)
    _grant(tmp_path, monkeypatch, "willow", ["grove_write"])
    _grant(tmp_path, monkeypatch, "hanuman", ["grove_read", "grove_write"])
    monkeypatch.setattr(
        grove_tools, "resolve_grove_sender",
        lambda app_id: "Hanuman-of-the-Forge" if app_id == "hanuman" else app_id,
    )
    pg = _MiniGrovePg()
    monkeypatch.setattr(grove_tools, "get_pg", lambda: pg)

    ch = grove.create_channel(pg, name="hanuman", channel_type="group")
    # Plain, address-style text — not JSON-envelope-shaped.
    grove.bus_send(pg, channel_id=ch["id"], sender="willow", content="hanuman: hi there",
                    to_agent="hanuman", bus_type="COMMAND", priority=3)

    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("", encoding="utf-8")
    offset = tmp_path / "offset"

    daemon = seat_daemon.build_full_seat_daemon(
        "hanuman", ledger_path=ledger, offset_path=offset,
    )

    outputs_1 = daemon.listener.run_once()
    assert outputs_1

    # The reply landed on #general (hardcoded for this parse path), not
    # #hanuman, and is stored under app_id, not the persona.
    spilled = [m for m in pg.messages if m["sender"] == "hanuman" and m["channel_id"] != ch["id"]]
    assert len(spilled) == 1, f"expected exactly one spilled reply; messages={pg.messages}"
    assert not any(m["sender"] == "Hanuman-of-the-Forge" for m in pg.messages)

    # tick 2 (still polling #hanuman only) sees nothing new — no loop.
    outputs_2 = daemon.listener.run_once()
    assert outputs_2 == []
    assert len(pg.messages) == 2, "no additional message — nothing looped on #hanuman"


# ── 7. FINDING 1 real regression: the DB name actually resolves ────────────
#
# The e2e seam test above monkeypatches grove_tools.get_pg directly, so it
# cannot catch a regression of the deploy-template fix (WILLOW_PG_DB, not
# WILLOW_DB_URL). These two tests exercise the REAL resolution chain the
# template's env var feeds: WILLOW_PG_DB -> paths.pg_db() -> db.get_pg()'s
# actual psycopg2.connect() call.

def test_pg_db_resolves_from_willow_pg_db_env(monkeypatch):
    from willow_mcp import paths
    monkeypatch.delenv("WILLOW_PG_DB", raising=False)
    monkeypatch.setattr(paths, "_settings_global", lambda: {})
    assert paths.pg_db() == "willow"  # the willow-mcp-wide default

    monkeypatch.setenv("WILLOW_PG_DB", "willow_20")
    assert paths.pg_db() == "willow_20"  # what the seat-daemon template sets


def test_get_pg_actually_connects_using_pg_db_not_a_url(monkeypatch):
    """Regression for grove-activation-rail FINDING 1: `db.get_pg()` must
    resolve its Postgres database name from `paths.pg_db()`
    (`WILLOW_PG_DB`) — the actual knob `deploy/willow-seat-daemon.service
    .template` sets to `willow_20` — not from any DSN/url env var (nothing
    on this path reads one)."""
    from willow_mcp import db as db_module

    monkeypatch.setenv("WILLOW_PG_DB", "willow_20")
    monkeypatch.setattr(db_module, "_pg_conn", None)
    monkeypatch.setattr(db_module, "_pg_last_error", None)

    seen_kwargs = {}

    class _FakeCursor:
        def execute(self, *_args, **_kwargs):
            pass

    class _FakeConn:
        closed = False

        def cursor(self):
            return _FakeCursor()

    def fake_connect(**kwargs):
        seen_kwargs.update(kwargs)
        return _FakeConn()

    monkeypatch.setattr(db_module.psycopg2, "connect", fake_connect)

    conn = db_module.get_pg()

    assert conn is not None
    assert seen_kwargs.get("dbname") == "willow_20"
    # WILLOW_DB_URL is not part of this call at all — confirms the deploy
    # template's env var actually reaches this connection.
    assert "dsn" not in seen_kwargs and "url" not in seen_kwargs
