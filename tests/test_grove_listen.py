"""Tests for willow_mcp/grove_listen.py — the seat's ear on the Grove.

Ported from willow-2.0's tests/test_grove_listen.py (mention detection) and
extended for what changed: classification is one pure function over a row,
the gate refuses an ungranted seat before Postgres is touched, and a
read-only seat listens without announcing. No Postgres here — the SQL
helpers are pinned with a fake cursor.
"""
from __future__ import annotations

import io
import json
from unittest.mock import MagicMock

import pytest

from willow_mcp import grove_listen as gl

_APP = "vishwakarma"


@pytest.fixture(autouse=True)
def _reset_cache():
    gl._alias_regex.cache_clear()
    yield
    gl._alias_regex.cache_clear()


def _manifest(tmp_path, monkeypatch, app: str, perms: list[str]):
    apps_root = tmp_path / "mcp_apps"
    (apps_root / app).mkdir(parents=True, exist_ok=True)
    (apps_root / app / "manifest.json").write_text(json.dumps({"permissions": perms}))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    return apps_root


# ── mention detection (2.0 parity) ───────────────────────────────────────────

def test_broadcast_all():
    assert gl.is_broadcast_mention("hey @all, meeting now") is True


def test_broadcast_all_case_insensitive():
    assert gl.is_broadcast_mention("@All please read") is True


def test_broadcast_not_matched_mid_word():
    assert gl.is_broadcast_mention("join @alliance today") is False


def test_broadcast_false_for_unrelated():
    assert gl.is_broadcast_mention("just a regular message") is False


def test_direct_hanuman_primary():
    assert gl.is_direct_mention("@hanuman can you check this", "hanuman") is True


def test_direct_hanuman_alias():
    assert gl.is_direct_mention("@hanu look at this", "hanuman") is True


def test_direct_vishwakarma_aliases():
    assert gl.is_direct_mention("@vish build it", "vishwakarma") is True
    assert gl.is_direct_mention("@karma deploy now", "vishwakarma") is True


def test_direct_no_match():
    assert gl.is_direct_mention("no one is mentioned here", "hanuman") is False


def test_direct_not_matched_mid_word():
    assert gl.is_direct_mention("@hanuman123 is not hanuman", "hanuman") is False


def test_direct_unknown_seat_uses_its_own_handle():
    assert gl.is_direct_mention("@loki audit this", "loki") is True
    assert gl.is_direct_mention("@lokii audit this", "loki") is False


def test_alias_regex_cached():
    assert gl._alias_regex("@hanuman") is gl._alias_regex("@hanuman")


# ── watch identities ─────────────────────────────────────────────────────────

def test_watch_identities_seat_first_and_deduped():
    assert gl.watch_identities("hanuman", ["loki", "Hanuman", "heimdallr"]) == [
        "hanuman", "loki", "heimdallr"]


def test_watch_identities_no_implied_auto():
    # 2.0 folded in "Auto" by default; willow-mcp has no such seat.
    assert gl.watch_identities("hanuman") == ["hanuman"]


def test_direct_mention_identity():
    ids = gl.watch_identities("hanuman", ["loki"])
    assert gl.direct_mention_identity("@hanu check the logs", ids) == "hanuman"
    assert gl.direct_mention_identity("@loki check the logs", ids) == "loki"
    assert gl.direct_mention_identity("nothing here", ids) is None


# ── classify ─────────────────────────────────────────────────────────────────

def _row(**kw):
    base = {"id": 7, "channel": "general", "sender": "willow", "content": "",
            "to_agent": "", "bus_type": ""}
    base.update(kw)
    return base


def _cls(row, agent="vishwakarma", watch=(), verbose=()):
    return gl.classify(row, agent=agent, identities=gl.watch_identities(agent, watch),
                       verbose=verbose)


def test_classify_broadcast():
    line = _cls(_row(content="@all stand-up in five"))
    assert line == "[MENTION:BROADCAST] #general id=7 willow: @all stand-up in five"


def test_classify_direct_mention_by_alias():
    line = _cls(_row(content="@vish the mapping is confirmed"))
    assert line.startswith("[MENTION:DIRECT:vishwakarma] #general id=7 willow:")


def test_classify_watched_extra_identity():
    line = _cls(_row(content="@loki please audit"), watch=["loki"])
    assert line.startswith("[MENTION:DIRECT:loki]")


def test_classify_bus_addressed_to_me():
    line = _cls(_row(channel="dispatch", bus_type="COMMAND", to_agent="vishwakarma",
                     content="build the deposit"))
    assert line == "[BUS:COMMAND] #dispatch id=7 willow -> vishwakarma: build the deposit"


def test_classify_bus_addressed_to_someone_else_is_silent():
    assert _cls(_row(channel="dispatch", bus_type="COMMAND", to_agent="hanuman",
                     content="build it")) is None


def test_classify_heartbeat_and_ack_are_noise():
    assert _cls(_row(bus_type="HEARTBEAT", to_agent="__all__", content="hanuman online")) is None
    assert _cls(_row(bus_type="ACK", to_agent="vishwakarma", content="ok")) is None


def test_classify_own_channel_is_inbox():
    line = _cls(_row(channel="vishwakarma", content="note for the seat"))
    assert line == "[INBOX] #vishwakarma id=7 willow: note for the seat"


def test_classify_own_posts_never_wake_the_seat():
    assert _cls(_row(sender="vishwakarma", content="@vish talking to myself")) is None
    assert _cls(_row(sender="Vishwakarma", channel="vishwakarma", content="mine")) is None


def test_classify_verbose_channel():
    line = _cls(_row(channel="architecture", sender="loki", content="a thought"),
                verbose=["architecture"])
    assert line == "[CHANNEL] #architecture id=7 loki: a thought"


def test_classify_unrelated_is_silent():
    assert _cls(_row(channel="architecture", sender="loki", content="a thought")) is None


def test_classify_preview_is_one_line_and_capped():
    content = "line one\nline two " + "x" * 200
    line = _cls(_row(content="@all " + content))
    assert "\n" not in line
    assert len(line.split(": ", 1)[1]) == 80


# ── SQL helpers over a fake cursor ───────────────────────────────────────────

def test_drain_channel_advances_cursor_and_shapes_rows():
    cur = MagicMock()
    cur.fetchall.return_value = [
        (10, "willow", "@vish one", "", ""),
        (12, "loki", "two", "vishwakarma", "COMMAND"),
    ]
    cursors = {3: 9}
    rows = gl.drain_channel(cur, 3, "general", cursors)
    assert cursors[3] == 12
    assert [r["id"] for r in rows] == [10, 12]
    assert rows[1] == {"id": 12, "channel": "general", "sender": "loki", "content": "two",
                       "to_agent": "vishwakarma", "bus_type": "COMMAND"}
    sql, params = cur.execute.call_args[0]
    assert "id > %s" in sql and params == (3, 9)


def test_seed_cursors_starts_at_newest():
    cur = MagicMock()
    cur.fetchall.return_value = [(1, 40), (2, 55)]
    assert gl.seed_cursors(cur, [1, 2, 3]) == {1: 40, 2: 55, 3: 0}


def test_seed_cursors_empty_skips_query():
    cur = MagicMock()
    assert gl.seed_cursors(cur, []) == {}
    cur.execute.assert_not_called()


# ── gate ─────────────────────────────────────────────────────────────────────

def test_main_refuses_ungranted_seat_before_connecting(tmp_path, monkeypatch, capsys):
    _manifest(tmp_path, monkeypatch, _APP, ["dispatch_read"])
    monkeypatch.setattr(gl, "connect", MagicMock(side_effect=AssertionError("must not connect")))
    rc = gl.main(argv=["--app-id", _APP, "--log", str(tmp_path / "l.log")])
    assert rc == 2
    assert "gate denied" in capsys.readouterr().err
    assert not (tmp_path / "l.log").exists()


def test_main_refuses_missing_manifest(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path / "empty"))
    monkeypatch.setattr(gl, "connect", MagicMock(side_effect=AssertionError("must not connect")))
    assert gl.main(argv=["--app-id", "nobody", "--log", str(tmp_path / "l.log")]) == 2


def test_read_only_seat_listens_without_heartbeat(tmp_path, monkeypatch):
    _manifest(tmp_path, monkeypatch, _APP, ["grove_read"])
    log = io.StringIO()
    lst = gl.Listener(_APP, log=log, echo=False)
    assert lst.can_write is False
    bus_send = MagicMock()
    monkeypatch.setattr(gl.grove, "bus_send", bus_send)
    lst.conn = MagicMock()
    lst.heartbeat(force=True)
    bus_send.assert_not_called()


def test_granted_seat_heartbeats_as_itself(tmp_path, monkeypatch):
    _manifest(tmp_path, monkeypatch, _APP, ["grove_read", "grove_write"])
    log = io.StringIO()
    lst = gl.Listener(_APP, log=log, echo=False, heartbeat_s=60)
    assert lst.can_write is True
    monkeypatch.setattr(gl.grove, "list_channels", MagicMock(return_value=[{"id": 9, "name": "general"}]))
    monkeypatch.setattr(gl.grove, "find_channel_in", lambda chans, name: chans[0])
    bus_send = MagicMock()
    monkeypatch.setattr(gl.grove, "bus_send", bus_send)
    lst.conn = MagicMock()
    lst.heartbeat(force=True)
    kw = bus_send.call_args.kwargs
    assert kw["sender"] == lst.agent and kw["bus_type"] == "HEARTBEAT" and kw["channel_id"] == 9
    # throttled: a second call inside the interval does nothing
    lst.heartbeat()
    assert bus_send.call_count == 1


# ── loop plumbing ────────────────────────────────────────────────────────────

def _wired(tmp_path, monkeypatch, perms=("grove_read",)):
    _manifest(tmp_path, monkeypatch, _APP, list(perms))
    log = io.StringIO()
    lst = gl.Listener(_APP, log=log, echo=False, heartbeat_s=0)
    return lst, log


def test_once_drains_and_reports(tmp_path, monkeypatch):
    lst, log = _wired(tmp_path, monkeypatch)
    conn = MagicMock()
    cur = MagicMock()
    conn.cursor.return_value = cur
    monkeypatch.setattr(gl, "connect", MagicMock(return_value=conn))
    monkeypatch.setattr(gl, "load_channels", MagicMock(return_value={1: "general"}))
    monkeypatch.setattr(gl, "seed_cursors", MagicMock(return_value={1: 0}))
    monkeypatch.setattr(gl, "drain_channel", MagicMock(return_value=[
        {"id": 5, "channel": "general", "sender": "willow", "content": "@vish hello",
         "to_agent": "", "bus_type": ""}]))
    lst.run(once=True)
    out = log.getvalue()
    assert "[grove-listen] ready as" in out
    assert "[MENTION:DIRECT:vishwakarma] #general id=5 willow: @vish hello" in out
    assert "drained, 1 line(s)" in out
    cur.execute.assert_any_call("LISTEN grove_channel")


def test_reconnect_closes_stale_and_keeps_cursors(tmp_path, monkeypatch):
    lst, log = _wired(tmp_path, monkeypatch)
    stale, fresh = MagicMock(name="stale"), MagicMock(name="fresh")
    monkeypatch.setattr(gl, "connect", MagicMock(side_effect=[stale, fresh]))
    monkeypatch.setattr(gl, "load_channels", MagicMock(return_value={1: "general"}))
    monkeypatch.setattr(gl, "seed_cursors", MagicMock(side_effect=[{1: 10}, {1: 99}]))
    monkeypatch.setattr(gl, "drain_channel", MagicMock(return_value=[]))
    lst.open()
    assert lst.cursors == {1: 10}
    lst.reconnect()
    stale.close.assert_called_once()
    assert lst.conn is fresh
    # the cursor survives the reconnect — re-seeding to MAX would skip the gap
    assert lst.cursors == {1: 10}


def test_run_recovers_from_select_error(tmp_path, monkeypatch):
    lst, log = _wired(tmp_path, monkeypatch)
    conn = MagicMock()
    monkeypatch.setattr(gl, "connect", MagicMock(return_value=conn))
    monkeypatch.setattr(gl, "load_channels", MagicMock(return_value={}))
    monkeypatch.setattr(gl, "seed_cursors", MagicMock(return_value={}))
    calls = {"n": 0}

    def flaky(*_a, **_k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("link down")
        raise KeyboardInterrupt()

    monkeypatch.setattr(gl.select, "select", flaky)
    with pytest.raises(KeyboardInterrupt):
        lst.run()
    assert "link down — reconnecting" in log.getvalue()
    assert gl.connect.call_count == 2


def test_second_instance_exits_clean(tmp_path, monkeypatch, capsys):
    _manifest(tmp_path, monkeypatch, _APP, ["grove_read"])
    log = tmp_path / "l.log"
    held = gl._single_instance(log.with_suffix(".lock"))
    assert held is not None
    monkeypatch.setattr(gl, "connect", MagicMock(side_effect=AssertionError("must not connect")))
    assert gl.main(argv=["--app-id", _APP, "--log", str(log)]) == 0
    assert "already running" in capsys.readouterr().out
    held.close()


def test_default_log_path_under_willow_home(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    assert gl.default_log_path("loki") == tmp_path / "logs" / "grove-listen-loki.log"
