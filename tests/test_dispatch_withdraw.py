"""dispatch_withdraw and the end of autoclaim (gaps afa515539c0a / 22c8c1aab079).

Before this, a packet the orchestrator no longer wanted worked had no
terminal state short of somebody accepting and closing it, and a bare
session_enter handed the seat's oldest pending packet to whoever entered
next. Now: `withdrawn` is a terminal status only the orchestrator writes,
excluded from pending lists, refused by every entry verb; a bare
session_enter names pending packets and binds none.
"""
import json

import pytest

from willow_mcp import dispatch as ds
from willow_mcp import handoff as ho
from willow_mcp import server


@pytest.fixture(autouse=True)
def _fresh_rate_buckets():
    server._buckets.clear()
    yield
    server._buckets.clear()


def _write_manifest(home, app_id, permissions):
    d = home / "mcp_apps" / app_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "manifest.json").write_text(
        json.dumps({"app_id": app_id, "permissions": permissions})
    )


@pytest.fixture
def seats(home, monkeypatch):
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    _write_manifest(home, "willow", ["orchestrator"])
    _write_manifest(home, "hanuman", ["dispatch_read", "dispatch_write"])
    _write_manifest(home, "loki", ["dispatch_read", "dispatch_write"])
    return home


def _pending(to_app="hanuman"):
    return ds.dispatch_send("willow", to_app, "# Task\n\nDo it.\n", summary="task")["dispatch_id"]


# ── the stack verb ───────────────────────────────────────────────────────────

def test_withdraw_pending_is_terminal_and_ledgered_in_status(home):
    did = _pending()
    out = ds.dispatch_withdraw(did, "superseded by a newer packet", by_app="willow")
    assert out == {
        "dispatch_id": did, "previous": "pending", "status": "withdrawn",
        "to_app": "hanuman", "reason": "superseded by a newer packet",
    }
    status = json.loads((home / "dispatch" / did / "status.json").read_text())
    assert status["status"] == "withdrawn"
    assert status["withdrawn_by"] == "willow"
    assert status["withdraw_reason"] == "superseded by a newer packet"
    assert status["withdrawn_at"]
    # meta is re-signed, so the packet still reads as a valid packet
    assert ds.dispatch_read(did)["status"]["status"] == "withdrawn"


def test_withdraw_requires_a_reason(home):
    did = _pending()
    assert ds.dispatch_withdraw(did, "   ", by_app="willow")["error"] == "reason_required"
    assert ds.dispatch_read(did)["status"]["status"] == "pending"


def test_withdraw_twice_says_already(home):
    did = _pending()
    ds.dispatch_withdraw(did, "no longer needed", by_app="willow")
    again = ds.dispatch_withdraw(did, "no longer needed", by_app="willow")
    assert again["error"] == "already"
    assert again["status"] == "withdrawn"


def test_withdraw_unknown_packet(home):
    assert ds.dispatch_withdraw("00000000", "x", by_app="willow")["error"]


def test_withdraw_working_with_live_session_is_ebusy_naming_the_reconcile_path(home):
    did = _pending()
    ds.session_enter("hanuman", "sess-live", dispatch_id=did)
    out = ds.dispatch_withdraw(did, "changed my mind", by_app="willow")
    assert out["error"] == "EBUSY"
    assert out["sessions"] == ["sess-live"]
    assert out["reconcile"] == [
        {"tool": "session_reconcile", "app_id": "hanuman", "session_id": "sess-live"}
    ]
    assert "sess-live" in out["message"] and "session_reconcile" in out["message"]
    assert "force=True" in out["message"]
    assert ds.dispatch_read(did)["status"]["status"] == "working"


def test_accepted_then_dead_seat_is_ebusy_until_forced(home):
    """Loki 40A353F2 B1: dispatch_accept binds a session, so a dead seat's
    packet stays EBUSY; the orchestrator withdraws it with force=True and
    the forced-over sessions are recorded on the packet."""
    did = _pending()
    ds.dispatch_accept(did, "hanuman", session_id="sess-dead")
    assert ds.dispatch_withdraw(did, "seat is gone", by_app="willow")["error"] == "EBUSY"
    out = ds.dispatch_withdraw(did, "seat is gone", by_app="willow", force=True)
    assert out["status"] == "withdrawn" and out["previous"] == "working"
    assert out["forced_over_sessions"] == ["sess-dead"]
    status = json.loads((home / "dispatch" / did / "status.json").read_text())
    assert status["forced_over_sessions"] == ["sess-dead"]


def test_force_is_honoured_for_the_orchestrator_only(home):
    did = _pending()
    ds.dispatch_accept(did, "hanuman", session_id="sess-dead")
    out = ds.dispatch_withdraw(did, "mine", by_app="loki", force=True)
    assert out["error"] == "EBUSY"
    assert ds.dispatch_read(did)["status"]["status"] == "working"


def test_force_on_a_pending_packet_records_nothing_extra(home):
    did = _pending()
    out = ds.dispatch_withdraw(did, "dropped", by_app="willow", force=True)
    assert out["status"] == "withdrawn"
    assert "forced_over_sessions" not in out
    status = json.loads((home / "dispatch" / did / "status.json").read_text())
    assert "forced_over_sessions" not in status


def test_withdraw_working_with_no_live_session_succeeds(home):
    did = _pending()
    # accepted but never entered: no session record binds it
    ds.dispatch_accept(did, "hanuman")
    assert ds.dispatch_read(did)["status"]["status"] == "working"
    out = ds.dispatch_withdraw(did, "abandoned", by_app="willow")
    assert out["previous"] == "working"
    assert out["status"] == "withdrawn"


def test_withdraw_working_after_session_went_idle_succeeds(home):
    did = _pending()
    ds.session_enter("hanuman", "sess-gone", dispatch_id=did)
    # the seat wrote a human closeout and released the packet
    ds.session_bind("hanuman", "sess-gone", "", "idle")
    out = ds.dispatch_withdraw(did, "seat released it", by_app="willow")
    assert out["status"] == "withdrawn"


@pytest.mark.parametrize("closer", ["complete", "verified", "cleared"])
def test_withdraw_refuses_closed_packets(home, closer):
    did = _pending()
    ds.dispatch_accept(did, "hanuman")
    ho.handoff_write_v4(
        "hanuman", did, narrative="Did it: 3 checks, 0 issues.", findings=[],
        no_findings_reason="test fixture: withdraw-refusal test",
    )
    if closer in ("verified", "cleared"):
        assert ho.verify_handoff(did).get("verified") is True
    if closer == "cleared":
        ds.agent_clear("hanuman", did)
    out = ds.dispatch_withdraw(did, "too late", by_app="willow")
    assert out["error"] == "invalid_transition"
    assert out["from"] == closer
    assert out["to"] == "withdrawn"


# ── withdrawn is terminal for every entry verb ───────────────────────────────

def test_withdrawn_is_excluded_from_pending_lists(home):
    kept = _pending()
    gone = _pending()
    ds.dispatch_withdraw(gone, "dropped", by_app="willow")
    ids = [r["dispatch_id"] for r in ds.dispatch_list(to_app="hanuman", status="pending")["dispatches"]]
    assert kept in ids
    assert gone not in ids
    listed = {r["dispatch_id"]: r["status"] for r in ds.dispatch_list(to_app="hanuman")["dispatches"]}
    assert listed[gone] == "withdrawn"


def test_withdrawn_refuses_accept_enter_and_handoff(home):
    did = _pending()
    ds.dispatch_withdraw(did, "dropped", by_app="willow")

    acc = ds.dispatch_accept(did, "hanuman", session_id="s1")
    assert acc["error"] == "invalid_transition"
    assert acc["from"] == "withdrawn"

    ent = ds.session_enter("hanuman", "s2", dispatch_id=did)
    assert ent["error"] == "invalid_transition"
    assert ent["from"] == "withdrawn"
    assert "withdrawn" in ent["message"]

    hand = ho.handoff_write_v4("hanuman", did, narrative="done", findings=[])
    assert hand["error"] == "invalid_transition"
    assert hand["from"] == "withdrawn"
    assert not (home / "dispatch" / did / "handoff.json").exists()


def test_bare_session_enter_does_not_claim_a_withdrawn_or_pending_packet(home):
    live = _pending()
    gone = _pending()
    ds.dispatch_withdraw(gone, "dropped", by_app="willow")
    out = ds.session_enter("hanuman", "sess-bare")
    assert out["entry_mode"] == "human"
    assert out["dispatch_id"] is None
    assert out["pending_dispatches"] == [live]
    assert ds.dispatch_read(live)["status"]["status"] == "pending"


# ── the MCP tool: orchestrator-only, human-attested, receipted ───────────────

def test_tool_refuses_builder_seat(seats):
    did = _pending()
    out = server.dispatch_withdraw("hanuman", did, "mine to drop?")
    assert "error" in out
    assert "not permitted for 'dispatch_withdraw'" in out["error"]
    assert ds.dispatch_read(did)["status"]["status"] == "pending"


def test_tool_refuses_unattested_orchestrator(seats, monkeypatch):
    monkeypatch.delenv("WILLOW_HUMAN_ORCHESTRATOR", raising=False)
    did = _pending()
    out = server.dispatch_withdraw("willow", did, "drop")
    assert "orchestrator_human_required" in out["error"]
    assert "dispatch_withdraw" in out["error"]


def test_tool_withdraws_for_attested_orchestrator(seats, monkeypatch):
    monkeypatch.setattr(server, "get_pg", lambda: None)
    did = _pending()
    out = server.dispatch_withdraw("willow", did, "superseded")
    assert out["status"] == "withdrawn"
    assert out["previous"] == "pending"
    assert out["dispatch_id"] == did
    # no ledger reachable is said, not hidden
    assert out["frank_error"] == "postgres_unavailable"
    tail = server._receipt_log.tail("willow", 5)
    assert any(r["tool"] == "dispatch_withdraw" for r in tail)


def test_tool_writes_frank_event_when_ledger_reachable(seats, monkeypatch):
    appended = []

    class _Ledger:
        def __init__(self, pg):
            self.pg = pg

        def append(self, project, event_type, content):
            appended.append((project, event_type, content))
            return 4242

    import willow_mcp.governance_ledger as gl
    monkeypatch.setattr(gl, "GovernanceLedger", _Ledger)
    monkeypatch.setattr(server, "get_pg", lambda: object())
    did = _pending()
    out = server.dispatch_withdraw("willow", did, "superseded by 03DCABBB")
    assert out["frank_id"] == 4242
    (project, event_type, content), = appended
    assert event_type == "dispatch_withdraw"
    assert content["dispatch_id"] == did
    assert content["previous"] == "pending"
    assert content["reason"] == "superseded by 03DCABBB"
    assert content["actor"] == "willow"
    assert content["forced"] is False and content["forced_over_sessions"] == []


def test_tool_forced_withdraw_lists_the_bound_sessions_in_frank(seats, monkeypatch):
    appended = []

    class _Ledger:
        def __init__(self, pg):
            pass

        def append(self, project, event_type, content):
            appended.append(content)
            return 7

    import willow_mcp.governance_ledger as gl
    monkeypatch.setattr(gl, "GovernanceLedger", _Ledger)
    monkeypatch.setattr(server, "get_pg", lambda: object())
    did = _pending()
    ds.dispatch_accept(did, "hanuman", session_id="sess-dead")
    busy = server.dispatch_withdraw("willow", did, "seat is gone")
    assert busy["error"] == "EBUSY" and busy["reconcile"][0]["session_id"] == "sess-dead"
    out = server.dispatch_withdraw("willow", did, "seat is gone", force=True)
    assert out["status"] == "withdrawn" and out["frank_id"] == 7
    (content,) = appended
    assert content["forced"] is True
    assert content["forced_over_sessions"] == ["sess-dead"]


def test_tool_ebusy_passes_through(seats, monkeypatch):
    monkeypatch.setattr(server, "get_pg", lambda: None)
    did = _pending()
    ds.session_enter("hanuman", "sess-live", dispatch_id=did)
    out = server.dispatch_withdraw("willow", did, "drop")
    assert out["error"] == "EBUSY"
    assert "frank_id" not in out
