"""Rework 2 of bite 1 (dispatch 1AD03A64), after Loki's REVISE (10A39E21):
listener opt-in via a packet `runner`, session_id resolved from request
context, the bound id withheld from non-holders, correct handling of a
lost accept race, archive-on-re-accept, the O_NOFOLLOW lockfile, and
dispatch_set_status taking the lock for callers that don't already hold
it.
"""
from __future__ import annotations

import json
import os
import threading

import pytest

from willow_mcp import dispatch as ds
from willow_mcp import dispatch_signing
from willow_mcp import handoff as ho
from willow_mcp import server as srv

GOOD = dict(
    findings=[{"text": "real verdict", "evidence": ["diff reviewed"]}],
    narrative="Audit: 12 passed.",
    checklist_resolved=True,
)


def _send(runner: str = "seat", to_app: str = "loki"):
    return ds.dispatch_send(
        "willow", to_app, "# Task\n", summary="t", runner=runner,
    )["dispatch_id"]


# ── N1: listener opt-in ──────────────────────────────────────────────────


def test_listener_first_accept_on_seat_packet_is_refused_then_real_seat_wins(home):
    did = _send(runner="seat")
    listener = ds.dispatch_accept(did, "loki", "listener-sid", runner="ratatosk")
    assert listener.get("error") == "ERUNNER", listener
    assert ds.dispatch_read(did)["status"]["status"] == "pending"
    real = ds.dispatch_accept(did, "loki", "real-sid", runner="seat")
    assert real["status"]["status"] == "working"
    assert real["status"]["accepted_session_id"] == "real-sid"
    close = ho.handoff_write_v4("loki", did, session_id="real-sid", **GOOD)
    assert close["status"] == "complete"


def test_ratatosk_packet_is_accepted_by_the_listener(home):
    did = _send(runner="ratatosk")
    r = ds.dispatch_accept(did, "loki", "listener-sid", runner="ratatosk")
    assert r["status"]["status"] == "working"


def test_both_runner_mismatches_are_refused(home):
    seat_pkt = _send(runner="seat")
    r1 = ds.dispatch_accept(seat_pkt, "loki", "s1", runner="ratatosk")
    assert r1.get("error") == "ERUNNER"
    assert ds.dispatch_read(seat_pkt)["status"]["status"] == "pending"

    rat_pkt = _send(runner="ratatosk")
    r2 = ds.dispatch_accept(rat_pkt, "loki", "s2", runner="seat")
    assert r2.get("error") == "ERUNNER"
    assert ds.dispatch_read(rat_pkt)["status"]["status"] == "pending"


def test_legacy_packet_without_runner_field_counts_as_seat(home):
    did = ds.dispatch_send("willow", "loki", "# Task\n", summary="t")["dispatch_id"]
    meta_path = ds.dispatch_dir(did) / "meta.json"
    meta = json.loads(meta_path.read_text())
    meta.pop("runner", None)
    meta["signature"] = dispatch_signing.sign_meta(meta)
    meta_path.write_text(json.dumps(meta, indent=2) + "\n")
    r = ds.dispatch_accept(did, "loki", "s1", runner="ratatosk")
    assert r.get("error") == "ERUNNER"
    r2 = ds.dispatch_accept(did, "loki", "s1", runner="seat")
    assert r2["status"]["status"] == "working"


def test_dispatch_send_rejects_an_unknown_runner(home):
    r = ds.dispatch_send("willow", "loki", "# Task\n", summary="t", runner="bogus")
    assert r.get("error") == "EINVAL", r


def test_session_enter_pending_accept_surfaces_erunner(home):
    did = _send(runner="ratatosk")
    r = ds.session_enter(app_id="loki", session_id="s1", dispatch_id=did, runner="seat")
    assert r.get("error") == "ERUNNER", r
    assert ds.dispatch_read(did)["status"]["status"] == "pending"


# ── N2: session resolved from request context ────────────────────────────


def test_specialist_session_store_round_trips(home):
    assert srv._current_specialist_session("loki-ctx") == ""
    srv._set_specialist_session("loki-ctx", "ctx-sid")
    assert srv._current_specialist_session("loki-ctx") == "ctx-sid"
    assert srv._current_specialist_session("LOKI-CTX") == "ctx-sid"


def test_handoff_resolves_session_id_from_recorded_context_and_succeeds(home):
    did = ds.dispatch_send("willow", "loki", "# Task\n", summary="t")["dispatch_id"]
    srv._set_specialist_session("loki", "ctx-sid")
    ds.dispatch_accept(did, "loki", "ctx-sid")
    resolved = "" or srv._current_specialist_session("loki")
    assert resolved == "ctx-sid"
    r = ho.handoff_write_v4("loki", did, session_id=resolved, **GOOD)
    assert r["status"] == "complete", r


def test_handoff_esession_names_the_remedy_when_nothing_resolves(home):
    did = ds.dispatch_send("willow", "loki", "# Task\n", summary="t")["dispatch_id"]
    ds.dispatch_accept(did, "loki", "accepted-sid")
    resolved = "" or srv._current_specialist_session("some-unbound-app")
    assert resolved == ""
    r = ho.handoff_write_v4("loki", did, session_id=resolved, **GOOD)
    assert r.get("error") == "ESESSION", r
    assert "session_enter" in r["message"]


# ── N4: concurrent session_enter losers never get a success-shaped empty
#    result -- either they're told they're held, or they get a real error.


def test_concurrent_session_enter_losers_never_look_like_empty_success(home):
    did = _send(runner="seat")
    results = [None] * 8
    barrier = threading.Barrier(8)

    def worker(i):
        barrier.wait()
        results[i] = ds.session_enter(
            app_id="loki", session_id=f"s{i}", dispatch_id=did,
        )

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=10)

    winners = [r for r in results if r.get("status") == "working" and not r.get("held_by_other_session")]
    assert len(winners) == 1, results
    for r in results:
        if r is winners[0]:
            continue
        assert r.get("held_by_other_session") is True or r.get("error"), r
        assert r.get("assignment", "__missing__") != "" or r.get("error"), r


# ── F3: archive on re-accept ──────────────────────────────────────────────


def test_cleared_reaccept_archives_prior_handoff_and_allows_fresh_write(home):
    did = _send(runner="seat")
    ds.dispatch_accept(did, "loki", "cycle-1")
    r1 = ho.handoff_write_v4("loki", did, session_id="cycle-1", **GOOD)
    assert r1["status"] == "complete"
    old_handoff_bytes = (ds.dispatch_dir(did) / "handoff.json").read_bytes()
    v1 = ho.verify_handoff(did)
    assert v1["verified"] is True
    assert v1["history_count"] == 0
    ds.agent_clear("loki", did)
    assert ds.dispatch_read(did)["status"]["status"] == "cleared"

    acc2 = ds.dispatch_accept(did, "loki", "cycle-2")
    assert acc2["status"]["status"] == "working"
    hist_dir = ds.dispatch_dir(did) / "history"
    assert hist_dir.is_dir()
    cycles = list(hist_dir.iterdir())
    assert len(cycles) == 1
    assert (cycles[0] / "handoff.json").read_bytes() == old_handoff_bytes

    second = dict(GOOD)
    second["narrative"] = "Second cycle audit: 3 passed."
    r2 = ho.handoff_write_v4("loki", did, session_id="cycle-2", **second)
    assert r2["status"] == "complete", r2
    v2 = ho.verify_handoff(did)
    assert v2["verified"] is True
    assert v2["history_count"] == 1


def test_eclosed_refusal_names_the_real_status_not_a_hardcoded_complete(home, monkeypatch):
    """F3/Loki 10A39E21 F3: if a stale handoff.json ever sits next to a
    'working' packet (e.g. the archive step failing), the lost-create-race
    refusal must report the packet's REAL status, not a hardcoded
    'complete'."""
    did = _send(runner="seat")
    ds.dispatch_accept(did, "loki", "s1")
    root = ds.dispatch_dir(did)
    root.mkdir(parents=True, exist_ok=True)
    (root / "handoff.json").write_text('{"stale": true}\n', encoding="utf-8")
    r = ho.handoff_write_v4("loki", did, session_id="s1", **GOOD)
    assert r.get("error") == "ECLOSED", r
    assert r["status"] == "working"


# ── F6: atomic handoff.json create (temp + os.link) ───────────────────────


def test_create_handoff_exclusive_uses_link_and_only_one_thread_wins(home, tmp_path):
    target = tmp_path / "handoff.json"
    results = []
    lock = threading.Lock()
    barrier = threading.Barrier(6)

    def worker(i):
        barrier.wait()
        ok = ho._create_handoff_exclusive(target, {"n": i})
        with lock:
            results.append(ok)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=10)

    assert results.count(True) == 1
    assert results.count(False) == 5
    assert target.exists()
    leftovers = [p for p in tmp_path.iterdir() if p.name.startswith(".handoff.json.")]
    assert leftovers == []


# ── N7: lockfile symlink refused via O_NOFOLLOW ───────────────────────────


def test_packet_lock_refuses_a_symlinked_lockfile(home, tmp_path):
    did = _send(runner="seat")
    root = ds.dispatch_dir(did)
    outside = tmp_path / "outside.lock"
    lock_path = root / ".handoff.lock"
    if lock_path.exists():
        lock_path.unlink()
    os.symlink(str(outside), str(lock_path))
    with pytest.raises(OSError):
        with ds.packet_lock(root):
            pass
    assert not outside.exists()


def test_handoff_lock_is_in_packet_file_names(home):
    assert ".handoff.lock" in ds.PACKET_FILE_NAMES
    did = _send(runner="seat")
    root = ds.dispatch_dir(did)
    ds.dispatch_accept(did, "loki", "s1")
    lock_path = root / ".handoff.lock"
    lock_path.unlink()
    outside = root.parent / "outside-target.txt"
    outside.write_text("secret", encoding="utf-8")
    os.symlink(str(outside), str(lock_path))
    assert ds.packet_symlink_refused(root) is True


# ── N5: dispatch_set_status takes the lock for callers that don't have it ─


def test_withdraw_race_against_accept_never_torn(home):
    """N5B (Loki ADC80409) rework: the old version of this test only
    checked the FINAL status landed in {working, withdrawn} -- it never
    checked the two callers' own return values agreed with that final
    status, so a torn outcome (e.g. the packet ends up "withdrawn" while
    a session record still shows it bound "working" to a packet nobody
    told was gone) would have passed silently. Both withdraw and accept
    now decide under packet_lock (dispatch.py), so the race resolves to
    exactly one of two internally consistent end states -- assert which
    one, and that it is consistent, not just that the status string is
    one of two values."""
    did = _send(runner="seat")
    outcomes = {}
    lock = threading.Lock()
    barrier = threading.Barrier(2)

    def do_accept():
        barrier.wait()
        r = ds.dispatch_accept(did, "loki", "s-accept")
        with lock:
            outcomes["accept"] = r

    def do_withdraw():
        barrier.wait()
        r = ds.dispatch_withdraw(did, "no longer needed", by_app="willow")
        with lock:
            outcomes["withdraw"] = r

    t1 = threading.Thread(target=do_accept)
    t2 = threading.Thread(target=do_withdraw)
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    final = ds.dispatch_read(did)["status"]["status"]
    accept_r, withdraw_r = outcomes["accept"], outcomes["withdraw"]
    bound = ds._sessions_bound_to("loki", did)

    if final == "working":
        # accept won the lock first: withdraw must have seen the bound
        # session and refused EBUSY -- a working packet bound to a
        # session is never withdrawn.
        assert not accept_r.get("error"), accept_r
        assert withdraw_r.get("error") == "EBUSY", withdraw_r
        assert any(r.get("session_id") == "s-accept" for r in bound), bound
    elif final == "withdrawn":
        # withdraw won the lock first: accept must have seen the packet
        # already withdrawn and refused invalid_transition -- no session
        # is left bound to a withdrawn packet.
        assert not withdraw_r.get("error"), withdraw_r
        assert accept_r.get("error") == "invalid_transition", accept_r
        assert not bound, bound
    else:
        pytest.fail(f"torn/unexpected final status: {final}")


def test_verify_handoff_and_agent_clear_still_work_after_locking_change(home):
    did = _send(runner="seat")
    ds.dispatch_accept(did, "loki", "s1")
    ho.handoff_write_v4("loki", did, session_id="s1", **GOOD)
    v = ho.verify_handoff(did)
    assert v["verified"] is True
    c = ds.agent_clear("loki", did)
    assert c["status"] == "cleared"
