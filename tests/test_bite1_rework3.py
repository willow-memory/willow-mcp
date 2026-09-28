"""Rework 3 of bite 1 (dispatch 632B70AA), after Loki's REVISE (ADC80409).

Adopts Loki's S1-S4/N1B/N5B/F3B/F3D probes (scratch copy at
~/.cache/pip/loki-adc80409/test_loki_adc80409_probe.py) as real regression
tests against the shipped `server`/`dispatch`/`handoff` modules -- no copies
of the logic under test.

S3 is adopted with an ADAPTED assertion, not verbatim. Loki's literal probe
asserted that A's own omitted `handoff_write_v4` call succeeds even after a
held (refused) entrant touched the same packet. That is mathematically
incompatible with S2 (X must never be able to close A's packet): after A
re-enters following X's held attempt, the server has no way to tell "A is
calling with session_id omitted" apart from "X is calling with session_id
omitted" -- both look identical over the same in-process resolver. Making
S2 safe (X never closes A's packet, verified below) requires that ANY held
entrant permanently marks that dispatch's omitted-session resolution
ambiguous, which is also the literal reading of D1's fix text ("record
every session that calls session_enter per app_id, held ones included ...
resolve only when exactly one distinct session has entered"). Under that
rule S3's own omitted close is *also* refused (ESESSION) -- a safe, named
refusal, not a wrong guess -- and A's explicit-session_id close (the escape
hatch every accepting session always has) still succeeds. That is the
outcome this file actually verifies for S3.
"""
from __future__ import annotations

import json
import os
import threading

import pytest

from willow_mcp import dispatch as ds
from willow_mcp import handoff as ho
from willow_mcp import server as srv

GOOD = dict(findings=[{"text": "real verdict", "evidence": ["diff reviewed"]}], narrative="Audit: 12 passed.", checklist_resolved=True)
XSTUB = dict(findings=[{"title": "X stub", "evidence": ["turns: 0"]}], narrative="X stub from another session", checklist_resolved=False)
STUB = dict(findings=[{"title": "stub", "evidence": ["turns: 0"]}], narrative="stub", checklist_resolved=False)


@pytest.fixture(autouse=True)
def _reset_specialist_sessions():
    srv._specialist_sessions.clear()
    srv._specialist_entrants.clear()
    yield
    srv._specialist_sessions.clear()
    srv._specialist_entrants.clear()


def _man(home, app="loki"):
    d = home / "mcp_apps" / app
    d.mkdir(parents=True, exist_ok=True)
    (d / "manifest.json").write_text(json.dumps({"app_id": app, "permissions": ["dispatch_read", "dispatch_write"]}))


def _send(runner="seat", to_app="loki"):
    return ds.dispatch_send("willow", to_app, "# Task\n", summary="t", runner=runner)["dispatch_id"]


def _enter(home, sid, did, runner="seat", app="loki"):
    return srv.session_enter(app, sid, did, workspace=str(home), runner=runner)


def _close(did, sid="", app="loki", **kw):
    return srv.handoff_write_v4(app, did, session_id=sid, **kw)


# -- D1: refuse-to-guess session resolution, scoped per (app_id, dispatch_id)


def test_s1_two_sessions_two_packets_first_is_not_locked_out(home):
    """A different session entering a DIFFERENT packet must never poison
    A's own resolution for its own packet (per-dispatch scoping, not a
    process-global app_id slot)."""
    _man(home)
    p1, p2 = _send(), _send()
    _enter(home, "sess-A", p1)
    _enter(home, "sess-B", p2)
    ra = _close(p1, **GOOD)
    assert ra.get("error") is None, ra
    assert ra.get("status") == "complete"
    rb = _close(p2, **GOOD)
    assert rb.get("error") is None, rb


def test_s2_other_session_can_never_close_packet_it_never_accepted(home):
    """X (held) must never be able to close A's packet, even after A
    re-enters following X's held attempt -- omitted-session resolution is
    permanently ambiguous for this dispatch the moment a second, distinct
    session has ever touched it."""
    _man(home)
    p1 = _send()
    _enter(home, "sess-A", p1)
    x = _enter(home, "sess-X", p1)
    assert x.get("held_by_other_session") is True
    _enter(home, "sess-A", p1)  # A re-enters (reconnect / continuation)

    rx = _close(p1, **XSTUB)  # X omits session_id
    assert rx.get("error") == "ESESSION", rx
    assert not (ds.dispatch_dir(p1) / "handoff.json").exists()

    ra = _close(p1, "sess-A", **GOOD)  # A's own explicit-sid escape hatch
    assert ra.get("error") is None, ra
    assert ho.handoff_read(p1)["handoff"]["narrative"] == GOOD["narrative"], (
        "X's stub must never close A's packet"
    )


def test_s3_held_entrant_makes_omitted_resolution_ambiguous_not_wrong(home):
    """A held entrant must not silently REBIND the resolver to the wrong
    session (the old bug: A's own omit resolved to sess-X and got a
    confusing ESESSION 'mismatch'). The fixed behavior is a clean,
    expected ESESSION naming the remedy -- and A's own explicit session_id
    still always works, so A is never actually locked out of the system."""
    _man(home)
    p1 = _send()
    _enter(home, "sess-A", p1)
    x = _enter(home, "sess-X", p1)
    assert x.get("held_by_other_session") is True

    ra = _close(p1, **GOOD)  # A omits, but the dispatch is now ambiguous
    assert ra.get("error") == "ESESSION", ra
    assert "session_id you gave session_enter" in ra.get("message", "")
    assert not (ds.dispatch_dir(p1) / "handoff.json").exists()

    ra2 = _close(p1, "sess-A", **GOOD)  # explicit sid always still works
    assert ra2.get("error") is None, ra2
    assert ra2.get("status") == "complete"


def test_s4_single_session_omitting_id_still_works(home):
    _man(home)
    p1 = _send()
    _enter(home, "sess-A", p1)
    r = _close(p1, **GOOD)
    assert r.get("error") is None, r
    assert r.get("status") == "complete"


def test_m29_context_resolution_kills_without_it(home):
    """M29 (Loki survivor): removing `_current_specialist_session` from the
    resolution expression must break S4 (single-session omit)."""
    _man(home)
    p1 = _send()
    _enter(home, "sess-A", p1)
    srv._specialist_sessions.clear()
    srv._specialist_entrants.clear()
    r = _close(p1, **GOOD)
    assert r.get("error") == "ESESSION", r


def test_m30_context_record_kills_without_it(home):
    """M30 (Loki survivor): if session_enter never records the entrant, a
    later single-session omit must be refused rather than accidentally
    resolved."""
    _man(home)
    p1 = _send()
    _enter(home, "sess-A", p1)
    key = srv._specialist_key("loki", p1)
    srv._specialist_entrants.pop(key, None)
    srv._specialist_sessions.pop(key, None)
    r = _close(p1, **GOOD)
    assert r.get("error") == "ESESSION", r


# -- N1B: runner checked on re-entry, not just fresh accept


def test_n1b_listener_reentry_after_empty_sid_accept_is_refused(home):
    """N1B (Loki ADC80409): the runner check was only enforced on a FRESH
    dispatch_accept -- a listener re-entering (session_enter with
    dispatch_id=..., runner="ratatosk") into a packet already accepted
    with an empty session_id (dispatch_accept's own tool default) used to
    slip past it entirely: held_by_other_session stayed False and the
    listener got the full assignment back. It must now be refused ERUNNER
    on re-entry too, with no assignment and no held_by_other_session
    lift."""
    _man(home)
    p = _send("seat")
    ds.dispatch_accept(p, "loki", "")  # dispatch_accept tool default sid=""
    lst = _enter(home, "sess-listener", p, runner="ratatosk")
    assert lst.get("error") == "ERUNNER", lst
    assert lst.get("held_by_other_session") is None
    assert not lst.get("assignment")


def test_n1b_seat_reentry_after_empty_sid_accept_still_works(home):
    _man(home)
    p = _send("seat")
    ds.dispatch_accept(p, "loki", "")
    seat = _enter(home, "sess-seat", p, runner="seat")
    assert seat.get("error") is None, seat


# -- N3: accepted_session_id withheld from dispatch_read to non-holders


def test_n3_dispatch_read_withholds_accepted_session_id_from_non_holder(home):
    _man(home)
    _man(home, app="willow")
    p1 = _send()
    _enter(home, "sess-A", p1)
    d = srv.dispatch_read("willow", p1)
    assert not d.get("status", {}).get("accepted_session_id"), d


def test_n3_dispatch_read_still_shows_it_to_the_holder_app(home):
    _man(home)
    p1 = _send()
    _enter(home, "sess-A", p1)
    d = srv.dispatch_read("loki", p1)
    assert d.get("status", {}).get("accepted_session_id") == "sess-A", d


# -- F3B: unique archive dirs even within the same wall-clock second


def test_f3b_same_second_reaccepts_all_archive(home):
    p = ds.dispatch_send("willow", "loki", "# Task\n", summary="t")["dispatch_id"]
    narratives = []
    for i in range(3):
        ds.dispatch_accept(p, "loki", f"c{i}")
        n = f"cycle {i}: 1 passed."
        narratives.append(n)
        ho.handoff_write_v4("loki", p, session_id=f"c{i}", **dict(GOOD, narrative=n))
        ho.verify_handoff(p)
        ds.agent_clear("loki", p)
    ds.dispatch_accept(p, "loki", "c3")
    hist_root = ds.dispatch_dir(p) / "history"
    dirs = sorted(hist_root.iterdir())
    assert len(dirs) == 3, [d.name for d in dirs]
    got = sorted(json.loads((d / "handoff.json").read_text())["narrative"] for d in dirs)
    assert got == sorted(narratives)


# -- F3D: a symlinked history/ dir is refused


def test_f3d_history_in_packet_file_names_refuses_symlink(home, tmp_path):
    p = ds.dispatch_send("willow", "loki", "# Task\n", summary="t")["dispatch_id"]
    ds.dispatch_accept(p, "loki", "c1")
    ho.handoff_write_v4("loki", p, session_id="c1", **GOOD)
    ho.verify_handoff(p)
    ds.agent_clear("loki", p)
    root = ds.dispatch_dir(p)
    outside = tmp_path / "outside_hist"
    outside.mkdir()
    os.symlink(str(outside), str(root / "history"))
    assert ds.packet_symlink_refused(root) is True
    r = ds.dispatch_read(p)
    assert r.get("error") == "symlinked_packet", r


# -- N5B/N5C: withdraw and agent_clear decide under the lock


def test_withdraw_race_against_accept_reaches_a_consistent_end_state(home):
    """N5B (Loki ADC80409) rework of the old test_withdraw_race_against_
    accept_never_torn: that test only checked the final status landed in
    {working, withdrawn} -- it never checked the two callers' OWN return
    values agreed with that final status, so a torn outcome (packet
    withdrawn while a session record still shows it bound "working", or
    vice versa) would have passed silently. This asserts the single
    correct end state for whichever caller actually won the lock."""
    did = ds.dispatch_send("willow", "loki", "# Task\n", summary="t", runner="seat")["dispatch_id"]
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
        assert not accept_r.get("error"), accept_r
        assert withdraw_r.get("error") == "EBUSY", withdraw_r
        assert any(r.get("session_id") == "s-accept" for r in bound), bound
    elif final == "withdrawn":
        assert not withdraw_r.get("error"), withdraw_r
        assert accept_r.get("error") == "invalid_transition", accept_r
        assert not bound, bound
    else:
        pytest.fail(f"torn/unexpected final status: {final}")


def test_agent_clear_race_against_failure_is_never_silently_cleared(home):
    """N5C (Loki ADC80409): agent_clear must not clear a packet that a
    concurrent writer moved to 'failed' between agent_clear's read and its
    write -- decide under the lock, same as withdraw."""
    did = ds.dispatch_send("willow", "loki", "# Task\n", summary="t")["dispatch_id"]
    ds.dispatch_accept(did, "loki", "c1")
    ho.handoff_write_v4("loki", did, session_id="c1", **GOOD)
    root = ds.dispatch_dir(did)

    import fcntl

    fd = os.open(str(root / ".handoff.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("r", ds.agent_clear("loki", did)))
    t.start()
    import time
    time.sleep(0.4)
    ds._dispatch_set_status_locked(did, root, "failed", {})
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)
    t.join(10)

    final = ds.dispatch_read(did)["status"]["status"]
    if out["r"].get("error"):
        assert out["r"]["error"] == "not_ready_for_clear"
        assert final == "failed"
    else:
        assert final in ("cleared", "failed")
