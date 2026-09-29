"""Loki 6FC22847 residual probes: print-first; assertions mark what the desk
asked for.

Adaptation note (test_r_empty_sid_enter): Loki's literal probe expected
ERUNNER for an empty session_id entering with a mismatched runner. The
packet's own fix (G2) refuses the empty session_id first -- EINVAL -- before
the runner check ever runs, since a dispatch entry always names the session
entering it. The assertion below reflects that decision, not Loki's literal
analysis, per this file's own docstring: assertions mark what the desk
asked for."""
import json

import pytest

from willow_mcp import dispatch as ds
from willow_mcp import handoff as ho
from willow_mcp import server as srv

GOOD = dict(findings=[{"text": "real verdict", "evidence": ["diff reviewed"]}], narrative="Audit: 12 passed.", checklist_resolved=True)
XSTUB = dict(findings=[{"title": "X stub", "evidence": ["turns: 0"]}], narrative="X stub from another session", checklist_resolved=False)


def _clear_ctx():
    srv._buckets.clear()
    for n in ("_specialist_sessions", "_specialist_entrants"):
        getattr(srv, n, {}).clear()


@pytest.fixture(autouse=True)
def _reset():
    _clear_ctx()
    yield
    _clear_ctx()


def _man(home, app="loki"):
    d = home / "mcp_apps" / app
    d.mkdir(parents=True, exist_ok=True)
    (d / "manifest.json").write_text(json.dumps({"app_id": app, "permissions": ["dispatch_read", "dispatch_write"]}))


def _send(runner="seat"):
    return ds.dispatch_send("willow", "loki", "# Task\n", summary="t", runner=runner)["dispatch_id"]


def _enter(home, sid, did, runner="seat"):
    srv._buckets.clear()
    return srv.session_enter("loki", sid, did, workspace=str(home), runner=runner)


def _close(did, sid="", **kw):
    srv._buckets.clear()
    return srv.handoff_write_v4("loki", did, session_id=sid, **kw)


def test_r_s3_literal(home):
    """The ADC80409 LITERAL S3 expectation (A's own omit still succeeds after
    a held X touched the packet) is superseded by the S3-strict rule
    test_bite1_rework3.py ships and documents: a held entrant permanently
    marks the omitted-session resolution ambiguous for this dispatch, so
    A's omit is refused (a clean, named ESESSION) and only A's own explicit
    session_id still works. This test records that the literal S3 reading
    is intentionally NOT what is shipped."""
    _man(home)
    p = _send()
    _enter(home, "sess-A", p)
    _enter(home, "sess-X", p)
    r = _close(p, **GOOD)
    print("RES S3-literal A-omit", r.get("error"))
    assert r.get("error") == "ESESSION"


def test_r_x_echo_same_app(home):
    """X (same app_id) reads the packet through the real dispatch_read tool and echoes the id."""
    _man(home)
    p = _send()
    _enter(home, "sess-A", p)
    x = _enter(home, "sess-X", p)
    srv._buckets.clear()
    d = srv.dispatch_read("loki", p)
    disclosed = d.get("status", {}).get("accepted_session_id")
    r = _close(p, disclosed or "", **XSTUB)
    narr = (ho.handoff_read(p).get("handoff") or {}).get("narrative")
    print("RES X-echo held", x.get("held_by_other_session"), "disclosed", repr(disclosed), "close", r.get("error"), r.get("status"), "narr", narr)
    assert not disclosed


def test_r_other_app_cannot_close(home):
    """The party N3 now redacts from: can it close the packet at all?"""
    _man(home)
    _man(home, "willow")
    _man(home, "ada")
    p = _send()
    _enter(home, "sess-A", p)
    out = {}
    for app in ("willow", "ada"):
        srv._buckets.clear()
        r = srv.handoff_write_v4(app, p, session_id="sess-A", **XSTUB)
        out[app] = r.get("error")
    print("RES other-app close with bearer", out, "handoff exists", (ds.dispatch_dir(p) / "handoff.json").exists())


def test_r_empty_sid_enter(home):
    """session_enter with session_id='' on a packet A holds: G2 refuses the
    empty session_id outright (EINVAL), before the runner check that Loki's
    literal probe named (ERUNNER) ever runs -- see module docstring."""
    _man(home)
    p = _send()
    _enter(home, "sess-A", p)
    e = _enter(home, "", p, runner="ratatosk")
    print("RES empty-sid enter err", e.get("error"), "held", e.get("held_by_other_session"), "alen", len(e.get("assignment") or ""), "acc", repr(e.get("accepted_session_id")))
    assert e.get("error") == "EINVAL"
    assert not e.get("assignment")
    assert "accepted_session_id" not in e


@pytest.mark.xfail(strict=True, reason=(
    "G2b (Loki 74DA52ED): dispatch_accept's empty/whitespace session_id "
    "was found to be load-bearing across dozens of real callers -- "
    "tests/test_dispatch_withdraw.py::test_withdraw_working_with_no_live_"
    "session_succeeds documents accept-with-no-session as an intended "
    "lifecycle shape, and tests/test_dispatch_stack.py, "
    "tests/test_at_m2_dispatch_lifecycle.py, tests/test_bite1_rework3.py "
    "and tests/test_loki_6fc22847_probe.py all call dispatch_accept with "
    "no session_id as their normal, low-ceremony accept path. An EINVAL "
    "guard on dispatch_accept broke all of them. The hole stays open; "
    "this pins the gap as a strict xfail rather than silently accepting "
    "it as correct."
))
def test_r_empty_accept_then_x(home):
    """Packet accepted with session_id='' (dispatch_accept tool default):
    nothing was recorded at accept time to check a later caller against, so
    the pre-existing permissive behavior holds (same shape as
    test_no_session_check_when_packet_was_accepted_without_one in
    test_handoff_write_once_concurrency.py) -- X's omitted-session write
    succeeds, it is NOT refused ESESSION even though it should be. This
    test asserts the refusal G2b calls for; it stays red (xfail) until the
    hole is actually closed without breaking the real callers named above."""
    _man(home)
    p = _send()
    ds.dispatch_accept(p, "loki", "")
    x = _enter(home, "sess-X", p)
    r = _close(p, **XSTUB)
    print("RES empty-accept X enter held", x.get("held_by_other_session"), "X-omit", r.get("error"), r.get("status"))
    assert r.get("error") == "ESESSION"


def test_r_resume_without_dispatch_id(home):
    """A re-enters with no dispatch_id (resume via its session file) in a
    fresh process -- the resume itself works (dispatch_id and entry_mode
    resolve correctly from the session record), but
    server._set_specialist_session records THIS resume's entrant under
    the LITERAL dispatch_id ARGUMENT ("", not the resolved dispatch_id --
    see server._specialist_key/_set_specialist_session, which key on the
    caller's own dispatch_id parameter, not on result["dispatch_id"]).
    _clear_ctx() before it only simulates a fresh process by wiping the
    in-memory entrant/session caches entirely; it is not itself what
    keys the resume's entry to the wrong slot. So the resolver, keyed on
    the REAL dispatch_id at close time, finds no entrant recorded for it
    at all, and a SUBSEQUENT omitted close cannot be resolved
    unambiguously -- ESESSION, not a silent success. Pre-existing
    behavior, unrelated to G1/G2/G3."""
    _man(home)
    p = _send()
    _enter(home, "sess-A", p)
    _clear_ctx()
    e = _enter(home, "sess-A", "")
    r = _close(p, **GOOD)
    print("RES resume did", e.get("dispatch_id"), e.get("entry_mode"), "A-omit", r.get("error"), r.get("status"))
    assert r.get("error") == "ESESSION"


def test_r_n5b_window_between_accept_status_and_bind(home, monkeypatch):
    """dispatch_accept now writes status AND binds the session under the SAME
    lock (G3) -- a withdraw that wants the lock in the old window between
    them now simply blocks until the accept finishes, so no torn state is
    observable regardless of which caller's own return value 'wins'."""
    import threading
    p = _send()
    real_bind = ds.session_bind
    in_window = threading.Event()
    go_on = threading.Event()

    def slow_bind(app_id, session_id, dispatch_id, status, **kw):
        if dispatch_id == p and status == "working":
            in_window.set()
            go_on.wait(5)
        return real_bind(app_id, session_id, dispatch_id, status, **kw)
    monkeypatch.setattr(ds, "session_bind", slow_bind)
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("acc", ds.dispatch_accept(p, "loki", "s-accept")))
    t.start()
    assert in_window.wait(5)
    w = ds.dispatch_withdraw(p, "no longer needed", by_app="willow")
    go_on.set()
    t.join(10)
    final = ds.dispatch_read(p)["status"]["status"]
    bound = [r.get("session_id") for r in ds._sessions_bound_to("loki", p)]
    print("RES N5B-window accept", out["acc"].get("error") or out["acc"]["status"]["status"], "| withdraw", w.get("error") or w.get("status"), "| final", final, "| bound", bound)
    assert not (final == "withdrawn" and bound), "torn: withdrawn packet with a session bound working"


def test_r_cleared_reenter_via_session_enter(home):
    """Recurring packet: new session c2 enters a CLEARED packet through session_enter."""
    _man(home)
    p = _send()
    _enter(home, "c1", p)
    _close(p, "c1", **GOOD)
    ho.verify_handoff(p)
    ds.agent_clear("loki", p)
    e = _enter(home, "c2", p)
    print("RES cleared re-enter err", e.get("error"), "held", e.get("held_by_other_session"), "status", ds.dispatch_read(p)["status"]["status"])
