"""Loki 74DA52ED probes against 9dc836c: G1 bearer sweep, G2 empty-id, G3 accept window + idle rule."""
import inspect
import json
import threading

import pytest

from willow_mcp import dispatch as ds
from willow_mcp import server as srv

SID = "SECRETSID-A-7f3e"
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
    (d / "manifest.json").write_text(json.dumps({"app_id": app, "permissions": ["full_access", "dispatch_read", "dispatch_write"]}))


def _send():
    return ds.dispatch_send("willow", "loki", "# Task\n", summary="t")["dispatch_id"]


def _enter(home, sid, did, app="loki"):
    srv._buckets.clear()
    return srv.session_enter(app, sid, did, workspace=str(home))


def _call(name, **given):
    fn = getattr(srv, name, None)
    if fn is None:
        return "<absent>"
    target = inspect.unwrap(fn)
    kw = {}
    for p in inspect.signature(target).parameters.values():
        if p.name in given:
            kw[p.name] = given[p.name]
    srv._buckets.clear()
    try:
        return fn(**kw)
    except Exception as e:  # noqa: BLE001
        return f"<exc {type(e).__name__}: {e}>"


def _leaks(obj):
    # the caller's own echoed input (top-level session_id) is not a disclosure
    if isinstance(obj, dict) and obj.get("session_id") == SID:
        obj = {k: v for k, v in obj.items() if k != "session_id"}
    return SID in json.dumps(obj, default=str)


def test_g1_sweep_no_verb_echoes_bearer(home):
    _man(home)
    _man(home, "willow")
    _man(home, "ada")
    p = _send()
    a = _enter(home, SID, p)
    assert not a.get("error"), a
    leaks = {}
    # every read verb, as X (same app, other session), as the holder, as orchestrator, as another app
    for who, app, sid in (("X", "loki", "sess-X"), ("A", "loki", SID), ("willow", "willow", "w-1"), ("ada", "ada", "d-1")):
        if who in ("X", "A"):
            leaks[f"{who}:session_enter"] = _leaks(_enter(home, sid, p))
            leaks[f"{who}:session_enter_bare"] = _leaks(_enter(home, sid, ""))
        for verb in ("dispatch_read", "dispatch_list", "handoff_read", "session_read", "receipts_tail",
                     "fleet_status", "grove_fleet_status", "whoami", "diagnostic_summary", "dispatch_accept",
                     "sessions_read_unverifiable", "verify_handoff"):
            r = _call(verb, app_id=app, dispatch_id=p, session_id=sid, to_app="loki", limit=200, n=200)
            leaks[f"{who}:{verb}"] = _leaks(r)
    # X's closing attempts: refusal text/sidecar must not carry A's id
    rx = srv.handoff_write_v4("loki", p, session_id="sess-X", **XSTUB)
    leaks["X:handoff_write_v4_refusal"] = _leaks(rx)
    rx2 = srv.handoff_write_v4("loki", p, session_id="", **XSTUB)
    leaks["X:handoff_write_v4_omit_refusal"] = _leaks(rx2)
    # after A closes: verify / handoff_read / receipts
    ra = srv.handoff_write_v4("loki", p, session_id=SID, **GOOD)
    assert ra.get("status") == "complete", ra
    for who, app in (("X", "loki"), ("willow", "willow")):
        for verb in ("handoff_read", "dispatch_read", "dispatch_list", "receipts_tail", "verify_handoff"):
            leaks[f"post:{who}:{verb}"] = _leaks(_call(verb, app_id=app, dispatch_id=p, limit=200, n=200))
    # the raw holder session_read (holder names its own id -- expected to echo its own record)
    print("G1 SWEEP", json.dumps(leaks, indent=0, sort_keys=True))
    bad = sorted(k for k, v in leaks.items() if v and not k.endswith(("A:session_read",)))
    print("G1 LEAKS (excluding holder reading its own session record)", bad)
    assert not bad


def test_g1_holder_accept_return(home):
    _man(home)
    p = _send()
    srv._buckets.clear()
    r = srv.dispatch_accept("loki", p, session_id=SID)
    print("G1 holder dispatch_accept return leaks", _leaks(r), "keys", sorted((r.get("status") or {}).keys()))


def test_g2_empty_and_whitespace_sid(home):
    _man(home)
    p = _send()
    _enter(home, "sess-A", p)
    out = {}
    for label, sid, runner in (("empty-seat", "", "seat"), ("empty-rat", "", "ratatosk"), ("ws", "   ", "seat"),
                               ("none", None, "seat")):
        srv._buckets.clear()
        try:
            e = srv.session_enter("loki", sid, p, workspace=str(home), runner=runner)
        except Exception as ex:  # noqa: BLE001
            e = {"error": f"exc {type(ex).__name__}"}
        out[label] = (e.get("error"), len(e.get("assignment") or ""), "accepted_session_id" in e)
    # empty id on a PENDING packet: must not accept
    p2 = _send()
    srv._buckets.clear()
    e2 = srv.session_enter("loki", "", p2, workspace=str(home))
    st2 = ds.dispatch_read(p2)["status"]["status"]
    print("G2", out, "| pending+empty", e2.get("error"), st2)
    assert all(v[0] == "EINVAL" and v[1] == 0 and not v[2] for k, v in out.items() if k != "none")
    assert e2.get("error") == "EINVAL" and st2 == "pending"


def test_g3_accept_window_withdraw_blocks(home, monkeypatch):
    """Withdraw attempted while accept is between status write and bind must BLOCK on the lock,
    then see a bound session (EBUSY)."""
    p = _send()
    real_bind = ds.session_bind
    in_window = threading.Event()
    go_on = threading.Event()

    def slow_bind(app_id, session_id, dispatch_id, status, **kw):
        if dispatch_id == p and status == "working":
            in_window.set()
            go_on.wait(3)
        return real_bind(app_id, session_id, dispatch_id, status, **kw)
    monkeypatch.setattr(ds, "session_bind", slow_bind)
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("acc", ds.dispatch_accept(p, "loki", "s-accept")))
    t.start()
    assert in_window.wait(5)
    wres = {}
    w = threading.Thread(target=lambda: wres.setdefault("w", ds.dispatch_withdraw(p, "x", by_app="willow")))
    w.start()
    w.join(0.5)
    blocked = w.is_alive()
    go_on.set()
    t.join(10)
    w.join(10)
    final = ds.dispatch_read(p)["status"]["status"]
    print("G3 window: withdraw blocked on lock", blocked, "| withdraw", wres["w"].get("error") or wres["w"].get("status"),
          "| final", final)
    assert blocked
    assert wres["w"].get("error") == "EBUSY" and final == "working"


def test_g3_accepted_id_without_record_is_ebusy(home):
    """Crash-between shape: status names a session, no session file exists."""
    p = _send()
    ds.dispatch_set_status(p, "working", accepted_session_id="ghost")
    w = ds.dispatch_withdraw(p, "x", by_app="willow")
    print("G3 no-record", w.get("error"), w.get("sessions"))
    assert w.get("error") == "EBUSY" and w.get("sessions") == ["ghost"]


def test_g3_idle_routes(home):
    """What moves A's record off 'working for P' -- each is a non-forced withdraw route."""
    _man(home)
    res = {}
    # (a) no time element: a record untouched is never idle
    p = _send()
    _enter(home, SID, p)
    rec = ds.session_path("loki", SID)
    import os
    import time
    old = time.time() - 30 * 86400
    os.utime(rec, (old, old))
    d = json.loads(rec.read_text())
    d["updated_at"] = "2020-01-01T00:00:00Z"
    rec.write_text(json.dumps(d))
    res["stale_30d"] = ds.dispatch_withdraw(p, "x", by_app="willow").get("error") or "withdrawn"
    # (b) X (same app) knowing A's id calls session_handoff_write with A's id
    p = _send()
    _enter(home, "sid-b", p)
    srv._buckets.clear()
    r = _call("session_handoff_write", app_id="loki", session_id="sid-b", narrative="X", summary="X")
    res["X_session_handoff_write_with_A_id"] = (str(r)[:60], ds.session_read("loki", "sid-b").get("status"),
                                                ds.dispatch_withdraw(p, "x", by_app="willow").get("error") or "withdrawn")
    # (c) X re-enters ANOTHER packet with A's id
    p, p2 = _send(), _send()
    _enter(home, "sid-c", p)
    _enter(home, "sid-c", p2)
    res["same_id_enters_P2"] = ds.dispatch_withdraw(p, "x", by_app="willow").get("error") or "withdrawn"
    # (d) X enters bare with A's id (resume path)
    p = _send()
    _enter(home, "sid-d", p)
    _enter(home, "sid-d", "")
    res["bare_resume"] = (ds.session_read("loki", "sid-d").get("status"),
                          ds.dispatch_withdraw(p, "x", by_app="willow").get("error") or "withdrawn")
    # (e) X without A's id: can X idle A? try its own id everywhere
    p = _send()
    _enter(home, "sid-e", p)
    _enter(home, "sess-X", p)
    _call("session_handoff_write", app_id="loki", session_id="sess-X", narrative="X", summary="X")
    res["X_own_id_only"] = (ds.session_read("loki", "sid-e").get("status"),
                            ds.dispatch_withdraw(p, "x", by_app="willow").get("error") or "withdrawn")
    # (f) can a non-orchestrator withdraw at all through the server verb?
    p = _send()
    _enter(home, "sid-f", p)
    ds.session_bind("loki", "sid-f", "", "idle")
    srv._buckets.clear()
    res["loki_server_withdraw_idle"] = str(_call("dispatch_withdraw", app_id="loki", dispatch_id=p, reason="x"))[:120]
    print("G3 IDLE", json.dumps(res, indent=0, default=str))
