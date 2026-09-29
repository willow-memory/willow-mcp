"""Loki 6FC22847 probes (green-expected at 70a2953): real FS, real server tool wrappers.

Reuses ADC80409's probes, flipped to assert the fixed behaviour, plus the new
checks the packet asks for (X-never-closes-A sweep, two Lokis in one process,
N1B on every re-entry shape, single-outcome N5B/N5C)."""
import fcntl
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from willow_mcp import dispatch as ds
from willow_mcp import handoff as ho
from willow_mcp import server as srv

GOOD = dict(findings=[{"text": "real verdict", "evidence": ["diff reviewed"]}], narrative="Audit: 12 passed.", checklist_resolved=True)
GOOD2 = dict(findings=[{"text": "second verdict", "evidence": ["diff reviewed"]}], narrative="Audit two: 7 passed.", checklist_resolved=True)
STUB = dict(findings=[{"title": "stub", "evidence": ["turns: 0"]}], narrative="stub", checklist_resolved=False)
XSTUB = dict(findings=[{"title": "X stub", "evidence": ["turns: 0"]}], narrative="X stub from another session", checklist_resolved=False)
WORKER = str(Path(__file__).parent / "_loki_6fc_worker.py")


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


def _st(did):
    return ds.dispatch_read(did)["status"]


def _narr(did):
    return ho.handoff_read(did)["handoff"]["narrative"]


def _no_handoff(did):
    return not (ds.dispatch_dir(did) / "handoff.json").exists()


# ---------------- S1-S4 through the real server tools ----------------

def test_s1_two_sessions_two_packets_both_close_on_omit(home):
    _man(home)
    p1, p2 = _send(), _send()
    _enter(home, "sess-A", p1)
    _enter(home, "sess-B", p2)
    ra = _close(p1, **GOOD)
    rb = _close(p2, **GOOD2)
    print("S1 A-omit", ra.get("error"), ra.get("status"), "| B-omit", rb.get("error"), rb.get("status"))
    assert ra.get("status") == "complete" and rb.get("status") == "complete"
    assert _narr(p1) == GOOD["narrative"] and _narr(p2) == GOOD2["narrative"]


def test_s2_held_x_omit_refused_a_explicit_wins(home):
    _man(home)
    p1 = _send()
    _enter(home, "sess-A", p1)
    x = _enter(home, "sess-X", p1)
    _enter(home, "sess-A", p1)
    rx = _close(p1, **XSTUB)
    ra = _close(p1, "sess-A", **GOOD)
    print("S2 X held", x.get("held_by_other_session"), "X-omit", rx.get("error"), "| A-sid", ra.get("error"), ra.get("status"))
    assert x.get("held_by_other_session") is True
    assert rx.get("error") == "ESESSION"
    assert ra.get("status") == "complete" and _narr(p1) == GOOD["narrative"]


def test_s3_strict_a_omit_refused_explicit_works(home):
    _man(home)
    p1 = _send()
    _enter(home, "sess-A", p1)
    _enter(home, "sess-X", p1)
    ra = _close(p1, **GOOD)
    no_h = _no_handoff(p1)
    ra2 = _close(p1, "sess-A", **GOOD)
    print("S3 A-omit", ra.get("error"), "handoff absent", no_h, "| A-sid", ra2.get("error"), ra2.get("status"), "| msg", (ra.get("message") or "")[:160])
    assert ra.get("error") == "ESESSION" and no_h
    assert ra2.get("status") == "complete"


def test_s4_single_session_omit(home):
    _man(home)
    p1 = _send()
    _enter(home, "sess-A", p1)
    r = _close(p1, **GOOD)
    print("S4", r.get("error"), r.get("status"))
    assert r.get("status") == "complete"


def test_s4b_single_session_reenters_same_id_omit(home):
    _man(home)
    p1 = _send()
    _enter(home, "sess-A", p1)
    _enter(home, "sess-A", p1)
    r = _close(p1, **GOOD)
    print("S4b", r.get("error"), r.get("status"))
    assert r.get("status") == "complete"


# ---------------- X must never close A's packet (sweep) ----------------

def test_x_sweep_never_closes(home):
    """Every accidental route: X omits (same process), X omits (X alone in its
    own process), X passes its own id, X enters first-and-held on another
    packet. None may produce a handoff on A's packet."""
    _man(home)
    out = {}
    # a) same process, X held, X omits
    p = _send(); _enter(home, "sess-A", p); _enter(home, "sess-X", p)
    out["a_same_proc_omit"] = _close(p, **XSTUB).get("error"); assert _no_handoff(p)
    # b) X alone in a different process (A entered elsewhere): X is the sole entrant here
    p = _send(); _enter(home, "sess-A", p); _clear_ctx(); _enter(home, "sess-X", p)
    out["b_other_proc_omit"] = _close(p, **XSTUB).get("error"); assert _no_handoff(p)
    # c) X passes its own id
    p = _send(); _enter(home, "sess-A", p); _enter(home, "sess-X", p)
    out["c_own_sid"] = _close(p, "sess-X", **XSTUB).get("error"); assert _no_handoff(p)
    # d) X never entered this packet at all, omits
    p = _send(); _enter(home, "sess-A", p); _clear_ctx()
    out["d_never_entered_omit"] = _close(p, **XSTUB).get("error"); assert _no_handoff(p)
    # e) X entered a different packet, omits on A's
    p = _send(); q = _send(); _enter(home, "sess-A", p); _clear_ctx(); _enter(home, "sess-X", q)
    out["e_other_packet_omit"] = _close(p, **XSTUB).get("error"); assert _no_handoff(p)
    print("XSWEEP", out)
    assert all(v == "ESESSION" for v in out.values()), out


# ---------------- two Lokis, one stdio process ----------------

def test_two_lokis_one_process_omit(home):
    _man(home)
    p1, p2 = _send(), _send()
    _enter(home, "loki-1", p1)
    _enter(home, "loki-2", p2)
    _enter(home, "loki-1", p1)  # continuation
    r2 = _close(p2, **GOOD2)
    r1 = _close(p1, **GOOD)
    print("2LOKI omit", r1.get("error"), r1.get("status"), r2.get("error"), r2.get("status"))
    assert r1.get("status") == "complete" and r2.get("status") == "complete"
    assert _narr(p1) == GOOD["narrative"] and _narr(p2) == GOOD2["narrative"]


def test_two_lokis_one_process_explicit_and_mixed(home):
    _man(home)
    p1, p2 = _send(), _send()
    _enter(home, "loki-1", p1)
    _enter(home, "loki-2", p2)
    r1 = _close(p1, "loki-1", **GOOD)
    r2 = _close(p2, **GOOD2)
    print("2LOKI mixed", r1.get("status"), r2.get("status"))
    assert r1.get("status") == "complete" and r2.get("status") == "complete"


def test_two_lokis_one_process_concurrent_threads(home):
    _man(home)
    for _ in range(5):
        p1, p2 = _send(), _send()
        _enter(home, "loki-1", p1)
        _enter(home, "loki-2", p2)
        bar = threading.Barrier(2)
        res = {}

        def go(k, did, kw):
            bar.wait()
            res[k] = srv.handoff_write_v4("loki", did, session_id="", **kw)
        srv._buckets.clear()
        ts = [threading.Thread(target=go, args=("1", p1, GOOD)), threading.Thread(target=go, args=("2", p2, GOOD2))]
        [t.start() for t in ts]
        [t.join(20) for t in ts]
        print("2LOKI threads", {k: (v.get("error"), v.get("status")) for k, v in res.items()})
        assert res["1"].get("status") == "complete" and res["2"].get("status") == "complete"
        assert _narr(p1) == GOOD["narrative"] and _narr(p2) == GOOD2["narrative"]


def test_held_on_other_packet_does_not_poison(home):
    _man(home)
    p1, p2 = _send(), _send()
    _enter(home, "sess-A", p1)
    _enter(home, "sess-B", p2)
    _enter(home, "sess-X", p2)  # held on P2
    ra = _close(p1, **GOOD)
    print("POISON A-omit on P1", ra.get("error"), ra.get("status"))
    assert ra.get("status") == "complete"


# ---------------- N1B ----------------

def test_n1b_listener_reentry_after_empty_accept(home):
    _man(home)
    p = _send("seat")
    ds.dispatch_accept(p, "loki", "")
    lst = _enter(home, "sess-listener", p, runner="ratatosk")
    sr = ds.session_read("loki", "sess-listener")
    print("N1B", lst.get("error"), "alen", len(lst.get("assignment") or ""), "status", _st(p)["status"], "sess", sr.get("error") or sr.get("status"))
    assert lst.get("error") == "ERUNNER" and not lst.get("assignment")
    assert _st(p)["status"] == "working"
    assert sr.get("error")  # no session record written


def test_n1b_listener_reentry_into_seat_held_packet(home):
    _man(home)
    p = _send("seat")
    _enter(home, "sess-A", p)
    lst = _enter(home, "sess-listener", p, runner="ratatosk")
    print("N1B-held", lst.get("error"), lst.get("held_by_other_session"))
    assert lst.get("error") == "ERUNNER"


def test_n1b_listener_on_closed_packet(home):
    _man(home)
    p = _send("seat")
    _enter(home, "sess-A", p)
    _close(p, "sess-A", **GOOD)
    lst = _enter(home, "sess-listener", p, runner="ratatosk")
    print("N1B-complete", lst.get("error"))
    assert lst.get("error") == "ERUNNER"


def test_n1b_seat_on_listener_packet_reentry(home):
    _man(home)
    p = _send("ratatosk")
    ds.dispatch_accept(p, "loki", "", runner="ratatosk")
    seat = _enter(home, "sess-seat", p, runner="seat")
    print("N1B-reverse", seat.get("error"))
    assert seat.get("error") == "ERUNNER"


def test_n1_fresh_listener_refused_then_seat_closes(home):
    _man(home)
    p = _send("seat")
    lst = _enter(home, "sess-listener", p, runner="ratatosk")
    st = _st(p)
    _enter(home, "sess-real", p)
    r = _close(p, **GOOD)
    print("N1", lst.get("error"), st.get("status"), "close-omit", r.get("error"), r.get("status"))
    assert lst.get("error") == "ERUNNER" and st.get("status") == "pending"
    assert r.get("status") == "complete"


def test_n1d_legacy_meta_without_runner_is_seat(home):
    from willow_mcp import dispatch_signing
    p = ds.dispatch_send("willow", "loki", "# Task\n", summary="t")["dispatch_id"]
    mp_ = ds.dispatch_dir(p) / "meta.json"
    meta = json.loads(mp_.read_text())
    meta.pop("runner", None)
    meta["signature"] = dispatch_signing.sign_meta(meta)
    mp_.write_text(json.dumps(meta, indent=2) + "\n")
    r1 = ds.dispatch_accept(p, "loki", "L", runner="ratatosk")
    r2 = ds.dispatch_accept(p, "loki", "S", runner="seat")
    assert r1.get("error") == "ERUNNER" and r2["status"]["status"] == "working"


def test_m20b_legacy_meta_without_runner_defaults_to_seat_on_reentry(home):
    """M20b (Loki 6FC22847 drv.py): a packet accepted before the `runner`
    field existed has no `runner` key on disk at all -- the default must
    read as 'seat' on RE-ENTRY (session_enter into an already-working
    packet), not just on a fresh dispatch_accept. Deploy-time legacy shape:
    every packet on disk today predates this field."""
    from willow_mcp import dispatch_signing
    _man(home)
    p = _send()  # runner="seat" at send time
    _enter(home, "sess-A", p)  # pending -> working
    mp_ = ds.dispatch_dir(p) / "meta.json"
    meta = json.loads(mp_.read_text())
    meta.pop("runner", None)
    meta["signature"] = dispatch_signing.sign_meta(meta)
    mp_.write_text(json.dumps(meta, indent=2) + "\n")

    reentry_seat = _enter(home, "sess-A", p, runner="seat")
    print("M20B reentry seat", reentry_seat.get("error"))
    assert reentry_seat.get("error") is None

    reentry_ratatosk = _enter(home, "sess-A", p, runner="ratatosk")
    print("M20B reentry ratatosk", reentry_ratatosk.get("error"))
    assert reentry_ratatosk.get("error") == "ERUNNER"


# ---------------- N3 ----------------

def _walk_has_key(obj, key):
    if isinstance(obj, dict):
        return key in obj or any(_walk_has_key(v, key) for v in obj.values())
    if isinstance(obj, list):
        return any(_walk_has_key(v, key) for v in obj)
    return False


def test_n3_other_app_redacted_read_and_list(home):
    _man(home)
    _man(home, "willow")
    _man(home, "ada")
    p = _send()
    _enter(home, "sess-A", p)
    srv._buckets.clear()
    dw = srv.dispatch_read("willow", p)
    srv._buckets.clear()
    lw = srv.dispatch_list("willow", to_app="loki")
    srv._buckets.clear()
    ll = srv.dispatch_list("loki", to_app="loki")
    print("N3 willow read has", _walk_has_key(dw, "accepted_session_id"), "| list(willow) has", _walk_has_key(lw, "accepted_session_id"), "| list(loki) has", _walk_has_key(ll, "accepted_session_id"))
    assert not _walk_has_key(dw, "accepted_session_id")
    assert not _walk_has_key(lw, "accepted_session_id")
    assert not _walk_has_key(ll, "accepted_session_id")
    assert "sess-A" not in json.dumps(lw) and "sess-A" not in json.dumps(ll)


def test_n3_withheld_from_held_enter(home):
    _man(home)
    p = _send()
    _enter(home, "sess-A", p)
    x = _enter(home, "sess-X", p)
    assert "accepted_session_id" not in x


# ---------------- N4 ----------------

def _spawn(did, n, tmp):
    go = tmp / f"go-{did}"
    outs = [tmp / f"{did}-{i}.json" for i in range(n)]
    ps = [subprocess.Popen([sys.executable, WORKER, did, str(i), str(go), str(outs[i])], env=dict(os.environ)) for i in range(n)]
    time.sleep(1.2)
    go.write_text("go")
    [p.wait(timeout=60) for p in ps]
    return [json.loads(o.read_text()) for o in outs]


def test_n4_separate_interpreters(home, tmp_path):
    for _ in range(2):
        did = _send()
        res = _spawn(did, 6, tmp_path)
        told = [r for r in res if r.get("held_by_other_session") or r.get("error")]
        win = [r for r in res if r.get("status") == "working" and not r.get("held_by_other_session") and not r.get("error")]
        print("N4", len(win), len(told))
        assert len(win) == 1 and len(told) == 5


# ---------------- F3 ----------------

def test_f3_cleared_reaccept_archives_and_closes(home):
    p = _send()
    ds.dispatch_accept(p, "loki", "c1")
    ho.handoff_write_v4("loki", p, session_id="c1", **GOOD)
    h1 = (ds.dispatch_dir(p) / "handoff.json").read_bytes()
    ho.verify_handoff(p)
    ds.agent_clear("loki", p)
    ds.dispatch_accept(p, "loki", "c2")
    r = ho.handoff_write_v4("loki", p, session_id="c2", **dict(GOOD, narrative="Cycle 2: 3 passed."))
    v = ho.verify_handoff(p)
    hist = sorted((ds.dispatch_dir(p) / "history").iterdir())
    assert r.get("status") == "complete" and v["history_count"] == 1
    assert (hist[0] / "handoff.json").read_bytes() == h1


def test_f3b_same_second_cycles_all_archived(home):
    p = _send()
    narr = []
    for i in range(4):
        ds.dispatch_accept(p, "loki", f"c{i}")
        n = f"cycle {i}: 1 passed."
        narr.append(n)
        ho.handoff_write_v4("loki", p, session_id=f"c{i}", **dict(GOOD, narrative=n))
        ho.verify_handoff(p)
        ds.agent_clear("loki", p)
    ds.dispatch_accept(p, "loki", "c9")
    dirs = sorted((ds.dispatch_dir(p) / "history").iterdir())
    got = sorted(json.loads((d / "handoff.json").read_text())["narrative"] for d in dirs)
    print("F3B dirs", [d.name for d in dirs])
    assert got == sorted(narr) and ho._history_count(p) == 4


def test_f3d_history_symlink_refused_nothing_lands(home, tmp_path):
    p = _send()
    ds.dispatch_accept(p, "loki", "c1")
    ho.handoff_write_v4("loki", p, session_id="c1", **GOOD)
    ho.verify_handoff(p)
    ds.agent_clear("loki", p)
    root = ds.dispatch_dir(p)
    outside = tmp_path / "outside_hist"
    outside.mkdir()
    os.symlink(str(outside), str(root / "history"))
    try:
        r = ds.dispatch_accept(p, "loki", "c2")
    except Exception as e:  # noqa: BLE001
        r = {"error": f"raised {e!r}"}
    landed = [str(x.relative_to(outside)) for x in outside.rglob("*")]
    print("F3D accept", r.get("error"), "landed", landed, "read", ds.dispatch_read(p).get("error"))
    assert not landed
    assert r.get("error") == "symlinked_packet"
    assert ds.dispatch_read(p).get("error") == "symlinked_packet"


def test_f3c_archive_under_lock(home):
    p = _send()
    ds.dispatch_accept(p, "loki", "c1")
    ho.handoff_write_v4("loki", p, session_id="c1", **GOOD)
    ho.verify_handoff(p)
    ds.agent_clear("loki", p)
    root = ds.dispatch_dir(p)
    fd = os.open(str(root / ".handoff.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    t = threading.Thread(target=lambda: ds.dispatch_accept(p, "loki", "c2"))
    t.start()
    time.sleep(0.5)
    before = (root / "handoff.json").exists(), (root / "history").exists()
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)
    t.join(10)
    after = (root / "handoff.json").exists(), (root / "history").exists()
    assert before == (True, False) and after == (False, True)


# ---------------- N5 (single outcome, forced interleaving) ----------------

def _hold(root):
    root.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(root / ".handoff.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def _release(fd):
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)


def test_n5_set_status_blocks_on_lock(home):
    p = _send()
    fd = _hold(ds.dispatch_dir(p))
    t = threading.Thread(target=lambda: ds.dispatch_set_status(p, "withdrawn"))
    t.start()
    time.sleep(0.4)
    mid = _st(p)["status"]
    _release(fd)
    t.join(10)
    assert mid == "pending"


def test_n5b_withdraw_single_outcome(home):
    """withdraw reads 'pending' pre-lock; while it waits the packet becomes working
    and session-bound. The ONLY correct outcome: EBUSY, packet stays working."""
    p = _send()
    root = ds.dispatch_dir(p)
    fd = _hold(root)
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("r", ds.dispatch_withdraw(p, "no longer needed", by_app="willow")))
    t.start()
    time.sleep(0.5)
    ds._dispatch_set_status_locked(p, root, "working", {"accepted_session_id": "sess-A"})
    ds.session_bind("loki", "sess-A", p, "working")
    _release(fd)
    t.join(10)
    print("N5B", out["r"].get("error"), "final", _st(p)["status"])
    assert out["r"].get("error") == "EBUSY"
    assert _st(p)["status"] == "working"


def test_n5b2_withdraw_vs_complete_single_outcome(home):
    p = _send()
    ds.dispatch_accept(p, "loki", "")
    root = ds.dispatch_dir(p)
    fd = _hold(root)
    out = {}
    # pre-lock read sees 'working' with no bound session (accepted with '') -> would withdraw
    t = threading.Thread(target=lambda: out.setdefault("r", ds.dispatch_withdraw(p, "stale", by_app="willow")))
    t.start()
    time.sleep(0.5)
    ds._dispatch_set_status_locked(p, root, "complete", {})
    _release(fd)
    t.join(10)
    print("N5B2", out["r"].get("error"), "final", _st(p)["status"])
    assert out["r"].get("error") == "invalid_transition"
    assert _st(p)["status"] == "complete"


def test_n5c_clear_single_outcome(home):
    p = _send()
    ds.dispatch_accept(p, "loki", "c1")
    ho.handoff_write_v4("loki", p, session_id="c1", **GOOD)
    root = ds.dispatch_dir(p)
    fd = _hold(root)
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("r", ds.agent_clear("loki", p)))
    t.start()
    time.sleep(0.5)
    ds._dispatch_set_status_locked(p, root, "failed", {})
    _release(fd)
    t.join(10)
    print("N5C", out["r"].get("error"), "final", _st(p)["status"])
    assert out["r"].get("error") == "not_ready_for_clear"
    assert _st(p)["status"] == "failed"


# ---------------- p16 / N7 / F6 ----------------

def test_p16_write_rereads_under_lock(home):
    did = _send()
    ds.dispatch_accept(did, "loki", "")
    root = ds.dispatch_dir(did)
    fd = _hold(root)
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("r", ho.handoff_write_v4("loki", did, **GOOD)))
    t.start()
    time.sleep(0.5)
    ds._dispatch_set_status_locked(did, root, "withdrawn", {})
    _release(fd)
    t.join(10)
    assert out["r"].get("error") == "invalid_transition"
    assert not (root / "handoff.json").exists()


def test_n7_lockfile_symlink(home, tmp_path):
    p = _send()
    ds.dispatch_accept(p, "loki", "s")
    root = ds.dispatch_dir(p)
    (root / ".handoff.lock").unlink()
    target = tmp_path / "outside.txt"
    os.symlink(str(target), str(root / ".handoff.lock"))
    r = ho.handoff_write_v4("loki", p, session_id="s", **GOOD)
    try:
        with ds.packet_lock(root):
            direct = "entered"
    except OSError as e:
        direct = f"OSError {e.errno}"
    assert r.get("error") == "symlinked_packet" and not target.exists() and direct.startswith("OSError")


def test_f6_no_partial_read(home):
    p = _send()
    ds.dispatch_accept(p, "loki", "s")
    path = ds.dispatch_dir(p) / "handoff.json"
    stop = threading.Event()
    stats = {"reads": 0, "bad": 0}

    def reader():
        while not stop.is_set():
            try:
                b = path.read_bytes()
            except FileNotFoundError:
                continue
            stats["reads"] += 1
            try:
                json.loads(b)
            except ValueError:
                stats["bad"] += 1
    t = threading.Thread(target=reader)
    t.start()
    ho.handoff_write_v4("loki", p, session_id="s", **dict(GOOD, narrative="Audit: 12 passed. " + "x" * 3_000_000))
    time.sleep(0.2)
    stop.set()
    t.join(10)
    left = [x.name for x in path.parent.iterdir() if x.name.endswith(".tmp")]
    print("F6 reads", stats)
    assert stats["bad"] == 0 and not left
