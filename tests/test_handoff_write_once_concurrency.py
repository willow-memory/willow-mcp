"""Bite 1 rework (dispatch 9BA76253, after Loki's REVISE on 262F89A1):
write-once handoffs under REAL concurrency -- real filesystem, no mocks.

Adopts Loki's last-line probes p1, p4, p5, p7, p10, p11 from 262F89A1's Kart
tasks R5UXS8A0/8CTGJHD2, ported to the shipped API (accepted_session_id,
session_id on handoff_write_v4, packet_lock). Every guard here is exercised
as the ONLY line of defence in the mutation matrix (see the packet's
handoff, section "mutation table").
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

from willow_mcp import dispatch as ds
from willow_mcp import handoff as ho

_WORKER = Path(__file__).parent / "_bite1_subprocess_worker.py"


def _run_subprocess_race(mode: str, dispatch_id: str, n: int, tmp_dir: Path):
    """Launch N real, separate `python` subprocesses (never forked -- no
    inherited threads, locks, or mock-patched module state) that all race
    dispatch_id through `mode` ("accept" or "handoff"). A file-based
    barrier (`go_path`) holds every worker at the starting line until all
    N have been spawned, then releases them together."""
    go_path = tmp_dir / "go"
    procs = []
    out_paths = []
    env = os.environ.copy()
    for i in range(n):
        out_path = tmp_dir / f"out-{i}.json"
        out_paths.append(out_path)
        procs.append(subprocess.Popen(
            [sys.executable, str(_WORKER), mode, dispatch_id, str(i), str(go_path), str(out_path)],
            env=env,
        ))
    time.sleep(0.1)  # let every worker reach its wait loop before releasing
    go_path.write_text("go", encoding="utf-8")
    for p in procs:
        rc = p.wait(timeout=30)
        assert rc == 0, f"worker exited {rc}"
    return [json.loads(op.read_text(encoding="utf-8")) for op in out_paths]

GOOD = dict(
    findings=[{"text": "real verdict", "evidence": ["diff reviewed"]}],
    narrative="Audit: 12 passed.",
    checklist_resolved=True,
)
STUB = dict(
    findings=[{"title": "stub", "evidence": ["turns: 0"]}],
    narrative="stub",
    checklist_resolved=False,
)


def _pkt(accept: bool = True, session_id: str = "s-real"):
    did = ds.dispatch_send("willow", "loki", "# Task\n", summary="t")["dispatch_id"]
    if accept:
        acc = ds.dispatch_accept(did, "loki", session_id)
        assert acc.get("status", {}).get("status") == "working", acc
    return did


# ── p1: ESTATE is the last line of defence, even for an otherwise-VALID
#    payload -- proves the state guard, not the evidence gate underneath it.


def test_p1_estate_refuses_a_pending_packet_with_an_otherwise_valid_payload(home):
    did = _pkt(accept=False)
    r = ho.handoff_write_v4("loki", did, session_id="s-real", **GOOD)
    assert r.get("error") == "ESTATE", r
    assert not (ds.dispatch_dir(did) / "handoff.json").exists()
    assert ds.dispatch_read(did)["status"]["status"] == "pending"


# ── p2/M2 (ECLOSED): the second write is refused, the sidecar carries the
#    stub payload, and the ORIGINAL handoff.json/closeout.md are unchanged
#    byte-for-byte across three closed statuses.


def test_p2_eclosed_last_line_sidecar_and_bytes_unchanged(home):
    did = _pkt(session_id="s-real")
    assert ho.handoff_write_v4("loki", did, session_id="s-real", **GOOD)["status"] == "complete"
    root = ds.dispatch_dir(did)
    hb = (root / "handoff.json").read_bytes()
    cb = (root / "closeout.md").read_bytes()

    r2 = ho.handoff_write_v4("loki", did, session_id="s-real", **STUB)
    assert r2.get("error") == "ECLOSED", r2
    side = sorted((root / "refused").glob("*.json"))
    assert len(side) == 1
    body = json.loads(side[0].read_text())
    assert body["payload"]["narrative"] == "stub"
    assert body["writer_app"] == "loki"
    assert (root / "handoff.json").read_bytes() == hb
    assert (root / "closeout.md").read_bytes() == cb

    for st in ("verified", "failed"):
        ds.dispatch_set_status(did, st)
        r = ho.handoff_write_v4("loki", did, session_id="s-real", **STUB)
        assert r.get("error") == "ECLOSED"
        assert r["status"] == st

    assert len(list((root / "refused").glob("*.json"))) == 3
    assert (root / "handoff.json").read_bytes() == hb


# ── p3: sidecars never collide, even 25 in a row against the same packet.


def test_p3_sidecars_never_collide_sequential(home):
    did = _pkt(session_id="s-real")
    ho.handoff_write_v4("loki", did, session_id="s-real", **GOOD)
    paths = {
        ho.handoff_write_v4("loki", did, session_id="s-real", **STUB)["sidecar"]
        for _ in range(25)
    }
    assert len(paths) == 25
    assert len(list((ds.dispatch_dir(did) / "refused").glob("*.json"))) == 25


# ── p4/M10: refusals are receipts_tail-visible, ESTATE and ECLOSED alike.


def test_p4_refusals_write_receipts(home):
    did = _pkt(session_id="s-real")
    ho.handoff_write_v4("loki", did, session_id="s-real", **GOOD)
    ho.handoff_write_v4("loki", did, session_id="s-real", **STUB)  # ECLOSED
    d2 = _pkt(accept=False)
    ho.handoff_write_v4("loki", d2, **GOOD)  # ESTATE
    log = ho._handoff_receipt_log()
    rows = log.tail("loki", 50)
    assert any(
        r["outcome"] == "refused_eclosed" and did in (r["detail"] or "") for r in rows
    )
    assert any(
        r["outcome"] == "refused_estate" and d2 in (r["detail"] or "") for r in rows
    )


# ── p5/M7: a receipt-log failure never breaks the refusal itself -- the
#    exception is swallowed by _record_handoff_refusal_receipt, not by
#    accident.


def test_p5_receipt_log_failure_does_not_break_the_refusal(home, monkeypatch):
    class Boom:
        def record(self, *a, **k):
            raise RuntimeError("receipt db unwritable")

    monkeypatch.setattr(ho, "_handoff_receipt_log", lambda: Boom())
    did = _pkt(session_id="s-real")
    ho.handoff_write_v4("loki", did, session_id="s-real", **GOOD)
    hb = (ds.dispatch_dir(did) / "handoff.json").read_bytes()
    r = ho.handoff_write_v4("loki", did, session_id="s-real", **STUB)
    assert r.get("error") == "ECLOSED"
    assert (ds.dispatch_dir(did) / "handoff.json").read_bytes() == hb
    d2 = _pkt(accept=False)
    assert ho.handoff_write_v4("loki", d2, **GOOD).get("error") == "ESTATE"


# ── LOW-4: a sidecar write failure is caught -- ECLOSED still returned,
#    with sidecar_error set, and the original handoff.json is untouched.


def test_write_refused_sidecar_catches_a_real_oserror(home, monkeypatch):
    """The real try/except inside _write_refused_sidecar (not a mock of the
    function itself) turns a genuine write failure into "" rather than
    letting the OSError propagate."""
    from pathlib import Path as _Path

    did = _pkt(session_id="s-real")

    def boom(self, *a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(_Path, "write_text", boom, raising=True)
    result = ho._write_refused_sidecar(did, "loki", {"x": 1}, "reason")
    assert result == ""


def test_sidecar_write_failure_still_refuses_with_sidecar_error(home, monkeypatch):
    """_eclosed_refusal's handling of an already-failed sidecar write:
    ECLOSED still returned, sidecar_error names it, the receipt is still
    written, and the original handoff.json is untouched."""
    did = _pkt(session_id="s-real")
    ho.handoff_write_v4("loki", did, session_id="s-real", **GOOD)
    hb = (ds.dispatch_dir(did) / "handoff.json").read_bytes()

    monkeypatch.setattr(ho, "_write_refused_sidecar", lambda *a, **k: "")
    r = ho.handoff_write_v4("loki", did, session_id="s-real", **STUB)
    assert r.get("error") == "ECLOSED"
    assert r.get("sidecar") == ""
    assert r.get("sidecar_error")
    assert (ds.dispatch_dir(did) / "handoff.json").read_bytes() == hb

    log = ho._handoff_receipt_log()
    rows = log.tail("loki", 20)
    assert any(
        r2["outcome"] == "refused_eclosed" and did in (r2["detail"] or "") for r2 in rows
    )


# ── p7/M9: verify_handoff reads only the ORIGINAL handoff, and sidecar_count
#    counts real sidecars only -- not dotfiles/temp files/subdirectories a
#    concurrent writer might leave transiently in refused/.


def test_p7_verify_reads_original_and_sidecar_count_ignores_dotfiles_and_dirs(home):
    did = _pkt(session_id="s-real")
    ho.handoff_write_v4("loki", did, session_id="s-real", **GOOD)
    ho.handoff_write_v4("loki", did, session_id="s-real", **STUB)
    ho.handoff_write_v4("loki", did, session_id="s-real", **STUB)
    rd = ds.dispatch_dir(did) / "refused"
    (rd / ".partial.tmp").write_text("x", encoding="utf-8")
    (rd / "subdir").mkdir()
    v = ho.verify_handoff(did)
    assert v["verified"] is True
    assert v["sidecar_count"] == 2, v
    assert v["findings_count"] == 1
    assert ho.handoff_read(did)["handoff"]["narrative"] == GOOD["narrative"]


def test_verify_handoff_sidecar_count_zero_when_no_race(home):
    did = _pkt(session_id="s-real")
    ho.handoff_write_v4("loki", did, session_id="s-real", **GOOD)
    v = ho.verify_handoff(did)
    assert v["sidecar_count"] == 0


# ── ESESSION: only the accepting session may write the handoff. The
#    non-accepting session's otherwise-valid payload lands in a sidecar,
#    never in handoff.json.


def test_esession_refuses_the_non_accepting_session(home):
    did = _pkt(session_id="s-real-loki")
    r = ho.handoff_write_v4("loki", did, session_id="s-listener", **GOOD)
    assert r.get("error") == "ESESSION", r
    side = list((ds.dispatch_dir(did) / "refused").glob("*.json"))
    assert len(side) == 1
    assert json.loads(side[0].read_text())["payload"]["narrative"] == GOOD["narrative"]
    assert not (ds.dispatch_dir(did) / "handoff.json").exists()

    # The accepting session's write still succeeds afterward.
    ok = ho.handoff_write_v4("loki", did, session_id="s-real-loki", **GOOD)
    assert ok["status"] == "complete"


def test_esession_no_session_id_at_all_is_refused_when_one_was_recorded(home):
    did = _pkt(session_id="s-real-loki")
    r = ho.handoff_write_v4("loki", did, **GOOD)  # no session_id supplied
    assert r.get("error") == "ESESSION", r


def test_no_session_check_when_packet_was_accepted_without_one(home):
    """Legacy shape: dispatch_accept called with no session_id records an
    empty accepted_session_id -- nothing to check a caller against, so the
    pre-existing permissive behavior holds (backward compatible with
    packets accepted before this bite)."""
    did = _pkt(session_id="")
    ok = ho.handoff_write_v4("loki", did, **GOOD)
    assert ok["status"] == "complete"


def test_listener_stub_via_session_enter_never_becomes_canonical(home):
    """The exact shape Loki's F2 named: a real session accepts, a second
    session_enter (the listener's own process) re-enters the same packet,
    then both attempt handoff_write_v4. The real verdict is canonical; the
    stub is refused into a sidecar."""
    did = ds.dispatch_send("willow", "loki", "# Task\n", summary="t")["dispatch_id"]
    e1 = ds.session_enter("loki", "sess-real-loki", did)
    assert e1.get("error") is None
    e2 = ds.session_enter("loki", "sess-listener", did)
    assert e2.get("error") is None
    assert e2["held_by_other_session"] is True
    # N3 (dispatch 1AD03A64): withheld from a non-holder.
    assert "accepted_session_id" not in e2

    stub_result = ho.handoff_write_v4("loki", did, session_id="sess-listener", **STUB)
    assert stub_result.get("error") == "ESESSION"
    real_result = ho.handoff_write_v4("loki", did, session_id="sess-real-loki", **GOOD)
    assert real_result["status"] == "complete"
    assert ho.handoff_read(did)["handoff"]["narrative"] == GOOD["narrative"]


# ── p10: N threads race one 'working' packet -- real filesystem, real
#    packet_lock, no mocks. Exactly one wins; every loser gets ECLOSED and a
#    distinct sidecar.


def _judge(did, results, n):
    wins = [
        r for r in results
        if isinstance(r, dict) and r.get("status") == "complete" and not r.get("error")
    ]
    eclosed = [r for r in results if isinstance(r, dict) and r.get("error") == "ECLOSED"]
    rd = ds.dispatch_dir(did) / "refused"
    side = len(list(rd.glob("*.json"))) if rd.exists() else 0
    return len(wins), len(eclosed), side


def _good(i):
    return dict(
        findings=[{"text": f"writer {i}", "evidence": ["e"]}],
        narrative=f"writer {i}: 1 passed.",
        checklist_resolved=True,
    )


def test_p10_concurrent_threads_exactly_one_wins(home):
    n, trials, bad, worst = 8, 15, 0, None
    for _ in range(trials):
        did = _pkt(session_id="")  # no session recorded: any thread may write
        barrier = threading.Barrier(n)
        results = [None] * n

        def w(i):
            barrier.wait()
            results[i] = ho.handoff_write_v4("loki", did, **_good(i))

        threads = [threading.Thread(target=w, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        wins, eclosed, sidecars = _judge(did, results, n)
        if wins != 1 or eclosed != n - 1 or sidecars != n - 1:
            bad += 1
            worst = worst or (wins, eclosed, sidecars)
    assert bad == 0, f"trials={trials} bad_trials={bad} first_bad(wins,eclosed,sidecars)={worst}"


# ── p11: N separate OS PROCESSES race the same packet -- the shape that
#    actually matters (the ratatosk listener is its own process, not a
#    thread in the specialist's). Real `python` subprocesses, not forked --
#    a fork of a multi-threaded pytest process can inherit a
#    threading.Lock held (and never released) by a thread that doesn't
#    exist in the child, which hangs the WHOLE suite the first time some
#    unrelated test's background thread is alive at fork time. A real
#    subprocess shares no such state.


def test_p11_concurrent_processes_exactly_one_wins(home, tmp_path):
    n, trials, bad, worst = 6, 5, 0, None
    for t in range(trials):
        did = _pkt(session_id="")
        race_dir = tmp_path / f"race-{t}"
        race_dir.mkdir()
        results = _run_subprocess_race("handoff", did, n, race_dir)
        wins, eclosed, sidecars = _judge(did, results, n)
        if wins != 1 or eclosed != n - 1 or sidecars != n - 1:
            bad += 1
            worst = worst or (wins, eclosed, sidecars)
    assert bad == 0, f"trials={trials} bad_trials={bad} first_bad(wins,eclosed,sidecars)={worst}"


# ── dispatch_accept's OWN lock: N threads race ONE pending packet through
#    dispatch_accept -- exactly one may flip pending -> working. Without the
#    lock, dispatch_set_status's unconditional overwrite lets every caller
#    that read "pending" before any of them wrote "working" all succeed.


def test_accept_race_exactly_one_thread_wins(home):
    n, trials, bad, worst = 8, 15, 0, None
    for _ in range(trials):
        did = ds.dispatch_send("willow", "loki", "# Task\n", summary="t")["dispatch_id"]
        barrier = threading.Barrier(n)
        results = [None] * n

        def w(i):
            barrier.wait()
            results[i] = ds.dispatch_accept(did, "loki", f"s-{i}")

        threads = [threading.Thread(target=w, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        wins = [r for r in results if isinstance(r, dict) and not r.get("error")]
        losses = [r for r in results if isinstance(r, dict) and r.get("error") == "invalid_transition"]
        if len(wins) != 1 or len(losses) != n - 1:
            bad += 1
            worst = worst or (len(wins), len(losses))
    assert bad == 0, f"trials={trials} bad_trials={bad} first_bad(wins,losses)={worst}"


def test_accept_race_exactly_one_process_wins(home, tmp_path):
    n, trials, bad, worst = 6, 5, 0, None
    for t in range(trials):
        did = ds.dispatch_send("willow", "loki", "# Task\n", summary="t")["dispatch_id"]
        race_dir = tmp_path / f"accept-race-{t}"
        race_dir.mkdir()
        results = _run_subprocess_race("accept", did, n, race_dir)
        wins = [r for r in results if isinstance(r, dict) and not r.get("error")]
        losses = [r for r in results if isinstance(r, dict) and r.get("error") == "invalid_transition"]
        if len(wins) != 1 or len(losses) != n - 1:
            bad += 1
            worst = worst or (len(wins), len(losses))
    assert bad == 0, f"trials={trials} bad_trials={bad} first_bad(wins,losses)={worst}"


# ── sidecar mode / dir mode sanity (informational, matches Loki's F10) ──────


def test_sidecar_and_refused_dir_modes(home):
    did = _pkt(session_id="s-real")
    ho.handoff_write_v4("loki", did, session_id="s-real", **GOOD)
    r = ho.handoff_write_v4("loki", did, session_id="s-real", **STUB)
    side_path = ds.dispatch_dir(did) / "refused" / r["sidecar"].rsplit("/", 1)[-1]
    assert stat.S_IMODE(side_path.stat().st_mode) == 0o644
    assert stat.S_IMODE((ds.dispatch_dir(did) / "refused").stat().st_mode) == 0o755
