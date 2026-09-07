"""Two willow-mcp instances over one $WILLOW_HOME.

MCP 2026-07-28 (SEP-2567) drops `Mcp-Session-Id` — *"any server instance can
handle any stateless request"* — which removes the sticky routing this server's
in-memory state has been quietly relying on. This module holds the evidence for
`docs/design/stateless-session-state.md`:

  1. the AGENT-BINDING LOCKOUT, reproduced and characterised (NOT fixed here —
     the design doc argues why the instance guard, not a durable session store,
     is the right first move);
  2. the RECEIPT-CHAIN FORK, which is worse and is fixed here: it is silent,
     permanent, and already reachable today without any multi-replica deploy;
  3. the SINGLE-INSTANCE GUARD that makes the surviving assumption declared and
     enforced instead of undeclared.
"""
import subprocess
import sys
import textwrap
import threading
import uuid

import pytest

from willow_mcp import agent_registry as reg
from willow_mcp import instance_lock
from willow_mcp import session_binder as sb
from willow_mcp.receipts import ReceiptLog


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.delenv("WILLOW_MCP_APPS_ROOT", raising=False)
    monkeypatch.delenv(instance_lock.OVERRIDE_ENV, raising=False)
    return tmp_path


def _header(agent_id, secret, trust=3, *, nonce=None):
    h = {"agent_id": agent_id, "agent_name": agent_id, "last_gate": "t",
         "pass_count": 1, "fail_count": 0, "drift": 0,
         "nonce": nonce or uuid.uuid4().hex, "trust_level": trust,
         "timestamp": 1000, "tools": ["read"], "state_hash": "s0",
         "reserved": 0, "signature": "0" * 64}
    h["signature"] = sb.expected_header_sig(secret, h)
    return h


# ── 1. the agent-binding lockout (characterised, not fixed) ───────────────────
#
# These assert what the code does TODAY. They are the reproduction the design
# doc is built on, so they are written to fail the day someone makes
# SessionBinder._sessions durable — at which point they become the tests of that
# change, inverted. Do not "fix" one by deleting it.

def test_session_bound_on_one_instance_is_invisible_to_the_other():
    """The lockout, step 1-2: bind lands on A, the next tool call lands on B."""
    secret = bytes.fromhex(reg.register_agent("op", 4)["secret_hex"])
    a, b = sb.SessionBinder(), sb.SessionBinder()      # two replicas, one WILLOW_HOME

    opened = a.check_in(_header("op", secret))
    sid = opened["session_id"]
    call_nonce = uuid.uuid4().hex
    sig = sb.call_sig(secret, sid, "op", "store_get", call_nonce)

    assert a.verify_call(sid, "op", "store_get", call_nonce, sig)["bound"] is True
    on_b = b.verify_call(sid, "op", "store_get", uuid.uuid4().hex,
                         sb.call_sig(secret, sid, "op", "store_get", "x"))
    assert on_b == {"bound": False, "reason": "no live session for session_id"}
    # …and under WILLOW_MCP_ENFORCE_BINDING that reason is a hard denial, not a
    # downgrade: server._enforce_binding_gate returns {"error": "binding rejected…"}.


def test_retrying_the_same_signed_header_on_the_other_instance_is_refused():
    """The lockout, step 3: the check-in nonce file IS shared, so the obvious
    retry — re-send the identical signed request — is refused as a replay. Half
    the state shared and half not is what turns a miss into a lockout."""
    secret = bytes.fromhex(reg.register_agent("op", 4)["secret_hex"])
    a, b = sb.SessionBinder(), sb.SessionBinder()
    header = _header("op", secret)

    a.check_in(header)
    with pytest.raises(sb.BindError, match="nonce already used"):
        b.check_in(header)


def test_a_fresh_nonce_does_rebind_so_the_lockout_is_recoverable_in_principle():
    """Correction to the folk description: the agent is not cryptographically
    stuck. The check-in nonce is agent-chosen and its own signature covers it, so
    a NEW header binds fine on B.

    The lockout is real anyway, for two reasons the design doc leans on:
      * the shipped harness (`signing.SigningClientSession`) binds ONCE in
        `bind()` and has no re-bind path — `call()` just keeps failing;
      * even with re-binding, each call independently lands on a replica that may
        not hold the session, so this is a per-call coin flip, not a bootstrap
        problem that settles.
    """
    secret = bytes.fromhex(reg.register_agent("op", 4)["secret_hex"])
    a, b = sb.SessionBinder(), sb.SessionBinder()

    a.check_in(_header("op", secret))
    assert b.check_in(_header("op", secret))["session_id"]      # fresh nonce ⇒ fine


def test_check_out_reconciliation_is_lost_with_the_session():
    """The quieter half: `entry_declared` and the server-stamped `started_ts` die
    with the process that holds them, so H3 declare-vs-did reconciliation cannot
    run on any other instance. An integrity control that silently stops running is
    worse than one that visibly fails."""
    secret = bytes.fromhex(reg.register_agent("op", 4)["secret_hex"])
    a, b = sb.SessionBinder(), sb.SessionBinder()
    sid = a.check_in(_header("op", secret))["session_id"]

    assert a.session_started_ts(sid, app_id="op") is not None
    assert b.session_started_ts(sid, app_id="op") is None       # ⇒ server returns no_live_session
    with pytest.raises(sb.BindError, match="no live session"):
        b.check_out(sid, {"tools": ["read"]}, ["store_get"], app_id="op")


# ── 2. the receipt-chain fork (fixed) ─────────────────────────────────────────

def test_two_receipt_logs_appending_concurrently_keep_one_unbroken_chain(tmp_path):
    """Two ReceiptLog handles on one DB — two processes, or one desktop client and
    one terminal — must not fork the hash chain.

    Before `_write_txn`'s BEGIN IMMEDIATE, both read the same head via
    `SELECT entry_hash … ORDER BY id DESC LIMIT 1` and appended two rows each
    claiming it as `prev_hash`; `verify()` then failed with `prev_hash linkage`
    forever, because the log is append-only and cannot be repaired. That failure
    also makes `session_reconcile` return `receipt_integrity_failed` for every
    session from then on.
    """
    db = str(tmp_path / "receipts.db")
    a, b = ReceiptLog(db_path=db), ReceiptLog(db_path=db)
    a.record("op", "store_put", "ok", "seed")

    barrier = threading.Barrier(2)

    def hammer(log, tag):
        barrier.wait()
        for i in range(15):
            log.record("op", "store_get", "ok", f"{tag}{i}")

    threads = [threading.Thread(target=hammer, args=(log, tag))
               for log, tag in ((a, "A"), (b, "B"))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    result = a.verify()
    assert result["ok"] is True, result
    assert result["count"] == 31                       # nothing lost to the serialisation


_CHILD = textwrap.dedent("""
    import sys, time
    from willow_mcp.receipts import ReceiptLog
    log = ReceiptLog(db_path=sys.argv[1])
    go = float(sys.argv[2])
    while time.time() < go:
        pass
    for i in range(15):
        log.record("op", "store_get", "ok", sys.argv[3] + str(i))
""")


def test_the_chain_survives_two_real_processes(tmp_path):
    """The same guarantee across true OS processes, where a `threading.Lock`
    provably says nothing. This is not a hypothetical replica deploy: two stdio
    clients over one ~/.willow are separate processes today."""
    import time

    db = str(tmp_path / "receipts.db")
    child = tmp_path / "child.py"
    child.write_text(_CHILD)
    go = time.time() + 2.0
    procs = [subprocess.Popen([sys.executable, str(child), db, str(go), tag])
             for tag in ("A", "B")]
    for p in procs:
        assert p.wait(timeout=60) == 0

    result = ReceiptLog(db_path=db).verify()
    assert result["ok"] is True, result
    assert result["count"] == 30


# ── 3. the single-instance declaration, enforced ──────────────────────────────

def test_second_serve_instance_on_the_same_home_is_refused(tmp_path):
    held = instance_lock.acquire(tmp_path)
    assert held is not None, "POSIX flock expected in the test environment"
    try:
        with pytest.raises(instance_lock.InstanceLockError) as excinfo:
            instance_lock.acquire(tmp_path)
        # The refusal must say WHY, not just "locked" — this is the declaration.
        assert "single-instance per WILLOW_HOME" in str(excinfo.value)
        assert "stateless-session-state" in str(excinfo.value)
    finally:
        held.close()


def test_lock_is_released_when_the_holder_closes(tmp_path):
    """flock, not a PID file: the kernel drops it when the fd goes, so there is no
    stale lock to reap after a SIGKILL / OOM / container eviction."""
    instance_lock.acquire(tmp_path).close()
    second = instance_lock.acquire(tmp_path)
    assert second is not None
    second.close()


def test_different_homes_never_collide(tmp_path):
    one, two = tmp_path / "a", tmp_path / "b"
    a, b = instance_lock.acquire(one), instance_lock.acquire(two)
    assert a is not None and b is not None
    a.close(); b.close()


def test_override_downgrades_the_refusal_to_a_warning(tmp_path, monkeypatch, caplog):
    held = instance_lock.acquire(tmp_path)
    try:
        monkeypatch.setenv(instance_lock.OVERRIDE_ENV, "1")
        with caplog.at_level("WARNING"):
            assert instance_lock.acquire(tmp_path) is None   # started, but unlocked
        assert instance_lock.OVERRIDE_ENV in caplog.text
        assert "WILL fail" in caplog.text
    finally:
        held.close()


def test_lock_file_names_its_holder(tmp_path):
    held = instance_lock.acquire(tmp_path)
    try:
        import os
        assert f"pid={os.getpid()}" in instance_lock.lock_path(tmp_path).read_text()
    finally:
        held.close()


# ── 4. the guard is actually wired into the serve path ────────────────────────

def test_serve_takes_the_instance_lock_before_running(monkeypatch):
    """Wiring, not just the module: `willow-mcp --serve` must acquire it, and the
    handle must be parked somewhere that outlives _main() — a lock released the
    moment the acquiring frame returns guards nothing."""
    from willow_mcp import server

    monkeypatch.setattr(sys, "argv", ["willow-mcp", "--serve"])
    calls, ran = [], []
    monkeypatch.setattr(instance_lock, "acquire", lambda *a, **k: calls.append(a) or "handle")
    monkeypatch.setattr(server.mcp, "run", lambda **k: ran.append(k))
    monkeypatch.setattr(server, "_INSTANCE_LOCK", None, raising=False)

    server._main()

    assert len(calls) == 1
    assert len(ran) == 1
    assert ran[0]["transport"] == "streamable-http"
    assert ran[0]["host"] == server._HOST
    assert ran[0]["port"] == server._PORT
    # serve() also passes transport_security -- the loopback-only allowlist
    # default defeats any tunnelled deployment (5431120). Assert it is wired
    # and rebinding protection is on, rather than pinning the whole kwargs
    # dict: pinning it is what made this test fail on an unrelated fix.
    assert ran[0]["transport_security"].enable_dns_rebinding_protection is True
    assert server._INSTANCE_LOCK == "handle"


def test_serve_refusal_exits_1_with_the_reason_not_a_traceback(monkeypatch, capsys):
    from willow_mcp import server

    monkeypatch.setattr(sys, "argv", ["willow-mcp", "--serve"])

    def _refuse(*a, **k):
        raise instance_lock.InstanceLockError("already served by pid=999")

    monkeypatch.setattr(instance_lock, "acquire", _refuse)
    monkeypatch.setattr(server.mcp, "run", lambda **k: pytest.fail("must not start"))

    with pytest.raises(SystemExit) as exc:
        server._main()
    assert exc.value.code == 1
    assert "already served by pid=999" in capsys.readouterr().err


def test_stdio_does_not_take_the_serve_lock(monkeypatch):
    """Multiple stdio processes over one $WILLOW_HOME are normal and supported —
    a desktop client and a terminal are separate agents, not replicas of one
    server. Locking them out would break the ordinary case to guard a deployment
    shape stdio cannot be in. Their shared state must be made process-safe on
    disk instead; the receipt-chain fix above is the first of those."""
    from willow_mcp import server

    monkeypatch.setattr(sys, "argv", ["willow-mcp"])
    monkeypatch.setattr(server, "_SERVE_MODE", False)
    monkeypatch.setattr(instance_lock, "acquire",
                        lambda *a, **k: pytest.fail("stdio must not take the serve lock"))
    ran = []
    monkeypatch.setattr(server.mcp, "run", lambda **k: ran.append(k))

    server._main()
    assert ran == [{"transport": "stdio"}]
