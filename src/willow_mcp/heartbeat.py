"""Worker liveness — the missing half of the task queue.

`task_submit` writes a row; a `willow-mcp worker` process drains it. Nothing
connected the two, so a submission into a fleet with no running worker looked
identical to one that was about to execute: `pending`, forever. `skills/kart-tasks.md`
had to warn readers in prose that "a submission is not an execution."

This module closes that. kartikeya's worker loop calls an `on_heartbeat` seam on
every tick (`kartikeya/worker.py`, `on_heartbeat(lane=..., tick_ok=True)`);
`WorkerHeartbeat` implements it as an atomic write of a small JSON file, one per
running worker process. `read_workers()` reads them back and classifies each as
alive, stale, or dead. `fleet_health` and `diagnostic_summary` surface the result.

**This is telemetry, not authorization.** The heartbeat directory lives under
`$WILLOW_HOME`, which the Kart sandbox mounts read-write, so a sandboxed task can
forge a heartbeat file. That buys an attacker nothing — no gate reads this, and
`store_scope`/`task_net` decisions never consult it — but it does mean a "worker
alive" reading must never become an input to a permission decision. Reads verify
the recorded pid is a live process on this host (a forged file naming a dead pid
reads `dead`, not `alive`), which makes the signal honest for its one job:
telling an operator why their task is not running. The trust root stays
`mcp_apps/`, which is `bound_ro` to the sandbox (B-14).
"""
from __future__ import annotations

import json
import logging
import os
import socket
import time
from pathlib import Path

logger = logging.getLogger("willow_mcp.heartbeat")

# The in-sandbox signal Kart actually sets: kartikeya's kart_env() writes this
# unconditionally into every sandboxed task's environment (kartikeya/sandbox.py
# ~line 939, "WILLOW_IN_KART": "1" if allow_net else ... -- the literal key is
# always present, only its value shape varies), not KART_TASK_ID, which
# kartikeya never sets. Reused by the private `_in_kart()` check in
# manifest_grant_executor.py; exported here (public, not underscored) so
# other in-sandbox refusals -- packet 7E6C2D84 -- can share one check instead
# of re-deriving the env var name.
_KART_SANDBOX_ENV_VAR = "WILLOW_IN_KART"


def in_kart_sandbox() -> bool:
    """Whether this process is running inside a Kart bwrap sandbox.

    A sandboxed task has read-write access to $WILLOW_HOME (the heartbeat
    directory lives under it), so it could otherwise forge a heartbeat file
    claiming to be a live worker -- a worker never runs inside its own
    sandbox, so any in-sandbox write is definitionally a forgery, not
    telemetry. Callers that need to refuse an in-sandbox act use this
    instead of re-checking the env var directly.
    """
    return os.environ.get(_KART_SANDBOX_ENV_VAR, "").strip() not in ("", "0")

# A worker rewrites its file every loop tick: `interval` seconds when idle, ~0.5s
# when busy. Three missed idle ticks (floor 30s) is a real absence, not a slow
# poll — long enough that a worker mid-`bwrap`-setup is never called dead.
_STALE_FLOOR_S = 30.0
# A record this far past its own interval is dead no matter what the pid says.
# Gap c400089095c7: kart-fast-4.json, written by a worker that died 2026-09-03,
# was immortal because PID 4 on this host is a kernel thread that lives as long
# as the machine — `os.kill(4, 0)` succeeds forever, so the file never reaped
# and fleet_health showed a phantom worker for a week. Liveness of *a* process
# with that number is not liveness of *the* process that wrote the file.
_DEAD_FLOOR_S = 600.0
_DEAD_MULTIPLIER = 20.0
# The busy loop ticks twice a second; a disk write per tick is pointless churn.
_MIN_WRITE_INTERVAL_S = 1.0


def heartbeat_root() -> Path:
    """Where workers publish liveness. Explicit service env wins."""
    configured = os.environ.get("WILLOW_WORKER_HEARTBEAT_ROOT", "").strip()
    if configured:
        return Path(configured).expanduser()
    home = Path(os.environ.get("WILLOW_HOME", Path.home() / ".willow"))
    return home / "worker_heartbeat"


def stale_after(interval: float) -> float:
    return max(3.0 * float(interval or 0.0), _STALE_FLOOR_S)


def dead_after(interval: float) -> float:
    """Age past which a record is dead regardless of pid liveness."""
    return max(_DEAD_MULTIPLIER * float(interval or 0.0), _DEAD_FLOOR_S)


def _proc_starttime(pid: int) -> int | None:
    """The kernel's start time for ``pid`` (clock ticks since boot), or None.

    Field 22 of ``/proc/<pid>/stat``. Recorded by the writer and compared by the
    reader: a recycled pid has the same number and a different start time, and
    that difference is what tells a live unrelated process from the worker
    that actually wrote the file. Linux only; elsewhere the check degrades to
    age alone, which is still enough to retire a phantom.
    """
    try:
        raw = Path(f"/proc/{int(pid)}/stat").read_text()
    except (OSError, ValueError, TypeError):
        return None
    # comm (field 2) may contain spaces and parens; everything after the LAST
    # ')' is fields 3..N, so starttime (field 22) is index 19 of that tail.
    tail = raw.rsplit(")", 1)[-1].split()
    try:
        return int(tail[19])
    except (IndexError, ValueError):
        return None


def _pid_alive(pid: int) -> bool:
    """Signal-0 liveness probe. EPERM means the pid exists but is another user's."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (OverflowError, ValueError, TypeError):
        return False
    return True


class WorkerHeartbeat:
    """`on_heartbeat` implementation: publish this worker's liveness to disk.

    Passed straight to `kartikeya.run_worker(on_heartbeat=...)`. Never raises —
    a failure to write telemetry must not take down a worker that is otherwise
    draining tasks correctly, so errors are logged once and swallowed.
    """

    def __init__(self, agent: str = "kart", lane: str = "fast",
                 interval: float = 5.0, root: Path | None = None):
        self.agent = agent
        self.lane = lane
        self.interval = float(interval)
        self.pid = os.getpid()
        self.starttime = _proc_starttime(self.pid)
        self.host = socket.gethostname()
        self.root = Path(root) if root is not None else heartbeat_root()
        self.path = self.root / f"{self.agent}-{self.lane}-{self.pid}.json"
        self._last_write = 0.0
        self._warned = False

    def __call__(self, *, lane: str | None = None, tick_ok: bool = True, **_) -> None:
        if in_kart_sandbox():
            # A Kart task carries only its submitter's identity (ruling D,
            # pair b8b24c45): a sandboxed task is never the worker loop
            # itself, so a heartbeat written from inside one is always a
            # forgery, not telemetry. Refuse it, once, and move on -- never
            # raise, matching this class's own "telemetry must not take the
            # worker down" contract.
            if not self._warned:
                logger.warning(
                    "heartbeat write refused: running inside a Kart sandbox "
                    "(%s set) -- a sandboxed task must never publish a "
                    "worker-liveness record",
                    _KART_SANDBOX_ENV_VAR,
                )
                self._warned = True
            return
        now = time.time()
        if now - self._last_write < _MIN_WRITE_INTERVAL_S:
            return
        self._last_write = now
        record = {
            "agent": self.agent,
            "lane": lane or self.lane,
            "pid": self.pid,
            "starttime": self.starttime,
            "host": self.host,
            "interval": self.interval,
            "tick_ok": bool(tick_ok),
            "ts": now,
        }
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(record))
            os.replace(tmp, self.path)  # atomic — a reader never sees a half-written file
        except Exception as e:
            if not self._warned:
                logger.warning("heartbeat write failed (%s): %s", self.path, e)
                self._warned = True

    def close(self) -> None:
        """Remove this worker's file on clean shutdown, so it reads absent rather
        than aging into `stale` and provoking a false 'worker died' diagnosis."""
        try:
            self.path.unlink(missing_ok=True)
        except Exception:
            logger.debug("heartbeat close unlink failed: %s", self.path, exc_info=True)


def _pid_namespace(pid: int) -> str | None:
    """The pid namespace `pid` lives in, as the target of /proc/<pid>/ns/pid.

    Compared against our own to tell a real top-level worker pid from one
    that only exists inside a Kart bwrap sandbox's own (nested) pid
    namespace -- bwrap unshares pid, so a sandboxed task's own os.getpid()
    restarts near 1 and can collide with an unrelated low host pid (a
    kernel thread, gap c400089095c7) when a task forges a heartbeat file
    (see the module docstring). Returns None when the link cannot be read
    (proc absent, permission denied, non-Linux) -- the caller then falls
    back to the existing liveness/starttime checks rather than guessing.
    """
    try:
        return os.readlink(f"/proc/{int(pid)}/ns/pid")
    except (OSError, ValueError, TypeError):
        return None


def _pid_in_foreign_namespace(pid: int) -> bool:
    """True when `pid`, read from here, is not in our own pid namespace.

    read_workers()/reap() always run on the host, outside any Kart sandbox
    -- so a live worker's own heartbeat is always written by (and later
    read as) a process in the reader's own pid namespace. A record whose
    pid resolves to a DIFFERENT namespace names either a process running
    inside a bwrap sandbox right now, or is otherwise not us -- either way
    it is not the worker that (claims to have) written this file, and the
    fleet_health pids seen 2026-09-27 (3, 4, 6, 9, 12, 20, 35, 128 -- low
    numbers typical of a sandbox's own nested pid counting) are exactly
    this shape. Fails open (False) when either namespace cannot be read,
    so the existing liveness/starttime checks still apply.
    """
    own = _pid_namespace(os.getpid())
    other = _pid_namespace(pid)
    if own is None or other is None:
        return False
    return own != other


def _classify(record: dict, now: float) -> tuple[str, float]:
    age = now - float(record.get("ts") or 0.0)
    pid, host = record.get("pid"), record.get("host")
    interval = record.get("interval", 0.0)
    # A pid is only meaningful on the host that recorded it; cross-host records
    # fall back to age alone rather than probing an unrelated local process.
    if host == socket.gethostname() and isinstance(pid, int):
        if _pid_in_foreign_namespace(pid):
            return "dead", age
        if not _pid_alive(pid):
            return "dead", age
        # The pid is live — but is it the process that wrote this file? A
        # recycled pid (gap c400089095c7) answers os.kill(pid, 0) for a
        # stranger. When the writer recorded its start time, require a match.
        recorded = record.get("starttime")
        if isinstance(recorded, int):
            live = _proc_starttime(pid)
            if live is not None and live != recorded:
                return "dead", age
    # Far past its own interval is dead whatever the pid says: no worker goes
    # twenty intervals (floor ten minutes) without a tick and is still the one
    # you want to count. This is what retires a phantom that predates the
    # starttime field, and any cross-host record nobody can probe.
    if age > dead_after(interval):
        return "dead", age
    if age > stale_after(interval):
        return "stale", age
    return "alive", age


def _readiness_from_states(states: set) -> str:
    """Collapse a set of worker states into a single readiness verdict.

    Only a fresh, live tick (`alive`) is ready; `stale`/`dead`/absent are not.
    """
    if "alive" in states:
        return "alive"
    if "stale" in states:
        return "stale"
    if "dead" in states:
        return "dead"
    return "absent"


def read_workers(root: Path | None = None) -> dict:
    """Report every worker that has published a heartbeat.

    States: `alive` (ticking), `stale` (file fresh enough to exist but its ticks
    stopped), `dead` (its pid is gone from this host). Only `alive` counts.

    `by_lane` rolls the same verdict up per lane so an alive worker in one lane
    never masks a stranded peer lane (Loki DD0114E5 §2.2).
    """
    root = Path(root) if root is not None else heartbeat_root()
    check: dict = {
        "root": str(root),
        "workers": [],
        "alive": 0,
        "readiness": "absent",
    }
    try:
        if not root.exists():
            check["status"] = "ok"
            return check
        now = time.time()
        for f in sorted(root.glob("*.json")):
            try:
                record = json.loads(f.read_text())
            except Exception:
                logger.debug("unreadable heartbeat file %s", f, exc_info=True)
                continue
            state, age = _classify(record, now)
            check["workers"].append({
                "agent": record.get("agent"),
                "lane": record.get("lane"),
                "pid": record.get("pid"),
                "host": record.get("host"),
                "state": state,
                "age_s": round(age, 1),
                "last_tick_ok": record.get("tick_ok"),
            })
        check["alive"] = sum(1 for w in check["workers"] if w["state"] == "alive")
        states = {worker["state"] for worker in check["workers"]}
        check["readiness"] = _readiness_from_states(states)
        by_lane: dict = {}
        for worker in check["workers"]:
            lane = worker.get("lane") or "unknown"
            bucket = by_lane.setdefault(
                lane, {"alive": 0, "stale": 0, "dead": 0, "readiness": "absent"}
            )
            if worker["state"] in bucket:
                bucket[worker["state"]] += 1
        for bucket in by_lane.values():
            lane_states = {s for s in ("alive", "stale", "dead") if bucket[s]}
            bucket["readiness"] = _readiness_from_states(lane_states)
        check["by_lane"] = by_lane
        check["status"] = "ok"
    except Exception as e:
        check["status"] = "fail"
        check["error"] = str(e)[:160]
    return check


def live_worker_keys(root: Path | None = None) -> set:
    """`(host, pid)` of every worker whose heartbeat currently classifies `alive`.

    The task queue's liveness-aware reap uses this to distinguish a slow-but-living
    worker from a dead one. Best-effort: any read error yields an empty set, and
    callers must keep their own same-host pid-liveness fallback for that case.
    """
    root = Path(root) if root is not None else heartbeat_root()
    keys: set = set()
    if not root.exists():
        return keys
    now = time.time()
    for f in sorted(root.glob("*.json")):
        try:
            record = json.loads(f.read_text())
        except Exception:
            logger.debug("unreadable heartbeat file %s", f, exc_info=True)
            continue
        if _classify(record, now)[0] != "alive":
            continue
        host, pid = record.get("host"), record.get("pid")
        if isinstance(host, str) and isinstance(pid, int):
            keys.add((host, pid))
    return keys


def reap(root: Path | None = None) -> int:
    """Delete heartbeat files whose process is gone. Returns the count removed."""
    root = Path(root) if root is not None else heartbeat_root()
    removed = 0
    if not root.exists():
        return 0
    now = time.time()
    for f in sorted(root.glob("*.json")):
        try:
            record = json.loads(f.read_text())
        except Exception:
            logger.debug("unreadable heartbeat file %s", f, exc_info=True)
            continue
        if _classify(record, now)[0] == "dead":
            try:
                f.unlink(missing_ok=True)
                removed += 1
            except Exception:
                logger.debug("reap unlink failed: %s", f, exc_info=True)
    return removed
