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

# A worker rewrites its file every loop tick: `interval` seconds when idle, ~0.5s
# when busy. Three missed idle ticks (floor 30s) is a real absence, not a slow
# poll — long enough that a worker mid-`bwrap`-setup is never called dead.
_STALE_FLOOR_S = 30.0
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
        self.host = socket.gethostname()
        self.root = Path(root) if root is not None else heartbeat_root()
        self.path = self.root / f"{self.agent}-{self.lane}-{self.pid}.json"
        self._last_write = 0.0
        self._warned = False

    def __call__(self, *, lane: str | None = None, tick_ok: bool = True, **_) -> None:
        now = time.time()
        if now - self._last_write < _MIN_WRITE_INTERVAL_S:
            return
        self._last_write = now
        record = {
            "agent": self.agent,
            "lane": lane or self.lane,
            "pid": self.pid,
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


def _classify(record: dict, now: float) -> tuple[str, float]:
    age = now - float(record.get("ts") or 0.0)
    pid, host = record.get("pid"), record.get("host")
    # A pid is only meaningful on the host that recorded it; cross-host records
    # fall back to age alone rather than probing an unrelated local process.
    if host == socket.gethostname() and isinstance(pid, int) and not _pid_alive(pid):
        return "dead", age
    if age > stale_after(record.get("interval", 0.0)):
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
