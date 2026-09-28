"""Production Kart worker — drains willow_20 via PgTaskQueue + kartikeya.

Entry points:
  - ``python -m willow_mcp.worker`` (systemd / operator cutover)
  - ``willow-mcp worker`` (console script — delegates here)

Caps-on execution only: tasks run through kartikeya ``sandbox.run_shell`` with
cgroup/rlimit limits. No willow-2.0 ``run_shell`` import.
"""
from __future__ import annotations

import argparse
import os
import sys


def _default_app_id() -> str:
    return os.environ.get("WILLOW_APP_ID", "").strip()


def _lane_from_env(default: str = "fast") -> str:
    return (
        os.environ.get("WILLOW_WORKER_LANE")
        or os.environ.get("KART_WORKER_LANE")
        or default
    ).strip().lower()


def check_sandbox_config(*, require_fleet_config: bool) -> str:
    """Resolve the mount policy this worker will execute under, and report it.

    A production worker that cannot find the fleet policy falls back to
    kartikeya's vendored product-neutral default. That fallback is silent and
    total: every task it then runs gets a reduced bind set, and on this fleet
    that manifests as ``bwrap: Creating new namespace failed`` on every single
    task — for as long as the process stays up. A worker started on
    2026-07-20 dead-lettered the whole batch lane for 28 hours that way,
    because nothing in the task result distinguished "wrong policy" from
    "policy says no".

    So: name the policy at startup, and refuse to serve a production lane on
    the generic one. A unit that fails to start is visible; a unit that runs
    and fails every task is not.

    kartikeya is asked to report its own resolution and is not second-guessed.
    There used to be a fallback here for a kartikeya without the reporting API,
    which named the source by re-implementing `load_sandbox_config`'s search
    order locally. It is gone, on the same principle as the paragraph above.
    Two reasons, in rising order:

    * It cannot be reached by an installed kartikeya. `resolve_sandbox_config`
      and `is_vendored_default` shipped in 0.0.8, and `pyproject.toml` floors
      the dependency at 0.0.9.
    * It was a second copy of another package's search order, kept in step by
      nothing. If kartikeya's order moves, the copy names a policy that is not
      the one bwrap is handed — a worker that reports a policy it is not running
      under, which is the exact failure this function exists to prevent, wearing
      a success message.

    What is left to reach it is an unresolved source checkout or a vendored copy
    on `PYTHONPATH` — a development loop, where a startup ImportError naming the
    floor is the visible failure and the right one.

    Returns the resolved config source.
    """
    try:
        from kartikeya.sandbox import is_vendored_default, resolve_sandbox_config
    except ImportError as exc:
        raise RuntimeError(
            "refusing to start: the installed kartikeya cannot report its "
            "resolved sandbox policy (no sandbox.resolve_sandbox_config). That "
            "API ships in kartikeya 0.0.8+, and this package requires "
            ">=0.0.9 — so this is a source checkout or a vendored copy ahead of "
            "the installed wheel, not a supported install. Reinstall kartikeya "
            "from PyPI, or update the checkout."
        ) from exc

    _cfg, source = resolve_sandbox_config()
    generic = is_vendored_default(source)
    print(f"willow-mcp worker: sandbox policy {source}", file=sys.stderr)
    if generic and require_fleet_config:
        raise RuntimeError(
            "refusing to start: resolved kartikeya's vendored default sandbox "
            f"policy ({source}), not a fleet policy. Set KART_SANDBOX_CONFIG "
            "in the unit's Environment= (an EnvironmentFile edit does NOT reach "
            "an already-running process), or place the policy at "
            "$WILLOW_HOME/kart-sandbox.json. Pass --allow-generic-sandbox to "
            "serve on the generic policy deliberately."
        )
    return source


def run_worker_daemon(
    *,
    app_id: str,
    lane: str | None = None,
    slots: int | None = None,
    interval: float = 5.0,
    once: bool = False,
    require_postgres: bool = False,
    allow_generic_sandbox: bool = False,
) -> None:
    """Drain the adopted Postgres queue until stopped (or once=True, until empty)."""
    try:
        import kartikeya
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "willow-mcp worker requires the 'kartikeya' package — "
            "reinstall with `pip install willow-mcp` or `pip install -e .`"
        ) from exc

    from .commitments.proactive import CommitmentProactiveHook, chain_heartbeat
    from .egress_authorization import ExecutorNetworkAuthorizer
    from .heartbeat import WorkerHeartbeat, reap
    from .soil_heartbeat import SoilWatchmenHeartbeat
    from .task_queue import build_task_queue

    lane = (lane or _lane_from_env()).strip().lower()
    if lane not in ("fast", "batch"):
        raise ValueError(f"lane must be fast|batch, got {lane!r}")

    production = require_postgres or lane == "batch"
    check_sandbox_config(require_fleet_config=production and not allow_generic_sandbox)

    queue = build_task_queue(app_id, require_postgres=production)
    reap()

    file_beat = WorkerHeartbeat(agent="kart", lane=lane, interval=interval)
    beat = chain_heartbeat(file_beat, SoilWatchmenHeartbeat(lane))

    def _worker_commitment_surface():
        from datetime import datetime

        from .server import _commitment_ledger_restored

        return _commitment_ledger_restored().dew_surface(datetime.utcnow())

    beat = chain_heartbeat(
        beat,
        CommitmentProactiveHook(surface_fn=_worker_commitment_surface),
    )
    network_authorizer = ExecutorNetworkAuthorizer()
    try:
        kartikeya.run_worker(
            queue,
            lane=lane,
            slots=slots,
            interval=interval,
            once=once,
            on_heartbeat=beat,
            network_authorizer=network_authorizer,
        )
    finally:
        file_beat.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="willow_mcp.worker",
        description="Drain the Kart task queue via PgTaskQueue + kartikeya (caps on).",
    )
    parser.add_argument("--lane", default=None, choices=["fast", "batch"],
                        help="worker lane (default: WILLOW_WORKER_LANE or KART_WORKER_LANE or fast)")
    parser.add_argument("--slots", type=int, default=None,
                        help="worker concurrency for the selected lane (default: "
                             "KART_FAST_WORKERS or 3 for fast, KART_BATCH_WORKERS or 1 for batch)")
    parser.add_argument("--interval", type=float, default=5.0,
                        help="idle poll interval in seconds")
    parser.add_argument("--once", action="store_true",
                        help="drain pending tasks and exit")
    parser.add_argument(
        "--require-postgres",
        action="store_true",
        help="refuse the SQLite fallback (required for production lane workers)",
    )
    parser.add_argument(
        "--allow-generic-sandbox",
        action="store_true",
        help="serve a production lane on kartikeya's vendored default mount policy "
             "(default: refuse — see check_sandbox_config)",
    )
    parser.add_argument(
        "--app-id",
        dest="app_id",
        default=None,
        help="schema-profile app id (default: WILLOW_APP_ID)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    app_id = (args.app_id or _default_app_id()).strip()
    if not app_id:
        print(
            "willow-mcp worker: WILLOW_APP_ID (or --app-id) is required",
            file=sys.stderr,
        )
        return 1
    lane = args.lane or _lane_from_env()
    try:
        run_worker_daemon(
            app_id=app_id,
            lane=lane,
            slots=args.slots,
            interval=args.interval,
            once=args.once,
            require_postgres=args.require_postgres,
            allow_generic_sandbox=args.allow_generic_sandbox,
        )
    except (RuntimeError, ValueError) as exc:
        print(f"willow-mcp worker: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
