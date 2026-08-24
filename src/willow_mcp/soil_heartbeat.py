"""Fleet SOIL watchmen heartbeats — parity with willow-2.0 core.loop_heartbeat.

Legacy kart_worker writes throttled ticks to collection ``willow/loops/heartbeat``
(record ids ``kart_worker`` / ``kart_worker_batch``) so fleet watchmen can tell a
dead loop from a quiet one. willow-mcp's flat Store API rejects slash collections,
so this module writes the canonical ``{collection}.db`` layout directly under
``$WILLOW_STORE_ROOT`` (same files willow-2.0's WillowStore opens).
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("willow_mcp.soil_heartbeat")

HEARTBEAT_SOIL_COLLECTION = "willow/loops/heartbeat"
_DEFAULT_INTERVAL_S = 900
_WATCHMEN_BY_LANE = {
    "fast": "kart_worker",
    "batch": "kart_worker_batch",
}

_last_mono: dict[str, float] = {}
_lock = threading.Lock()


def store_root() -> Path:
    return Path(
        os.environ.get(
            "WILLOW_STORE_ROOT",
            Path(os.environ.get("WILLOW_HOME", Path.home() / ".willow")) / "store",
        )
    ).expanduser().resolve()


def soil_db_path(collection: str, *, root: Path | None = None) -> Path:
    """Resolve a fleet SOIL collection to its on-disk ``{name}.db`` path."""
    base = (root or store_root()).resolve()
    clean = collection.strip().strip("/")
    if not clean or ".." in clean.split("/"):
        raise ValueError(f"invalid SOIL collection: {collection!r}")
    parts = clean.split("/")
    db_dir = base.joinpath(*parts[:-1]) if len(parts) > 1 else base
    db_path = (db_dir / f"{parts[-1]}.db").resolve()
    if not str(db_path).startswith(str(base)):
        raise ValueError(f"path escape blocked for collection: {collection!r}")
    return db_path


def interval_sec_for(watchmen_key: str) -> int:
    raw = os.environ.get(
        f"WILLOW_SOIL_HEARTBEAT_INTERVAL_{watchmen_key.upper()}",
        os.environ.get("WILLOW_SOIL_HEARTBEAT_INTERVAL", ""),
    ).strip()
    if raw:
        try:
            return max(1, int(raw))
        except ValueError:
            pass
    return _DEFAULT_INTERVAL_S


def watchmen_key_for_lane(lane: str) -> str:
    key = _WATCHMEN_BY_LANE.get((lane or "fast").strip().lower())
    if not key:
        raise ValueError(f"lane must be fast|batch, got {lane!r}")
    return key


def write_watchmen_heartbeat(
    watchmen_key: str,
    *,
    tick_ok: bool = True,
    interval_sec: int | None = None,
    **extra,
) -> bool:
    """Write one heartbeat record. Returns False on lookup or SOIL errors."""
    interval = interval_sec if interval_sec is not None else interval_sec_for(watchmen_key)
    payload = {
        "last_tick_at": datetime.now(timezone.utc).isoformat(),
        "interval_sec": interval,
        "tick_ok": bool(tick_ok),
        "pid": os.getpid(),
        **extra,
    }
    try:
        db_path = soil_db_path(HEARTBEAT_SOIL_COLLECTION)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS records (
                    id         TEXT PRIMARY KEY,
                    data       TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    deviation  REAL NOT NULL DEFAULT 0.0,
                    action     TEXT NOT NULL DEFAULT 'work_quiet',
                    deleted    INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                "INSERT INTO records "
                "(id, data, created_at, updated_at, deviation, action, deleted) "
                "VALUES (?, ?, ?, ?, 0.0, 'work_quiet', 0) "
                "ON CONFLICT(id) DO UPDATE SET "
                "data=excluded.data, updated_at=excluded.updated_at",
                (watchmen_key, json.dumps(payload), now, now),
            )
            conn.commit()
        finally:
            conn.close()
        return True
    except Exception as exc:
        logger.debug("SOIL heartbeat write skipped for %s: %s", watchmen_key, exc)
        return False


def write_throttled(
    watchmen_key: str,
    *,
    tick_ok: bool = True,
    **extra,
) -> bool:
    """Write at most once per interval (per process, per key)."""
    interval = interval_sec_for(watchmen_key)
    now = time.monotonic()
    with _lock:
        last = _last_mono.get(watchmen_key, 0.0)
        if last and (now - last) < interval:
            return False
        if write_watchmen_heartbeat(
            watchmen_key, tick_ok=tick_ok, interval_sec=interval, **extra
        ):
            _last_mono[watchmen_key] = now
            return True
    return False


def reset_throttle(watchmen_key: str = "") -> None:
    """Test helper — clear throttle state for one key or all keys."""
    with _lock:
        if watchmen_key:
            _last_mono.pop(watchmen_key, None)
        else:
            _last_mono.clear()


class SoilWatchmenHeartbeat:
    """``on_heartbeat`` callback publishing fleet watchmen SOIL ticks."""

    def __init__(self, lane: str):
        self.lane = (lane or "fast").strip().lower()
        self.watchmen_key = watchmen_key_for_lane(self.lane)

    def __call__(self, *, lane: str | None = None, tick_ok: bool = True, **extra) -> None:
        key = watchmen_key_for_lane(lane or self.lane)
        write_throttled(key, tick_ok=tick_ok, **extra)
