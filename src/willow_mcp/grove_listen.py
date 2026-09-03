"""willow_mcp/grove_listen.py — the seat's ear on the Grove.

willow-2.0 had ``willow/grove_listen.py``: a per-agent Postgres LISTEN/NOTIFY
monitor that a SessionStart hook launched, that printed one line per message
that concerned the agent, and that Claude Code tailed with a Monitor. That is
what turned a Grove bus message into an agent actually noticing. The Grove
tool surface came over to willow-mcp in full (``grove_tools.py``, 20 tools);
the listener did not, and the fleet has been deaf since: ``grove_inbox`` and
``grove_watch`` are polls, and a seat that is not polling hears nothing. This
module is the listener, rebuilt on willow-mcp's own gate and data layer.

What it does
------------
* Opens its OWN Postgres connection (``LISTEN`` needs a dedicated one; the
  shared ``db.get_pg()`` autocommit connection is every tool's, never a
  listener's), ``LISTEN grove_channel``, and waits. Grove's schema fires
  ``pg_notify('grove_channel', channel_id)`` on every insert into
  ``grove.messages`` (canonical ``grove_db.init_schema``).
* On a notify, drains that channel with ``WHERE id > cursor`` — so coalesced or
  missed notifies are harmless; the next drain catches up from the last id.
* Classifies each new row for THIS seat and writes one line per hit to a log
  file (and stdout). A Claude Code session tails the file. Lines:

    [MENTION:BROADCAST] #general id=42 willow: @all ...
    [MENTION:DIRECT:vishwakarma] #general id=43 willow: @vish ...
    [BUS:COMMAND] #dispatch id=44 willow -> vishwakarma: ...
    [INBOX] #vishwakarma id=45 willow: ...
    [CHANNEL] #architecture id=46 loki: ...        (only for --verbose-channels)

* Announces presence with a ``HEARTBEAT`` bus message on start and every
  ``--heartbeat`` seconds, so ``grove_agents`` / ``grove_fleet_status`` show
  the seat alive. Heartbeat is a write and needs ``grove_write``; a seat with
  only ``grove_read`` still listens, it just does not announce.

What it will not do
-------------------
* Run for a seat the manifest gate would refuse. The listener checks
  ``gate.permitted(app_id, "grove_inbox")`` before touching Postgres and exits
  2 with the same wording the tools use. A missing manifest is a denial.
* Speak as anyone but the seat. The heartbeat sender is
  ``grove_tools.resolve_grove_sender(app_id)``, never a flag.
* Act on what it hears. It reports; the seat decides. No dispatch, no reply,
  no Kart. (2.0's version was the same: a monitor, not an agent.)
* Run twice for one seat. A ``flock`` on the log's sibling ``.lock`` makes a
  second launch exit 0 with one line.

Run
---
    willow-mcp grove-listen --app-id vishwakarma
    willow-mcp grove-listen --app-id willow --verbose-channels dispatch,alerts
    python -m willow_mcp.grove_listen --app-id loki --once   # drain + exit

Log: ``$WILLOW_HOME/logs/grove-listen-<app_id>.log`` (override ``--log``).
"""
from __future__ import annotations

import argparse
import fcntl
import os
import re
import select
import sys
import time
from functools import lru_cache
from pathlib import Path
from typing import IO, Iterable, Optional

from . import gate
from . import grove

# ── identity ─────────────────────────────────────────────────────────────────

#: Short handles a seat answers to besides ``@<agent>``. Ported from 2.0's
#: ALIASES verbatim; the registry carries no alias field today, so this is the
#: one table. Extend here, not in a seat's env.
ALIASES: dict[str, list[str]] = {
    "hanuman": ["@hanuman", "@hanu"],
    "vishwakarma": ["@vishwakarma", "@vish", "@karma"],
    "auto": ["@auto"],
}

_BROADCAST_RE = re.compile(r"(?:^|[^a-z0-9_])@all(?:[^a-z0-9_]|$)", re.IGNORECASE)

#: Bus rows that are presence/plumbing, never something to wake a seat for.
_BUS_NOISE = frozenset({"HEARTBEAT", "ACK"})


def resolve_identity(app_id: str) -> str:
    """The name this seat posts and is addressed as. Registry ``grove_sender``
    when a specialist row exists, else the app_id — same rule the tools use."""
    try:
        from .grove_tools import resolve_grove_sender
        return resolve_grove_sender(app_id) or app_id
    except Exception:  # noqa: BLE001 — registry absent: the seat is its app_id
        return app_id


def watch_identities(agent: str, extra: Optional[Iterable[str]] = None) -> list[str]:
    """Identities whose @mentions this listener reports: the seat first, then
    any extras (``--watch``, or ``GROVE_MENTION_WATCH``), de-duplicated
    case-insensitively, order kept. 2.0 also folded in ``Auto`` by default;
    willow-mcp has no Auto seat, so nothing is implied."""
    seen: set[str] = set()
    out: list[str] = []
    for name in [agent, *(extra or [])]:
        n = (name or "").strip()
        if not n or n.lower() in seen:
            continue
        seen.add(n.lower())
        out.append(n)
    return out


@lru_cache(maxsize=64)
def _alias_regex(alias: str) -> re.Pattern:
    handle = alias.lstrip("@")
    return re.compile(rf"(?:^|[^a-z0-9_])@{re.escape(handle)}(?:[^a-z0-9_]|$)", re.IGNORECASE)


def is_broadcast_mention(content: str) -> bool:
    return _BROADCAST_RE.search(content or "") is not None


def is_direct_mention(content: str, agent: str) -> bool:
    for alias in ALIASES.get(agent.lower(), [f"@{agent}"]):
        if _alias_regex(alias).search(content or ""):
            return True
    return False


def direct_mention_identity(content: str, identities: Iterable[str]) -> Optional[str]:
    """Which watched identity, if any, is @mentioned in ``content``."""
    for name in identities:
        if is_direct_mention(content, name):
            return name
    return None


# ── classification ───────────────────────────────────────────────────────────

def classify(row: dict, *, agent: str, identities: Iterable[str],
             verbose: Iterable[str] = ()) -> Optional[str]:
    """One line for a ``grove.messages`` row if it concerns this seat, else
    ``None``. Pure: no I/O, so it is the whole of what the tests pin.

    ``row`` needs: id, channel (name), sender, content; optional: to_agent,
    bus_type. Precedence: broadcast, direct mention, bus-addressed, own
    channel, verbose channel. A seat's own posts never wake it.
    """
    sender = str(row.get("sender") or "")
    content = str(row.get("content") or "")
    channel = str(row.get("channel") or row.get("channel_id") or "?")
    msg_id = row.get("id")
    bus_type = str(row.get("bus_type") or "").upper()
    to_agent = str(row.get("to_agent") or "")
    me = agent.lower()
    own_post = sender.lower() == me
    preview = " ".join(content.split())[:80]
    tail = f" #{channel} id={msg_id} {sender}"

    def _line(tag: str, arrow: str = "") -> str:
        line = f"[{tag}]{tail}{arrow}"
        return f"{line}: {preview}" if preview else line

    if bus_type in _BUS_NOISE:
        return None
    if not own_post and is_broadcast_mention(content):
        return _line("MENTION:BROADCAST")
    who = None if own_post else direct_mention_identity(content, identities)
    if who:
        return _line(f"MENTION:DIRECT:{who}")
    if not own_post and bus_type and to_agent.lower() == me:
        return _line(f"BUS:{bus_type}", f" -> {to_agent}")
    if not own_post and channel.lower() == me.replace(" ", "-"):
        return _line("INBOX")
    if channel.lower() in {v.lower() for v in verbose}:
        return _line("CHANNEL")
    return None


# ── postgres ─────────────────────────────────────────────────────────────────

def connect():
    """A dedicated autocommit connection for LISTEN. Same env contract as
    ``db.get_pg`` but defaulting to ``willow_20``, where grove.* lives (the
    DB-name trap ``grove.py`` documents)."""
    import psycopg2
    dsn = os.environ.get("WILLOW_DB_URL")
    if dsn:
        conn = psycopg2.connect(dsn)
    else:
        conn = psycopg2.connect(
            dbname=os.environ.get("WILLOW_PG_DB", "willow_20"),
            user=os.environ.get("WILLOW_PG_USER", os.environ.get("USER", "")),
        )
    conn.autocommit = True
    return conn


def load_channels(cur) -> dict[int, str]:
    cur.execute("SELECT id, name FROM grove.channels WHERE is_archived = FALSE")
    return {int(r[0]): str(r[1]) for r in cur.fetchall()}


def seed_cursors(cur, channel_ids: Iterable[int]) -> dict[int, int]:
    """Start at each channel's newest id: a fresh listener reports what
    arrives from now, not the archive. ``--since`` overrides."""
    ids = list(channel_ids)
    cursors = {cid: 0 for cid in ids}
    if ids:
        cur.execute(
            "SELECT channel_id, COALESCE(MAX(id), 0) FROM grove.messages"
            " WHERE channel_id = ANY(%s) GROUP BY channel_id", (ids,))
        for cid, mx in cur.fetchall():
            cursors[int(cid)] = int(mx)
    return cursors


def drain_channel(cur, ch_id: int, ch_name: str, cursors: dict[int, int]) -> list[dict]:
    """Rows in ``ch_id`` newer than the cursor, oldest first; advances the
    cursor. Idempotent on repeat — ``id > cursor`` is the whole contract."""
    cur.execute(
        "SELECT id, sender, content, to_agent, bus_type FROM grove.messages"
        " WHERE channel_id = %s AND id > %s AND is_deleted = 0 ORDER BY id ASC",
        (ch_id, cursors.get(ch_id, 0)))
    rows = []
    for mid, sender, content, to_agent, bus_type in cur.fetchall():
        cursors[ch_id] = int(mid)
        rows.append({"id": int(mid), "channel": ch_name, "sender": sender,
                     "content": content, "to_agent": to_agent, "bus_type": bus_type})
    return rows


# ── the listener ─────────────────────────────────────────────────────────────

class Listener:
    def __init__(self, app_id: str, *, log: IO[str], watch: Iterable[str] = (),
                 verbose: Iterable[str] = (), heartbeat_s: int = 300,
                 since: Optional[int] = None, echo: bool = True) -> None:
        self.app_id = app_id
        self.agent = resolve_identity(app_id)
        self.identities = watch_identities(self.agent, list(watch) + [app_id])
        self.verbose = [v.strip() for v in verbose if v.strip()]
        self.heartbeat_s = max(0, int(heartbeat_s))
        self.since = since
        self.log = log
        self.echo = echo
        self.can_write = gate.permitted(app_id, "grove_heartbeat")
        self._last_hb = 0.0
        self.conn = None
        self.cur = None
        self.channels: dict[int, str] = {}
        self.cursors: dict[int, int] = {}

    # output
    def emit(self, line: str) -> None:
        self.log.write(line + "\n")
        self.log.flush()
        if self.echo:
            print(line, flush=True)

    def note(self, text: str) -> None:
        self.emit(f"[grove-listen] {text}")

    # lifecycle
    def open(self) -> None:
        self.conn = connect()
        self.cur = self.conn.cursor()
        self.channels = load_channels(self.cur)
        fresh = seed_cursors(self.cur, self.channels)
        if self.since is not None:
            fresh = {cid: int(self.since) for cid in fresh}
        # keep cursors across reconnects; only new channels take the seed
        for cid, v in fresh.items():
            self.cursors.setdefault(cid, v)
        self.cur.execute("LISTEN grove_channel")

    def heartbeat(self, force: bool = False) -> None:
        if not self.can_write or not self.heartbeat_s:
            return
        now = time.monotonic()
        if not force and now - self._last_hb < self.heartbeat_s:
            return
        self._last_hb = now
        try:
            channels = grove.list_channels(self.conn)
            ch = grove.find_channel_in(channels, "general") or (channels[0] if channels else None)
            if ch:
                grove.bus_send(self.conn, channel_id=int(ch["id"]), sender=self.agent,
                               content=f"{self.agent} listening", bus_type="HEARTBEAT",
                               priority=6)
        except Exception as e:  # noqa: BLE001 — presence is best-effort
            self.note(f"heartbeat skipped: {e}")

    def drain(self, ch_ids: Iterable[int]) -> int:
        hits = 0
        for cid in ch_ids:
            if cid not in self.channels:
                self.channels = load_channels(self.cur)
                self.cursors.setdefault(cid, 0)
            name = self.channels.get(cid, str(cid))
            for row in drain_channel(self.cur, cid, name, self.cursors):
                line = classify(row, agent=self.agent, identities=self.identities,
                                verbose=self.verbose)
                if line:
                    self.emit(line)
                    hits += 1
        return hits

    def drain_all(self) -> int:
        return self.drain(list(self.channels))

    def reconnect(self) -> None:
        stale = self.conn
        self.conn = None
        try:
            self.open()
        finally:
            try:
                if stale is not None:
                    stale.close()
            except Exception:  # noqa: BLE001
                pass
        # the disconnect window: id > cursor makes this a no-op if nothing came
        self.drain_all()

    def run(self, *, once: bool = False, timeout_s: float = 30.0) -> None:
        self.open()
        self.heartbeat(force=True)
        self.note(f"ready as {self.agent} (app_id={self.app_id}) — "
                  + ", ".join(f"#{n}" for n in self.channels.values())
                  + ("" if self.can_write else " — read-only, no heartbeat"))
        if once:
            n = self.drain_all()
            self.note(f"drained, {n} line(s)")
            return
        while True:
            try:
                self.heartbeat()
                if select.select([self.conn], [], [], timeout_s)[0]:
                    self.conn.poll()
                    notified: set[int] = set()
                    while self.conn.notifies:
                        n = self.conn.notifies.pop(0)
                        try:
                            notified.add(int(n.payload))
                        except (TypeError, ValueError):
                            pass
                    self.drain(sorted(notified))
            except KeyboardInterrupt:
                raise
            except Exception as e:  # noqa: BLE001 — stay at the post
                self.note(f"error: {e} — reconnecting")
                try:
                    self.reconnect()
                except Exception as e2:  # noqa: BLE001
                    self.note(f"reconnect failed: {e2}")
                    time.sleep(5)


# ── entry ────────────────────────────────────────────────────────────────────

def default_log_path(app_id: str) -> Path:
    home = os.environ.get("WILLOW_HOME") or str(Path.home() / ".willow")
    return Path(home) / "logs" / f"grove-listen-{app_id}.log"


def _single_instance(lock_path: Path):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(lock_path, "a+", encoding="utf-8")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fh.close()
        return None
    fh.seek(0)
    fh.truncate()
    fh.write(f"{os.getpid()}\n")
    fh.flush()
    return fh


def build_parser(parser: Optional[argparse.ArgumentParser] = None) -> argparse.ArgumentParser:
    p = parser or argparse.ArgumentParser(
        prog="willow-mcp grove-listen",
        description="Listen on the Grove for this seat and log what concerns it.")
    p.add_argument("--app-id", required=True, dest="app_id",
                   help="the seat listening; must hold grove_read")
    p.add_argument("--log", default="", help="log file (default $WILLOW_HOME/logs/grove-listen-<app_id>.log)")
    p.add_argument("--watch", default=os.environ.get("GROVE_MENTION_WATCH", ""),
                   help="extra @handles to report, comma-separated")
    p.add_argument("--verbose-channels", default=os.environ.get("GROVE_VERBOSE_CHANNELS", ""),
                   help="channels to log every message of, comma-separated")
    p.add_argument("--heartbeat", type=int, default=300,
                   help="seconds between HEARTBEAT bus messages (0 = never)")
    p.add_argument("--since", type=int, default=None,
                   help="start from this message id instead of each channel's newest")
    p.add_argument("--once", action="store_true", help="drain once and exit")
    p.add_argument("--quiet", action="store_true", help="log file only, no stdout")
    return p


def main(args: Optional[argparse.Namespace] = None, argv: Optional[list[str]] = None) -> int:
    if args is None:
        args = build_parser().parse_args(argv)
    app_id = args.app_id.strip()
    if not gate.permitted(app_id, "grove_inbox"):
        print(f"gate denied: '{app_id}' not permitted for 'grove_inbox'. "
              "Grant grove_read in the app manifest.", file=sys.stderr)
        return 2
    log_path = Path(args.log) if args.log else default_log_path(app_id)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    lock = _single_instance(log_path.with_suffix(".lock"))
    if lock is None:
        print(f"[grove-listen] already running for {app_id} — exiting", flush=True)
        return 0
    split = lambda s: [x.strip() for x in (s or "").split(",") if x.strip()]  # noqa: E731
    with open(log_path, "a", encoding="utf-8") as log:
        listener = Listener(app_id, log=log, watch=split(args.watch),
                            verbose=split(args.verbose_channels),
                            heartbeat_s=args.heartbeat, since=args.since,
                            echo=not args.quiet)
        try:
            listener.run(once=args.once)
        except KeyboardInterrupt:
            listener.note("stopped")
        except Exception as e:  # noqa: BLE001
            print(f"[grove-listen] connect failed: {e}", file=sys.stderr)
            return 1
        finally:
            lock.close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
