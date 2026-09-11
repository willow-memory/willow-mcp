"""willow_mcp/activation.py — surface-only Grove wake activation.

Grove activation rail, slice 1 (operator-ratified — see
docs/design/grove-activation-rail.md): dispatch_send now posts an
Intent.WAKE Grove envelope (``grove_tools.post_wake_envelope``); ratatosk's
``BusListener``/``SeatDaemon`` already route a received WAKE to an
``activate(env)`` callback, but until this module existed that callback was
``daemon.default_activate`` — a no-op that only proves the wake arrived.

"Surface-only" is the whole point of this slice: ``activate`` here does not
spawn a process, does not start an agent, and does not touch Kart. It writes
ONE line to the seat's own grove-listen log — the exact path and line shape
``willow_mcp.grove_listen`` already writes, and that
``skills/session-start.md`` already documents Claude Code tailing with
``Monitor`` — so a session that is (or starts) watching that file notices
the wake exactly the way it notices a bus-addressed message today. Spawning
the seat's own runtime automatically on a wake is the DEFERRED fork out of
scope here; see the design doc's "Deferred" section.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Optional

from ratatosk.protocol.envelope import Envelope

from . import grove_listen

logger = logging.getLogger(__name__)


def _wake_line(app_id: str, env: Envelope) -> str:
    """One grove-listen-format line for a WAKE envelope.

    Mirrors the bracket-tag / ``#channel`` / arrow shape
    ``grove_listen.classify`` already produces for a bus-addressed message
    (``[BUS:COMMAND] #dispatch id=44 willow -> vishwakarma: ...`` — see that
    module's docstring and ``skills/session-start.md``'s mention table), so
    a reader already trained on those tags reads a wake the same way.

    There is no real ``grove.messages`` row id available here — a WAKE
    reaches ``activate`` through ratatosk's ``BusListener`` after
    ``grove_tools.post_wake_envelope`` already posted it, not through
    ``grove_listen``'s own LISTEN/NOTIFY drain of that same row — so
    ``trace=<trace_id>`` stands in for ``id=<id>``: it is the one identifier
    that actually ties this line back to the dispatch packet
    (``dispatch=<id>`` is appended too, when the envelope carries one).
    """
    dispatch_id = str((env.extra or {}).get("dispatch_id") or "")
    preview = " ".join((env.prompt or "").split())[:80]
    channel = env.reply_channel or app_id
    line = f"[WAKE] #{channel} trace={env.trace_id} {env.from_agent} -> {app_id}"
    if dispatch_id:
        line += f" dispatch={dispatch_id}"
    return f"{line}: {preview}" if preview else line


def build_activate(
    app_id: str, *, log_path: Optional[Path] = None
) -> Callable[[Envelope], str]:
    """Build the real ``activate`` callable for ``app_id``'s ``SeatDaemon``.

    Surface-only: appends a ``[WAKE]`` line to
    ``$WILLOW_HOME/logs/grove-listen-<app_id>.log`` (``log_path`` overrides
    this, mainly for tests) — the identical file
    ``willow_mcp.grove_listen.default_log_path`` resolves to and appends
    lines to — and returns an honest trace string describing what actually
    happened. No process is spawned, no agent runs; the seat's own session,
    if one is open and tailing that log, is what notices next.

    A failure to write the line (permission error, missing parent that
    cannot be created, disk full) is logged and reflected honestly in the
    returned trace string rather than raised — the caller here is
    ``BusListener.process_message``'s handler dispatch, which is not
    prepared for ``activate`` to raise, and a silently-swallowed exception
    there is worse than an honest "log write failed" trace.
    """
    path = log_path or grove_listen.default_log_path(app_id)

    def activate(env: Envelope) -> str:
        line = _wake_line(app_id, env)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            logger.error(
                "activation: failed writing wake line to %s", path, exc_info=True
            )
            return f"[{app_id}] wake trace={env.trace_id} received — log write failed"
        return f"[{app_id}] wake trace={env.trace_id} noticed — logged to {path}"

    return activate
