"""willow_mcp/activation.py — Grove wake activation + bounded local draft.

Grove activation rail, slice 1 (operator-ratified — see
docs/design/grove-activation-rail.md): dispatch_send posts an Intent.WAKE;
``activate`` appends a ``[WAKE]`` line to the seat's grove-listen log.

Session extension (triad close): after the wake line, attempt a loopback-only
``nestor.engine.OllamaEngine.draft_task`` triage of the wake prompt. Result
lands as ``$WILLOW_HOME/logs/wake-draft-<dispatch_id|trace>.json`` plus a
``[WAKE-DRAFT]`` log line. States are distinct: ``ok``, ``empty``,
``unreachable``. No cloud fallback, no ``nestor_propose``, no project writes,
no process spawn. Auto-spawning a seat runtime remains deferred.
"""
from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Optional

from ratatosk.protocol.envelope import Envelope

from . import grove_listen

logger = logging.getLogger(__name__)

#: Env: skip the local-draft attempt (tests / hosts without Ollama).
SKIP_LOCAL_DRAFT_ENV = "WILLOW_ACTIVATION_SKIP_LOCAL_DRAFT"


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


def _draft_id(env: Envelope) -> str:
    dispatch_id = str((env.extra or {}).get("dispatch_id") or "").strip()
    if dispatch_id:
        return dispatch_id
    return str(env.trace_id or "unknown")


def _draft_artifact_path(app_id: str, env: Envelope, *, log_path: Path) -> Path:
    """JSON sibling of the grove-listen log (same logs directory)."""
    return log_path.parent / f"wake-draft-{_draft_id(env)}.json"


def _provenance_dict(provenance: Any) -> dict:
    if provenance is None:
        return {}
    if is_dataclass(provenance):
        return asdict(provenance)
    if isinstance(provenance, dict):
        return provenance
    return {"repr": repr(provenance)}


def _run_local_draft(app_id: str, env: Envelope) -> dict:
    """Bounded loopback draft of the wake prompt. Never raises to caller."""
    if (os.environ.get(SKIP_LOCAL_DRAFT_ENV) or "").strip() in (
        "1",
        "true",
        "yes",
    ):
        return {
            "status": "unreachable",
            "detail": f"{SKIP_LOCAL_DRAFT_ENV} set",
            "app_id": app_id,
            "dispatch_id": str((env.extra or {}).get("dispatch_id") or ""),
            "trace_id": env.trace_id,
        }
    task = (
        f"Triage this Grove WAKE for seat {app_id}. "
        f"Summarize the ask in ≤5 bullets and name the single next bite. "
        f"Do not claim verification. Dispatch="
        f"{(env.extra or {}).get('dispatch_id') or 'none'}. "
        f"From={env.from_agent}. Prompt:\n{(env.prompt or '').strip()}"
    )
    try:
        from nestor.engine import OllamaEngine
    except ImportError as exc:
        return {
            "status": "unreachable",
            "detail": f"nestor.engine import failed: {exc}",
            "app_id": app_id,
            "dispatch_id": str((env.extra or {}).get("dispatch_id") or ""),
            "trace_id": env.trace_id,
        }
    try:
        engine = OllamaEngine()
        draft = engine.draft_task(task)
    except Exception as exc:  # noqa: BLE001 — three-state honesty, never raise
        logger.info(
            "activation: local_draft unreachable for %s: %s", app_id, exc
        )
        return {
            "status": "unreachable",
            "detail": f"{type(exc).__name__}: {exc}",
            "app_id": app_id,
            "dispatch_id": str((env.extra or {}).get("dispatch_id") or ""),
            "trace_id": env.trace_id,
        }
    text = (draft.text or "").strip()
    if not text:
        return {
            "status": "empty",
            "detail": "Ollama returned empty draft",
            "app_id": app_id,
            "engine": getattr(draft, "engine", ""),
            "provenance": _provenance_dict(getattr(draft, "provenance", None)),
            "dispatch_id": str((env.extra or {}).get("dispatch_id") or ""),
            "trace_id": env.trace_id,
            "text": "",
        }
    return {
        "status": "ok",
        "app_id": app_id,
        "engine": getattr(draft, "engine", ""),
        "provenance": _provenance_dict(getattr(draft, "provenance", None)),
        "dispatch_id": str((env.extra or {}).get("dispatch_id") or ""),
        "trace_id": env.trace_id,
        "text": text,
    }


def _write_draft_artifact(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _draft_log_line(payload: dict) -> str:
    status = payload.get("status", "unreachable")
    dispatch_id = payload.get("dispatch_id") or ""
    trace = payload.get("trace_id") or ""
    line = f"[WAKE-DRAFT] local_draft={status} trace={trace}"
    if dispatch_id:
        line += f" dispatch={dispatch_id}"
    return line


def build_activate(
    app_id: str, *, log_path: Optional[Path] = None
) -> Callable[[Envelope], str]:
    """Build the real ``activate`` callable for ``app_id``'s ``SeatDaemon``.

    Surface-only for process spawn: appends a ``[WAKE]`` line to
    ``$WILLOW_HOME/logs/grove-listen-<app_id>.log``, then attempts a
    loopback local draft (see module docstring). No agent process is
    started.

    A failure to write the wake line is logged and reflected in the
    returned trace string rather than raised — ``BusListener`` must not
    see ``activate`` raise.
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

        draft_payload = _run_local_draft(app_id, env)
        artifact = _draft_artifact_path(app_id, env, log_path=path)
        try:
            _write_draft_artifact(artifact, draft_payload)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(_draft_log_line(draft_payload) + "\n")
        except OSError:
            logger.error(
                "activation: failed writing wake-draft artifact to %s",
                artifact,
                exc_info=True,
            )
            return (
                f"[{app_id}] wake trace={env.trace_id} noticed — logged to {path}; "
                f"local_draft={draft_payload.get('status')} artifact write failed"
            )
        return (
            f"[{app_id}] wake trace={env.trace_id} noticed — logged to {path}; "
            f"local_draft={draft_payload.get('status')} artifact={artifact}"
        )

    return activate
