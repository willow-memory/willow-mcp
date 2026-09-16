"""willow_mcp/bot_status.py — the desk reads the steward without a shell.

Gap ``158600e03598``: the Willow seat could not tell the bot unit's active
state, running commit, or recent journal apart through any read-only tool.
willow-bot now exposes that as one JSON object on stdout —
``willow-bot-steward status``, backed by ``willow_bot/status.py::report()``
(its own module docstring lays out the three-state contract per field:
populated / empty / unreachable, so an unreadable journal never reads as
"unit absent"). This module is the seat half: run the binary, bounded, and
translate what happened into the SAME three states at the top level —
never collapsing a shell failure into an empty success (INVARIANTS §1).

Unreachable, named distinctly by cause:

* ``binary_missing`` — the resolved path does not exist / is not executable.
* ``nonzero_exit`` — the process ran and refused.
* ``timeout`` — the process did not finish inside the bound.
* ``unparseable`` — stdout was not a single JSON object.

Reachable outcomes fall through to the bot's own report: ``populated`` if
any field in it reports ``status: populated``, else ``empty`` — a fresh
install with a binary that runs cleanly but has nothing to say yet.

No writes, no envelope, no FRANK citation — a read, gated like one.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Callable, Optional

#: Env override for tests and non-default installs — checked before the
#: derived `$WILLOW_HOME/venvs/willow-bot/bin/willow-bot-steward` path, the
#: same override-then-derive shape `pull_executor._github_root` uses.
BINARY_ENV = "WILLOW_BOT_STEWARD_BIN"

_DEFAULT_TIMEOUT_S = 5.0


def _willow_home() -> Path:
    home = (os.environ.get("WILLOW_HOME") or "").strip()
    return Path(home).expanduser() if home else Path.home() / ".willow"


def resolve_binary() -> str:
    """The steward CLI to run: ``$WILLOW_BOT_STEWARD_BIN`` if set, else the
    installed entrypoint under the bot's own venv beneath ``$WILLOW_HOME``.
    Never hardcodes an operator home — ``_willow_home`` is the one place
    that falls back to ``~/.willow``, matching ``pull_executor.trigger_dir``."""
    override = (os.environ.get(BINARY_ENV) or "").strip()
    if override:
        return override
    return str(_willow_home() / "venvs" / "willow-bot" / "bin" / "willow-bot-steward")


def _tail(text: str, n: int = 200) -> str:
    return (text or "").strip()[:n]


def _has_populated_field(report: dict) -> bool:
    """True if any top-level field of the bot's report names itself
    ``populated`` — the report's own three-state contract, read here rather
    than re-derived, so a field this module has never heard of still counts."""
    return any(isinstance(value, dict) and value.get("status") == "populated" for value in report.values())


def read_status(
    *,
    binary: Optional[str] = None,
    timeout: float = _DEFAULT_TIMEOUT_S,
    runner: Optional[Callable] = None,
) -> dict:
    """Run the steward's ``status`` verb and translate it to the desk's
    three-state contract. ``runner`` replaces ``subprocess.run`` for tests —
    it must raise ``FileNotFoundError`` / ``subprocess.TimeoutExpired`` the
    way the real one does, since those are exactly the states this function
    tells apart."""
    resolved = binary or resolve_binary()
    run = runner or subprocess.run
    try:
        proc = run(
            [resolved, "status"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return {
            "state": "unreachable",
            "reason": "binary_missing",
            "binary": resolved,
        }
    except subprocess.TimeoutExpired:
        return {
            "state": "unreachable",
            "reason": "timeout",
            "binary": resolved,
            "timeout_s": timeout,
        }

    if proc.returncode != 0:
        return {
            "state": "unreachable",
            "reason": "nonzero_exit",
            "binary": resolved,
            "returncode": proc.returncode,
            "detail": _tail(proc.stderr or proc.stdout),
        }

    try:
        parsed = json.loads(proc.stdout)
    except (json.JSONDecodeError, TypeError):
        return {
            "state": "unreachable",
            "reason": "unparseable",
            "binary": resolved,
            "detail": _tail(proc.stdout),
        }
    if not isinstance(parsed, dict):
        return {
            "state": "unreachable",
            "reason": "unparseable",
            "binary": resolved,
            "detail": "top-level JSON is not an object",
        }

    if _has_populated_field(parsed):
        return {"state": "populated", "binary": resolved, "report": parsed}
    return {
        "state": "empty",
        "reason": "no populated field in the bot's report",
        "binary": resolved,
        "report": parsed,
    }
