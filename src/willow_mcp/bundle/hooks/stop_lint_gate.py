"""willow-mcp Claude Code hook — Stop.

Green-claim gate (hook spec #7; gap afc3e12c9e17): a session claimed green on
pytest but never ran the repo's ruff, and CI caught what the session missed —
an E402 that forced a re-push. This hook runs at Stop and closes that gap
cheaper than a CI round-trip: it detects the repo's configured linter, runs
it, and blocks the stop (so the session cannot claim green/close) when it
fails, naming the violation in the block reason.

Detection is pluggable — see _LINTERS below — but only ruff ships today: a
ruff.toml/.ruff.toml file, or a [tool.ruff] table in pyproject.toml. A repo
with no matching linter config is a silent, deliberate no-op: this hook does
not invent a lint policy a repo never adopted. Deterministic (shells out to
`ruff check`), no model in the loop.

Protocol: reads a JSON object from stdin ({"session_id": ..., "cwd": ...,
"stop_hook_active": ...}), optionally prints a JSON decision to stdout
({"decision": "block", "reason": "..."}), always exits 0 — same convention as
pre_tool_use.py. `stop_hook_active` means the harness already re-invoked this
hook once because of a previous block; honoring it (exit clean, no re-block)
avoids trapping the session in a stop-block loop it cannot itself resolve
(e.g. ruff genuinely missing from PATH).

Guardrail, not a control: this lives in the agent's own harness like
pre_tool_use.py, and an agent that bypasses its own Stop hook faces no
OS-level obstacle. It makes "green" mean "lint clean too" the cheap way, at
the point a mistake is caught, not a durable enforcement boundary — the real
backstop for that stays CI.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Callable, Optional

# Must stay well under the outer harness's own timeout for a hook invocation
# (~30-60s observed) so a genuinely slow lint always fails loud from inside
# this process (the TimeoutExpired branch below), never gets silently
# SIGKILLed by the harness before it can print a block reason.
_TIMEOUT_S = 20


def _project_dir() -> Path:
    """The project root, from CLAUDE_PROJECT_DIR (the harness sets it on every
    hook invocation), falling back to cwd for a direct/manual invocation."""
    root = os.environ.get("CLAUDE_PROJECT_DIR")
    return Path(root) if root else Path.cwd()


def _ruff_configured(root: Path) -> bool:
    """True when the repo declares ruff config: a ruff.toml/.ruff.toml file,
    or a `[tool.ruff]` table (or a `[tool.ruff.*]` sub-table) in
    pyproject.toml. Absence of all three means ruff is not this repo's
    linter — a clean no-op, not a guess.

    Parses the TOML properly rather than substring-matching `"[tool.ruff"` —
    a naive substring check would false-positive on a commented-out table
    (`# [tool.ruff]`) or the literal text showing up inside an unrelated
    string value."""
    if (root / "ruff.toml").is_file() or (root / ".ruff.toml").is_file():
        return True
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        return False
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
        return False
    tool = data.get("tool")
    return isinstance(tool, dict) and "ruff" in tool


def _ruff_targets(root: Path) -> list[str]:
    """src + tests when they exist (this repo's own layout); fall back to the
    project root itself so a differently-laid-out repo still gets checked."""
    targets = [d for d in ("src", "tests") if (root / d).is_dir()]
    return targets or ["."]


def _resolve_ruff() -> Optional[list[str]]:
    """The argv prefix to invoke ruff with, or None if it can't be found at
    all. Prefers the `ruff` executable on PATH; falls back to
    `<this interpreter> -m ruff` since a venv that installed ruff as a
    dependency (rather than a standalone tool) may not put its console
    script on the caller's PATH even though the module is importable."""
    exe = shutil.which("ruff")
    if exe:
        return [exe]
    try:
        import ruff as _ruff_mod  # noqa: F401  — presence check only
    except ImportError:
        return None
    return [sys.executable, "-m", "ruff"]


def _run_ruff(root: Path) -> Optional[str]:
    """Return a block reason if ruff reports a violation or can't run at all,
    else None (clean)."""
    argv_prefix = _resolve_ruff()
    if argv_prefix is None:
        return (
            "willow-mcp: this repo configures ruff (pyproject.toml/ruff.toml) "
            "but no `ruff` executable or module was found — install it "
            "(pip install ruff / uv tool install ruff) before claiming green. "
            "A configured linter that silently never runs is exactly the gap "
            "this hook closes."
        )
    argv = [*argv_prefix, "check", *_ruff_targets(root)]
    try:
        proc = subprocess.run(
            argv, cwd=str(root), capture_output=True, text=True, timeout=_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return (
            f"willow-mcp: `{' '.join(argv)}` did not finish within "
            f"{_TIMEOUT_S}s — investigate before claiming green."
        )
    except OSError as exc:
        return f"willow-mcp: could not run ruff ({exc}) — investigate before claiming green."
    if proc.returncode == 0:
        return None
    output = (proc.stdout or "").strip() or (proc.stderr or "").strip()
    return (
        "willow-mcp: ruff reported lint violations — fix them before claiming "
        f"green:\n{output}"
    )


# Registry of (name, is_configured, run) triples, in the order they're tried.
# Adding a second linter is one entry here, not a rewrite of check_lint().
_LINTERS: list[tuple[str, Callable[[Path], bool], Callable[[Path], Optional[str]]]] = [
    ("ruff", _ruff_configured, _run_ruff),
]


def check_lint(root: Path) -> Optional[str]:
    """Return a block reason from the first configured linter that fails,
    else None. No configured linter at all is a clean no-op — the whole
    point of the gate is enforcing what the repo already opted into, not a
    house style this hook imposes on every repo it runs in."""
    for _name, is_configured, run in _LINTERS:
        if is_configured(root):
            reason = run(root)
            if reason:
                return reason
    return None


def main() -> None:
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}

    # Avoid a stop-block loop: the harness sets this true when it already
    # re-invoked the Stop hook once as a result of a previous block.
    if payload.get("stop_hook_active"):
        sys.exit(0)

    reason = check_lint(_project_dir())
    if reason:
        print(json.dumps({"decision": "block", "reason": reason}))
    sys.exit(0)


if __name__ == "__main__":
    main()
