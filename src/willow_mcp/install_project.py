"""willow-mcp installer verb — atomic settings.json merge with preservation.

Composes `deploy/claude-settings.json` (the shipped template with
`{{WILLOW_MCP_PYTHON}}` placeholder) into an operator's `~/.claude/settings.json`
so a fresh clone wires up in one command instead of hand-editing JSON.

The Fylgja shape (rudi193-cmd/willow-2.0/willow/fylgja/install_project.py)
minus the fleet-identity bookkeeping:

- `_is_managed_entry(entry)` — detect fleet-managed hooks by command
  substring (`willow_mcp.hook_runner`, `willow_mcp.session_start_hook`,
  `willow_mcp.pre_tool_hook`, `willow_mcp.session_stop_hook`,
  `willow_mcp.stop_lint_hook`). A user's hand-added third-party hook is
  NOT managed and MUST survive a reinstall.
- `_merge_event_hooks(existing, managed)` — replace managed entries with
  the freshly-rendered set; preserve every non-managed entry. Order:
  managed first, then preserved, matching Fylgja.
- `apply_hooks(settings_path, package_root)` — read existing, merge,
  atomic `.tmp` + `replace` write. Same rename-into-place shape
  `project_wiring._write_json` already uses.
- `install_project(agent_name, ...)` — top-level entrypoint. Renders the
  hook block from `deploy/claude-settings.json`, resolves the
  `{{WILLOW_MCP_PYTHON}}` placeholder, and applies it.

Two-halves rule (Nestor decision `0225`) — this module is the "settings
half"; `hook_runner.py`'s `_EVENT_HANDLERS` is the "runner half".
Test `test_hook_wiring_sync.py` pins the join between them.

Called via `python -m willow_mcp.install_project <agent> [--ide claude]`.
Cursor / Codex targets are follow-ups; this PR does Claude only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any


DEFAULT_SETTINGS_PATH = Path.home() / ".claude" / "settings.json"


# Command substrings that identify a hook entry as fleet-managed.
# `_merge_event_hooks` drops these on the merge; anything else in an
# `hooks` block is preserved verbatim. Keep this list tight — a
# substring that matches a plausible third-party hook name would silently
# eat someone's real work on reinstall.
_MANAGED_SIGNATURES: tuple[str, ...] = (
    "willow_mcp.hook_runner",
    "willow_mcp.session_start_hook",
    "willow_mcp.pre_tool_hook",
    "willow_mcp.session_stop_hook",
    "willow_mcp.stop_lint_hook",
    "willow_mcp/hooks/pre_tool_use.py",
    "willow_mcp/hooks/stop_lint_gate.py",
    "willow-mcp/hooks/pre_tool_use.py",
    "willow-mcp/hooks/stop_lint_gate.py",
    "${CLAUDE_PLUGIN_ROOT}/hooks/pre_tool_use.py",
    "${CLAUDE_PLUGIN_ROOT}/hooks/stop_lint_gate.py",
    # Sibling-repo hook commands added for PR 2c: Grove's own hook wrapper
    # and Nestor's hook wrapper must be classified as fleet-managed when
    # those repos delegate their settings write through apply_hooks below.
    # Without these entries, a Grove or Nestor hook row from a previous
    # sync would be misclassified as third-party and never replaced on
    # re-sync — exactly the regression the caller wants to avoid.
    "hooks/grove-hook",
    "hooks/grove_hook.py",
    "hooks/nestor-hook",
    "hooks/nestor_hook.py",
    "grove-hook",
    "nestor-hook",
)


def _entry_commands(entry: dict[str, Any]) -> list[str]:
    return [str(h.get("command", "")) for h in entry.get("hooks", []) if isinstance(h, dict)]


def _is_managed_entry(entry: dict[str, Any]) -> bool:
    """True when every command in this hooks-entry names a managed signature.

    A mixed entry (one managed hook + one third-party) is NOT wholly managed —
    conservatively preserve it and let a subsequent hand-edit clean up. The
    reinstall's managed replacement lands separately.
    """
    cmds = _entry_commands(entry)
    if not cmds:
        return False
    return all(any(sig in cmd for sig in _MANAGED_SIGNATURES) for cmd in cmds)


def _merge_event_hooks(
    existing: list[dict[str, Any]],
    managed: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge managed hooks into an event list, preserving third-party entries.

    Returned order: managed entries first (so the fleet gate runs first),
    then everything from `existing` that was NOT managed. A user's hand-added
    entry never disappears; the fleet's own prior entries are replaced by the
    freshly-rendered `managed`.
    """
    preserved = [entry for entry in (existing or []) if isinstance(entry, dict) and not _is_managed_entry(entry)]
    return list(managed) + preserved


def _render_hook_block(
    template_path: Path,
    python_bin: str,
) -> dict[str, Any]:
    """Read the shipped deploy template and substitute `{{WILLOW_MCP_PYTHON}}`.

    The template lives at `src/willow_mcp/deploy/claude-settings.json` and
    is version-controlled; the ONLY placeholder it declares is the Python
    interpreter path, which the caller resolves (or asks the operator to
    resolve — see `_resolve_python_bin`).
    """
    raw = template_path.read_text(encoding="utf-8")
    substituted = raw.replace("{{WILLOW_MCP_PYTHON}}", python_bin)
    return json.loads(substituted)


def _resolve_python_bin(explicit: str | None) -> str:
    """Pick the Python that will run the hooks.

    Order: explicit arg > `$WILLOW_MCP_PYTHON` env > current interpreter
    (`sys.executable`). Never guesses at a vault-box path — a fresh clone
    without either env or arg gets its own current-interpreter python,
    which is the same shape the packet flagged for portable use.
    """
    if explicit:
        return explicit
    env = os.environ.get("WILLOW_MCP_PYTHON", "").strip()
    if env:
        return env
    return sys.executable


def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    """`.tmp` + `replace` — same shape as project_wiring._write_json.

    An interrupted write must leave the original settings.json intact, not
    a half-serialized JSON. `Path.replace` is atomic on POSIX; on Windows
    it works if the target doesn't exist or is on the same volume, which
    is the setup Claude Code produces.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def apply_hooks(
    settings_path: Path,
    package_root: Path | None = None,
    python_bin: str | None = None,
    dry_run: bool = False,
    managed_hooks: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Read `settings_path`, merge willow-mcp's hook block in, write back.

    Two call shapes:

    - **Default** — `package_root` is the installed willow-mcp package directory
      (parent of `deploy/`). Callers usually pass `Path(__file__).resolve().parent`
      from a wrapper. The managed block is loaded from
      `<package_root>/deploy/claude-settings.json` with `{{WILLOW_MCP_PYTHON}}`
      substituted from `python_bin` (or the env/`sys.executable` fallback).
    - **Pre-rendered** — `managed_hooks` is a `{"hooks": {...}}`-shaped dict a
      sibling repo already compiled (Grove's `sync_desk_client_hooks.py`, for
      example, hands its `_compile_hook_manifest` output through here so its
      project-local `.claude/settings.json` write gets the same third-party
      preservation the global install path has). When `managed_hooks` is set,
      `package_root` and `python_bin` are ignored — the caller owns the block.

    Returns the merged settings dict, whether or not it was written.
    """
    if managed_hooks is not None:
        if not isinstance(managed_hooks, dict):
            raise TypeError(
                "managed_hooks must be a dict with a 'hooks' key (a full "
                "settings.json-shaped block); got "
                f"{type(managed_hooks).__name__}"
            )
        fresh = managed_hooks
    else:
        if package_root is None:
            raise ValueError(
                "apply_hooks() needs either `package_root` (to render the "
                "shipped deploy/claude-settings.json template) or "
                "`managed_hooks` (a pre-rendered block from a sibling repo). "
                "Called with neither."
            )
        template = package_root / "deploy" / "claude-settings.json"
        if not template.is_file():
            raise FileNotFoundError(f"deploy/claude-settings.json not found under {package_root}")
        py = _resolve_python_bin(python_bin)
        fresh = _render_hook_block(template, py)

    existing: dict[str, Any] = {}
    if settings_path.is_file():
        try:
            existing = json.loads(settings_path.read_text(encoding="utf-8"))
            if not isinstance(existing, dict):
                existing = {}
        except json.JSONDecodeError:
            # An unparseable settings.json is a user problem, not ours —
            # refuse to overwrite it rather than silently discarding it.
            raise ValueError(
                f"{settings_path} is not valid JSON; refusing to overwrite. Fix by hand first, then re-run install."
            )

    hooks_out: dict[str, list[dict[str, Any]]] = dict(existing.get("hooks", {}))
    for event, managed_entries in fresh.get("hooks", {}).items():
        hooks_out[event] = _merge_event_hooks(
            hooks_out.get(event, []),
            managed_entries,
        )
    merged = dict(existing)
    merged["hooks"] = hooks_out
    if managed_hooks is not None:
        # Pre-rendered path: the caller owns the block. Forward every top-level
        # key they set (env, mcpServers, whatever) so a Grove-shaped settings
        # write doesn't require a second file rewrite. `hooks` was already
        # merged above.
        for key, value in fresh.items():
            if key == "hooks":
                continue
            merged[key] = value
    else:
        # Template path: preserve the historical seed-only behavior for the
        # one flag the shipped deploy template carries.
        for key in ("enableAllProjectMcpServers",):
            if key in fresh and key not in existing:
                merged[key] = fresh[key]

    if not dry_run:
        _write_json_atomic(settings_path, merged)
    return merged


def install_project(
    agent_name: str,
    settings_path: Path | None = None,
    package_root: Path | None = None,
    python_bin: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Install the willow-mcp hook block for one agent on the Claude Code seat.

    `agent_name` is currently informational — future work sets `WILLOW_APP_ID`
    per-seat and rotates a symlinked `.mcp.json`. This PR just wires the
    hooks; the per-agent identity rotation is deliberately out of scope.
    """
    target = settings_path or DEFAULT_SETTINGS_PATH
    pkg = package_root or Path(__file__).resolve().parent
    return apply_hooks(
        settings_path=target,
        package_root=pkg,
        python_bin=python_bin,
        dry_run=dry_run,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Install willow-mcp Claude Code hooks into ~/.claude/settings.json",
    )
    parser.add_argument("agent", help="Agent id (currently informational)")
    parser.add_argument(
        "--settings",
        type=Path,
        default=None,
        help=f"Settings file to write (default: {DEFAULT_SETTINGS_PATH})",
    )
    parser.add_argument(
        "--package-root",
        type=Path,
        default=None,
        help="willow-mcp package root (default: this module's parent)",
    )
    parser.add_argument(
        "--python-bin",
        default=None,
        help="Interpreter path substituted for {{WILLOW_MCP_PYTHON}} "
        "(default: $WILLOW_MCP_PYTHON, else sys.executable)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the merged settings dict without writing",
    )
    args = parser.parse_args()

    merged = install_project(
        agent_name=args.agent,
        settings_path=args.settings,
        package_root=args.package_root,
        python_bin=args.python_bin,
        dry_run=args.dry_run,
    )
    if args.dry_run:
        print(json.dumps(merged, indent=2))
    else:
        target = args.settings or DEFAULT_SETTINGS_PATH
        print(f"[install_project] wrote {target}", file=sys.stderr)


if __name__ == "__main__":
    main()
