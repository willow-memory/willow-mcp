"""The three places hooks get wired for Claude Code must agree on WHAT is
wired, even though HOW they invoke it differs by install shape:

- src/willow_mcp/deploy/claude-settings.json — the canonical, generated-from
  template config (project_wiring.py copies its hooks block verbatim into
  every project it wires).
- .claude-plugin/plugin.json — what a Claude Code plugin install registers.
- .claude/settings.json — this repo's own dev-environment wiring.

Found live (2026-07-31): .claude/settings.json was missing the
WebSearch|WebFetch PreToolUse matcher (so check_native_web never fired in
this repo's own sessions), and plugin.json had no SessionStart entry at all
(so a plugin install never got the session_enter() orientation bridge).
Neither had a test — this is the drift-catcher hooks/pre_tool_use.py's own
test_bundled_hook_is_identical_to_the_repo_copy already has, extended to
the wiring configs the hook file's own docstring points at.
"""
import json
import re
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent

_CONFIGS = {
    "deploy/claude-settings.json": _REPO / "src/willow_mcp/deploy/claude-settings.json",
    "plugin.json": _REPO / ".claude-plugin/plugin.json",
    ".claude/settings.json": _REPO / ".claude/settings.json",
}


def _pre_tool_use_matchers(config: dict) -> set[str]:
    entries = config.get("hooks", {}).get("PreToolUse", [])
    return {e["matcher"] for e in entries}


def _has_session_start(config: dict) -> bool:
    return bool(config.get("hooks", {}).get("SessionStart"))


# ── wiring-level: the willow_web_search corpus-first warn must be REACHABLE ──
#
# Found live (audit, corpus-first-jeles-nestor hook): pre_tool_use.py's
# check_corpus_first() warns on a direct willow_web_search call, and that
# logic was fully unit-tested — but Claude Code's PreToolUse matcher is a
# regex tested against the tool name (see project_wiring.py's own
# "mcp__memory__.*"-shaped abstraction and the "mcp__" wildcard tool
# matcher), matched from the start of the string, not a substring search.
# "WebSearch|WebFetch" never starts a match against "willow_web_search" (a
# different literal string) or "mcp__willow-mcp__willow_web_search" (starts
# with "mcp__", not "WebSearch"). So on a Claude Code seat the hook body
# never even ran for that tool name — logic tests that call
# check_corpus_first()/main() directly can't see this at all, because they
# skip the matcher entirely. This test compiles each config's actual
# PreToolUse matcher and checks it the way Claude Code would: does it match
# at the START of a real willow_web_search tool_name, bare or
# MCP-server-qualified. Wired to _CONFIGS so it runs against all three
# surfaces and can't silently regress on just one.
_WEB_SEARCH_TOOL_NAMES = [
    "willow_web_search",
    "mcp__willow-mcp__willow_web_search",
    "mcp__willow-mcp-serve__willow_web_search",
]


def _web_search_matcher(config: dict) -> str | None:
    for entry in config.get("hooks", {}).get("PreToolUse", []):
        matcher = entry.get("matcher", "")
        if "WebSearch" in matcher:
            return matcher
    return None


def test_pre_tool_use_web_matcher_selects_willow_web_search():
    for name, path in _CONFIGS.items():
        config = json.loads(path.read_text())
        matcher = _web_search_matcher(config)
        assert matcher, f"{name} has no WebSearch/WebFetch-family PreToolUse matcher"
        pattern = re.compile(matcher)
        for tool_name in _WEB_SEARCH_TOOL_NAMES:
            assert pattern.match(tool_name), (
                f"{name}'s PreToolUse matcher {matcher!r} does not select "
                f"{tool_name!r} — the corpus-first warn would never fire "
                "for a direct willow_web_search call on this deploy surface"
            )


def test_pre_tool_use_web_matcher_does_not_swallow_unrelated_mcp_tools():
    """The wildcard added for willow_web_search (mcp__.*__willow_web_search)
    must stay scoped to that one tool — not broaden into matching every MCP
    call, which would be a much bigger behavior change than this fix intends."""
    unrelated = [
        "knowledge_search",
        "store_get",
        "mcp__willow-mcp__knowledge_search",
        "mcp__willow-mcp__willow_web_fetch",
    ]
    for name, path in _CONFIGS.items():
        config = json.loads(path.read_text())
        matcher = _web_search_matcher(config)
        assert matcher
        pattern = re.compile(matcher)
        for tool_name in unrelated:
            assert not pattern.match(tool_name), (
                f"{name}'s PreToolUse matcher {matcher!r} unexpectedly "
                f"selects unrelated tool {tool_name!r}"
            )


def test_pre_tool_use_matchers_agree_across_every_wiring_config():
    matchers_by_config = {
        name: _pre_tool_use_matchers(json.loads(path.read_text()))
        for name, path in _CONFIGS.items()
    }
    canonical = matchers_by_config["deploy/claude-settings.json"]
    assert canonical, "the canonical deploy config itself has no PreToolUse matchers"
    for name, matchers in matchers_by_config.items():
        assert matchers == canonical, (
            f"{name} wires PreToolUse matchers {matchers}, "
            f"but deploy/claude-settings.json wires {canonical}"
        )


def test_every_wiring_config_has_a_session_start_hook():
    for name, path in _CONFIGS.items():
        config = json.loads(path.read_text())
        assert _has_session_start(config), f"{name} has no SessionStart hook wired"


def _stop_hook_commands(config: dict) -> list[str]:
    entries = config.get("hooks", {}).get("Stop", [])
    return [
        h["command"]
        for entry in entries
        for h in entry.get("hooks", [])
        if "stop_lint" in h.get("command", "")
    ]


def test_dev_environment_stop_lint_hook_does_not_invoke_bare_python3():
    """Audit 56C746EB (MEDIUM, interpreter mismatch): this box's bare
    `python3` has no ruff installed, so a Stop hook command of bare
    `python3 hooks/stop_lint_gate.py` false-blocks every Stop (the gate
    can never find ruff, so it always reports "not found"). The repo's own
    dev-environment configs (.claude/settings.json, .claude-plugin/plugin.json)
    must instead invoke an interpreter known to have ruff — the
    operator-box venv python the desk's other hooks already resolve to.
    (src/willow_mcp/deploy/claude-settings.json is exempt: it ships
    {{WILLOW_MCP_PYTHON}}, resolved per-project at wiring time.)"""
    dev_configs = {
        name: path for name, path in _CONFIGS.items() if name != "deploy/claude-settings.json"
    }
    for name, path in dev_configs.items():
        config = json.loads(path.read_text())
        commands = _stop_hook_commands(config)
        assert commands, f"{name} has no stop_lint hook wired"
        for command in commands:
            first_token = command.split()[0]
            assert first_token != "python3", (
                f"{name} invokes the green-claim gate with bare `python3` "
                f"({command!r}) — this box's system python3 has no ruff, "
                "so the gate silently degrades to always-block. Point it at "
                "the operator-box venv python instead."
            )
            assert "venvs/willow-mcp/bin/python3" in first_token, (
                f"{name} does not invoke the operator-box venv python for "
                f"the green-claim gate: {command!r}"
            )
