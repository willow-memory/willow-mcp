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
    # willow_web_fetch and willow_institutional_search were added to the
    # matcher (auditor finding, 2026-09-13): the corpus-first / three-key
    # reminder must also fire when the seat reaches for the guarded fetch
    # verb or the institutional-search verb directly, not only WebSearch.
    "willow_web_fetch",
    "mcp__willow-mcp__willow_web_fetch",
    "willow_institutional_search",
    "mcp__willow-mcp__willow_institutional_search",
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
        # willow_web_fetch was moved OUT of "unrelated" (auditor 2026-09-13):
        # it is now intentionally matched — the corpus-first / three-key
        # reminder must fire for a direct fetch call too. See
        # _WEB_SEARCH_TOOL_NAMES above for the positive assertion.
        "mcp__willow-mcp__store_search",
    ]
    for name, path in _CONFIGS.items():
        config = json.loads(path.read_text())
        matcher = _web_search_matcher(config)
        assert matcher
        pattern = re.compile(matcher)
        for tool_name in unrelated:
            assert not pattern.match(tool_name), (
                f"{name}'s PreToolUse matcher {matcher!r} unexpectedly selects unrelated tool {tool_name!r}"
            )


def test_pre_tool_use_matchers_agree_across_every_wiring_config():
    matchers_by_config = {name: _pre_tool_use_matchers(json.loads(path.read_text())) for name, path in _CONFIGS.items()}
    canonical = matchers_by_config["deploy/claude-settings.json"]
    assert canonical, "the canonical deploy config itself has no PreToolUse matchers"
    for name, matchers in matchers_by_config.items():
        assert matchers == canonical, (
            f"{name} wires PreToolUse matchers {matchers}, but deploy/claude-settings.json wires {canonical}"
        )


def test_every_wiring_config_has_a_session_start_hook():
    for name, path in _CONFIGS.items():
        config = json.loads(path.read_text())
        assert _has_session_start(config), f"{name} has no SessionStart hook wired"


def _stop_hook_commands(config: dict) -> list[str]:
    entries = config.get("hooks", {}).get("Stop", [])
    return [h["command"] for entry in entries for h in entry.get("hooks", []) if "stop_lint" in h.get("command", "")]


def test_dev_environment_stop_lint_hook_does_not_invoke_bare_python3():
    """Audit 56C746EB (MEDIUM, interpreter mismatch): this box's bare
    `python3` has no ruff installed, so a Stop hook command of bare
    `python3 hooks/stop_lint_gate.py` false-blocks every Stop on the
    operator's own dev box. `.claude/settings.json` is the dev-only
    override for that specific box, so it must invoke an interpreter
    known to have ruff — the operator-box venv python.

    `.claude-plugin/plugin.json` is EXEMPT (2026-09-13, auditor 1): it is
    the plugin manifest a Claude Code user's plugin config points at, so
    it ships to every consumer. A vault-path hardcoded there breaks every
    fresh clone. On a fresh clone with no ruff, `stop_lint_gate._run_ruff`
    returns an explicit "install ruff" block — not silent — which is the
    right consumer-facing behavior. The operator's own box carries the
    ruff-having venv via .claude/settings.json's override.

    `deploy/claude-settings.json` is exempt: it ships {{WILLOW_MCP_PYTHON}},
    resolved per-project at wiring time."""
    exempt = {"deploy/claude-settings.json", "plugin.json"}
    dev_configs = {name: path for name, path in _CONFIGS.items() if name not in exempt}
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
                f"{name} does not invoke the operator-box venv python for the green-claim gate: {command!r}"
            )


# ── two-halves rule (Nestor decision 0225) ────────────────────────────────
#
# A hook is only wired if BOTH (a) the runner knows how to dispatch it AND
# (b) the settings file invokes the runner with that event name. These are
# separate assertions kept deliberately apart — see
# `Nestor/docs/dogfood/decisions/0225-a-hook-is-only-wired-if-the-settings-invoke-it.json`.
# The runner half is pinned in `tests/test_hook_runner.py`
# (`test_event_dispatch_table_covers_every_wired_event`); this section pins
# the settings half against the runner-half's own registry.


def _hook_runner_events() -> set[str]:
    """The runner-side truth: which events the dispatch table names.

    Read from the runner module directly rather than a hand-kept list — a
    roster in the test file would be one more thing to remember to update,
    which is the same shape as the bug Nestor `0225` and `0221→0225` were
    written to catch (a hook wired by name, dead in practice).
    """
    from willow_mcp import hook_runner

    return set(hook_runner._EVENT_HANDLERS.keys())


def _runner_events_wired_in(config: dict) -> set[str]:
    """The settings-side truth: which events this config actually invokes
    the runner with. Scans every hook command in every event block for
    `willow_mcp.hook_runner --format <fmt> <event>` and collects the event
    argument. A settings file that fires the runner for an event NOT in
    the runner's dispatch table would silently no-op — but that failure
    is caught by argparse choices; here we only care about the positive
    side (settings invokes runner ⟹ event in table)."""
    import re as _re

    wired: set[str] = set()
    pattern = _re.compile(r"willow_mcp\.hook_runner\s+--format\s+\S+\s+(\S+)")
    for entries in config.get("hooks", {}).values():
        for entry in entries or []:
            for hook in (entry or {}).get("hooks", []) or []:
                cmd = hook.get("command", "") if isinstance(hook, dict) else ""
                m = pattern.search(cmd)
                if m:
                    wired.add(m.group(1))
    return wired


def test_every_hook_runner_event_has_a_settings_invocation():
    """The two-halves rule (Nestor `0225`): every event in the runner's
    dispatch table MUST be invoked by at least one deploy-shipped settings
    file. An event registered by name that no settings file fires is dead
    code — the exact "hook wired by name, dead in practice" failure `0221`
    exposed in Nestor when a UserPromptSubmit module was named but never
    reached.

    We pin the join against the two SHIPPED settings files
    (`.claude-plugin/plugin.json` and `deploy/claude-settings.json`).
    `.claude/settings.json` is the operator's dev override — it may
    legitimately invoke a subset (e.g. no SessionStart if it uses a
    dev-bootstrap bash script instead), so it is not required to cover
    every event.
    """
    shipped_names = ("plugin.json", "deploy/claude-settings.json")
    shipped_wired: set[str] = set()
    for name in shipped_names:
        assert name in _CONFIGS, f"missing shipped settings file: {name}"
        config = json.loads(_CONFIGS[name].read_text())
        shipped_wired |= _runner_events_wired_in(config)

    runner_events = _hook_runner_events()
    missing = runner_events - shipped_wired
    assert not missing, (
        "hook_runner dispatch table names events with no matching invocation "
        f"in any shipped settings file: {sorted(missing)}. Either add an "
        "invocation to plugin.json / deploy/claude-settings.json, or remove "
        "the entry from `_EVENT_HANDLERS`. Two-halves rule (Nestor 0225): "
        "a hook is only wired if the settings invoke it."
    )


def test_two_halves_rule_pin_fires_on_a_fixture_missing_every_invocation():
    """Prove-it-can-fail case (mirrors Nestor `0225`'s discipline): a
    fixture settings file that omits every runner invocation MUST fail
    the pin. A guard that cannot fail is not a guard — the same rule
    marching-arts's mutation tests and this test suite's own audit
    harness state."""
    empty_config = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {"type": "command", "command": "python3 -m my.unrelated.hook"},
                    ],
                },
            ]
        }
    }
    wired = _runner_events_wired_in(empty_config)
    # Confirm the reader sees no runner invocations in this fixture.
    assert wired == set(), f"the empty-fixture reader should find zero runner events, saw {wired}"
    # If this fixture were the ONLY shipped settings file, the pin would
    # fail because runner_events - wired == runner_events (non-empty).
    runner_events = _hook_runner_events()
    assert runner_events - wired == runner_events, (
        "the fixture must expose the full missing set — a guard that "
        "silently passes with no invocations wouldn't catch a settings "
        "file that lost every runner reference."
    )


def test_shipped_plugin_manifest_uses_only_portable_interpreters():
    """The shipped plugin manifest goes to every consumer of the plugin
    (Claude Code plugin install). Hardcoded operator-box vault paths there
    break every fresh clone. Every Stop-hook command in plugin.json must
    start with bare `python3` (portable) or a placeholder that the
    installer resolves per-project. Pinned 2026-09-13 (auditor 1)."""
    plugin_json = _CONFIGS["plugin.json"]
    config = json.loads(plugin_json.read_text())
    commands = _stop_hook_commands(config)
    assert commands, "plugin.json has no stop_lint hook wired"
    for command in commands:
        first_token = command.split()[0]
        assert first_token == "python3" or "{{" in first_token, (
            f"plugin.json Stop hook uses {first_token!r} — a shipped "
            "manifest must start with bare `python3` or a placeholder, "
            "never a foreign-user absolute path."
        )
        assert "sean-campbell" not in command, (
            f"plugin.json Stop hook still contains an operator-box path: "
            f"{command!r}. The manifest ships; foreign-user absolute paths "
            "break every consumer."
        )
