"""Structural guards for the sudo invariant and hook integrity.

These assert, from source, the invariants the willow-gate seam relies on but that
were previously only prose + code review:
  * the two PreToolUse hook copies never drift,
  * no operator-authority verb is reachable as an MCP tool or via any permission
    group (an agent may REQUEST standing/egress, never CONFIRM it).
"""
import re
from pathlib import Path

from willow_mcp import gate

_ROOT = Path(__file__).resolve().parents[1]
_SERVER = _ROOT / "src" / "willow_mcp" / "server.py"
_HOOK = _ROOT / "hooks" / "pre_tool_use.py"
_BUNDLE_HOOK = _ROOT / "src" / "willow_mcp" / "bundle" / "hooks" / "pre_tool_use.py"

# Verbs that mint authority — identity/trust secrets, egress, consent, roster.
# None may be an MCP tool or live inside any permission group.
_AUTHORITY_TOOLS = {
    "register_agent", "revoke_agent", "rotate_agent",
    "grant_net", "sign_net_task", "revoke_net",
    "write_consent", "set_key", "reconcile",
}


def _mcp_tool_names() -> set[str]:
    """Every function directly decorated @mcp.tool() in server.py, read from
    source (importing server pulls in a heavy runtime)."""
    src = _SERVER.read_text(encoding="utf-8")
    # `(?:async\s+)?`: no tool in server.py is `async def` today, and the first
    # one would have escaped every assertion in this file — the plant below
    # found the gap. test_annotation_consistency.py's extractor already
    # accepted both forms.
    return set(re.findall(
        r"@mcp\.tool\([^)]*\)\s*(?:@_guarded\([^\n]*\)\s*)?(?:async\s+)?def\s+([a-zA-Z0-9_]+)", src))


def test_hook_and_bundle_copy_are_byte_identical():
    """The deployed guard is the bundle copy; the tests import the repo-root copy.
    If they diverge, every guard test still passes against a file that isn't the
    one shipped. Keep them identical."""
    assert _HOOK.read_bytes() == _BUNDLE_HOOK.read_bytes()


def test_no_registry_mutation_is_an_mcp_tool():
    tools = _mcp_tool_names()
    assert tools, "sanity: found no @mcp.tool functions — regex likely broke"
    leaked = tools & _AUTHORITY_TOOLS
    assert not leaked, f"authority verbs exposed as MCP tools: {sorted(leaked)}"
    # the seam's identity tools ARE tools, and must stay read/observe-only
    assert "session_bind" in tools and "session_reconcile" in tools


def test_no_authority_verb_lives_in_any_permission_group():
    for group, tools in gate.PERMISSION_GROUPS.items():
        leaked = set(tools) & _AUTHORITY_TOOLS
        assert not leaked, f"permission group {group!r} contains authority verb(s): {sorted(leaked)}"


def test_egress_tools_stay_off_full_access():
    # integration_call / task_net are own-line grants, never bundled into full_access.
    fa = gate.PERMISSION_GROUPS["full_access"]
    assert "integration_call" not in fa
    assert gate.NET_PERMISSION not in fa and gate.INTEGRATION_NET_PERMISSION not in fa


def _capability_flags() -> dict[str, str]:
    """The own-line capability flags, read off `gate` rather than retyped.

    Retyping is how the check above went stale: it names `task_net` and
    `integration_net` and silently omits `web_net`, which was added later and is
    the newest of the three. Reading the constants means a fifth flag —
    `mcp_federation`, see docs/design/federated-mcp-gating.md — is covered the
    day it is declared, with no edit here.
    """
    return {
        name: getattr(gate, name) for name in dir(gate)
        if name.endswith("_PERMISSION") and isinstance(getattr(gate, name), str)
    }


def test_no_capability_flag_is_a_member_of_any_permission_group():
    """The own-line rule, as a property rather than three named instances.

    A capability flag is a privilege a manifest lists to unlock an extra
    capability on a tool it already holds — not a tool name. Landing one inside
    *any* group means a grant of that group silently carries it, which is what
    `gate.py` separated `task_net` from `integration_net` from `web_net` to
    prevent. `full_access` is the group that would hurt most, but it is not the
    only one that would hurt: `task_queue` carrying `task_net` would be the
    original B-19 bug wearing a smaller name.
    """
    flags = _capability_flags()
    assert flags, "no *_PERMISSION constants found — has gate.py been renamed?"

    leaks = {
        f"{const}={value!r}": sorted(
            group for group, tools in gate.PERMISSION_GROUPS.items() if value in tools)
        for const, value in flags.items()
    }
    leaks = {k: v for k, v in leaks.items() if v}
    assert not leaks, (
        "capability flags must be granted on their own manifest line, never "
        f"bundled into a permission group: {leaks}")


def test_the_tool_name_scan_catches_a_planted_tool(tmp_path, monkeypatch):
    """Planted: a server module with two `@mcp.tool` functions — one behind
    `@_guarded`, one bare — and a plain function beside them. `_mcp_tool_names`
    reads `_SERVER` from source; every test above asserts what it does NOT
    contain, so nothing had shown it finding a tool at all."""
    planted = tmp_path / "server.py"
    planted.write_text(
        "@mcp.tool()\n"
        '@_guarded("store_put")\n'
        "def store_put(record):\n"
        "    pass\n"
        "\n"
        "@mcp.tool(annotations=_ANNO_WRITE)\n"
        "async def planted_registry_mutation(app_id):\n"
        "    pass\n"
        "\n"
        "def not_a_tool():\n"
        "    pass\n",
        encoding="utf-8",
    )
    monkeypatch.setitem(globals(), "_SERVER", planted)
    assert _mcp_tool_names() == {"store_put", "planted_registry_mutation"}
