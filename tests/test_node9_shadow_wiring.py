"""node9 shadow mode (sealed a6d054b3, amended node9-shadow-hybrid-ledger-
2026-09-27 per Loki 53741054) — call-site wiring tests.

Confirms `task_submit` and the PreToolUse hook's Bash branch call
`node9_shadow.spawn_shadow` AFTER their own decision, with the
accepted/refused result intact and unchanged, and that a broken shadow
(including an import failure, F10) can no longer turn a queued/refused
task_submit result into a raised exception.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

# hooks/ is a sibling directory, not installed with the willow_mcp package
# (see tests/test_pre_tool_use_hook.py's own header) — imported by path,
# same convention.
_HOOK_PATH = Path(__file__).resolve().parents[1] / "hooks" / "pre_tool_use.py"
_spec = importlib.util.spec_from_file_location("pre_tool_use_node9_shadow", _HOOK_PATH)
pre_tool_use = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pre_tool_use)


def _app_with_task_submit(tmp_path, monkeypatch, name="hanuman"):
    """Same shape as tests/test_server.py's own `_app_with_perms` — a
    manifest granting `task_submit` so `@_guarded("task_submit")` lets the
    call through to `_task_submit_impl` (which these tests stub out)."""
    apps_root = tmp_path / "mcp_apps"
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    app_dir = apps_root / name
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(json.dumps({"permissions": ["task_submit"]}))
    return name


@pytest.fixture(autouse=True)
def _willow_home(tmp_path, monkeypatch):
    home = tmp_path / "willow"
    home.mkdir()
    monkeypatch.setenv("WILLOW_HOME", str(home))
    _app_with_task_submit(home, monkeypatch)
    return home


# ── task_submit wrapper ──────────────────────────────────────────────────────

def test_task_submit_calls_spawn_shadow_after_a_refusal(monkeypatch):
    from willow_mcp import server

    calls = []
    monkeypatch.setattr(
        server, "_task_submit_impl",
        lambda *a, **k: {"error": "allow_localhost_retired: no"},
    )

    import willow_mcp.node9_shadow as node9_shadow_mod
    monkeypatch.setattr(node9_shadow_mod, "spawn_shadow", lambda **kw: calls.append(kw))

    result = server.task_submit("hanuman", "echo hi", allow_localhost=True)

    assert result == {"error": "allow_localhost_retired: no"}  # untouched
    assert len(calls) == 1
    assert calls[0]["surface"] == "kart"
    assert calls[0]["seat"] == "hanuman"
    assert calls[0]["command"] == "echo hi"
    assert calls[0]["willow_verdict"] == "block"


def test_task_submit_calls_spawn_shadow_after_acceptance(monkeypatch):
    from willow_mcp import server

    calls = []
    monkeypatch.setattr(
        server, "_task_submit_impl",
        lambda *a, **k: {"task_id": "ABCD1234", "status": "pending"},
    )
    import willow_mcp.node9_shadow as node9_shadow_mod
    monkeypatch.setattr(node9_shadow_mod, "spawn_shadow", lambda **kw: calls.append(kw))

    result = server.task_submit("hanuman", "echo hi")

    assert result == {"task_id": "ABCD1234", "status": "pending"}
    assert calls[0]["willow_verdict"] == "allow"


def test_task_submit_treats_held_net_authorization_as_its_own_status(monkeypatch):
    """F10: a held row carries no 'error' key and must not be recorded as
    willow 'allow' — it is its own distinct status, excluded from the four
    agreement classes downstream."""
    from willow_mcp import server

    calls = []
    monkeypatch.setattr(
        server, "_task_submit_impl",
        lambda *a, **k: {"task_id": "ABCD1234", "status": "held_net_authorization",
                          "pair_id": "pair-1"},
    )
    import willow_mcp.node9_shadow as node9_shadow_mod
    monkeypatch.setattr(node9_shadow_mod, "spawn_shadow", lambda **kw: calls.append(kw))

    result = server.task_submit("hanuman", "curl https://example.com", allow_net=True)

    assert result["status"] == "held_net_authorization"  # untouched
    assert calls[0]["willow_verdict"] == "held"


def test_task_submit_call_site_survives_a_broken_spawn_shadow(monkeypatch):
    """F10: the import + call at this call site is now inside its own
    try/except — an import failure or a raise in spawn_shadow can no longer
    turn a queued/refused task_submit result into a visible error for the
    caller."""
    from willow_mcp import server

    monkeypatch.setattr(
        server, "_task_submit_impl",
        lambda *a, **k: {"task_id": "ABCD1234", "status": "pending"},
    )
    import willow_mcp.node9_shadow as node9_shadow_mod

    def _boom(**kw):
        raise RuntimeError("shadow blew up")

    monkeypatch.setattr(node9_shadow_mod, "spawn_shadow", _boom)

    result = server.task_submit("hanuman", "echo hi")  # must NOT raise
    assert result == {"task_id": "ABCD1234", "status": "pending"}


def test_task_submit_call_site_survives_an_import_failure(monkeypatch):
    """F10's other half: the import itself (not just the call) is inside
    the guard."""
    from willow_mcp import server

    monkeypatch.setattr(
        server, "_task_submit_impl",
        lambda *a, **k: {"task_id": "ABCD1234", "status": "pending"},
    )
    monkeypatch.setitem(sys.modules, "willow_mcp.node9_shadow", None)

    result = server.task_submit("hanuman", "echo hi")  # must NOT raise
    assert result == {"task_id": "ABCD1234", "status": "pending"}


# ── PreToolUse hook, Bash surface ────────────────────────────────────────────

def test_shadow_bash_calls_spawn_shadow_with_the_hooks_own_verdict(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "willow_mcp.node9_shadow.spawn_shadow",
        lambda **kw: calls.append(kw),
    )
    monkeypatch.setenv("WILLOW_APP_ID", "hanuman")

    pre_tool_use._shadow_bash("rm -rf /", "block", "destructive")

    assert len(calls) == 1
    assert calls[0] == {
        "surface": "bash", "seat": "hanuman", "command": "rm -rf /",
        "willow_verdict": "block", "willow_reason": "destructive",
    }


def test_shadow_bash_never_raises_when_node9_shadow_import_fails(monkeypatch):
    monkeypatch.setitem(sys.modules, "willow_mcp.node9_shadow", None)
    # Must not raise even though the import above is now poisoned.
    pre_tool_use._shadow_bash("echo hi", "allow", "")
