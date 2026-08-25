"""PR4: session_start_hook no longer silently defaults WILLOW_APP_ID to 'willow'.

The prior behavior was a silent orchestrator-seat claim on any workspace
where WILLOW_APP_ID was unset. This test file pins the new refusal.
"""
from __future__ import annotations

import pytest

from willow_mcp import session_start_hook


def test_hook_refuses_when_app_id_unset(monkeypatch):
    monkeypatch.delenv("WILLOW_APP_ID", raising=False)
    result = session_start_hook.handle({"session_id": "s-1"})
    ctx = result.get("additional_context", "")
    assert "FAILED" in ctx
    assert "WILLOW_APP_ID is not set" in ctx
    # Actionable — names both options and points at the doc
    assert "orchestrator workspace" in ctx or "orchestrator" in ctx
    assert "specialist" in ctx
    assert "docs/design/human-orchestrator.md" in ctx


def test_hook_refuses_when_app_id_empty_string(monkeypatch):
    """Whitespace-only or empty is treated as unset — no room for a value
    that looks set but resolves to nothing."""
    monkeypatch.setenv("WILLOW_APP_ID", "   ")
    result = session_start_hook.handle({"session_id": "s-1"})
    assert "FAILED" in result.get("additional_context", "")


def test_hook_proceeds_past_app_id_gate_when_willow_set(monkeypatch):
    """The orchestrator workspace still works past the WILLOW_APP_ID gate
    after this change; it just needs to declare its identity explicitly.
    (Downstream gates like manifest ACL are a separate concern — the test
    env has no willow manifest so session_enter itself denies, but the
    PR4-added refusal at the hook's boundary must not fire.)"""
    monkeypatch.setenv("WILLOW_APP_ID", "willow")
    result = session_start_hook.handle({"session_id": "s-explicit-willow"})
    ctx = result.get("additional_context", "")
    assert "WILLOW_APP_ID is not set" not in ctx, (
        "the app_id gate must not fire when WILLOW_APP_ID is set"
    )


def test_hook_proceeds_past_app_id_gate_for_specialist(monkeypatch):
    """Specialist workspaces work past the WILLOW_APP_ID gate — they
    declare their own app_id and no longer inherit the silent
    orchestrator-seat default."""
    monkeypatch.setenv("WILLOW_APP_ID", "hanuman")
    result = session_start_hook.handle({"session_id": "s-hanuman"})
    ctx = result.get("additional_context", "")
    assert "WILLOW_APP_ID is not set" not in ctx
