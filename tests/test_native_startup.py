"""Native startup contract (decommission §1d) — tests only."""

from __future__ import annotations

import inspect

from willow_mcp import session_start_hook as ssh


def test_session_start_hook_has_no_fylgja_imports():
    source = inspect.getsource(ssh)
    assert "fylgja" not in source
    assert "persona" not in source.lower() or "seed_corpus" in source


def test_session_start_calls_session_enter_only(monkeypatch):
    calls = []

    def fake_enter(**kwargs):
        calls.append(kwargs)
        return {
            "entry_mode": "human_orchestrator",
            "orientation": {
                "latest_handoff": {"path": "handoffs/x.md"},
                "stack_snapshot": {"open_tasks": []},
            },
        }

    import willow_mcp.server as server

    monkeypatch.setattr(server, "session_enter", fake_enter)
    monkeypatch.setattr(ssh, "seed_corpus_corrections", lambda: 0)
    monkeypatch.setenv("WILLOW_APP_ID", "willow")
    out = ssh.handle({"session_id": "s", "source": "startup", "workspace": "/w"})
    assert calls and calls[0]["app_id"] == "willow"
    ctx = out["additional_context"]
    assert "entry_mode=human_orchestrator" in ctx
    assert "handoff: handoffs/x.md" in ctx
    assert len(ctx) < 8000


def test_continuation_source_trims_boot(monkeypatch):
    import willow_mcp.server as server

    monkeypatch.setattr(
        server,
        "session_enter",
        lambda **k: {"entry_mode": "human", "orientation": {}},
    )
    monkeypatch.setattr(ssh, "seed_corpus_corrections", lambda: 0)
    monkeypatch.setenv("WILLOW_APP_ID", "hanuman")
    out = ssh.handle({"session_id": "s", "source": "compact"})
    ctx = out["additional_context"]
    assert "trimmed boot" in ctx or "continuation" in ctx
