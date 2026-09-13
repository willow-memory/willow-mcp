"""Tests for willow_mcp.hook_runner — dispatcher + per-session boot sentinel.

Two-halves rule (Nestor decision `0225-a-hook-is-only-wired-if-the-settings-invoke-it`):
a hook is only wired when BOTH (a) the runner knows how to dispatch it AND
(b) the settings file invokes the runner with that event name. This file
covers half (a); `test_hook_wiring_sync.py` covers half (b) and the join.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from willow_mcp import hook_runner


# ── boot sentinel ──────────────────────────────────────────────────────────


def test_boot_sentinel_path_uses_agent_and_session(monkeypatch):
    path = hook_runner.boot_sentinel_path("ada", "sid_abc123")
    assert path == Path("/tmp/willow-boot-done-ada-sid_abc123.flag")


def test_boot_sentinel_path_falls_back_to_agent_only_when_session_id_empty():
    """A hook fired with no session_id in the payload still gets a sentinel
    at the legacy shape — the runner degrades cleanly, not silently."""
    path = hook_runner.boot_sentinel_path("willow", "")
    assert path == Path("/tmp/willow-boot-done-willow.flag")


def test_boot_sentinel_path_sanitizes_untrusted_session_id():
    """A payload's session_id is arbitrary caller input; the sentinel path
    must not accept characters that could escape the /tmp namespace."""
    path = hook_runner.boot_sentinel_path("willow", "abc/../etc/passwd")
    assert ".." not in str(path)
    assert "/" not in path.name


def test_boot_sentinel_path_truncates_long_session_id():
    long = "a" * 200
    path = hook_runner.boot_sentinel_path("willow", long)
    # Legacy shape truncates to first 16 alnum chars for a bounded filename.
    assert path.name == "willow-boot-done-willow-" + ("a" * 16) + ".flag"


def test_parallel_windows_get_isolated_sentinels():
    """The bug this sentinel fixes: two windows on the same agent, different
    session_ids, must not clear each other's boot state."""
    p1 = hook_runner.boot_sentinel_path("willow", "sess_one")
    p2 = hook_runner.boot_sentinel_path("willow", "sess_two")
    assert p1 != p2


# ── stdin snapshot + restore ───────────────────────────────────────────────


def test_stdin_snapshot_preserves_payload_for_downstream_read(monkeypatch):
    """The runner peeks at stdin to name the sentinel, then restores it so
    the underlying session_start_hook.main()'s json.load(sys.stdin) still
    works. Without this, session_start would run against an empty stdin."""
    payload = {"session_id": "sid_xyz", "source": "startup"}
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    raw, parsed = hook_runner._snapshot_stdin_then_restore()
    assert parsed == payload
    # After restore, a downstream reader sees the SAME bytes.
    assert sys.stdin.read() == raw


def test_stdin_snapshot_survives_non_json_payload(monkeypatch):
    """A malformed payload must never crash the runner — parsed becomes {},
    stdin is still restored intact for the underlying handler to reject."""
    monkeypatch.setattr("sys.stdin", io.StringIO("not json"))
    raw, parsed = hook_runner._snapshot_stdin_then_restore()
    assert parsed == {}
    assert sys.stdin.read() == "not json"


def test_stdin_snapshot_survives_empty_payload(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    raw, parsed = hook_runner._snapshot_stdin_then_restore()
    assert parsed == {}
    assert raw == ""


# ── event dispatch table ───────────────────────────────────────────────────


def test_event_dispatch_table_covers_every_wired_event():
    """The table must cover exactly the events every deploy settings file
    invokes. A settings file naming an event the runner does not dispatch
    would silently fail-open — the two-halves rule's exact failure mode."""
    assert set(hook_runner._EVENT_HANDLERS.keys()) == {
        "session_start",
        "pre_tool",
        "session_stop",
        "stop_lint",
    }


def test_event_handler_targets_point_at_files_that_exist():
    """Every handler in the dispatch table must name a module whose source
    file exists — a stale entry pointing at a renamed or deleted module
    would fail only in production. Checked structurally (path exists) rather
    than by importing, so the CI env's missing psycopg2 doesn't hide a real
    stale entry."""
    import willow_mcp as _wmc

    pkg_root = Path(_wmc.__file__).resolve().parent
    for target in hook_runner._EVENT_HANDLERS.values():
        modpath, _, attr = target.partition(":")
        assert attr, f"{target} missing :attr suffix"
        # `willow_mcp.session_start_hook` → willow_mcp/session_start_hook.py
        assert modpath.startswith("willow_mcp."), f"{modpath} not under willow_mcp package"
        rel = modpath[len("willow_mcp.") :].replace(".", "/") + ".py"
        source = pkg_root / rel
        assert source.is_file(), f"{target} → {source} does not exist"


def test_event_handler_targets_are_importable_when_deps_present():
    """Belt-and-braces to the structural check above: when the runtime deps
    are actually installed (CI / production), every dispatch target must
    also resolve to a callable. Skipped when psycopg2 isn't available —
    the local dev container has no Postgres client."""
    pytest.importorskip("psycopg2")
    for target in hook_runner._EVENT_HANDLERS.values():
        fn = hook_runner._resolve(target)
        assert callable(fn), f"{target} is not callable"


# ── end-to-end runner invocation ───────────────────────────────────────────


def _run_runner(fmt: str, event: str, payload: dict) -> subprocess.CompletedProcess:
    """Run the module as a subprocess with a real stdin."""
    return subprocess.run(
        [sys.executable, "-m", "willow_mcp.hook_runner", "--format", fmt, event],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "WILLOW_APP_ID": "willow"},
    )


def test_runner_dispatches_pre_tool_to_bundle_guard(tmp_path):
    """`python -m willow_mcp.hook_runner --format claude pre_tool` must reach
    the same bundle guard the standalone `pre_tool_hook` does — a native
    WebSearch call still ends in a block decision naming Nestor + Jeles."""
    proc = _run_runner(
        "claude",
        "pre_tool",
        {
            "tool_name": "WebSearch",
            "tool_input": {"search_term": "x"},
            "session_id": "s1",
        },
    )
    assert proc.returncode == 0, proc.stderr
    decision = json.loads(proc.stdout)
    assert decision["decision"] == "block"
    assert "nestor" in decision["reason"].lower()
    assert "8cae3d1dcdf4" in decision["reason"]


def test_runner_session_start_writes_per_session_sentinel(tmp_path, monkeypatch):
    """The full session_start dispatch writes the per-session sentinel — a
    parallel window on the same agent gets a distinct file."""
    sid = "sid_test_" + tmp_path.name[:8]
    monkeypatch.setattr("os.environ", {**__import__("os").environ, "WILLOW_APP_ID": "willow"})
    sentinel = hook_runner.boot_sentinel_path("willow", sid)
    sentinel.unlink(missing_ok=True)
    try:
        # Direct in-process call to _write_boot_sentinel — avoids running
        # the full session_start handler which touches a live MCP server.
        hook_runner._write_boot_sentinel({"session_id": sid})
        assert sentinel.exists()
    finally:
        sentinel.unlink(missing_ok=True)


def test_runner_boot_sentinel_write_never_raises(monkeypatch):
    """A filesystem failure inside the sentinel write must degrade silently —
    a hook that crashed on a /tmp permissions blip would be worse than
    one that noted the sentinel and moved on."""

    def blow_up(*a, **k):
        raise OSError("simulated /tmp failure")

    monkeypatch.setattr(Path, "touch", blow_up)
    hook_runner._write_boot_sentinel({"session_id": "sid_x"})  # must not raise


def test_runner_rejects_unknown_event():
    proc = subprocess.run(
        [sys.executable, "-m", "willow_mcp.hook_runner", "--format", "claude", "not_a_real_event"],
        input="{}",
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert "invalid choice" in proc.stderr.lower() or "not_a_real_event" in proc.stderr


def test_runner_defaults_format_to_claude(monkeypatch):
    """Absent `--format`, dispatch defaults to Claude — the fleet's primary
    dialect. Cursor callers must pass it explicitly."""
    monkeypatch.setattr(sys, "argv", ["hook_runner", "pre_tool"])
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(
            json.dumps(
                {
                    "tool_name": "Read",
                    "tool_input": {"file_path": "/tmp/x"},
                }
            )
        ),
    )
    # Run just far enough to set WILLOW_HOOK_FORMAT — the real handler runs
    # too, but Read is not gated so it should not raise.
    try:
        hook_runner.main()
    except SystemExit:
        pass
    import os as _os

    assert _os.environ.get("WILLOW_HOOK_FORMAT") == "claude"
