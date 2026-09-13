from willow_mcp.hook_parity import parity_report


def test_cursor_and_claude_hook_modules_align():
    """Post-2026-09-13 PR 2b: every lifecycle hook routes through the shared
    `willow_mcp.hook_runner`, and the parity report's `cursor_modules` /
    `claude_modules` are the EVENT fingerprints the runner dispatches on
    (session_start / pre_tool / session_stop / stop_lint). Cursor and Claude
    templates must produce the same event set — that's the alignment
    invariant. The specific module name (`hook_runner` vs the legacy
    `session_start_hook`) is normalized away by `_extract_names`, so this
    test survives a re-migration in either direction."""
    report = parity_report()
    assert report["aligned"] is True, report
    assert "session_start" in report["cursor_modules"]
    assert "session_stop" in report["cursor_modules"]
    assert "pre_tool" in report["cursor_modules"]
