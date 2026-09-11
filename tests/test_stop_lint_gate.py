"""Tests for hooks/stop_lint_gate.py — the Stop-hook green-claim gate (hook
spec #7; gap afc3e12c9e17). Imported by path, same convention as
test_pre_tool_use_hook.py, since hooks/ is a sibling directory, not part of
the installed willow_mcp package.
"""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

_HOOK_PATH = Path(__file__).resolve().parents[1] / "hooks" / "stop_lint_gate.py"
_spec = importlib.util.spec_from_file_location("stop_lint_gate", _HOOK_PATH)
stop_lint_gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(stop_lint_gate)


def _write_ruff_project(tmp_path: Path, *, configured: bool = True) -> Path:
    if configured:
        (tmp_path / "pyproject.toml").write_text(
            "[tool.ruff]\nline-length = 120\n", encoding="utf-8"
        )
    (tmp_path / "src").mkdir()
    return tmp_path


def test_lint_violation_blocks_and_names_it(tmp_path):
    """A tree with a ruff violation → the gate blocks and names the violation
    (rule code + offending file) in the reason, not just a generic failure."""
    _write_ruff_project(tmp_path)
    bad = tmp_path / "src" / "bad.py"
    bad.write_text("import os\n\n\ndef f():\n    return 1\n", encoding="utf-8")

    reason = stop_lint_gate.check_lint(tmp_path)

    assert reason is not None
    assert "ruff" in reason.lower()
    assert "bad.py" in reason
    assert "F401" in reason  # unused-import: the actual violation, named


def test_clean_tree_passes(tmp_path):
    """A clean tree (ruff configured, no violations) → the gate passes, no
    block reason at all."""
    _write_ruff_project(tmp_path)
    good = tmp_path / "src" / "good.py"
    good.write_text('"""A clean module."""\n\n\ndef f():\n    return 1\n', encoding="utf-8")

    assert stop_lint_gate.check_lint(tmp_path) is None


def test_no_linter_configured_is_a_noop(tmp_path):
    """No ruff.toml/.ruff.toml and no [tool.ruff] in pyproject.toml → no-op,
    never blocks, even with an obvious violation sitting right there."""
    _write_ruff_project(tmp_path, configured=False)
    (tmp_path / "pyproject.toml").write_text("[project]\nname = \"x\"\n", encoding="utf-8")
    bad = tmp_path / "src" / "bad.py"
    bad.write_text("import os\n\n\ndef f():\n    return 1\n", encoding="utf-8")

    assert stop_lint_gate.check_lint(tmp_path) is None


def test_no_pyproject_at_all_is_a_noop(tmp_path):
    """No pyproject.toml, no ruff.toml → not configured, not an error."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "bad.py").write_text("import os\n", encoding="utf-8")

    assert stop_lint_gate.check_lint(tmp_path) is None


def test_ruff_toml_alone_counts_as_configured(tmp_path):
    """Detection is not pyproject-only: a bare ruff.toml also counts."""
    (tmp_path / "ruff.toml").write_text("line-length = 120\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "bad.py").write_text("import os\n", encoding="utf-8")

    reason = stop_lint_gate.check_lint(tmp_path)
    assert reason is not None
    assert "F401" in reason


def test_main_blocks_via_stdin_stdout_protocol(tmp_path, monkeypatch):
    """End-to-end: main() reads CLAUDE_PROJECT_DIR + stdin JSON, prints a
    block decision naming the violation, and always exits 0 (the decision is
    the JSON, not the exit code — same convention as pre_tool_use.py)."""
    _write_ruff_project(tmp_path)
    (tmp_path / "src" / "bad.py").write_text("import os\n", encoding="utf-8")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))

    proc = subprocess.run(
        [sys.executable, str(_HOOK_PATH)],
        input=json.dumps({"session_id": "abc"}),
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "CLAUDE_PROJECT_DIR": str(tmp_path)},
    )

    assert proc.returncode == 0
    out = json.loads(proc.stdout)
    assert out["decision"] == "block"
    assert "F401" in out["reason"]


def test_main_is_silent_on_a_clean_tree(tmp_path):
    """No output at all (not even an empty decision) when lint is clean —
    matching pre_tool_use.py's "no output means allow" convention."""
    _write_ruff_project(tmp_path)
    (tmp_path / "src" / "good.py").write_text('"""ok."""\n', encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, str(_HOOK_PATH)],
        input=json.dumps({"session_id": "abc"}),
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "CLAUDE_PROJECT_DIR": str(tmp_path)},
    )

    assert proc.returncode == 0
    assert proc.stdout.strip() == ""


def test_stop_hook_active_short_circuits(tmp_path):
    """`stop_hook_active: true` means the harness already re-invoked this hook
    once because of a previous block — honor it and exit clean rather than
    trap the session in a stop-block loop it cannot resolve itself."""
    _write_ruff_project(tmp_path)
    (tmp_path / "src" / "bad.py").write_text("import os\n", encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, str(_HOOK_PATH)],
        input=json.dumps({"session_id": "abc", "stop_hook_active": True}),
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "CLAUDE_PROJECT_DIR": str(tmp_path)},
    )

    assert proc.returncode == 0
    assert proc.stdout.strip() == ""


def test_ruff_missing_blocks_with_an_explanatory_reason(tmp_path, monkeypatch):
    """Configured but the executable/module can't be found at all → block
    (not a silent pass) — a configured linter that never runs is exactly the
    gap this hook exists to close."""
    _write_ruff_project(tmp_path)
    monkeypatch.setattr(stop_lint_gate, "_resolve_ruff", lambda: None)

    reason = stop_lint_gate.check_lint(tmp_path)

    assert reason is not None
    assert "ruff" in reason.lower()
    assert "not" in reason.lower() or "no" in reason.lower()


def test_internal_timeout_is_well_under_the_outer_harness_budget():
    """Audit 56C746EB (timeout silent-pass): the internal ruff timeout used
    to be 120s, comfortably longer than the outer harness's own timeout for
    a hook invocation (~30-60s observed) — a slow lint got the whole hook
    process SIGKILLed by the harness before the internal timeout could ever
    fire and print a block reason, so it degraded to a silent pass. The
    internal timeout must stay well under that budget so the fail-loud path
    below always wins the race."""
    assert stop_lint_gate._TIMEOUT_S <= 25


def test_ruff_timeout_blocks_loud_not_silent(tmp_path, monkeypatch):
    """A ruff invocation that times out must block with a reason naming the
    timeout — never a silent pass. This is the fail-loud half of the
    timeout fix: even though lowering _TIMEOUT_S is the harness-race fix,
    the in-process handling of TimeoutExpired must still surface a reason
    rather than swallowing it."""
    _write_ruff_project(tmp_path)

    def _fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="ruff", timeout=kwargs.get("timeout"))

    monkeypatch.setattr(stop_lint_gate.subprocess, "run", _fake_run)

    reason = stop_lint_gate.check_lint(tmp_path)

    assert reason is not None
    assert "timed out" in reason.lower() or "timeout" in reason.lower() or "did not finish" in reason.lower()


def test_ruff_configured_ignores_a_commented_out_table(tmp_path):
    """Nit fix: `_ruff_configured` parses the TOML instead of doing a naive
    substring match on `"[tool.ruff"` — a commented-out table must not
    false-positive as configured."""
    (tmp_path / "pyproject.toml").write_text(
        "# [tool.ruff]\n# line-length = 120\n\n[project]\nname = \"x\"\n",
        encoding="utf-8",
    )
    (tmp_path / "src").mkdir()

    assert stop_lint_gate._ruff_configured(tmp_path) is False


def test_ruff_configured_ignores_a_string_mention(tmp_path):
    """A `[tool.ruff` substring appearing inside an unrelated string value
    (not a real table header) must not false-positive as configured."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndescription = "mentions [tool.ruff] in prose"\n',
        encoding="utf-8",
    )
    (tmp_path / "src").mkdir()

    assert stop_lint_gate._ruff_configured(tmp_path) is False


def test_ruff_configured_still_true_for_a_real_table(tmp_path):
    """Sanity check the parse-based detection still recognizes a genuine
    `[tool.ruff]` table (and a `[tool.ruff.lint]` sub-table)."""
    (tmp_path / "pyproject.toml").write_text(
        "[tool.ruff.lint]\nselect = [\"E\"]\n", encoding="utf-8"
    )

    assert stop_lint_gate._ruff_configured(tmp_path) is True


def test_bundled_hook_is_identical_to_the_repo_copy():
    """src/willow_mcp/bundle/hooks/stop_lint_gate.py is what ships to an
    agent's harness; hooks/stop_lint_gate.py is what these tests exercise —
    same drift-catcher as test_pre_tool_use_hook.py's parity test. A fix
    applied to one and not the other is a guardrail that passes CI and is
    absent in production."""
    bundled = (
        Path(__file__).resolve().parents[1]
        / "src/willow_mcp/bundle/hooks/stop_lint_gate.py"
    )
    assert bundled.read_text() == _HOOK_PATH.read_text()
