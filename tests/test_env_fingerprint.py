"""willow_mcp/env_fingerprint.py — the reloader's env-trigger detect half.

A fingerprint must be stable across value-preserving rewrites (reordering,
re-quoting is NOT normalized — only whitespace/comment/blank-line noise is),
change on any name or value edit, and never carry a raw value into anything
that gets written down or asserted against in a test. That last property is
checked mechanically here (`_assert_no_secret_leak`) rather than just by
argument, per the assignment's "grep your own test output."
"""
from __future__ import annotations

import json
import subprocess

from willow_mcp import env_fingerprint as envfp

_SECRET = "sk-super-secret-value-do-not-leak-9f8e7d6c"


def _write(path, text):
    path.write_text(text, encoding="utf-8")
    return path


def _assert_no_secret_leak(*blobs) -> None:
    """The one grep the assignment asks for: the literal secret value must
    never appear in anything handed back — receipt content, state-file
    content, or a diff. Digests are fine; the raw string is not."""
    for blob in blobs:
        text = blob if isinstance(blob, str) else json.dumps(blob, default=str)
        assert _SECRET not in text


# ── compute_fingerprint: the three-state read of a file ───────────────────────

def test_missing_file_is_empty(tmp_path):
    out = envfp.compute_fingerprint(tmp_path / "nope")
    assert out["state"] == "empty"


def test_unreadable_file_is_unreachable(tmp_path, monkeypatch):
    p = _write(tmp_path / "env", "A=1\n")

    def boom(*a, **kw):
        raise OSError("permission denied")

    monkeypatch.setattr(envfp.Path, "read_text", boom)
    out = envfp.compute_fingerprint(p)
    assert out["state"] == "unreachable" and "cause" in out


def test_populated_never_carries_the_value(tmp_path):
    p = _write(tmp_path / "env", f"API_KEY={_SECRET}\nOTHER=1\n")
    out = envfp.compute_fingerprint(p)
    assert out["state"] == "populated"
    assert out["keys"] == ["API_KEY", "OTHER"]
    _assert_no_secret_leak(out)


# ── stability / sensitivity ────────────────────────────────────────────────────

def test_fingerprint_stable_across_value_preserving_rewrites(tmp_path):
    a = envfp.compute_fingerprint(_write(tmp_path / "a", "A=1\nB=2\n"))
    # reordered, blank lines and a comment added — same names, same values.
    b = envfp.compute_fingerprint(_write(tmp_path / "b", "\n# a comment\nB=2\nA=1\n"))
    assert a["digest"] == b["digest"]
    assert a["keys"] == b["keys"] == ["A", "B"]


def test_fingerprint_changes_on_value_edit(tmp_path):
    a = envfp.compute_fingerprint(_write(tmp_path / "a", "A=1\n"))
    b = envfp.compute_fingerprint(_write(tmp_path / "b", "A=2\n"))
    assert a["digest"] != b["digest"]
    assert a["keys"] == b["keys"]


def test_fingerprint_changes_on_name_added(tmp_path):
    a = envfp.compute_fingerprint(_write(tmp_path / "a", "A=1\n"))
    b = envfp.compute_fingerprint(_write(tmp_path / "b", "A=1\nB=2\n"))
    assert a["digest"] != b["digest"]
    assert b["keys"] == ["A", "B"]


def test_fingerprints_equal_helper(tmp_path):
    a = envfp.compute_fingerprint(_write(tmp_path / "a", "A=1\n"))
    b = envfp.compute_fingerprint(_write(tmp_path / "b", "A=1\n"))
    c = envfp.compute_fingerprint(_write(tmp_path / "c", "A=2\n"))
    assert envfp.fingerprints_equal(a, b)
    assert not envfp.fingerprints_equal(a, c)
    assert envfp.fingerprints_equal({"state": "empty"}, {"state": "empty"})
    assert not envfp.fingerprints_equal({"state": "empty"}, a)


# ── diff_keys: names only ──────────────────────────────────────────────────────

def test_diff_keys_names_only_no_values(tmp_path):
    before = envfp.compute_fingerprint(_write(tmp_path / "before", f"KEEP=1\nDROP={_SECRET}\nCHANGE=old\n"))
    after = envfp.compute_fingerprint(_write(tmp_path / "after", "KEEP=1\nADD=new\nCHANGE=new\n"))
    diff = envfp.diff_keys(before, after)
    assert diff == {"keys_added": ["ADD"], "keys_removed": ["DROP"], "keys_changed": ["CHANGE"]}
    _assert_no_secret_leak(diff, before, after)


def test_diff_keys_no_diff_when_nothing_changed(tmp_path):
    a = envfp.compute_fingerprint(_write(tmp_path / "a", "A=1\nB=2\n"))
    b = envfp.compute_fingerprint(_write(tmp_path / "b", "B=2\nA=1\n"))
    assert envfp.diff_keys(a, b) == {"keys_added": [], "keys_removed": [], "keys_changed": []}


# ── resolve_env_file ────────────────────────────────────────────────────────────

def test_resolve_env_file_reads_systemctl_environmentfiles(tmp_path):
    def runner(argv, **kw):
        assert argv[:3] == ["systemctl", "--user", "show"]
        return subprocess.CompletedProcess(
            argv, 0, "EnvironmentFiles=/custom/env/path (ignore_errors=no)\n", "")

    out = envfp.resolve_env_file("willow-mcp-serve.service", runner=runner)
    assert str(out) == "/custom/env/path"


def test_resolve_env_file_falls_back_when_systemctl_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))

    def runner(argv, **kw):
        return subprocess.CompletedProcess(argv, 1, "", "no such unit")

    out = envfp.resolve_env_file("willow-mcp-serve.service", runner=runner)
    assert out == tmp_path / "env"


def test_resolve_env_file_falls_back_on_empty_property(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))

    def runner(argv, **kw):
        return subprocess.CompletedProcess(argv, 0, "EnvironmentFiles=\n", "")

    out = envfp.resolve_env_file("willow-mcp-serve.service", runner=runner)
    assert out == tmp_path / "env"


def test_resolve_env_file_never_raises_on_missing_systemctl(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))

    def runner(argv, **kw):
        raise FileNotFoundError("no systemctl")

    out = envfp.resolve_env_file("willow-mcp-serve.service", runner=runner)
    assert out == tmp_path / "env"


# ── the running broker's own record: state_path / read_state / record_startup ──

def test_read_state_missing_file_is_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    assert envfp.read_state() == {"state": "empty"}


def test_read_state_malformed_json_is_unreachable(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    envfp.state_path().parent.mkdir(parents=True, exist_ok=True)
    envfp.state_path().write_text("not json{{{", encoding="utf-8")
    out = envfp.read_state()
    assert out["state"] == "unreachable" and "cause" in out


def test_read_state_missing_env_fingerprint_key_is_unreachable(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    envfp.state_path().parent.mkdir(parents=True, exist_ok=True)
    envfp.state_path().write_text(json.dumps({"env_loaded_at": "now"}), encoding="utf-8")
    out = envfp.read_state()
    assert out["state"] == "unreachable"


def test_record_startup_writes_readable_state_and_0600(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    env_file = _write(tmp_path / "myenv", f"SECRET={_SECRET}\nPLAIN=1\n")
    record = envfp.record_startup(env_file)
    assert "write_error" not in record
    assert record["env_fingerprint"]["state"] == "populated"

    p = envfp.state_path()
    assert p.is_file()
    mode = p.stat().st_mode & 0o777
    assert mode == 0o600

    state = envfp.read_state()
    assert state["state"] == "populated"
    assert state["env_fingerprint"]["keys"] == ["PLAIN", "SECRET"]
    _assert_no_secret_leak(p.read_text(encoding="utf-8"))


def test_record_startup_round_trips_into_read_state(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    env_file = _write(tmp_path / "myenv", "A=1\n")
    written = envfp.record_startup(env_file)
    state = envfp.read_state()
    assert state["env_fingerprint"]["digest"] == written["env_fingerprint"]["digest"]


def test_record_startup_default_env_path_is_willow_home_env(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    _write(tmp_path / "env", "A=1\n")
    written = envfp.record_startup()
    assert written["env_path"] == str(tmp_path / "env")


def test_record_startup_never_raises_when_state_dir_unwritable(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    env_file = _write(tmp_path / "myenv", "A=1\n")
    blocker = envfp.state_dir()
    blocker.parent.mkdir(parents=True, exist_ok=True)
    # A FILE where the state directory should be: mkdir(parents=True) inside
    # record_startup must fail cleanly, not raise past this call.
    blocker.write_text("not a directory", encoding="utf-8")
    out = envfp.record_startup(env_file)
    assert "write_error" in out
