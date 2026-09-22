"""willow_mcp/env_fingerprint.py — the reloader's env-trigger detect half.

A fingerprint must be stable across value-preserving rewrites (reordering,
re-quoting is NOT normalized — only whitespace/comment/blank-line noise is),
change on any name or value edit, and never carry a raw value — or anything
derived per-key from a value — into anything that gets written down or
asserted against in a test. That last property is checked mechanically here
(`_assert_no_secret_leak`, plus a structural `key_digests` absence check)
rather than just by argument, per Loki audit E79FCAE7's F2: the first cut of
this module kept a per-key value digest, which is itself the rainbow-table
oracle the brief forbade. F3 covers `resolve_env_source`: the live unit this
fleet runs carries `Environment=` lines, not `EnvironmentFile=`, and a
fallback file the unit does not load must never be silently fingerprinted
and called "the unit's env."
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


def _assert_no_per_key_material(*blobs) -> None:
    """F2's structural check: no per-key digest field of ANY name survives
    into a fingerprint, receipt, or state-file dict — not `key_digests`,
    not anything keyed by value. A fingerprint dict's only allowed keys are
    state/keys/digest/env_source/env_ref."""
    allowed = {"state", "keys", "digest", "env_source", "env_ref"}
    for blob in blobs:
        if isinstance(blob, dict) and blob.get("state") == "populated" and "digest" in blob:
            assert set(blob) <= allowed, f"unexpected per-fingerprint field(s): {set(blob) - allowed}"
        text = json.dumps(blob, default=str)
        assert "key_digest" not in text


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


def test_populated_never_carries_the_value_or_per_key_material(tmp_path):
    p = _write(tmp_path / "env", f"API_KEY={_SECRET}\nOTHER=1\n")
    out = envfp.compute_fingerprint(p)
    assert out["state"] == "populated"
    assert out["keys"] == ["API_KEY", "OTHER"]
    assert set(out) == {"state", "keys", "digest"}
    _assert_no_secret_leak(out)
    _assert_no_per_key_material(out)


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


# ── diff_keys: names only, over-inclusive on "changed" (F2) ───────────────────

def test_diff_keys_added_removed_are_exact(tmp_path):
    before = envfp.compute_fingerprint(_write(tmp_path / "before", f"KEEP=1\nDROP={_SECRET}\n"))
    after = envfp.compute_fingerprint(_write(tmp_path / "after", "KEEP=1\nADD=new\n"))
    diff = envfp.diff_keys(before, after)
    assert diff["keys_added"] == ["ADD"]
    assert diff["keys_removed"] == ["DROP"]
    _assert_no_secret_leak(diff, before, after)
    _assert_no_per_key_material(diff, before, after)


def test_diff_keys_changed_is_every_common_key_not_just_the_one_that_moved(tmp_path):
    """F2: a single whole-set digest cannot say WHICH common name's value
    moved — only that the set's content differs. Rather than guess (which
    would require deriving something from the values), every name common
    to both sides is reported when the digest differs. KEEP's value never
    moved here, and it is still named — over-inclusive on purpose, never
    narrowed by anything derived from a value."""
    before = envfp.compute_fingerprint(_write(tmp_path / "before", "KEEP=1\nCHANGE=old\n"))
    after = envfp.compute_fingerprint(_write(tmp_path / "after", "KEEP=1\nCHANGE=new\n"))
    diff = envfp.diff_keys(before, after)
    assert diff["keys_added"] == [] and diff["keys_removed"] == []
    assert diff["keys_changed"] == ["CHANGE", "KEEP"]


def test_diff_keys_no_diff_when_nothing_changed(tmp_path):
    a = envfp.compute_fingerprint(_write(tmp_path / "a", "A=1\nB=2\n"))
    b = envfp.compute_fingerprint(_write(tmp_path / "b", "B=2\nA=1\n"))
    assert envfp.diff_keys(a, b) == {"keys_added": [], "keys_removed": [], "keys_changed": []}


# ── resolve_env_source (F3): read the unit the way the box actually has it ────

def test_resolve_env_source_prefers_environment_file(tmp_path):
    def runner(argv, **kw):
        assert argv[:3] == ["systemctl", "--user", "show"]
        return subprocess.CompletedProcess(
            argv, 0, "EnvironmentFiles=/custom/env/path (ignore_errors=no)\nEnvironment=\n", "")

    out = envfp.resolve_env_source("willow-mcp-serve.service", runner=runner)
    assert out == {"source": "environment_file", "path": envfp.Path("/custom/env/path")}


def test_resolve_env_source_reads_unit_environment_lines_when_no_file(tmp_path):
    """The shape this fleet's live unit actually has: no EnvironmentFile=,
    Environment= lines carrying the pairs directly."""
    def runner(argv, **kw):
        return subprocess.CompletedProcess(
            argv, 0, 'EnvironmentFiles=\nEnvironment=WILLOW_HOME=/h A=1 B="two words"\n', "")

    out = envfp.resolve_env_source("willow-mcp-serve.service", runner=runner)
    assert out["source"] == "unit_environment"
    assert dict(out["pairs"]) == {"WILLOW_HOME": "/h", "A": "1", "B": "two words"}


def test_resolve_env_source_falls_back_when_neither_is_set(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))

    def runner(argv, **kw):
        return subprocess.CompletedProcess(argv, 0, "EnvironmentFiles=\nEnvironment=\n", "")

    out = envfp.resolve_env_source("willow-mcp-serve.service", runner=runner)
    assert out == {"source": "fallback", "path": tmp_path / "env"}


def test_resolve_env_source_falls_back_when_systemctl_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))

    def runner(argv, **kw):
        return subprocess.CompletedProcess(argv, 1, "", "no such unit")

    out = envfp.resolve_env_source("willow-mcp-serve.service", runner=runner)
    assert out == {"source": "fallback", "path": tmp_path / "env"}


def test_resolve_env_source_never_raises_on_missing_systemctl(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))

    def runner(argv, **kw):
        raise FileNotFoundError("no systemctl")

    out = envfp.resolve_env_source("willow-mcp-serve.service", runner=runner)
    assert out == {"source": "fallback", "path": tmp_path / "env"}


def test_fingerprint_source_environment_file(tmp_path):
    env_file = _write(tmp_path / "myenv", "A=1\n")
    out = envfp.fingerprint_source({"source": "environment_file", "path": env_file})
    assert out["state"] == "populated" and out["keys"] == ["A"]
    assert out["env_source"] == "environment_file" and out["env_ref"] == str(env_file)


def test_fingerprint_source_unit_environment_never_leaks_a_value_and_has_no_ref(tmp_path):
    out = envfp.fingerprint_source(
        {"source": "unit_environment", "pairs": [("A", "1"), ("SECRET", _SECRET)]})
    assert out["state"] == "populated"
    assert out["keys"] == ["A", "SECRET"]
    assert out["env_source"] == "unit_environment"
    assert out["env_ref"] is None
    _assert_no_secret_leak(out)
    _assert_no_per_key_material(out)


def test_fingerprint_source_fallback_missing_file_is_empty(tmp_path):
    out = envfp.fingerprint_source({"source": "fallback", "path": tmp_path / "nope"})
    assert out["state"] == "empty" and out["env_source"] == "fallback"


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
    record = envfp.record_startup(source={"source": "environment_file", "path": env_file})
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
    _assert_no_per_key_material(state["env_fingerprint"])


def test_record_startup_round_trips_into_read_state(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    env_file = _write(tmp_path / "myenv", "A=1\n")
    written = envfp.record_startup(source={"source": "environment_file", "path": env_file})
    state = envfp.read_state()
    assert state["env_fingerprint"]["digest"] == written["env_fingerprint"]["digest"]


def test_record_startup_resolves_via_systemctl_when_no_source_given(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))

    def runner(argv, **kw):
        return subprocess.CompletedProcess(argv, 0, "EnvironmentFiles=\nEnvironment=A=1 B=2\n", "")

    written = envfp.record_startup(unit="willow-mcp-serve.service", runner=runner)
    assert written["env_fingerprint"]["env_source"] == "unit_environment"
    assert written["env_fingerprint"]["keys"] == ["A", "B"]


def test_record_startup_never_raises_when_state_dir_unwritable(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    env_file = _write(tmp_path / "myenv", "A=1\n")
    blocker = envfp.state_dir()
    blocker.parent.mkdir(parents=True, exist_ok=True)
    # A FILE where the state directory should be: mkdir(parents=True) inside
    # record_startup must fail cleanly, not raise past this call.
    blocker.write_text("not a directory", encoding="utf-8")
    out = envfp.record_startup(source={"source": "environment_file", "path": env_file})
    assert "write_error" in out
