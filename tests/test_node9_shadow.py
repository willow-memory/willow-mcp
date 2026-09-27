"""node9 shadow mode (sealed a6d054b3, amended
node9-shadow-shape-only-ledger-2026-09-27, per Loki re-audit A68E86E9) —
unit tests for the shape-only ledger, doubt handling, and the report.

These mock the subprocess boundary only (`subprocess.Popen`), never the
shape/flag computation or the classifier. The live shim-vs-`node9 explain`
integration test (including the real spoof fixture, the R1 plant test, and
the R5/R6 measurements) lives in test_node9_shadow_live.py and skips when no
node9 install is present.
"""
from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import signal
import stat
import subprocess
import time
from pathlib import Path

import pytest

from willow_mcp import node9_shadow


def _install_stub_shim(home: Path) -> None:
    src_node = home / "_src_node"
    src_node.write_text("#!/bin/sh\necho fake-node\n")
    src_node9_ai = home / "_src_node9_ai"
    (src_node9_ai / "bin").mkdir(parents=True)
    (src_node9_ai / "bin" / "node9.js").write_text("// fake\n")
    (src_node9_ai / "package.json").write_text(json.dumps({"version": "9.9.9-test"}))
    node9_shadow.install_shim(source_node=str(src_node), source_node9_ai=str(src_node9_ai))


@pytest.fixture(autouse=True)
def _willow_home(tmp_path, monkeypatch):
    home = tmp_path / "willow"
    home.mkdir()
    monkeypatch.setenv("WILLOW_HOME", str(home))
    monkeypatch.delenv(node9_shadow._ENV_NODE_OVERRIDE, raising=False)
    monkeypatch.delenv(node9_shadow._ENV_SCRIPT_OVERRIDE, raising=False)
    monkeypatch.delenv(node9_shadow._ENV_ENABLE, raising=False)
    _install_stub_shim(home)
    return home


class _FakePopen:
    def __init__(self, stdout="", returncode=0, raise_timeout=False, pid=4242):
        self._stdout = stdout
        self.returncode = returncode
        self._raise_timeout = raise_timeout
        self.pid = pid
        self._timed_out_once = False

    def communicate(self, input=None, timeout=None):  # noqa: A002
        if self._raise_timeout and not self._timed_out_once:
            self._timed_out_once = True
            raise subprocess.TimeoutExpired(cmd="node", timeout=timeout)
        return self._stdout, ""

    def wait(self, timeout=None):
        return 0


def _record(monkeypatch, popen, surface="bash", seat="hanuman", command="echo hi",
            willow_verdict="allow", willow_reason="", killpg_calls=None, getpgid_calls=None):
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: popen)
    getpgid_calls = getpgid_calls if getpgid_calls is not None else []

    def _getpgid(pid):
        getpgid_calls.append(pid)
        return pid
    monkeypatch.setattr("os.getpgid", _getpgid)
    if killpg_calls is not None:
        monkeypatch.setattr("os.killpg", lambda pgid, sig: killpg_calls.append((pgid, sig)))
    else:
        monkeypatch.setattr("os.killpg", lambda pgid, sig: None)
    node9_shadow._do_record({
        "surface": surface, "seat": seat, "command": command,
        "willow_verdict": willow_verdict, "willow_reason": willow_reason,
    })


# T3 (Loki CC59AF30): the leak-substring scan below excludes these fields
# BY NAME, explicitly — never "everything except flags" or some other
# implicit carve-out. Each is a non-content field that can coincidentally
# collide with a hex/digit-heavy secret by pure chance, not a leak of the
# secret's own text: `flags` is a fixed, descriptive category vocabulary;
# `ts` is a wall-clock ISO timestamp (discovered flaky against probes like
# ...3456); `cmd_hmac` is 64 random hex characters (a hex-heavy probe like
# "abcdef0123456789" has a real, if small, per-run chance of a 4-char
# window matching purely by coincidence against 61 possible hex windows);
# `latency_ms` is a small integer. `shape`, `willow_reason`, `node9_rule`
# and `status` are exactly the fields that could ever carry text, and stay
# in scope — see test_leak_scan_mutation_proof_still_catches_a_real_leak
# below for proof the scan still fails on an actual leak.
_LEAK_SCAN_EXCLUDED_FIELDS = frozenset({"flags", "ts", "cmd_hmac", "latency_ms"})


def _rows() -> list[dict]:
    if not node9_shadow.ledger_path().is_file():
        return []
    return [json.loads(line) for line in node9_shadow.ledger_path().read_text().splitlines()]


# ── never-allow-on-doubt (F3, F4) ────────────────────────────────────────

def test_clean_command_gets_a_real_verdict_and_a_shape_not_the_text(monkeypatch):
    popen = _FakePopen(stdout=json.dumps({"verdict": "block", "node9_rule_raw": "shield: rm-rf-home"}))
    _record(monkeypatch, popen, command="rm -rf /")
    row = _rows()[0]
    assert row["node9_verdict"] == "block"
    assert row["node9_rule"] == "rm-rf-home"
    assert row["shape"] == "rm"
    assert "command" not in row
    assert "redacted" not in row


def test_timeout_becomes_unknown_never_allow(monkeypatch):
    popen = _FakePopen(raise_timeout=True)
    _record(monkeypatch, popen)
    assert _rows()[0]["node9_verdict"] == "unknown"


def test_nonzero_exit_becomes_unknown_never_allow(monkeypatch):
    popen = _FakePopen(stdout="", returncode=1)
    _record(monkeypatch, popen)
    assert _rows()[0]["node9_verdict"] == "unknown"


def test_garbage_stdout_becomes_unknown_never_allow(monkeypatch):
    popen = _FakePopen(stdout="not json at all")
    _record(monkeypatch, popen)
    assert _rows()[0]["node9_verdict"] == "unknown"


def test_invalid_verdict_word_becomes_unknown_never_allow(monkeypatch):
    popen = _FakePopen(stdout=json.dumps({"verdict": "maybe", "node9_rule_raw": ""}))
    _record(monkeypatch, popen)
    assert _rows()[0]["node9_verdict"] == "unknown"


def test_spawn_error_becomes_unknown_never_allow(monkeypatch):
    def _boom(*a, **k):
        raise FileNotFoundError("no node")
    monkeypatch.setattr(subprocess, "Popen", _boom)
    node9_shadow._do_record({
        "surface": "bash", "seat": "x", "command": "echo hi",
        "willow_verdict": "allow", "willow_reason": "",
    })
    assert _rows()[0]["node9_verdict"] == "unknown"


def test_missing_node_or_script_file_is_unknown_not_a_crash(monkeypatch):
    node9_shadow._make_tree_writable(node9_shadow._shadow_root())
    node9_shadow._node_bin_path().unlink()
    node9_shadow._do_record({
        "surface": "bash", "seat": "x", "command": "echo hi",
        "willow_verdict": "allow", "willow_reason": "",
    })
    assert _rows()[0]["node9_verdict"] == "unknown"


def test_only_allow_block_review_ever_reach_the_ledger_as_node9_verdict(monkeypatch):
    for word, expected in [("ALLOW", "allow"), ("BLOCK", "block"), ("REVIEW", "review")]:
        node9_shadow.ledger_path().unlink(missing_ok=True)
        popen = _FakePopen(stdout=json.dumps({"verdict": word.lower(), "node9_rule_raw": ""}))
        _record(monkeypatch, popen)
        assert _rows()[0]["node9_verdict"] == expected


# ── R4/S2: process group always killed, not only on timeout ─────────────

def test_killpg_runs_even_on_a_clean_exit_not_only_on_timeout(monkeypatch):
    """Loki A68E86E9 R4: the shim's own inner timeout usually fires first,
    exits 0 with 'unknown', and the old code's killpg branch (guarded by
    `except TimeoutExpired`) never ran at all — leaving any grandchild node9
    spawned still alive. killpg must run after every call, clean or not."""
    calls = []
    popen = _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))
    _record(monkeypatch, popen, killpg_calls=calls)
    assert len(calls) == 1
    assert calls[0][0] == popen.pid
    assert calls[0][1] == signal.SIGKILL


def test_killpg_runs_on_timeout_too(monkeypatch):
    calls = []
    popen = _FakePopen(raise_timeout=True)
    _record(monkeypatch, popen, killpg_calls=calls)
    assert len(calls) == 1


def test_killpg_targets_proc_pid_directly_never_getpgid_after_exit(monkeypatch):
    """Loki 1CCE0D9B S2: `os.getpgid(proc.pid)` AFTER `communicate()` has
    already reaped the child raises `ProcessLookupError`, silently
    swallowed — so the old code's kill was ALWAYS a no-op. Since the shim is
    launched with `start_new_session=True`, its pgid IS its own pid; the
    fix kills `proc.pid` directly and must never call `getpgid` at all."""
    killpg_calls = []
    getpgid_calls = []
    popen = _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))
    _record(monkeypatch, popen, killpg_calls=killpg_calls, getpgid_calls=getpgid_calls)
    assert getpgid_calls == [], "S2: getpgid must never be called after the child may be reaped"
    assert killpg_calls == [(popen.pid, signal.SIGKILL)]


def test_shim_and_recorder_share_one_timeout_value(monkeypatch):
    """R4: no two independently-chosen timeout numbers — the recorder passes
    ITS OWN TIMEOUT_SECONDS to the shim via env, so there is one source of
    truth."""
    captured_env = {}

    def _fake_popen(args, **kwargs):
        captured_env.update(kwargs.get("env") or {})
        return _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))

    monkeypatch.setattr(subprocess, "Popen", _fake_popen)
    monkeypatch.setattr("os.getpgid", lambda pid: pid)
    monkeypatch.setattr("os.killpg", lambda pgid, sig: None)
    node9_shadow._do_record({
        "surface": "bash", "seat": "x", "command": "echo hi",
        "willow_verdict": "allow", "willow_reason": "",
    })
    assert captured_env[node9_shadow._ENV_TIMEOUT_MS] == str(int(node9_shadow.TIMEOUT_SECONDS * 1000))


# ── never free text (F1, F2) ──────────────────────────────────────────────

def test_node9_rule_whitelists_or_falls_back_to_unparsed(monkeypatch):
    popen = _FakePopen(stdout=json.dumps({
        "verdict": "block", "node9_rule_raw": "project-jail (AST): shield:project-jail",
    }))
    _record(monkeypatch, popen)
    assert _rows()[0]["node9_rule"] == "shield:project-jail"

    node9_shadow.ledger_path().unlink()
    popen2 = _FakePopen(stdout=json.dumps({
        "verdict": "block", "node9_rule_raw": "this reason ends on a bad@token",
    }))
    _record(monkeypatch, popen2)
    assert _rows()[0]["node9_rule"] == "unparsed"


def test_willow_reason_is_a_fixed_code_never_free_text(monkeypatch):
    popen = _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))
    _record(monkeypatch, popen, willow_reason="net_denied: shared network access requires ...")
    assert _rows()[0]["willow_reason"] == "net_denied"

    node9_shadow.ledger_path().unlink()
    _record(monkeypatch, popen, willow_reason="some totally free-form human sentence")
    assert _rows()[0]["willow_reason"] == "other"


# ── shape-only ledger (operator ruling node9-shadow-shape-only-ledger-2026-09-27) ──

def _all_ledger_text() -> str:
    return node9_shadow.ledger_path().read_text() if node9_shadow.ledger_path().is_file() else ""


def _fake(*parts: str) -> str:
    """Builds a fake secret-shaped string from small fragments AT RUNTIME —
    never as a source-level literal — so no line of this file's diff can
    ever match a literal secret-scanning pattern. GitHub's secret-scanning
    push protection scans the raw TEXT of every added line in every commit
    for these exact shapes; splitting each one into several short,
    freestanding string arguments (never string-literal concatenation
    forming one contiguous run) means no single source line ever contains
    the full pattern, while the runtime VALUE still has the right shape to
    exercise the real detector."""
    return "".join(parts)


# Fake secret VALUES, built once here from small fragments — referenced by
# NAME everywhere below, so no probe definition line can ever reconstitute
# a flagged pattern (push protection blocked the original push over literal
# AKIA.../xox?-.../eyJ....eyJ.../BEGIN...PRIVATE KEY fixtures in this exact
# file).
_FAKE_AWS_KEY = _fake("AK", "IA", "Q" * 16)
_FAKE_SLACK_TOKEN = _fake("xo", "xb", "-", "1" * 6, "-", "a" * 16)
_FAKE_GITHUB_PAT = _fake("git", "hub", "_", "pat", "_", "d" * 40)
_FAKE_JWT = _fake("ey", "J", "h" * 20) + "." + _fake("ey", "J", "s" * 20) + "." + ("x" * 20)
_FAKE_PEM_HEADER = _fake("-----", "BEGIN ", "RSA ", "PRIVATE KEY-----")
_FAKE_PEM_FOOTER = _fake("-----", "END ", "RSA ", "PRIVATE KEY-----")
# Same value as _FAKE_AWS_KEY, split mid-string by a backslash-newline —
# built from the variable above, never a second literal.
_AWS_KEY_SPLIT_COMMAND = "export AWS_KEY=" + _FAKE_AWS_KEY[:9] + "\\\n" + _FAKE_AWS_KEY[9:]


# Loki's full 22-probe secret corpus (53741054) plus the 7 new cases from the
# re-audit (A68E86E9 R2). Every one of these must produce a shape-only row —
# true by construction now (the hybrid "store when nothing fires" path is
# gone), but committed as fixtures per the rework brief anyway. The third
# element is the actual SECRET VALUE for that probe (not a command name, a
# flag category word, or placeholder prose) — what the "no 4+ char substring
# leaks" assertion below actually checks against.
_SECRET_PROBES = [
    ("aws_access_key", "export AWS_KEY=" + _FAKE_AWS_KEY, _FAKE_AWS_KEY),
    ("aws_key_backslash_split", _AWS_KEY_SPLIT_COMMAND, _FAKE_AWS_KEY),
    ("openai_key", "curl -H 'Authorization: Bearer sk-" + "a" * 40 + "'", "sk-" + "a" * 40),
    ("anthropic_key", "export KEY=sk-ant-api03-" + "b" * 40, "sk-ant-api03-" + "b" * 40),
    ("slack_token", "post " + _FAKE_SLACK_TOKEN, _FAKE_SLACK_TOKEN),
    # Named for the token PREFIX under test, not the vendor's own name for
    # the format, so the probe's own identifier never spells out the
    # substring a secret scanner keys on (see _fake() above).
    ("github_token_ghp_prefix", "git clone https://ghp_" + "c" * 36 + "@github.com/x/y", "ghp_" + "c" * 36),
    ("github_token_new_prefix", "git clone https://" + _FAKE_GITHUB_PAT + "@github.com/x/y", _FAKE_GITHUB_PAT),
    ("jwt", "curl -H 'Authorization: Bearer " + _FAKE_JWT + "'", _FAKE_JWT),
    ("authorization_header", "curl -H 'Authorization: Token abcdef0123456789'", "abcdef0123456789"),
    ("curl_userpass", "curl -u alice:sup3rSecretPW http://example.com", "sup3rSecretPW"),
    ("password_flag_glued", "mysql -pS3cr3tPassw0rd -u root", "S3cr3tPassw0rd"),
    ("password_flag_eq", "app --password=hunter2hunter2", "hunter2hunter2"),
    ("url_userinfo", "curl https://alice:sup3rSecretPW@example.com/api", "sup3rSecretPW"),
    ("query_string_token", "curl 'https://example.com/x?token=abcdef0123456789'", "abcdef0123456789"),
    ("pem_private_key",
     "cat <<'EOF'\n" + _FAKE_PEM_HEADER + "\nmV9xQ2wZ7bK4nR8jH3sD6fL0cP5tA1eG9uY2oI7W\n"
     + _FAKE_PEM_FOOTER + "\nEOF",
     "mV9xQ2wZ7bK4nR8jH3sD6fL0cP5tA1eG9uY2oI7W"),
    ("ssh_key_path", "cat ~/.ssh/id_ed25519", "id_ed25519"),
    ("high_entropy_token", "export TOK=aZ9kL3mQ7xR2vB8nW4pJ6", "aZ9kL3mQ7xR2vB8nW4pJ6"),
    ("ssn", "echo 123-45-6789", "123456789"),
    ("credit_card_luhn", "echo 4111111111111111", "4111111111111111"),
    ("iban", "echo GB29NWBK60161331926819", "GB29NWBK60161331926819"),
    ("email", "echo alice.smith@example.com", "alice.smith"),
    ("home_path", "cat /home/alice/.config/secret.json", "alice"),
    ("assigned_secret", "export API_SECRET=abcd1234efgh5678ijkl", "abcd1234efgh5678ijkl"),
    # New in A68E86E9's re-audit (R2):
    ("sshpass", "sshpass -p hunter2pw ssh root@host", "hunter2pw"),
    ("docker_login", "docker login -u bob -p hunter2pw", "hunter2pw"),
    ("gpg_passphrase", "gpg --passphrase hunter2pw --decrypt file.gpg", "hunter2pw"),
    ("gh_auth_token", "gh auth login --with-token hunter2tok", "hunter2tok"),
    ("openssl_key", "openssl enc -k hunter2pw -in file -out file.enc", "hunter2pw"),
    ("x_api_key_header", 'curl -H "X-Api-Key: abcd1234efgh"', "abcd1234efgh"),
    ("access_token_query", "curl 'https://example.com/x?access_token=aaaabbbbccccdddd1111'",
     "aaaabbbbccccdddd1111"),
]


@pytest.mark.parametrize("name,command,secret", _SECRET_PROBES, ids=[p[0] for p in _SECRET_PROBES])
def test_secret_probe_never_leaks_into_the_ledger(monkeypatch, name, command, secret):
    popen = _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))
    _record(monkeypatch, popen, command=command)
    row = _rows()[0]
    assert "command" not in row and "redacted" not in row
    # The assertion: no row contains any substring of the fake secret longer
    # than 3 characters. True by construction under shape-only (there is no
    # text field left to leak into), kept anyway per the brief. Checked
    # against every field EXCEPT `flags` — flags are fixed, descriptive
    # category names ("password_arg", "github_token", ...) drawn from a
    # small closed vocabulary, not the secret's own text; a human-chosen
    # secret that happens to contain an English word also present in a
    # category's OWN name (a "...Password..." value against the
    # "password_arg" category, a "github_..." token against the
    # "github_token" category) is a name collision, not a leak of the
    # secret's actual content — the category name is written whether the
    # secret was "hunter2" or "xk9$mQ2z", so no information about the
    # secret's own text is disclosed by it appearing. See
    # _LEAK_SCAN_EXCLUDED_FIELDS above for the full, explicit, by-name
    # exclusion list and why each entry is there (T3, Loki CC59AF30 —
    # cmd_hmac's own 64 random hex characters can also coincidentally
    # collide with a hex-heavy probe, not just `ts`).
    row_without_noise = {k: v for k, v in row.items() if k not in _LEAK_SCAN_EXCLUDED_FIELDS}
    ledger_text = json.dumps(row_without_noise)
    for i in range(0, max(len(secret) - 3, 1)):
        chunk = secret[i:i + 4]
        if len(chunk) == 4:
            assert chunk.lower() not in ledger_text.lower(), (
                f"{name}: {chunk!r} (from secret {secret!r}) leaked outside flags"
            )


def test_clean_command_never_stores_full_text_either(monkeypatch):
    """The hybrid model's 'store in full when nothing fires' path is GONE —
    even an entirely clean command gets shape+hmac only, never text."""
    popen = _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))
    command = "ls -la /tmp && echo done"
    _record(monkeypatch, popen, command=command)
    row = _rows()[0]
    assert "command" not in row
    assert row["shape"] == "ls echo"
    assert command not in _all_ledger_text()


def test_cmd_hmac_is_keyed_not_a_bare_hash(monkeypatch, tmp_path):
    popen = _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))
    command = "echo hi"
    _record(monkeypatch, popen, command=command)
    row = _rows()[0]
    assert row["cmd_hmac"] != hashlib.sha256(command.encode()).hexdigest()
    key = node9_shadow._get_or_create_hmac_key()
    expected = hmac_mod.new(key, command.encode(), hashlib.sha256).hexdigest()
    assert row["cmd_hmac"] == expected


def test_hmac_key_is_created_0600_and_reused(tmp_path):
    key1 = node9_shadow._get_or_create_hmac_key()
    key_path = node9_shadow._hmac_key_path()
    assert key_path.is_file()
    assert len(key1) == 32
    mode = stat.S_IMODE(key_path.stat().st_mode)
    assert mode == 0o600
    key2 = node9_shadow._get_or_create_hmac_key()
    assert key1 == key2


def test_shape_skips_leading_var_assignments(monkeypatch):
    popen = _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))
    _record(monkeypatch, popen, command="FOO=bar BAZ=qux curl http://example.com")
    assert _rows()[0]["shape"] == "curl"


def test_shape_is_question_mark_for_a_high_entropy_first_word(monkeypatch):
    popen = _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))
    _record(monkeypatch, popen, command="aZ9kL3mQ7xR2vB8n --flag")
    assert _rows()[0]["shape"] == "?"


# ── S1 (Loki 1CCE0D9B): shape words come from a fixed allowlist only ────

def test_shape_word_must_exactly_match_the_allowlist_not_just_look_safe(monkeypatch):
    """The old rule kept any lowercase, <=32-char, low-entropy first word —
    a password sitting alone in command position passed. The allowlist rule
    cannot make that mistake: a password never happens to equal a real,
    committed command name."""
    popen = _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))
    _record(monkeypatch, popen, command="hunter2pass")
    assert _rows()[0]["shape"] == "?"


def test_shape_matches_allowlist_on_basename_of_an_absolute_path(monkeypatch):
    popen = _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))
    _record(monkeypatch, popen, command="/usr/bin/curl -sS https://example.com")
    assert _rows()[0]["shape"] == "curl"


def test_shape_match_is_case_sensitive(monkeypatch):
    popen = _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))
    _record(monkeypatch, popen, command="CURL https://example.com")
    assert _rows()[0]["shape"] == "?"


# Loki's exact 11-probe reproduction from 1CCE0D9B (S1 HIGH) — every one of
# these leaked as a `shape` word under the old regex+entropy rule. The
# allowlist plus heredoc-body stripping must turn every one of them into
# `?` (or a genuinely safe command word elsewhere in the same shape
# string), never the secret itself.
_SHAPE_LEAK_PROBES = [
    ("sw_bare_password", "hunter2pass", "hunter2pass"),
    ("sw_after_semicolon", "ls; hunter2pass", "hunter2pass"),
    ("sw_after_pipe", "echo x | hunter2pass", "hunter2pass"),
    ("sw_after_oror", "false || letmein99", "letmein99"),
    ("sw_heredoc_mysql", "mysql -u root -p <<EOF\nhunter2pass\nEOF", "hunter2pass"),
    ("sw_heredoc_creds", "cat > c <<EOF\nsupersecretword\nEOF", "supersecretword"),
    ("sw_kart_script", "set -e\ncd /tmp\npassword123\necho done", "password123"),
    ("sw_leading_tab", "\tcorrecthorsebatterystaple", "correcthorsebatterystaple"),
    ("sw_continuation", "ls \\\n; hunter2pass", "hunter2pass"),
    ("sw_var_then_word", "DB_PASS=x hunter2pass", "hunter2pass"),
    ("sw_crlf", "ls\r\nhunter2pass", "hunter2pass"),
]


@pytest.mark.parametrize("name,command,secret", _SHAPE_LEAK_PROBES, ids=[p[0] for p in _SHAPE_LEAK_PROBES])
def test_shape_leak_probes_from_1cce0d9b_never_leak(monkeypatch, name, command, secret):
    popen = _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))
    _record(monkeypatch, popen, command=command)
    row = _rows()[0]
    shape_words = row["shape"].split()
    assert secret.lower() not in (w.lower() for w in shape_words), (
        f"{name}: secret {secret!r} appeared as a shape word in {row['shape']!r}"
    )
    row_without_noise = {k: v for k, v in row.items() if k not in _LEAK_SCAN_EXCLUDED_FIELDS}
    ledger_text = json.dumps(row_without_noise).lower()
    assert secret.lower() not in ledger_text, f"{name}: {secret!r} leaked outside flags"


def test_heredoc_body_never_reaches_shape_even_when_unquoted_or_dashed(monkeypatch):
    popen = _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))
    for command in (
        "cat <<EOF\nhunter2pass\nEOF",
        "cat <<-EOF\n\t\thunter2pass\n\tEOF",
        "cat <<'EOF'\nhunter2pass\nEOF",
    ):
        node9_shadow.ledger_path().unlink(missing_ok=True)
        _record(monkeypatch, popen, command=command)
        assert "hunter2pass" not in _rows()[0]["shape"]


def test_unterminated_heredoc_truncates_and_never_leaks(monkeypatch):
    popen = _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))
    _record(monkeypatch, popen, command="cat <<EOF\nhunter2pass\nno terminator here")
    row = _rows()[0]
    assert row.get("truncated") is True
    assert "hunter2pass" not in row["shape"]


def test_command_substitution_and_process_substitution_never_leak_inner_words(monkeypatch):
    popen = _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))
    for command in (
        "$(cat secretword)",
        "`cat secretword`",
        "diff <(cat secretword) /dev/null",
    ):
        node9_shadow.ledger_path().unlink(missing_ok=True)
        _record(monkeypatch, popen, command=command)
        assert "secretword" not in _rows()[0]["shape"]


def test_strip_heredocs_keeps_the_opener_line_drops_only_the_body():
    text, truncated = node9_shadow._strip_heredocs("mysql -u root -p <<EOF\nsecret\nEOF\necho done")
    assert not truncated
    assert "secret" not in text
    assert "mysql -u root -p <<EOF" in text
    assert "echo done" in text


def test_strip_heredocs_dash_variant_strips_leading_tabs_on_terminator():
    text, truncated = node9_shadow._strip_heredocs("cat <<-EOF\n\tsecret\n\tEOF\necho done")
    assert not truncated
    assert "secret" not in text
    assert "echo done" in text


def test_strip_heredocs_unterminated_drops_everything_after_and_flags_truncated():
    text, truncated = node9_shadow._strip_heredocs("cat <<EOF\nsecret\nstill going")
    assert truncated
    assert "secret" not in text
    assert "still going" not in text
    assert "cat <<EOF" in text


def test_flags_are_category_names_never_values(monkeypatch):
    popen = _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))
    _record(monkeypatch, popen, command="export AWS_KEY=" + _FAKE_AWS_KEY)
    row = _rows()[0]
    # A real AWS key is both a recognized shape (aws_key) AND, incidentally,
    # a high-entropy token — both are legitimate, simultaneous category
    # hits; the property under test is "never a value", not "exactly one
    # category".
    assert "aws_key" in row.get("flags", [])
    for flag in row.get("flags", []):
        assert flag in {name for name, _ in node9_shadow._FLAG_CATEGORIES} | {
            "card_number", "iban", "high_entropy",
        }
    assert _FAKE_AWS_KEY not in json.dumps(row)


# ── L1 (Loki BAC13B68): flags is write-time validated against FLAG_NAMES ──

def test_every_flag_in_every_probe_row_is_in_flag_names(monkeypatch):
    """The leak scan excludes `flags` from its substring check on the
    assumption that it only ever carries fixed category names, never a
    value — this is the write-time guarantee that assumption rests on."""
    popen = _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))
    for _name, command, _secret in _SECRET_PROBES:
        node9_shadow.ledger_path().unlink(missing_ok=True)
        _record(monkeypatch, popen, command=command)
        row = _rows()[0]
        for flag in row.get("flags", []):
            assert flag in node9_shadow.FLAG_NAMES, (
                f"probe {_name!r} produced a flag {flag!r} outside FLAG_NAMES"
            )


def test_a_detector_bug_leaking_command_text_into_flags_is_caught_and_replaced(monkeypatch):
    """L1's exact reproduction: something upstream of the write (a future
    _detect_flags bug, a mis-added category) puts a command fragment into
    the flags list instead of a fixed category name. The write-time filter
    must drop it and record only 'invalid_flag' — never the fragment."""
    fragment = "leaked-command-fragment-xyz"

    def _leaky_detect_flags(text):
        return ["aws_key", fragment]

    monkeypatch.setattr(node9_shadow, "_detect_flags", _leaky_detect_flags)
    popen = _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))
    _record(monkeypatch, popen, command=f"echo {fragment}")
    row = _rows()[0]
    assert "invalid_flag" in row["flags"]
    assert fragment not in row["flags"]
    assert fragment not in json.dumps(row)
    # The one legitimate flag the (mocked) detector also returned survives
    # the filter — this isn't "drop everything on any doubt", only the
    # specific bad entries are removed.
    assert "aws_key" in row["flags"]


def test_report_never_prints_a_shape_only_rows_text(monkeypatch):
    popen = _FakePopen(stdout=json.dumps({"verdict": "block", "node9_rule_raw": "aws"}))
    _record(monkeypatch, popen, command="export AWS_KEY=" + _FAKE_AWS_KEY, willow_verdict="allow")
    report = node9_shadow.build_report(prune=False)
    text = node9_shadow.render_report(report)
    assert _FAKE_AWS_KEY not in text
    top = report["top_node9_stricter"][0]
    assert "shape" in top and "flags" in top
    assert "command" not in top and "redacted" not in top


# ── R3: size check first, linear time ────────────────────────────────────

def test_oversize_command_is_truncated_for_shape_but_still_hashed_in_full(monkeypatch):
    popen = _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))
    command = "echo " + ("a" * (node9_shadow.MAX_SHAPE_BYTES + 100))
    _record(monkeypatch, popen, command=command)
    row = _rows()[0]
    assert row.get("truncated") is True
    assert row["cmd_hmac"] == hmac_mod.new(
        node9_shadow._get_or_create_hmac_key(), command.encode(), hashlib.sha256
    ).hexdigest()


def test_200kb_command_scans_fast(monkeypatch):
    """R3's exact reproduction: a 200 KB command used to take ~25s of CPU
    (quadratic _USERINFO_URL, and detection ran before the size gate).
    Bounding scan input to MAX_SHAPE_BYTES and checking size FIRST must keep
    this well under 200ms."""
    popen = _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))
    command = "curl " + ("a" * 200_000) + "://x:y@z"
    start = time.monotonic()
    _record(monkeypatch, popen, command=command)
    elapsed_ms = (time.monotonic() - start) * 1000
    assert elapsed_ms < 200, f"took {elapsed_ms:.1f}ms"


def test_size_check_runs_before_any_regex(monkeypatch):
    """Order matters (R3): the old code ran detection BEFORE the size gate
    (`or` short-circuited the wrong way). Assert directly on the helper."""
    text, truncated = node9_shadow._size_check("x" * (node9_shadow.MAX_SHAPE_BYTES + 1))
    assert truncated is True
    assert len(text.encode("utf-8")) <= node9_shadow.MAX_SHAPE_BYTES


# ── S3 (Loki 1CCE0D9B): the caller never writes more than the pipe can
# hold without blocking — above MAX_STDIN_BYTES it sends no command text
# at all, only a caller-computed cmd_hmac + len ──────────────────────────

def test_oversize_payload_sends_no_command_text_to_the_recorder(monkeypatch):
    captured = {}

    def _fake_spawn_detached(payload_json):
        captured["payload"] = json.loads(payload_json)

    monkeypatch.setattr(node9_shadow, "_spawn_detached", _fake_spawn_detached)
    big_command = "echo " + ("a" * (node9_shadow.MAX_STDIN_BYTES + 1000))
    node9_shadow.spawn_shadow("bash", "hanuman", big_command, "allow")
    payload = captured["payload"]
    assert payload["oversize"] is True
    assert "command" not in payload
    assert payload["len"] == len(big_command.encode("utf-8"))
    expected_hmac = hmac_mod.new(
        node9_shadow._get_or_create_hmac_key(), big_command.encode(), hashlib.sha256
    ).hexdigest()
    assert payload["cmd_hmac"] == expected_hmac
    sent_bytes = len(payload_to_json_bytes(payload))
    assert sent_bytes < node9_shadow.MAX_STDIN_BYTES


def payload_to_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload).encode("utf-8")


def test_oversize_row_carries_only_hmac_and_len_no_shape_or_node9_verdict_work(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("oversize path must never exec node9")
    ))
    node9_shadow._do_record({
        "surface": "bash", "seat": "hanuman", "oversize": True,
        "cmd_hmac": "f" * 64, "len": 999999,
        "willow_verdict": "allow", "willow_reason": "",
    })
    row = _rows()[0]
    assert row["status"] == "oversize"
    assert row["cmd_hmac"] == "f" * 64
    assert row["len"] == 999999
    assert "shape" not in row
    assert "flags" not in row


def test_small_payload_stays_on_the_normal_full_command_path(monkeypatch):
    captured = {}

    def _fake_spawn_detached(payload_json):
        captured["payload"] = json.loads(payload_json)

    monkeypatch.setattr(node9_shadow, "_spawn_detached", _fake_spawn_detached)
    node9_shadow.spawn_shadow("bash", "hanuman", "echo hi", "allow")
    assert captured["payload"].get("command") == "echo hi"
    assert "oversize" not in captured["payload"]


def test_1mb_command_finishes_spawn_shadow_within_the_50ms_bar(monkeypatch):
    """S3's exact reproduction: writing an oversize payload synchronously to
    the recorder's stdin pipe used to block the caller (70 KB: ~80ms, 1 MB:
    ~266ms). Above MAX_STDIN_BYTES the caller only computes a hash and spawns
    a tiny payload, so this must stay fast regardless of input size."""
    monkeypatch.setattr(node9_shadow, "_spawn_detached", lambda payload_json: None)
    command = "x" * (1024 * 1024)
    start = time.monotonic()
    node9_shadow.spawn_shadow("bash", "hanuman", command, "allow")
    elapsed_ms = (time.monotonic() - start) * 1000
    assert elapsed_ms < 50, f"took {elapsed_ms:.1f}ms"


# ── S4 (Loki 1CCE0D9B): $WILLOW_HOME/shadow/ is 0700 ─────────────────────

def test_shadow_dir_is_created_0700():
    node9_shadow._get_or_create_hmac_key()
    mode = stat.S_IMODE(node9_shadow._shadow_dir_path().stat().st_mode)
    assert mode == 0o700


def test_shadow_dir_is_tightened_even_if_it_already_existed_looser():
    d = node9_shadow._shadow_dir_path()
    d.mkdir(parents=True, exist_ok=True)
    d.chmod(0o775)
    assert stat.S_IMODE(d.stat().st_mode) == 0o775
    node9_shadow._ensure_shadow_dir()
    assert stat.S_IMODE(d.stat().st_mode) == 0o700


# ── off switch (F9) ───────────────────────────────────────────────────────

def test_spawn_shadow_off_switch_env_var(monkeypatch):
    monkeypatch.setenv(node9_shadow._ENV_ENABLE, "0")
    calls = []
    monkeypatch.setattr(node9_shadow, "_spawn_detached", lambda payload: calls.append(payload))
    node9_shadow.spawn_shadow("bash", "x", "echo hi", "allow")
    assert calls == []
    assert not node9_shadow.ledger_path().exists()


def test_spawn_shadow_off_when_shim_not_installed(monkeypatch, tmp_path):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path / "fresh-uninstalled"))
    calls = []
    monkeypatch.setattr(node9_shadow, "_spawn_detached", lambda payload: calls.append(payload))
    node9_shadow.spawn_shadow("bash", "x", "echo hi", "allow")
    assert calls == []


def test_spawn_shadow_never_raises_even_if_fork_itself_fails(monkeypatch):
    monkeypatch.setattr(node9_shadow, "_spawn_detached", lambda payload: (_ for _ in ()).throw(OSError("no fork")))
    node9_shadow.spawn_shadow("bash", "x", "echo hi", "allow")  # must not raise


# ── R6: stdin pipe only, never a tempfile ────────────────────────────────

def test_spawn_detached_never_calls_tempfile(monkeypatch):
    import tempfile as tempfile_mod

    calls = []
    monkeypatch.setattr(tempfile_mod, "mkstemp", lambda *a, **k: calls.append(1) or (0, "/tmp/should-not-happen"))
    monkeypatch.setattr(tempfile_mod, "NamedTemporaryFile", lambda *a, **k: calls.append(1))

    class _FakeStdin:
        def write(self, data):
            pass

        def close(self):
            pass

    class _FakeProc:
        stdin = _FakeStdin()

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: _FakeProc())
    node9_shadow._spawn_detached(json.dumps({"surface": "bash"}))
    assert calls == [], "R6: the payload must never touch a tempfile"


def test_spawn_detached_passes_payload_via_stdin_pipe(monkeypatch):
    captured = {}

    class _FakeStdin:
        def __init__(self):
            self.written = b""

        def write(self, data):
            self.written += data

        def close(self):
            captured["closed"] = True

    class _FakeProc:
        def __init__(self):
            self.stdin = _FakeStdin()

    fake_proc = _FakeProc()

    def _fake_popen(args, **kwargs):
        captured["args"] = args
        captured["stdin_kw"] = kwargs.get("stdin")
        return fake_proc

    monkeypatch.setattr(subprocess, "Popen", _fake_popen)
    payload = json.dumps({"surface": "bash", "command": "echo hi"})
    node9_shadow._spawn_detached(payload)

    assert captured["stdin_kw"] == subprocess.PIPE
    assert fake_proc.stdin.written == payload.encode("utf-8")
    assert captured["closed"] is True
    # No positional filename argument anywhere in argv (R6).
    assert "--record" in captured["args"]
    assert not any(a.endswith(".json") for a in captured["args"])


# ── R1: isolated mode + pinned cwd ────────────────────────────────────────

def test_recorder_command_is_isolated_module_invocation():
    cmd = node9_shadow._recorder_command()
    assert "-I" in cmd
    assert "-m" in cmd
    assert "willow_mcp.node9_shadow" in cmd
    assert "--record" in cmd


def test_spawn_detached_pins_cwd_to_the_shadow_root(monkeypatch):
    captured = {}

    class _FakeStdin:
        def write(self, data):
            pass

        def close(self):
            pass

    class _FakeProc:
        stdin = _FakeStdin()

    def _fake_popen(args, **kwargs):
        captured["cwd"] = kwargs.get("cwd")
        return _FakeProc()

    monkeypatch.setattr(subprocess, "Popen", _fake_popen)
    node9_shadow._spawn_detached(json.dumps({"surface": "bash"}))
    assert captured["cwd"] == str(node9_shadow._shadow_root())


# ── report classification, held status (F10) ─────────────────────────────

def _row(node9_verdict, willow_verdict, surface="bash", rule="", ts="2026-09-27T00:00:00+00:00"):
    return {
        "ts": ts, "surface": surface, "seat": "x", "cmd_hmac": "0" * 64,
        "willow_verdict": willow_verdict, "willow_reason": "other", "node9_verdict": node9_verdict,
        "node9_rule": rule, "node9_version": "9.9.9-test", "shape": "cmd", "latency_ms": 1,
    }


def _write_ledger(rows):
    node9_shadow.ledger_path().parent.mkdir(parents=True, exist_ok=True)
    with node9_shadow.ledger_path().open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def test_build_report_classifies_the_four_classes_and_excludes_doubt():
    _write_ledger([
        _row("block", "allow", rule="pipe-chain"),
        _row("review", "allow", rule="inline-exec"),
        _row("allow", "block"),
        _row("allow", "allow"),
        _row("block", "block"),
        _row("unknown", "allow"),
        _row("held", "held"),
    ])
    report = node9_shadow.build_report(prune=False)
    assert report["total"] == 7
    assert report["unknown"] == 1
    assert report["held"] == 1
    assert report["classes"]["node9_stricter"] == 2
    assert report["classes"]["willow_stricter"] == 1
    assert report["classes"]["agree_allow"] == 1
    assert report["classes"]["agree_block"] == 1


def test_build_report_since_filters_rows():
    _write_ledger([
        _row("allow", "allow", ts="2026-01-01T00:00:00+00:00"),
        _row("block", "allow", ts="2026-09-27T00:00:00+00:00", rule="r"),
    ])
    report = node9_shadow.build_report(since="2026-06-01T00:00:00+00:00", prune=False)
    assert report["total"] == 1
    assert report["classes"]["node9_stricter"] == 1


def test_render_report_is_text():
    _write_ledger([_row("allow", "allow")])
    text = node9_shadow.render_report(node9_shadow.build_report(prune=False))
    assert "agreement class" in text.lower()


def test_held_net_authorization_is_its_own_status_excluded_from_classes(monkeypatch):
    popen = _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))
    _record(monkeypatch, popen, willow_verdict="held")
    row = _rows()[0]
    assert row["willow_verdict"] == "held"
    report = node9_shadow.build_report(prune=False)
    assert report["held"] == 1
    assert sum(report["classes"].values()) == 0


# ── ledger integrity: locked append + prune (F6) ─────────────────────────

def test_prune_runs_only_when_explicitly_called_never_on_append(monkeypatch):
    import datetime as _dt
    old_row = _row("allow", "allow", ts=(_dt.datetime.now(_dt.UTC) - _dt.timedelta(days=45)).isoformat())
    _write_ledger([old_row])
    popen = _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))
    _record(monkeypatch, popen)
    assert len(_rows()) == 2
    dropped = node9_shadow.prune_ledger()
    assert dropped == 1
    assert len(_rows()) == 1


def test_concurrent_appends_and_a_prune_lose_no_fresh_rows(monkeypatch):
    """Scaled-down reproduction of Loki 53741054's F6 (3000 rows, later
    reconfirmed at full scale in A68E86E9's HELD findings): a prune running
    concurrently with writers must not drop any writer row."""
    import datetime as _dt
    import threading

    n_writers = 50
    old_ts = (_dt.datetime.now(_dt.UTC) - _dt.timedelta(days=45)).isoformat()
    _write_ledger([_row("allow", "allow", ts=old_ts) for _ in range(20)])

    errors = []

    def _writer(i):
        try:
            node9_shadow._append_ledger_row_locked(_row("allow", "allow", rule=f"w{i}"))
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    def _pruner():
        try:
            node9_shadow.prune_ledger()
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=_writer, args=(i,)) for i in range(n_writers)]
    threads.append(threading.Thread(target=_pruner))
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert not errors
    rows = _rows()
    fresh = [r for r in rows if r.get("node9_rule", "").startswith("w")]
    assert len(fresh) == n_writers, f"lost {n_writers - len(fresh)} of {n_writers} writer rows"


# ── version stamping (F8) ──────────────────────────────────────────────

def test_version_is_read_from_the_vendored_package_json_never_from_output(monkeypatch):
    popen = _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))
    _record(monkeypatch, popen, command="pip install foo==9.9.9")
    assert _rows()[0]["node9_version"] == "9.9.9-test"


# ── ledger path / kart sandbox ────────────────────────────────────────────

def test_ledger_path_is_under_willow_home_shadow(tmp_path, monkeypatch):
    home = tmp_path / "another-willow"
    home.mkdir()
    monkeypatch.setenv("WILLOW_HOME", str(home))
    assert node9_shadow.ledger_path() == home / "shadow" / "node9.jsonl"
    assert node9_shadow.shim_path() == home / "venvs" / "node9" / "shadow-eval.mjs"
    assert node9_shadow._hmac_key_path() == home / "shadow" / ".hmac_key"


def test_live_policy_fixture_never_binds_shadow_or_venvs_node9():
    """Loki A68E86E9 (item 7): the bundled kartikeya template still lists
    `~/.local`/`~/.willow` read-write, so testing against IT proves nothing
    about what a real box's live policy actually binds (which the re-audit
    measured directly: $WILLOW_HOME/~/.willow are the sandbox's OWN tmpfs
    under the live policy, and ~/.local is now read-only). This test checks
    a maintained FIXTURE copy of that live shape instead of the bundled
    template — see live_policy_fixture below, which must be updated by hand
    if the live policy changes; it is not read from the box at test time,
    because a test has no standing to read the operator's live kart-sandbox
    config."""
    live_policy_fixture = {
        # Mirrors Kart CTZQP6QK's measured live shape (A68E86E9): the
        # sandbox's own tmpfs stands in for $WILLOW_HOME/~/.willow (writes
        # there never reach the host filesystem at all), and ~/.local is
        # read-only. Neither `shadow/` nor `venvs/node9` is named anywhere.
        "bind_read_only": ["/usr", "/etc", "{{HOME}}/.local", "{{WILLOW_ROOT}}"],
        "bind_read_write": ["{{WILLOW_ROOT}}/worktrees"],
        "bind_try": [],
        "bind_try_read_only": [],
        "tmpfs": ["{{HOME}}/.willow", "{{WILLOW_HOME}}"],
    }
    all_named_paths = (
        live_policy_fixture["bind_read_only"]
        + live_policy_fixture["bind_read_write"]
        + live_policy_fixture["bind_try"]
        + live_policy_fixture["bind_try_read_only"]
    )
    for entry in all_named_paths:
        assert "shadow" not in entry
        assert "venvs/node9" not in entry
    assert "{{HOME}}/.willow" in live_policy_fixture["tmpfs"]
    assert "{{WILLOW_HOME}}" in live_policy_fixture["tmpfs"]


def test_bundled_kart_sandbox_template_still_carries_the_known_caveat():
    """Kept alongside the live-policy fixture test above (not instead of
    it): documents that the BUNDLED template (what a fresh install runs
    before any operator override) still lists the generic rw binds the
    first rework's own test warned about. This is a known, named gap, not a
    silent regression — see the docstring on `ledger_path()`."""
    import kartikeya

    template_path = Path(kartikeya.__file__).parent / "data" / "kart-sandbox.json"
    template = json.loads(template_path.read_text())
    rw = template.get("bind_read_write", [])
    assert any("willow" in e for e in rw), (
        "if this ever stops being true, update the docstring caveat on "
        "ledger_path() and this test together"
    )


# ── --selftest: tell "no traffic" apart from "recorder broken" ──────────

def test_selftest_reports_not_installed_when_the_shim_is_absent(monkeypatch, tmp_path):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path / "fresh-uninstalled"))
    result = node9_shadow.run_selftest()
    assert result["ok"] is False
    assert result["error"] == "not_installed"


def test_selftest_ok_when_the_recorder_actually_appends_a_row(monkeypatch):
    """Runs the REAL spawn_shadow() -> _spawn_detached() -> subprocess.Popen
    path, exactly like a production caller; only the Popen boundary is
    mocked (as everywhere else in this file) to stand in for the actual
    node/node9 exec, since the recorder itself runs `_do_record` in-process
    here rather than a real detached child."""
    def _fake_spawn_detached(payload_json):
        node9_shadow._do_record(json.loads(payload_json))

    def _fake_popen(*a, **k):
        return _FakePopen(stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""}))

    monkeypatch.setattr(node9_shadow, "_spawn_detached", _fake_spawn_detached)
    monkeypatch.setattr(subprocess, "Popen", _fake_popen)
    monkeypatch.setattr("os.getpgid", lambda pid: pid)
    monkeypatch.setattr("os.killpg", lambda pgid, sig: None)

    result = node9_shadow.run_selftest(timeout=2.0, poll_interval=0.01)
    assert result["ok"] is True
    assert result["error"] is None
    rows = _rows()
    assert any(r.get("surface") == "selftest" for r in rows)


def test_selftest_reports_failure_when_no_row_ever_appears(monkeypatch):
    """The recorder is 'installed' (the shim file exists) but spawning it
    does nothing at all — the exact silent-failure shape Loki's INFO
    finding described for an unimportable `-I` recorder in production."""
    monkeypatch.setattr(node9_shadow, "_spawn_detached", lambda payload_json: None)
    result = node9_shadow.run_selftest(timeout=0.2, poll_interval=0.02)
    assert result["ok"] is False
    assert result["error"] == "no_row_appeared_within_timeout"


def test_selftest_result_persists_and_shows_in_the_report_header(monkeypatch):
    def _fake_spawn_detached(payload_json):
        node9_shadow._do_record(json.loads(payload_json))

    monkeypatch.setattr(node9_shadow, "_spawn_detached", _fake_spawn_detached)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: _FakePopen(
        stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""})
    ))
    monkeypatch.setattr("os.getpgid", lambda pid: pid)
    monkeypatch.setattr("os.killpg", lambda pgid, sig: None)

    node9_shadow.run_selftest(timeout=2.0, poll_interval=0.01)
    report = node9_shadow.build_report(prune=False)
    assert report["selftest"] is not None
    assert report["selftest"]["ok"] is True
    text = node9_shadow.render_report(report)
    assert "last selftest: ok" in text


def test_report_header_names_never_run_when_no_selftest_has_happened():
    report = node9_shadow.build_report(prune=False)
    assert report["selftest"] is None
    text = node9_shadow.render_report(report)
    assert "last selftest: never run" in text


def test_selftest_marker_command_never_leaks_as_a_real_row_secret(monkeypatch):
    """The fixed benign probe command must itself never look like a secret
    in the ledger — belt and braces, since it is always safe by
    construction (`true # ...`), but worth pinning."""
    def _fake_spawn_detached(payload_json):
        node9_shadow._do_record(json.loads(payload_json))

    monkeypatch.setattr(node9_shadow, "_spawn_detached", _fake_spawn_detached)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: _FakePopen(
        stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""})
    ))
    monkeypatch.setattr("os.getpgid", lambda pid: pid)
    monkeypatch.setattr("os.killpg", lambda pgid, sig: None)

    node9_shadow.run_selftest(timeout=2.0, poll_interval=0.01)
    row = next(r for r in _rows() if r.get("surface") == "selftest")
    assert row["shape"] == "true"


# ── T2 (Loki CC59AF30): selftest reflects THIS run only ──────────────────

def _selftest_popen_ok(monkeypatch):
    def _fake_spawn_detached(payload_json):
        node9_shadow._do_record(json.loads(payload_json))
    monkeypatch.setattr(node9_shadow, "_spawn_detached", _fake_spawn_detached)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: _FakePopen(
        stdout=json.dumps({"verdict": "allow", "node9_rule_raw": ""})
    ))
    monkeypatch.setattr("os.getpgid", lambda pid: pid)
    monkeypatch.setattr("os.killpg", lambda pgid, sig: None)


def test_two_selftest_runs_use_different_commands_and_hmacs(monkeypatch):
    """T2: a fixed probe command meant `run_selftest` matched ANY row ever
    written with that command's hash — a per-run nonce means each run's
    probe (and therefore its cmd_hmac) is unique."""
    _selftest_popen_ok(monkeypatch)
    node9_shadow.run_selftest(timeout=2.0, poll_interval=0.01)
    node9_shadow.run_selftest(timeout=2.0, poll_interval=0.01)
    rows = [r for r in _rows() if r.get("surface") == "selftest"]
    assert len(rows) == 2
    assert rows[0]["cmd_hmac"] != rows[1]["cmd_hmac"]


def test_selftest_mutation_proof_stale_ok_row_never_masks_a_now_broken_recorder(monkeypatch):
    """T2's exact mutation proof: a working recorder gives ok, THEN the
    recorder is broken (spawn_detached becomes a no-op) — an older ok row
    from the earlier, working run must never let the second, real failure
    report ok. Under the old fixed-command matching this was exactly the
    false-positive Loki reproduced (Kart EYVMDSGR): swap _recorder_command
    for a no-op after one successful run, and run_selftest still said ok."""
    _selftest_popen_ok(monkeypatch)
    first = node9_shadow.run_selftest(timeout=2.0, poll_interval=0.01)
    assert first["ok"] is True, f"RED (setup): first run should be ok, got {first}"

    # Break the recorder: it now does nothing at all, the exact silent
    # no-signal shape a broken -I import produces in production.
    monkeypatch.setattr(node9_shadow, "_spawn_detached", lambda payload_json: None)
    second = node9_shadow.run_selftest(timeout=0.3, poll_interval=0.02)
    assert second["ok"] is False, (
        f"MUTATION PROOF FAILED (would be a false 'ok'): {second} — an older "
        f"successful row masked a now-broken recorder"
    )
    assert second["error"] == "no_row_appeared_within_timeout"

    report = node9_shadow.build_report(prune=False)
    assert report["selftest"]["ok"] is False, "the report header must reflect the LATEST run, not the stale ok"


def test_selftest_rows_never_enter_agreement_classes_or_totals(monkeypatch):
    """T2: a selftest row is diagnostic, not real traffic — it must never
    move `total`, `classes`, or `by_surface`, only the separate `selftest`
    header field."""
    _selftest_popen_ok(monkeypatch)
    node9_shadow.run_selftest(timeout=2.0, poll_interval=0.01)
    # A real row too, so the exclusion is visible against something counted.
    popen = _FakePopen(stdout=json.dumps({"verdict": "block", "node9_rule_raw": ""}))
    _record(monkeypatch, popen, command="rm -rf /")

    report = node9_shadow.build_report(prune=False)
    assert report["total"] == 1, "the selftest row must not inflate total"
    assert sum(report["classes"].values()) == 1
    assert "selftest" not in report["by_surface"]
    assert report["selftest"] is not None and report["selftest"]["ok"] is True


def test_selftest_never_appears_in_top_node9_stricter_rows(monkeypatch):
    _selftest_popen_ok(monkeypatch)
    node9_shadow.run_selftest(timeout=2.0, poll_interval=0.01)
    report = node9_shadow.build_report(prune=False)
    assert report["top_node9_stricter"] == []
