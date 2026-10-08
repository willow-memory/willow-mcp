"""Broker onescript_run_execute — the one script's host steps, no shell.

Every test runs against stub executables in a throwaway WILLOW_HOME: no real
Ollama, no real keyring, no real willow-bot checkout. The stubs record the argv,
the working directory and the environment they were started with, so the tests
assert what the child actually received, not what the code meant to send.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from willow_mcp import gate
from willow_mcp import onescript_executor as ox
from willow_mcp import server

SUBJECT = "serve:" + "ab12" * 16
PROPOSAL = "proposal:" + "cd34" * 16
FAKE_SECRET = "FAKE-SIGNING-MATERIAL-not-a-real-key"
FAKE_HEX = "9f" * 32  # 64 hex chars: shaped like a key, is nothing

STUB = r"""#!/bin/sh
d="$(dirname "$0")"
n=$(ls "$d" | grep -c '^call\.[0-9]*\.argv$')
printf '%s\0' "$@" > "$d/call.$n.argv"
env > "$d/call.$n.env"
pwd > "$d/call.$n.cwd"
prev=""; out=""
for a in "$@"; do [ "$prev" = "--out" ] && out="$a"; prev="$a"; done
[ -n "$out" ] && [ -f "$d/append" ] && cat "$d/append" >> "$out"
[ -f "$d/grandchild" ] && setsid sleep 60 &
[ -f "$d/sleep" ] && sleep 30
[ -f "$d/stdout" ] && cat "$d/stdout"
[ -f "$d/rc" ] && exit "$(cat "$d/rc")"
exit 0
"""


class _Ledger:
    def __init__(self):
        self.rows = []

    def append(self, project, event_type, content):
        rid = f"rec-{len(self.rows) + 1}"
        self.rows.append({"id": rid, "project": project, "event_type": event_type,
                          "content": content})
        return rid


def _stub(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(STUB, encoding="utf-8")
    path.chmod(0o755)
    return path


class Box:
    """A throwaway home + willow-bot checkout wired to stub executables."""

    def __init__(self, tmp_path: Path):
        self.home = tmp_path / "home"
        self.bot = tmp_path / "willow-bot"
        self.py = _stub(self.home / "venvs" / "willow-bot" / "bin" / "python")
        self.rat = _stub(self.home / "venvs" / "willow-mcp" / "bin" / "ratatosk")
        (self.home / "verifiers.json").write_text(
            json.dumps({"verifiers": [], "note": FAKE_SECRET}), encoding="utf-8")
        (self.bot / "one-script" / "onescript").mkdir(parents=True)
        (self.bot / "one-script" / "onescript" / "__main__.py").write_text("", encoding="utf-8")
        self.box = self.bot / ".flow" / "onescript"
        self.box.mkdir(parents=True)
        self.ledger = _Ledger()

    def set(self, which: Path, *, stdout: str = "", rc: int | None = None, sleep: bool = False,
            append: str | None = None, grandchild: bool = False):
        d = which.parent
        (d / "stdout").write_text(stdout, encoding="utf-8")
        if append is not None:
            (d / "append").write_text(append, encoding="utf-8")
        if grandchild:
            (d / "grandchild").write_text("", encoding="utf-8")
        if rc is not None:
            (d / "rc").write_text(str(rc), encoding="utf-8")
        if sleep:
            (d / "sleep").write_text("", encoding="utf-8")

    def calls(self, which: Path) -> list[dict]:
        out = []
        for argv in sorted(which.parent.glob("call.*.argv"), key=lambda p: int(p.name.split(".")[1])):
            stem = argv.name[: -len(".argv")]
            raw = argv.read_bytes().decode()
            out.append({
                "argv": raw.split("\0")[:-1] if raw else [],
                "env": dict(ln.split("=", 1) for ln in
                            (which.parent / f"{stem}.env").read_text().splitlines() if "=" in ln),
                "cwd": (which.parent / f"{stem}.cwd").read_text().strip(),
            })
        return out

    def run(self, step, args=None, **kw):
        kw.setdefault("bot_checkout", self.bot)
        kw.setdefault("model_lister", lambda: ["qwen3:4b", "llama3.2:latest"])
        return ox.execute_step("hanuman", step, args, project="t", session="s",
                               ledger=self.ledger, **kw)


@pytest.fixture
def box(tmp_path, monkeypatch):
    b = Box(tmp_path)
    monkeypatch.setenv("WILLOW_HOME", str(b.home))
    monkeypatch.setenv("NESTOR_DB", str(tmp_path / "nestor.db"))
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    return b


def _py_argv(*rest):
    return ["-m", "onescript", *rest]


# ── each step's argv, exactly ────────────────────────────────────────────────

def test_keys_export_argv(box):
    box.set(box.py, stdout="exported 1 public key(s) to x\n  kept     sean campbell\n")
    out = box.run("keys_export")
    assert out["state"] == "populated" and out["ok"]
    [call] = box.calls(box.py)
    assert call["argv"] == _py_argv(
        "keys", "export", "--from", str(box.home / "verifiers.json"),
        "--to", str(box.home / "config" / "verifiers.public.json"))
    assert call["cwd"] == str((box.bot / "one-script").resolve())


@pytest.mark.parametrize("step", ["checkin", "checkout"])
def test_no_arg_steps_argv(box, step):
    box.set(box.py, stdout="ok\n")
    assert box.run(step)["state"] == "populated"
    assert box.calls(box.py)[0]["argv"] == _py_argv(step)


def test_scope_argv(box):
    box.set(box.py, stdout='{"subject": "x"}')
    out = box.run("scope", {"by": ["who", "what"], "match": {"who": "desk"}, "upto": 12})
    assert out["state"] == "populated" and out["stdout_json"] == {"subject": "x"}
    assert box.calls(box.py)[0]["argv"] == _py_argv(
        "scope", "--by", "who,what", "--match", "who=desk", "--upto", "12")


def test_scope_defaults_by_who(box):
    box.set(box.py, stdout="{}")
    box.run("scope")
    assert box.calls(box.py)[0]["argv"] == _py_argv("scope", "--by", "who")


@pytest.mark.parametrize("subject", [SUBJECT, PROPOSAL])
def test_seal_argv_and_pair_id_not_passed(box, subject):
    box.set(box.py, stdout="{}")
    _nestor(box, [("3613d55e-aaaa", subject)])
    out = box.run("seal", {"subject": subject, "pair_id": "3613d55e"})
    assert out["pair_id"] == "3613d55e-aaaa" and "pair_id_mismatch" not in out
    assert box.calls(box.py)[0]["argv"] == _py_argv("seal", subject)


def _nestor(box, rows):
    """A throwaway Nestor store: (id, target_text) rows, all live and sealed."""
    import sqlite3

    con = sqlite3.connect(os.environ["NESTOR_DB"])
    con.execute("CREATE TABLE IF NOT EXISTS tm_pairs (id TEXT, target_text TEXT, "
                "status TEXT, superseded_by TEXT)")
    con.executemany("INSERT INTO tm_pairs VALUES (?, ?, 'sealed', '')", rows)
    con.commit()
    con.close()


def test_seal_records_the_pair_that_actually_sealed_not_the_callers(box):
    box.set(box.py, stdout="{}")
    _nestor(box, [("realpair-1", SUBJECT)])
    out = box.run("seal", {"subject": SUBJECT, "pair_id": "feedbeef"})
    assert out["pair_id"] == "realpair-1" and out["pair_id_mismatch"] is True
    assert out["caller_pair_id"] == "feedbeef" and out["sealed_pair_ids"] == ["realpair-1"]
    assert box.ledger.rows[-1]["content"]["pair_id"] == "realpair-1"


def test_seal_with_no_live_pair_says_so_and_does_not_echo_the_caller(box):
    box.set(box.py, stdout="{}")
    _nestor(box, [("other", PROPOSAL)])
    out = box.run("seal", {"subject": SUBJECT, "pair_id": "feedbeef"})
    assert "pair_id" not in out and out["sealed_pair_ids"] == []
    assert out["pair_id_mismatch"] is True and "no live sealed pair" in out["pair_check"]


def test_seal_with_an_unreadable_store_is_reported_not_guessed(box):
    box.set(box.py, stdout="{}")
    out = box.run("seal", {"subject": SUBJECT, "pair_id": "feedbeef"})
    assert "pair_id" not in out and out["pair_check"].startswith("unreachable")


def test_serve_argv(box):
    box.set(box.py, stdout="{}")
    box.run("serve", {"by": ["who"], "match": {"what": "turn"}, "upto": 9, "max_chars": 4000})
    assert box.calls(box.py)[0]["argv"] == _py_argv(
        "serve", "--by", "who", "--match", "what=turn", "--upto", "9", "--max-chars", "4000")


def test_rat_turn_argv(box):
    box.set(box.rat, stdout="[onescript] done\n")
    out = box.run("rat_turn", {"model": "qwen3:4b", "task": "summarise the stack"})
    assert out["state"] == "populated"
    [call] = box.calls(box.rat)
    assert call["argv"] == [
        "--onescript", "--served", str(box.box / "served.json"),
        "--out", str(box.box / "proposals.jsonl"), "--model", "qwen3:4b",
        "summarise the stack"]


def test_turn_argv_with_proposals(box):
    box.set(box.py, stdout="{}")
    (box.box / "proposals.jsonl").write_text("", encoding="utf-8")
    box.run("turn", {"bite": "the bite"})
    assert box.calls(box.py)[0]["argv"] == _py_argv(
        "turn", "the bite", "--proposal", str(box.box / "proposals.jsonl"))


def test_turn_without_proposals_file_is_unreachable_not_a_crash(box):
    out = box.run("turn", {"bite": "b"})
    assert out["state"] == "unreachable" and "proposals" in out["reason"]
    assert box.calls(box.py) == []


def test_turn_can_skip_proposals(box):
    box.set(box.py, stdout="{}")
    box.run("turn", {"bite": "b", "proposals": False})
    assert box.calls(box.py)[0]["argv"] == _py_argv("turn", "b")


# ── the caller cannot reach argv, paths or env ───────────────────────────────

@pytest.mark.parametrize("step,args", [
    ("checkin", {"argv": ["--no-tests"]}),
    ("checkout", {"cwd": "/tmp"}),
    ("keys_export", {"from": "/etc/passwd", "to": "/tmp/x"}),
    ("keys_export", {"src": "/etc/passwd"}),
    ("scope", {"box": "/tmp/box"}),
    ("scope", {"keyring": "/tmp/k"}),
    ("seal", {"subject": SUBJECT, "keyring": "/tmp/k"}),
    ("seal", {"subject": SUBJECT, "pair": "/tmp/pair.json"}),
    ("serve", {"upto": 1, "max_chars": 10, "out": "/tmp/served.json"}),
    ("rat_turn", {"model": "qwen3:4b", "task": "t", "served": "/etc/shadow"}),
    ("rat_turn", {"model": "qwen3:4b", "task": "t", "out": "/tmp/o"}),
    ("rat_turn", {"model": "qwen3:4b", "task": "t", "env": {"X": "1"}}),
    ("turn", {"bite": "b", "proposal": "/etc/passwd"}),
])
def test_unknown_or_path_arguments_are_refused(box, step, args):
    out = box.run(step, args)
    assert out["ok"] is False and out["ran"] is False and out["error"] == "EINVAL"
    assert box.calls(box.py) == [] and box.calls(box.rat) == []


@pytest.mark.parametrize("step,args", [
    ("seal", {"subject": "serve:abc; rm -rf /"}),
    ("seal", {"subject": "--proof=x"}),
    ("seal", {"subject": SUBJECT + " --verifier x"}),
    ("seal", {"subject": "other:" + "ab" * 32}),
    ("seal", {"subject": SUBJECT, "pair_id": "x; id"}),
    ("scope", {"by": ["who", "--upto"]}),
    ("scope", {"by": "nope"}),
    ("scope", {"match": {"--phone": "x"}}),
    ("scope", {"match": {"who": ""}}),
    ("scope", {"upto": "5; ls"}),
    ("serve", {"upto": 1}),
    ("serve", {"max_chars": 10}),
    ("serve", {"upto": 1, "max_chars": 10**9}),
    ("serve", {"upto": 1, "max_chars": True}),
    ("turn", {"bite": "-v"}),
    ("turn", {"bite": ""}),
    ("turn", {"bite": "a\x00b"}),
    ("turn", {"bite": "x" * 2001}),
    ("rat_turn", {"model": "qwen3:4b", "task": "--model other"}),
    ("rat_turn", {"model": "qwen3:4b", "task": "x" * 2001}),
    ("rat_turn", {"model": "qwen3:4b"}),
])
def test_bad_values_are_refused_before_anything_runs(box, step, args):
    out = box.run(step, args)
    assert out["ok"] is False and out["ran"] is False and out["error"] == "EINVAL"
    assert box.calls(box.py) == [] and box.calls(box.rat) == []


def test_unknown_step_and_non_object_args(box):
    assert box.run("bash", {})["error"] == "EINVAL"
    assert box.run("checkin", ["--x"])["error"] == "EINVAL"
    assert box.run("", None)["error"] == "EINVAL"


def test_child_env_is_the_allowlist_only(box, monkeypatch):
    for k, v in {
        "OPENAI_API_KEY": "sk-canary", "ANTHROPIC_API_KEY": "sk-canary",
        "GROQ_API_KEY": "canary", "HTTPS_PROXY": "http://proxy:3128",
        "http_proxy": "http://proxy:3128", "ALL_PROXY": "socks5://p",
        "WILLOW_KEYRING": "/secret/signing.json", "WILLOW_PGP_FINGERPRINT": "canary",
        "PYTHONPATH": "/evil", "LD_PRELOAD": "/evil.so", "GIT_SSH_COMMAND": "evil",
        "ONESCRIPT_GROVE": str(box.bot.parent / "grove"),
    }.items():
        monkeypatch.setenv(k, v)
    box.set(box.py, stdout="ok\n")
    box.run("checkin")
    env = box.calls(box.py)[0]["env"]
    names = set(env) - {"PWD", "SHLVL", "_", "OLDPWD"}
    assert names <= set(ox.ENV_ALLOW), f"leaked: {sorted(names - set(ox.ENV_ALLOW))}"
    assert env["WILLOW_HOME"] == str(box.home)
    assert env["ONESCRIPT_GROVE"] == str(box.bot.parent / "grove")
    assert "NESTOR_DB" in env and "PATH" in env and "HOME" in env
    assert not any("canary" in v or "proxy" in v for v in env.values())


def test_non_loopback_ollama_host_is_not_passed_and_blocks_rat(box, monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://203.0.113.9:11434")
    box.set(box.py, stdout="ok\n")
    box.run("checkin")
    assert "OLLAMA_HOST" not in box.calls(box.py)[0]["env"]
    out = box.run("rat_turn", {"model": "qwen3:4b", "task": "t"})
    assert out["state"] == "unreachable" and "loopback" in out["reason"]
    assert box.calls(box.rat) == []


def test_loopback_ollama_host_is_passed(box, monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "127.0.0.1:11500")
    box.set(box.rat, stdout="done\n")
    box.run("rat_turn", {"model": "qwen3:4b", "task": "t"})
    assert box.calls(box.rat)[0]["env"]["OLLAMA_HOST"] == "127.0.0.1:11500"


# ── rat_turn: the model and the task ─────────────────────────────────────────

@pytest.mark.parametrize("model", [
    "qwen3:4b; id", "../etc/passwd x", "-m", "has space", "", "a" * 200, None, 7,
])
def test_bad_model_tag_is_refused(box, model):
    out = box.run("rat_turn", {"model": model, "task": "t"})
    assert out["ok"] is False and out["error"] == "EINVAL" and out["ran"] is False
    assert box.calls(box.rat) == []


@pytest.mark.parametrize("model", ["gpt-oss:120b-cloud", "kimi:cloud"])
def test_cloud_model_is_refused(box, model):
    out = box.run("rat_turn", {"model": model, "task": "t"},
                  model_lister=lambda: [model])
    assert out["error"] == "EINVAL" and box.calls(box.rat) == []


def test_model_not_installed_is_refused(box):
    out = box.run("rat_turn", {"model": "mistral:7b", "task": "t"})
    assert out["error"] == "EMODEL" and out["ran"] is False
    assert box.calls(box.rat) == []


def test_bare_model_name_matches_latest(box):
    box.set(box.rat, stdout="done\n")
    assert box.run("rat_turn", {"model": "llama3.2", "task": "t"})["state"] == "populated"


def test_ollama_silent_is_unreachable(box):
    out = box.run("rat_turn", {"model": "qwen3:4b", "task": "t"}, model_lister=lambda: None)
    assert out["state"] == "unreachable" and "Ollama" in out["reason"]
    assert box.calls(box.rat) == []


def test_ratatosk_not_installed_is_unreachable_with_reason(box):
    box.rat.unlink()
    out = box.run("rat_turn", {"model": "qwen3:4b", "task": "t"})
    assert out["state"] == "unreachable" and out["exit"] is None
    assert "not installed" in out["reason"]


def test_rat_turn_needs_the_box(box):
    box.box.rmdir()
    out = box.run("rat_turn", {"model": "qwen3:4b", "task": "t"})
    assert out["state"] == "unreachable" and "checkin" in out["reason"]


# ── three states, timeouts, prerequisites ────────────────────────────────────

def test_three_states_are_distinct(box):
    box.set(box.py, stdout='{"a": 1}')
    populated = box.run("scope")
    box.set(box.py, stdout="")
    empty = box.run("scope")
    box.set(box.py, stdout="refused: nothing is open\n", rc=1)
    unreachable = box.run("scope")
    assert (populated["state"], empty["state"], unreachable["state"]) == (
        "populated", "empty", "unreachable")
    assert populated["exit"] == 0 and empty["exit"] == 0 and unreachable["exit"] == 1
    assert populated["ok"] and empty["ok"] and not unreachable["ok"]
    assert unreachable["reason"] == "refused: nothing is open"
    assert populated["stdout_json"] == {"a": 1}


def test_non_json_output_comes_back_as_a_tail(box):
    box.set(box.py, stdout="\n".join(f"line {i}" for i in range(50)))
    out = box.run("checkin")
    assert "stdout_json" not in out
    assert out["tail"].splitlines()[-1] == "line 49" and len(out["tail"].splitlines()) == 20


def test_timeout_is_recorded_and_the_child_killed(box, monkeypatch):
    monkeypatch.setitem(ox.TIMEOUTS, "checkout", 1)
    box.set(box.py, sleep=True)
    out = box.run("checkout")
    assert out["state"] == "unreachable" and out["timed_out"] is True and out["exit"] is None
    assert "timed out after 1s" in out["reason"]
    assert out["duration_s"] < 10
    assert box.ledger.rows[-1]["content"]["timed_out"] is True


def test_every_step_has_a_bounded_timeout():
    assert set(ox.TIMEOUTS) == set(ox.STEPS)
    assert ox.TIMEOUTS["rat_turn"] == 900
    assert all(0 < t <= 300 for s, t in ox.TIMEOUTS.items() if s != "rat_turn")


def test_missing_bot_interpreter_is_unreachable(box):
    box.py.unlink()
    out = box.run("checkin")
    assert out["state"] == "unreachable" and "interpreter" in out["reason"]


def test_symlinked_checkout_is_refused(box, tmp_path):
    link = tmp_path / "link-to-bot"
    link.symlink_to(box.bot, target_is_directory=True)
    out = box.run("checkin", bot_checkout=link)
    assert out["state"] == "unreachable" and "symlink" in out["reason"]
    assert box.calls(box.py) == []


def test_symlinked_box_is_refused(box, tmp_path):
    real = tmp_path / "elsewhere"
    real.mkdir()
    box.box.rmdir()
    box.box.symlink_to(real, target_is_directory=True)
    out = box.run("rat_turn", {"model": "qwen3:4b", "task": "t"})
    assert out["state"] == "unreachable" and "symlink" in out["reason"]
    assert box.calls(box.rat) == []


def test_symlinked_onescript_package_is_refused(box, tmp_path):
    pkg = box.bot / "one-script" / "onescript"
    real = tmp_path / "elsewhere-pkg"
    pkg.rename(real)
    pkg.symlink_to(real, target_is_directory=True)
    out = box.run("checkin")
    assert out["state"] == "unreachable" and "one-script" in out["reason"]
    assert box.calls(box.py) == []


@pytest.mark.parametrize("which", ["dir", "file"])
def test_symlinked_keys_export_target_is_refused(box, tmp_path, which):
    cfg = box.home / "config"
    target = cfg / "verifiers.public.json"
    if which == "dir":
        real = tmp_path / "elsewhere-cfg"
        real.mkdir()
        cfg.symlink_to(real, target_is_directory=True)
    else:
        cfg.mkdir()
        elsewhere = tmp_path / "victim.json"
        elsewhere.write_text("x", encoding="utf-8")
        target.symlink_to(elsewhere)
    out = box.run("keys_export")
    assert out["state"] == "unreachable" and "symlink" in out["reason"]
    assert box.calls(box.py) == []


# ── F1/F6: proposals are this run's, or nothing ──────────────────────────────

STALE = '{"stale": "row from an earlier run"}\n'


def test_stale_proposals_never_reach_turn(box):
    proposals = box.box / "proposals.jsonl"
    proposals.write_text(STALE, encoding="utf-8")
    box.set(box.rat, stdout="done\n")  # a ratatosk that appends nothing
    assert box.run("rat_turn", {"model": "qwen3:4b", "task": "t"})["state"] == "populated"
    assert proposals.read_text(encoding="utf-8") == ""
    box.set(box.py, stdout="{}")
    box.run("turn", {"bite": "b"})
    assert box.calls(box.py)[0]["argv"][-1] == str(proposals)
    assert "stale" not in proposals.read_text(encoding="utf-8")


def test_this_runs_rows_survive_and_only_they_do(box):
    proposals = box.box / "proposals.jsonl"
    proposals.write_text(STALE, encoding="utf-8")
    box.set(box.rat, stdout="done\n", append='{"new": 1}\n')
    box.run("rat_turn", {"model": "qwen3:4b", "task": "t"})
    assert proposals.read_text(encoding="utf-8") == '{"new": 1}\n'


def test_symlinked_proposals_path_is_refused_and_not_written_through(box, tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me", encoding="utf-8")
    (box.box / "proposals.jsonl").symlink_to(victim)
    box.set(box.rat, stdout="done\n")
    out = box.run("rat_turn", {"model": "qwen3:4b", "task": "t"})
    assert out["state"] == "unreachable" and "symlink" in out["reason"]
    assert victim.read_text(encoding="utf-8") == "keep me"
    assert box.calls(box.rat) == []


def test_capped_run_stays_unreachable_and_its_partial_rows_are_discarded(box):
    proposals = box.box / "proposals.jsonl"
    box.set(box.rat, stdout="[onescript] capped\n", rc=1, append='{"partial": 1}\n')
    out = box.run("rat_turn", {"model": "qwen3:4b", "task": "t"})
    assert out["state"] == "unreachable" and out["exit"] == 1 and not out["ok"]
    assert out["partial_rows_discarded"] is True and "discarded" in out["reason"]
    assert proposals.read_text(encoding="utf-8") == ""
    box.set(box.py, stdout="{}")
    box.run("turn", {"bite": "b"})
    assert "partial" not in proposals.read_text(encoding="utf-8")


# ── F2: a timeout returns within timeout + the drain bound ───────────────────

def test_grandchild_in_a_new_session_cannot_hold_the_call(box, monkeypatch):
    monkeypatch.setitem(ox.TIMEOUTS, "checkout", 1)
    monkeypatch.setattr(ox, "DRAIN_BOUND", 1.0)
    box.set(box.py, sleep=True, grandchild=True)
    t0 = time.monotonic()
    out = box.run("checkout")
    elapsed = time.monotonic() - t0
    assert out["state"] == "unreachable" and out["timed_out"] is True
    assert elapsed < 1 + 2 * 1.0 + 3, elapsed  # timeout + two bounded waits + slack
    assert elapsed < 30


# ── F4: anchored values ──────────────────────────────────────────────────────

@pytest.mark.parametrize("step,args", [
    ("seal", {"subject": SUBJECT + "\n"}),
    ("seal", {"subject": SUBJECT, "pair_id": "3613d55e\n"}),
    ("rat_turn", {"model": "qwen3:4b\n", "task": "t"}),
])
def test_trailing_newline_values_are_refused(box, step, args):
    out = box.run(step, args)
    assert out["ok"] is False and out["ran"] is False and out["error"] == "EINVAL"
    assert box.calls(box.py) == [] and box.calls(box.rat) == []


# ── keys_export never carries key material ───────────────────────────────────

def test_keys_export_returns_names_and_counts_only(box):
    box.set(box.py, stdout=(
        "exported 2 public key(s) to /h/config/verifiers.public.json\n"
        "  kept     sean campbell\n"
        "  kept     second\n"
        "  dropped  legacy (HMAC: a shared secret, not a public key)\n"
        f"{FAKE_SECRET}\n"
        f"key: {FAKE_HEX}\n"))
    out = box.run("keys_export")
    assert out["stdout_json"]["exported"] == ["sean campbell", "second"]
    assert out["stdout_json"]["exported_count"] == 2
    assert out["stdout_json"]["dropped_hmac_count"] == 1
    blob = json.dumps(out)
    assert FAKE_SECRET not in blob and FAKE_HEX not in blob


def test_keys_export_failure_hides_hex(box):
    box.set(box.py, stdout=f"refused: entry carries {FAKE_HEX}\n", rc=2)
    out = box.run("keys_export")
    assert out["state"] == "unreachable" and FAKE_HEX not in json.dumps(out)


def test_keys_export_without_a_signing_ring_is_unreachable(box):
    (box.home / "verifiers.json").unlink()
    out = box.run("keys_export")
    assert out["state"] == "unreachable" and "signing keyring" in out["reason"]
    assert box.calls(box.py) == []


def test_other_steps_redact_long_hex_in_tails_and_reasons(box):
    box.set(box.py, stdout=f"plain text {FAKE_HEX}\n")
    assert FAKE_HEX not in json.dumps(box.run("checkin"))
    box.set(box.py, stdout=f"refused: {FAKE_HEX}\n", rc=1)
    assert FAKE_HEX not in json.dumps(box.run("checkin"))


# ── ink ──────────────────────────────────────────────────────────────────────

def test_a_receipt_per_run_carries_step_digest_exit_duration(box):
    box.set(box.rat, stdout="done\n")
    task = "a private task text"
    out = box.run("rat_turn", {"model": "qwen3:4b", "task": task})
    [row] = box.ledger.rows
    assert row["event_type"] == ox.EVENT == "onescript_run"
    c = row["content"]
    assert c["step"] == "rat_turn" and c["exit"] == 0 and c["state"] == "populated"
    assert c["args_digest"] == out["args_digest"] and len(c["args_digest"]) == 16
    assert "duration_s" in c and c["actor"] == "hanuman"
    assert task not in json.dumps(row)
    assert out["receipt_id"] == "rec-1"


def test_refused_calls_leave_no_receipt_unreachable_ones_do(box):
    box.run("checkin", {"argv": ["x"]})
    assert box.ledger.rows == []
    box.py.unlink()
    box.run("checkin")
    assert box.ledger.rows[-1]["content"]["state"] == "unreachable"
    assert box.ledger.rows[-1]["content"]["ran"] is False


def test_digest_is_stable_and_argument_sensitive(box):
    box.set(box.py, stdout="{}")
    a = box.run("scope", {"by": ["who"]})["args_digest"]
    b = box.run("scope", {"by": ["who"]})["args_digest"]
    c = box.run("scope", {"by": ["what"]})["args_digest"]
    assert a == b != c


# ── the gate ─────────────────────────────────────────────────────────────────

@pytest.fixture
def apps_root(tmp_path, monkeypatch):
    root = tmp_path / "mcp_apps"
    root.mkdir()
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(root))
    return root


def _manifest(root, app_id, permissions):
    d = root / app_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "manifest.json").write_text(json.dumps({"permissions": permissions}))


def test_tool_is_gated_on_its_own_name():
    assert server._gate_tool_catalogue()["onescript_run_execute"] == "onescript_run_execute"
    groups = gate.PERMISSION_GROUPS
    assert "onescript_run_execute" in groups["orchestrator"]
    holders = {g for g, names in groups.items() if "onescript_run_execute" in names}
    assert holders == {"orchestrator"}, holders  # F7: orchestrator only
    for other in ("full_access", "steward_sweep", "envelope_apply", "fleet_read", "dispatch_write"):
        assert "onescript_run_execute" not in groups[other]


@pytest.mark.parametrize("perms,allowed", [
    (["orchestrator"], True),
    (["full_access"], False),
    (["steward_sweep"], False),
    (["envelope_apply"], False),
    (["fleet_read", "dispatch_write"], False),
    ([], False),
])
def test_seat_without_the_name_is_refused(apps_root, perms, allowed):
    _manifest(apps_root, "seat-x", perms)
    assert gate.permitted("seat-x", "onescript_run_execute") is allowed


def test_the_tool_body_never_runs_for_a_seat_without_the_name(apps_root, monkeypatch):
    _manifest(apps_root, "seat-x", ["steward_sweep"])
    called = []
    monkeypatch.setattr(ox, "execute_step", lambda *a, **k: called.append(a) or {"ok": True})
    out = server.onescript_run_execute(app_id="seat-x", step="checkout")
    assert called == []
    assert out.get("ok") is not True
