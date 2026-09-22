"""The willow-mcp reloader (decision `e961aff8`): a separate principal that
restarts the broker's unit onto a `git_pull` FRANK receipt, and only when a
sealed Nestor decision names that receipt. Sibling of `test_unit_reload.py`
— same fake systemctl/git, plus a real SQLite `tm_pairs` table standing in
for nestor.db so the seal lookup runs the real query. Nothing here touches a
real unit, repo, or Postgres.
"""
from __future__ import annotations

import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from willow_mcp import env_fingerprint as envfp
from willow_mcp import reloader
from willow_mcp import unit_reload_executor as urx


@pytest.fixture(autouse=True)
def _reloader_willow_home(tmp_path, monkeypatch):
    """Every test in this module gets its own throwaway WILLOW_HOME so
    `env_fingerprint.state_path()` (which resolves off WILLOW_HOME) never
    touches the real operator box. A pull-only test that never mentions the
    env trigger at all must not accidentally read a real
    ``~/.willow/serve/env_fingerprint.json`` and have its behavior depend
    on whatever happens to be sitting there."""
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path / "willow_home_default"))


# ── fakes ─────────────────────────────────────────────────────────────────────

class _FakeLedger:
    """The two methods the reloader uses — generic enough for both triggers.

    ``receipt`` is the original single git_pull fixture every pre-existing
    test seeds directly (unchanged shape/behavior). Anything ``append()``ed
    during a test — an ``env_changed`` receipt the env trigger writes, a
    ``unit_reload`` receipt either trigger inks — is queryable by a later
    ``latest_event`` call in the SAME ledger instance, which is what the env
    trigger's own idempotence check (``_open_env_receipt``, looking for an
    unconsumed ``env_changed`` row) and the both-triggers test need.
    """

    def __init__(self, receipt=None):
        self.receipt = receipt
        self.appended = []
        self._rows: dict[str, list[dict]] = {}

    def latest_event(self, event_type, *, match):
        if event_type == "git_pull" and self.receipt is not None:
            if all(self.receipt["content"].get(k) == v for k, v in match.items()):
                return self.receipt
        for row in self._rows.get(event_type, []):
            if all(row["content"].get(k) == v for k, v in match.items()):
                return row
        return None

    def append(self, project, event_type, content):
        self.appended.append((project, event_type, content))
        rid = f"reload-receipt-{len(self.appended)}" if event_type == urx.EVENT \
            else f"{event_type}-receipt-{len(self.appended)}"
        self._rows.setdefault(event_type, []).insert(
            0, {"id": rid, "content": content, "created_at": datetime.now(timezone.utc)})
        return rid


class _FakeSystemctlGit:
    def __init__(self, *, active_enter="Mon 2026-09-15 10:00:00 UTC", head="deadbeef",
                 restart_rc=0, show_rc=0, after_active_enter="Mon 2026-09-17 10:00:00 UTC"):
        self.active_enter = active_enter
        self.after_active_enter = after_active_enter
        self.head = head
        self.restart_rc = restart_rc
        self.show_rc = show_rc
        self.calls: list[list[str]] = []
        self.env_seen: list[dict] = []
        self._restarted = False

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        if argv[0] == "systemctl" and "env" in kw:
            self.env_seen.append(kw["env"])
        if argv[0] == "systemctl":
            if argv[1:3] == ["--user", "show"]:
                active = self.after_active_enter if self._restarted else self.active_enter
                out = (f"ActiveState=active\nActiveEnterTimestamp={active}\n"
                       f"ActiveEnterTimestampMonotonic=1\nMainPID=1\nExecMainStartTimestamp={active}\n")
                return subprocess.CompletedProcess(argv, self.show_rc, out, "bus gone" if self.show_rc else "")
            if argv[1:3] == ["--user", "restart"]:
                self._restarted = True
                return subprocess.CompletedProcess(argv, self.restart_rc, "", "boom" if self.restart_rc else "")
            raise AssertionError(argv)
        if argv[0] == "git" and argv[3:] == ["rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(argv, 0, self.head + "\n", "")
        raise AssertionError(argv)

    @property
    def restarts(self):
        return [c for c in self.calls if c[0] == "systemctl" and c[1:3] == ["--user", "restart"]]


class _NeverRun:
    def __call__(self, argv, **kw):
        raise AssertionError(f"refusal should precede any call: {argv}")


_RECEIPT_AT = datetime(2026, 9, 16, 10, 0, 0, tzinfo=timezone.utc)


def _receipt(checkout, *, after="deadbeef", rid="receipt-7", repo="willow-memory/willow-mcp"):
    return {"id": rid, "created_at": _RECEIPT_AT,
            "content": {"repo": repo, "checkout": str(checkout), "before": "0ld", "after": after}}


def _nestor_db(tmp_path, *rows) -> Path:
    """A tm_pairs table with the columns the query names. Each row is
    (id, target_text, status, seal_sig, superseded_by, source_lang)."""
    db = tmp_path / "nestor.db"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE tm_pairs (
            id TEXT PRIMARY KEY, source_text TEXT NOT NULL, source_norm TEXT NOT NULL,
            source_lang TEXT NOT NULL, target_text TEXT NOT NULL, target_lang TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft', verifier TEXT NOT NULL DEFAULT '',
            weight REAL NOT NULL DEFAULT 1.0, origin TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL, seal_sig TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '', superseded_by TEXT NOT NULL DEFAULT '',
            visibility TEXT NOT NULL DEFAULT 'internal'
        );
    """)
    for i, (pid, target, status, sig, superseded, lang) in enumerate(rows):
        conn.execute(
            "INSERT INTO tm_pairs (id, source_text, source_norm, source_lang, target_text, target_lang, "
            "status, verifier, created_at, seal_sig, superseded_by) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (pid, "restart the broker?", "restart the broker", lang, target, lang,
             status, "sean campbell", f"2026-09-16T1{i}:00:00Z", sig, superseded))
    conn.commit()
    conn.close()
    return db


def _sealed(rid, pid="pair-1"):
    return (pid, f"yes — restart onto pull receipt {rid}", "sealed", "sig", "", "decision")


@pytest.fixture
def checkout(tmp_path):
    d = tmp_path / "willow-mcp"
    (d / ".git").mkdir(parents=True)
    return d


def _config(checkout, db, unit="willow-mcp-serve.service"):
    return reloader.ReloaderConfig(unit=unit, checkout=checkout, repo="willow-memory/willow-mcp", nestor_db=db)


# ── the seal lookup ───────────────────────────────────────────────────────────

def test_seal_lookup_three_states(tmp_path):
    db = _nestor_db(tmp_path, _sealed("receipt-7"))
    assert reloader.find_sealing_decision("receipt-7", db)["state"] == "populated"
    assert reloader.find_sealing_decision("receipt-8", db)["state"] == "empty"
    missing = reloader.find_sealing_decision("receipt-7", tmp_path / "nope.db")
    assert missing["state"] == "unreachable" and "cause" in missing


def test_seal_lookup_ignores_draft_unsigned_superseded_and_other_domains(tmp_path):
    db = _nestor_db(
        tmp_path,
        ("draft", "restart onto pull receipt receipt-7", "draft", "", "", "decision"),
        ("unsigned", "restart onto pull receipt receipt-7", "sealed", "", "", "decision"),
        ("old", "restart onto pull receipt receipt-7", "sealed", "sig", "newer", "decision"),
        ("es", "restart onto pull receipt receipt-7", "sealed", "sig", "", "es"),
    )
    assert reloader.find_sealing_decision("receipt-7", db)["state"] == "empty"


def test_seal_lookup_reports_verifier_and_pair(tmp_path):
    db = _nestor_db(tmp_path, _sealed("receipt-7", pid="e961aff8-x"))
    out = reloader.find_sealing_decision("receipt-7", db)
    assert out["pair_id"] == "e961aff8-x" and out["verifier"] == "sean campbell"


# ── the check ─────────────────────────────────────────────────────────────────

def test_only_the_broker_unit_is_this_units_business(tmp_path, checkout):
    db = _nestor_db(tmp_path)
    out = reloader.check(_config(checkout, db, unit="willow-bot.service"),
                         ledger=_FakeLedger(), runner=_NeverRun())
    assert out["error"] == "EINVAL" and "unit_reload_execute" in out["reason"]


def test_no_receipt_is_enoreceipt_before_any_call(tmp_path, checkout):
    db = _nestor_db(tmp_path)
    out = reloader.check(_config(checkout, db), ledger=_FakeLedger(None), runner=_NeverRun())
    assert out["error"] == "ENORECEIPT"


def test_receipt_without_id_cannot_be_named(tmp_path, checkout):
    db = _nestor_db(tmp_path)
    r = _receipt(checkout)
    del r["id"]
    out = reloader.check(_config(checkout, db), ledger=_FakeLedger(r), runner=_NeverRun())
    assert out["error"] == "EAMBIG"


def test_unit_already_newer_than_receipt_is_ealready(tmp_path, checkout):
    db = _nestor_db(tmp_path, _sealed("receipt-7"))
    git = _FakeSystemctlGit(active_enter="Mon 2026-09-17 10:00:00 UTC")
    out = reloader.check(_config(checkout, db), ledger=_FakeLedger(_receipt(checkout)), runner=git)
    assert out["error"] == "EALREADY" and out["receipt_id"] == "receipt-7"


def test_head_moved_since_the_pull_is_edrift(tmp_path, checkout):
    db = _nestor_db(tmp_path, _sealed("receipt-7"))
    git = _FakeSystemctlGit(head="cafef00d")
    out = reloader.check(_config(checkout, db), ledger=_FakeLedger(_receipt(checkout)), runner=git)
    assert out["error"] == "EDRIFT" and out["head"] == "cafef00d"


def test_receipt_without_seal_waits_as_enoseal(tmp_path, checkout):
    db = _nestor_db(tmp_path)
    git = _FakeSystemctlGit()
    out = reloader.check(_config(checkout, db), ledger=_FakeLedger(_receipt(checkout)), runner=git)
    assert out["error"] == "ENOSEAL" and out["receipt_id"] == "receipt-7"
    assert git.restarts == []


def test_seal_store_unreachable_is_eseals_not_enoseal(tmp_path, checkout):
    git = _FakeSystemctlGit()
    out = reloader.check(_config(checkout, tmp_path / "absent.db"),
                         ledger=_FakeLedger(_receipt(checkout)), runner=git)
    assert out["error"] == "ESEALS"


def test_unit_state_unreachable_is_eunreach(tmp_path, checkout):
    db = _nestor_db(tmp_path, _sealed("receipt-7"))
    git = _FakeSystemctlGit(show_rc=1)
    out = reloader.check(_config(checkout, db), ledger=_FakeLedger(_receipt(checkout)), runner=git)
    assert out["error"] == "EUNREACH"


def test_all_conditions_met_is_act(tmp_path, checkout):
    db = _nestor_db(tmp_path, _sealed("receipt-7"))
    git = _FakeSystemctlGit()
    out = reloader.check(_config(checkout, db), ledger=_FakeLedger(_receipt(checkout)), runner=git)
    assert out["ok"] and out["act"]
    assert out["seal"]["pair_id"] == "pair-1"
    assert git.restarts == []  # check never acts


# ── the act ───────────────────────────────────────────────────────────────────

def test_tick_restarts_once_and_leaves_ink(tmp_path, checkout):
    db = _nestor_db(tmp_path, _sealed("receipt-7"))
    git = _FakeSystemctlGit()
    ledger = _FakeLedger(_receipt(checkout))
    out = reloader.run_once(_config(checkout, db), ledger=ledger, runner=git)
    assert out["ok"] and out["reloaded"], out
    assert len(git.restarts) == 1 and git.restarts[0][-1] == "willow-mcp-serve.service"
    assert out["reload_receipt_id"] == "reload-receipt-1"
    project, event, content = ledger.appended[0]
    assert event == urx.EVENT
    assert content["actor"] == reloader.ACTOR
    assert content["pull_receipt_id"] == "receipt-7"
    assert content["nestor_pair_id"] == "pair-1" and content["nestor_verifier"] == "sean campbell"
    assert content["decision"] == "e961aff8"


def test_second_tick_after_restart_is_quiet(tmp_path, checkout):
    """The idempotence the timer relies on: after the restart the unit is
    newer than the receipt, so the next tick is EALREADY, not a second
    restart — and no second receipt."""
    db = _nestor_db(tmp_path, _sealed("receipt-7"))
    git = _FakeSystemctlGit()
    ledger = _FakeLedger(_receipt(checkout))
    first = reloader.run_once(_config(checkout, db), ledger=ledger, runner=git)
    second = reloader.run_once(_config(checkout, db), ledger=ledger, runner=git)
    assert first["reloaded"] and not second["reloaded"]
    assert second["error"] == "EALREADY"
    assert len(git.restarts) == 1 and len(ledger.appended) == 1


def test_failed_restart_is_erestart_without_ink(tmp_path, checkout):
    db = _nestor_db(tmp_path, _sealed("receipt-7"))
    git = _FakeSystemctlGit(restart_rc=1)
    ledger = _FakeLedger(_receipt(checkout))
    out = reloader.run_once(_config(checkout, db), ledger=ledger, runner=git)
    assert out["error"] == "ERESTART" and not out["reloaded"] and out["act"]
    assert ledger.appended == []


def test_refusal_is_not_ink(tmp_path, checkout):
    db = _nestor_db(tmp_path)
    ledger = _FakeLedger(_receipt(checkout))
    out = reloader.run_once(_config(checkout, db), ledger=ledger, runner=_FakeSystemctlGit())
    assert out["error"] == "ENOSEAL" and ledger.appended == []


def test_systemctl_runs_in_utc_so_the_parse_matches_the_print(tmp_path, checkout):
    db = _nestor_db(tmp_path, _sealed("receipt-7"))
    git = _FakeSystemctlGit()
    reloader.check(_config(checkout, db), ledger=_FakeLedger(_receipt(checkout)), runner=git)
    assert git.env_seen and all(env.get("TZ") == "UTC" for env in git.env_seen)


# ── the units ─────────────────────────────────────────────────────────────────

def test_render_units_fills_every_placeholder(tmp_path, checkout, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "home" / "store"))
    db = _nestor_db(tmp_path)
    units = reloader.render_units(_config(checkout, db), python=Path("/venv/bin/python"), interval="90s")
    svc, tmr = units[reloader.SERVICE_UNIT], units[reloader.TIMER_UNIT]
    assert "@" not in svc and "@" not in tmr
    assert "Type=oneshot" in svc
    assert "-m willow_mcp.reloader tick" in svc
    assert "WILLOW_RELOADER_UNIT=willow-mcp-serve.service" in svc
    assert f"WILLOW_RELOADER_CHECKOUT={checkout}" in svc
    assert f"WILLOW_NESTOR_DB={db}" in svc
    assert "OnUnitActiveSec=90s" in tmr and f"Unit={reloader.SERVICE_UNIT}" in tmr


def test_render_refuses_without_a_checkout(tmp_path):
    cfg = reloader.ReloaderConfig(unit="willow-mcp-serve.service", checkout=None,
                                  repo="willow-memory/willow-mcp", nestor_db=tmp_path / "n.db")
    with pytest.raises(ValueError):
        reloader.render_units(cfg)


def test_install_writes_units_and_never_starts_them(tmp_path, checkout, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path / "home"))
    db = _nestor_db(tmp_path)
    dest = tmp_path / "units"
    out = reloader.install_services(_config(checkout, db), destination=dest, reload=False)
    assert sorted(Path(p).name for p in out["installed"]) == sorted([reloader.SERVICE_UNIT, reloader.TIMER_UNIT])
    assert out["started"] == [] and out["enabled"] == []
    assert (dest / reloader.TIMER_UNIT).read_text().count("OnUnitActiveSec=60s") == 1


def test_uninstall_refuses_an_active_unit(tmp_path, checkout, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path / "home"))
    db = _nestor_db(tmp_path)
    dest = tmp_path / "units"
    reloader.install_services(_config(checkout, db), destination=dest, reload=False)

    def active(*args):
        return subprocess.CompletedProcess(args, 0, "active\n", "")

    with pytest.raises(RuntimeError, match="active"):
        reloader.uninstall_services(destination=dest, reload=False, runner=active)

    def inactive(*args):
        return subprocess.CompletedProcess(args, 3, "inactive\n", "")

    out = reloader.uninstall_services(destination=dest, reload=False, runner=inactive)
    assert len(out["removed"]) == 2 and not any(dest.iterdir())


def test_default_checkout_prefers_env_then_source_tree(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_RELOADER_CHECKOUT", str(tmp_path / "elsewhere"))
    assert reloader.default_checkout() == tmp_path / "elsewhere"
    monkeypatch.delenv("WILLOW_RELOADER_CHECKOUT")
    tree = reloader.default_checkout()
    # This test runs from the editable checkout, so the tree resolves to it.
    assert tree is None or (tree / ".git").exists()


# ── entrypoint ────────────────────────────────────────────────────────────────

def test_check_command_exits_zero_when_waiting(tmp_path, checkout, monkeypatch, capsys):
    db = _nestor_db(tmp_path)
    monkeypatch.setattr(reloader, "_live_ledger", lambda: _FakeLedger(_receipt(checkout)))
    monkeypatch.setattr(reloader, "default_config", lambda: _config(checkout, db))
    monkeypatch.setattr(urx.subprocess, "run", _FakeSystemctlGit())
    rc = reloader.main(["check"])
    assert rc == 0
    assert '"ENOSEAL"' in capsys.readouterr().out


def test_tick_command_exits_one_only_when_due_and_failed(tmp_path, checkout, monkeypatch, capsys):
    db = _nestor_db(tmp_path, _sealed("receipt-7"))
    monkeypatch.setattr(reloader, "_live_ledger", lambda: _FakeLedger(_receipt(checkout)))
    monkeypatch.setattr(reloader, "default_config", lambda: _config(checkout, db))
    monkeypatch.setattr(urx.subprocess, "run", _FakeSystemctlGit(restart_rc=1))
    assert reloader.main(["tick"]) == 1
    assert '"ERESTART"' in capsys.readouterr().out


# ── the env trigger: check_env (detect / request / confirm+act) ───────────────
#
# `_FakeSystemctlGit`'s `show` branch never sets `EnvironmentFiles=`, so
# `resolve_env_file` always falls back to `$WILLOW_HOME/env` — the autouse
# `_reloader_willow_home` fixture gives every test here its own throwaway
# WILLOW_HOME, so these helpers write/seed exactly that file.

_ENV_SECRET = "sk-do-not-leak-this-literal-9182"


def _seed_running_env(text: str) -> dict:
    """What 'the running broker' loaded, per its own startup record —
    `env_fingerprint.record_startup` against the same path
    `resolve_env_file` falls back to."""
    p = envfp.default_env_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return envfp.record_startup(p)


def _write_live_env(text: str) -> Path:
    p = envfp.default_env_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _assert_no_secret_leak(*blobs) -> None:
    import json
    for blob in blobs:
        text = blob if isinstance(blob, str) else json.dumps(blob, default=str)
        assert _ENV_SECRET not in text


def test_check_env_missing_state_file_is_estateempty(tmp_path, checkout):
    db = _nestor_db(tmp_path)
    out = reloader.check_env(_config(checkout, db), ledger=_FakeLedger(), runner=_FakeSystemctlGit())
    assert out["error"] == "ESTATEEMPTY" and not out["act"]


def test_check_env_unreachable_state_file_is_eunreach(tmp_path, checkout):
    db = _nestor_db(tmp_path)
    envfp.state_path().parent.mkdir(parents=True, exist_ok=True)
    envfp.state_path().write_text("not json{{{", encoding="utf-8")
    out = reloader.check_env(_config(checkout, db), ledger=_FakeLedger(), runner=_FakeSystemctlGit())
    assert out["error"] == "EUNREACH"


def test_check_env_no_diff_is_quiet_not_a_refusal(tmp_path, checkout):
    db = _nestor_db(tmp_path)
    _seed_running_env("A=1\n")
    _write_live_env("A=1\n")
    out = reloader.check_env(_config(checkout, db), ledger=_FakeLedger(), runner=_FakeSystemctlGit())
    assert out["ok"] and not out["act"] and out["error"] is None


def test_check_env_diff_without_seal_is_enoseal_and_writes_one_receipt(tmp_path, checkout):
    db = _nestor_db(tmp_path)
    _seed_running_env(f"A=1\nSECRET={_ENV_SECRET}\n")
    _write_live_env(f"A=1\nSECRET={_ENV_SECRET}\nB=2\n")
    ledger = _FakeLedger()
    out = reloader.check_env(_config(checkout, db), ledger=ledger, runner=_FakeSystemctlGit())
    assert out["error"] == "ENOSEAL"
    assert len(ledger.appended) == 1
    project, event, content = ledger.appended[0]
    assert event == reloader.ENV_EVENT
    assert content["actor"] == reloader.ACTOR
    assert content["keys_added"] == ["B"]
    assert content["keys_removed"] == [] and content["keys_changed"] == []
    _assert_no_secret_leak(content, out)


def test_check_env_idempotent_no_second_receipt_while_open(tmp_path, checkout):
    db = _nestor_db(tmp_path)
    _seed_running_env("A=1\n")
    _write_live_env("A=1\nB=2\n")
    ledger = _FakeLedger()
    first = reloader.check_env(_config(checkout, db), ledger=ledger, runner=_FakeSystemctlGit())
    second = reloader.check_env(_config(checkout, db), ledger=ledger, runner=_FakeSystemctlGit())
    assert first["error"] == second["error"] == "ENOSEAL"
    assert first["receipt_id"] == second["receipt_id"]
    assert len(ledger.appended) == 1


def test_check_env_all_conditions_met_is_act(tmp_path, checkout):
    _seed_running_env("A=1\n")
    _write_live_env("A=1\nB=2\n")
    ledger = _FakeLedger()
    git = _FakeSystemctlGit()
    (tmp_path / "empty").mkdir()
    (tmp_path / "sealed").mkdir()
    empty_db = _nestor_db(tmp_path / "empty")
    detect = reloader.check_env(_config(checkout, empty_db), ledger=ledger, runner=git)
    assert detect["error"] == "ENOSEAL"
    sealed_db = _nestor_db(tmp_path / "sealed", _sealed(detect["receipt_id"]))
    out = reloader.check_env(_config(checkout, sealed_db), ledger=ledger, runner=git)
    assert out["ok"] and out["act"]
    assert out["seal"]["pair_id"] == "pair-1"
    assert git.restarts == []  # check never acts
    assert len(ledger.appended) == 1  # still just the one request


def test_check_env_unit_already_active_since_receipt_is_ealready(tmp_path, checkout):
    _seed_running_env("A=1\n")
    _write_live_env("A=1\nB=2\n")
    ledger = _FakeLedger()
    git = _FakeSystemctlGit(active_enter="Mon 2030-01-01 10:00:00 UTC")
    db = _nestor_db(tmp_path)
    out = reloader.check_env(_config(checkout, db), ledger=ledger, runner=git)
    assert out["error"] == "EALREADY"


def test_check_env_drift_since_receipt_is_edrift(tmp_path, checkout):
    _seed_running_env("A=1\n")
    _write_live_env("A=1\nB=2\n")
    ledger = _FakeLedger()
    git = _FakeSystemctlGit()
    db = _nestor_db(tmp_path)
    first = reloader.check_env(_config(checkout, db), ledger=ledger, runner=git)
    assert first["error"] == "ENOSEAL"
    _write_live_env("A=1\nB=3\n")  # the file moves again before any seal
    second = reloader.check_env(_config(checkout, db), ledger=ledger, runner=git)
    assert second["error"] == "EDRIFT"
    assert second["receipt_id"] == first["receipt_id"]
    assert len(ledger.appended) == 1  # still idempotent — no second receipt


def test_check_env_unit_unreachable_is_eunreach(tmp_path, checkout):
    _seed_running_env("A=1\n")
    _write_live_env("A=1\nB=2\n")
    ledger = _FakeLedger()
    git = _FakeSystemctlGit(show_rc=1)
    db = _nestor_db(tmp_path)
    out = reloader.check_env(_config(checkout, db), ledger=ledger, runner=git)
    assert out["error"] == "EUNREACH"


# ── both triggers, one tick ─────────────────────────────────────────────────

def test_run_once_env_trigger_restarts_and_leaves_ink(tmp_path, checkout):
    _seed_running_env("A=1\n")
    _write_live_env(f"A=1\nSECRET={_ENV_SECRET}\n")
    ledger = _FakeLedger()  # no pull receipt at all
    git = _FakeSystemctlGit()
    (tmp_path / "empty").mkdir()
    (tmp_path / "sealed").mkdir()
    empty_db = _nestor_db(tmp_path / "empty")
    first = reloader.run_once(_config(checkout, empty_db), ledger=ledger, runner=git)
    assert not first["reloaded"]
    rid = first["env"]["receipt_id"]
    sealed_db = _nestor_db(tmp_path / "sealed", _sealed(rid))
    second = reloader.run_once(_config(checkout, sealed_db), ledger=ledger, runner=git)
    assert second["ok"] and second["reloaded"]
    assert second["triggers"] == ["env_changed"]
    assert len(git.restarts) == 1 and git.restarts[0][-1] == "willow-mcp-serve.service"
    project, event, content = ledger.appended[-1]
    assert event == urx.EVENT
    assert content["trigger"] == "env_changed"
    assert content["env_receipt_id"] == rid
    assert "pull_receipt_id" not in content
    assert content["nestor_pair_id"] == "pair-1"
    _assert_no_secret_leak(content)


def test_run_once_second_tick_after_restart_env_trigger_is_quiet(tmp_path, checkout):
    _seed_running_env("A=1\n")
    _write_live_env("A=1\nB=2\n")
    ledger = _FakeLedger()
    git = _FakeSystemctlGit()
    (tmp_path / "empty").mkdir()
    (tmp_path / "sealed").mkdir()
    empty_db = _nestor_db(tmp_path / "empty")
    first = reloader.run_once(_config(checkout, empty_db), ledger=ledger, runner=git)
    rid = first["env"]["receipt_id"]
    sealed_db = _nestor_db(tmp_path / "sealed", _sealed(rid))
    second = reloader.run_once(_config(checkout, sealed_db), ledger=ledger, runner=git)
    assert second["reloaded"]
    # the restarted broker's own startup records its new baseline, same as
    # `env_fingerprint.record_startup()` really would on the next boot.
    _seed_running_env("A=1\nB=2\n")
    third = reloader.run_once(_config(checkout, sealed_db), ledger=ledger, runner=git)
    assert not third["reloaded"]
    assert third["env"]["act"] is False and third["env"]["error"] is None
    assert len(git.restarts) == 1


def test_run_once_both_triggers_sealed_restarts_once_cites_both(tmp_path, checkout):
    _seed_running_env("A=1\n")
    _write_live_env("A=1\nB=2\n")
    ledger = _FakeLedger(_receipt(checkout))
    git = _FakeSystemctlGit()
    (tmp_path / "empty").mkdir()
    (tmp_path / "sealed").mkdir()
    empty_db = _nestor_db(tmp_path / "empty")
    first = reloader.run_once(_config(checkout, empty_db), ledger=ledger, runner=git)
    assert not first["reloaded"]
    pull_rid = first["receipt_id"]
    env_rid = first["env"]["receipt_id"]
    db = _nestor_db(tmp_path / "sealed", _sealed(pull_rid, pid="pair-1"), _sealed(env_rid, pid="pair-2"))
    second = reloader.run_once(_config(checkout, db), ledger=ledger, runner=git)
    assert second["ok"] and second["reloaded"]
    assert set(second["triggers"]) == {"git_pull", "env_changed"}
    assert len(git.restarts) == 1  # one restart satisfies both
    project, event, content = ledger.appended[-1]
    assert content["trigger"] == "both"
    assert content["pull_receipt_id"] == pull_rid
    assert content["env_receipt_id"] == env_rid
    assert content["nestor_pair_ids"] == {"pull": "pair-1", "env": "pair-2"}


def test_run_once_only_pull_sealed_acts_on_pull_only(tmp_path, checkout):
    _seed_running_env("A=1\n")
    _write_live_env("A=1\nB=2\n")
    ledger = _FakeLedger(_receipt(checkout))
    git = _FakeSystemctlGit()
    (tmp_path / "empty").mkdir()
    (tmp_path / "sealed").mkdir()
    empty_db = _nestor_db(tmp_path / "empty")
    first = reloader.run_once(_config(checkout, empty_db), ledger=ledger, runner=git)
    pull_rid = first["receipt_id"]
    assert first["env"]["receipt_id"]  # the env request was filed too
    db = _nestor_db(tmp_path / "sealed", _sealed(pull_rid, pid="pair-1"))  # env stays unsealed
    second = reloader.run_once(_config(checkout, db), ledger=ledger, runner=git)
    assert second["reloaded"] and second["triggers"] == ["git_pull"]
    project, event, content = ledger.appended[-1]
    assert content["trigger"] == "git_pull"
    assert "env_receipt_id" not in content
    assert len(git.restarts) == 1  # the still-waiting env receipt earns no second restart
