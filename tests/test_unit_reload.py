"""The brokered unit reload (verb 15 `unit.reload`, sealed `06075e99`) — a
systemd `--user` unit restarts onto code a `git_pull` FRANK receipt already
brought home, without a keyboard. Sibling of `test_push_executor.py`: the
agent asks, this process checks and cites the `unit.reload` envelope, files
the ask on a miss, and only then restarts the unit. Every `systemctl`/`git`
call goes through a fake runner; nothing here touches a real unit or repo.
"""
from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone

import pytest

from willow_mcp import server
from willow_mcp import unit_reload_executor as urx


# ── a fake frank ledger, same shape as test_push_executor ────────────────────

class _FakeGovernancePg:
    def __init__(self):
        self.rows = []

    def cursor(self):
        return _FakeGovernanceCursor(self)

    def commit(self):
        pass


class _FakeGovernanceCursor:
    def __init__(self, pg):
        self.pg = pg
        self._result = []

    def execute(self, sql, params=None):
        params = params or ()
        s = sql.strip()
        if "pg_advisory" in s:
            return
        if s.startswith("SELECT COUNT(*)"):
            envelope_id = params[0]
            self._result = [(sum(
                1 for r in self.pg.rows
                if r["event_type"] == "envelope_citation"
                and r["content"].get("envelope_id") == envelope_id
                and r["content"].get("outcome") == "granted"
            ),)]
            return
        if s.startswith("SELECT hash FROM"):
            self._result = [(self.pg.rows[-1]["hash"],)] if self.pg.rows else []
            return
        if s.startswith("SELECT id, content, created_at FROM"):
            event_type = params[0]
            matches = [r for r in self.pg.rows if r["event_type"] == event_type]
            matches.sort(key=lambda r: r.get("created_at") or 0, reverse=True)
            self._result = [(r["id"], r["content"], r.get("created_at")) for r in matches]
            return
        if s.startswith("INSERT INTO"):
            record_id, project, event_type, content, prev_hash, digest = params
            self.pg.rows.append({
                "id": record_id, "project": project, "event_type": event_type,
                "content": getattr(content, "adapted", content),
                "prev_hash": prev_hash, "hash": digest,
                "created_at": datetime.now(timezone.utc),
            })
            return
        raise AssertionError(f"unexpected SQL: {sql!r}")

    def fetchone(self):
        return self._result[0] if self._result else None

    def fetchall(self):
        return self._result

    def close(self):
        pass


def _ledger(pg):
    from willow_mcp.governance_ledger import GovernanceLedger
    return GovernanceLedger(pg)


def _citations(pg):
    return [r for r in pg.rows if r["event_type"] == "envelope_citation"]


def _seed_receipt(pg, *, repo, checkout, after, created_at, before="oldsha"):
    pg.rows.append({
        "id": "receipt-1", "project": "p", "event_type": "git_pull",
        "content": {"repo": repo, "checkout": str(checkout), "before": before,
                    "after": after},
        "prev_hash": None, "hash": "recepthash", "created_at": created_at,
    })


# ── registry with one unit.reload grant ───────────────────────────────────────

def _charter(tmp_path, monkeypatch, *, grantee="willow",
             units=("willow-bot.service",), extra=None, expires="2027-01-01"):
    active = [{
        "id": "env-unit.reload-test",
        "verb_id": 15,
        "verb": "unit.reload",
        "grantee": grantee,
        "bounds": {"units": list(units)},
        "issued_by": "root",
        "issued_at": "2026-01-01",
        "expires_at": expires,
        "max_count": None,
        "use_count_source": "frank",
        "status": "active",
    }] + list(extra or [])
    table = {"verbs": [{"id": 15, "verb": "unit.reload", "bounds": {"units": "l"}}]}
    reg = tmp_path / "pre-approved.json"
    tab = tmp_path / "syscall-table.json"
    tmp_path.chmod(0o700)
    reg.write_text(json.dumps({"active": active}))
    tab.write_text(json.dumps(table))
    reg.chmod(0o600)
    tab.chmod(0o600)
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(reg))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(tab))


@pytest.fixture
def checkout(tmp_path):
    d = tmp_path / "willow-bot"
    (d / ".git").mkdir(parents=True)
    return d


# ── a fake systemctl + git ────────────────────────────────────────────────────

class _FakeSystemctlGit:
    """Answers the `systemctl --user show/restart` and `git rev-parse HEAD`
    calls the executor makes. Records every call."""

    def __init__(self, *, active_enter="Mon 2026-09-15 10:00:00 UTC",
                 active_state="active", show_rc=0, show_detail="",
                 restart_rc=0, restart_err="", head="deadbeef",
                 after_active_enter=None, empty_show=False):
        self.active_enter = active_enter
        self.active_state = active_state
        self.show_rc = show_rc
        self.show_detail = show_detail
        self.restart_rc = restart_rc
        self.restart_err = restart_err
        self.head = head
        self.after_active_enter = after_active_enter or active_enter
        self.empty_show = empty_show
        self.calls: list[list[str]] = []
        self._restarted = False

    def _show_output(self) -> str:
        if self.empty_show:
            return ""
        active_enter = self.after_active_enter if self._restarted else self.active_enter
        return (
            f"ActiveState={self.active_state}\n"
            f"ActiveEnterTimestamp={active_enter}\n"
            f"ActiveEnterTimestampMonotonic=123456\n"
            f"MainPID=1234\n"
            f"ExecMainStartTimestamp={active_enter}\n"
        )

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        if argv[0] == "systemctl":
            if argv[1:3] == ["--user", "show"]:
                return subprocess.CompletedProcess(
                    argv, self.show_rc, self._show_output(), self.show_detail)
            if argv[1:3] == ["--user", "restart"]:
                self._restarted = True
                return subprocess.CompletedProcess(argv, self.restart_rc, "", self.restart_err)
            raise AssertionError(f"unexpected systemctl call {argv}")
        if argv[0] == "git":
            rest = argv[3:]
            if rest == ["rev-parse", "HEAD"]:
                return subprocess.CompletedProcess(argv, 0, self.head + "\n", "")
            raise AssertionError(f"unexpected git call {rest}")
        raise AssertionError(f"unexpected call {argv}")

    @property
    def restarts(self):
        return [c for c in self.calls
                if c[0] == "systemctl" and c[1:3] == ["--user", "restart"]]


class _NeverRun:
    """A runner that fails the test if it is ever invoked — for refusals
    that must short-circuit before any subprocess call."""

    def __call__(self, argv, **kw):
        raise AssertionError(f"unexpected call — refusal should precede it: {argv}")


def _reload(checkout, pg, runner, **kw):
    args = dict(app_id="willow", unit="willow-bot.service", checkout=checkout,
                repo="willow-memory/willow-bot", project="willow-mcp",
                ledger=_ledger(pg), runner=runner)
    args.update(kw)
    return urx.execute_unit_reload(args.pop("app_id"), **args)


_BEFORE = datetime(2026, 9, 15, 10, 0, 0, tzinfo=timezone.utc)
_AFTER_RECEIPT = datetime(2026, 9, 16, 10, 0, 0, tzinfo=timezone.utc)


# ── granted ──────────────────────────────────────────────────────────────────

def test_granted_reload_cites_then_restarts(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    _seed_receipt(pg, repo="willow-memory/willow-bot", checkout=checkout,
                  after="deadbeef", created_at=_AFTER_RECEIPT)
    git = _FakeSystemctlGit(active_enter="Mon 2026-09-15 10:00:00 UTC", head="deadbeef")
    out = _reload(checkout, pg, git)
    assert out["ok"] and out["reloaded"], out
    assert out["envelope_id"] == "env-unit.reload-test"
    assert out["head"] == "deadbeef"
    assert len(git.restarts) == 1
    cites = _citations(pg)
    assert len(cites) == 1 and cites[0]["content"]["outcome"] == "granted"
    assert cites[0]["content"]["call_args"] == {"units": ["willow-bot.service"]}
    assert out["citation_id"] == cites[0]["id"]
    # willow-bot unit -> steward status is inlined via bot_status
    assert "steward" in out


def test_non_bot_unit_has_no_steward_field(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch, units=("forge.service",))
    pg = _FakeGovernancePg()
    _seed_receipt(pg, repo="willow-memory/willow-bot", checkout=checkout,
                  after="deadbeef", created_at=_AFTER_RECEIPT)
    git = _FakeSystemctlGit(head="deadbeef")
    out = _reload(checkout, pg, git, unit="forge.service")
    assert out["ok"] and "steward" not in out


# ── refused before any subprocess call ────────────────────────────────────────

def test_broker_own_unit_is_refused_before_any_call(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch, units=("willow-mcp.service",))
    pg = _FakeGovernancePg()
    out = _reload(checkout, pg, _NeverRun(), unit="willow-mcp.service")
    assert out["error"] == "EPERM"
    assert _citations(pg) == []


def test_broker_serve_unit_is_also_refused(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch, units=("willow-mcp-serve.service",))
    pg = _FakeGovernancePg()
    out = _reload(checkout, pg, _NeverRun(), unit="willow-mcp-serve.service")
    assert out["error"] == "EPERM"


# ── unit state unreachable, cause distinct per failure ───────────────────────

def test_no_user_bus_is_unreachable_not_empty(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    git = _FakeSystemctlGit(show_rc=1,
                            show_detail="Failed to connect to bus: No such file or directory")
    out = _reload(checkout, pg, git)
    assert out["error"] == "EUNREACH" and out["cause"] == "no_user_bus"
    assert _citations(pg) == []


def test_unknown_unit_is_unreachable(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    git = _FakeSystemctlGit(show_rc=1, show_detail="Unit foo.service could not be found.")
    out = _reload(checkout, pg, git)
    assert out["error"] == "EUNREACH" and out["cause"] == "unit_unknown"


def test_empty_show_output_is_unreachable_unit_unknown(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    git = _FakeSystemctlGit(empty_show=True)
    out = _reload(checkout, pg, git)
    assert out["error"] == "EUNREACH" and out["cause"] == "unit_unknown"


def test_systemctl_missing_is_unreachable(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()

    def _runner(argv, **kw):
        raise FileNotFoundError("systemctl")

    out = _reload(checkout, pg, _runner)
    assert out["error"] == "EUNREACH" and out["cause"] == "systemctl_missing"


def test_show_timeout_is_unreachable(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()

    def _runner(argv, **kw):
        raise subprocess.TimeoutExpired(argv, 10)

    out = _reload(checkout, pg, _runner)
    assert out["error"] == "EUNREACH" and out["cause"] == "timeout"


# ── receipt discipline ────────────────────────────────────────────────────────

def test_no_pull_receipt_refuses_ENORECEIPT(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    git = _FakeSystemctlGit(head="deadbeef")
    out = _reload(checkout, pg, git)
    assert out["error"] == "ENORECEIPT"
    assert _citations(pg) == [] and git.restarts == []


def test_already_active_since_after_the_receipt_refuses_EALREADY(
        home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    _seed_receipt(pg, repo="willow-memory/willow-bot", checkout=checkout,
                  after="deadbeef", created_at=_BEFORE)
    # unit has been active since AFTER the receipt — nothing to reload onto
    git = _FakeSystemctlGit(active_enter="Wed 2026-09-16 12:00:00 UTC", head="deadbeef")
    out = _reload(checkout, pg, git)
    assert out["error"] == "EALREADY"
    assert _citations(pg) == [] and git.restarts == []


def test_drifted_head_refuses_EDRIFT(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    _seed_receipt(pg, repo="willow-memory/willow-bot", checkout=checkout,
                  after="deadbeef", created_at=_AFTER_RECEIPT)
    git = _FakeSystemctlGit(active_enter="Mon 2026-09-15 10:00:00 UTC", head="somethingelse")
    out = _reload(checkout, pg, git)
    assert out["error"] == "EDRIFT"
    assert _citations(pg) == [] and git.restarts == []


# ── envelope resolution ────────────────────────────────────────────────────────

def test_bounds_mismatch_is_refused_cited_and_asked(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch, units=("some-other.service",))
    pg = _FakeGovernancePg()
    _seed_receipt(pg, repo="willow-memory/willow-bot", checkout=checkout,
                  after="deadbeef", created_at=_AFTER_RECEIPT)
    git = _FakeSystemctlGit(head="deadbeef")
    out = _reload(checkout, pg, git)
    assert out["error"] == "EAMBIG"
    assert "units" in out["fields"]
    assert git.restarts == []
    assert _citations(pg)[0]["content"]["outcome"] == "EAMBIG"
    assert out["ask"]["queued"] is True
    from willow_mcp import human_loop
    from willow_mcp.db import Store
    rows = human_loop.list_queue(Store())
    assert any("willow-bot.service" in (r.get("title") or "") for r in rows)


def test_no_governing_envelope_refuses_and_files_the_ask(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch, grantee="loki")
    pg = _FakeGovernancePg()
    _seed_receipt(pg, repo="willow-memory/willow-bot", checkout=checkout,
                  after="deadbeef", created_at=_AFTER_RECEIPT)
    git = _FakeSystemctlGit(head="deadbeef")
    out = _reload(checkout, pg, git)
    assert out["error"] == "ENOENT"
    assert out["ask"]["queued"] is True
    assert git.restarts == [] and _citations(pg) == []


def test_named_envelope_must_be_one_the_actor_holds(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    _seed_receipt(pg, repo="willow-memory/willow-bot", checkout=checkout,
                  after="deadbeef", created_at=_AFTER_RECEIPT)
    git = _FakeSystemctlGit(head="deadbeef")
    out = _reload(checkout, pg, git, envelope_id="env-someone-elses")
    assert out["error"] == "ENOENT"
    assert out["envelope_ids"] == ["env-unit.reload-test"]


def test_two_governing_envelopes_is_ambiguous_until_named(home, tmp_path, monkeypatch, checkout):
    second = {"id": "env-unit.reload-two", "verb_id": 15, "verb": "unit.reload",
              "grantee": "willow", "bounds": {"units": ["willow-bot.service"]},
              "issued_by": "root", "issued_at": "2026-01-01", "expires_at": "2027-01-01",
              "max_count": None, "use_count_source": "frank", "status": "active"}
    _charter(tmp_path, monkeypatch, extra=[second])
    pg = _FakeGovernancePg()
    _seed_receipt(pg, repo="willow-memory/willow-bot", checkout=checkout,
                  after="deadbeef", created_at=_AFTER_RECEIPT)
    git = _FakeSystemctlGit(head="deadbeef")
    assert _reload(checkout, pg, git)["error"] == "EAMBIG"
    assert _reload(checkout, pg, git, envelope_id="env-unit.reload-two")["reloaded"] is True


def test_expired_envelope_is_refused_and_asked(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch, expires="2020-01-01")
    pg = _FakeGovernancePg()
    _seed_receipt(pg, repo="willow-memory/willow-bot", checkout=checkout,
                  after="deadbeef", created_at=_AFTER_RECEIPT)
    git = _FakeSystemctlGit(head="deadbeef")
    out = _reload(checkout, pg, git)
    assert out["error"] == "EEXPIRED" and out["ask"]["queued"] is True
    assert git.restarts == []


# ── the tool is wired like the push and the pull ──────────────────────────────

def test_the_unit_reload_tool_is_gated_as_envelope_apply_by_name():
    catalogue = server._gate_tool_catalogue()
    assert catalogue["unit_reload_execute"] == "envelope_apply"


def test_unit_reload_is_not_advertised_in_desk_core():
    from willow_mcp import advertise
    assert "unit_reload_execute" not in advertise.DESK_CORE
