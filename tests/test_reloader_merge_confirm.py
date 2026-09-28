"""The merge-is-confirm path (gap 55fc7c9681e9; replaces sealed ruling
e961aff8): reloader.check_merge()/run_once_v2(). The operator's own merge
into master, checked live against GitHub, is the reloader's confirm --
not a per-restart Nestor seal. Gated behind governance record
RULING_RECORD_ID being sealed: check_merge() always refuses ENORULING
while it is not, and run_once_v2() falls back to run_once() (the
sealed-pair path) unchanged in that case.

Fakes only -- no real systemd, git, GitHub, Postgres or Nestor. Every
test gets its own throwaway WILLOW_HOME via the autouse fixture in
test_reloader.py's module (not reused directly; this file sets its own).
"""
from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from willow_mcp import reloader


@pytest.fixture(autouse=True)
def _merge_willow_home(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path / "willow_home_default"))


# -- fakes --------------------------------------------------------------------

class _FakeLedger:
    def __init__(self, receipt=None):
        self.receipt = receipt
        self._rows: dict[str, list[dict]] = {}

    def latest_event(self, event_type, *, match):
        if event_type == "git_pull" and self.receipt is not None:
            if all(self.receipt["content"].get(k) == v for k, v in match.items()):
                return self.receipt
        for row in self._rows.get(event_type, []):
            if all(row["content"].get(k) == v for k, v in match.items()):
                return row
        return None

    def all_events(self, event_type, *, match):
        out = list(self._rows.get(event_type, []))
        if event_type == "git_pull" and self.receipt is not None:
            if all(self.receipt["content"].get(k) == v for k, v in match.items()):
                out.append(self.receipt)
        return [r for r in out if all(r["content"].get(k) == v for k, v in match.items())]

    def append(self, project, event_type, content):
        rid = f"{event_type}-{len(self._rows.get(event_type, [])) + 1}"
        self._rows.setdefault(event_type, []).insert(
            0, {"id": rid, "content": content, "created_at": datetime.now(timezone.utc)})
        return rid


class _FakeStore:
    def __init__(self, status=None):
        self.status = status

    def get(self, collection, record_id):
        assert record_id == reloader.RULING_RECORD_ID
        if self.status is None:
            return None
        return {"status": self.status}


class _Git:
    """systemctl+git fake covering the merge path's own calls: branch,
    HEAD, unit show, restart."""

    def __init__(self, *, branch="master", head="cafef00d",
                 active_enter="Mon 2026-09-15 10:00:00 UTC", show_rc=0, restart_rc=0,
                 after_active_enter="Mon 2026-09-17 10:00:00 UTC"):
        self.branch = branch
        self.head = head
        self.active_enter = active_enter
        self.after_active_enter = after_active_enter
        self.show_rc = show_rc
        self.restart_rc = restart_rc
        self.calls: list[list[str]] = []
        self._restarted = False

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        if argv[0] == "systemctl":
            if argv[1:3] == ["--user", "show"]:
                active = self.after_active_enter if self._restarted else self.active_enter
                out = f"ActiveState=active\nActiveEnterTimestamp={active}\nLoadState=loaded\n"
                return subprocess.CompletedProcess(argv, self.show_rc, out, "bus gone" if self.show_rc else "")
            if argv[1:3] == ["--user", "restart"]:
                self._restarted = True
                return subprocess.CompletedProcess(argv, self.restart_rc, "", "boom" if self.restart_rc else "")
            raise AssertionError(argv)
        if argv[0] == "git":
            if argv[3:] == ["rev-parse", "--abbrev-ref", "HEAD"]:
                return subprocess.CompletedProcess(argv, 0, self.branch + "\n", "")
            if argv[3:] == ["rev-parse", "HEAD"]:
                return subprocess.CompletedProcess(argv, 0, self.head + "\n", "")
        raise AssertionError(argv)

    @property
    def restarts(self):
        return [c for c in self.calls if c[0] == "systemctl" and c[1:3] == ["--user", "restart"]]


def _minter(*, ok=True, permissions=None, reason="no creds"):
    def mint(repo):
        if not ok:
            return {"ok": False, "reason": reason}
        return {"ok": True, "mode": "app", "token": "tok",
                "permissions": permissions if permissions is not None else {"checks": "read"}}
    return mint


def _api(*, pr_response=None, checks_response=None):
    def call(method, url, *, bearer, body=None):
        if "/pulls" in url and "/commits/" in url:
            return pr_response
        if "/check-runs" in url:
            return checks_response
        raise AssertionError(url)
    return call


def _pr_ok(number=42):
    return {"ok": True, "body": [
        {"number": number, "merged_at": "2026-09-28T10:00:00Z",
         "base": {"ref": "master"}, "merge_commit_sha": "cafef00d"},
    ]}


def _pr_empty():
    return {"ok": True, "body": []}


def _checks_ok(runs=None):
    runs = runs if runs is not None else [
        {"id": 1, "name": "test", "status": "completed", "conclusion": "success",
         "output": {}, "app": {}},
    ]
    return {"ok": True, "body": {"total_count": len(runs), "check_runs": runs}}


_AT = datetime(2026, 9, 16, 10, 0, 0, tzinfo=timezone.utc)


def _pull_receipt(checkout, *, after="cafef00d", remote_sha=None, rid="pull-1",
                  changed=True, created_at=_AT):
    remote_sha = remote_sha if remote_sha is not None else after
    return {"id": rid, "created_at": created_at,
            "content": {"repo": "willow-memory/willow-mcp", "checkout": str(checkout),
                        "before": "old", "after": after, "remote_sha": remote_sha,
                        "changed": changed}}


@pytest.fixture
def checkout(tmp_path):
    d = tmp_path / "willow-mcp"
    (d / ".git").mkdir(parents=True)
    return d


def _config(checkout, unit="willow-mcp-serve.service"):
    return reloader.ReloaderConfig(unit=unit, checkout=checkout, repo="willow-memory/willow-mcp",
                                   nestor_db=Path("/dev/null"))


# -- ENORULING: the gate -------------------------------------------------------

def test_check_merge_refuses_enoruling_while_unsealed(checkout):
    config = _config(checkout)
    ledger = _FakeLedger(_pull_receipt(checkout))
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(), store=_FakeStore(None))
    assert out == {"ok": False, "act": False, "error": "ENORULING",
                   "reason": out["reason"]}
    assert "e961aff8" in out["reason"]


def test_check_merge_refuses_enoruling_when_proposed_not_sealed(checkout):
    config = _config(checkout)
    ledger = _FakeLedger(_pull_receipt(checkout))
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(), store=_FakeStore("proposed"))
    assert out["error"] == "ENORULING"


# -- ENOTMASTER -----------------------------------------------------------------

def test_check_merge_refuses_enotmaster(checkout):
    config = _config(checkout)
    ledger = _FakeLedger(_pull_receipt(checkout))
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(branch="feat/x"),
                               store=_FakeStore("sealed"))
    assert out["error"] == "ENOTMASTER"


# -- ENORECEIPT / EALREADY -------------------------------------------------------

def test_check_merge_refuses_enoreceipt_with_no_pull_receipt(checkout):
    config = _config(checkout)
    ledger = _FakeLedger(None)
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(), store=_FakeStore("sealed"))
    assert out["error"] == "ENORECEIPT"


def test_check_merge_refuses_ealready_when_unit_already_active_since_receipt(checkout):
    config = _config(checkout)
    ledger = _FakeLedger(_pull_receipt(checkout))
    git = _Git(active_enter="Mon 2026-09-17 10:00:00 UTC")  # after the receipt's _AT
    out = reloader.check_merge(config, ledger=ledger, runner=git, store=_FakeStore("sealed"))
    assert out["error"] == "EALREADY"


def test_check_merge_refuses_ealready_when_receipt_already_consumed(checkout):
    config = _config(checkout)
    receipt = _pull_receipt(checkout)
    ledger = _FakeLedger(receipt)
    ledger.append("willow-mcp", reloader.MERGE_EVENT, {
        "repo": config.repo, "checkout": str(checkout), "pull_receipt_id": receipt["id"],
    })
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(), store=_FakeStore("sealed"))
    assert out["error"] == "EALREADY"


# -- ENOTMERGED (after != remote_sha) -------------------------------------------

def test_check_merge_refuses_enotmerged_when_after_neq_remote_sha(checkout):
    config = _config(checkout)
    ledger = _FakeLedger(_pull_receipt(checkout, after="cafef00d", remote_sha="deadbeef"))
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(), store=_FakeStore("sealed"))
    assert out["error"] == "ENOTMERGED"


# -- EDRIFT ----------------------------------------------------------------------

def test_check_merge_refuses_edrift_when_head_moved_again(checkout):
    config = _config(checkout)
    ledger = _FakeLedger(_pull_receipt(checkout, after="cafef00d"))
    git = _Git(head="newerhead")
    out = reloader.check_merge(config, ledger=ledger, runner=git, store=_FakeStore("sealed"))
    assert out["error"] == "EDRIFT"


# -- EUNREACH (token mint) -------------------------------------------------------

def test_check_merge_refuses_eunreach_when_token_mint_fails(checkout):
    config = _config(checkout)
    ledger = _FakeLedger(_pull_receipt(checkout))
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(), store=_FakeStore("sealed"),
                               token_minter=_minter(ok=False))
    assert out["error"] == "EUNREACH"


def test_check_merge_refuses_eunreach_when_checks_permission_absent(checkout):
    config = _config(checkout)
    ledger = _FakeLedger(_pull_receipt(checkout))
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(), store=_FakeStore("sealed"),
                               token_minter=_minter(permissions={}))
    assert out["error"] == "EUNREACH"


# -- ENOTMERGED (no PR found) / EUNREACH (github read) --------------------------

def test_check_merge_refuses_enotmerged_when_no_pr_names_the_sha(checkout):
    config = _config(checkout)
    ledger = _FakeLedger(_pull_receipt(checkout))
    api = _api(pr_response=_pr_empty())
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(), store=_FakeStore("sealed"),
                               api=api, token_minter=_minter())
    assert out["error"] == "ENOTMERGED"


def test_check_merge_refuses_eunreach_when_github_pr_lookup_fails(checkout):
    config = _config(checkout)
    ledger = _FakeLedger(_pull_receipt(checkout))
    api = _api(pr_response={"ok": False, "status": 0, "reason": "timeout"})
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(), store=_FakeStore("sealed"),
                               api=api, token_minter=_minter())
    assert out["error"] == "EUNREACH"


# -- ECHECKS ----------------------------------------------------------------------

def test_check_merge_refuses_echecks_when_a_run_is_not_conclusive(checkout):
    config = _config(checkout)
    ledger = _FakeLedger(_pull_receipt(checkout))
    api = _api(pr_response=_pr_ok(), checks_response=_checks_ok(
        runs=[{"id": 1, "name": "test", "status": "in_progress", "conclusion": None,
               "output": {}, "app": {}}]))
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(), store=_FakeStore("sealed"),
                               api=api, token_minter=_minter())
    assert out["error"] == "ECHECKS"


def test_check_merge_refuses_echecks_when_a_run_failed(checkout):
    config = _config(checkout)
    ledger = _FakeLedger(_pull_receipt(checkout))
    api = _api(pr_response=_pr_ok(), checks_response=_checks_ok(
        runs=[{"id": 1, "name": "test", "status": "completed", "conclusion": "failure",
               "output": {}, "app": {}}]))
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(), store=_FakeStore("sealed"),
                               api=api, token_minter=_minter())
    assert out["error"] == "ECHECKS"


def test_check_merge_refuses_eunreach_when_github_checks_lookup_fails(checkout):
    config = _config(checkout)
    ledger = _FakeLedger(_pull_receipt(checkout))
    api = _api(pr_response=_pr_ok(), checks_response={"ok": False, "status": 500, "reason": "boom"})
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(), store=_FakeStore("sealed"),
                               api=api, token_minter=_minter())
    assert out["error"] == "EUNREACH"


# -- act ---------------------------------------------------------------------------

def test_check_merge_acts_when_every_condition_holds(checkout):
    config = _config(checkout)
    ledger = _FakeLedger(_pull_receipt(checkout))
    api = _api(pr_response=_pr_ok(number=99), checks_response=_checks_ok())
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(), store=_FakeStore("sealed"),
                               api=api, token_minter=_minter())
    assert out["ok"] is True and out["act"] is True
    assert out["pr_number"] == 99
    assert out["head"] == "cafef00d"
    assert out["receipt_id"] == "pull-1"
    assert out["check_summary"] == {"runs": 1}


# -- run_once_v2: dispatch and the act/receipt shape ------------------------------

def test_run_once_v2_falls_back_to_run_once_while_unsealed(checkout, monkeypatch):
    config = _config(checkout)
    ledger = _FakeLedger(_pull_receipt(checkout))
    called = {}

    def fake_run_once(cfg, *, ledger, runner=None, project="willow-mcp"):
        called["hit"] = True
        return {"ok": False, "act": False, "error": "ENORECEIPT", "reason": "x", "reloaded": False}

    monkeypatch.setattr(reloader, "run_once", fake_run_once)
    out = reloader.run_once_v2(config, ledger=ledger, runner=_Git(), store=_FakeStore(None))
    assert called.get("hit") is True
    assert out["error"] == "ENORECEIPT"


def test_run_once_v2_restarts_and_writes_merge_receipt_when_sealed_and_due(checkout):
    config = _config(checkout)
    ledger = _FakeLedger(_pull_receipt(checkout))
    api = _api(pr_response=_pr_ok(number=7), checks_response=_checks_ok())
    git = _Git()
    out = reloader.run_once_v2(config, ledger=ledger, runner=git, store=_FakeStore("sealed"),
                               api=api, token_minter=_minter())
    assert out["reloaded"] is True
    assert "merge" in out["triggers"]
    assert git.restarts, "systemctl restart was never called"
    rows = ledger._rows.get(reloader.MERGE_EVENT, [])
    assert len(rows) == 1
    assert rows[0]["content"]["pull_receipt_id"] == "pull-1"
    assert rows[0]["content"]["pr_number"] == 7


def test_run_once_v2_never_restarts_twice_for_the_same_receipt(checkout):
    config = _config(checkout)
    receipt = _pull_receipt(checkout)
    ledger = _FakeLedger(receipt)
    api = _api(pr_response=_pr_ok(), checks_response=_checks_ok())
    git = _Git()
    first = reloader.run_once_v2(config, ledger=ledger, runner=git, store=_FakeStore("sealed"),
                                 api=api, token_minter=_minter())
    assert first["reloaded"] is True
    second = reloader.run_once_v2(config, ledger=ledger, runner=git, store=_FakeStore("sealed"),
                                  api=api, token_minter=_minter())
    assert second.get("reloaded") is not True
    assert len(git.restarts) == 1


def test_run_once_v2_writes_a_refusal_receipt_naming_the_reason_code(checkout):
    config = _config(checkout)
    ledger = _FakeLedger(None)  # ENORECEIPT
    out = reloader.run_once_v2(config, ledger=ledger, runner=_Git(), store=_FakeStore("sealed"))
    assert out["error"] == "ENORECEIPT"
    rows = ledger._rows.get(reloader.MERGE_REFUSAL_EVENT, [])
    assert len(rows) == 1
    assert rows[0]["content"]["error"] == "ENORECEIPT"
