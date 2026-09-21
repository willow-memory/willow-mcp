"""Gap 4464a63db1a9 (apk/keyboard-act): a missing GitHub App permission files
ONE named human_required item — deduped on (permission, level) while an open
item exists — beside the verb's unchanged ``permission_absent`` refusal.
"""
from __future__ import annotations

from willow_mcp import github_app_permissions as gap_
from willow_mcp import human_loop, pr_checks
from willow_mcp.db import Store

from tests.test_pr_checks import _FakeApi, _app_token, _read

_RED_RUN = {
    "id": 2, "name": "test", "status": "completed", "conclusion": "failure",
    "html_url": "https://github.com/forge-play/Forge/actions/runs/9/job/91",
    "details_url": "https://github.com/forge-play/Forge/actions/runs/9/job/91",
    "app": {"slug": "github-actions"}, "started_at": "t0", "completed_at": "t1",
    "output": {"title": "failed", "summary": "boom", "text": "boom"},
}


def _store(tmp_path):
    return Store(str(tmp_path / "store"))


def _open_titles(store):
    return [i["title"] for i in human_loop.list_queue(store, status="open", kind="onboarding")]


# ── the helper ────────────────────────────────────────────────────────────────

def test_files_one_named_onboarding_item(home, tmp_path):
    store = _store(tmp_path)
    out = gap_.file_permission_ask(store, app_id="willow", verb="pr_checks_read",
                                   repo="forge-play/Forge", permission="actions", level="read")
    assert out["state"] == "filed" and out["human_required_id"]
    items = human_loop.list_queue(store, status="open", kind="onboarding")
    assert len(items) == 1
    item = items[0]
    assert item["title"] == "GitHub App: grant actions:read to willows-bot"
    assert "pr_checks_read on forge-play/Forge" in item["summary"]
    assert "App settings → Permissions & events → Repository permissions → Actions → Read-only" in item["summary"]
    assert "approve the updated permissions in each org's Installed GitHub Apps" in item["summary"]
    assert item["source_agent"] == "willow"
    assert item["source_ref"] == "pr_checks_read:forge-play/Forge:actions"


def test_two_verbs_same_permission_file_once(home, tmp_path):
    store = _store(tmp_path)
    a = gap_.file_permission_ask(store, app_id="willow", verb="pr_checks_read",
                                 repo="forge-play/Forge", permission="actions")
    b = gap_.file_permission_ask(store, app_id="willow", verb="pr_open_execute",
                                 repo="willow-memory/ratatosk", permission="actions")
    assert a["state"] == "filed"
    assert b["state"] == "already" and b["human_required_id"] == a["human_required_id"]
    assert _open_titles(store) == ["GitHub App: grant actions:read to willows-bot"]


def test_different_level_is_a_different_item(home, tmp_path):
    store = _store(tmp_path)
    gap_.file_permission_ask(store, app_id="willow", verb="v", repo="o/r",
                             permission="contents", level="read")
    out = gap_.file_permission_ask(store, app_id="willow", verb="v", repo="o/r",
                                   permission="contents", level="write")
    assert out["state"] == "filed"
    assert len(_open_titles(store)) == 2


def test_resolved_item_allows_a_new_filing(home, tmp_path):
    store = _store(tmp_path)
    first = gap_.file_permission_ask(store, app_id="willow", verb="v", repo="o/r",
                                     permission="actions")
    human_loop.resolve(store, first["human_required_id"], resolved_by="sean campbell",
                       status="resolved", note="granted")
    second = gap_.file_permission_ask(store, app_id="willow", verb="v", repo="o/r",
                                      permission="actions")
    assert second["state"] == "filed"
    assert second["human_required_id"] != first["human_required_id"]


def test_unwritable_queue_is_unreachable_not_a_crash(home):
    class _Broken:
        def __getattr__(self, name):  # every store method: the disk is gone
            def _boom(*a, **k):
                raise RuntimeError("disk gone")
            return _boom

    out = gap_.file_permission_ask(_Broken(), app_id="willow", verb="v", repo="o/r",
                                   permission="actions")
    assert out["state"] == "unreachable" and "disk gone" in out["reason"]


def test_no_permission_named_is_unreachable(home, tmp_path):
    out = gap_.file_permission_ask(_store(tmp_path), app_id="willow", verb="v", repo="o/r",
                                   permission="")
    assert out["state"] == "unreachable"


# ── wired into pr_checks_read ─────────────────────────────────────────────────

def test_pr_checks_actions_absent_files_once_and_keeps_its_shape(home, tmp_path, monkeypatch):
    store = _store(tmp_path)
    _app_token(monkeypatch, checks="read", actions="")
    api = _FakeApi(runs=[_RED_RUN, {**_RED_RUN, "id": 3, "name": "lint"}])
    out = _read(api, store=store)
    # the verb's own return is unchanged …
    assert out["state"] == "populated"
    assert out["check_runs"][0]["log_tail"] == {
        "state": "unreachable", "reason": "permission_absent", "permission": "actions"}
    assert out["red"][0]["first_error_line"] == "(log unreachable: permission_absent: actions)"
    # … plus the item id, filed once for two failing runs
    assert out["human_required_state"] == "filed" and out["human_required_id"]
    assert _open_titles(store) == ["GitHub App: grant actions:read to willows-bot"]
    # a second read while the item is open does not file again
    again = _read(_FakeApi(runs=[_RED_RUN]), store=store)
    assert again["human_required_state"] == "already"
    assert again["human_required_id"] == out["human_required_id"]


def test_pr_checks_checks_absent_files_and_keeps_its_shape(home, tmp_path, monkeypatch):
    store = _store(tmp_path)
    _app_token(monkeypatch, checks="", actions="read")
    out = _read(_FakeApi(), store=store)
    assert out["state"] == "unreachable" and out["reason"] == "permission_absent"
    assert out["permission"] == "checks"
    assert out["human_required_state"] == "filed"
    assert _open_titles(store) == ["GitHub App: grant checks:read to willows-bot"]


def test_pr_checks_without_a_store_still_answers(home, monkeypatch):
    """No store (a bare library call): the verb answers, the ask is
    unreachable, nothing raises."""
    _app_token(monkeypatch, checks="", actions="read")
    out = pr_checks.read_pr_checks("willow", repo="forge-play/Forge", pr=31, api=_FakeApi())
    assert out["reason"] == "permission_absent"
    assert out["human_required_state"] == "unreachable"
    assert "human_required_id" not in out
