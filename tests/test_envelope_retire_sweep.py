"""Tests for willow_mcp.envelope_retire_sweep (sealed pair 83faa340)."""
from __future__ import annotations

from willow_mcp import envelope_retire_sweep as sweep_mod


VERBS_BY_ID = {
    2: {"id": 2, "verb": "git.commit", "bounds": {"repo": "s", "branches": "l"}},
    3: {"id": 3, "verb": "git.push", "bounds": {"repo": "s", "branches": "l", "remote": "s", "force": "b"}},
    4: {"id": 4, "verb": "pr.open", "bounds": {"repo": "s", "base_branches": "l"}},
    13: {"id": 13, "verb": "envelope.apply", "bounds": {}},
}


def _row(**over):
    row = {
        "id": "env-1",
        "verb": "git.push",
        "grantee": "willow",
        "bounds": {"repo": "org/repo", "branches": ["feat/meter"], "remote": "origin", "force": False},
        "max_count": None,
        "status": "active",
    }
    row.update(over)
    return row


class _FakeLedger:
    def __init__(self, counts=None):
        self.counts = counts or {}
        self.appended = []

    def citation_count(self, envelope_id):
        return self.counts.get(envelope_id, 0)

    def append(self, project, event_type, content):
        self.appended.append((project, event_type, content))
        return f"ledger-{len(self.appended)}"


def _fake_api(responses):
    """`responses` maps 'METHOD url-fragment' -> {ok, status, body}. The
    fragment is matched by substring so tests don't need the exact query
    string."""
    calls = []

    def api(method, url, *, bearer, body=None):
        calls.append((method, url))
        for frag, resp in responses.items():
            if frag in f"{method} {url}":
                return resp
        return {"ok": False, "status": 404, "reason": "unmapped in test fake"}

    api.calls = calls
    return api


def _monkeypatch_mint(monkeypatch, *, ok=True, token="tok"):
    from willow_mcp import github_app_credentials as gac

    def fake_mint(repo):
        if ok:
            return {"ok": True, "mode": "app", "token": token}
        return {"ok": False, "mode": "unavailable", "reason": "no creds in test"}

    monkeypatch.setattr(gac, "mint_installation_token", fake_mint)


# --------------------------------------------------------------------------
# classify()
# --------------------------------------------------------------------------

def test_classify_branch_bound_git_push():
    row = _row()
    out = sweep_mod.classify(row)
    assert out == {"class": "branch_bound", "repo": "org/repo", "branch": "feat/meter"}


def test_classify_branch_bound_pr_open_uses_base_branches():
    row = _row(verb="pr.open", bounds={"repo": "org/repo", "base_branches": ["feat/meter"]})
    out = sweep_mod.classify(row)
    assert out == {"class": "branch_bound", "repo": "org/repo", "branch": "feat/meter"}


def test_classify_counted():
    # max_count is checked before branch-bound: a row carrying BOTH a
    # literal branch and max_count is countable regardless of verb.
    row = _row(max_count=5)
    out = sweep_mod.classify(row)
    assert out == {"class": "counted", "max_count": 5}


def test_classify_standing_no_branch_no_max_count():
    row = _row(verb="envelope.apply", bounds={})
    out = sweep_mod.classify(row)
    assert out == {"class": "standing"}


def test_classify_glob_branches_is_standing():
    row = _row(bounds={"repo": "org/repo", "branches": ["feat/*"], "remote": "origin", "force": False})
    out = sweep_mod.classify(row)
    assert out == {"class": "standing"}


def test_classify_multiple_branches_is_standing():
    row = _row(bounds={"repo": "org/repo", "branches": ["a", "b"], "remote": "origin", "force": False})
    out = sweep_mod.classify(row)
    assert out == {"class": "standing"}


def test_classify_counted_wins_when_branch_absent_but_max_count_set():
    row = _row(verb="envelope.apply", bounds={}, max_count=3)
    out = sweep_mod.classify(row)
    assert out == {"class": "counted", "max_count": 3}


# --------------------------------------------------------------------------
# sweep()
# --------------------------------------------------------------------------

def _registry(rows):
    return {"active": rows, "proposals": []}


def test_sweep_empty_registry_reports_empty():
    receipt = sweep_mod.sweep(dry_run=True, registry=_registry([]), api=_fake_api({}))
    assert receipt["state"] == "empty"
    assert receipt["examined"] == 0


def test_sweep_standing_row_is_kept_standing_and_untouched():
    row = _row(verb="envelope.apply", bounds={})
    reg = _registry([row])
    receipt = sweep_mod.sweep(dry_run=True, registry=reg, api=_fake_api({}))
    assert receipt["kept_standing"] == 1
    assert receipt["retired"] == []
    assert row.get("status") == "active"


def test_sweep_branch_gone_and_merged_retires_dry_run(monkeypatch):
    _monkeypatch_mint(monkeypatch)
    row = _row()
    reg = _registry([row])
    api = _fake_api({
        "GET https://api.github.com/repos/org/repo/branches/feat/meter":
            {"ok": False, "status": 404, "reason": "Not Found"},
        "GET https://api.github.com/repos/org/repo/pulls?head=org:feat/meter":
            {"ok": True, "status": 200, "body": [{"number": 1, "merged_at": "2026-09-03T00:00:00Z"}]},
    })
    receipt = sweep_mod.sweep(dry_run=True, registry=reg, api=api, ledger=_FakeLedger())
    assert receipt["dry_run"] is True
    assert len(receipt["retired"]) == 1
    assert receipt["retired"][0] == {
        "id": "env-1", "verb": "git.push", "reason": "branch_gone",
        "repo": "org/repo", "branch": "feat/meter",
    }
    # dry run: registry untouched
    assert row.get("status") == "active"
    assert row.get("revoked") is not True


def test_sweep_branch_gone_and_merged_retires_live(monkeypatch):
    _monkeypatch_mint(monkeypatch)
    row = _row()
    reg = _registry([row])
    api = _fake_api({
        "GET https://api.github.com/repos/org/repo/branches/feat/meter":
            {"ok": False, "status": 404, "reason": "Not Found"},
        "GET https://api.github.com/repos/org/repo/pulls?head=org:feat/meter":
            {"ok": True, "status": 200, "body": [{"number": 1, "merged_at": "2026-09-03T00:00:00Z"}]},
    })
    ledger = _FakeLedger()
    receipt = sweep_mod.sweep(dry_run=False, actor="willow-mcp-sweep", registry=reg, api=api, ledger=ledger)
    assert len(receipt["retired"]) == 1
    assert row["status"] == "revoked"
    assert row["revoked"] is True
    assert row["revoked_reason"] == "branch_gone"
    assert row["revoked_by"] == "willow-mcp-sweep"
    assert row["revoked_at"]
    assert len(ledger.appended) == 1
    project, event_type, content = ledger.appended[0]
    assert event_type == "envelope_revoked"
    assert content["envelope_id"] == "env-1"
    assert content["reason"] == "branch_gone"
    # proposals[] untouched, row never deleted
    assert reg["proposals"] == []
    assert reg["active"] == [row]


def test_sweep_branch_absent_but_unmerged_is_kept_in_force(monkeypatch):
    _monkeypatch_mint(monkeypatch)
    row = _row()
    reg = _registry([row])
    api = _fake_api({
        "GET https://api.github.com/repos/org/repo/branches/feat/meter":
            {"ok": False, "status": 404, "reason": "Not Found"},
        "GET https://api.github.com/repos/org/repo/pulls?head=org:feat/meter":
            {"ok": True, "status": 200, "body": [{"number": 1, "merged_at": None}]},
    })
    receipt = sweep_mod.sweep(dry_run=True, registry=reg, api=api)
    assert receipt["retired"] == []
    assert len(receipt["kept_in_force"]) == 1
    assert receipt["kept_in_force"][0]["id"] == "env-1"


def test_sweep_branch_still_present_is_kept_in_force(monkeypatch):
    _monkeypatch_mint(monkeypatch)
    row = _row()
    reg = _registry([row])
    api = _fake_api({
        "GET https://api.github.com/repos/org/repo/branches/feat/meter":
            {"ok": True, "status": 200, "body": {"name": "feat/meter"}},
    })
    receipt = sweep_mod.sweep(dry_run=True, registry=reg, api=api)
    assert receipt["retired"] == []
    assert len(receipt["kept_in_force"]) == 1


def test_sweep_unreachable_remote_leaves_row_and_says_so(monkeypatch):
    _monkeypatch_mint(monkeypatch)
    row = _row()
    reg = _registry([row])
    api = _fake_api({
        "GET https://api.github.com/repos/org/repo/branches/feat/meter":
            {"ok": False, "status": 500, "reason": "server error"},
    })
    receipt = sweep_mod.sweep(dry_run=True, registry=reg, api=api)
    assert receipt["retired"] == []
    assert len(receipt["unreachable"]) == 1
    assert receipt["unreachable"][0]["id"] == "env-1"
    assert row.get("status") == "active"


def test_sweep_unreachable_when_token_mint_fails(monkeypatch):
    _monkeypatch_mint(monkeypatch, ok=False)
    row = _row()
    reg = _registry([row])
    receipt = sweep_mod.sweep(dry_run=True, registry=reg, api=_fake_api({}))
    assert receipt["retired"] == []
    assert len(receipt["unreachable"]) == 1


def test_sweep_counted_row_retires_when_spent():
    row = _row(verb="pr.open", bounds={"repo": "org/repo", "base_branches": ["master"]}, max_count=2)
    reg = _registry([row])
    ledger = _FakeLedger(counts={"env-1": 2})
    receipt = sweep_mod.sweep(dry_run=False, registry=reg, api=_fake_api({}), ledger=ledger)
    assert len(receipt["retired"]) == 1
    assert receipt["retired"][0]["reason"] == "spent"
    assert row["status"] == "revoked"
    assert row["revoked_reason"] == "spent"


def test_sweep_counted_row_kept_when_not_spent():
    row = _row(verb="pr.open", bounds={"repo": "org/repo", "base_branches": ["master"]}, max_count=5)
    reg = _registry([row])
    ledger = _FakeLedger(counts={"env-1": 2})
    receipt = sweep_mod.sweep(dry_run=True, registry=reg, api=_fake_api({}), ledger=ledger)
    assert receipt["retired"] == []
    assert len(receipt["kept_in_force"]) == 1


def test_sweep_counted_row_unreachable_without_ledger():
    row = _row(verb="pr.open", bounds={"repo": "org/repo", "base_branches": ["master"]}, max_count=5)
    reg = _registry([row])
    receipt = sweep_mod.sweep(dry_run=True, registry=reg, api=_fake_api({}), ledger=None)
    assert receipt["retired"] == []
    assert len(receipt["unreachable"]) == 1


def test_sweep_already_revoked_rows_are_skipped():
    row = _row(status="revoked", revoked=True)
    reg = _registry([row])
    receipt = sweep_mod.sweep(dry_run=True, registry=reg, api=_fake_api({}))
    assert receipt["examined"] == 0
    assert receipt["state"] == "empty"


def test_sweep_registry_unreadable_reports_unreachable(monkeypatch):
    from willow_mcp import envelope_authoring as authoring

    def boom():
        raise OSError("registry gone")

    monkeypatch.setattr(authoring, "_load_registry", boom)
    receipt = sweep_mod.sweep(dry_run=True, api=_fake_api({}))
    assert receipt["state"] == "unreachable"
    assert "registry_unreadable" in receipt["reason"]
    assert receipt["examined"] == 0


def test_sweep_never_touches_proposals():
    row = _row()
    reg = {"active": [row], "proposals": [{"id": "prop-1", "status": "proposed"}]}
    ledger = _FakeLedger()
    api = _fake_api({
        "GET https://api.github.com/repos/org/repo/branches/feat/meter":
            {"ok": True, "status": 200, "body": {"name": "feat/meter"}},
    })
    sweep_mod.sweep(dry_run=False, registry=reg, api=api, ledger=ledger)
    assert reg["proposals"] == [{"id": "prop-1", "status": "proposed"}]


def test_envelope_retire_sweep_is_gated_by_its_own_name():
    from willow_mcp import server

    catalogue = server._gate_tool_catalogue()
    assert catalogue["envelope_retire_sweep"] == "envelope_retire_sweep"


def test_envelope_retire_sweep_tool_in_governance_sync_and_full_access():
    from willow_mcp import gate

    assert "envelope_retire_sweep" in gate.PERMISSION_GROUPS["governance_sync"]
    assert "envelope_retire_sweep" in gate.PERMISSION_GROUPS["full_access"]


def test_sweep_mixed_registry_counts_all_classes(monkeypatch):
    _monkeypatch_mint(monkeypatch)
    standing = _row(id="env-standing", verb="envelope.apply", bounds={})
    branch_bound_retire = _row(id="env-retire")
    counted_spent = _row(id="env-counted", verb="pr.open",
                         bounds={"repo": "org/repo", "base_branches": ["master"]}, max_count=1)
    reg = _registry([standing, branch_bound_retire, counted_spent])
    api = _fake_api({
        "GET https://api.github.com/repos/org/repo/branches/feat/meter":
            {"ok": False, "status": 404, "reason": "Not Found"},
        "GET https://api.github.com/repos/org/repo/pulls?head=org:feat/meter":
            {"ok": True, "status": 200, "body": [{"number": 1, "merged_at": "2026-09-03T00:00:00Z"}]},
    })
    ledger = _FakeLedger(counts={"env-counted": 1})
    receipt = sweep_mod.sweep(dry_run=True, registry=reg, api=api, ledger=ledger)
    assert receipt["examined"] == 3
    assert receipt["kept_standing"] == 1
    assert len(receipt["retired"]) == 2
    assert {r["id"] for r in receipt["retired"]} == {"env-retire", "env-counted"}
    assert receipt["state"] == "populated"
