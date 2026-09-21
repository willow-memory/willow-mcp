"""Tests for willow_mcp.envelope_retire_sweep (sealed pair 83faa340).

Rework of BAA43543/#615 per Loki's findings (dispatch 9494D3AF): a
clobbering whole-registry write, pr.open misclassified as branch-bound to
its base, no bound against the steward's 90s call budget, no EREGISTRY
guard, a FRANK-before-registry write ordering, an uncounted
use_count_source, and the tick misattributing itself to the caller's
app_id.
"""
from __future__ import annotations

from contextlib import nullcontext

import pytest

from willow_mcp import envelope_retire_sweep as sweep_mod


@pytest.fixture(autouse=True)
def _no_real_cursor_file(monkeypatch):
    """Every test that does not explicitly inject read_cursor/write_cursor
    gets a no-op cursor (always absent, writes always "succeed" without
    touching disk) — otherwise sweep()'s default file-backed cursor would
    read/write a real file under paths.store_root() and leak state between
    tests (and between this test module and a live box). Tests of the
    cursor itself override both params explicitly, which wins over this
    patch."""
    monkeypatch.setattr(sweep_mod, "_read_cursor_state", lambda: ("", "absent"))
    monkeypatch.setattr(sweep_mod, "_write_cursor", lambda envelope_id: True)


def _row(**over):
    row = {
        "id": "env-1",
        "verb": "git.push",
        "grantee": "willow",
        "bounds": {"repo": "org/repo", "branches": ["feat/meter"], "remote": "origin", "force": False},
        "max_count": None,
        "use_count_source": "frank",
        "status": "active",
    }
    row.update(over)
    return row


class _FakeLedger:
    def __init__(self, counts=None):
        self.counts = counts or {}
        self.appended = []
        self.events = []  # shared ordering log; append(("ledger", ...)) entries land here

    def citation_count(self, envelope_id):
        return self.counts.get(envelope_id, 0)

    def append(self, project, event_type, content):
        self.appended.append((project, event_type, content))
        self.events.append("ledger")
        return f"ledger-{len(self.appended)}"


def _fake_api(responses):
    """`responses` maps 'METHOD url-fragment' -> {ok, status, body}. The
    fragment is matched by substring so tests don't need the exact query
    string."""
    calls = []

    def api(method, url, *, bearer, body=None, timeout=20):
        calls.append((method, url, timeout))
        for frag, resp in responses.items():
            if frag in f"{method} {url}":
                return resp
        return {"ok": False, "status": 404, "reason": "unmapped in test fake"}

    api.calls = calls
    return api


def _monkeypatch_mint(monkeypatch, *, ok=True, token="tok"):
    from willow_mcp import github_app_credentials as gac

    def fake_mint(repo, timeout=20):
        if ok:
            return {"ok": True, "mode": "app", "token": token}
        return {"ok": False, "mode": "unavailable", "reason": "no creds in test"}

    monkeypatch.setattr(gac, "mint_installation_token", fake_mint)


def _null_lock(path):
    return nullcontext()


class _Backend:
    """A fake on-disk registry: `store` is the ground truth `reload()`
    reads fresh each call (simulating a re-read from the JSON file) and
    `write()` replaces; deep-ish copies on both sides so aliasing with a
    caller-held snapshot never hides a bug. `events` (when given) records
    "write"/"ledger" in call order, for ordering assertions."""

    def __init__(self, active, proposals=None, events=None):
        self.store = {"active": [dict(r) for r in active], "proposals": list(proposals or [])}
        self.events = events

    def reload(self):
        return {"active": [dict(r) for r in self.store["active"]],
                "proposals": list(self.store["proposals"])}

    def write(self, doc):
        self.store["active"] = list(doc.get("active") or [])
        self.store["proposals"] = list(doc.get("proposals") or self.store["proposals"])
        if self.events is not None:
            self.events.append("write")

    def snapshot(self):
        """A classification-time registry snapshot — a separate copy, same
        shape reload() would have returned at call time."""
        return self.reload()


# --------------------------------------------------------------------------
# classify()
# --------------------------------------------------------------------------

def test_classify_branch_bound_git_push():
    row = _row()
    out = sweep_mod.classify(row)
    assert out == {"class": "branch_bound", "repo": "org/repo", "branch": "feat/meter"}


def test_classify_pr_open_base_branches_is_never_branch_bound():
    """Rework of Loki's MEDIUM finding: pr.open's only branch-shaped bound
    (`base_branches`) names the MERGE TARGET, not the feature branch the
    envelope was cut for — treating it as branch-bound made every live
    pr.open row look "bound to master", probed every tick and never
    retirable. A pr.open row with no max_count is standing."""
    row = _row(verb="pr.open", bounds={"repo": "org/repo", "base_branches": ["master"]})
    out = sweep_mod.classify(row)
    assert out == {"class": "standing"}
    assert "pr.open" not in sweep_mod.BRANCH_BOUND_KEY


def test_classify_pr_open_with_max_count_is_counted():
    row = _row(verb="pr.open", bounds={"repo": "org/repo", "base_branches": ["master"]}, max_count=3)
    out = sweep_mod.classify(row)
    assert out == {"class": "counted", "max_count": 3, "use_count_source": "frank"}


def test_classify_counted():
    # max_count is checked before branch-bound: a row carrying BOTH a
    # literal branch and max_count is countable regardless of verb.
    row = _row(max_count=5)
    out = sweep_mod.classify(row)
    assert out == {"class": "counted", "max_count": 5, "use_count_source": "frank"}


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
    assert out == {"class": "counted", "max_count": 3, "use_count_source": "frank"}


# --------------------------------------------------------------------------
# sweep() — dry run / classification-only paths (registry snapshot only,
# no reload/write backend needed since nothing is written)
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
    # dry run: no lock/reload/write path is ever touched
    assert row.get("status") == "active"
    assert row.get("revoked") is not True


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


def test_sweep_counted_row_kept_when_not_spent():
    row = _row(max_count=5)
    reg = _registry([row])
    ledger = _FakeLedger(counts={"env-1": 2})
    receipt = sweep_mod.sweep(dry_run=True, registry=reg, api=_fake_api({}), ledger=ledger)
    assert receipt["retired"] == []
    assert len(receipt["kept_in_force"]) == 1


def test_sweep_counted_row_unreachable_without_ledger():
    row = _row(max_count=5)
    reg = _registry([row])
    receipt = sweep_mod.sweep(dry_run=True, registry=reg, api=_fake_api({}), ledger=None)
    assert receipt["retired"] == []
    assert len(receipt["unreachable"]) == 1


def test_sweep_counted_row_with_untrusted_source_is_unreachable_not_counted():
    """Rework of Loki's LOW finding: a row proposed with a use_count_source
    other than "frank" must not be silently metered against FRANK anyway."""
    row = _row(max_count=1, use_count_source="something_else")
    reg = _registry([row])
    ledger = _FakeLedger(counts={"env-1": 99})
    receipt = sweep_mod.sweep(dry_run=True, registry=reg, api=_fake_api({}), ledger=ledger)
    assert receipt["retired"] == []
    assert len(receipt["unreachable"]) == 1
    assert "use_count_source" in receipt["unreachable"][0]["why"]


def test_sweep_already_revoked_rows_are_skipped():
    row = _row(status="revoked", revoked=True)
    reg = _registry([row])
    receipt = sweep_mod.sweep(dry_run=True, registry=reg, api=_fake_api({}))
    assert receipt["examined"] == 0
    assert receipt["state"] == "empty"


def test_sweep_registry_unreadable_reports_unreachable(monkeypatch):
    from willow_mcp import envelope_authoring as authoring

    monkeypatch.setattr(authoring, "registry_mismatch", lambda: None)

    def boom():
        raise OSError("registry gone")

    monkeypatch.setattr(authoring, "_load_registry", boom)
    receipt = sweep_mod.sweep(dry_run=True, api=_fake_api({}))
    assert receipt["state"] == "unreachable"
    assert "registry_unreadable" in receipt["reason"]
    assert receipt["examined"] == 0


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
    counted_spent = _row(id="env-counted", max_count=1)
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


# --------------------------------------------------------------------------
# EREGISTRY guard (rework of Loki's MEDIUM finding)
# --------------------------------------------------------------------------

def test_sweep_refuses_eregistry_before_any_read(monkeypatch):
    from willow_mcp import envelope_authoring as authoring

    detail = {
        "error": "EREGISTRY", "resolved": "/tmp/other/pre-approved.json",
        "expected": "/tmp/home/constitutional/pre-approved.json",
        "steered_by": "WILLOW_ENVELOPE_REGISTRY",
        "message": "EREGISTRY: this process resolves the envelope registry to "
                   "/tmp/other/pre-approved.json but $WILLOW_HOME names /tmp/home/...",
    }
    monkeypatch.setattr(authoring, "registry_mismatch", lambda: detail)
    loaded = []
    monkeypatch.setattr(authoring, "_load_registry", lambda: loaded.append(1) or {"active": []})
    receipt = sweep_mod.sweep(dry_run=True, api=_fake_api({}))
    assert receipt["state"] == "unreachable"
    assert "EREGISTRY" in receipt["reason"]
    assert receipt["examined"] == 0
    assert loaded == []  # refused BEFORE any registry read


def test_sweep_proceeds_when_registry_matches(monkeypatch):
    from willow_mcp import envelope_authoring as authoring

    monkeypatch.setattr(authoring, "registry_mismatch", lambda: None)
    monkeypatch.setattr(authoring, "_load_registry", lambda: {"active": []})
    receipt = sweep_mod.sweep(dry_run=True, api=_fake_api({}))
    assert receipt["state"] == "empty"


def test_sweep_with_injected_registry_snapshot_skips_eregistry_check(monkeypatch):
    """A test/caller-injected snapshot bypasses live-file resolution
    entirely — the EREGISTRY guard only applies to the live path."""
    from willow_mcp import envelope_authoring as authoring

    def boom():
        raise AssertionError("registry_mismatch must not be called when registry is injected")

    monkeypatch.setattr(authoring, "registry_mismatch", boom)
    receipt = sweep_mod.sweep(dry_run=True, registry=_registry([]), api=_fake_api({}))
    assert receipt["state"] == "empty"


# --------------------------------------------------------------------------
# Concurrency: per-row lock + fresh re-read (rework of Loki's HIGH finding)
# --------------------------------------------------------------------------

def test_live_retirement_preserves_a_proposal_written_after_classification(monkeypatch):
    """The bug Loki's probe (task Y3TVZXUX) found: classify off a
    snapshot, write the WHOLE stale snapshot back at the end -> a proposal
    added after classification vanished. Now the write applies to whatever
    reload() returns at retire time, so a proposal that landed before the
    retire's fresh re-read survives."""
    _monkeypatch_mint(monkeypatch)
    row = _row()
    backend = _Backend([row])
    snapshot = backend.snapshot()  # classification-time view: no proposals yet
    assert snapshot["proposals"] == []
    # Simulate a proposal written to the register before this row's retire
    # actually re-reads (i.e. before _retire_locked's reload()).
    backend.store["proposals"].append({"id": "prop-new", "status": "proposed"})

    api = _fake_api({
        "GET https://api.github.com/repos/org/repo/branches/feat/meter":
            {"ok": False, "status": 404, "reason": "Not Found"},
        "GET https://api.github.com/repos/org/repo/pulls?head=org:feat/meter":
            {"ok": True, "status": 200, "body": [{"number": 1, "merged_at": "2026-09-03T00:00:00Z"}]},
    })
    ledger = _FakeLedger()
    receipt = sweep_mod.sweep(
        dry_run=False, registry=snapshot, api=api, ledger=ledger,
        reload_registry=backend.reload, write_registry=backend.write, lock=_null_lock,
    )
    assert len(receipt["retired"]) == 1
    assert backend.store["proposals"] == [{"id": "prop-new", "status": "proposed"}]
    assert backend.store["active"][0]["status"] == "revoked"


def test_live_retirement_does_not_clobber_a_concurrent_operator_revoke(monkeypatch):
    """The other half of Loki's probe: an operator revoked the row (with
    their own reason/verifier) after classification but before this row's
    retire re-read. The sweep must see that fresh state and leave it
    alone — never overwrite the operator's revoke with its own."""
    _monkeypatch_mint(monkeypatch)
    row = _row()
    backend = _Backend([row])
    snapshot = backend.snapshot()  # classification-time: still active
    # Operator revokes it for an unrelated reason before the retire step's
    # fresh re-read.
    backend.store["active"][0].update(
        status="revoked", revoked=True, revoked_at="2026-09-21T21:00:00Z",
        revoked_by="sean-campbell", revoked_reason="operator manual revoke",
    )
    api = _fake_api({
        "GET https://api.github.com/repos/org/repo/branches/feat/meter":
            {"ok": False, "status": 404, "reason": "Not Found"},
        "GET https://api.github.com/repos/org/repo/pulls?head=org:feat/meter":
            {"ok": True, "status": 200, "body": [{"number": 1, "merged_at": "2026-09-03T00:00:00Z"}]},
    })
    ledger = _FakeLedger()
    receipt = sweep_mod.sweep(
        dry_run=False, registry=snapshot, api=api, ledger=ledger,
        reload_registry=backend.reload, write_registry=backend.write, lock=_null_lock,
    )
    # Not retired a second time by the sweep — reported as kept, not re-clobbered.
    assert receipt["retired"] == []
    assert len(receipt["kept_in_force"]) == 1
    assert "already revoked" in receipt["kept_in_force"][0]["why"]
    # The operator's own fields survive untouched.
    assert backend.store["active"][0]["revoked_by"] == "sean-campbell"
    assert backend.store["active"][0]["revoked_reason"] == "operator manual revoke"
    assert ledger.appended == []  # the sweep never inked its own revoke over theirs


def test_live_retirement_writes_registry_before_appending_frank(monkeypatch):
    """Rework of Loki's LOW ordering finding: a crash between the two
    writes must leave an under-logged retirement (registry says revoked,
    FRANK silent), never an over-logged one."""
    _monkeypatch_mint(monkeypatch)
    row = _row()
    events = []
    backend = _Backend([row], events=events)
    snapshot = backend.snapshot()
    api = _fake_api({
        "GET https://api.github.com/repos/org/repo/branches/feat/meter":
            {"ok": False, "status": 404, "reason": "Not Found"},
        "GET https://api.github.com/repos/org/repo/pulls?head=org:feat/meter":
            {"ok": True, "status": 200, "body": [{"number": 1, "merged_at": "2026-09-03T00:00:00Z"}]},
    })
    ledger = _FakeLedger()
    ledger.events = events
    sweep_mod.sweep(
        dry_run=False, registry=snapshot, api=api, ledger=ledger,
        reload_registry=backend.reload, write_registry=backend.write, lock=_null_lock,
    )
    assert events == ["write", "ledger"]


def test_live_retirement_uses_the_default_actor_not_the_callers_app_id(monkeypatch):
    """Rework of Loki's LOW finding: an unattended tick must name itself,
    not whichever app_id happened to invoke the tool."""
    _monkeypatch_mint(monkeypatch)
    row = _row()
    backend = _Backend([row])
    snapshot = backend.snapshot()
    api = _fake_api({
        "GET https://api.github.com/repos/org/repo/branches/feat/meter":
            {"ok": False, "status": 404, "reason": "Not Found"},
        "GET https://api.github.com/repos/org/repo/pulls?head=org:feat/meter":
            {"ok": True, "status": 200, "body": [{"number": 1, "merged_at": "2026-09-03T00:00:00Z"}]},
    })
    sweep_mod.sweep(
        dry_run=False, registry=snapshot, api=api, ledger=_FakeLedger(),
        reload_registry=backend.reload, write_registry=backend.write, lock=_null_lock,
    )
    assert backend.store["active"][0]["revoked_by"] == sweep_mod.DEFAULT_ACTOR
    assert sweep_mod.DEFAULT_ACTOR != "willow"


def test_live_retirement_never_touches_other_active_rows(monkeypatch):
    """A concurrent unrelated active row change (added by whoever else
    holds the lock next) must ride through the fresh reload() untouched by
    this sweep's write of a different row."""
    _monkeypatch_mint(monkeypatch)
    row = _row()
    other = _row(id="env-other", bounds={"repo": "org/repo", "branches": ["feat/other"],
                                          "remote": "origin", "force": False})
    backend = _Backend([row])
    snapshot = backend.snapshot()
    # A second row appears in the live store before this retire's reload —
    # simulating another process's concurrent write landing mid-sweep.
    backend.store["active"].append(dict(other))
    api = _fake_api({
        "GET https://api.github.com/repos/org/repo/branches/feat/meter":
            {"ok": False, "status": 404, "reason": "Not Found"},
        "GET https://api.github.com/repos/org/repo/pulls?head=org:feat/meter":
            {"ok": True, "status": 200, "body": [{"number": 1, "merged_at": "2026-09-03T00:00:00Z"}]},
    })
    sweep_mod.sweep(
        dry_run=False, registry=snapshot, api=api, ledger=_FakeLedger(),
        reload_registry=backend.reload, write_registry=backend.write, lock=_null_lock,
    )
    ids_and_status = {r["id"]: r["status"] for r in backend.store["active"]}
    assert ids_and_status == {"env-1": "revoked", "env-other": "active"}


def test_sweep_never_touches_proposals_live(monkeypatch):
    _monkeypatch_mint(monkeypatch)
    row = _row()
    backend = _Backend([row], proposals=[{"id": "prop-1", "status": "proposed"}])
    snapshot = backend.snapshot()
    api = _fake_api({
        "GET https://api.github.com/repos/org/repo/branches/feat/meter":
            {"ok": True, "status": 200, "body": {"name": "feat/meter"}},
    })
    sweep_mod.sweep(
        dry_run=False, registry=snapshot, api=api, ledger=_FakeLedger(),
        reload_registry=backend.reload, write_registry=backend.write, lock=_null_lock,
    )
    assert backend.store["proposals"] == [{"id": "prop-1", "status": "proposed"}]


def test_counted_live_retirement_goes_through_the_same_lock_path(monkeypatch):
    row = _row(max_count=2)
    backend = _Backend([row])
    snapshot = backend.snapshot()
    ledger = _FakeLedger(counts={"env-1": 2})
    receipt = sweep_mod.sweep(
        dry_run=False, registry=snapshot, api=_fake_api({}), ledger=ledger,
        reload_registry=backend.reload, write_registry=backend.write, lock=_null_lock,
    )
    assert len(receipt["retired"]) == 1
    assert backend.store["active"][0]["status"] == "revoked"
    assert backend.store["active"][0]["revoked_reason"] == "spent"


# --------------------------------------------------------------------------
# Bounding against the steward's 90s call budget (rework of Loki's MEDIUM
# finding)
# --------------------------------------------------------------------------

def test_sweep_max_rows_bounds_examined_and_sets_truncated():
    rows = [_row(id=f"env-standing-{i}", verb="envelope.apply", bounds={}) for i in range(5)]
    reg = _registry(rows)
    receipt = sweep_mod.sweep(dry_run=True, registry=reg, api=_fake_api({}), max_rows=2)
    assert receipt["examined"] == 2
    assert receipt["kept_standing"] == 2
    assert receipt["truncated"] is True


def test_sweep_max_rows_zero_is_unbounded():
    rows = [_row(id=f"env-standing-{i}", verb="envelope.apply", bounds={}) for i in range(5)]
    reg = _registry(rows)
    receipt = sweep_mod.sweep(dry_run=True, registry=reg, api=_fake_api({}), max_rows=0)
    assert receipt["examined"] == 5
    assert receipt["truncated"] is False


def test_sweep_time_budget_stops_between_rows_and_sets_truncated(monkeypatch):
    rows = [_row(id=f"env-standing-{i}", verb="envelope.apply", bounds={}) for i in range(5)]
    reg = _registry(rows)

    calls = {"n": 0}

    def fake_monotonic():
        calls["n"] += 1
        # First call is the loop's `started` timestamp; every call after
        # the first row makes the budget look already exceeded.
        return 0.0 if calls["n"] <= 2 else 1000.0

    monkeypatch.setattr(sweep_mod.time, "monotonic", fake_monotonic)
    receipt = sweep_mod.sweep(dry_run=True, registry=reg, api=_fake_api({}), time_budget_s=1.0)
    assert receipt["examined"] < 5
    assert receipt["truncated"] is True


def test_sweep_time_budget_zero_means_unbounded_same_as_max_rows():
    """`time_budget_s=0` disables the wall-clock bound entirely, the same
    convention `max_rows=0` uses — an explicit opt-out, not an
    always-already-expired budget that would silently examine nothing."""
    row = _row(max_count=1)
    backend = _Backend([row])
    snapshot = backend.snapshot()
    ledger = _FakeLedger(counts={"env-1": 1})
    receipt = sweep_mod.sweep(
        dry_run=False, registry=snapshot, api=_fake_api({}), ledger=ledger,
        reload_registry=backend.reload, write_registry=backend.write, lock=_null_lock,
        time_budget_s=0.0,
    )
    assert receipt["examined"] == 1
    assert backend.store["active"][0]["status"] == "revoked"


# --------------------------------------------------------------------------
# Cursor: consecutive under-budget calls sweep progressively further
# (rework of Loki's MEDIUM finding, D81165E5)
# --------------------------------------------------------------------------

def _fake_cursor(*, writable=True):
    """An in-memory read/write pair, standing in for the file the real
    default persists to — shared mutable state across calls, same as a
    real file would give across ticks. `read_cursor()` returns `(value,
    state)` and `write_cursor(id)` returns a success bool, matching
    sweep()'s injectable contract. `writable=False` simulates an
    unwritable store root: every write fails and the value never changes."""
    state = {"value": ""}

    def read():
        return (state["value"], "populated") if state["value"] else ("", "absent")

    def write(envelope_id):
        if not writable:
            return False
        state["value"] = envelope_id
        return True

    return read, write


def test_cursor_rotates_so_two_calls_examine_different_prefixes():
    rows = [_row(id=f"env-{i}", verb="envelope.apply", bounds={}) for i in range(5)]
    reg = _registry(rows)
    read_cursor, write_cursor = _fake_cursor()

    r1 = sweep_mod.sweep(dry_run=False, registry=reg, api=_fake_api({}), max_rows=2,
                         read_cursor=read_cursor, write_cursor=write_cursor)
    assert r1["examined"] == 2
    assert r1["truncated"] is True
    assert read_cursor()[0] == "env-1"  # sorted ids env-0..env-4, first 2 examined
    assert r1["cursor"] == {"state": "populated", "value": "env-1"}

    r2 = sweep_mod.sweep(dry_run=False, registry=reg, api=_fake_api({}), max_rows=2,
                         read_cursor=read_cursor, write_cursor=write_cursor)
    assert r2["examined"] == 2
    # second call resumed past env-1, not from the top again
    assert read_cursor()[0] == "env-3"
    assert r2["cursor"] == {"state": "populated", "value": "env-3"}


def test_cursor_wraps_around_after_the_last_row():
    rows = [_row(id=f"env-{i}", verb="envelope.apply", bounds={}) for i in range(3)]
    reg = _registry(rows)
    read_cursor, write_cursor = _fake_cursor()

    sweep_mod.sweep(dry_run=False, registry=reg, api=_fake_api({}), max_rows=3,
                    read_cursor=read_cursor, write_cursor=write_cursor)
    assert read_cursor()[0] == "env-2"  # examined every row this call

    r2 = sweep_mod.sweep(dry_run=False, registry=reg, api=_fake_api({}), max_rows=3,
                         read_cursor=read_cursor, write_cursor=write_cursor)
    # cursor was at the end -> wraps to the start; the whole register is
    # examined again from env-0, not starved forever.
    assert r2["examined"] == 3


def test_cursor_skips_a_row_no_longer_present_and_resumes_past_it():
    rows = [_row(id="env-1", verb="envelope.apply", bounds={}),
            _row(id="env-3", verb="envelope.apply", bounds={})]
    reg = _registry(rows)
    read_cursor, write_cursor = _fake_cursor()
    write_cursor("env-2")  # a row that no longer exists (retired/removed since)

    receipt = sweep_mod.sweep(dry_run=False, registry=reg, api=_fake_api({}), max_rows=1,
                              read_cursor=read_cursor, write_cursor=write_cursor)
    assert receipt["examined"] == 1
    assert read_cursor()[0] == "env-3"  # resumed at the next HIGHER id, not env-1


def test_cursor_never_advances_on_a_dry_run():
    rows = [_row(id=f"env-{i}", verb="envelope.apply", bounds={}) for i in range(3)]
    reg = _registry(rows)
    read_cursor, write_cursor = _fake_cursor()
    receipt = sweep_mod.sweep(dry_run=True, registry=reg, api=_fake_api({}), max_rows=2,
                              read_cursor=read_cursor, write_cursor=write_cursor)
    assert read_cursor()[0] == ""
    assert receipt["cursor"] == {"state": "absent", "value": None}


def test_cursor_reports_unreachable_when_the_store_root_is_unwritable():
    """Rework of Loki's LOW finding (FAAD3E4A): an unwritable store root
    used to be silent — no cursor field, identical prefix every call."""
    rows = [_row(id=f"env-{i}", verb="envelope.apply", bounds={}) for i in range(3)]
    reg = _registry(rows)
    read_cursor, write_cursor = _fake_cursor(writable=False)

    r1 = sweep_mod.sweep(dry_run=False, registry=reg, api=_fake_api({}), max_rows=2,
                         read_cursor=read_cursor, write_cursor=write_cursor)
    assert r1["cursor"] == {"state": "unreachable", "value": None}
    # the failed write means the value never actually changed
    assert read_cursor()[0] == ""

    r2 = sweep_mod.sweep(dry_run=False, registry=reg, api=_fake_api({}), max_rows=2,
                         read_cursor=read_cursor, write_cursor=write_cursor)
    # honest: still the same prefix, and the receipt still says why
    assert r1["examined"] == r2["examined"] == 2
    assert r2["cursor"]["state"] == "unreachable"


def test_cursor_state_populated_absent_unreachable_are_the_only_values():
    assert sweep_mod._read_cursor_state()[1] in ("populated", "absent", "unreachable")


def test_cursor_path_lives_beside_the_seal_watchs_offset_file():
    from willow_mcp import paths

    assert sweep_mod._cursor_path().parent == paths.store_root()
    assert sweep_mod._cursor_path().name == "envelope_retire_sweep.cursor"


# --------------------------------------------------------------------------
# Per-row deadline (rework of Loki's MEDIUM finding, D81165E5)
# --------------------------------------------------------------------------

def test_clipped_timeout_none_deadline_means_no_clipping():
    assert sweep_mod._clipped_timeout(None) is None


def test_clipped_timeout_floors_and_caps():
    now = sweep_mod.time.monotonic()
    assert sweep_mod._clipped_timeout(now + 100) == 20  # capped at 20
    assert sweep_mod._clipped_timeout(now + 10) in (9, 10)  # not capped, ~10s left
    assert sweep_mod._clipped_timeout(now + 1) == 0  # below the floor -> do not start


def test_branch_state_skips_the_first_call_when_budget_already_exhausted():
    calls = []

    def api(method, url, *, bearer, body=None, timeout=20):
        calls.append((method, timeout))
        return {"ok": True, "status": 200, "body": {}}

    past_deadline = sweep_mod.time.monotonic() - 5
    state = sweep_mod._branch_state(api, repo="org/repo", branch="feat/x", token="t",
                                     deadline=past_deadline)
    assert calls == []  # never even attempted
    assert state["reachable"] is False
    assert "budget exhausted" in state["reason"]


def test_branch_state_skips_the_second_call_when_budget_runs_out_between_them(monkeypatch):
    """The branch-existence call succeeds (branch gone -> 404); by the time
    the PR-history call would start, the budget is spent."""
    sequence = [995.0, 999.0]  # 1st _clipped_timeout call, 2nd _clipped_timeout call

    def fake_monotonic():
        return sequence.pop(0) if sequence else 999.0

    monkeypatch.setattr(sweep_mod.time, "monotonic", fake_monotonic)

    def api(method, url, *, bearer, body=None, timeout=20):
        if "branches" in url:
            return {"ok": False, "status": 404, "reason": "Not Found"}
        raise AssertionError("the PR-history call must not be attempted")

    state = sweep_mod._branch_state(api, repo="org/repo", branch="feat/x", token="t",
                                     deadline=1001.0)
    assert state["reachable"] is False
    assert "PR-history check" in state["reason"]


def test_sweep_ends_the_call_not_a_crash_when_deadline_is_already_gone(monkeypatch):
    """End-to-end: a deadline already in the past means the row is never
    examined and never attempted — not marked unreachable, not counted,
    the call simply ends (rework of Loki's MEDIUM finding, probe
    7AFN806Y, FAAD3E4A)."""
    row = _row()
    reg = _registry([row])
    monkeypatch.setattr(sweep_mod.time, "monotonic", lambda: 1000.0)
    receipt = sweep_mod.sweep(dry_run=True, registry=reg, api=_fake_api({}), time_budget_s=1.0)
    assert receipt["examined"] == 0
    assert receipt["retired"] == receipt["kept_in_force"] == receipt["unreachable"] == []
    assert receipt["truncated"] is True


# --------------------------------------------------------------------------
# Reproduction of Loki's probe 7AFN806Y (FAAD3E4A): 20 rows, a budget that
# only fits a handful of network calls, three consecutive live calls — the
# old bug burned the whole tail as fake "unreachable, examined" progress
# with truncated=False; the fix must show real, bounded progress instead.
# --------------------------------------------------------------------------

def test_probe_7AFN806Y_never_claims_full_coverage_and_makes_real_progress(monkeypatch):
    n = 20
    rows = [_row(id=f"env-{i:02d}",
                 bounds={"repo": "org/repo", "branches": [f"feat/{i:02d}"],
                         "remote": "origin", "force": False})
            for i in range(n)]
    reg = _registry(rows)
    clock = {"t": 0.0}

    def fake_monotonic():
        return clock["t"]

    monkeypatch.setattr(sweep_mod.time, "monotonic", fake_monotonic)
    _monkeypatch_mint(monkeypatch)

    def api(method, url, *, bearer, body=None, timeout=20):
        clock["t"] += 1.0  # simulate ~1s of real network cost per call
        if "/branches/" in url:
            return {"ok": True, "status": 200, "body": {"name": "x"}}  # still exists
        raise AssertionError("branch exists -> the PR-history call is never reached")

    read_cursor, write_cursor = _fake_cursor()
    per_call_examined = []
    for _ in range(3):
        r = sweep_mod.sweep(dry_run=False, registry=reg, api=api, ledger=_FakeLedger(),
                            time_budget_s=6.0, read_cursor=read_cursor, write_cursor=write_cursor)
        assert r["truncated"] is True  # never claims full coverage of 20 rows
        assert r["examined"] < n
        per_call_examined.append({e["id"] for e in r["kept_in_force"]})

    # Real progress: each call must not re-examine exactly the same set the
    # first call did (the bug's signature: env-01..03 forever).
    assert per_call_examined[1] != per_call_examined[0]
    assert per_call_examined[2] != per_call_examined[0]
    # And across the three calls, meaningfully more of the register has
    # actually been looked at than what any single call covered alone.
    total_seen = set().union(*per_call_examined)
    assert len(total_seen) > len(per_call_examined[0])


# --------------------------------------------------------------------------
# App token mints: clipped to the SAME budget, checked at the SAME point
# (rework of Loki's LOW finding, probe I, FAAD3E4A)
# --------------------------------------------------------------------------

def test_mint_never_called_when_budget_is_already_under_the_floor(monkeypatch):
    row = _row()
    reg = _registry([row])
    monkeypatch.setattr(sweep_mod.time, "monotonic", lambda: 1000.0)
    mint_calls = []

    def fake_mint(repo, timeout=20):
        mint_calls.append(timeout)
        return {"ok": True, "mode": "app", "token": "t"}

    from willow_mcp import github_app_credentials as gac
    monkeypatch.setattr(gac, "mint_installation_token", fake_mint)

    receipt = sweep_mod.sweep(dry_run=True, registry=reg, api=_fake_api({}), time_budget_s=1.0)
    assert mint_calls == []
    assert receipt["examined"] == 0
    assert receipt["truncated"] is True


def test_mint_receives_the_clipped_timeout_not_a_flat_20(monkeypatch):
    row = _row()
    reg = _registry([row])
    monkeypatch.setattr(sweep_mod.time, "monotonic", lambda: 1000.0)
    mint_calls = []

    def fake_mint(repo, timeout=20):
        mint_calls.append(timeout)
        return {"ok": False, "mode": "unavailable", "reason": "stub"}

    from willow_mcp import github_app_credentials as gac
    monkeypatch.setattr(gac, "mint_installation_token", fake_mint)

    sweep_mod.sweep(dry_run=True, registry=reg, api=_fake_api({}), time_budget_s=10.0)
    assert mint_calls == [10]  # min(20, 10s remaining), not the flat default


def test_github_app_credentials_mint_installation_token_default_unchanged():
    """Rework guard: every EXISTING caller of mint_installation_token
    (pr_executor, push_executor) calls it with just `repo` — the new
    `timeout` kwarg must default to 20, matching the client's prior
    hardcoded behavior exactly."""
    import inspect

    from willow_mcp import github_app_credentials as gac

    sig = inspect.signature(gac.mint_installation_token)
    assert sig.parameters["timeout"].default == 20


# --------------------------------------------------------------------------
# A registry write failure is reported on that row, not raised (rework of
# Loki's LOW finding, probe C, D81165E5)
# --------------------------------------------------------------------------

def test_write_failure_on_one_row_does_not_lose_an_earlier_rows_retirement():
    rows = [_row(id="env-a", verb="envelope.apply", bounds={}, max_count=1),
            _row(id="env-b", verb="envelope.apply", bounds={}, max_count=1)]
    backend = _Backend(rows)
    snapshot = backend.snapshot()
    ledger = _FakeLedger(counts={"env-a": 1, "env-b": 1})

    calls = {"n": 0}
    real_write = backend.write

    def flaky_write(doc):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("disk full")
        real_write(doc)

    receipt = sweep_mod.sweep(
        dry_run=False, registry=snapshot, api=_fake_api({}), ledger=ledger,
        reload_registry=backend.reload, write_registry=flaky_write, lock=_null_lock,
    )
    # First row retired and persisted; second row's write blew up but is
    # reported, not raised, and does not erase the first row's receipt.
    assert len(receipt["retired"]) == 1
    assert receipt["retired"][0]["id"] == "env-a"
    assert len(receipt["kept_in_force"]) == 1
    assert receipt["kept_in_force"][0]["id"] == "env-b"
    assert "registry write failed" in receipt["kept_in_force"][0]["why"]
    # The first row's write actually landed on disk (the fake backend).
    by_id = {r["id"]: r["status"] for r in backend.store["active"]}
    assert by_id["env-a"] == "revoked"
    assert by_id["env-b"] == "active"
    # No FRANK row for the row whose write never landed.
    assert len(ledger.appended) == 1
    assert ledger.appended[0][2]["envelope_id"] == "env-a"
