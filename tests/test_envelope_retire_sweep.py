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

from willow_mcp import envelope_retire_sweep as sweep_mod


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
