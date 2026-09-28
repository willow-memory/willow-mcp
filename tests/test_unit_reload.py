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
                 after_active_enter=None, empty_show=False,
                 post_restart_samples=None, raise_on_post_restart_show=None,
                 journal_output=None):
        self.active_enter = active_enter
        self.active_state = active_state
        self.show_rc = show_rc
        self.show_detail = show_detail
        self.restart_rc = restart_rc
        self.restart_err = restart_err
        self.head = head
        self.after_active_enter = after_active_enter or active_enter
        self.empty_show = empty_show
        # sample_restart_loop takes TWO show samples after a successful
        # restart; each entry here is a dict of property overrides (e.g.
        # {"NRestarts": "3"} or {"SubState": "auto-restart"}) consumed one
        # per post-restart show call, in order. Missing entries fall back to
        # the plain post-restart text (active_state/after_active_enter).
        self.post_restart_samples = list(post_restart_samples or [])
        # 0-based index into the post-restart show calls (sample_restart_loop
        # always makes exactly two) at which to raise instead of answering —
        # a test seam for "the SECOND sample itself is unreachable" (Loki
        # 6ACB1F10 F2), distinct from a post-restart sample that answers but
        # reports a dead ActiveState.
        self.raise_on_post_restart_show = raise_on_post_restart_show
        # ELOOP/EDEAD attaches a real journal tail (unit_status.journal_tail)
        # — a test seam so a mutant that empties or drops it can be caught by
        # asserting on ACTUAL content, not merely the key's presence.
        self.journal_output = journal_output or ("2026-09-27T10:00:00 loop tail\n", 0, "")
        self.calls: list[list[str]] = []
        self._restarted = False
        self._post_restart_show_count = 0

    def _show_output(self) -> str:
        if self.empty_show:
            return ""
        if not self._restarted:
            active_enter = self.active_enter
            return (
                f"ActiveState={self.active_state}\n"
                f"ActiveEnterTimestamp={active_enter}\n"
                f"ActiveEnterTimestampMonotonic=123456\n"
                f"MainPID=1234\n"
                f"ExecMainStartTimestamp={active_enter}\n"
            )
        idx = self._post_restart_show_count
        self._post_restart_show_count += 1
        extra = self.post_restart_samples[idx] if idx < len(self.post_restart_samples) else {}
        active_enter = extra.get("ActiveEnterTimestamp", self.after_active_enter)
        lines = [
            f"ActiveState={extra.get('ActiveState', self.active_state)}",
            f"ActiveEnterTimestamp={active_enter}",
            "ActiveEnterTimestampMonotonic=123456",
            f"MainPID={extra.get('MainPID', 1234)}",
            f"ExecMainStartTimestamp={active_enter}",
        ]
        if "NRestarts" in extra:
            lines.append(f"NRestarts={extra['NRestarts']}")
        if "SubState" in extra:
            lines.append(f"SubState={extra['SubState']}")
        if "RestartUSec" in extra:
            lines.append(f"RestartUSec={extra['RestartUSec']}")
        # Type/Result/ExecMainStatus (Loki 0DFFEFA6 B2): a realistic
        # `Type=oneshot` post-restart sample.
        if "Type" in extra:
            lines.append(f"Type={extra['Type']}")
        if "Result" in extra:
            lines.append(f"Result={extra['Result']}")
        if "ExecMainStatus" in extra:
            lines.append(f"ExecMainStatus={extra['ExecMainStatus']}")
        return "\n".join(lines) + "\n"

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        if argv[0] == "systemctl":
            if argv[1:3] == ["--user", "show"]:
                if self._restarted and self.raise_on_post_restart_show == self._post_restart_show_count:
                    self._post_restart_show_count += 1
                    raise subprocess.TimeoutExpired(argv, 10)
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
        if argv[0] == "journalctl":
            # Only reached on an ELOOP/EDEAD refusal, which attaches a journal
            # tail via unit_status.journal_tail.
            stdout, rc, err = self.journal_output
            return subprocess.CompletedProcess(argv, rc, stdout, err)
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
    # sleeper defaults to a no-op: sample_restart_loop's wait must never be a
    # real sleep under test (B2BF4DB9). Override with a recording fake to
    # assert on the wait itself.
    args = dict(app_id="willow", unit="willow-bot.service", checkout=checkout,
                repo="willow-memory/willow-bot", project="willow-mcp",
                ledger=_ledger(pg), runner=runner, sleeper=lambda s: None)
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


# ── restart loop (gap d30c923424a0's amendment): two samples, not one ───────

def test_stable_unit_after_restart_reports_ok(home, tmp_path, monkeypatch, checkout):
    """Two identical post-restart samples (the common case) still report ok
    -- the two-sample guard must not manufacture a false restart_loop."""
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    _seed_receipt(pg, repo="willow-memory/willow-bot", checkout=checkout,
                  after="deadbeef", created_at=_AFTER_RECEIPT)
    git = _FakeSystemctlGit(head="deadbeef", post_restart_samples=[{}, {}])
    out = _reload(checkout, pg, git)
    assert out["ok"] and out["reloaded"] and "error" not in out


def test_restart_loop_from_climbing_nrestarts_refuses_eloop(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    _seed_receipt(pg, repo="willow-memory/willow-bot", checkout=checkout,
                  after="deadbeef", created_at=_AFTER_RECEIPT)
    git = _FakeSystemctlGit(head="deadbeef", post_restart_samples=[
        {"NRestarts": "2"}, {"NRestarts": "3"},
    ])
    out = _reload(checkout, pg, git)
    assert out["ok"] is False
    assert out["error"] == "ELOOP"
    assert out["state_first"]["NRestarts"] == "2"
    assert out["state_after"]["NRestarts"] == "3"
    # L7: the ELOOP journal must carry the REAL tail, not an emptied stand-in.
    assert out["journal"]["state"] == "populated"
    assert out["journal"]["lines"] == ["2026-09-27T10:00:00 loop tail"]
    # L5: the ELOOP refusal still writes a FRANK receipt.
    assert out["receipt_id"]
    restart_loop_receipts = [r for r in pg.rows if r["event_type"] == f"{urx.EVENT}_restart_loop"]
    assert len(restart_loop_receipts) == 1
    assert restart_loop_receipts[0]["id"] == out["receipt_id"]


def test_restart_loop_from_auto_restart_substate_refuses_eloop(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    _seed_receipt(pg, repo="willow-memory/willow-bot", checkout=checkout,
                  after="deadbeef", created_at=_AFTER_RECEIPT)
    git = _FakeSystemctlGit(head="deadbeef", post_restart_samples=[
        {"SubState": "auto-restart"}, {"SubState": "auto-restart"},
    ])
    out = _reload(checkout, pg, git)
    assert out["ok"] is False
    assert out["error"] == "ELOOP"


# ── L1: ActiveEnterTimestamp moving ALONE (no NRestarts climb, no
# auto-restart substate) is still a restart loop ─────────────────────────────

def test_restart_loop_from_active_enter_timestamp_alone_moving():
    first = {"ok": True, "NRestarts": "0", "ActiveEnterTimestamp": "Mon 2026-09-15 10:00:00 UTC"}
    second = {"ok": True, "NRestarts": "0", "ActiveEnterTimestamp": "Mon 2026-09-15 10:05:00 UTC"}
    assert urx._restart_loop_between(first, second) is True


# ── F2 (Loki 6ACB1F10): a unit dead or unreachable after the action never
# reports ok — distinct errnos from ELOOP, never collapsed into success ────

def test_crashed_after_restart_with_restart_no_refuses_edead(home, tmp_path, monkeypatch, checkout):
    """Restart=no (no auto-restart, NRestarts never climbs, ActiveEnterTimestamp
    never moves again): the OLD code's restart-loop check saw none of its three
    signals and reported ok=True with a `failed` state_after. EDEAD is
    distinct from ELOOP -- this unit is not looping, it is simply dead."""
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    _seed_receipt(pg, repo="willow-memory/willow-bot", checkout=checkout,
                  after="deadbeef", created_at=_AFTER_RECEIPT)
    git = _FakeSystemctlGit(head="deadbeef", post_restart_samples=[
        {"ActiveState": "active"}, {"ActiveState": "failed"},
    ])
    out = _reload(checkout, pg, git)
    assert out["ok"] is False
    assert out["error"] == "EDEAD"
    assert out["state_after"]["ActiveState"] == "failed"
    # N8-N11 (Loki 0DFFEFA6): the EDEAD receipt and its journal must carry
    # REAL content, not merely be present under the key.
    assert out["journal"]["state"] == "populated"
    assert out["journal"]["lines"] == ["2026-09-27T10:00:00 loop tail"]
    assert out["receipt_id"]
    edead_receipts = [r for r in pg.rows if r["event_type"] == f"{urx.EVENT}_dead"]
    assert len(edead_receipts) == 1 and edead_receipts[0]["id"] == out["receipt_id"]
    assert edead_receipts[0]["content"]["errno"] == "EDEAD"


def test_inactive_dead_both_samples_refuses_edead(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    _seed_receipt(pg, repo="willow-memory/willow-bot", checkout=checkout,
                  after="deadbeef", created_at=_AFTER_RECEIPT)
    git = _FakeSystemctlGit(head="deadbeef", post_restart_samples=[
        {"ActiveState": "inactive"}, {"ActiveState": "inactive"},
    ])
    out = _reload(checkout, pg, git)
    assert out["ok"] is False and out["error"] == "EDEAD"
    assert out["journal"]["state"] == "populated"
    assert out["journal"]["lines"] == ["2026-09-27T10:00:00 loop tail"]
    assert out["receipt_id"]


def test_direct_oneshot_reload_with_a_clean_run_reports_ok(home, tmp_path, monkeypatch, checkout):
    """Loki 0DFFEFA6 B2 ("the same logic, inferred, applies to reloading a
    oneshot"): a `Type=oneshot` unit restarted directly (no timer) runs once
    and goes `inactive` on its own — that is success, not EDEAD."""
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    _seed_receipt(pg, repo="willow-memory/willow-bot", checkout=checkout,
                  after="deadbeef", created_at=_AFTER_RECEIPT)
    git = _FakeSystemctlGit(head="deadbeef", post_restart_samples=[
        {"ActiveState": "inactive", "Type": "oneshot", "Result": "success", "ExecMainStatus": "0"},
        {"ActiveState": "inactive", "Type": "oneshot", "Result": "success", "ExecMainStatus": "0"},
    ])
    out = _reload(checkout, pg, git)
    assert out["ok"] and out["reloaded"] and "error" not in out, out


def test_direct_oneshot_reload_with_a_failed_run_refuses_edead(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    _seed_receipt(pg, repo="willow-memory/willow-bot", checkout=checkout,
                  after="deadbeef", created_at=_AFTER_RECEIPT)
    git = _FakeSystemctlGit(head="deadbeef", post_restart_samples=[
        {"ActiveState": "inactive", "Type": "oneshot", "Result": "exit-code", "ExecMainStatus": "1"},
        {"ActiveState": "inactive", "Type": "oneshot", "Result": "exit-code", "ExecMainStatus": "1"},
    ])
    out = _reload(checkout, pg, git)
    assert out["ok"] is False and out["error"] == "EDEAD"


def test_second_sample_unreachable_refuses_eunreach_not_ok(home, tmp_path, monkeypatch, checkout):
    """The OLD code let `_restart_loop_between` return False on an unreachable
    second sample and reported ok=True with a broken state_after -- an
    unreachable post-action read must never collapse into success."""
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    _seed_receipt(pg, repo="willow-memory/willow-bot", checkout=checkout,
                  after="deadbeef", created_at=_AFTER_RECEIPT)
    git = _FakeSystemctlGit(head="deadbeef", raise_on_post_restart_show=1)
    out = _reload(checkout, pg, git)
    assert out["ok"] is False
    assert out["error"] == "EUNREACH"
    assert out["state_after"]["ok"] is False


def test_restart_loop_wait_comes_from_restart_usec():
    """sample_restart_loop reads the FIRST sample's RestartUSec, doubles it,
    and clamps to [2, 15]s -- verified directly against the shared helper,
    with an injected sleeper so no real sleep happens."""
    calls = []
    git = _FakeSystemctlGit(head="deadbeef", post_restart_samples=[{"RestartUSec": "3s"}])
    git._restarted = True  # skip the "before restart" branch of _show_output
    out = urx.sample_restart_loop("x", runner=git, sleeper=lambda s: calls.append(s))
    assert calls == [out["wait_s"]]
    assert out["wait_s"] == 6.0  # 2 x 3s, inside the [2, 15] clamp


def test_show_unit_requests_loadstate_property():
    """N13 (Loki 0DFFEFA6): the fake used to emit `LoadState` whether or not
    it was actually requested, which let a mutant that DELETED `LoadState`
    from `_SHOW_PROPERTIES` survive silently — on real systemd, a property
    not named in `--property=` is simply not printed. Assert it is actually
    in the argv `show_unit` sends."""
    calls = []

    def _runner(argv, **kw):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "ActiveState=active\nLoadState=loaded\n", "")

    urx.show_unit("willow-bot.service", runner=_runner)
    assert calls, "no show call recorded"
    prop_arg = next(a for a in calls[0] if a.startswith("--property="))
    assert "LoadState" in prop_arg.split("=", 1)[1].split(",")
    # F2 (Loki 58BC828C): `Type`/`Result` must also be requested — dropping
    # either from `_SHOW_PROPERTIES` silently makes every oneshot reload, and
    # every install without a timer, read as EDEAD on real systemd.
    requested = prop_arg.split("=", 1)[1].split(",")
    assert "Type" in requested
    assert "Result" in requested


# ── F3/F4/N27/N28 (Loki 58BC828C): liveness_refusal_after_action's own
# clauses, pinned directly against the shared function ──────────────────────

def test_type_simple_clean_exit_is_edead_not_accepted():
    """F3: a real-shaped clean exit (inactive, Result=success,
    ExecMainStatus=0) from a `Type=simple` unit must still be EDEAD — the
    oneshot-success allowance is narrow to `Type == 'oneshot'`. Without the
    guard, a `Type=simple` daemon that merely exited 0 would read as healthy
    on real systemd."""
    loop_sample = {"restart_loop": False, "second": {
        "ok": True, "ActiveState": "inactive", "Type": "simple",
        "Result": "success", "ExecMainStatus": "0",
    }}
    out = urx.liveness_refusal_after_action(loop_sample)
    assert out is not None and out["errno"] == "EDEAD"


def test_timer_unreachable_after_action_refuses_eunreach():
    """F4: no fixture covered a timer `show` that came back unreachable
    (LoadState=not-found, or the read itself failing) — the code already
    returns EUNREACH via the shared `timer_state.get('ok')` check; pin it."""
    loop_sample = {"restart_loop": False, "second": {"ok": True, "ActiveState": "active"}}
    timer_state = {"ok": False, "cause": "unit_unknown", "detail": "not-found"}
    out = urx.liveness_refusal_after_action(loop_sample, timer_state=timer_state)
    assert out is not None
    assert out["errno"] == "EUNREACH"
    assert out["cause"] == "unit_unknown"


def test_oneshot_success_accepted_via_result_success_clause_alone():
    """N27: the oneshot-success check ORs two clauses. `Result == 'success'`
    must accept on its own even when the OTHER clause (inactive + exit 0)
    does not hold — every existing fixture sets both together, which let a
    mutant dropping this clause survive."""
    loop_sample = {"restart_loop": False, "second": {
        "ok": True, "ActiveState": "activating", "Type": "oneshot",
        "Result": "success", "ExecMainStatus": "1",
    }}
    out = urx.liveness_refusal_after_action(loop_sample)
    assert out is None


def test_oneshot_success_accepted_via_inactive_and_exec_status_zero_clause_alone():
    """N28: the OTHER clause (`ActiveState == 'inactive'` and
    `ExecMainStatus == '0'`) must accept on its own even when `Result` is not
    literally `'success'` (e.g. empty/absent)."""
    loop_sample = {"restart_loop": False, "second": {
        "ok": True, "ActiveState": "inactive", "Type": "oneshot",
        "Result": "", "ExecMainStatus": "0",
    }}
    out = urx.liveness_refusal_after_action(loop_sample)
    assert out is None


# ── EFAILED (Loki 58BC828C INFO): a timer can be healthy while the oneshot
# it just activated failed its very first run inside the sample window ──────

def test_timer_healthy_but_oneshot_first_run_failed_refuses_efailed():
    loop_sample = {"restart_loop": False, "second": {
        "ok": True, "ActiveState": "inactive", "Type": "oneshot",
        "Result": "exit-code", "ExecMainStatus": "1",
    }}
    timer_state = {"ok": True, "ActiveState": "active"}
    out = urx.liveness_refusal_after_action(loop_sample, timer_state=timer_state)
    assert out is not None
    assert out["errno"] == "EFAILED"


def test_timer_healthy_and_oneshot_clean_run_reports_ok():
    loop_sample = {"restart_loop": False, "second": {
        "ok": True, "ActiveState": "inactive", "Type": "oneshot",
        "Result": "success", "ExecMainStatus": "0",
    }}
    timer_state = {"ok": True, "ActiveState": "active"}
    out = urx.liveness_refusal_after_action(loop_sample, timer_state=timer_state)
    assert out is None


def test_timer_healthy_and_oneshot_never_ran_reports_ok():
    """Absence of a run is not failure; `_oneshot_run_failed` must not treat
    a unit that simply hasn't run as EFAILED. Uses systemd's own pre-run
    DEFAULTS (`Result=success`, `ExecMainStatus=0`) rather than empty
    strings — that is the real shape a oneshot that has never fired reports
    (Loki 2359F421: the code already handles this shape, this pins it)."""
    loop_sample = {"restart_loop": False, "second": {
        "ok": True, "ActiveState": "inactive", "Type": "oneshot",
        "Result": "success", "ExecMainStatus": "0",
    }}
    timer_state = {"ok": True, "ActiveState": "active"}
    out = urx.liveness_refusal_after_action(loop_sample, timer_state=timer_state)
    assert out is None


def test_timer_healthy_and_oneshot_never_ran_with_empty_fields_reports_ok():
    """Sibling shape: Result/ExecMainStatus both empty (also seen in
    practice) must likewise not be treated as failure."""
    loop_sample = {"restart_loop": False, "second": {
        "ok": True, "ActiveState": "inactive", "Type": "oneshot",
        "Result": "", "ExecMainStatus": "",
    }}
    timer_state = {"ok": True, "ActiveState": "active"}
    out = urx.liveness_refusal_after_action(loop_sample, timer_state=timer_state)
    assert out is None


def test_timer_healthy_oneshot_result_failure_with_zero_exit_status_refuses_efailed():
    """M6 (Loki 2359F421): every existing failed-run fixture set BOTH
    `Result != success` AND a non-zero `ExecMainStatus`, so a mutant that
    ignores `Result` entirely (deciding failure from `ExecMainStatus` alone)
    still passed. `Result=timeout` with `ExecMainStatus=0` is the real-world
    case that clause alone would miss — systemd reports a killed/timed-out
    run with the last exit status still 0."""
    loop_sample = {"restart_loop": False, "second": {
        "ok": True, "ActiveState": "inactive", "Type": "oneshot",
        "Result": "timeout", "ExecMainStatus": "0",
    }}
    timer_state = {"ok": True, "ActiveState": "active"}
    out = urx.liveness_refusal_after_action(loop_sample, timer_state=timer_state)
    assert out is not None
    assert out["errno"] == "EFAILED"


def test_timer_healthy_oneshot_success_result_with_nonzero_exit_status_refuses_efailed():
    """M5 (Loki 2359F421): a mutant that ignores `ExecMainStatus` entirely
    (deciding failure from `Result` alone) still passed every existing
    fixture, because every failed-run fixture also set `Result != success`.
    `Result=success` with a non-zero `ExecMainStatus` pins the second
    clause on its own."""
    loop_sample = {"restart_loop": False, "second": {
        "ok": True, "ActiveState": "inactive", "Type": "oneshot",
        "Result": "success", "ExecMainStatus": "1",
    }}
    timer_state = {"ok": True, "ActiveState": "active"}
    out = urx.liveness_refusal_after_action(loop_sample, timer_state=timer_state)
    assert out is not None
    assert out["errno"] == "EFAILED"


def test_restart_wait_clamps_low_and_high():
    assert urx._parse_restart_wait_s("") == 2.0
    assert urx._parse_restart_wait_s("infinity") == 2.0
    assert urx._parse_restart_wait_s("100ms") == 2.0  # 0.2s doubled, clamped up
    assert urx._parse_restart_wait_s("10s") == 15.0    # 20s doubled, clamped down
    assert urx._parse_restart_wait_s("3s") == 6.0       # inside the clamp


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
