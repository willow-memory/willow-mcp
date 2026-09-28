"""The merge-is-confirm path (gap 55fc7c9681e9; replaces sealed ruling
e961aff8): reloader.check_merge()/run_once_v2(). The operator's own merge
into master, checked live against GitHub, is the reloader's confirm --
not a per-restart Nestor seal. Gated behind the PINNED pair RULING_PAIR_ID
being a real, verified seal in nestor.db: check_merge() always refuses
ENORULING while it is not, and run_once_v2() falls back to run_once() (the
sealed-pair path) unchanged in that case.

Rework (Loki FAIL 40F02AAD): F1 (the merge path could never fire on a
real pull-executor receipt -- remote_sha/changed were missing from the
FRANK row), F2 (the ruling gate trusted a bare SOIL {"status": "sealed"}
record via an injectable store= parameter -- no store parameter exists
any more; the ONLY thing that can flip _ruling_sealed() is a real,
verified seal on the one pinned pair id), F3 (the env trigger could
restart onto unconfirmed/drifted/off-master code once the ruling went
live), F4/F5 (ledger spam -- idle ticks now write nothing), F6 (EPARTIAL
recorded error=None), F7 (a failed/timed-out restart wrote no receipt),
F8 (the checks conclusion check was a denylist, so "stale" counted as
green), F9 (the App token was minted with no permission scope).

Fakes for GitHub/the unit manager/git and the FRANK ledger; ONE test
(test_real_pull_executor_receipt_is_readable_by_check_merge) runs a real
local git repo through the real pull_executor.execute_pull(), proving F1
against the real production write path rather than a hand-built receipt.
Real ed25519 signing for the ruling pair (net_signer.verify_seal, F2) via
the ring_with_sean fixture -- same pattern test_reloader.py's F5 rework
already established.
"""
from __future__ import annotations

import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from willow_mcp import keyring as keyring_mod
from willow_mcp import net_signer as ns
from willow_mcp import reloader

_SC = "systemctl"


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


class _Git:
    """The unit-manager+git fake covering the merge path's own calls:
    branch, HEAD, unit show, restart."""

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
        if argv[0] == _SC:
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
        return [c for c in self.calls if c[0] == _SC and c[1:3] == ["--user", "restart"]]


def _hybrid_runner(*, active_enter="Mon 2026-09-15 10:00:00 UTC"):
    """REAL git subprocess calls (the checkout is a real repo), a FAKE
    unit-show (never touch the real box's units). Used only by the
    real-pull-executor test."""
    def run(argv, **kw):
        if argv[0] == _SC:
            if argv[1:3] == ["--user", "show"]:
                out = f"ActiveState=active\nActiveEnterTimestamp={active_enter}\nLoadState=loaded\n"
                return subprocess.CompletedProcess(argv, 0, out, "")
            raise AssertionError(argv)
        kw.pop("env", None)
        return subprocess.run(argv, capture_output=True, text=True, timeout=kw.get("timeout", 30), check=False)
    return run


def _minter(*, ok=True, permissions=None, reason="no creds"):
    def mint(repo, **kwargs):
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


def _pr_ok(number=42, sha="cafef00d"):
    return {"ok": True, "body": [
        {"number": number, "merged_at": "2026-09-28T10:00:00Z",
         "base": {"ref": "master"}, "merge_commit_sha": sha},
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


def _config(checkout, nestor_db, unit="willow-mcp-serve.service"):
    return reloader.ReloaderConfig(unit=unit, checkout=checkout, repo="willow-memory/willow-mcp",
                                   nestor_db=nestor_db)


# -- the pinned ruling pair (F2) -----------------------------------------------

_RULING_SOURCE_NORM = "reloader merge is confirm ruling"
_RULING_TARGET = "yes -- the operator's merge into master is the confirm"


def _sign_ruling(kr, verifier="sean campbell", *, source_norm=_RULING_SOURCE_NORM,
                 target=_RULING_TARGET):
    entry = kr.get(verifier)
    priv = Ed25519PrivateKey.from_private_bytes(entry.private)
    return priv.sign(ns.seal_message(source_norm, target, verifier)).hex()


def _ruling_db(tmp_path, *, row=True, status="sealed", superseded="", source_lang="decision",
              verifier="sean campbell", seal_sig="", pair_id=None,
              source_norm=_RULING_SOURCE_NORM, target=_RULING_TARGET,
              created_at=None) -> Path:
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
    if row:
        conn.execute(
            "INSERT INTO tm_pairs (id, source_text, source_norm, source_lang, target_text, "
            "target_lang, status, verifier, created_at, seal_sig, superseded_by) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (pair_id or reloader.RULING_PAIR_ID, source_norm, source_norm, source_lang, target,
             source_lang, status, verifier,
             created_at or datetime.now(timezone.utc).isoformat(), seal_sig, superseded))
    conn.commit()
    conn.close()
    return db


@pytest.fixture
def ring_with_sean(tmp_path):
    with keyring_mod.isolated():
        k = keyring_mod.Keyring(path=str(tmp_path / "keys.json"))
        k.add("sean campbell", kind="ed25519")
        k.save()
        keyring_mod.set_keyring(k)
        try:
            yield k
        finally:
            keyring_mod.set_keyring(None)


@pytest.fixture
def sealed_db(tmp_path, ring_with_sean):
    return _ruling_db(tmp_path, seal_sig=_sign_ruling(ring_with_sean))


@pytest.fixture
def unsealed_db(tmp_path):
    return _ruling_db(tmp_path, row=False)


def test_ruling_sealed_true_when_pinned_pair_is_sealed_and_verifies(tmp_path, ring_with_sean):
    db = _ruling_db(tmp_path, seal_sig=_sign_ruling(ring_with_sean))
    assert reloader._ruling_sealed(db) is True


def test_ruling_sealed_false_when_no_row(tmp_path):
    db = _ruling_db(tmp_path, row=False)
    assert reloader._ruling_sealed(db) is False


def test_ruling_sealed_false_when_status_not_sealed(tmp_path, ring_with_sean):
    db = _ruling_db(tmp_path, status="proposed")
    assert reloader._ruling_sealed(db) is False


def test_ruling_sealed_false_when_superseded(tmp_path, ring_with_sean):
    db = _ruling_db(tmp_path, seal_sig=_sign_ruling(ring_with_sean), superseded="newer-pair")
    assert reloader._ruling_sealed(db) is False


def test_ruling_sealed_false_when_source_lang_is_not_decision(tmp_path, ring_with_sean):
    db = _ruling_db(tmp_path, seal_sig=_sign_ruling(ring_with_sean), source_lang="es")
    assert reloader._ruling_sealed(db) is False


def test_ruling_sealed_false_when_signature_is_garbage(tmp_path, ring_with_sean):
    db = _ruling_db(tmp_path, seal_sig="not-a-real-signature")
    assert reloader._ruling_sealed(db) is False


def test_ruling_sealed_false_when_verifier_unknown_to_ring(tmp_path, ring_with_sean):
    outsider = Ed25519PrivateKey.generate()
    sig = outsider.sign(ns.seal_message(_RULING_SOURCE_NORM, _RULING_TARGET, "someone else")).hex()
    db = _ruling_db(tmp_path, seal_sig=sig, verifier="someone else")
    assert reloader._ruling_sealed(db) is False


def test_ruling_sealed_false_when_no_keyring_configured(tmp_path):
    db = _ruling_db(tmp_path, seal_sig="whatever")
    assert reloader._ruling_sealed(db) is False


def test_ruling_sealed_false_when_db_unreachable(tmp_path, ring_with_sean):
    assert reloader._ruling_sealed(tmp_path / "does-not-exist.db") is False


def test_forged_soil_status_has_no_hook_to_forge():
    """F2: check_merge/run_once_v2/_ruling_sealed take no store/Store
    parameter at all -- a forged {"status": "sealed"} SOIL record has
    nothing left to attach to."""
    import inspect
    assert "store" not in inspect.signature(reloader.check_merge).parameters
    assert "store" not in inspect.signature(reloader.run_once_v2).parameters
    assert "store" not in inspect.signature(reloader._ruling_sealed).parameters


# -- ENORULING: the gate -------------------------------------------------------

def test_check_merge_refuses_enoruling_while_unsealed(checkout, unsealed_db):
    config = _config(checkout, unsealed_db)
    ledger = _FakeLedger(_pull_receipt(checkout))
    out = reloader.check_merge(config, ledger=ledger, runner=_Git())
    assert out == {"ok": False, "act": False, "error": "ENORULING", "reason": out["reason"]}
    assert "e961aff8" in out["reason"]


def test_check_merge_refuses_enoruling_when_proposed_not_sealed(checkout, tmp_path, ring_with_sean):
    db = _ruling_db(tmp_path, status="proposed")
    config = _config(checkout, db)
    ledger = _FakeLedger(_pull_receipt(checkout))
    out = reloader.check_merge(config, ledger=ledger, runner=_Git())
    assert out["error"] == "ENORULING"


# -- ENOTMASTER -----------------------------------------------------------------

def test_check_merge_refuses_enotmaster(checkout, sealed_db):
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(_pull_receipt(checkout))
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(branch="feat/x"))
    assert out["error"] == "ENOTMASTER"


# -- ENORECEIPT / EALREADY -------------------------------------------------------

def test_check_merge_refuses_enoreceipt_with_no_pull_receipt(checkout, sealed_db):
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(None)
    out = reloader.check_merge(config, ledger=ledger, runner=_Git())
    assert out["error"] == "ENORECEIPT"


def test_check_merge_refuses_ealready_when_unit_already_active_since_receipt(checkout, sealed_db):
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(_pull_receipt(checkout))
    git = _Git(active_enter="Mon 2026-09-17 10:00:00 UTC")  # after the receipt's _AT
    out = reloader.check_merge(config, ledger=ledger, runner=git)
    assert out["error"] == "EALREADY"


def test_check_merge_refuses_ealready_when_receipt_already_consumed(checkout, sealed_db):
    config = _config(checkout, sealed_db)
    receipt = _pull_receipt(checkout)
    ledger = _FakeLedger(receipt)
    ledger.append("willow-mcp", reloader.MERGE_EVENT, {
        "repo": config.repo, "checkout": str(checkout), "pull_receipt_id": receipt["id"],
    })
    out = reloader.check_merge(config, ledger=ledger, runner=_Git())
    assert out["error"] == "EALREADY"


# -- ENOTMERGED (after != remote_sha) -------------------------------------------

def test_check_merge_refuses_enotmerged_when_after_neq_remote_sha(checkout, sealed_db):
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(_pull_receipt(checkout, after="cafef00d", remote_sha="deadbeef"))
    out = reloader.check_merge(config, ledger=ledger, runner=_Git())
    assert out["error"] == "ENOTMERGED"


# -- EDRIFT ----------------------------------------------------------------------

def test_check_merge_refuses_edrift_when_head_moved_again(checkout, sealed_db):
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(_pull_receipt(checkout, after="cafef00d"))
    git = _Git(head="newerhead")
    out = reloader.check_merge(config, ledger=ledger, runner=git)
    assert out["error"] == "EDRIFT"


# -- EUNREACH (token mint) -------------------------------------------------------

def test_check_merge_refuses_eunreach_when_token_mint_fails(checkout, sealed_db):
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(_pull_receipt(checkout))
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(), token_minter=_minter(ok=False))
    assert out["error"] == "EUNREACH"


def test_check_merge_refuses_eunreach_when_checks_permission_absent(checkout, sealed_db):
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(_pull_receipt(checkout))
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(), token_minter=_minter(permissions={}))
    assert out["error"] == "EUNREACH"


# -- F9: read-only token permissions --------------------------------------------

def test_check_merge_requests_read_only_token_permissions(checkout, sealed_db):
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(_pull_receipt(checkout))
    seen = {}

    def mint(repo, **kwargs):
        seen.update(kwargs)
        return {"ok": True, "mode": "app", "token": "tok", "permissions": {"checks": "read"}}

    api = _api(pr_response=_pr_ok(), checks_response=_checks_ok())
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(), api=api, token_minter=mint)
    assert out["act"] is True
    assert seen.get("permissions") == reloader._MERGE_TOKEN_PERMISSIONS


# -- ENOTMERGED (no PR found / base != master / merge_commit_sha mismatch / not merged) --

def test_check_merge_refuses_enotmerged_when_no_pr_names_the_sha(checkout, sealed_db):
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(_pull_receipt(checkout))
    api = _api(pr_response=_pr_empty())
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(), api=api, token_minter=_minter())
    assert out["error"] == "ENOTMERGED"


def test_check_merge_refuses_eunreach_when_github_pr_lookup_fails(checkout, sealed_db):
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(_pull_receipt(checkout))
    api = _api(pr_response={"ok": False, "status": 0, "reason": "timeout"})
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(), api=api, token_minter=_minter())
    assert out["error"] == "EUNREACH"


def test_pr_for_commit_empty_when_base_is_not_master():
    api = _api(pr_response={"ok": True, "body": [
        {"number": 1, "merged_at": "2026-09-28T10:00:00Z", "base": {"ref": "develop"},
         "merge_commit_sha": "cafef00d"}]})
    out = reloader._pr_for_commit("willow-memory/willow-mcp", "cafef00d", api=api, bearer="t")
    assert out["state"] == "empty"


def test_pr_for_commit_empty_when_merge_commit_sha_mismatches():
    api = _api(pr_response={"ok": True, "body": [
        {"number": 1, "merged_at": "2026-09-28T10:00:00Z", "base": {"ref": "master"},
         "merge_commit_sha": "other-sha"}]})
    out = reloader._pr_for_commit("willow-memory/willow-mcp", "cafef00d", api=api, bearer="t")
    assert out["state"] == "empty"


def test_pr_for_commit_empty_when_not_merged():
    api = _api(pr_response={"ok": True, "body": [
        {"number": 1, "merged_at": None, "base": {"ref": "master"},
         "merge_commit_sha": "cafef00d"}]})
    out = reloader._pr_for_commit("willow-memory/willow-mcp", "cafef00d", api=api, bearer="t")
    assert out["state"] == "empty"


# -- ECHECKS (allowlist, F8) -----------------------------------------------------

def test_check_merge_refuses_echecks_when_a_run_is_not_conclusive(checkout, sealed_db):
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(_pull_receipt(checkout))
    api = _api(pr_response=_pr_ok(), checks_response=_checks_ok(
        runs=[{"id": 1, "name": "test", "status": "in_progress", "conclusion": None,
               "output": {}, "app": {}}]))
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(), api=api, token_minter=_minter())
    assert out["error"] == "ECHECKS"


def test_check_merge_refuses_echecks_when_a_run_failed(checkout, sealed_db):
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(_pull_receipt(checkout))
    api = _api(pr_response=_pr_ok(), checks_response=_checks_ok(
        runs=[{"id": 1, "name": "test", "status": "completed", "conclusion": "failure",
               "output": {}, "app": {}}]))
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(), api=api, token_minter=_minter())
    assert out["error"] == "ECHECKS"


def test_check_merge_refuses_echecks_when_conclusion_is_stale(checkout, sealed_db):
    """F8: 'stale' is not on the allowlist -- it must NOT count as green."""
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(_pull_receipt(checkout))
    api = _api(pr_response=_pr_ok(), checks_response=_checks_ok(
        runs=[{"id": 1, "name": "test", "status": "completed", "conclusion": "stale",
               "output": {}, "app": {}}]))
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(), api=api, token_minter=_minter())
    assert out["error"] == "ECHECKS"


def test_check_merge_refuses_eunreach_when_github_checks_lookup_fails(checkout, sealed_db):
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(_pull_receipt(checkout))
    api = _api(pr_response=_pr_ok(), checks_response={"ok": False, "status": 500, "reason": "boom"})
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(), api=api, token_minter=_minter())
    assert out["error"] == "EUNREACH"


# -- act ---------------------------------------------------------------------------

def test_check_merge_acts_when_every_condition_holds(checkout, sealed_db):
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(_pull_receipt(checkout))
    api = _api(pr_response=_pr_ok(number=99), checks_response=_checks_ok())
    out = reloader.check_merge(config, ledger=ledger, runner=_Git(), api=api, token_minter=_minter())
    assert out["ok"] is True and out["act"] is True
    assert out["pr_number"] == 99
    assert out["head"] == "cafef00d"
    assert out["receipt_id"] == "pull-1"
    assert out["check_summary"] == {"runs": 1}


# -- F1: the real pull_executor's ledger row, not a hand-built receipt ---------

def _init_git_repo(path):
    subprocess.run(["git", "init", "-q", "-b", "master", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "t@example.com"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "test"], check=True)


def test_real_pull_executor_receipt_is_readable_by_check_merge(tmp_path, sealed_db):
    from willow_mcp import pull_executor

    # _repo_matches_remote (push_executor) matches the URL's LAST TWO path
    # segments against "org/name" -- name the local bare repo's path
    # accordingly so a real fetch/merge against it passes that check.
    remote = tmp_path / "willow-memory" / "willow-mcp.git"
    remote.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)

    seed = tmp_path / "seed"
    _init_git_repo(seed)
    (seed / "f.txt").write_text("one")
    subprocess.run(["git", "-C", str(seed), "add", "."], check=True)
    subprocess.run(["git", "-C", str(seed), "commit", "-q", "-m", "one"], check=True)
    subprocess.run(["git", "-C", str(seed), "remote", "add", "origin", str(remote)], check=True)
    subprocess.run(["git", "-C", str(seed), "push", "-q", "origin", "master"], check=True)

    checkout = tmp_path / "checkout"
    subprocess.run(["git", "clone", "-q", str(remote), str(checkout)], check=True)
    # Force branch "master" regardless of this git's init.defaultBranch --
    # the fixture must not depend on the ambient git config.
    subprocess.run(["git", "-C", str(checkout), "checkout", "-B", "master", "origin/master"], check=True)
    subprocess.run(["git", "-C", str(checkout), "config", "user.email", "t@example.com"], check=True)
    subprocess.run(["git", "-C", str(checkout), "config", "user.name", "test"], check=True)

    # A second commit lands on origin/master after the checkout cloned --
    # exactly what execute_pull is for.
    (seed / "f.txt").write_text("two")
    subprocess.run(["git", "-C", str(seed), "commit", "-q", "-am", "two"], check=True)
    subprocess.run(["git", "-C", str(seed), "push", "-q", "origin", "master"], check=True)

    ledger = _FakeLedger(None)
    result = pull_executor.execute_pull(
        "willow-bot", checkout=checkout, repo="willow-memory/willow-mcp",
        branch="master", project="willow-mcp", ledger=ledger)
    assert result["ok"] is True and result["changed"] is True

    rows = ledger._rows.get("git_pull", [])
    assert len(rows) == 1
    content = rows[0]["content"]
    # F1: the REAL ledger row carries remote_sha and changed -- the exact
    # two fields check_merge's own receipt match/read depend on, which the
    # OLD pull_executor never wrote.
    assert content["remote_sha"] == result["after"]
    assert content["changed"] is True

    config = _config(checkout, sealed_db)
    # The real merge commit is a real sha, not the "cafef00d" fixture
    # default -- name it explicitly so the fake PR/checks fixtures match
    # what execute_pull actually produced.
    api = _api(pr_response=_pr_ok(sha=result["after"]), checks_response=_checks_ok())
    out = reloader.check_merge(config, ledger=ledger, runner=_hybrid_runner(),
                               api=api, token_minter=_minter())
    assert out["ok"] is True and out["act"] is True
    assert out["receipt_id"] == rows[0]["id"]


# -- run_once_v2: dispatch and the act/receipt shape ------------------------------

def test_run_once_v2_falls_back_to_run_once_while_unsealed(checkout, unsealed_db, monkeypatch):
    config = _config(checkout, unsealed_db)
    ledger = _FakeLedger(_pull_receipt(checkout))
    called = {}

    def fake_run_once(cfg, *, ledger, runner=None, project="willow-mcp"):
        called["hit"] = True
        return {"ok": False, "act": False, "error": "ENORECEIPT", "reason": "x", "reloaded": False}

    monkeypatch.setattr(reloader, "run_once", fake_run_once)
    out = reloader.run_once_v2(config, ledger=ledger, runner=_Git())
    assert called.get("hit") is True
    assert out["error"] == "ENORECEIPT"


def test_run_once_v2_restarts_and_writes_merge_receipt_when_sealed_and_due(checkout, sealed_db):
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(_pull_receipt(checkout))
    api = _api(pr_response=_pr_ok(number=7), checks_response=_checks_ok())
    git = _Git()
    out = reloader.run_once_v2(config, ledger=ledger, runner=git, api=api, token_minter=_minter())
    assert out["reloaded"] is True
    assert "merge" in out["triggers"]
    assert git.restarts, "the restart call was never made"
    rows = ledger._rows.get(reloader.MERGE_EVENT, [])
    assert len(rows) == 1
    assert rows[0]["content"]["pull_receipt_id"] == "pull-1"
    assert rows[0]["content"]["pr_number"] == 7


def test_run_once_v2_never_restarts_twice_for_the_same_receipt(checkout, sealed_db):
    config = _config(checkout, sealed_db)
    receipt = _pull_receipt(checkout)
    ledger = _FakeLedger(receipt)
    api = _api(pr_response=_pr_ok(), checks_response=_checks_ok())
    git = _Git()
    first = reloader.run_once_v2(config, ledger=ledger, runner=git, api=api, token_minter=_minter())
    assert first["reloaded"] is True
    second = reloader.run_once_v2(config, ledger=ledger, runner=git, api=api, token_minter=_minter())
    assert second.get("reloaded") is not True
    assert len(git.restarts) == 1


# -- F4/F5: refusal ledger dedup -------------------------------------------------

def test_run_once_v2_writes_a_refusal_receipt_naming_the_reason_code(checkout, sealed_db):
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(None)
    out = reloader.run_once_v2(config, ledger=ledger, runner=_Git())
    assert out["error"] == "ENORECEIPT"
    rows = ledger._rows.get(reloader.MERGE_REFUSAL_EVENT, [])
    assert len(rows) == 1
    assert rows[0]["content"]["error"] == "ENORECEIPT"


def test_run_once_v2_idle_ticks_write_no_new_refusal_row(checkout, sealed_db):
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(None)
    reloader.run_once_v2(config, ledger=ledger, runner=_Git())
    reloader.run_once_v2(config, ledger=ledger, runner=_Git())
    reloader.run_once_v2(config, ledger=ledger, runner=_Git())
    rows = ledger._rows.get(reloader.MERGE_REFUSAL_EVENT, [])
    assert len(rows) == 1


def test_run_once_v2_writes_a_new_refusal_row_when_the_reason_changes(checkout, sealed_db):
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(None)
    reloader.run_once_v2(config, ledger=ledger, runner=_Git())  # ENORECEIPT
    ledger.receipt = _pull_receipt(checkout, after="cafef00d", remote_sha="deadbeef")  # ENOTMERGED
    reloader.run_once_v2(config, ledger=ledger, runner=_Git())
    rows = ledger._rows.get(reloader.MERGE_REFUSAL_EVENT, [])
    assert len(rows) == 2
    assert {r["content"]["error"] for r in rows} == {"ENORECEIPT", "ENOTMERGED"}


# -- F6: EPARTIAL records its own error plus both causes -----------------------

def test_run_once_v2_epartial_refusal_records_error_and_both_causes(checkout, sealed_db, monkeypatch):
    """EPARTIAL only fires when at least one trigger IS due while the
    other is open-but-unconfirmed (env due here, merge open on
    ENOTMERGED) -- F6 requires the refusal row to carry error="EPARTIAL"
    itself plus BOTH triggers' own errors (the due side's is None), never
    error=None the way the pre-rework row did."""
    _stub_env_due(monkeypatch)
    config = _config(checkout, sealed_db)
    receipt = _pull_receipt(checkout, after="cafef00d", remote_sha="deadbeef")  # ENOTMERGED, open not due
    ledger = _FakeLedger(receipt)
    out = reloader.run_once_v2(config, ledger=ledger, runner=_Git())
    assert out["error"] == "EPARTIAL"
    rows = ledger._rows.get(reloader.MERGE_REFUSAL_EVENT, [])
    assert len(rows) == 1
    assert rows[0]["content"]["error"] == "EPARTIAL"
    assert rows[0]["content"]["merge_error"] == "ENOTMERGED"
    assert rows[0]["content"]["env_error"] is None


# -- F7: a failed restart writes a refusal receipt ------------------------------

def test_run_once_v2_erestart_writes_a_refusal_receipt(checkout, sealed_db):
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(_pull_receipt(checkout))
    api = _api(pr_response=_pr_ok(), checks_response=_checks_ok())
    git = _Git(restart_rc=1)
    out = reloader.run_once_v2(config, ledger=ledger, runner=git, api=api, token_minter=_minter())
    assert out["error"] == "ERESTART"
    rows = ledger._rows.get(reloader.MERGE_REFUSAL_EVENT, [])
    assert len(rows) == 1
    assert rows[0]["content"]["error"] == "ERESTART"


# -- F3: the env trigger must not restart onto unconfirmed merge state ---------

def _stub_env_due(monkeypatch):
    def fake_check_env(cfg, *, ledger, runner=None):
        return {"ok": True, "act": True, "unit": cfg.unit, "env_path": "/x", "receipt_id": "env-1",
                "receipt": {}, "seal": {"pair_id": "p", "verifier": "v"}, "state_before": {}}
    monkeypatch.setattr(reloader, "check_env", fake_check_env)


def test_run_once_v2_env_trigger_blocked_by_enotmaster(checkout, sealed_db, monkeypatch):
    _stub_env_due(monkeypatch)
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(_pull_receipt(checkout))
    git = _Git(branch="feat/x")
    out = reloader.run_once_v2(config, ledger=ledger, runner=git)
    assert out["error"] == "EPARTIAL" and out["merge"]["error"] == "ENOTMASTER"
    assert not git.restarts


def test_run_once_v2_env_trigger_blocked_by_edrift(checkout, sealed_db, monkeypatch):
    _stub_env_due(monkeypatch)
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(_pull_receipt(checkout, after="cafef00d"))
    git = _Git(head="movedagain")
    out = reloader.run_once_v2(config, ledger=ledger, runner=git)
    assert out["error"] == "EPARTIAL" and out["merge"]["error"] == "EDRIFT"
    assert not git.restarts


def test_run_once_v2_env_trigger_blocked_by_enotmerged_after_neq_remote_sha(checkout, sealed_db, monkeypatch):
    _stub_env_due(monkeypatch)
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(_pull_receipt(checkout, after="cafef00d", remote_sha="deadbeef"))
    git = _Git()
    out = reloader.run_once_v2(config, ledger=ledger, runner=git)
    assert out["error"] == "EPARTIAL" and out["merge"]["error"] == "ENOTMERGED"
    assert not git.restarts


def test_run_once_v2_env_trigger_blocked_by_enotmerged_no_pr_names_the_sha(checkout, sealed_db, monkeypatch):
    _stub_env_due(monkeypatch)
    config = _config(checkout, sealed_db)
    ledger = _FakeLedger(_pull_receipt(checkout))
    api = _api(pr_response=_pr_empty())
    git = _Git()
    out = reloader.run_once_v2(config, ledger=ledger, runner=git, api=api, token_minter=_minter())
    assert out["error"] == "EPARTIAL" and out["merge"]["error"] == "ENOTMERGED"
    assert not git.restarts
