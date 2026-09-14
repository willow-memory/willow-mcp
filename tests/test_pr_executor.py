"""The brokered PR open (gap ee5ff1342c37) — push_executor's sibling for verb 4.

The agent asks; this process checks and cites the pr.open envelope, files the
ask on a miss, mints the willows-bot token, and only then POSTs. No network
before the citation, and none at all here: the GitHub call is a fake.
"""
from __future__ import annotations

import json

import pytest

from willow_mcp import pr_executor as prx
from willow_mcp import server


# ── a fake frank ledger, same shape as test_push_executor ───────────────────

class _FakeGovernancePg:
    def __init__(self):
        self.rows = []
        self.commits = 0

    def cursor(self):
        return _FakeGovernanceCursor(self)

    def commit(self):
        self.commits += 1


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
        if s.startswith("INSERT INTO"):
            record_id, project, event_type, content, prev_hash, digest = params
            self.pg.rows.append({
                "id": record_id, "project": project, "event_type": event_type,
                "content": getattr(content, "adapted", content),
                "prev_hash": prev_hash, "hash": digest,
            })
            return
        raise AssertionError(f"unexpected SQL: {sql!r}")

    def fetchone(self):
        return self._result[0] if self._result else None

    def close(self):
        pass


def _ledger(pg):
    from willow_mcp.governance_ledger import GovernanceLedger
    return GovernanceLedger(pg)


def _citations(pg):
    return [r for r in pg.rows if r["event_type"] == "envelope_citation"]


# ── registry with one pr.open grant ─────────────────────────────────────────

def _charter(tmp_path, monkeypatch, *, grantee="willow", bases=("master",),
             extra=None, expires="2027-01-01", max_count=None):
    active = [{
        "id": "env-pr.open-test",
        "verb_id": 4,
        "verb": "pr.open",
        "grantee": grantee,
        "bounds": {"repo": "forge-play/Forge", "base_branches": list(bases)},
        "issued_by": "root",
        "issued_at": "2026-01-01",
        "expires_at": expires,
        "max_count": max_count,
        "use_count_source": "frank",
        "status": "active",
    }] + list(extra or [])
    table = {"verbs": [{"id": 4, "verb": "pr.open",
                        "bounds": {"repo": "s", "base_branches": "l"}}]}
    reg = tmp_path / "pre-approved.json"
    tab = tmp_path / "syscall-table.json"
    tmp_path.chmod(0o700)
    reg.write_text(json.dumps({"active": active}))
    tab.write_text(json.dumps(table))
    reg.chmod(0o600)
    tab.chmod(0o600)
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(reg))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(tab))


# ── a fake GitHub ───────────────────────────────────────────────────────────

class _FakeApi:
    def __init__(self, *, status=201, ok=True, reason=""):
        self.calls: list[dict] = []
        self.status, self.ok, self.reason = status, ok, reason

    def __call__(self, method, url, *, bearer, body=None):
        self.calls.append({"method": method, "url": url, "bearer": bearer, "body": body})
        if not self.ok:
            return {"ok": False, "status": self.status, "reason": self.reason}
        return {"ok": True, "status": self.status,
                "body": {"number": 31, "html_url": "https://github.com/forge-play/Forge/pull/31"}}


def _app_token(monkeypatch, *, pulls="write"):
    monkeypatch.setattr(
        "willow_mcp.github_app_credentials.mint_installation_token",
        lambda repo: {"ok": True, "mode": "app", "token": "ghs_test_token",
                      "permissions": {"contents": "write", "pull_requests": pulls},
                      "installation_id": 1},
    )


def _open(pg, api, **kw):
    args = dict(app_id="willow", repo="forge-play/Forge", head="feat/x", base="master",
                title="feat: x", body="the body", project="forge-play", ledger=_ledger(pg),
                api=api)
    args.update(kw)
    return prx.execute_pr_open(args.pop("app_id"), **args)


# ── granted ──────────────────────────────────────────────────────────────────

def test_granted_open_cites_then_posts_as_the_app(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi()
    out = _open(pg, api)
    assert out["ok"] and out["opened"], out
    assert out["number"] == 31 and out["url"].endswith("/pull/31")
    assert out["envelope_id"] == "env-pr.open-test" and out["auth_mode"] == "app"
    assert len(api.calls) == 1
    call = api.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == "https://api.github.com/repos/forge-play/Forge/pulls"
    assert call["bearer"] == "ghs_test_token"
    assert call["body"] == {"title": "feat: x", "head": "feat/x", "base": "master",
                            "body": "the body", "draft": False}
    cites = _citations(pg)
    assert len(cites) == 1 and cites[0]["content"]["outcome"] == "granted"
    assert cites[0]["content"]["call_args"] == {"repo": "forge-play/Forge",
                                                "base_branches": ["master"]}
    assert out["citation_id"] == cites[0]["id"]


def test_the_token_is_not_in_the_receipt(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    out = _open(_FakeGovernancePg(), _FakeApi())
    assert "ghs_test_token" not in json.dumps(out)


# ── refused before any network ───────────────────────────────────────────────

def test_base_outside_bounds_is_refused_cited_and_asked(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch, bases=("main",))
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi()
    out = _open(pg, api)
    assert out["ok"] is False and out["opened"] is False
    assert out["error"] == "EAMBIG" and "base_branches" in out["fields"]
    assert api.calls == []
    assert _citations(pg)[0]["content"]["outcome"] == "EAMBIG"
    assert out["ask"]["queued"] is True
    from willow_mcp import human_loop
    from willow_mcp.db import Store
    rows = human_loop.list_queue(Store())
    assert any("feat/x" in (r.get("title") or "") for r in rows)


def test_foreign_repo_is_refused(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi()
    out = _open(pg, api, repo="someone-else/Forge")
    assert not out["ok"] and out["error"] == "EAMBIG" and "repo" in out["fields"]
    assert api.calls == []


def test_no_envelope_is_enoent_and_asked(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch, grantee="hanuman")
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi()
    out = _open(pg, api)
    assert out["error"] == "ENOENT" and out["ask"]["queued"] is True
    assert api.calls == [] and _citations(pg) == []


def test_a_spent_single_use_grant_is_edquot(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch, max_count=1)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi()
    assert _open(pg, api)["ok"]
    again = _open(pg, api)
    assert not again["ok"] and again["error"] == "EDQUOT"
    assert len(api.calls) == 1


@pytest.mark.parametrize("bad", [
    dict(repo="Forge"), dict(head=""), dict(base=""), dict(title="  "),
    dict(head="-x"), dict(base="--force"),
])
def test_malformed_asks_are_einval_before_the_registry(home, tmp_path, monkeypatch, bad):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi()
    out = _open(pg, api, **bad)
    assert out["error"] == "EINVAL" and api.calls == [] and _citations(pg) == []


def test_no_ledger_is_refused_without_a_request(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    api = _FakeApi()
    out = _open(_FakeGovernancePg(), api, ledger=None)
    assert out["error"] == "EAMBIG" and "cited" in out["reason"] and api.calls == []


# ── the credential: the App or nothing ───────────────────────────────────────

def test_no_app_coverage_is_eauth_not_a_host_fallback(home, tmp_path, monkeypatch):
    """The push falls back to the host helper; the PR does not. A PR opened
    on the operator's token is authored by the operator, and the point of
    this verb is that the bot's acts are the bot's."""
    _charter(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "willow_mcp.github_app_credentials.mint_installation_token",
        lambda repo: {"ok": False, "mode": "host", "reason": "willows-bot is not installed on forge-play/Forge"},
    )
    pg, api = _FakeGovernancePg(), _FakeApi()
    out = _open(pg, api)
    assert not out["ok"] and out["error"] == "EAUTH"
    assert "not installed" in out["reason"]
    assert api.calls == []
    # The grant was checked and cited before the credential was consulted.
    assert _citations(pg)[0]["content"]["outcome"] == "granted"


def test_pull_requests_read_only_is_eperm(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch, pulls="read")
    pg, api = _FakeGovernancePg(), _FakeApi()
    out = _open(pg, api)
    assert not out["ok"] and out["error"] == "EPERM" and "Pull requests" in out["reason"]
    assert api.calls == []


def test_github_refusal_is_epr_with_the_status(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi(ok=False, status=422, reason="A pull request already exists")
    out = _open(pg, api)
    assert not out["ok"] and out["opened"] is False and out["error"] == "EPR"
    assert "422" in out["reason"] and "already exists" in out["reason"]
    assert out["citation_id"]


# ── the tool is wired the way git_push_execute is ────────────────────────────

def test_pr_open_execute_is_gated_as_envelope_apply_by_name():
    catalogue = server._gate_tool_catalogue()
    assert catalogue["pr_open_execute"] == "envelope_apply"
