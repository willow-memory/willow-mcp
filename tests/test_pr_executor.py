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
    """The pr-open executor talks to three endpoints now: ``GET /compare/…``
    (the remote-base preflight, gap bc9945dd47da), ``GET /contents/…`` (the
    PR template preflight, gap 378c2e57c3d0), and ``POST /pulls`` (the PR
    create). ``_FakeApi`` answers each; defaults produce ``ahead`` compare
    and 404 on every template lookup so existing tests keep landing at
    ``no_template`` (proceed). Tests that exercise the template path pass a
    non-empty ``template`` to serve the first well-known path.
    """

    def __init__(self, *, status=201, ok=True, reason="",
                 compare_status="ahead", compare_ahead_by=5, compare_behind_by=0,
                 compare_ok=True, compare_http_status=200, compare_reason="",
                 template="", template_path=".github/pull_request_template.md",
                 template_from="repo"):
        self.calls: list[dict] = []
        self.status, self.ok, self.reason = status, ok, reason
        self.compare_status = compare_status
        self.compare_ahead_by = compare_ahead_by
        self.compare_behind_by = compare_behind_by
        self.compare_ok = compare_ok
        self.compare_http_status = compare_http_status
        self.compare_reason = compare_reason
        self.template = template
        self.template_path = template_path
        self.template_from = template_from  # "repo" | "org"

    def __call__(self, method, url, *, bearer, body=None):
        self.calls.append({"method": method, "url": url, "bearer": bearer, "body": body})
        if "/compare/" in url:
            if not self.compare_ok:
                return {"ok": False, "status": self.compare_http_status,
                        "reason": self.compare_reason}
            return {
                "ok": True, "status": self.compare_http_status,
                "body": {
                    "status": self.compare_status,
                    "ahead_by": self.compare_ahead_by,
                    "behind_by": self.compare_behind_by,
                    "base_commit": {"sha": "base-sha"},
                    "merge_base_commit": {"sha": "base-sha"},
                    "commits": [{"sha": "head-sha"}],
                },
            }
        if "/contents/" in url:
            if not self.template:
                return {"ok": False, "status": 404, "reason": "Not Found"}
            wanted = (f"/repos/forge-play/Forge/contents/{self.template_path}"
                      if self.template_from == "repo" else
                      f"/repos/forge-play/.github/contents/{self.template_path}")
            if wanted in url:
                import base64
                content = base64.b64encode(self.template.encode()).decode()
                return {"ok": True, "status": 200,
                        "body": {"type": "file", "encoding": "base64",
                                 "content": content, "path": self.template_path}}
            return {"ok": False, "status": 404, "reason": "Not Found"}
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
    # The remote-base preflight compare runs before the atomic citation, the
    # PR template preflight runs after (both before citation, gap
    # bc9945dd47da / 378c2e57c3d0), and the POST /pulls runs last.
    compares = [c for c in api.calls if "/compare/" in c["url"]]
    posts = [c for c in api.calls if c["method"] == "POST" and c["url"].endswith("/pulls")]
    assert len(compares) == 1 and compares[0]["url"].endswith("/compare/master...feat/x")
    assert len(posts) == 1
    post = posts[0]
    assert post["bearer"] == "ghs_test_token"
    assert post["body"] == {"title": "feat: x", "head": "feat/x", "base": "master",
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
    # Post-migration (gap 5ecb87cfdf56 follow-up): the gate id carries the
    # base (`pr.<repo>:<base>` — envelope bounds); the head rides in the
    # summary alongside the reason. Assert both surface.
    assert any(
        "master" in (r.get("title") or "") and "feat/x" in (r.get("summary") or "")
        for r in rows
    )


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
    posts_after_first = [c for c in api.calls if c["method"] == "POST" and c["url"].endswith("/pulls")]
    again = _open(pg, api)
    assert not again["ok"] and again["error"] == "EDQUOT"
    # Only one POST /pulls ever happened; the second (EDQUOT) refused at the
    # cheap bounds check before any network preflight or POST.
    posts_after_second = [c for c in api.calls if c["method"] == "POST" and c["url"].endswith("/pulls")]
    assert len(posts_after_first) == 1
    assert len(posts_after_second) == 1  # unchanged — no POST on the EDQUOT retry


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


# ── the PR lands on the operator's list ──────────────────────────────────────
#
# github.com/pulls and the mobile app list what you created / are assigned /
# are mentioned in / were asked to review. The bot created it, so a bot PR was
# on none of those lists (operator, 2026-09-14). The broker asks for the
# operator's review and assigns it to them, from a login in the seat env.


class _ApiWithFollowups(_FakeApi):
    def __init__(self, *, review_ok=True, assign_ok=True):
        super().__init__()
        self.review_ok, self.assign_ok = review_ok, assign_ok

    def __call__(self, method, url, *, bearer, body=None):
        if url.endswith("/requested_reviewers"):
            self.calls.append({"method": method, "url": url, "bearer": bearer, "body": body})
            return {"ok": True, "status": 201, "body": {}} if self.review_ok else \
                {"ok": False, "status": 422, "reason": "Review cannot be requested from pull request author."}
        if url.endswith("/assignees"):
            self.calls.append({"method": method, "url": url, "bearer": bearer, "body": body})
            return {"ok": True, "status": 201, "body": {}} if self.assign_ok else \
                {"ok": False, "status": 403, "reason": "Resource not accessible by integration"}
        return super().__call__(method, url, bearer=bearer, body=body)


def test_the_operator_is_asked_to_review_and_assigned(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    monkeypatch.setenv("WILLOW_OPERATOR_GITHUB_LOGIN", "the-operator")
    api = _ApiWithFollowups()
    out = _open(_FakeGovernancePg(), api)
    assert out["ok"]
    assert out["operator"] == {"login": "the-operator", "review_requested": True, "assigned": True}
    # The follow-up review/assign calls come after the POST /pulls; the
    # template preflight lookups happen before it and are not asserted here
    # (their exact count depends on the resolver's path list).
    urls = [c["url"] for c in api.calls]
    review_urls = [u for u in urls if u.endswith("/requested_reviewers")]
    assignee_urls = [u for u in urls if u.endswith("/assignees")]
    pulls_urls = [u for u in urls if u.endswith("/pulls")]
    assert pulls_urls == ["https://api.github.com/repos/forge-play/Forge/pulls"]
    assert review_urls == ["https://api.github.com/repos/forge-play/Forge/pulls/31/requested_reviewers"]
    assert assignee_urls == ["https://api.github.com/repos/forge-play/Forge/issues/31/assignees"]
    review_call = next(c for c in api.calls if c["url"].endswith("/requested_reviewers"))
    assignee_call = next(c for c in api.calls if c["url"].endswith("/assignees"))
    assert review_call["body"] == {"reviewers": ["the-operator"]}
    assert assignee_call["body"] == {"assignees": ["the-operator"]}
    assert all(c["bearer"] == "ghs_test_token" for c in api.calls)


def test_no_login_configured_is_said_not_pretended(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    monkeypatch.delenv("WILLOW_OPERATOR_GITHUB_LOGIN", raising=False)
    api = _ApiWithFollowups()
    out = _open(_FakeGovernancePg(), api)
    assert out["ok"] and out["operator"]["login"] is None
    assert out["operator"]["review_requested"] is False and out["operator"]["assigned"] is False
    assert "WILLOW_OPERATOR_GITHUB_LOGIN" in out["operator"]["detail"]
    # No follow-up review/assign calls without a login; the POST /pulls
    # itself and the preflight lookups still happened.
    urls = [c["url"] for c in api.calls]
    assert not any(u.endswith("/requested_reviewers") for u in urls)
    assert not any(u.endswith("/assignees") for u in urls)
    assert any(u.endswith("/pulls") for u in urls)


def test_a_refused_followup_does_not_unopen_the_pr(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    monkeypatch.setenv("WILLOW_OPERATOR_GITHUB_LOGIN", "the-operator")
    api = _ApiWithFollowups(review_ok=False, assign_ok=True)
    out = _open(_FakeGovernancePg(), api)
    assert out["ok"] and out["opened"] and out["number"] == 31
    assert out["operator"]["review_requested"] is False and "422" in out["operator"]["review_error"]
    assert out["operator"]["assigned"] is True


# ── the seat that asked is on the record the steward reads (pair 11ccb0f7) ──

def test_a_granted_open_names_who_asked_and_writes_the_watch_row(home, tmp_path, monkeypatch):
    from willow_mcp import pr_watch

    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    out = _open(_FakeGovernancePg(), _FakeApi(), session="sess-371aa2fc")
    assert out["ok"] and out["opened"]
    assert out["opened_by"] == {"app_id": "willow", "session_id": "sess-371aa2fc",
                               "grove_channel": "#willow"}
    assert out["watch"]["state"] == "populated"
    assert out["watch"]["key"] == "forge-play/Forge#31"
    table = pr_watch.load()
    row = table["forge-play/Forge#31"]
    assert row["app_id"] == "willow" and row["session_id"] == "sess-371aa2fc"
    assert row["channel"] == "#willow" and row["head"] == "feat/x"
    assert row["opened_at"].endswith("Z")
    # The steward's own state root, not the seat's.
    assert pr_watch.watch_path().parent.name == "willow-bot"


def test_the_watch_row_is_exactly_the_seat_and_nothing_else(home, tmp_path, monkeypatch):
    """The row names the seat by app_id/session/channel/head/opened_at — a
    fixed key set, so a credential cannot ride along unnoticed."""
    from willow_mcp import pr_watch

    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    _open(_FakeGovernancePg(), _FakeApi(), session="s")
    row = pr_watch.load()["forge-play/Forge#31"]
    assert set(row) == {"app_id", "session_id", "channel", "opened_at", "head"}
    assert row["session_id"] == "s" and row["app_id"] == "willow"


def test_a_second_open_adds_a_row_and_keeps_the_first(home, tmp_path, monkeypatch):
    from willow_mcp import pr_watch

    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    _open(_FakeGovernancePg(), _FakeApi(), session="s1")
    pr_watch.record(repo="forge-play/Forge", number=7, app_id="hanuman", session_id="s2", head="feat/y")
    table = pr_watch.load()
    assert set(table) == {"forge-play/Forge#31", "forge-play/Forge#7"}
    assert table["forge-play/Forge#7"]["channel"] == "#hanuman"


def test_an_unwritable_watch_root_is_reported_not_raised(home, tmp_path, monkeypatch):
    from willow_mcp import pr_watch

    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    # A file where the directory must be: mkdir fails, the PR is still open.
    (pr_watch.watch_path().parent).write_text("not a directory")
    out = _open(_FakeGovernancePg(), _FakeApi(), session="s")
    assert out["ok"] and out["opened"] and out["number"] == 31
    assert out["watch"]["state"] == "unreachable" and out["watch"]["reason"]
    assert pr_watch.load() == {}


def test_a_malformed_watch_file_reads_as_empty(home, tmp_path):
    from willow_mcp import pr_watch

    p = pr_watch.watch_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{not json")
    assert pr_watch.load() == {}
    p.write_text("[1, 2]")
    assert pr_watch.load() == {}


# ── the tool is wired the way git_push_execute is ────────────────────────────

def test_pr_open_execute_is_gated_as_envelope_apply_by_name():
    catalogue = server._gate_tool_catalogue()
    assert catalogue["pr_open_execute"] == "envelope_apply"


# ── remote-base ancestry preflight (gap bc9945dd47da) ────────────────────────

def test_behind_base_is_refused_with_estale_before_citation(home, tmp_path, monkeypatch):
    """A head that is entirely behind the base on GitHub is stale — the
    envelope must not be consumed and no POST is attempted."""
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi(compare_status="behind",
                                            compare_ahead_by=0, compare_behind_by=4)
    out = _open(pg, api)
    assert out["ok"] is False and out["opened"] is False
    assert out["error"] == "ESTALE"
    assert out["preflight"]["state"] == "behind"
    assert out["preflight"]["behind"] == 4
    # Only the compare call happened; no POST to /pulls.
    urls = [c["url"] for c in api.calls]
    assert urls == ["https://api.github.com/repos/forge-play/Forge/compare/master...feat/x"]
    # No granted citation — the audit citation from `authorize_and_cite` did
    # not run because the preflight refused first. (An EAMBIG citation from
    # the cheap check is also absent because bounds match.)
    assert _citations(pg) == []


def test_diverged_base_is_refused_with_estale(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi(compare_status="diverged",
                                            compare_ahead_by=2, compare_behind_by=3)
    out = _open(pg, api)
    assert out["error"] == "ESTALE"
    assert out["preflight"]["state"] == "diverged"
    assert out["preflight"]["ahead"] == 2 and out["preflight"]["behind"] == 3
    assert _citations(pg) == []
    assert not any(c["url"].endswith("/pulls") for c in api.calls if c["method"] == "POST")


def test_identical_base_is_treated_as_current_and_pushes(home, tmp_path, monkeypatch):
    """An `identical` compare status (head == base) does not itself refuse —
    the PR-open call itself will 422 if base and head are the same commit,
    which the executor reports as EPR. That is a remote refusal AFTER
    citation, not a preflight refusal BEFORE it."""
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi(compare_status="identical",
                                            compare_ahead_by=0, compare_behind_by=0)
    out = _open(pg, api)
    assert out["ok"] is True and out["opened"] is True
    assert out["preflight"]["state"] == "current"


def test_compare_http_failure_is_efetch_before_citation(home, tmp_path, monkeypatch):
    """A 5xx from GitHub during the preflight compare is EFETCH — refuse
    before citation and do not attempt the POST."""
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi(compare_ok=False,
                                            compare_http_status=502,
                                            compare_reason="Bad Gateway")
    out = _open(pg, api)
    assert out["error"] == "EFETCH"
    assert "502" in out["reason"] and "Bad Gateway" in out["reason"]
    assert _citations(pg) == []
    urls = [c["url"] for c in api.calls]
    assert urls == ["https://api.github.com/repos/forge-play/Forge/compare/master...feat/x"]


def test_preflight_receipt_rides_on_a_successful_open(home, tmp_path, monkeypatch):
    """A granted open carries the preflight receipt so the seat can prove the
    check happened (and see the ahead/behind counts as evidence)."""
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    out = _open(_FakeGovernancePg(),
                _FakeApi(compare_status="ahead", compare_ahead_by=7, compare_behind_by=0))
    assert out["ok"] and out["opened"]
    pf = out["preflight"]
    assert pf["state"] == "current"
    assert pf["ahead"] == 7 and pf["behind"] == 0


def test_a_stale_preflight_does_not_spend_a_single_use_grant(home, tmp_path, monkeypatch):
    """The key promise: an ESTALE refusal does NOT consume a max_count=1
    grant. A second attempt after the head is refreshed can still cite."""
    _charter(tmp_path, monkeypatch, max_count=1)
    _app_token(monkeypatch)
    pg = _FakeGovernancePg()
    # First: stale head, ESTALE, no consumption.
    stale_api = _FakeApi(compare_status="behind", compare_ahead_by=0, compare_behind_by=1)
    first = _open(pg, stale_api)
    assert first["error"] == "ESTALE"
    # Second: head refreshed, compare returns `ahead`, grant is still available.
    fresh_api = _FakeApi()
    second = _open(pg, fresh_api)
    assert second["ok"] and second["opened"]
    # Only the second attempt cited (as `granted`).
    granted = [c for c in _citations(pg) if c["content"]["outcome"] == "granted"]
    assert len(granted) == 1


# ── PR template enforcement (gap 378c2e57c3d0) ───────────────────────────────

_TEMPLATE = """## Bite

_a one-line summary of what this PR delivers_

## What was done

_the change, in commits_

## Evidence

_receipts_

## Out of scope

_what is deliberately not here_

## Next bite

_the follow-up_
"""


_GOOD_BODY = """## Bite

Ancestry preflight.

## What was done

The base preflight refuses stale heads.

## Evidence

Tests pass.

## Out of scope

Workflow preflight (separate PR).

## Next bite

Ship it.
"""

_MISSING_EVIDENCE = """## Bite

Ancestry preflight.

## What was done

The base preflight refuses stale heads.

## Out of scope

Workflow preflight.

## Next bite

Ship it.
"""


def test_a_body_matching_the_template_is_accepted(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi(template=_TEMPLATE)
    out = _open(pg, api, body=_GOOD_BODY)
    assert out["ok"] and out["opened"], out
    tpl = out["template"]
    assert tpl["state"] == "complete"
    assert tpl["template_source"] == "repo:.github/pull_request_template.md"
    assert set(tpl["sections"]) >= {"bite", "what was done", "evidence", "out of scope", "next bite"}


def test_a_body_missing_a_required_section_is_ebody_before_citation(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi(template=_TEMPLATE)
    out = _open(pg, api, body=_MISSING_EVIDENCE)
    assert out["ok"] is False and out["opened"] is False
    assert out["error"] == "EBODY"
    tpl = out["template"]
    assert tpl["state"] == "missing_sections"
    assert tpl["missing"] == ["evidence"]
    # No POST — the envelope was NOT consumed.
    urls = [c["url"] for c in api.calls]
    assert not any(u.endswith("/pulls") for u in urls)
    granted = [c for c in _citations(pg) if c["content"]["outcome"] == "granted"]
    assert granted == []


def test_absent_template_is_not_a_refusal_but_a_no_template_state(home, tmp_path, monkeypatch):
    """A repo with no PR template (and no org-level one) opens PRs with any
    body — there is no shape to enforce. The template receipt names the
    absence explicitly rather than pretending the check passed."""
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi(template="")  # 404 on every contents lookup
    out = _open(pg, api, body="anything")
    assert out["ok"] and out["opened"]
    assert out["template"]["state"] == "no_template"


def test_a_template_with_no_headings_enforces_no_sections(home, tmp_path, monkeypatch):
    """A template that is prose only (no `##` headings) is a template that
    names no required sections. The preflight passes with `no_headings`."""
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi(template="Please describe your changes.")
    out = _open(pg, api, body="did the thing")
    assert out["ok"] and out["opened"]
    assert out["template"]["state"] == "no_headings"


def test_org_fallback_is_used_when_the_repo_has_no_template(home, tmp_path, monkeypatch):
    """The repo has no template, but ``forge-play/.github`` carries one — the
    resolver uses the org fallback."""
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi(template=_TEMPLATE, template_from="org")
    out = _open(pg, api, body=_GOOD_BODY)
    assert out["ok"] and out["opened"]
    assert out["template"]["template_source"].startswith("org:")


def test_enforce_template_can_be_disabled(home, tmp_path, monkeypatch):
    """Some workflows (a bot opening a series of tiny follow-up PRs against
    a repo with a heavyweight template) need to bypass the shape check;
    `enforce_template=False` skips it entirely, and the receipt names why."""
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi(template=_TEMPLATE)
    out = _open(pg, api, body="empty", enforce_template=False)
    assert out["ok"] and out["opened"]
    assert out["template"]["state"] == "not_enforced"
    # No /contents/ calls happened — the resolver never ran.
    assert not any("/contents/" in c["url"] for c in api.calls)
