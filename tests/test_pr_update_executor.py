"""The brokered PR update (gap 8d1bcb2b7c02) — pr_open_execute's sibling for
verb 16, `pr.update`, sealed `783bab4e`.

The agent asks; this process checks and cites the `pr.update` envelope,
files the ask on a miss, mints the willows-bot token, verifies the PR is one
the App itself opened, and only then PATCHes/labels. No network before the
citation, and none at all here: the GitHub call is a fake.
"""
from __future__ import annotations

import json

import pytest

from willow_mcp import pr_update_executor as prux
from willow_mcp import server


# ── a fake frank ledger, same shape as test_pr_executor ─────────────────────

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


# ── registry with one pr.update grant ────────────────────────────────────────

def _charter(tmp_path, monkeypatch, *, grantee="willow",
             fields=("title", "body", "labels"), extra=None,
             expires="2027-01-01", max_count=None):
    active = [{
        "id": "env-pr.update-test",
        "verb_id": 16,
        "verb": "pr.update",
        "grantee": grantee,
        "bounds": {"repo": "forge-play/Forge", "fields": list(fields)},
        "issued_by": "root",
        "issued_at": "2026-01-01",
        "expires_at": expires,
        "max_count": max_count,
        "use_count_source": "frank",
        "status": "active",
    }] + list(extra or [])
    table = {"verbs": [{"id": 16, "verb": "pr.update",
                        "bounds": {"repo": "s", "fields": "l"}}]}
    reg = tmp_path / "pre-approved.json"
    tab = tmp_path / "syscall-table.json"
    tmp_path.chmod(0o700)
    reg.write_text(json.dumps({"active": active}))
    tab.write_text(json.dumps(table))
    reg.chmod(0o600)
    tab.chmod(0o600)
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(reg))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(tab))


# ── a fake GitHub ─────────────────────────────────────────────────────────────

_BOT_LOGIN = "willows-bot[bot]"

_TEMPLATE = """## Bite

_a one-line summary_

## What was done

_the change_
"""

_GOOD_BODY = """## Bite

Fix the title.

## What was done

Retyped the commit; pr-title.yml needed a matching PR title.
"""

_MISSING_SECTION_BODY = """## Bite

Fix the title.
"""


class _FakeApi:
    """Answers GET /pulls/{number}, GET /contents/... (template), PATCH
    /pulls/{number}, POST/DELETE /issues/{number}/labels. Defaults: PR is
    open, bot-authored, no existing labels, no template (proceed)."""

    def __init__(self, *, pr_status=200, pr_ok=True, pr_reason="",
                 state="open", author_login=_BOT_LOGIN, author_type="Bot",
                 existing_labels=(), template="",
                 patch_ok=True, patch_status=200, patch_reason="",
                 labels_ok=True, labels_status=200, labels_reason=""):
        self.calls: list[dict] = []
        self.pr_status, self.pr_ok, self.pr_reason = pr_status, pr_ok, pr_reason
        self.state = state
        self.author_login = author_login
        self.author_type = author_type
        self.existing_labels = list(existing_labels)
        self.template = template
        self.patch_ok, self.patch_status, self.patch_reason = patch_ok, patch_status, patch_reason
        self.labels_ok, self.labels_status, self.labels_reason = labels_ok, labels_status, labels_reason

    def __call__(self, method, url, *, bearer, body=None):
        self.calls.append({"method": method, "url": url, "bearer": bearer, "body": body})
        if method == "GET" and "/pulls/" in url and "/contents/" not in url:
            if not self.pr_ok:
                return {"ok": False, "status": self.pr_status, "reason": self.pr_reason}
            return {
                "ok": True, "status": 200,
                "body": {
                    "number": 31, "state": self.state, "title": "old title",
                    "body": "old body",
                    "user": {"login": self.author_login, "type": self.author_type},
                    "labels": [{"name": n} for n in self.existing_labels],
                },
            }
        if "/contents/" in url:
            if not self.template:
                return {"ok": False, "status": 404, "reason": "Not Found"}
            import base64
            wanted = "/repos/forge-play/Forge/contents/.github/pull_request_template.md"
            if wanted in url:
                content = base64.b64encode(self.template.encode()).decode()
                return {"ok": True, "status": 200,
                        "body": {"type": "file", "encoding": "base64",
                                 "content": content,
                                 "path": ".github/pull_request_template.md"}}
            return {"ok": False, "status": 404, "reason": "Not Found"}
        if method == "PATCH" and "/pulls/" in url:
            if not self.patch_ok:
                return {"ok": False, "status": self.patch_status, "reason": self.patch_reason}
            return {"ok": True, "status": 200, "body": {**(body or {})}}
        if method == "POST" and url.endswith("/labels"):
            if not self.labels_ok:
                return {"ok": False, "status": self.labels_status, "reason": self.labels_reason}
            return {"ok": True, "status": 200, "body": [{"name": n} for n in (body or {}).get("labels", [])]}
        if method == "DELETE" and "/labels/" in url:
            if not self.labels_ok:
                return {"ok": False, "status": self.labels_status, "reason": self.labels_reason}
            return {"ok": True, "status": 200, "body": {}}
        raise AssertionError(f"unexpected call {method} {url}")


def _app_token(monkeypatch, *, app_slug="willows-bot"):
    monkeypatch.setattr(
        "willow_mcp.github_app_credentials.mint_installation_token",
        lambda repo: {"ok": True, "mode": "app", "token": "ghs_test_token",
                      "permissions": {"contents": "write", "pull_requests": "write"},
                      "installation_id": 1, "app_slug": app_slug},
    )


def _update(pg, api, **kw):
    args = dict(app_id="willow", repo="forge-play/Forge", number=31,
                title="fix: title", project="forge-play", ledger=_ledger(pg), api=api)
    args.update(kw)
    return prux.execute_pr_update(args.pop("app_id"), **args)


# ── granted: title / body / labels / all three ───────────────────────────────

def test_granted_title_only_cites_then_patches(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi()
    out = _update(pg, api, title="fix: retype")
    assert out["ok"] and out["updated"], out
    assert out["fields_changed"] == ["title"]
    patches = [c for c in api.calls if c["method"] == "PATCH"]
    assert len(patches) == 1 and patches[0]["body"] == {"title": "fix: retype"}
    cites = _citations(pg)
    assert len(cites) == 1 and cites[0]["content"]["outcome"] == "granted"
    assert cites[0]["content"]["call_args"] == {"repo": "forge-play/Forge", "fields": ["title"]}
    assert out["citation_id"] == cites[0]["id"]
    assert out["before"]["title"] == "old title"
    assert out["after"]["title"] == "fix: retype"


def test_granted_body_only(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi()
    out = _update(pg, api, title="", body=_GOOD_BODY)
    assert out["ok"] and out["updated"], out
    assert out["fields_changed"] == ["body"]
    patches = [c for c in api.calls if c["method"] == "PATCH"]
    assert patches[0]["body"] == {"body": _GOOD_BODY}


def test_granted_labels_only_adds_and_removes_within_bot_namespace(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg = _FakeGovernancePg()
    api = _FakeApi(existing_labels=["willow-bot/needs-review", "human-owned"])
    out = _update(pg, api, title="", labels=["willow-bot/ready"])
    assert out["ok"] and out["updated"], out
    assert out["fields_changed"] == ["labels"]
    adds = [c for c in api.calls if c["method"] == "POST" and c["url"].endswith("/labels")]
    removes = [c for c in api.calls if c["method"] == "DELETE"]
    assert adds[0]["body"] == {"labels": ["willow-bot/ready"]}
    assert len(removes) == 1 and removes[0]["url"].endswith("/labels/willow-bot%2Fneeds-review")
    # human-owned label untouched: never added, never removed.
    assert out["before"]["labels"] == ["human-owned", "willow-bot/needs-review"]
    assert out["after"]["labels"] == ["human-owned", "willow-bot/ready"]


def test_granted_all_three_fields(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg = _FakeGovernancePg()
    api = _FakeApi(existing_labels=["willow-bot/old"])
    out = _update(pg, api, title="fix: retype", body=_GOOD_BODY, labels=["willow-bot/new"])
    assert out["ok"] and out["updated"], out
    assert out["fields_changed"] == ["body", "labels", "title"]
    patches = [c for c in api.calls if c["method"] == "PATCH"]
    assert patches[0]["body"] == {"title": "fix: retype", "body": _GOOD_BODY}


def test_the_token_is_not_in_the_receipt(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    out = _update(_FakeGovernancePg(), _FakeApi())
    assert "ghs_test_token" not in json.dumps(out)


# ── refused before any network: EINVAL / ELABEL ──────────────────────────────

def test_no_fields_set_is_einval_before_the_registry(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi()
    out = _update(pg, api, title="")
    assert out["error"] == "EINVAL" and api.calls == [] and _citations(pg) == []


@pytest.mark.parametrize("bad", [
    dict(repo="Forge"), dict(number=0), dict(number=-1), dict(number="not-a-number"),
])
def test_malformed_ask_is_einval_before_the_registry(home, tmp_path, monkeypatch, bad):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi()
    out = _update(pg, api, **bad)
    assert out["error"] == "EINVAL" and api.calls == [] and _citations(pg) == []


def test_foreign_label_is_elabel_before_the_registry(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi()
    out = _update(pg, api, title="", labels=["not-owned/foo"])
    assert out["error"] == "ELABEL"
    assert out["labels"] == ["not-owned/foo"]
    assert api.calls == [] and _citations(pg) == []


# ── refused before any network: bounds mismatch ──────────────────────────────

def test_fields_outside_bounds_is_refused_cited_and_asked(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch, fields=("title",))
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi()
    out = _update(pg, api, title="", body=_GOOD_BODY)
    assert out["ok"] is False and out["updated"] is False
    assert out["error"] == "EAMBIG" and "fields" in out["fields"]
    assert api.calls == []
    assert _citations(pg)[0]["content"]["outcome"] == "EAMBIG"
    assert out["ask"]["queued"] is True
    from willow_mcp import human_loop
    from willow_mcp.db import Store
    rows = human_loop.list_queue(Store())
    assert any("forge-play/Forge#31" in (r.get("summary") or "") for r in rows)


def test_foreign_repo_is_refused(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi()
    out = _update(pg, api, repo="someone-else/Forge")
    assert not out["ok"] and out["error"] == "EAMBIG" and "repo" in out["fields"]
    assert api.calls == []


def test_no_envelope_is_enoent_and_asked(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch, grantee="hanuman")
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi()
    out = _update(pg, api)
    assert out["error"] == "ENOENT" and out["ask"]["queued"] is True
    assert api.calls == [] and _citations(pg) == []


def test_a_spent_single_use_grant_is_edquot(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch, max_count=1)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi()
    assert _update(pg, api)["ok"]
    again = _update(pg, api)
    assert not again["ok"] and again["error"] == "EDQUOT"
    assert len([c for c in api.calls if c["method"] == "PATCH"]) == 1


# ── the credential: the App or nothing ───────────────────────────────────────

def test_no_app_coverage_is_eauth_not_a_host_fallback(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "willow_mcp.github_app_credentials.mint_installation_token",
        lambda repo: {"ok": False, "mode": "host", "reason": "willows-bot is not installed on forge-play/Forge"},
    )
    pg, api = _FakeGovernancePg(), _FakeApi()
    out = _update(pg, api)
    assert not out["ok"] and out["error"] == "EAUTH"
    assert "not installed" in out["reason"]
    assert api.calls == []
    assert _citations(pg)[0]["content"]["outcome"] == "granted"


# ── the PR itself: existence, state, authorship ──────────────────────────────

def test_missing_pr_is_enoent(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi(pr_ok=False, pr_status=404, pr_reason="Not Found")
    out = _update(pg, api)
    assert not out["ok"] and out["error"] == "ENOENT"


def test_closed_pr_is_eclosed(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi(state="closed")
    out = _update(pg, api)
    assert not out["ok"] and out["error"] == "ECLOSED"


def test_human_authored_pr_is_eauthor_and_asked(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi(author_login="a-human", author_type="User")
    out = _update(pg, api)
    assert not out["ok"] and out["error"] == "EAUTHOR"
    assert out["ask"]["queued"] is True
    patches = [c for c in api.calls if c["method"] == "PATCH"]
    assert patches == []


def test_bot_type_but_wrong_login_is_eauthor(home, tmp_path, monkeypatch):
    """BOT-INVENTORY: type alone is not enough — a different bot's PR is
    still not this app's PR to touch."""
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi(author_login="dependabot[bot]", author_type="Bot")
    out = _update(pg, api)
    assert not out["ok"] and out["error"] == "EAUTHOR"


def test_missing_pull_requests_write_is_eperm_and_files_one_ask(home, tmp_path, monkeypatch):
    """Gap 4464a63db1a9 (Loki 8A23D1AE low): pr_update_execute checks the
    App's `pull_requests` permission on the minted token like pr_open does,
    refuses EPERM before any GitHub read, and files ONE human_required item."""
    from willow_mcp import human_loop
    from willow_mcp.db import Store

    _charter(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "willow_mcp.github_app_credentials.mint_installation_token",
        lambda repo: {"ok": True, "mode": "app", "token": "ghs_test_token",
                      "permissions": {"contents": "write", "pull_requests": "read"},
                      "installation_id": 1, "app_slug": "willows-bot"},
    )
    store = Store(str(tmp_path / "store"))
    pg, api = _FakeGovernancePg(), _FakeApi()
    out = _update(pg, api, store=store)
    assert not out["ok"] and out["error"] == "EPERM"
    assert "Pull requests is 'read'" in out["reason"]
    assert out["human_required_state"] == "filed" and out["human_required_id"]
    assert api.calls == []  # refused before any GitHub read
    titles = [i["title"] for i in human_loop.list_queue(store, status="open", kind="onboarding")]
    assert titles == ["GitHub App: grant pull_requests:write to willows-bot"]
    again = _update(pg, _FakeApi(), store=store)
    assert again["human_required_state"] == "already"


# ── PR template enforcement on a new body (gap 378c2e57c3d0) ─────────────────

def test_a_body_missing_a_required_section_is_ebody_before_citation(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi(template=_TEMPLATE)
    out = _update(pg, api, title="", body=_MISSING_SECTION_BODY)
    assert out["ok"] is False and out["updated"] is False
    assert out["error"] == "EBODY"
    assert out["template"]["missing"] == ["what was done"]
    patches = [c for c in api.calls if c["method"] == "PATCH"]
    assert patches == []
    granted = [c for c in _citations(pg) if c["content"]["outcome"] == "granted"]
    assert granted == []


def test_a_body_matching_the_template_is_accepted(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi(template=_TEMPLATE)
    out = _update(pg, api, title="", body=_GOOD_BODY)
    assert out["ok"] and out["updated"], out
    assert out["template"]["state"] == "complete"


def test_title_only_does_not_run_the_template_preflight(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg, api = _FakeGovernancePg(), _FakeApi(template=_TEMPLATE)
    out = _update(pg, api, title="fix: retype")
    assert out["ok"] and out["template"]["state"] == "not_enforced"
    assert not any("/contents/" in c["url"] for c in api.calls)


# ── PATCH / labels failures after citation ───────────────────────────────────

def test_github_patch_failure_is_epr_with_the_status(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg = _FakeGovernancePg()
    api = _FakeApi(patch_ok=False, patch_status=422, patch_reason="Validation failed")
    out = _update(pg, api, title="fix: retype")
    assert not out["ok"] and out["updated"] is False and out["error"] == "EPR"
    assert "422" in out["reason"]
    assert out["citation_id"]


def test_github_label_failure_is_epr(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    _app_token(monkeypatch)
    pg = _FakeGovernancePg()
    api = _FakeApi(labels_ok=False, labels_status=403, labels_reason="Forbidden")
    out = _update(pg, api, title="", labels=["willow-bot/ready"])
    assert not out["ok"] and out["error"] == "EPR"


# ── the tool is wired the way pr_open_execute is ─────────────────────────────

def test_pr_update_execute_is_gated_as_envelope_apply_by_name():
    catalogue = server._gate_tool_catalogue()
    assert catalogue["pr_update_execute"] == "envelope_apply"


def test_pr_update_is_not_advertised_in_desk_core():
    from willow_mcp import advertise
    assert "pr_update_execute" not in advertise.DESK_CORE
