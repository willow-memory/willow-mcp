"""The read-only broker verb that opens a red CI check without a shell (gap
a50c3d9c9a71). No envelope, no citation, no network — the GitHub and log
calls are fakes.
"""
from __future__ import annotations

from willow_mcp import pr_checks
from willow_mcp import server


# ── a fake GitHub JSON API ──────────────────────────────────────────────────

class _FakeApi:
    """Answers ``GET /pulls/{pr}``, ``GET /commits/{sha}/check-runs``
    (paginated), and ``GET /check-runs/{id}/annotations``. Defaults produce
    one populated, all-green check-run set."""

    def __init__(self, *, pr_ok=True, pr_status=200, pr_reason="",
                 pr_sha="head-sha", pr_ref="feat/x", pr_title="feat: x",
                 pr_state="open",
                 runs=None, runs_ok=True, runs_status=200, runs_reason="",
                 total_runs=None,
                 annotations=None, annotations_ok=True, annotations_status=200,
                 annotations_reason=""):
        self.calls: list[dict] = []
        self.pr_ok, self.pr_status, self.pr_reason = pr_ok, pr_status, pr_reason
        self.pr_sha, self.pr_ref, self.pr_title, self.pr_state = (
            pr_sha, pr_ref, pr_title, pr_state,
        )
        self.runs = runs if runs is not None else [
            {"id": 1, "name": "build", "status": "completed", "conclusion": "success",
             "html_url": "https://github.com/forge-play/Forge/actions/runs/9/job/90",
             "details_url": "https://github.com/forge-play/Forge/actions/runs/9/job/90",
             "app": {"slug": "github-actions"}, "started_at": "t0", "completed_at": "t1",
             "output": {"title": "ok", "summary": "ok", "text": ""}},
        ]
        self.total_runs = total_runs if total_runs is not None else len(self.runs)
        self.runs_ok, self.runs_status, self.runs_reason = runs_ok, runs_status, runs_reason
        self.annotations = annotations if annotations is not None else []
        self.annotations_ok = annotations_ok
        self.annotations_status = annotations_status
        self.annotations_reason = annotations_reason

    def __call__(self, method, url, *, bearer, body=None):
        self.calls.append({"method": method, "url": url, "bearer": bearer, "body": body})
        if "/pulls/" in url:
            if not self.pr_ok:
                return {"ok": False, "status": self.pr_status, "reason": self.pr_reason}
            return {"ok": True, "status": 200, "body": {
                "title": self.pr_title, "state": self.pr_state,
                "head": {"sha": self.pr_sha, "ref": self.pr_ref},
            }}
        if "/check-runs/" in url and "/annotations" in url:
            if not self.annotations_ok:
                return {"ok": False, "status": self.annotations_status, "reason": self.annotations_reason}
            return {"ok": True, "status": 200, "body": self.annotations}
        if "/check-runs" in url:
            if not self.runs_ok:
                return {"ok": False, "status": self.runs_status, "reason": self.runs_reason}
            page = int(url.rsplit("page=", 1)[-1]) if "page=" in url else 1
            per_page = 100
            start, end = (page - 1) * per_page, page * per_page
            return {"ok": True, "status": 200,
                    "body": {"total_count": self.total_runs, "check_runs": self.runs[start:end]}}
        raise AssertionError(f"unexpected URL: {url}")


def _app_token(monkeypatch, *, checks="read", actions="read"):
    perms = {"contents": "write"}
    if checks:
        perms["checks"] = checks
    if actions:
        perms["actions"] = actions
    monkeypatch.setattr(
        "willow_mcp.github_app_credentials.mint_installation_token",
        lambda repo: {"ok": True, "mode": "app", "token": "ghs_test_token",
                      "permissions": perms, "installation_id": 1},
    )


def _read(api, log_fetch=None, **kw):
    args = dict(app_id="willow", repo="forge-play/Forge", pr=31, api=api, log_fetch=log_fetch)
    args.update(kw)
    return pr_checks.read_pr_checks(args.pop("app_id"), **args)


# ── validation ───────────────────────────────────────────────────────────────

def test_neither_pr_nor_ref_is_einval(home):
    out = pr_checks.read_pr_checks("willow", repo="forge-play/Forge")
    assert out["error"] == "EINVAL"


def test_malformed_repo_is_einval(home):
    out = pr_checks.read_pr_checks("willow", repo="not-a-repo", ref="master")
    assert out["error"] == "EINVAL"


# ── head resolution ──────────────────────────────────────────────────────────

def test_pr_path_resolves_head(home, monkeypatch):
    _app_token(monkeypatch)
    api = _FakeApi()
    out = _read(api)
    assert out["state"] == "populated"
    assert out["head"] == {"pr": 31, "sha": "head-sha", "ref": "feat/x",
                            "title": "feat: x", "pr_state": "open"}
    pulls_calls = [c for c in api.calls if "/pulls/" in c["url"]]
    assert len(pulls_calls) == 1 and pulls_calls[0]["url"].endswith("/pulls/31")


def test_ref_path_uses_the_ref_directly(home, monkeypatch):
    _app_token(monkeypatch)
    api = _FakeApi()
    out = _read(api, pr=0, ref="deadbeef")
    assert out["head"] == {"sha": "deadbeef"}
    check_run_calls = [c for c in api.calls if "/check-runs" in c["url"] and "annotations" not in c["url"]]
    assert check_run_calls[0]["url"].endswith("/commits/deadbeef/check-runs?per_page=100&page=1")


# ── token / permission gates ──────────────────────────────────────────────────

def test_no_app_token_is_unreachable_token(home, monkeypatch):
    monkeypatch.setattr(
        "willow_mcp.github_app_credentials.mint_installation_token",
        lambda repo: {"ok": False, "mode": "host", "reason": "willows-bot is not installed on forge-play/Forge"},
    )
    out = _read(_FakeApi())
    assert out["state"] == "unreachable" and out["reason"] == "token"


def test_checks_permission_absent_stops_before_check_runs(home, monkeypatch):
    _app_token(monkeypatch, checks="", actions="read")
    api = _FakeApi()
    out = _read(api)
    assert out["state"] == "unreachable"
    assert out["reason"] == "permission_absent" and out["permission"] == "checks"
    # Never reached check-runs — only the pr-resolution call happened.
    assert not any("/check-runs" in c["url"] for c in api.calls)


def test_actions_permission_absent_still_returns_runs_but_marks_log_unreachable(home, monkeypatch):
    _app_token(monkeypatch, checks="read", actions="")
    red_run = {"id": 2, "name": "test", "status": "completed", "conclusion": "failure",
               "html_url": "https://github.com/forge-play/Forge/actions/runs/9/job/91",
               "details_url": "https://github.com/forge-play/Forge/actions/runs/9/job/91",
               "app": {"slug": "github-actions"}, "started_at": "t0", "completed_at": "t1",
               "output": {"title": "failed", "summary": "boom", "text": "boom"}}
    api = _FakeApi(runs=[red_run])
    out = _read(api)
    assert out["state"] == "populated"
    run = out["check_runs"][0]
    assert run["log_tail"] == {"state": "unreachable", "reason": "permission_absent",
                                "permission": "actions"}
    assert out["red"][0]["first_error_line"] == "(log unreachable: permission_absent: actions)"


# ── empty ────────────────────────────────────────────────────────────────────

def test_zero_check_runs_is_empty(home, monkeypatch):
    _app_token(monkeypatch)
    api = _FakeApi(runs=[], total_runs=0)
    out = _read(api)
    assert out["state"] == "empty"
    assert out["reason"] == "no checks reported for head-sha yet"


# ── unreachable classification ────────────────────────────────────────────────

def test_404_on_check_runs_is_not_found(home, monkeypatch):
    _app_token(monkeypatch)
    api = _FakeApi(runs_ok=False, runs_status=404, runs_reason="Not Found")
    out = _read(api)
    assert out["state"] == "unreachable" and out["reason"] == "not_found"


def test_timeout_on_check_runs_is_unreachable_timeout(home, monkeypatch):
    _app_token(monkeypatch)
    api = _FakeApi(runs_ok=False, runs_status=0, runs_reason="TimeoutError: timed out")
    out = _read(api)
    assert out["state"] == "unreachable" and out["reason"] == "timeout"


def test_pr_lookup_404_is_unreachable_not_found(home, monkeypatch):
    _app_token(monkeypatch)
    api = _FakeApi(pr_ok=False, pr_status=404, pr_reason="Not Found")
    out = _read(api)
    assert out["state"] == "unreachable" and out["reason"] == "not_found"


# ── pagination ────────────────────────────────────────────────────────────────

def test_pagination_over_100_runs(home, monkeypatch):
    _app_token(monkeypatch)
    many_runs = [
        {"id": i, "name": f"job{i}", "status": "completed", "conclusion": "success",
         "html_url": "", "details_url": "", "app": {"slug": "x"},
         "started_at": "t0", "completed_at": "t1", "output": {}}
        for i in range(150)
    ]
    api = _FakeApi(runs=many_runs, total_runs=150)
    out = _read(api)
    assert out["state"] == "populated"
    assert len(out["check_runs"]) == 150
    pages = sorted(int(c["url"].rsplit("page=", 1)[-1]) for c in api.calls if "/check-runs" in c["url"] and "annotations" not in c["url"])
    assert pages == [1, 2]


# ── a red run: tail + annotations + first_error_line ─────────────────────────

def _red_run():
    return {"id": 5, "name": "pytest", "status": "completed", "conclusion": "failure",
            "html_url": "https://github.com/forge-play/Forge/actions/runs/9/job/99",
            "details_url": "https://github.com/forge-play/Forge/actions/runs/9/job/99?check_suite_focus=true",
            "app": {"slug": "github-actions"}, "started_at": "t0", "completed_at": "t1",
            "output": {"title": "1 failed", "summary": "see log", "text": "boom"}}


def test_populated_with_one_red_tail_annotations_and_first_error_line(home, monkeypatch):
    _app_token(monkeypatch)
    annotations = [{"path": "tests/test_x.py", "message": "AssertionError: nope"}]
    api = _FakeApi(runs=[_red_run()], annotations=annotations)

    log_calls = []

    def log_fetch(url, *, bearer, timeout=10, max_bytes=2_000_000):
        log_calls.append({"url": url, "bearer": bearer})
        text = "\n".join([
            "2026-09-16T17:29:52.0000000Z ##[group]Run pytest",
            "2026-09-16T17:29:52.1000000Z collecting…",
            "2026-09-16T17:29:53.0000000Z FAILED tests/test_x.py::test_x - AssertionError: nope",
            "2026-09-16T17:29:53.1000000Z ##[endgroup]",
        ])
        return {"ok": True, "status": 200, "text": text, "redirected": True}

    out = _read(api, log_fetch=log_fetch)
    assert out["state"] == "populated"
    run = out["check_runs"][0]
    assert run["annotations"] == {"state": "populated", "annotations": annotations}
    assert run["log_tail"]["state"] == "populated"
    assert run["log_tail"]["log_lines_total"] == 2  # group markers dropped
    assert not any(line.startswith("2026-") for line in run["log_tail"]["lines"])
    assert out["red"] == [{
        "name": "pytest", "conclusion": "failure",
        "job_url": "https://github.com/forge-play/Forge/actions/runs/9/job/99",
        "first_error_line": "FAILED tests/test_x.py::test_x - AssertionError: nope",
    }]
    # The bearer rides the first (api.github.com) hop; the log fetch is a
    # separate call the fake here answers directly (redirect-following is
    # `_default_log_fetch`'s own concern, exercised below).
    assert log_calls[0]["url"].endswith("/actions/jobs/99/logs")
    assert log_calls[0]["bearer"] == "ghs_test_token"


def test_log_tail_bounded_at_200_and_truncated(home, monkeypatch):
    _app_token(monkeypatch)
    api = _FakeApi(runs=[_red_run()])
    lines = [f"line {i}: error {i}" for i in range(500)]

    def log_fetch(url, *, bearer, timeout=10, max_bytes=2_000_000):
        return {"ok": True, "status": 200, "text": "\n".join(lines)}

    out = _read(api, log_fetch=log_fetch, log_tail=500)
    run = out["check_runs"][0]
    assert run["log_tail"]["log_lines_total"] == 500
    assert len(run["log_tail"]["lines"]) == 200  # capped regardless of the ask
    assert run["log_tail"]["truncated"] is True
    assert run["log_tail"]["lines"][-1] == "line 499: error 499"


def test_log_fetch_failure_is_unreachable_but_run_still_returned(home, monkeypatch):
    _app_token(monkeypatch)
    api = _FakeApi(runs=[_red_run()])

    def log_fetch(url, *, bearer, timeout=10, max_bytes=2_000_000):
        return {"ok": False, "status": 404, "reason": "gone"}

    out = _read(api, log_fetch=log_fetch)
    run = out["check_runs"][0]
    assert run["log_tail"] == {"state": "unreachable", "reason": "not_found", "detail": "gone"}
    assert out["red"][0]["first_error_line"] == "(log unreachable: not_found)"


# ── the redirect-following default log fetch, no network ─────────────────────

def test_default_log_fetch_follows_one_redirect_without_the_bearer(monkeypatch):
    import urllib.request

    calls = []

    class _FakeResponse:
        status = 200

        def __init__(self, data: bytes):
            self._data = data

        def read(self, n=-1):
            return self._data[:n] if n and n > 0 else self._data

        def close(self):
            pass

    class _FakeOpener:
        def open(self, req, timeout=None):
            calls.append({"url": req.full_url, "auth": req.headers.get("Authorization")})
            if req.full_url == "https://api.github.com/repos/x/y/actions/jobs/1/logs":
                import urllib.error
                exc = urllib.error.HTTPError(
                    req.full_url, 302, "Found",
                    {"Location": "https://blob.example/signed"}, None,
                )
                raise exc
            return _FakeResponse(b"the log text")

    monkeypatch.setattr(urllib.request, "build_opener", lambda *a, **k: _FakeOpener())

    out = pr_checks._default_log_fetch(
        "https://api.github.com/repos/x/y/actions/jobs/1/logs", bearer="ghs_secret",
    )
    assert out == {"ok": True, "status": 200, "text": "the log text",
                    "redirected": True, "truncated": False}
    assert calls[0]["auth"] == "Bearer ghs_secret"
    assert calls[1]["url"] == "https://blob.example/signed"
    assert calls[1]["auth"] is None, "the bearer must not follow to the second host"


# ── gate visibility ────────────────────────────────────────────────────────────

def test_pr_checks_read_is_gated_by_its_own_name():
    catalogue = server._gate_tool_catalogue()
    assert catalogue["pr_checks_read"] == "pr_checks_read"


def test_pr_checks_read_is_in_fleet_read_and_full_access():
    from willow_mcp import gate

    assert "pr_checks_read" in gate.PERMISSION_GROUPS["fleet_read"]
    assert "pr_checks_read" in gate.PERMISSION_GROUPS["full_access"]


def test_pr_checks_read_is_classed_read_by_the_tier_ceiling():
    from willow_mcp import tier_policy

    assert tier_policy.TOOL_CLASS["pr_checks_read"] == tier_policy.READ


def test_pr_checks_read_is_not_in_desk_core():
    from willow_mcp import advertise

    assert "pr_checks_read" not in advertise.DESK_CORE
