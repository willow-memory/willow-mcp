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
        "failure": {
            "kind": "generic",
            "text": "collecting…\nFAILED tests/test_x.py::test_x - AssertionError: nope",
            "tests_failed": [],
            "count_line": "",
            "trimmed": False,
        },
        "truncated": False,
        "bytes_dropped": 0,
        "range_fallback": False,
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
    assert out["red"][0]["failure"] is None


def test_truncated_log_fetch_surfaces_truncated_and_bytes_dropped_on_the_job_entry(home, monkeypatch):
    _app_token(monkeypatch)
    api = _FakeApi(runs=[_red_run()])

    def log_fetch(url, *, bearer, timeout=10, max_bytes=5_000_000):
        return {"ok": True, "status": 200, "text": "some log text",
                "truncated": True, "bytes_dropped": 1234}

    out = _read(api, log_fetch=log_fetch)
    assert out["red"][0]["truncated"] is True
    assert out["red"][0]["bytes_dropped"] == 1234


def test_untruncated_log_fetch_reports_no_truncation_on_the_job_entry(home, monkeypatch):
    _app_token(monkeypatch)
    api = _FakeApi(runs=[_red_run()])

    def log_fetch(url, *, bearer, timeout=10, max_bytes=5_000_000):
        return {"ok": True, "status": 200, "text": "some log text",
                "truncated": False, "bytes_dropped": 0}

    out = _read(api, log_fetch=log_fetch)
    assert out["red"][0]["truncated"] is False
    assert out["red"][0]["bytes_dropped"] == 0


# ── failure-block extraction: the full log, not the tail window ──────────────
# Fixture shaped like tonight's #594 job 106227660755: ~880 lines, the pytest
# FAILURES/summary section around lines 650-700, Postgres service teardown
# noise after it — the exact shape that pushed the pytest summary out of the
# old 200-line tail window (gap d5345e7e737f).

def _ci_log_fixture_pytest():
    setup = [f"setting up step {i}" for i in range(1, 649)]           # ~648 lines
    failures = [
        "=================================== FAILURES ===================================",
        "_______________________________ test_alpha ___________________________________",
        "    def test_alpha():",
        ">       assert False",
        "E       AssertionError",
        "",
        "tests/test_a.py:10: AssertionError",
        "_______________________________ test_beta ____________________________________",
        "    def test_beta():",
        ">       raise KeyError('x')",
        "E       KeyError: 'x'",
        "",
        "tests/test_b.py:20: KeyError",
        "_______________________________ test_gamma ___________________________________",
        "    def test_gamma():",
        ">       raise ValueError('nope')",
        "E       ValueError: nope",
        "",
        "tests/test_c.py:30: ValueError",
        "=========================== short test summary info ============================",
        "FAILED tests/test_a.py::test_alpha - AssertionError",
        "FAILED tests/test_b.py::test_beta - KeyError: 'x'",
        "FAILED tests/test_c.py::test_gamma - ValueError: nope",
        "======================= 3 failed, 4351 passed, 26 skipped in 122.30s =======================",
    ]                                                                   # 24 lines: ~649-672
    teardown = []
    for i in range(1, 151):                                            # ~150 lines after
        if i % 3 == 0:
            teardown.append("2026-09-20 23:00:00.000 UTC [1] LOG:  received fast shutdown request")
        else:
            teardown.append(
                "2026-09-20 23:00:00.000 UTC [1] FATAL:  terminating connection due to "
                "administrator command"
            )
    lines = setup + failures + teardown
    # GitHub's per-line ISO timestamp prefix, on every line, per gap d5345e7e737f.
    return "\n".join(
        f"2026-09-21T00:{(i % 60):02d}:00.0000000Z {line}" for i, line in enumerate(lines)
    )


def test_pytest_failure_block_survives_postgres_teardown_after_it(home, monkeypatch):
    _app_token(monkeypatch)
    api = _FakeApi(runs=[_red_run()])
    text = _ci_log_fixture_pytest()

    def log_fetch(url, *, bearer, timeout=10, max_bytes=5_000_000):
        return {"ok": True, "status": 200, "text": text}

    out = _read(api, log_fetch=log_fetch)
    failure = out["red"][0]["failure"]
    assert failure["kind"] == "pytest"
    assert failure["tests_failed"] == [
        "tests/test_a.py::test_alpha",
        "tests/test_b.py::test_beta",
        "tests/test_c.py::test_gamma",
    ]
    assert failure["count_line"] == (
        "======================= 3 failed, 4351 passed, 26 skipped in 122.30s ======================="
    )
    # The Postgres teardown lines that follow the count line never make it in.
    assert "FATAL" not in failure["text"]
    assert "LOG:" not in failure["text"]
    # Timestamps are stripped from every retained line.
    assert "2026-09-21T00:" not in failure["text"]
    assert out["red"][0]["first_error_line"] == "FAILED tests/test_a.py::test_alpha - AssertionError"


def test_ruff_failure_block(home, monkeypatch):
    _app_token(monkeypatch)
    api = _FakeApi(runs=[_red_run()])
    text = "\n".join([
        "Run ruff check src tests hooks",
        "src/willow_mcp/foo.py:12:5: E501 line too long (100 > 88 characters)",
        "src/willow_mcp/bar.py:30:1: F401 'os' imported but unused",
        "Found 2 errors.",
    ])

    def log_fetch(url, *, bearer, timeout=10, max_bytes=5_000_000):
        return {"ok": True, "status": 200, "text": text}

    out = _read(api, log_fetch=log_fetch)
    failure = out["red"][0]["failure"]
    assert failure["kind"] == "ruff"
    assert failure["count_line"] == "Found 2 errors."
    assert "src/willow_mcp/foo.py:12:5: E501" in failure["text"]
    assert "src/willow_mcp/bar.py:30:1: F401" in failure["text"]


def test_generic_fallback_when_no_pytest_section_drops_postgres_noise(home, monkeypatch):
    _app_token(monkeypatch)
    api = _FakeApi(runs=[_red_run()])
    context = [f"context line {i}" for i in range(60)]
    pg = [
        "2026-09-20 23:00:00.000 UTC [1] LOG:  received fast shutdown request",
        "2026-09-20 23:00:01.000 UTC [1] FATAL:  terminating connection due to administrator command",
    ]
    tail = ["##[error]Process completed with exit code 1."]
    text = "\n".join(context + pg + tail)

    def log_fetch(url, *, bearer, timeout=10, max_bytes=5_000_000):
        return {"ok": True, "status": 200, "text": text}

    out = _read(api, log_fetch=log_fetch)
    failure = out["red"][0]["failure"]
    assert failure["kind"] == "generic"
    assert "##[error]Process completed with exit code 1." in failure["text"]
    assert "FATAL" not in failure["text"]
    assert "LOG:" not in failure["text"]
    assert "context line 20" in failure["text"]   # 40 lines of context, kept
    assert "context line 19" not in failure["text"]  # older than the 40-line window


def test_tb_no_short_summary_only_is_still_classified_pytest(home, monkeypatch):
    """`-q --tb=no`: no FAILURES section, no `___ title ___` header — only
    the short-test-summary-info block and the final count line. Must still
    be classified pytest, with tests_failed populated from the summary."""
    _app_token(monkeypatch)
    api = _FakeApi(runs=[_red_run()])
    text = "\n".join([
        "collecting…",
        "..F..F.",
        "=========================== short test summary info ============================",
        "FAILED tests/test_a.py::test_alpha - AssertionError",
        "FAILED tests/test_b.py::test_beta - KeyError: 'x'",
        "======================= 2 failed, 10 passed in 1.23s =======================",
    ])

    def log_fetch(url, *, bearer, timeout=10, max_bytes=5_000_000):
        return {"ok": True, "status": 200, "text": text}

    out = _read(api, log_fetch=log_fetch)
    failure = out["red"][0]["failure"]
    assert failure["kind"] == "pytest"
    assert failure["tests_failed"] == [
        "tests/test_a.py::test_alpha", "tests/test_b.py::test_beta",
    ]
    assert failure["count_line"] == "======================= 2 failed, 10 passed in 1.23s ======================="


def test_timed_out_job_no_count_line_ends_at_job_step_marker_and_caps_length(home, monkeypatch):
    """A timed-out job: FAILURES section present, no closing count line. The
    block must end at the next job-step marker (not run to EOF), be capped
    at 300 lines with trimmed=True, and drop Postgres teardown noise since
    no count line closed it."""
    _app_token(monkeypatch)
    api = _FakeApi(runs=[_red_run()])
    failures = [
        "=================================== FAILURES ===================================",
        "_______________________________ test_alpha ___________________________________",
        "    def test_alpha():",
        ">       assert False",
        "E       AssertionError",
    ]
    postgres_noise = [f"2026-09-20 23:00:{i:02d}.000 UTC [1] FATAL:  terminating" for i in range(50)]
    marker = ["2026-09-20T23:01:00.0000000Z ##[group]Post job cleanup"]
    after_marker = ["this must never appear in the failure text"]
    text = "\n".join(failures + postgres_noise + marker + after_marker)

    def log_fetch(url, *, bearer, timeout=10, max_bytes=5_000_000):
        return {"ok": True, "status": 200, "text": text}

    out = _read(api, log_fetch=log_fetch)
    failure = out["red"][0]["failure"]
    assert failure["kind"] == "pytest"
    assert failure["count_line"] == ""
    assert "FATAL" not in failure["text"], "Postgres noise dropped when no count line closes the block"
    assert "this must never appear" not in failure["text"], "block must end at the job-step marker"


def test_group_marker_immediately_before_a_pytest_fold_does_not_end_the_unclosed_block(home, monkeypatch):
    """Some CI wrappers print `##[group]` immediately before a pytest
    banner/header to fold it in the Actions UI — that must NOT be treated
    as a job-step boundary; only a `##[group]` before something else does."""
    _app_token(monkeypatch)
    api = _FakeApi(runs=[_red_run()])
    text = "\n".join([
        "=================================== FAILURES ===================================",
        "_______________________________ test_alpha ___________________________________",
        "    raise AssertionError",
        "##[group]test_gamma fold",
        "_______________________________ test_gamma ___________________________________",
        "    raise KeyError",
        "##[group]Post job cleanup",
        "this must never appear in the failure text",
    ])

    def log_fetch(url, *, bearer, timeout=10, max_bytes=5_000_000):
        return {"ok": True, "status": 200, "text": text}

    out = _read(api, log_fetch=log_fetch)
    failure = out["red"][0]["failure"]
    assert failure["kind"] == "pytest"
    assert "test_alpha" in failure["text"]
    assert "test_gamma" in failure["text"]
    assert "this must never appear" not in failure["text"]


def test_timed_out_job_59kb_case_caps_failure_text_at_300_lines(home, monkeypatch):
    """No count line, no job-step marker, no summary header — a big FAILURES
    section (Loki's 59 KB probe) must be capped at 300 lines with
    trimmed=True, ending 200 lines past the last FAILED line."""
    _app_token(monkeypatch)
    api = _FakeApi(runs=[_red_run()])
    header = ["=================================== FAILURES ==================================="]
    body = []
    for i in range(400):
        body.append(f"_______________________________ test_{i} ___________________________________")
        body.append(f"    raise AssertionError('boom {i}')")
    body.append("FAILED tests/test_big.py::test_last - AssertionError")
    trailer = [f"trailer line {i}" for i in range(400)]  # more than 200 lines past the last FAILED
    text = "\n".join(header + body + trailer)

    def log_fetch(url, *, bearer, timeout=10, max_bytes=5_000_000):
        return {"ok": True, "status": 200, "text": text}

    out = _read(api, log_fetch=log_fetch)
    failure = out["red"][0]["failure"]
    assert failure["kind"] == "pytest"
    assert failure["trimmed"] is True
    assert len(failure["text"].splitlines()) == 300


def test_closed_block_over_300_lines_keeps_head_and_tail_not_just_head(home, monkeypatch):
    """Gap d5345e7e737f's regression: a CLOSED block (one that ends in a real
    count line) must never be head-trimmed — that drops the summary header,
    the FAILED lines, and the count line themselves. It keeps the first 100
    lines (the opening tracebacks) and the last 200 (summary + FAILED +
    count line), with an omission marker between."""
    _app_token(monkeypatch)
    api = _FakeApi(runs=[_red_run()])
    header = [
        "=================================== FAILURES ===================================",
        "_______________________________ test_long ___________________________________",
    ]
    traceback_lines = [f"    frame {i}" for i in range(298)]
    tail = [
        "=========================== short test summary info ============================",
        "FAILED tests/test_long.py::test_long - AssertionError: the actual assertion",
        "======================= 1 failed in 1.00s =======================",
    ]
    postgres = [f"2026-09-20 23:00:00.000 UTC [1] FATAL:  terminating {i}" for i in range(250)]
    block_lines = header + traceback_lines + tail
    assert len(block_lines) == 303, "matches the everyday shape a full audit measured"
    text = "\n".join(block_lines + postgres)

    def log_fetch(url, *, bearer, timeout=10, max_bytes=5_000_000):
        return {"ok": True, "status": 200, "text": text}

    out = _read(api, log_fetch=log_fetch)
    failure = out["red"][0]["failure"]
    assert failure["kind"] == "pytest"
    assert failure["trimmed"] == {"omitted": 3, "kept": "head+tail"}
    assert failure["tests_failed"] == ["tests/test_long.py::test_long"]
    assert failure["count_line"] == "======================= 1 failed in 1.00s ======================="
    assert "short test summary info" in failure["text"]
    assert "FAILED tests/test_long.py::test_long - AssertionError" in failure["text"]
    assert failure["text"].splitlines()[-1] == failure["count_line"]
    assert "… 3 lines omitted …" in failure["text"]
    assert "FATAL" not in failure["text"]
    # first_error_line must come from the summary section, never the tail
    # heuristic (which, pre-fix, fell back to the last Postgres line).
    assert out["red"][0]["first_error_line"] == (
        "FAILED tests/test_long.py::test_long - AssertionError: the actual assertion"
    )


def test_captured_count_shaped_line_does_not_end_the_block_early(home, monkeypatch):
    """A test that runs pytest as a subprocess and captures its stdout will
    have a count-shaped line (`==== 5 passed ====`) sitting INSIDE its own
    'Captured stdout call' section — that must never be mistaken for the
    outer run's own closing count line, which would drop the whole
    FAILURES traceback."""
    _app_token(monkeypatch)
    api = _FakeApi(runs=[_red_run()])
    text = "\n".join([
        "=================================== FAILURES ===================================",
        "_______________________________ test_alpha ___________________________________",
        "    subprocess.run(['pytest', 'inner'])",
        "----------------------------- Captured stdout call -----------------------------",
        "collecting…",
        "==== 5 passed in 0.10s ====",
        "----------------------------- Captured stderr call -----------------------------",
        "=========================== short test summary info ============================",
        "FAILED tests/test_outer.py::test_alpha - AssertionError",
        "======================= 1 failed in 1.00s =======================",
    ])

    def log_fetch(url, *, bearer, timeout=10, max_bytes=5_000_000):
        return {"ok": True, "status": 200, "text": text}

    out = _read(api, log_fetch=log_fetch)
    failure = out["red"][0]["failure"]
    assert failure["kind"] == "pytest"
    assert "test_alpha" in failure["text"] and "FAILURES" in failure["text"]
    assert failure["tests_failed"] == ["tests/test_outer.py::test_alpha"]
    assert failure["count_line"] == "======================= 1 failed in 1.00s ======================="


def test_failed_regex_captures_parametrize_id_with_spaces(home, monkeypatch):
    _app_token(monkeypatch)
    api = _FakeApi(runs=[_red_run()])
    text = "\n".join([
        "=================================== FAILURES ===================================",
        "_____________________ test_a[a b] _____________________",
        "    raise AssertionError",
        "=========================== short test summary info ============================",
        "FAILED tests/t.py::test_a[a b] - AssertionError: nope",
        "======================= 1 failed in 1.00s =======================",
    ])

    def log_fetch(url, *, bearer, timeout=10, max_bytes=5_000_000):
        return {"ok": True, "status": 200, "text": text}

    out = _read(api, log_fetch=log_fetch)
    failure = out["red"][0]["failure"]
    assert failure["tests_failed"] == ["tests/t.py::test_a[a b]"]


def test_failed_regex_is_bracket_aware_when_the_id_itself_holds_a_dash(home, monkeypatch):
    """`test_b[a - b]` puts pytest's own `` - `` separator INSIDE the
    parametrize id's brackets — bracket-matching must find the id's real
    closing `]` before looking for the `` - `` that starts the message."""
    _app_token(monkeypatch)
    api = _FakeApi(runs=[_red_run()])
    text = "\n".join([
        "=================================== FAILURES ===================================",
        "_____________________ test_b[a - b] _____________________",
        "    raise AssertionError",
        "=========================== short test summary info ============================",
        "FAILED tests/t.py::test_b[a - b] - AssertionError: nope",
        "======================= 1 failed in 1.00s =======================",
    ])

    def log_fetch(url, *, bearer, timeout=10, max_bytes=5_000_000):
        return {"ok": True, "status": 200, "text": text}

    out = _read(api, log_fetch=log_fetch)
    failure = out["red"][0]["failure"]
    assert failure["tests_failed"] == ["tests/t.py::test_b[a - b]"]


def test_captured_log_lines_starting_with_failed_or_error_never_enter_tests_failed(home, monkeypatch):
    """A logging line that happens to start with the word ERROR/FAILED (app
    output captured by pytest, not a pytest summary line) must not be
    mistaken for one — it doesn't have the `path::name` shape."""
    _app_token(monkeypatch)
    api = _FakeApi(runs=[_red_run()])
    text = "\n".join([
        "=================================== FAILURES ===================================",
        "_______________________________ test_alpha ___________________________________",
        "----------------------------- Captured log call ------------------------------",
        "ERROR    willow_mcp.foo:foo.py:12 something broke",
        "FAILED to connect (app log)",
        "    raise AssertionError",
        "=========================== short test summary info ============================",
        "FAILED tests/test_a.py::test_alpha - AssertionError",
        "======================= 1 failed in 1.00s =======================",
    ])

    def log_fetch(url, *, bearer, timeout=10, max_bytes=5_000_000):
        return {"ok": True, "status": 200, "text": text}

    out = _read(api, log_fetch=log_fetch)
    failure = out["red"][0]["failure"]
    assert failure["tests_failed"] == ["tests/test_a.py::test_alpha"]


def test_bare_underscore_banner_in_a_make_log_is_not_classified_pytest(home, monkeypatch):
    """A `______` banner with no title text (e.g. from a `make` failure) must
    not trip the pytest test-header anchor — the FAILURES banner requires a
    non-underscore title and the word FAILURES on the `===` line."""
    _app_token(monkeypatch)
    api = _FakeApi(runs=[_red_run()])
    text = "\n".join([
        "make: *** [target] Error 1",
        "______________________________________________________",
        "##[error]Process completed with exit code 2.",
    ])

    def log_fetch(url, *, bearer, timeout=10, max_bytes=5_000_000):
        return {"ok": True, "status": 200, "text": text}

    out = _read(api, log_fetch=log_fetch)
    failure = out["red"][0]["failure"]
    assert failure["kind"] != "pytest"


def test_errors_section_before_failures_is_kept_and_error_lines_land_in_tests_failed(home, monkeypatch):
    _app_token(monkeypatch)
    api = _FakeApi(runs=[_red_run()])
    text = "\n".join([
        "=================================== ERRORS ===================================",
        "____________________ ERROR at setup of test_fixture __________________________",
        "    raise RuntimeError('fixture boom')",
        "=================================== FAILURES ===================================",
        "_______________________________ test_alpha ___________________________________",
        "    raise AssertionError",
        "=========================== short test summary info ============================",
        "ERROR tests/test_x.py::test_fixture - RuntimeError: fixture boom",
        "FAILED tests/test_a.py::test_alpha - AssertionError",
        "======================= 1 failed, 1 error in 1.00s =======================",
    ])

    def log_fetch(url, *, bearer, timeout=10, max_bytes=5_000_000):
        return {"ok": True, "status": 200, "text": text}

    out = _read(api, log_fetch=log_fetch)
    failure = out["red"][0]["failure"]
    assert failure["kind"] == "pytest"
    assert "ERROR at setup of test_fixture" in failure["text"], "the ERRORS section is not dropped"
    assert failure["tests_failed"] == [
        "tests/test_x.py::test_fixture", "tests/test_a.py::test_alpha",
    ]


def test_two_pytest_invocations_takes_the_last_complete_block(home, monkeypatch):
    """A retried job runs pytest twice; only the LAST complete invocation —
    the one CI actually judged — should be extracted."""
    _app_token(monkeypatch)
    api = _FakeApi(runs=[_red_run()])
    first_run = [
        "=================================== FAILURES ===================================",
        "_______________________________ test_flaky ___________________________________",
        "    raise AssertionError",
        "=========================== short test summary info ============================",
        "FAILED tests/test_x.py::test_flaky - AssertionError",
        "======================= 1 failed, 10 passed in 1.00s =======================",
    ]
    second_run = [
        "Retrying pytest run…",
        "=================================== FAILURES ===================================",
        "_______________________________ test_real ___________________________________",
        "    raise KeyError('x')",
        "=========================== short test summary info ============================",
        "FAILED tests/test_y.py::test_real - KeyError: 'x'",
        "======================= 1 failed, 10 passed in 1.00s =======================",
    ]
    text = "\n".join(first_run + second_run)

    def log_fetch(url, *, bearer, timeout=10, max_bytes=5_000_000):
        return {"ok": True, "status": 200, "text": text}

    out = _read(api, log_fetch=log_fetch)
    failure = out["red"][0]["failure"]
    assert failure["tests_failed"] == ["tests/test_y.py::test_real"]
    assert "test_flaky" not in failure["text"]


class _StreamingFakeResponse:
    """A minimal file-like stream that actually consumes bytes on ``read``,
    like a real ``http.client.HTTPResponse`` — a fake that always returns
    the full buffer regardless of ``n`` would spin ``_default_log_fetch``'s
    chunked read loop forever."""
    status = 200

    def __init__(self, data: bytes):
        self._data = data

    def read(self, n=-1):
        if n is None or n < 0:
            data, self._data = self._data, b""
            return data
        data, self._data = self._data[:n], self._data[n:]
        return data

    def close(self):
        pass


def test_default_log_fetch_caps_download_at_5mb(monkeypatch):
    import urllib.request

    huge = b"x" * (6 * 1024 * 1024)

    class _FakeOpener:
        def open(self, req, timeout=None):
            return _StreamingFakeResponse(huge)

    monkeypatch.setattr(urllib.request, "build_opener", lambda *a, **k: _FakeOpener())

    out = pr_checks._default_log_fetch(
        "https://api.github.com/repos/x/y/actions/jobs/1/logs", bearer="ghs_secret",
    )
    assert out["truncated"] is True
    assert len(out["text"].encode("utf-8")) == 5 * 1024 * 1024
    assert out["bytes_dropped"] == 1 * 1024 * 1024


def test_default_log_fetch_keeps_the_tail_not_the_head(monkeypatch):
    """A 6 MB log with the pytest failure block in the last 100 KB must
    still have that block survive the 5 MB cap — the cap must keep the
    TAIL of the stream, not the head."""
    import urllib.request

    head_sentinel = "HEAD_ONLY_SENTINEL_1234567890"
    marker = "FAILED tests/test_tail.py::test_marker - AssertionError: tail lives here"
    tail_block = "\n".join([
        "=================================== FAILURES ===================================",
        "_______________________________ test_marker __________________________________",
        "    raise AssertionError('tail lives here')",
        "=========================== short test summary info ============================",
        marker,
        "======================= 1 failed in 1.00s =======================",
    ])
    # 6 MB total: a sentinel tag sits at the very START of the log, far
    # outside the last 5 MB, so it — and only it — must be dropped, while
    # the pytest block living in the last 100 KB survives.
    filler_len = 6 * 1024 * 1024 - 100 * 1024 - len(head_sentinel)
    head_junk = head_sentinel + ("x" * filler_len)
    tail_padding = "y" * (100 * 1024 - len(tail_block.encode("utf-8")) - 1)
    huge = (head_junk + "\n" + tail_padding + "\n" + tail_block).encode("utf-8")

    class _FakeOpener:
        def open(self, req, timeout=None):
            return _StreamingFakeResponse(huge)

    monkeypatch.setattr(urllib.request, "build_opener", lambda *a, **k: _FakeOpener())

    out = pr_checks._default_log_fetch(
        "https://api.github.com/repos/x/y/actions/jobs/1/logs", bearer="ghs_secret",
    )
    assert out["truncated"] is True
    assert marker in out["text"]
    assert head_sentinel not in out["text"], "the head must have been dropped, not the tail"
    assert out["bytes_dropped"] == len(huge) - 5 * 1024 * 1024

    failure = pr_checks._extract_failure_block(out["text"])
    assert failure["kind"] == "pytest"
    assert failure["tests_failed"] == ["tests/test_tail.py::test_marker"]


class _StreamingFakeResponse206:
    """A minimal file-like stream standing in for a 206 Partial Content
    response to a `Range: bytes=-N` request — the body IS the tail already,
    a `Content-Range: bytes START-END/TOTAL` header names the full size."""
    status = 206

    def __init__(self, data: bytes, total_size: int):
        self._data = data
        start = max(0, total_size - len(data))
        self.headers = {"Content-Range": f"bytes {start}-{total_size - 1}/{total_size}"}

    def read(self, n=-1):
        if n is None or n < 0:
            data, self._data = self._data, b""
            return data
        data, self._data = self._data[:n], self._data[n:]
        return data

    def close(self):
        pass


def test_default_log_fetch_sends_range_only_on_the_blob_hop_and_uses_206_body_as_tail(monkeypatch):
    import urllib.error
    import urllib.request

    calls = []

    class _FakeOpener:
        def open(self, req, timeout=None):
            calls.append({"url": req.full_url, "range": req.headers.get("Range")})
            if req.full_url == "https://api.github.com/repos/x/y/actions/jobs/1/logs":
                raise urllib.error.HTTPError(
                    req.full_url, 302, "Found", {"Location": "https://blob.example/signed"}, None,
                )
            return _StreamingFakeResponse206(b"the tail of the log", total_size=50_000_000)

    monkeypatch.setattr(urllib.request, "build_opener", lambda *a, **k: _FakeOpener())

    out = pr_checks._default_log_fetch(
        "https://api.github.com/repos/x/y/actions/jobs/1/logs", bearer="ghs_secret",
    )
    assert calls[0]["range"] is None, "the first (api.github.com) hop never gets a Range header"
    assert calls[1]["range"] == f"bytes=-{pr_checks._LOG_FETCH_MAX_BYTES}"
    assert out["ok"] is True
    assert out["status"] == 206
    assert out["text"] == "the tail of the log"
    assert out["truncated"] is True
    assert out["bytes_dropped"] == 50_000_000 - len("the tail of the log")


def test_default_log_fetch_falls_back_to_ring_buffer_when_blob_ignores_range(monkeypatch):
    """A blob host that doesn't honour Range answers 200 with the whole
    body; the ring buffer must still keep only the tail, same as before
    Range existed — Range is an ask, the ring buffer is the guarantee."""
    import urllib.error
    import urllib.request

    calls = []
    huge = ("x" * 2000 + "\nFAILED tests/t.py::test_x - AssertionError\n").encode()

    class _FakeOpener:
        def open(self, req, timeout=None):
            calls.append({"url": req.full_url, "range": req.headers.get("Range")})
            if req.full_url == "https://api.github.com/repos/x/y/actions/jobs/1/logs":
                raise urllib.error.HTTPError(
                    req.full_url, 302, "Found", {"Location": "https://blob.example/signed"}, None,
                )
            return _StreamingFakeResponse(huge)

    monkeypatch.setattr(urllib.request, "build_opener", lambda *a, **k: _FakeOpener())

    out = pr_checks._default_log_fetch(
        "https://api.github.com/repos/x/y/actions/jobs/1/logs", bearer="ghs_secret", max_bytes=1000,
    )
    assert calls[1]["range"] == "bytes=-1000", "Range is still offered even though this server ignores it"
    assert out["ok"] is True
    assert out["status"] == 200
    assert len(out["text"].encode("utf-8")) == 1000
    assert "FAILED tests/t.py::test_x" in out["text"]


def test_missing_actions_permission_refusal_names_actions_read(home, monkeypatch):
    _app_token(monkeypatch, checks="read", actions="")
    calls = []

    def fake_file_ask(store, *, app_id, verb, repo, permission, level="read", current=None):
        calls.append({"permission": permission, "level": level})
        return {"state": "filed", "human_required_id": "abc"}

    monkeypatch.setattr(
        "willow_mcp.github_app_permissions.file_permission_ask", fake_file_ask,
    )
    api = _FakeApi(runs=[_red_run()])
    _read(api)
    assert calls, "a missing actions permission must file exactly one ask"
    assert f"{calls[0]['permission']}:{calls[0]['level']}" == "actions:read"


# ── the redirect-following default log fetch, no network ─────────────────────

def test_default_log_fetch_follows_one_redirect_without_the_bearer(monkeypatch):
    import urllib.request

    calls = []

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
            return _StreamingFakeResponse(b"the log text")

    monkeypatch.setattr(urllib.request, "build_opener", lambda *a, **k: _FakeOpener())

    out = pr_checks._default_log_fetch(
        "https://api.github.com/repos/x/y/actions/jobs/1/logs", bearer="ghs_secret",
    )
    assert out == {"ok": True, "status": 200, "text": "the log text",
                    "redirected": True, "truncated": False, "bytes_dropped": 0,
                    "range_fallback": False}
    assert calls[0]["auth"] == "Bearer ghs_secret"
    assert calls[1]["url"] == "https://blob.example/signed"
    assert calls[1]["auth"] is None, "the bearer must not follow to the second host"


def test_default_log_fetch_real_opener_chain_strips_bearer_cross_host(monkeypatch):
    """Drives the REAL urllib chain — the code's own ``build_opener`` and its
    ``_NoAutoRedirect`` handler, PLUS urllib's real ``HTTPErrorProcessor`` /
    ``HTTPRedirectHandler`` / ``HTTPDefaultErrorHandler`` machinery that turns
    a 302 response into the ``HTTPError`` our code catches. Only the
    socket-level transport (``http.client.HTTPSConnection``) is faked —
    genuine ``http.client.HTTPResponse`` objects are built from raw HTTP
    bytes over a fake socket — so the real redirect-refusal /
    re-request-without-bearer logic executes exactly as it would against
    GitHub (Loki's probe shape), unlike a test that fakes ``build_opener``
    (or raises ``HTTPError`` by hand) and never runs that machinery at all.
    """
    import http.client
    import io

    calls = []

    _RESPONSES = {
        "api.github.com": (
            b"HTTP/1.1 302 Found\r\n"
            b"Location: https://productionresultssa1.blob.core.windows.net/signed\r\n"
            b"Content-Length: 0\r\n\r\n"
        ),
        "productionresultssa1.blob.core.windows.net": (
            b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nthe log text"
        ),
    }

    class _FakeSocket:
        def __init__(self, data: bytes):
            self._data = data

        def makefile(self, mode, *a, **k):
            return io.BytesIO(self._data)

    class _FakeHTTPSConnection(http.client.HTTPConnection):
        """Subclassing the plain (non-TLS) HTTPConnection gets us the class
        attributes ``HTTPSHandler.__init__``/``do_open`` reach for
        (``_http_vsn``, ``debuglevel``, ``default_port``, …) for free; only
        the actual I/O methods are overridden so no socket is ever opened."""

        def __init__(self, host, timeout=None, **kwargs):
            self.host = host
            self.sock = None

        def set_debuglevel(self, level):
            pass

        def request(self, method, url, body=None, headers=None, **kw):
            calls.append({
                "url": f"https://{self.host}{url}",
                "auth": (headers or {}).get("Authorization"),
            })

        def getresponse(self):
            resp = http.client.HTTPResponse(_FakeSocket(_RESPONSES[self.host]))
            resp.begin()
            return resp

        def close(self):
            pass

    monkeypatch.setattr(http.client, "HTTPSConnection", _FakeHTTPSConnection)

    out = pr_checks._default_log_fetch(
        "https://api.github.com/repos/x/y/actions/jobs/1/logs", bearer="ghs_SECRET",
    )
    assert out["ok"] is True, out
    assert out["text"] == "the log text"
    assert len(calls) == 2
    assert calls[0]["url"] == "https://api.github.com/repos/x/y/actions/jobs/1/logs"
    assert calls[0]["auth"] == "Bearer ghs_SECRET"
    assert calls[1]["url"] == "https://productionresultssa1.blob.core.windows.net/signed"
    assert calls[1]["auth"] is None, "the bearer must not follow to the cross-host hop"


def test_default_log_fetch_range_4xx_falls_back_to_no_range_retry(monkeypatch):
    """Third audit's condition (Loki, 2026-09-21): a suffix Range
    (``bytes=-N``) is attempted on the blob hop, but is not among Azure
    Blob's documented Range formats, so the live host may refuse it. Drives
    the REAL urllib chain: hop 1 (api.github.com) 302s, hop 2 (the blob
    host) answers 416 to the ranged request, and the code refetches that
    SAME hop once with no Range header at all — the second attempt answers
    200 and extraction proceeds against that body. ``range_fallback: True``
    records that the retry happened."""
    import http.client
    import io

    calls = []
    blob_hits = {"n": 0}

    _FAILURES_TEXT = (
        b"=== FAILURES ===\n"
        b"FAILED tests/t.py::test_x - AssertionError\n"
        b"===== short test summary info =====\n"
        b"FAILED tests/t.py::test_x - AssertionError\n"
        b"===== 1 failed in 0.01s =====\n"
    )

    class _FakeSocket:
        def __init__(self, data: bytes):
            self._data = data

        def makefile(self, mode, *a, **k):
            return io.BytesIO(self._data)

    class _FakeHTTPSConnection(http.client.HTTPConnection):
        def __init__(self, host, timeout=None, **kwargs):
            self.host = host
            self.sock = None

        def set_debuglevel(self, level):
            pass

        def request(self, method, url, body=None, headers=None, **kw):
            calls.append({
                "url": f"https://{self.host}{url}",
                "range": (headers or {}).get("Range"),
                "auth": (headers or {}).get("Authorization"),
            })

        def getresponse(self):
            if self.host == "api.github.com":
                data = (
                    b"HTTP/1.1 302 Found\r\n"
                    b"Location: https://blob.example/signed\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
            else:
                blob_hits["n"] += 1
                if blob_hits["n"] == 1:
                    data = b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\n\r\n"
                else:
                    body = _FAILURES_TEXT
                    data = (
                        b"HTTP/1.1 200 OK\r\nContent-Length: "
                        + str(len(body)).encode() + b"\r\n\r\n" + body
                    )
            resp = http.client.HTTPResponse(_FakeSocket(data))
            resp.begin()
            return resp

        def close(self):
            pass

    monkeypatch.setattr(http.client, "HTTPSConnection", _FakeHTTPSConnection)

    out = pr_checks._default_log_fetch(
        "https://api.github.com/repos/x/y/actions/jobs/1/logs", bearer="ghs_SECRET",
    )
    assert out["ok"] is True, out
    assert out["status"] == 200
    assert out["range_fallback"] is True
    assert len(calls) == 3
    assert calls[1]["range"] == f"bytes=-{pr_checks._LOG_FETCH_MAX_BYTES}"
    assert calls[2]["range"] is None, "the no-Range retry must not send Range again"
    assert calls[2]["url"] == calls[1]["url"], "the same hop is retried, not a new redirect"
    assert calls[2]["auth"] is None, "the bearer must not follow to the blob host on retry either"

    failure = pr_checks._extract_failure_block(out["text"])
    assert failure["kind"] == "pytest"
    assert "tests/t.py::test_x" in failure["tests_failed"]
    assert failure["count_line"] == "===== 1 failed in 0.01s ====="


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
