"""willow_mcp/pr_checks.py — the desk reads why a check is red.

Gap ``a50c3d9c9a71``. willow-bot deposits CI conclusions and ``run_ci``
files "CI red: <leg>" with a job URL, but nothing on the desk could open
it: no lease for the operator's own GitHub session, and the App token
that mints check-run/log access is held by this broker for
push/pr.open/pull only. The operator's fallback was pasting the log into
the session by hand (gap ``a50c3d9c9a71``).

This is the READ-only sibling of pr_executor / push_executor: no
envelope, no citation, no write. It:

1. Resolves a commit — from a PR number (``GET /pulls/{pr}`` for
   ``head.sha``) or a ref (sha or branch name, used as given).
2. Mints the willows-bot App install token (``github_app_credentials``,
   App-only — no host-token fallback, same rule ``pr_executor`` follows)
   and inspects its ``permissions``: ``checks`` gates the check-runs/
   annotations read, ``actions`` additionally gates the job-log tail.
3. Lists check-runs on that commit (paginated past 100), and annotations
   for any run whose conclusion isn't quiet (``success``/``skipped``/
   ``neutral``).
4. For a run that actually failed (``failure``, ``timed_out``,
   ``cancelled``, ``action_required``, ``startup_failure``), fetches the
   FULL Actions job log (capped at 5 MB): the install token authenticates
   ``GET .../actions/jobs/{id}/logs``, and GitHub answers with a 302 to a
   pre-signed, unauthenticated blob URL — the bearer must not ride along
   to that second host, which is why the log fetch is its own helper
   rather than a reuse of ``github_app_credentials._api``.
5. Extracts a ``failure`` block from that full log (gap ``d5345e7e737f``:
   willow-mcp CI jobs end with ~200 lines of Postgres service teardown, so
   the pytest summary is never inside a 200-line tail window). Preference
   order: pytest's ``=== FAILURES ===``/``=== ERRORS ===``/``short test
   summary info`` section through the trailing count line (whichever of
   FAILURES/ERRORS appears first, when both are present; when the log holds
   more than one pytest invocation, the LAST complete one — the one CI
   actually judged); else a ruff/lint block (lines matching
   ``path.py:LINE:COL: CODE`` plus the ``Found N errors`` summary); else a
   generic fallback anchored on GitHub's own ``##[error]`` annotations
   (Postgres teardown lines are dropped from this fallback ONLY — the
   pytest/ruff blocks are bounded by their own markers and taken verbatim,
   UNLESS no count line closes the pytest block, in which case Postgres
   teardown noise is filtered from it too). A pytest block with no closing
   count line (a timed-out job) ends at the earliest of: the next
   ``##[group]``/job-step marker, 200 lines past the last FAILED/ERROR
   summary line, or end of log — and ``failure.text`` is capped at 300
   lines with ``trimmed: true`` when cut.

Three-state top level (INVARIANTS §1): ``populated`` (at least one
check-run), ``empty`` (the head resolved but zero check-runs are
reported yet), ``unreachable`` (``reason`` names the cause: ``token``,
``permission_absent``, ``not_found``, ``timeout``, ``http_<status>``).
A per-run ``log_tail`` that could not be read carries its OWN state the
same way — never an empty string standing in for "no output". ``log_tail``
stays a raw-line tail for callers that want it; each ``red[]`` entry gains
``failure`` (``{kind, text, tests_failed, count_line, trimmed}``, ``None``
when no log was fetched), ``first_error_line`` becomes the first ``FAILED``
line when ``failure.kind == "pytest"``, and ``truncated``/``bytes_dropped``
report whether the 5 MB log-fetch cap dropped bytes off the HEAD of the
log to keep the tail (the pytest summary lives at the tail).
"""
from __future__ import annotations

import re
from typing import Any, Callable, Optional

_API = "https://api.github.com"

#: Conclusions that actually failed a job — these get a log tail attempt.
_FAILING_CONCLUSIONS = frozenset({
    "failure", "timed_out", "cancelled", "action_required", "startup_failure",
})
#: Conclusions quiet enough that annotations are not worth fetching.
_QUIET_CONCLUSIONS = frozenset({"success", "skipped", "neutral"})

_MAX_OUTPUT_TEXT = 4096          # bytes; per run's output.text
_MAX_ANNOTATIONS = 50            # per run
_MAX_LOG_LINES = 200             # hard cap regardless of the caller's log_tail
_LOG_FETCH_TIMEOUT_S = 10
_LOG_FETCH_MAX_BYTES = 5 * 1024 * 1024   # the full job log, capped (gap d5345e7e737f)
_GENERIC_CONTEXT_LINES = 40       # lines of context kept before the first ##[error]

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_GROUP_MARKER_RE = re.compile(r"^##\[(?:group|endgroup)\]")
# GitHub Actions log-line timestamp prefix, e.g. "2026-09-16T17:29:52.6300000Z ".
_TS_PREFIX_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s?")
_JOB_ID_RE = re.compile(r"/actions/runs/\d+/job/(\d+)")
_ERROR_LINE_RE = re.compile(r"(?i)(error|failed|traceback|assert)")

# ── failure-block extraction (gap d5345e7e737f) ─────────────────────────────
# A pytest run's failure section: "=== FAILURES ===" (or the first
# "___ test_name ___" header if the former is missing — e.g. a single
# collection error), through "short test summary info" and the trailing
# count line.
_PYTEST_FAILURES_HEADER_RE = re.compile(r"^=+\s*FAILURES\s*=+\s*$")
_PYTEST_ERRORS_HEADER_RE = re.compile(r"^=+\s*ERRORS\s*=+\s*$")
# The middle group must hold at least one non-underscore character, else a
# bare "______" banner (e.g. from a make log) would satisfy this pattern —
# `.` matches an underscore too, so "at least one char" alone is not enough.
_PYTEST_TEST_HEADER_RE = re.compile(r"^_{3,}\s*(?P<title>.+?)\s*_{3,}$")
_PYTEST_SUMMARY_HEADER_RE = re.compile(r"^=+\s*short test summary info\s*=+\s*$", re.IGNORECASE)
_PYTEST_COUNT_LINE_RE = re.compile(
    r"^=+.*\b\d+\s+(?:failed|passed|error|errors|skipped|xfailed|xpassed|warnings?)\b.*=+\s*$",
    re.IGNORECASE,
)
# Capture up to " - " (pytest's separator before the failure message) or end
# of line, so a parametrize id containing a space (`test_a[a b]`) survives
# instead of being cut at its first space.
_PYTEST_FAILED_LINE_RE = re.compile(r"^FAILED\s+(.+?)(?: - .*)?$")
_PYTEST_ERROR_SUMMARY_LINE_RE = re.compile(r"^ERROR\s+(.+?)(?: - .*)?$")
_JOB_STEP_MARKER_RE = _GROUP_MARKER_RE  # alias: a "##[group]" line IS a job-step marker
_MAX_FAILURE_TEXT_LINES = 300            # cap on failure.text when no count line closes the block
_MAX_UNCLOSED_LINES_PAST_LAST_FAILURE = 200

# ruff: "path/to/file.py:12:5: E501 line too long"
_RUFF_LINE_RE = re.compile(r"^\S+\.py:\d+:\d+:\s+[A-Z]+\d+")
_RUFF_SUMMARY_RE = re.compile(r"^Found\s+\d+\s+error", re.IGNORECASE)

# Generic fallback: GitHub Actions' own error annotations.
_ACTIONS_ERROR_RE = re.compile(r"##\[error\]")

# Postgres service-container teardown noise — dropped from the GENERIC
# fallback only; pytest/ruff blocks are bounded and taken verbatim.
_PG_LOG_LINE_RE = re.compile(
    r"^\s*\d{4}-\d{2}-\d{2}\s+.*\b(FATAL|LOG|DETAIL|HINT):",
)


def checks_perm_present(permissions: dict | None) -> bool:
    level = (permissions or {}).get("checks") or ""
    return level in ("read", "write", "admin")


def actions_perm_present(permissions: dict | None) -> bool:
    level = (permissions or {}).get("actions") or ""
    return level in ("read", "write", "admin")


def _default_api(method: str, url: str, *, bearer: str, body: dict | None = None) -> dict[str, Any]:
    from . import github_app_credentials as gac

    return gac._api(method, url, bearer=bearer, body=body)


def _default_log_fetch(url: str, *, bearer: str, timeout: float = _LOG_FETCH_TIMEOUT_S,
                        max_bytes: int = _LOG_FETCH_MAX_BYTES) -> dict[str, Any]:
    """GET a job-logs URL, following at most one redirect WITHOUT carrying the
    bearer to the second hop. GitHub's ``.../actions/jobs/{id}/logs`` answers
    with a 302 to a pre-signed, unauthenticated blob URL; replaying
    ``Authorization: Bearer <installation token>`` at whatever host the
    ``Location`` header names would hand the App's credential to a third
    party. Bounded: ``timeout`` seconds per hop, ``max_bytes`` read cap.
    Never raises — every exit is a structured dict."""
    import urllib.error
    import urllib.request

    class _NoAutoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None  # refuse to auto-follow; this function follows by hand

    opener = urllib.request.build_opener(_NoAutoRedirect)
    hop_url, hop_bearer, redirected = url, bearer, False
    for _hop in range(2):  # the original request, plus at most one redirect
        headers = {"User-Agent": "willow-mcp-broker", "Accept": "*/*"}
        if hop_bearer:
            headers["Authorization"] = f"Bearer {hop_bearer}"
        req = urllib.request.Request(hop_url, headers=headers, method="GET")
        try:
            resp = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308):
                location = exc.headers.get("Location") if exc.headers else None
                if not location or redirected:
                    return {"ok": False, "status": exc.code,
                             "reason": "redirect without a usable Location, or a second redirect"}
                hop_url, hop_bearer, redirected = location, "", True
                continue
            detail = exc.read(400).decode(errors="replace")
            return {"ok": False, "status": exc.code, "reason": detail or str(exc.reason)}
        except Exception as exc:  # noqa: BLE001 — surface as a structured miss
            return {"ok": False, "status": 0, "reason": f"{type(exc).__name__}: {exc}"}
        # Ring-buffer the stream in chunks, keeping only the LAST max_bytes
        # bytes: the pytest FAILURES/summary section lives at the TAIL of a
        # CI log, so a cap that keeps the head (a plain `read(max_bytes)`)
        # silently drops exactly the block this feature exists to find.
        buf = bytearray()
        total_read = 0
        chunk_size = 65536
        while True:
            chunk = resp.read(chunk_size)
            if not chunk:
                break
            total_read += len(chunk)
            buf.extend(chunk)
            if len(buf) > max_bytes:
                del buf[: len(buf) - max_bytes]
        resp.close()
        truncated = total_read > max_bytes
        return {
            "ok": True, "status": getattr(resp, "status", 200),
            "text": bytes(buf).decode("utf-8", errors="replace"),
            "redirected": redirected, "truncated": truncated,
            "bytes_dropped": max(0, total_read - max_bytes),
        }
    return {"ok": False, "status": 0, "reason": "too many redirects"}


def _classify_http_failure(resp: dict) -> tuple[str, str]:
    status = resp.get("status") or 0
    reason = str(resp.get("reason") or "")
    if status == 404:
        return "not_found", reason
    if status == 0 and "timeout" in reason.lower():
        return "timeout", reason
    if status:
        return f"http_{status}", reason
    return "unavailable", reason


def _job_id_from_url(url: str) -> Optional[str]:
    if not url:
        return None
    m = _JOB_ID_RE.search(url)
    return m.group(1) if m else None


def _clean_log_line(line: str) -> str:
    line = _ANSI_RE.sub("", line)
    line = _TS_PREFIX_RE.sub("", line)
    return line


def _log_tail_lines(text: str, cap: int) -> tuple[list[str], int]:
    """(tail lines, total lines) — ANSI stripped, ``##[group]``/timestamp
    prefixes trimmed, ``##[group]``/``##[endgroup]`` marker lines dropped
    entirely (they carry no diagnostic content)."""
    cleaned = (_clean_log_line(raw) for raw in text.splitlines())
    lines = [line for line in cleaned if not _GROUP_MARKER_RE.match(line.strip())]
    total = len(lines)
    n = min(max(cap, 1), _MAX_LOG_LINES)
    return lines[-n:], total


def _first_error_line(tail_lines: list[str]) -> str:
    for line in tail_lines:
        if _ERROR_LINE_RE.search(line):
            return line
    return tail_lines[-1] if tail_lines else ""


def _clean_lines(text: str) -> list[str]:
    """The full log, ANSI-stripped, GitHub's per-line ISO timestamp prefix
    trimmed — the same cleaning ``_log_tail_lines`` does, but over the WHOLE
    log rather than the tail window, so failure-block extraction can see
    sections ``log_tail``'s cap would otherwise cut off (gap d5345e7e737f:
    a CI job's ~200-line Postgres teardown pushed the pytest summary out of
    the old tail-only window).

    Unlike ``_log_tail_lines``, ``##[group]``/``##[endgroup]`` marker lines
    are KEPT here (not dropped) — an unclosed pytest block (no count line)
    uses the next job-step marker as an end boundary, so extraction needs
    to see them. Each extractor strips marker lines from its own returned
    ``text``."""
    cleaned = (_clean_log_line(raw) for raw in text.splitlines())
    return list(cleaned)


def _find_pytest_block_start(lines: list[str], lo: int, hi: int) -> Optional[int]:
    """Earliest of a FAILURES/ERRORS header in ``[lo, hi)``; when both are
    present the earlier one wins so the ERRORS section is never dropped
    (item 6). Else the earliest ``___ title ___`` header whose title holds a
    non-underscore character. Else the earliest "short test summary info"
    header (the ``-q --tb=no`` shape: no FAILURES/ERRORS section at all)."""
    headers = [
        i for i in range(lo, hi)
        if _PYTEST_FAILURES_HEADER_RE.match(lines[i].strip())
        or _PYTEST_ERRORS_HEADER_RE.match(lines[i].strip())
    ]
    if headers:
        return min(headers)
    for i in range(lo, hi):
        m = _PYTEST_TEST_HEADER_RE.match(lines[i].strip())
        if m and any(c != "_" for c in m.group("title")):
            return i
    for i in range(lo, hi):
        if _PYTEST_SUMMARY_HEADER_RE.match(lines[i].strip()):
            return i
    return None


def _extract_pytest_failure(lines: list[str]) -> Optional[dict[str, Any]]:
    n = len(lines)
    count_idxs = [i for i in range(n) if _PYTEST_COUNT_LINE_RE.match(lines[i].strip())]

    if count_idxs:
        # Multiple pytest invocations in one log: take the LAST complete
        # block — the re-run is what CI judged (item 6) — searching for its
        # start only after the previous invocation's own count line.
        lo = count_idxs[-2] + 1 if len(count_idxs) > 1 else 0
        last_count_idx = count_idxs[-1]
        start = _find_pytest_block_start(lines, lo, last_count_idx + 1)
        if start is None:
            start = _find_pytest_block_start(lines, 0, last_count_idx + 1)
        if start is None:
            return None
        end = last_count_idx + 1
        count_line = lines[last_count_idx].strip()
        closed = True
    else:
        start = _find_pytest_block_start(lines, 0, n)
        if start is None:
            return None
        count_line = ""
        closed = False
        # No count line closes the block (a timed-out job): end at the
        # earliest of the next job-step marker, 200 lines past the last
        # FAILED/ERROR summary line, or end of log.
        last_failure_idx = None
        for i in range(start, n):
            s = lines[i].strip()
            if _PYTEST_FAILED_LINE_RE.match(s) or _PYTEST_ERROR_SUMMARY_LINE_RE.match(s):
                last_failure_idx = i
        next_marker_idx = None
        for i in range(start + 1, n):
            if _JOB_STEP_MARKER_RE.match(lines[i].strip()):
                next_marker_idx = i
                break
        candidates = [n]
        if next_marker_idx is not None:
            candidates.append(next_marker_idx)
        if last_failure_idx is not None:
            candidates.append(min(n, last_failure_idx + 1 + _MAX_UNCLOSED_LINES_PAST_LAST_FAILURE))
        end = min(candidates)

    block = [line for line in lines[start:end] if not _JOB_STEP_MARKER_RE.match(line.strip())]
    if not closed:
        # Postgres FATAL/LOG teardown noise is applied to the pytest block
        # ONLY when no count line closed it (item 3) — a closed block is
        # bounded by its own markers and taken verbatim.
        block = [line for line in block if not _PG_LOG_LINE_RE.match(line)]

    tests_failed = []
    for line in block:
        s = line.strip()
        m = _PYTEST_FAILED_LINE_RE.match(s)
        if m:
            tests_failed.append(m.group(1))
            continue
        m2 = _PYTEST_ERROR_SUMMARY_LINE_RE.match(s)
        if m2:
            tests_failed.append(m2.group(1))

    trimmed = len(block) > _MAX_FAILURE_TEXT_LINES
    if trimmed:
        block = block[:_MAX_FAILURE_TEXT_LINES]

    return {
        "kind": "pytest",
        "text": "\n".join(block),
        "tests_failed": tests_failed,
        "count_line": count_line,
        "trimmed": trimmed,
    }


def _extract_ruff_failure(lines: list[str]) -> Optional[dict[str, Any]]:
    matches = [line.strip() for line in lines if _RUFF_LINE_RE.match(line.strip())]
    if not matches:
        return None
    summary = ""
    for line in lines:
        if _RUFF_SUMMARY_RE.match(line.strip()):
            summary = line.strip()
            break
    block = matches + ([summary] if summary else [])
    return {
        "kind": "ruff",
        "text": "\n".join(block),
        "tests_failed": [],
        "count_line": summary,
        "trimmed": False,
    }


def _extract_generic_failure(lines: list[str]) -> dict[str, Any]:
    """The last resort: GitHub's own ``##[error]`` annotations, plus
    ``_GENERIC_CONTEXT_LINES`` of context before the first one. Postgres
    service-container teardown noise is dropped HERE ONLY — pytest/ruff
    blocks above are bounded by their own markers and taken verbatim."""
    filtered = [
        line for line in lines
        if not _PG_LOG_LINE_RE.match(line) and not _JOB_STEP_MARKER_RE.match(line.strip())
    ]
    error_idxs = [i for i, line in enumerate(filtered) if _ACTIONS_ERROR_RE.search(line)]
    if not error_idxs:
        block = filtered[-_GENERIC_CONTEXT_LINES:]
    else:
        start = max(0, error_idxs[0] - _GENERIC_CONTEXT_LINES)
        end = error_idxs[-1] + 1
        block = filtered[start:end]
    return {
        "kind": "generic",
        "text": "\n".join(block),
        "tests_failed": [],
        "count_line": "",
        "trimmed": False,
    }


def _extract_failure_block(text: str) -> dict[str, Any]:
    """Extract the diagnostic block from a full job log: pytest's
    FAILURES/summary section, else a ruff lint block, else a generic
    ``##[error]``-anchored fallback. Never raises on a text with no
    recognizable failure shape — the generic path always returns something."""
    lines = _clean_lines(text)
    return (
        _extract_pytest_failure(lines)
        or _extract_ruff_failure(lines)
        or _extract_generic_failure(lines)
    )


def _fetch_check_runs(api: Callable, *, repo: str, sha: str, bearer: str) -> tuple[Optional[list[dict]], Optional[dict]]:
    """(runs, None) on success, (None, failed_response) on the first miss.
    Paginates past GitHub's 100-per-page cap using ``total_count``."""
    runs: list[dict] = []
    page = 1
    while True:
        url = f"{_API}/repos/{repo}/commits/{sha}/check-runs?per_page=100&page={page}"
        resp = api("GET", url, bearer=bearer)
        if not resp.get("ok"):
            return None, resp
        body = resp.get("body") or {}
        total_count = int(body.get("total_count") or 0)
        page_runs = body.get("check_runs") or []
        runs.extend(page_runs)
        if not page_runs or len(runs) >= total_count:
            return runs, None
        page += 1


def _fetch_annotations(api: Callable, *, repo: str, run_id, bearer: str) -> dict:
    url = f"{_API}/repos/{repo}/check-runs/{run_id}/annotations?per_page={_MAX_ANNOTATIONS}"
    resp = api("GET", url, bearer=bearer)
    if not resp.get("ok"):
        cause, reason = _classify_http_failure(resp)
        return {"state": "unreachable", "reason": cause, "detail": reason}
    body = resp.get("body")
    items = body if isinstance(body, list) else []
    items = items[:_MAX_ANNOTATIONS]
    return {"state": "populated" if items else "empty", "annotations": items}


def _run_summary(run: dict) -> dict:
    output = run.get("output") or {}
    text = output.get("text") or ""
    encoded = text.encode("utf-8")
    truncated = len(encoded) > _MAX_OUTPUT_TEXT
    if truncated:
        text = encoded[:_MAX_OUTPUT_TEXT].decode("utf-8", errors="ignore")
    return {
        "id": run.get("id"),
        "name": run.get("name"),
        "status": run.get("status"),
        "conclusion": run.get("conclusion"),
        "html_url": run.get("html_url"),
        "details_url": run.get("details_url"),
        "app_slug": (run.get("app") or {}).get("slug"),
        "started_at": run.get("started_at"),
        "completed_at": run.get("completed_at"),
        "output": {
            "title": output.get("title"),
            "summary": output.get("summary"),
            "text": text,
            "truncated": truncated,
        },
    }


def read_pr_checks(
    app_id: str,
    *,
    repo: str,
    ref: str = "",
    pr: int = 0,
    log_tail: int = 120,
    project: str = "",
    api: Optional[Callable] = None,
    log_fetch: Optional[Callable] = None,
    store=None,
) -> dict:
    """Read check-runs (and, for a failing run, a bounded log tail) on a
    commit — named by ``pr`` (a PR number, resolved to its head sha) or
    ``ref`` (a sha or branch name, used as given). Never writes, never
    cites an envelope: a read like ``bot_status``, gated the same way.

    Returns the three-state contract at the top level (``state``:
    ``populated``/``empty``/``unreachable``); ``EINVAL`` is a validation
    refusal before any state applies (neither ``pr`` nor ``ref`` given, or
    ``repo`` malformed).
    """
    repo = (repo or "").strip().strip("/")
    ref = (ref or "").strip()
    pr = int(pr or 0)
    if repo.count("/") != 1:
        return {"ok": False, "error": "EINVAL", "reason": "repo must be org/name"}
    if not pr and not ref:
        return {"ok": False, "error": "EINVAL",
                "reason": "pass pr (a PR number) or ref (a sha or branch) to name a head"}

    call = api or _default_api
    fetch_log = log_fetch or _default_log_fetch
    cap = min(max(int(log_tail or 120), 1), _MAX_LOG_LINES)

    from . import github_app_credentials as gac

    auth = gac.mint_installation_token(repo)
    if not (auth.get("ok") and auth.get("mode") == "app"):
        return {"state": "unreachable", "reason": "token",
                "detail": auth.get("reason") or "could not mint a willows-bot installation token"}
    bearer = auth["token"]
    permissions = auth.get("permissions")

    head: dict[str, Any] = {}
    sha = ref
    if pr:
        resp = call("GET", f"{_API}/repos/{repo}/pulls/{pr}", bearer=bearer)
        if not resp.get("ok"):
            cause, reason = _classify_http_failure(resp)
            return {"state": "unreachable", "reason": cause, "detail": reason}
        body = resp.get("body") or {}
        sha = (body.get("head") or {}).get("sha") or ""
        head = {
            "pr": pr,
            "sha": sha,
            "ref": (body.get("head") or {}).get("ref"),
            "title": body.get("title"),
            "pr_state": body.get("state"),
        }
        if not sha:
            return {"state": "unreachable", "reason": "not_found",
                    "detail": f"pull request {pr} carries no head sha"}
    else:
        head = {"sha": sha}

    if not checks_perm_present(permissions):
        out = {"state": "unreachable", "reason": "permission_absent", "permission": "checks",
               "head": head}
        _file_ask(out, store=store, app_id=app_id, repo=repo, permission="checks",
                  current=(permissions or {}).get("checks"))
        return out

    runs, failed = _fetch_check_runs(call, repo=repo, sha=sha, bearer=bearer)
    if failed is not None:
        cause, reason = _classify_http_failure(failed)
        return {"state": "unreachable", "reason": cause, "detail": reason, "head": head}

    if not runs:
        return {"state": "empty", "head": head,
                "reason": f"no checks reported for {sha} yet"}

    actions_ok = actions_perm_present(permissions)
    out_runs: list[dict] = []
    red: list[dict] = []
    actions_ask: Optional[dict] = None
    for run in runs:
        summary = _run_summary(run)
        conclusion = summary.get("conclusion")
        if conclusion not in _QUIET_CONCLUSIONS:
            summary["annotations"] = _fetch_annotations(
                call, repo=repo, run_id=summary["id"], bearer=bearer,
            )
        first_error = ""
        failure: Optional[dict[str, Any]] = None
        log_truncated = False
        log_bytes_dropped = 0
        if conclusion in _FAILING_CONCLUSIONS:
            if not actions_ok:
                summary["log_tail"] = {
                    "state": "unreachable", "reason": "permission_absent",
                    "permission": "actions",
                }
                first_error = "(log unreachable: permission_absent: actions)"
                if actions_ask is None:  # one ask per call, not per failing run
                    actions_ask = {}
                    _file_ask(actions_ask, store=store, app_id=app_id, repo=repo,
                              permission="actions",
                              current=(permissions or {}).get("actions"))
            else:
                job_id = _job_id_from_url(summary.get("details_url") or "") or \
                    _job_id_from_url(summary.get("html_url") or "")
                if not job_id:
                    summary["log_tail"] = {
                        "state": "unreachable", "reason": "no_job_id",
                        "detail": "could not derive an Actions job id from details_url/html_url",
                    }
                    first_error = "(log unreachable: no_job_id)"
                else:
                    log_url = f"{_API}/repos/{repo}/actions/jobs/{job_id}/logs"
                    log_resp = fetch_log(log_url, bearer=bearer)
                    if not log_resp.get("ok"):
                        cause, reason = _classify_http_failure(log_resp)
                        summary["log_tail"] = {"state": "unreachable", "reason": cause, "detail": reason}
                        first_error = f"(log unreachable: {cause})"
                    else:
                        full_text = log_resp.get("text") or ""
                        log_truncated = bool(log_resp.get("truncated"))
                        log_bytes_dropped = int(log_resp.get("bytes_dropped") or 0)
                        tail_lines, total_lines = _log_tail_lines(full_text, cap)
                        summary["log_tail"] = {
                            "state": "populated" if tail_lines else "empty",
                            "lines": tail_lines,
                            "log_lines_total": total_lines,
                            "truncated": total_lines > len(tail_lines),
                        }
                        # The failure block is extracted from the FULL log, not
                        # the tail window: a job's Postgres-teardown noise (gap
                        # d5345e7e737f) can push the pytest summary past
                        # log_tail's 200-line cap entirely.
                        failure = _extract_failure_block(full_text)
                        if failure["kind"] == "pytest":
                            pytest_failed_lines = [
                                line for line in failure["text"].splitlines()
                                if line.strip().startswith("FAILED ")
                            ]
                            first_error = pytest_failed_lines[0].strip() if pytest_failed_lines \
                                else _first_error_line(tail_lines)
                        else:
                            first_error = _first_error_line(tail_lines)
            red.append({
                "name": summary.get("name"),
                "conclusion": conclusion,
                "job_url": summary.get("html_url") or summary.get("details_url"),
                "first_error_line": first_error,
                "failure": failure,
                "truncated": log_truncated,
                "bytes_dropped": log_bytes_dropped,
            })
        out_runs.append(summary)

    result = {
        "state": "populated",
        "repo": repo,
        "head": head,
        "check_runs": out_runs,
        "red": red,
    }
    if actions_ask:
        result.update(actions_ask)
    return result


def _file_ask(out: dict, *, store, app_id: str, repo: str, permission: str,
              current: Optional[str]) -> None:
    """Gap 4464a63db1a9: a missing App permission is told to the operator
    ONCE, as a named human_required item, beside the verb's own
    ``permission_absent`` — which is unchanged. Mutates ``out`` with
    ``human_required_id`` (and ``human_required_state``); never raises."""
    from . import github_app_permissions as gap_

    filed = gap_.file_permission_ask(
        store, app_id=app_id, verb="pr_checks_read", repo=repo,
        permission=permission, level="read", current=current,
    )
    out["human_required_state"] = filed.get("state")
    if filed.get("human_required_id"):
        out["human_required_id"] = filed["human_required_id"]
