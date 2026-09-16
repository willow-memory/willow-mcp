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
   ``cancelled``, ``action_required``, ``startup_failure``), tails the
   Actions job log: the install token authenticates
   ``GET .../actions/jobs/{id}/logs``, and GitHub answers with a 302 to a
   pre-signed, unauthenticated blob URL — the bearer must not ride along
   to that second host, which is why the log fetch is its own helper
   rather than a reuse of ``github_app_credentials._api``.

Three-state top level (INVARIANTS §1): ``populated`` (at least one
check-run), ``empty`` (the head resolved but zero check-runs are
reported yet), ``unreachable`` (``reason`` names the cause: ``token``,
``permission_absent``, ``not_found``, ``timeout``, ``http_<status>``).
A per-run ``log_tail`` that could not be read carries its OWN state the
same way — never an empty string standing in for "no output".
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
_LOG_FETCH_MAX_BYTES = 2 * 1024 * 1024

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_GROUP_MARKER_RE = re.compile(r"^##\[(?:group|endgroup)\]")
# GitHub Actions log-line timestamp prefix, e.g. "2026-09-16T17:29:52.6300000Z ".
_TS_PREFIX_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s?")
_JOB_ID_RE = re.compile(r"/actions/runs/\d+/job/(\d+)")
_ERROR_LINE_RE = re.compile(r"(?i)(error|failed|traceback|assert)")


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
        raw = resp.read(max_bytes + 1)
        resp.close()
        return {
            "ok": True, "status": getattr(resp, "status", 200),
            "text": raw[:max_bytes].decode("utf-8", errors="replace"),
            "redirected": redirected, "truncated": len(raw) > max_bytes,
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
        return {"state": "unreachable", "reason": "permission_absent", "permission": "checks",
                "head": head}

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
    for run in runs:
        summary = _run_summary(run)
        conclusion = summary.get("conclusion")
        if conclusion not in _QUIET_CONCLUSIONS:
            summary["annotations"] = _fetch_annotations(
                call, repo=repo, run_id=summary["id"], bearer=bearer,
            )
        first_error = ""
        if conclusion in _FAILING_CONCLUSIONS:
            if not actions_ok:
                summary["log_tail"] = {
                    "state": "unreachable", "reason": "permission_absent",
                    "permission": "actions",
                }
                first_error = "(log unreachable: permission_absent: actions)"
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
                        tail_lines, total_lines = _log_tail_lines(log_resp.get("text") or "", cap)
                        summary["log_tail"] = {
                            "state": "populated" if tail_lines else "empty",
                            "lines": tail_lines,
                            "log_lines_total": total_lines,
                            "truncated": total_lines > len(tail_lines),
                        }
                        first_error = _first_error_line(tail_lines)
            red.append({
                "name": summary.get("name"),
                "conclusion": conclusion,
                "job_url": summary.get("html_url") or summary.get("details_url"),
                "first_error_line": first_error,
            })
        out_runs.append(summary)

    return {
        "state": "populated",
        "repo": repo,
        "head": head,
        "check_runs": out_runs,
        "red": red,
    }
