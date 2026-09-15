"""willow_mcp/remote_base.py — remote-base ancestry preflight.

Gap ``bc9945dd47da``. A push (verb 3) or a pull-request-open (verb 4) that
proceeds from a stale local base is a request the operator must undo by
hand — the incident that motivated this: willow-mcp PR #530 was built
from stale local ``master`` and pushed without a preflight, the operator
had to click *Update branch*, and a later CI fix then had to be
reconciled in a worktree before it could be pushed non-force.

This module is the one preflight both executors call. For a push, it uses
a bounded ``git fetch`` and local ``rev-list --left-right --count`` — the
same shape ``pull_executor`` already uses (a fetch never rewrites HEAD,
so a preflight cannot lose work). For a PR-open, where there is no local
checkout in the executor, use ``preflight_via_compare`` which reads
GitHub's compare endpoint under the App's install token.

The returned dict is the same shape from both readers, so the caller
decides the same way in either lane:

- ``{"ok": True, "state": "current", "ahead": N, "behind": 0, ...}`` when
  the remote base is fully contained in the head — proceed.
- ``{"ok": False, "errno": "ESTALE", "state": "behind"|"diverged",
    "ahead": N, "behind": M, ...}`` when the head is missing commits from
  the remote base — refuse, before the envelope is consulted.
- ``{"ok": False, "errno": "EFETCH", "reason": "..."}`` on fetch or
  compare failure — refuse, before the envelope is consulted.
- ``{"ok": True, "state": "skipped", "reason": "..."}`` when no base
  could be resolved and none was passed — the receipt still names the
  reason so the seat can tell a passed check from an absent one.

``ESTALE`` is a distinct errno from ``EPUSH`` (git rejected the push) and
``EPR`` (GitHub refused the pull request open) so the receipt reader can
tell a preflight refusal (no envelope consumed) from a remote rejection
(envelope was consumed and the network answered no). Gap
``bc9945dd47da`` and the operator-facing part of ``5ecb87cfdf56``.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any, Callable, Optional


_GIT_TIMEOUT_S = 60


def _git(checkout: Path, *args: str, runner: Optional[Callable] = None) -> subprocess.CompletedProcess:
    run = runner or subprocess.run
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    return run(
        ["git", "-C", str(checkout), *args],
        capture_output=True, text=True, timeout=_GIT_TIMEOUT_S, env=env, check=False,
    )


def _out(proc: subprocess.CompletedProcess) -> str:
    return (proc.stdout or "").strip()


def _tail(proc: subprocess.CompletedProcess) -> str:
    return (proc.stderr or proc.stdout or "").strip()[-300:]


def _resolve_default_base(checkout: Path, *, remote: str,
                          runner: Optional[Callable] = None) -> str:
    """Read ``refs/remotes/<remote>/HEAD`` and return the branch it points at,
    or ``""`` if the symref is not set (a fresh ``git init`` clone, or a
    remote that never advertised its HEAD). Never raises."""
    proc = _git(checkout, "symbolic-ref", "--short", f"refs/remotes/{remote}/HEAD",
                runner=runner)
    if proc.returncode != 0:
        return ""
    v = _out(proc)
    prefix = f"{remote}/"
    if v.startswith(prefix):
        v = v[len(prefix):]
    return v


def preflight_local_ancestry(
    checkout: Path,
    *,
    remote: str,
    head_ref: str,
    base_branch: str = "",
    runner: Optional[Callable] = None,
) -> dict[str, Any]:
    """Fetch ``remote/base_branch`` and check that it is an ancestor of the
    local ``head_ref``.

    ``base_branch`` defaults to whatever ``refs/remotes/<remote>/HEAD``
    points at — a repo whose default branch has not been advertised, and a
    caller who did not name a base, produces ``state="skipped"`` (an
    honest absence rather than a fabricated verdict).

    ``head_ref`` names a local branch (``feat/x``, not
    ``refs/heads/feat/x``) — the executor already knows it exists at the
    time of the call.
    """
    result: dict[str, Any] = {"ok": True, "remote": remote, "base_branch": "", "head_ref": head_ref}
    base = (base_branch or "").strip()
    if not base:
        base = _resolve_default_base(checkout, remote=remote, runner=runner)
    if not base:
        result["state"] = "skipped"
        result["reason"] = (f"no {remote}/HEAD symref and no base branch given; "
                            "preflight cannot compare without a base")
        return result
    result["base_branch"] = base

    # A bounded fetch of the one ref we compare against. `--prune` is
    # deliberately not used (a pruning fetch on a shared clone can drop
    # someone else's tracking ref).
    fetched = _git(checkout, "fetch", remote, base, runner=runner)
    if fetched.returncode != 0:
        return {
            "ok": False, "errno": "EFETCH",
            "reason": _tail(fetched) or f"git fetch {remote} {base} exited {fetched.returncode}",
            "remote": remote, "base_branch": base, "head_ref": head_ref,
        }

    remote_ref = f"refs/remotes/{remote}/{base}"
    base_sha_proc = _git(checkout, "rev-parse", "--verify", "--quiet", remote_ref, runner=runner)
    if base_sha_proc.returncode != 0:
        return {
            "ok": False, "errno": "EFETCH",
            "reason": f"{remote}/{base} did not resolve after fetch — the remote does not carry it",
            "remote": remote, "base_branch": base, "head_ref": head_ref,
        }
    base_sha = _out(base_sha_proc)

    head_sha_proc = _git(checkout, "rev-parse", "--verify", "--quiet",
                         f"refs/heads/{head_ref}", runner=runner)
    if head_sha_proc.returncode != 0:
        return {
            "ok": False, "errno": "EINVAL",
            "reason": f"head {head_ref!r} does not exist in the checkout",
            "remote": remote, "base_branch": base, "head_ref": head_ref,
        }
    head_sha = _out(head_sha_proc)

    # left-right on `head...remote/base`: L is commits on head not on base,
    # R is commits on base not on head. `behind: 0` means the base is fully
    # contained; anything else means the head is stale w.r.t. the base.
    counts_proc = _git(
        checkout, "rev-list", "--left-right", "--count",
        f"refs/heads/{head_ref}...{remote_ref}", runner=runner,
    )
    if counts_proc.returncode != 0:
        return {
            "ok": False, "errno": "EFETCH",
            "reason": _tail(counts_proc) or f"git rev-list exited {counts_proc.returncode}",
            "remote": remote, "base_branch": base, "head_ref": head_ref,
            "base_sha": base_sha, "head_sha": head_sha,
        }
    parts = _out(counts_proc).split()
    if len(parts) != 2:
        return {
            "ok": False, "errno": "EFETCH",
            "reason": f"unexpected rev-list output: {_out(counts_proc)!r}",
            "remote": remote, "base_branch": base, "head_ref": head_ref,
            "base_sha": base_sha, "head_sha": head_sha,
        }
    try:
        ahead, behind = int(parts[0]), int(parts[1])
    except ValueError:
        return {
            "ok": False, "errno": "EFETCH",
            "reason": f"could not parse rev-list output: {_out(counts_proc)!r}",
            "remote": remote, "base_branch": base, "head_ref": head_ref,
            "base_sha": base_sha, "head_sha": head_sha,
        }

    common = {"remote": remote, "base_branch": base, "head_ref": head_ref,
              "base_sha": base_sha, "head_sha": head_sha,
              "ahead": ahead, "behind": behind}

    if behind == 0:
        # `ahead > 0` is normal for a feature branch; `ahead == 0` means the
        # head is identical to the base (a push directly onto the default,
        # already at HEAD — the push itself is then either a no-op or a
        # different verb).
        return {"ok": True, "state": "current", **common}
    if ahead == 0:
        return {
            "ok": False, "errno": "ESTALE", "state": "behind",
            "reason": (f"{head_ref} is {behind} commit(s) behind {remote}/{base}; "
                       "the push would carry a stale base — refresh locally "
                       "before opening the request"),
            **common,
        }
    return {
        "ok": False, "errno": "ESTALE", "state": "diverged",
        "reason": (f"{head_ref} is {ahead} commit(s) ahead of {remote}/{base} "
                   f"and {behind} commit(s) behind; the branches share history "
                   "but each has commits the other does not — rebase or merge "
                   "the current base before the request"),
        **common,
    }


def preflight_via_compare(
    api: Callable,
    *,
    repo: str,
    head: str,
    base: str,
    bearer: str,
    api_base: str = "https://api.github.com",
) -> dict[str, Any]:
    """The pr-open lane's preflight: no local checkout, so ask GitHub the
    same question. ``GET /repos/{repo}/compare/{base}...{head}`` returns
    ``status`` in ``{"identical", "ahead", "behind", "diverged"}`` plus
    ``ahead_by``/``behind_by``; we translate those to the same receipt
    :func:`preflight_local_ancestry` produces so a caller reads one shape
    regardless of which lane refused.

    ``api`` matches ``github_app_credentials._api`` — a callable taking
    ``(method, url, bearer=..., body=...)`` and returning
    ``{"ok": bool, "status": int, "body": ...}``. ``bearer`` is the App's
    install token minted for ``repo``.

    ``EFETCH`` covers a non-2xx or malformed response; ``ESTALE`` covers
    ``behind`` and ``diverged``. There is no ``skipped`` state in this
    lane — the PR-open caller has already named a base (it is a required
    argument).
    """
    common = {"remote": "origin", "base_branch": base, "head_ref": head}
    url = f"{api_base}/repos/{repo}/compare/{base}...{head}"
    resp = api("GET", url, bearer=bearer)
    if not resp.get("ok"):
        return {
            "ok": False, "errno": "EFETCH",
            "reason": (f"HTTP {resp.get('status')} from GET "
                       f"/repos/{repo}/compare/{base}...{head}: "
                       f"{str(resp.get('reason', ''))[:200]}"),
            **common,
        }
    body = resp.get("body") or {}
    status = (body.get("status") or "").strip()
    try:
        ahead = int(body.get("ahead_by") or 0)
        behind = int(body.get("behind_by") or 0)
    except (TypeError, ValueError):
        return {
            "ok": False, "errno": "EFETCH",
            "reason": "malformed compare response: ahead_by/behind_by not integers",
            **common,
        }
    base_sha = ((body.get("merge_base_commit") or {}).get("sha")
                or (body.get("base_commit") or {}).get("sha") or "")
    commits = body.get("commits") or []
    head_sha = commits[-1].get("sha") if commits else base_sha
    full = {**common, "base_sha": base_sha, "head_sha": head_sha,
            "ahead": ahead, "behind": behind}
    if status in ("identical", "ahead"):
        return {"ok": True, "state": "current", **full}
    if status == "behind":
        return {
            "ok": False, "errno": "ESTALE", "state": "behind",
            "reason": (f"{head} is {behind} commit(s) behind {base} on {repo}; "
                       "the pull request would carry a stale base — refresh the "
                       "head branch before opening the request"),
            **full,
        }
    if status == "diverged":
        return {
            "ok": False, "errno": "ESTALE", "state": "diverged",
            "reason": (f"{head} is {ahead} ahead of {base} and {behind} behind on {repo}; "
                       "the branches share history but each has commits the other "
                       "does not — rebase or merge the current base before the request"),
            **full,
        }
    return {
        "ok": False, "errno": "EFETCH",
        "reason": f"unexpected compare status: {status!r}",
        **full,
    }
