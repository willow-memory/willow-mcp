"""willow_mcp/pr_executor.py — the broker opens the pull request; the agent asks.

The sibling of :mod:`push_executor`, for verb 4. The brokered push (operator
ruling 2026-09-10) settled *who initiates* and *who holds the key* for
``git.push``; this module gives ``pr.open`` the same answer. Until it existed
every ``pr.open`` envelope in the register was applied "via gh on the host"
(gap ee5ff1342c37): the ``github`` integration adapter reads a token from
env/vault only, so with no host token it answered 401 even under a live
lease, while the willows-bot credential that pushed the branch sat one
module away, used by nothing but the push.

What this module does, in order, and nothing else:

1. **Validate the ask.** ``repo`` is ``org/name``; ``head`` and ``base`` are
   branch names that do not begin with ``-``; ``title`` is non-empty.
2. **Check and cite, before any network.** The call args —
   ``{repo, base_branches:[base]}``, the verb's bounds signature — go through
   :meth:`EnvelopeAuthority.authorize_and_cite`, the same indivisible
   check-then-cite ``envelope_apply`` performs. A refusal leaves a FRANK
   citation with its errno and no request.
3. **File the ask on a miss.** As the push does: the operator sees "X wants
   to open a PR on Y" while the work is still waiting.
4. **Mint the App token and POST.** ``github_app_credentials`` mints a
   willows-bot installation token scoped to the one repo; the request goes
   to ``POST /repos/{repo}/pulls`` with it. The token never leaves this
   process and is never written anywhere. A repo the App does not cover is
   an ``EAUTH`` refusal — there is deliberately no host-token fallback here,
   because a PR opened on a host token is authored by the operator's account
   and the fleet's rule is that the bot's acts are the bot's.
5. **Return a receipt**: the PR number and URL, the citation id, and the
   bot's response status.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

VERB = "pr.open"

_ASKABLE = frozenset({"ENOENT", "EAMBIG", "EEXPIRED", "EDQUOT", "ENOGRANTS"})

_API = "https://api.github.com"


def _refuse(errno: str, reason: str, **extra) -> dict:
    return {"ok": False, "error": errno, "reason": reason, "opened": False, **extra}


def pulls_perm_allows_open(permissions: dict | None) -> bool:
    level = (permissions or {}).get("pull_requests") or ""
    return level in ("write", "admin")


def _file_ask(app_id: str, *, repo: str, head: str, base: str, errno: str,
              reason: str, fields, task_id: str, store=None) -> dict:
    """Put the ask in front of the operator. Never raises — the caller is
    already refusing."""
    try:
        from . import human_loop
        from .db import Store

        if store is None:
            store = Store()
        detail = f"{errno}: {reason}"
        if fields:
            detail += f" (fields: {', '.join(str(f) for f in fields)})"
        item = human_loop.enqueue(
            store,
            kind="review",
            title=f"PR request: {repo} {head} -> {base}",
            summary=(
                f"{app_id or 'an agent'} asked to open a pull request on {repo} "
                f"from {head!r} into {base!r} and was refused: {detail}. Ratify a "
                f"pr.open envelope with these bounds (repo={repo!r}, "
                f"base_branches=[{base!r}]) and the agent can ask again."
            ),
            source_agent=app_id or "",
            source_ref=f"pr.{repo}#{head}" + (f"@{task_id}" if task_id else ""),
        )
        return {"queued": True, "id": item.get("id")}
    except Exception as exc:  # noqa: BLE001 — filing must never turn a refusal into a traceback
        return {"queued": False, "reason": f"could not enqueue the ask ({exc})"}


def _default_api(method: str, url: str, *, bearer: str, body: dict | None = None) -> dict[str, Any]:
    from . import github_app_credentials as gac

    return gac._api(method, url, bearer=bearer, body=body)


def execute_pr_open(
    app_id: str,
    *,
    repo: str,
    head: str,
    base: str,
    title: str,
    body: str = "",
    draft: bool = False,
    envelope_id: str = "",
    project: str,
    session: str = "",
    task_id: str = "",
    ledger=None,
    store=None,
    api: Optional[Callable] = None,
) -> dict:
    """Open a pull request ``head`` -> ``base`` on ``repo`` as willows-bot,
    under the ``pr.open`` envelope that governs ``app_id`` — or refuse, cite
    the refusal, and file the ask.

    ``ledger`` is a :class:`GovernanceLedger`; the MCP tool builds it from
    the live Postgres, tests pass a fake. ``api`` replaces the HTTPS call in
    tests. Returns a dict with ``ok``/``opened``; a refusal carries ``error``
    (the errno) and ``reason``.
    """
    from .envelopes import EnvelopeAuthority, governing_envelope_ids

    repo = (repo or "").strip().strip("/")
    head = (head or "").strip()
    base = (base or "").strip()
    title = (title or "").strip()
    if repo.count("/") != 1 or not head or not base or not title:
        return _refuse("EINVAL", "a pull request names a repo (org/name), a head branch, "
                                 "a base branch and a title")
    if head.startswith("-") or base.startswith("-"):
        return _refuse("EINVAL", "head and base may not begin with '-'")

    call_args = {"repo": repo, "base_branches": [base]}

    try:
        matches = governing_envelope_ids(VERB, app_id)
    except (OSError, ValueError) as exc:
        return _refuse("EAMBIG", f"envelope registry unreadable: {exc}")
    if envelope_id:
        if envelope_id not in matches:
            result = _refuse("ENOENT",
                             f"envelope {envelope_id!r} does not govern {VERB} for "
                             f"{app_id!r}", envelope_ids=matches)
            result["ask"] = _file_ask(app_id, repo=repo, head=head, base=base,
                                      errno="ENOENT", reason=result["reason"],
                                      fields=None, task_id=task_id, store=store)
            return result
        matches = [envelope_id]
    if not matches:
        result = _refuse("ENOENT", f"no active {VERB} envelope governs {app_id!r}")
        result["ask"] = _file_ask(app_id, repo=repo, head=head, base=base,
                                  errno="ENOENT", reason=result["reason"],
                                  fields=None, task_id=task_id, store=store)
        return result
    if len(matches) > 1:
        return _refuse("EAMBIG", f"multiple active {VERB} envelopes govern {app_id!r} — "
                                 "pass envelope_id to name which one to cite",
                       envelope_ids=matches)
    if ledger is None:
        return _refuse("EAMBIG", "no governance ledger: a pull request that cannot be "
                                 "cited is not opened")

    # Check and cite, before any network.
    result = EnvelopeAuthority(ledger).authorize_and_cite(
        matches[0], actor=app_id, verb=VERB, call_args=call_args,
        project=project, session=session,
    )
    if not result.get("ok"):
        errno = result.get("errno", "EAMBIG")
        out = _refuse(errno, result.get("reason", ""), envelope_id=matches[0],
                      citation_id=result.get("citation_id"),
                      fields=result.get("fields"))
        if errno in _ASKABLE:
            out["ask"] = _file_ask(app_id, repo=repo, head=head, base=base,
                                   errno=errno, reason=out["reason"],
                                   fields=result.get("fields"), task_id=task_id,
                                   store=store)
        return out

    # Credential: the App, or nothing. See the module docstring for why there
    # is no host-token fallback on this verb.
    from . import github_app_credentials as gac

    auth = gac.mint_installation_token(repo)
    if not (auth.get("ok") and auth.get("mode") == "app"):
        return _refuse(
            "EAUTH",
            auth.get("reason") or "could not mint a willows-bot installation token",
            envelope_id=matches[0], citation_id=result.get("citation_id"),
        )
    if not pulls_perm_allows_open(auth.get("permissions")):
        level = (auth.get("permissions") or {}).get("pull_requests")
        return _refuse(
            "EPERM",
            f"willows-bot is installed on {repo} but Pull requests is {level!r} "
            f"(need write). In GitHub App settings → Permissions → Repository → "
            f"Pull requests → Read and write, then re-install / accept the "
            f"permission request on each org.",
            envelope_id=matches[0], citation_id=result.get("citation_id"),
        )

    payload = {"title": title, "head": head, "base": base, "body": body or "",
               "draft": bool(draft)}
    call = api or _default_api
    resp = call("POST", f"{_API}/repos/{repo}/pulls", bearer=auth["token"], body=payload)
    if not resp.get("ok"):
        return {"ok": False, "opened": False, "error": "EPR",
                "reason": f"HTTP {resp.get('status')}: {str(resp.get('reason', ''))[:300]}",
                "envelope_id": matches[0], "citation_id": result.get("citation_id"),
                "auth_mode": "app"}
    pr = resp.get("body") or {}
    return {
        "ok": True, "opened": True, "repo": repo, "head": head, "base": base,
        "number": pr.get("number"), "url": pr.get("html_url"), "draft": bool(draft),
        "envelope_id": matches[0], "auth_mode": "app",
        "citation_id": result.get("citation_id"), "status": resp.get("status"),
    }
