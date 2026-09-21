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

import os
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
    already refusing.

    The row lands on the ``gates`` surface (``kind=consent`` under
    ``pr.<repo>:<base>``) rather than the review queue: same migration as
    ``push_executor._file_ask`` (gap ``5ecb87cfdf56``, slice 2b PR 1). The
    gate names ``base`` because the ``pr.open`` envelope's bounds are
    ``base_branches`` — the ratified grant admits any head into that base,
    so the head is task-specific rather than envelope-specific and belongs
    in the ask summary alongside the reason.
    """
    from . import gate_request

    detail = f"{errno}: {reason}"
    if fields:
        detail += f" (fields: {', '.join(str(f) for f in fields)})"
    summary = (
        f"{app_id or 'an agent'} asked to open a pull request on {repo} "
        f"from {head!r} into {base!r} and was refused: {detail}. Ratify a "
        f"pr.open envelope with these bounds (repo={repo!r}, "
        f"base_branches=[{base!r}]) and the agent can ask again."
    )
    return gate_request.open_request(
        app_id or "",
        f"pr.{repo}:{base}",
        task_id=task_id,
        reason=summary,
        store=store,
    )


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
    enforce_template: bool = True,
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

    authority = EnvelopeAuthority(ledger)

    # Cheap bounds/expiry/quota check first (no citation, no network). If it
    # fails we still run `authorize_and_cite` to leave the audit citation the
    # existing tests read — but neither the credential mint nor the remote-
    # base preflight has cost us anything to get there.
    pre_check = authority.check(matches[0], actor=app_id, verb=VERB, call_args=call_args)
    if not pre_check.get("ok"):
        result = authority.authorize_and_cite(
            matches[0], actor=app_id, verb=VERB, call_args=call_args,
            project=project, session=session,
        )
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
    # is no host-token fallback on this verb. The install-token mint is
    # idempotent and consumes no grant; it runs after the cheap bounds check
    # and BEFORE the atomic cite — an EAUTH/EPERM or a stale-base preflight
    # must not spend the operator's one-use pr.open authority
    # (gap ``bc9945dd47da``).
    from . import github_app_credentials as gac

    auth = gac.mint_installation_token(repo)
    if not (auth.get("ok") and auth.get("mode") == "app"):
        # Existing tests want EAUTH after the audit citation (they assert
        # the granted outcome landed). Cite first, then refuse.
        cite = authority.authorize_and_cite(
            matches[0], actor=app_id, verb=VERB, call_args=call_args,
            project=project, session=session,
        )
        return _refuse(
            "EAUTH",
            auth.get("reason") or "could not mint a willows-bot installation token",
            envelope_id=matches[0], citation_id=cite.get("citation_id"),
        )
    if not pulls_perm_allows_open(auth.get("permissions")):
        level = (auth.get("permissions") or {}).get("pull_requests")
        return _refuse(
            "EPERM",
            f"willows-bot is installed on {repo} but Pull requests is {level!r} "
            f"(need write). In GitHub App settings → Permissions → Repository → "
            f"Pull requests → Read and write, then re-install / accept the "
            f"permission request on each org.",
            envelope_id=matches[0],
        )

    # Remote-base ancestry preflight (gap bc9945dd47da). PR #530 was opened
    # from stale local `master` and the operator was told by GitHub to click
    # Update branch after the envelope had been consumed. This preflight
    # refuses ESTALE (or EFETCH) BEFORE citation, so the one-use grant is
    # not spent on a request that would fail at review.
    from . import remote_base as _rb

    call = api or _default_api
    preflight = _rb.preflight_via_compare(
        call, repo=repo, head=head, base=base, bearer=auth["token"], api_base=_API,
    )
    if not preflight.get("ok"):
        return _refuse(
            preflight.get("errno", "ESTALE"),
            preflight.get("reason", "remote-base preflight refused"),
            envelope_id=matches[0], preflight=preflight,
        )

    # PR template shape preflight (gap 378c2e57c3d0). The API path does not
    # apply the repo's ``pull_request_template.md`` to the body field the way
    # the web UI does, so a bot-opened PR ships an empty body and the first
    # thing the operator sees is "please fill this in". Enforce the template
    # BEFORE citation: a body missing required sections refuses ``EBODY``
    # and the one-use grant is not spent on a shape the reviewer will
    # bounce anyway. Absent template = no shape to enforce; proceed.
    from . import pr_template as _tpl

    template_check: dict = {"state": "not_enforced"}
    if enforce_template:
        template_check = _tpl.preflight(call, repo=repo, body=body or "",
                                        bearer=auth["token"], api_base=_API)
        if not template_check.get("ok"):
            return _refuse(
                template_check.get("errno", "EBODY"),
                template_check.get("reason", "PR body does not satisfy the repo template"),
                envelope_id=matches[0], preflight=preflight, template=template_check,
            )

    # All preflights passed. Atomic cite: bounds may have changed since the
    # cheap check (a racing caller could exhaust the max_count between now
    # and here), so re-check and cite in one indivisible step.
    result = authority.authorize_and_cite(
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

    payload = {"title": title, "head": head, "base": base, "body": body or "",
               "draft": bool(draft)}
    resp = call("POST", f"{_API}/repos/{repo}/pulls", bearer=auth["token"], body=payload)
    if not resp.get("ok"):
        return {"ok": False, "opened": False, "error": "EPR",
                "reason": f"HTTP {resp.get('status')}: {str(resp.get('reason', ''))[:300]}",
                "envelope_id": matches[0], "citation_id": result.get("citation_id"),
                "auth_mode": "app"}
    pr = resp.get("body") or {}
    number = pr.get("number")
    # Who asked, on the record the steward reads (sealed pair 11ccb0f7,
    # part 1): the citation above already carries ``actor`` + ``session``
    # for the ledger; the receipt says the same under ``opened_by`` and the
    # watch row under ``$WILLOW_HOME/willow-bot/pr_watch.json`` is what
    # lets ``steward_ci`` post a red on this PR to that seat's channel
    # without willow-mcp in-process. Never fatal: the PR is open.
    from . import pr_watch as _watch

    watch: dict = {"state": "empty", "reason": "no PR number in GitHub's response"}
    if number:
        watch = _watch.record(repo=repo, number=number, app_id=app_id,
                              session_id=session, head=head)
    return {
        "ok": True, "opened": True, "repo": repo, "head": head, "base": base,
        "number": number, "url": pr.get("html_url"), "draft": bool(draft),
        "envelope_id": matches[0], "auth_mode": "app",
        "citation_id": result.get("citation_id"), "status": resp.get("status"),
        "operator": _put_in_front_of_the_operator(call, repo, number, auth["token"]),
        "opened_by": _watch.opened_by(app_id, session),
        "watch": watch,
        "preflight": preflight, "template": template_check,
    }


OPERATOR_LOGIN_ENV = "WILLOW_OPERATOR_GITHUB_LOGIN"


def operator_login() -> str:
    return (os.environ.get(OPERATOR_LOGIN_ENV) or "").strip()


def _put_in_front_of_the_operator(call: Callable, repo: str, number, token: str) -> dict:
    """A PR the bot authored is on nobody's list: github.com/pulls and the
    mobile app show what you created, are assigned, are mentioned in, or
    were asked to review — and the bot created it. Request the operator's
    review and assign it to them, so it lands in "Review requests" and
    "Assigned" with the notification the "Created" path never gave.

    Never fatal: the PR is open either way, and the receipt says which
    half landed. Honest absence when no login is configured — the operator
    is named in the seat env, never in this file."""
    login = operator_login()
    if not login:
        return {"login": None, "review_requested": False, "assigned": False,
                "detail": f"none configured ({OPERATOR_LOGIN_ENV} unset)"}
    if not number:
        return {"login": login, "review_requested": False, "assigned": False,
                "detail": "no PR number in GitHub's response"}
    out: dict = {"login": login}
    review = call("POST", f"{_API}/repos/{repo}/pulls/{number}/requested_reviewers",
                  bearer=token, body={"reviewers": [login]})
    out["review_requested"] = bool(review.get("ok"))
    if not review.get("ok"):
        out["review_error"] = f"HTTP {review.get('status')}: {str(review.get('reason', ''))[:200]}"
    assign = call("POST", f"{_API}/repos/{repo}/issues/{number}/assignees",
                  bearer=token, body={"assignees": [login]})
    out["assigned"] = bool(assign.get("ok"))
    if not assign.get("ok"):
        out["assign_error"] = f"HTTP {assign.get('status')}: {str(assign.get('reason', ''))[:200]}"
    return out
