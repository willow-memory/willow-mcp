"""willow_mcp/pr_update_executor.py — edit a PR title/body/labels the broker
opened.

Sibling of ``pr_executor.py``'s ``pr.open`` (verb 4) for verb 16, ``pr.update``,
sealed ``783bab4e`` (operator, 2026-09-16; Nestor pair
``783bab4e-90e2-4735-b83b-a52108d411c3``) — see
``src/willow_mcp/bundle/constitutional/syscall-table.json`` row 16. Gap
``8d1bcb2b7c02``: no broker verb could edit a PR title; a ``pr-title.yml``
workflow failure after a commit retype was a click the seat could not make —
the fleet could open a PR but never touch it again.

Deliberately narrow. NOT merge, approve, close, request-review, or assignee —
those are verb 5 (``pr.merge``) or unexpressible (ENOSYS). A near-miss
stretched onto a neighboring verb is a fault (EAMBIG), never a grant, per the
table's own invariant.

What this module does, in order, and nothing else:

1. **Validate the ask.** ``repo`` is ``org/name``; ``number`` is a positive
   int; at least one of ``title``/``body``/``labels`` is set (``EINVAL``).
   Every requested label must live under the bot's own ``willow-bot/``
   prefix (``ELABEL``) — checked here, before the registry, because it is a
   shape fault in the request itself, not a network-dependent one.
2. **Check and cite, before any network.** The call args — ``{repo,
   fields}``, the verb's bounds signature — go through
   :meth:`EnvelopeAuthority.authorize_and_cite`. ``fields`` names every
   field this call would change; a field the envelope's bounds do not cover
   is ``EAMBIG`` with the field diff, the table's near-miss contract.
3. **File the ask on a miss.** Same as ``pr.open`` and ``unit.reload``: the
   operator sees "X wants to update PR Y" while the work is still waiting.
4. **Mint the App token** (idempotent, no grant consumed) and
   ``GET /repos/{repo}/pulls/{number}``: the PR must exist and be open
   (``ENOENT`` / ``ECLOSED``); its author must be the App — ``user.type ==
   "Bot"`` and ``user.login`` matching the App's own slug (BOT-INVENTORY:
   match by type first) — or the call refuses ``EAUTHOR`` and files the ask.
   There is no ``any_author`` escape hatch: row 16's bounds signature is
   exactly ``{repo, fields}``, and widening the author check is a table
   edit (verb 12), not this module's call to make.
5. **Body shape preflight.** If ``body`` is set, ``pr_template.preflight``
   on the NEW body, ``EBODY`` before citation — the same check ``pr.open``
   already enforces.
6. **Atomic cite**, then ``PATCH`` title/body and add/remove labels via the
   issues labels endpoints (add/remove computed only within the bot's own
   label namespace — a label outside it that the PR already carries is
   never touched, added or removed). Returns a receipt naming what changed.
"""
from __future__ import annotations

import hashlib
from typing import Any, Callable, Optional
from urllib.parse import quote

VERB = "pr.update"

_ASKABLE = frozenset({"ENOENT", "EAMBIG", "EEXPIRED", "EDQUOT", "ENOGRANTS"})

_API = "https://api.github.com"

#: Only labels under this prefix may be added or removed by ``pr.update`` —
#: the bot's own namespace. A label outside it, whether asked for or already
#: sitting on the PR, is never touched: this verb edits what the bot owns,
#: never a human's or another tool's labeling scheme.
_OWNED_LABEL_PREFIX = "willow-bot/"


def _refuse(errno: str, reason: str, **extra) -> dict:
    return {"ok": False, "error": errno, "reason": reason, "updated": False, **extra}


def _sha256(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _file_ask(app_id: str, *, repo: str, number: int, errno: str, reason: str,
              fields, task_id: str, store=None) -> dict:
    """Same shape as ``pr_executor._file_ask`` / ``unit_reload_executor.
    _file_ask``: the row lands on the ``gates`` surface under
    ``pr.<repo>#<number>`` — the ``#`` (not ``:``) tells ``gates_panel``
    apart from a ``pr.open`` ask on the same repo, since this names a
    specific PR rather than a base branch."""
    from . import gate_request

    detail = f"{errno}: {reason}"
    if fields:
        detail += f" (fields: {', '.join(str(f) for f in fields)})"
    summary = (
        f"{app_id or 'an agent'} asked to update pull request {repo}#{number} "
        f"and was refused: {detail}. Ratify a pr.update envelope with these "
        f"bounds (repo={repo!r}, fields=[...]) and the agent can ask again."
    )
    return gate_request.open_request(
        app_id or "",
        f"pr.{repo}#{number}",
        task_id=task_id,
        reason=summary,
        store=store,
    )


def _default_api(method: str, url: str, *, bearer: str, body: dict | None = None) -> dict[str, Any]:
    from . import github_app_credentials as gac

    return gac._api(method, url, bearer=bearer, body=body)


def execute_pr_update(
    app_id: str,
    *,
    repo: str,
    number: int,
    title: str = "",
    body: str = "",
    labels: Optional[list[str]] = None,
    envelope_id: str = "",
    project: str,
    session: str = "",
    task_id: str = "",
    ledger=None,
    store=None,
    api: Optional[Callable] = None,
) -> dict:
    """Edit the title, body, and/or bot-owned labels of pull request
    ``repo``#``number`` — or refuse, cite the refusal, and file the ask.

    ``ledger`` is a :class:`GovernanceLedger`; the MCP tool builds it from
    the live Postgres, tests pass a fake. ``api`` replaces the HTTPS call in
    tests. Returns a dict with ``ok``/``updated``; a refusal carries
    ``error`` (the errno) and ``reason``.
    """
    from .envelopes import EnvelopeAuthority, governing_envelope_ids

    repo = (repo or "").strip().strip("/")
    title = (title or "").strip()
    body = body or ""

    try:
        number_int = int(number)
    except (TypeError, ValueError):
        return _refuse("EINVAL", "a pull request number must be an integer")
    if repo.count("/") != 1 or number_int <= 0:
        return _refuse("EINVAL", "a pull request update names a repo (org/name) "
                                 "and a positive PR number")

    fields: list[str] = []
    if title:
        fields.append("title")
    if body:
        fields.append("body")
    if labels is not None:
        fields.append("labels")
    if not fields:
        return _refuse("EINVAL", "a pull request update must set at least one "
                                 "of title, body, or labels")

    if labels is not None:
        foreign = [name for name in labels if not str(name).startswith(_OWNED_LABEL_PREFIX)]
        if foreign:
            return _refuse(
                "ELABEL",
                f"label(s) {foreign!r} are not under the bot's own "
                f"{_OWNED_LABEL_PREFIX!r} prefix — pr.update may only add or "
                f"remove labels it owns",
                labels=foreign,
            )

    call_args = {"repo": repo, "fields": sorted(fields)}

    try:
        matches = governing_envelope_ids(VERB, app_id)
    except (OSError, ValueError) as exc:
        return _refuse("EAMBIG", f"envelope registry unreadable: {exc}")
    if envelope_id:
        if envelope_id not in matches:
            result = _refuse("ENOENT",
                             f"envelope {envelope_id!r} does not govern {VERB} for "
                             f"{app_id!r}", envelope_ids=matches)
            result["ask"] = _file_ask(app_id, repo=repo, number=number_int,
                                      errno="ENOENT", reason=result["reason"],
                                      fields=None, task_id=task_id, store=store)
            return result
        matches = [envelope_id]
    if not matches:
        result = _refuse("ENOENT", f"no active {VERB} envelope governs {app_id!r}")
        result["ask"] = _file_ask(app_id, repo=repo, number=number_int,
                                  errno="ENOENT", reason=result["reason"],
                                  fields=None, task_id=task_id, store=store)
        return result
    if len(matches) > 1:
        return _refuse("EAMBIG", f"multiple active {VERB} envelopes govern {app_id!r} — "
                                 "pass envelope_id to name which one to cite",
                       envelope_ids=matches)
    if ledger is None:
        return _refuse("EAMBIG", "no governance ledger: a pull request that cannot be "
                                 "cited is not updated")

    authority = EnvelopeAuthority(ledger)

    # Cheap bounds/expiry/quota check first (no citation, no network) — same
    # shape as execute_pr_open: we still run authorize_and_cite on a miss so
    # the audit citation lands, but neither the credential mint nor the
    # GitHub reads below have cost anything to get there.
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
            out["ask"] = _file_ask(app_id, repo=repo, number=number_int,
                                   errno=errno, reason=out["reason"],
                                   fields=result.get("fields"), task_id=task_id,
                                   store=store)
        return out

    # Credential: the App, or nothing — same posture as pr.open (module
    # docstring on pr_executor.py explains why there is no host-token
    # fallback). The mint is idempotent and consumes no grant.
    from . import github_app_credentials as gac

    auth = gac.mint_installation_token(repo)
    if not (auth.get("ok") and auth.get("mode") == "app"):
        cite = authority.authorize_and_cite(
            matches[0], actor=app_id, verb=VERB, call_args=call_args,
            project=project, session=session,
        )
        return _refuse(
            "EAUTH",
            auth.get("reason") or "could not mint a willows-bot installation token",
            envelope_id=matches[0], citation_id=cite.get("citation_id"),
        )
    # Editing a PR needs the same `pull_requests: write` that opening one does.
    # Check it on the minted token before any GitHub read, so a missing grant
    # is a named refusal (and one human_required item — gap 4464a63db1a9)
    # rather than a 403 on the PATCH reported as a generic EPR.
    from .pr_executor import pulls_perm_allows_open

    if not pulls_perm_allows_open(auth.get("permissions")):
        level = (auth.get("permissions") or {}).get("pull_requests")
        out = _refuse(
            "EPERM",
            f"willows-bot is installed on {repo} but Pull requests is {level!r} "
            f"(need write). In GitHub App settings → Permissions → Repository → "
            f"Pull requests → Read and write, then re-install / accept the "
            f"permission request on each org.",
            envelope_id=matches[0],
        )
        from . import github_app_permissions as gap_

        filed = gap_.file_permission_ask(
            store, app_id=app_id, verb="pr_update_execute", repo=repo,
            permission="pull_requests", level="write", current=level,
        )
        out["human_required_state"] = filed.get("state")
        if filed.get("human_required_id"):
            out["human_required_id"] = filed["human_required_id"]
        return out

    call = api or _default_api

    pr_resp = call("GET", f"{_API}/repos/{repo}/pulls/{number_int}", bearer=auth["token"])
    if not pr_resp.get("ok"):
        status = pr_resp.get("status")
        if status == 404:
            return _refuse("ENOENT", f"pull request {repo}#{number_int} does not exist",
                           envelope_id=matches[0])
        return _refuse("EPR", f"HTTP {status}: {str(pr_resp.get('reason', ''))[:300]}",
                       envelope_id=matches[0])
    pr = pr_resp.get("body") or {}
    if pr.get("state") != "open":
        return _refuse(
            "ECLOSED",
            f"pull request {repo}#{number_int} is {pr.get('state')!r}, not open",
            envelope_id=matches[0],
        )

    # Author identity: the App, or refuse. BOT-INVENTORY: match by
    # user.type == "Bot" first, then login — a human who happens to share
    # the bot's display name is not the bot.
    author = pr.get("user") or {}
    expected_login = gac.bot_login(auth)
    if author.get("type") != "Bot" or not expected_login or author.get("login") != expected_login:
        result = _refuse(
            "EAUTHOR",
            f"pull request {repo}#{number_int} was not authored by the app "
            f"(login={author.get('login')!r}, type={author.get('type')!r}) — "
            f"pr.update may only touch pull requests the broker opened",
            envelope_id=matches[0],
        )
        result["ask"] = _file_ask(app_id, repo=repo, number=number_int,
                                  errno="EAUTHOR", reason=result["reason"],
                                  fields=None, task_id=task_id, store=store)
        return result

    # PR template shape preflight (gap 378c2e57c3d0), same as pr.open: a new
    # body missing a required section refuses EBODY before citation.
    template_check: dict = {"state": "not_enforced"}
    if body:
        from . import pr_template as _tpl

        template_check = _tpl.preflight(call, repo=repo, body=body,
                                        bearer=auth["token"], api_base=_API)
        if not template_check.get("ok"):
            return _refuse(
                template_check.get("errno", "EBODY"),
                template_check.get("reason", "PR body does not satisfy the repo template"),
                envelope_id=matches[0], template=template_check,
            )

    existing_labels = sorted(
        name for lbl in (pr.get("labels") or [])
        if isinstance(lbl, dict) and (name := lbl.get("name"))
    )
    add_labels: list[str] = []
    remove_labels: list[str] = []
    if labels is not None:
        existing_owned = [name for name in existing_labels if name.startswith(_OWNED_LABEL_PREFIX)]
        wanted = list(dict.fromkeys(labels))  # de-dupe, keep order
        add_labels = [name for name in wanted if name not in existing_owned]
        remove_labels = [name for name in existing_owned if name not in wanted]

    # All preflights passed. Atomic cite: bounds may have changed since the
    # cheap check, so re-check and cite in one indivisible step.
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
            out["ask"] = _file_ask(app_id, repo=repo, number=number_int,
                                   errno=errno, reason=out["reason"],
                                   fields=result.get("fields"), task_id=task_id,
                                   store=store)
        return out

    before = {
        "title": pr.get("title"),
        "body_sha256": _sha256(pr.get("body") or ""),
        "labels": existing_labels,
    }

    patch_body: dict = {}
    if title:
        patch_body["title"] = title
    if body:
        patch_body["body"] = body
    if patch_body:
        patch_resp = call("PATCH", f"{_API}/repos/{repo}/pulls/{number_int}",
                          bearer=auth["token"], body=patch_body)
        if not patch_resp.get("ok"):
            return {"ok": False, "updated": False, "error": "EPR",
                    "reason": f"HTTP {patch_resp.get('status')}: "
                              f"{str(patch_resp.get('reason', ''))[:300]}",
                    "envelope_id": matches[0], "citation_id": result.get("citation_id"),
                    "auth_mode": "app"}

    if add_labels:
        add_resp = call("POST", f"{_API}/repos/{repo}/issues/{number_int}/labels",
                        bearer=auth["token"], body={"labels": add_labels})
        if not add_resp.get("ok"):
            return {"ok": False, "updated": False, "error": "EPR",
                    "reason": f"HTTP {add_resp.get('status')}: "
                              f"{str(add_resp.get('reason', ''))[:300]}",
                    "envelope_id": matches[0], "citation_id": result.get("citation_id"),
                    "auth_mode": "app"}
    for name in remove_labels:
        rem_resp = call(
            "DELETE",
            f"{_API}/repos/{repo}/issues/{number_int}/labels/{quote(name, safe='')}",
            bearer=auth["token"],
        )
        if not rem_resp.get("ok") and rem_resp.get("status") != 404:
            return {"ok": False, "updated": False, "error": "EPR",
                    "reason": f"HTTP {rem_resp.get('status')}: "
                              f"{str(rem_resp.get('reason', ''))[:300]}",
                    "envelope_id": matches[0], "citation_id": result.get("citation_id"),
                    "auth_mode": "app"}

    after_labels = existing_labels
    if labels is not None:
        after_labels = sorted((set(existing_labels) - set(remove_labels)) | set(add_labels))

    receipt: dict = {
        "ok": True, "updated": True, "repo": repo, "number": number_int,
        "fields_changed": sorted(fields),
        "before": before,
        "after": {
            "title": title or before["title"],
            "body_sha256": _sha256(body) if body else before["body_sha256"],
            "labels": after_labels,
        },
        "envelope_id": matches[0], "citation_id": result.get("citation_id"),
        "auth_mode": "app", "template": template_check,
    }

    try:
        rec = ledger.append(project, "pr_update", {
            "actor": app_id, "repo": repo, "number": number_int,
            "fields_changed": sorted(fields), "session": session,
            "citation_id": result.get("citation_id"),
        })
        receipt["receipt_id"] = rec
    except Exception as exc:  # noqa: BLE001 — the update happened; the receipt failing is reported, not hidden
        receipt["receipt_error"] = f"{type(exc).__name__}: {exc}"

    return receipt
