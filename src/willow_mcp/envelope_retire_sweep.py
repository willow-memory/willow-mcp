"""willow_mcp/envelope_retire_sweep.py — the register retires what is spent.

Sealed decision 83faa340 (operator, 2026-09-21; SOIL record
``envelopes-retire-when-spent-2026-09-21``): an envelope whose bounds name a
branch is retired when that branch is merged and deleted on the remote; an
envelope with ``max_count`` is retired when FRANK shows the count consumed.
Retirement is a revoke with ``revoked_reason=branch_gone`` or ``=spent`` and a
FRANK ``envelope_revoked`` row — the grant and its uses stay auditable, it is
just no longer listed as in force. Standing envelopes (no branch bound, no
``max_count`` — the planting, the per-class dispatch envelopes,
``envelope.apply``) are untouched. Gap 4c7512c57a7e (registry honesty): the
same resolver :func:`envelopes.registry_path` / :mod:`envelope_authoring`
already use, so this sweep and the gate cannot disagree about which file is
"the" registry.

**The gate does not depend on this.** A retired envelope was already
unusable (branch gone / count spent); this fixes what the register SAYS, not
what it enforces. A sweep that never runs changes nothing about what the
gate honours.

Classification (one pass over ``active[]``, never touching ``proposals[]``):

* **branch-bound** — the verb's bounds carry a branch-name field
  (``branches`` for ``git.commit``/``git.push``, ``base_branches`` for
  ``pr.open``; read from the syscall table, never guessed) whose value is a
  single non-glob branch name. Retired when that branch is ABSENT on the
  remote AND a merged PR from it exists — both, so a branch someone deleted
  unmerged is left alone and reported (``kept_in_force``), not retired on a
  guess. A registry lookup that fails to reach GitHub reports the row
  ``unreachable``, never ``gone``.
* **counted** — ``max_count`` is set. Retired when FRANK's granted-citation
  count for that envelope id is ``>= max_count``
  (:meth:`governance_ledger.GovernanceLedger.citation_count`).
* **standing** — neither. Untouched; counted in ``kept_standing``.

A bounds row whose branch field is absent, empty, or a glob (``*``, ``?``,
``[``) is treated as standing too — a glob is not bound to any one branch's
lifecycle, and the sweep must never guess which branch would decide it.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Optional

from . import envelope_authoring as _authoring
from . import envelopes as _envelopes

#: verb -> bounds key that names the branch this envelope is scoped to.
#: FROZEN alongside the syscall table (``bundle/constitutional/syscall-table.json``
#: rows 2-4): a verb added here without reading its actual bounds signature
#: is exactly the "do not guess" the sealed spec forbids.
BRANCH_BOUND_KEY = {
    "git.commit": "branches",
    "git.push": "branches",
    "pr.open": "base_branches",
}

_GLOB_CHARS = re.compile(r"[*?\[]")

FRANK_EVENT_REVOKED = _authoring.FRANK_EVENT_REVOKED


def _single_branch(bounds: dict, verb: str) -> Optional[str]:
    """The one literal branch name this row is scoped to, or ``None`` when
    the verb carries no branch-bound key, the field is empty, holds more
    than one entry, or is a glob — any of which means "not tied to one
    branch's lifecycle" and the row is standing, not branch-bound."""
    key = BRANCH_BOUND_KEY.get(verb)
    if not key:
        return None
    value = bounds.get(key)
    if isinstance(value, str):
        candidates = [value]
    elif isinstance(value, (list, tuple)):
        candidates = list(value)
    else:
        return None
    candidates = [c for c in candidates if isinstance(c, str) and c.strip()]
    if len(candidates) != 1:
        return None
    branch = candidates[0].strip()
    if _GLOB_CHARS.search(branch):
        return None
    return branch


def classify(row: dict) -> dict:
    """``{class: "branch_bound"|"counted"|"standing", ...}`` for one active
    row. Pure — reads only the row, no network, no ledger. ``branch_bound``
    carries ``repo``/``branch``; ``counted`` carries ``max_count``.

    The branch-bound key per verb (``BRANCH_BOUND_KEY``) is read from the
    syscall table's frozen bounds signatures at development time (rows 2-4
    of ``bundle/constitutional/syscall-table.json`` — ``git.commit`` /
    ``git.push`` carry ``branches``, ``pr.open`` carries ``base_branches``)
    rather than the live file at call time: those three rows are the
    verb/bounds CONTRACT the rest of the broker already hardcodes (see
    ``pr_executor.VERB`` / ``push_executor``'s own call_args), not registry
    data that could legitimately differ sweep to sweep.

    ``max_count`` is checked first: it is a universal per-row metering
    field (set by the proposer independently of which bounds keys the
    verb declares — see ``envelope_authoring.propose``'s ``max_count``
    kwarg), so a row that happens to carry BOTH a single literal branch
    and a max_count is countable regardless of verb. A row with no
    max_count and no single-literal branch (bounds absent, empty, or a
    glob) is standing."""
    verb = row.get("verb") or ""
    bounds = row.get("bounds") or {}
    max_count = row.get("max_count")
    if isinstance(max_count, int) and max_count > 0:
        return {"class": "counted", "max_count": max_count}
    branch = _single_branch(bounds, verb)
    if branch:
        repo = bounds.get("repo") or ""
        return {"class": "branch_bound", "repo": repo, "branch": branch}
    return {"class": "standing"}


def _retire_row(row: dict, *, reason: str, actor: str, ledger) -> dict:
    """Mark ``row`` revoked in place — the same fields
    :func:`envelope_authoring.revoke` writes (``status``, ``revoked``,
    ``revoked_at``, ``revoked_by``, ``revoked_reason``) and the same FRANK
    ``envelope_revoked`` shape — WITHOUT that function's operator-keyring
    gate.

    :func:`envelope_authoring.revoke` is deliberately operator/CLI-only ("an
    agent must not be able to withdraw the grants that bound it") and
    refuses any caller whose ``verifier`` is not a keyring-registered human.
    The sealed spec (pair 83faa340) explicitly wants a STEWARD TICK or an
    unattended sweep to perform retirement with no human at the keyboard —
    exactly the case that function's gate exists to refuse. Per the
    assignment's fallback clause ("if the register's revoke path does not
    exist as a callable ... build the smallest one that writes the same
    fields"), this is that smallest callable: it duplicates
    ``revoke``'s field-writes and ledger shape and nothing else. It does
    NOT touch ``proposals[]`` or delete the row — same invariant as
    ``revoke``. The caller is responsible for the atomic registry write;
    this only mutates the in-memory row and appends the ledger event."""
    revoked_at = _authoring._now_iso()
    row["status"] = "revoked"
    row["revoked"] = True
    row["revoked_at"] = revoked_at
    row["revoked_by"] = actor
    row["revoked_reason"] = reason
    ledger_record_id = None
    ledger_error = None
    if ledger is not None:
        try:
            ledger_record_id = ledger.append(
                "willow",
                FRANK_EVENT_REVOKED,
                {
                    "envelope_id": row.get("id"),
                    "verb": row.get("verb"),
                    "grantee": row.get("grantee"),
                    "bounds_digest": _authoring._bounds_digest(row.get("bounds") or {}),
                    "ratified_via": row.get("ratified_via"),
                    "revoked_by": actor,
                    "revoked_at": revoked_at,
                    "reason": reason,
                },
            )
        except Exception as exc:  # noqa: BLE001 — ledger down != act undone
            ledger_error = str(exc)
    return {"revoked_at": revoked_at, "ledger_record_id": ledger_record_id,
            "ledger_error": ledger_error}


def _default_api(method: str, url: str, *, bearer: str, body: dict | None = None) -> dict[str, Any]:
    from . import github_app_credentials as gac

    return gac._api(method, url, bearer=bearer, body=body)


def _branch_state(api: Callable, *, repo: str, branch: str, token: str,
                   api_base: str = "https://api.github.com") -> dict:
    """``{reachable: bool, branch_gone: bool, merged: bool}``. A non-2xx/
    non-404 response (network error, auth failure, rate limit) is
    ``reachable: False`` — never interpreted as "the branch is gone"."""
    resp = api("GET", f"{api_base}/repos/{repo}/branches/{branch}", bearer=token)
    if resp.get("ok"):
        return {"reachable": True, "branch_gone": False, "merged": None}
    status = int(resp.get("status") or 0)
    if status != 404:
        return {"reachable": False, "branch_gone": None, "merged": None,
                "reason": f"HTTP {status}: {str(resp.get('reason', ''))[:200]}"}
    # Branch absent on the remote. Was there a merged PR from it? GitHub's
    # `head` filter matches by name regardless of whether the branch still
    # exists, so a deleted branch's PR history is still reachable this way.
    owner = repo.split("/", 1)[0]
    pulls = api(
        "GET",
        f"{api_base}/repos/{repo}/pulls?head={owner}:{branch}&state=closed&per_page=10",
        bearer=token,
    )
    if not pulls.get("ok"):
        return {"reachable": False, "branch_gone": True, "merged": None,
                "reason": f"branch absent but PR history unreachable: "
                          f"HTTP {pulls.get('status')}"}
    body = pulls.get("body") or []
    merged = any((row or {}).get("merged_at") for row in body if isinstance(row, dict))
    return {"reachable": True, "branch_gone": True, "merged": merged}


def sweep(
    *,
    actor: str = "willow-mcp-sweep",
    dry_run: bool = True,
    ledger: Optional[Any] = None,
    api: Optional[Callable] = None,
    registry: Optional[dict] = None,
) -> dict:
    """One pass over the active register. Three-state receipt (INVARIANTS
    §1): ``{state: populated|empty|unreachable, examined, retired: [...],
    kept_standing, kept_in_force: [...], unreachable: [...], dry_run}``.

    ``registry`` is injectable for tests (the loaded ``pre-approved.json``
    dict); default reads the live one through :func:`envelope_authoring`'s
    own loader, so the sweep and the gate resolve the same file (gap
    4c7512c57a7e). ``api`` matches ``github_app_credentials._api`` — a
    callable ``(method, url, *, bearer, body=None) -> dict``; default mints
    a real installation token per repo. ``ledger`` is a
    :class:`governance_ledger.GovernanceLedger`; without one, ``counted``
    rows cannot be verified and are reported ``unreachable``.

    A dry run performs every read (remote lookups, FRANK counts) and
    reports the SAME shape with ``retired`` meaning "would retire" — nothing
    is written to the registry and no FRANK row is appended.
    """
    receipt: dict = {"dry_run": bool(dry_run)}

    try:
        reg = registry if registry is not None else _authoring._load_registry()
    except Exception as exc:  # noqa: BLE001 — a registry we cannot read is unreachable, not empty
        receipt.update(state="unreachable", reason=f"registry_unreadable: {exc}",
                        examined=0, retired=[], kept_standing=0,
                        kept_in_force=[], unreachable=[])
        return receipt

    rows = [r for r in (reg.get("active") or [])
            if isinstance(r, dict) and r.get("id") and not _authoring._is_revoked(r)]

    call = api or _default_api
    retired: list[dict] = []
    kept_in_force: list[dict] = []
    unreachable: list[dict] = []
    kept_standing = 0

    # Cache one installation token per repo per sweep — several rows can
    # share a repo, and each mint is a network round trip.
    token_cache: dict[str, dict] = {}

    def _token_for(repo: str) -> dict:
        if repo not in token_cache:
            from . import github_app_credentials as gac

            token_cache[repo] = gac.mint_installation_token(repo)
        return token_cache[repo]

    for row in rows:
        envelope_id = row.get("id")
        verb = row.get("verb") or ""
        shape = classify(row)

        if shape["class"] == "standing":
            kept_standing += 1
            continue

        if shape["class"] == "branch_bound":
            repo, branch = shape["repo"], shape["branch"]
            if not repo or "/" not in repo:
                unreachable.append({"id": envelope_id, "verb": verb,
                                    "why": f"bounds carry no usable repo (got {repo!r})"})
                continue
            auth = _token_for(repo)
            if not auth.get("ok"):
                unreachable.append({"id": envelope_id, "verb": verb,
                                    "why": f"could not mint installation token for "
                                           f"{repo}: {auth.get('reason')}"})
                continue
            state = _branch_state(call, repo=repo, branch=branch, token=auth["token"])
            if not state.get("reachable"):
                unreachable.append({"id": envelope_id, "verb": verb,
                                    "why": state.get("reason") or "remote unreachable"})
                continue
            if state["branch_gone"] and state["merged"]:
                retired.append({"id": envelope_id, "verb": verb, "reason": "branch_gone",
                                "repo": repo, "branch": branch})
                if not dry_run:
                    _retire_row(row, reason="branch_gone", actor=actor, ledger=ledger)
            elif state["branch_gone"] and not state["merged"]:
                kept_in_force.append({"id": envelope_id, "verb": verb,
                                      "why": f"{branch} is absent on {repo} but no merged "
                                             "PR from it was found — left alone"})
            else:
                kept_in_force.append({"id": envelope_id, "verb": verb,
                                      "why": f"{branch} still exists on {repo}"})
            continue

        # counted
        max_count = shape["max_count"]
        if ledger is None:
            unreachable.append({"id": envelope_id, "verb": verb,
                                "why": "no governance ledger — FRANK count unavailable"})
            continue
        try:
            count = ledger.citation_count(envelope_id)
        except Exception as exc:  # noqa: BLE001
            unreachable.append({"id": envelope_id, "verb": verb,
                                "why": f"FRANK count unreachable: {exc}"})
            continue
        if count >= max_count:
            retired.append({"id": envelope_id, "verb": verb, "reason": "spent",
                            "count": count, "max_count": max_count})
            if not dry_run:
                _retire_row(row, reason="spent", actor=actor, ledger=ledger)
        else:
            kept_in_force.append({"id": envelope_id, "verb": verb,
                                  "why": f"FRANK shows {count}/{max_count} granted uses"})

    if not dry_run and retired:
        # One atomic registry write for the whole sweep tick — the rows in
        # `retired` were mutated in place above (they are the same dict
        # objects `reg["active"]` holds); each still got its own FRANK
        # `envelope_revoked` row as it was decided. Never touches
        # `proposals[]` or deletes a row (`_atomic_write` writes `reg`
        # whole, unchanged apart from the mutated `active` rows).
        _authoring._atomic_write(_envelopes.registry_path(), reg)

    if not rows:
        state = "empty"
    elif retired or kept_in_force or unreachable or kept_standing:
        state = "populated"
    else:
        state = "empty"  # pragma: no cover — unreachable given the branches above

    receipt.update(
        state=state,
        examined=len(rows),
        retired=retired,
        kept_standing=kept_standing,
        kept_in_force=kept_in_force,
        unreachable=unreachable,
    )
    return receipt
