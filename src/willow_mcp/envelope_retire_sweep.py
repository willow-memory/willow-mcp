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

Classification (one pass over a snapshot of ``active[]``, never touching
``proposals[]``):

* **branch-bound** — the verb's bounds carry a branch-NAME field whose value
  is a single non-glob branch (``branches`` for ``git.commit``/``git.push``
  only — ``pr.open``'s only branch-shaped bound, ``base_branches``, names the
  MERGE TARGET, never the feature branch the envelope was cut for, so it
  carries no branch this sweep could ever retire on; rework of Loki's MEDIUM
  finding on BAA43543/9494D3AF — treating it as branch-bound made every live
  pr.open row "bound to master", probed every tick and never retirable).
  Retired when that branch is ABSENT on the remote AND a merged PR from it
  exists — both, so a branch someone deleted unmerged is left alone and
  reported (``kept_in_force``), not retired on a guess. A registry lookup
  that fails to reach GitHub reports the row ``unreachable``, never ``gone``.
* **counted** — ``max_count`` is set AND ``use_count_source`` is ``"frank"``
  (the only source this sweep knows how to verify; any other value is
  reported ``unreachable`` rather than trusted). Retired when FRANK's
  granted-citation count for that envelope id is ``>= max_count``
  (:meth:`governance_ledger.GovernanceLedger.citation_count`).
* **standing** — neither. Untouched; counted in ``kept_standing``.

A bounds row whose branch field is absent, empty, or a glob (``*``, ``?``,
``[``) is treated as standing too — a glob is not bound to any one branch's
lifecycle, and the sweep must never guess which branch would decide it.

**Concurrency (rework of Loki's HIGH finding).** The first cut classified
against one registry snapshot, made every network/FRANK call, then wrote the
WHOLE stale snapshot back at the end — an operator revoke or a proposal
written anywhere in that window was silently undone by the final write
(Loki's probe, task Y3TVZXUX). Retirement now happens per-row, under an
exclusive file lock (mirroring the "hold a lock, re-read under it" shape
:meth:`governance_ledger.GovernanceLedger.append_citation` already uses for
FRANK's own metering): classification runs off a snapshot (cheap, read-only,
no lock needed — it only decides WHICH ids to examine), but the instant
before a row is actually retired the lock is taken, the registry is
RE-READ fresh, and the write applies to that fresh copy — so any proposal or
operator action that landed mid-sweep survives untouched. If the row is no
longer active (already revoked by someone else, or gone) under the fresh
read, nothing is written and the row is reported, never silently
re-clobbered.

**Ordering (rework of Loki's LOW finding).** The registry write — the
durable, gate-visible state — happens BEFORE the FRANK ledger append, not
after: a crash in between leaves an under-logged retirement (row says
revoked, FRANK silent, still auditable from the row itself) rather than an
over-logged one (FRANK says revoked, the row is still active — the version
that actively misleads a reader).

**Bounding against the steward's 90s call budget (rework of Loki's MEDIUM
finding).** A live register with hundreds of branch-bound/counted rows can
need dozens of GitHub round trips and hundreds of FRANK counts; the client
that calls this tool (``willow_bot.steward.mcp_client``) times the whole
call out at 90s. ``time_budget_s`` (default 60s — well inside that 90s, and
inside it by design rather than by luck) stops examining FURTHER rows once
elapsed wall-clock crosses it; whatever was already decided this call is
still applied, and the receipt says ``truncated: true`` plus how many of
``examined`` rows were actually looked at vs. how many are left for next
tick. Nothing partially in-flight is left dangling: the loop only stops
BETWEEN rows, never mid-row.
"""
from __future__ import annotations

import re
import time
from contextlib import contextmanager
from typing import Any, Callable, Iterator, Optional

from . import envelope_authoring as _authoring
from . import envelopes as _envelopes

#: verb -> bounds key that names the branch this envelope is scoped to.
#: FROZEN alongside the syscall table (``bundle/constitutional/syscall-table.json``
#: row 2-3): a verb added here without reading its actual bounds signature is
#: exactly the "do not guess" the sealed spec forbids. ``pr.open`` (row 4) is
#: deliberately ABSENT: its only bound, ``base_branches``, names the merge
#: target, not the feature branch — see the module docstring.
BRANCH_BOUND_KEY = {
    "git.commit": "branches",
    "git.push": "branches",
}

_GLOB_CHARS = re.compile(r"[*?\[]")

FRANK_EVENT_REVOKED = _authoring.FRANK_EVENT_REVOKED

#: The only ``use_count_source`` this sweep trusts FRANK to verify. A row
#: proposed with any other source is reported ``unreachable`` rather than
#: silently counted against a ledger that was never the metering authority
#: for it (rework of Loki's LOW finding).
_TRUSTED_COUNT_SOURCE = "frank"

#: Wall-clock ceiling for one sweep call, well inside the steward
#: mcp_client's 90s per-call timeout (rework of Loki's MEDIUM finding).
DEFAULT_TIME_BUDGET_S = 60.0

#: The actor name written to ``revoked_by`` / the FRANK row for an unattended
#: tick. Deliberately NOT the caller's ``app_id`` (the first cut used
#: whatever app_id called the tool, usually "willow" — the same identity a
#: human orchestrator session carries — misattributing an automated act to
#: that seat; rework of Loki's LOW finding: "name the tick").
DEFAULT_ACTOR = "willow-mcp-envelope-retire-sweep"


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

    ``max_count`` is checked first: it is a universal per-row metering
    field (set by the proposer independently of which bounds keys the
    verb declares — see ``envelope_authoring.propose``'s ``max_count``
    kwarg), so a row that happens to carry BOTH a single literal branch
    and a max_count is countable regardless of verb. A ``max_count`` row
    whose ``use_count_source`` is not ``"frank"`` is NOT counted here —
    :func:`sweep` reports it ``unreachable`` rather than trusting a source
    this module cannot verify. A row with no max_count and no
    single-literal branch (bounds absent, empty, or a glob) is standing."""
    verb = row.get("verb") or ""
    bounds = row.get("bounds") or {}
    max_count = row.get("max_count")
    if isinstance(max_count, int) and max_count > 0:
        return {"class": "counted", "max_count": max_count,
                "use_count_source": row.get("use_count_source")}
    branch = _single_branch(bounds, verb)
    if branch:
        repo = bounds.get("repo") or ""
        return {"class": "branch_bound", "repo": repo, "branch": branch}
    return {"class": "standing"}


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


@contextmanager
def _default_lock(path) -> Iterator[None]:
    """Exclusive advisory lock on a sibling ``<registry>.lock`` file for the
    duration of one retirement's re-read-and-write. Same primitive
    :mod:`instance_lock` uses (``flock(LOCK_EX)``, kernel-released on
    process death, no stale-lock cleanup) — blocking here (no ``LOCK_NB``)
    is correct: a sweep retirement and an operator ratify/revoke/reject
    should serialize, not race and have one refuse.

    Soft-fails to no lock (same tolerance :mod:`instance_lock` extends for
    non-POSIX platforms) rather than blocking retirement entirely on a
    platform with no ``fcntl`` — the re-read-fresh-under-whatever-lock-we-
    have still narrows the clobber window to near zero even without OS
    locking; only true cross-process mutual exclusion is lost."""
    try:
        import fcntl
    except ImportError:  # pragma: no cover — POSIX only
        yield
        return
    lock_path = path.with_name(path.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:  # pragma: no cover
            pass
        handle.close()


def _retire_locked(
    envelope_id: str,
    *,
    reason: str,
    actor: str,
    ledger,
    reload_registry: Callable[[], dict],
    write_registry: Callable[[dict], None],
    lock: Callable[..., Any],
    registry_path,
) -> dict:
    """Retire ONE envelope under the lock: re-read fresh, verify the row is
    still there and still active, write it revoked, THEN append FRANK.
    Never touches any other row; never writes if the row is gone or was
    already revoked by someone else in the meantime — that is reported, not
    silently skipped-as-success (rework of Loki's HIGH finding: the sweep
    no longer decides off, or writes back, a stale whole-registry copy)."""
    with lock(registry_path):
        reg = reload_registry()
        rows = reg.get("active") or []
        match = next((r for r in rows if r.get("id") == envelope_id), None)
        if match is None:
            return {"ok": False, "why": "no longer in active[] as of the fresh re-read "
                                        "(removed or renamed since classification)"}
        if _authoring._is_revoked(match):
            return {"ok": False, "why": f"already revoked as of the fresh re-read "
                                        f"(at {match.get('revoked_at') or 'unknown time'}) "
                                        "— not re-retired"}
        revoked_at = _authoring._now_iso()
        match["status"] = "revoked"
        match["revoked"] = True
        match["revoked_at"] = revoked_at
        match["revoked_by"] = actor
        match["revoked_reason"] = reason
        # Durable state first (rework of Loki's LOW ordering finding): the
        # registry is what the gate and every reader trust. Written before
        # the FRANK append, so a crash between leaves an under-logged
        # retirement, never an over-logged one.
        write_registry(reg)
        ledger_record_id = None
        ledger_error = None
        if ledger is not None:
            try:
                ledger_record_id = ledger.append(
                    "willow",
                    FRANK_EVENT_REVOKED,
                    {
                        "envelope_id": envelope_id,
                        "verb": match.get("verb"),
                        "grantee": match.get("grantee"),
                        "bounds_digest": _authoring._bounds_digest(match.get("bounds") or {}),
                        "ratified_via": match.get("ratified_via"),
                        "revoked_by": actor,
                        "revoked_at": revoked_at,
                        "reason": reason,
                    },
                )
            except Exception as exc:  # noqa: BLE001 — ledger down != act undone
                ledger_error = str(exc)
        return {"ok": True, "revoked_at": revoked_at,
                "ledger_record_id": ledger_record_id, "ledger_error": ledger_error}


def sweep(
    *,
    actor: str = DEFAULT_ACTOR,
    dry_run: bool = True,
    ledger: Optional[Any] = None,
    api: Optional[Callable] = None,
    registry: Optional[dict] = None,
    max_rows: int = 0,
    time_budget_s: float = DEFAULT_TIME_BUDGET_S,
    reload_registry: Optional[Callable[[], dict]] = None,
    write_registry: Optional[Callable[[dict], None]] = None,
    lock: Optional[Callable[..., Any]] = None,
) -> dict:
    """One pass over a SNAPSHOT of the active register, retiring rows
    per-row under a fresh re-read (see module docstring). Three-state
    receipt (INVARIANTS §1): ``{state: populated|empty|unreachable,
    examined, retired: [...], kept_standing, kept_in_force: [...],
    unreachable: [...], dry_run, truncated}``.

    ``registry`` is the classification snapshot — injectable for tests;
    default reads the live one through :func:`envelope_authoring`'s own
    loader (gap 4c7512c57a7e). ``reload_registry``/``write_registry``/
    ``lock`` are the per-row retirement primitives — injectable
    separately from ``registry`` so a test can simulate a concurrent
    write landing between classification and retirement; defaults read/
    write the SAME live file ``registry`` defaults to and lock it with
    :func:`_default_lock`. ``api`` matches
    ``github_app_credentials._api``. ``ledger`` is a
    :class:`governance_ledger.GovernanceLedger`; without one, ``counted``
    rows are reported ``unreachable``.

    When the live registry is in effect (``registry`` not supplied), this
    refuses before any read if the process resolves a different file than
    ``$WILLOW_HOME`` names (``EREGISTRY``, gap 4c7512c57a7e) — the same
    guard :func:`envelope_authoring.revoke` applies, which the first cut
    of this sweep omitted.

    ``max_rows`` (0 = unbounded) and ``time_budget_s`` bound one call —
    the loop stops BETWEEN rows once either is hit, never mid-row; the
    receipt's ``truncated`` says whether more rows were waiting.

    A dry run performs every read (remote lookups, FRANK counts) and
    reports the SAME shape with ``retired`` meaning "would retire" —
    nothing is written to the registry and no FRANK row is appended, and
    the per-row lock/re-read is never taken.
    """
    receipt: dict = {"dry_run": bool(dry_run)}
    path = _envelopes.registry_path()
    using_live_registry = registry is None

    if using_live_registry:
        try:
            mismatch = _authoring.registry_mismatch()
        except Exception as exc:  # noqa: BLE001 — cannot even resolve $WILLOW_HOME
            receipt.update(state="unreachable", reason=f"registry_unresolvable: {exc}",
                            examined=0, retired=[], kept_standing=0,
                            kept_in_force=[], unreachable=[], truncated=False)
            return receipt
        if mismatch is not None:
            receipt.update(state="unreachable", reason=mismatch["message"],
                            examined=0, retired=[], kept_standing=0,
                            kept_in_force=[], unreachable=[], truncated=False)
            return receipt

    try:
        reg = registry if registry is not None else _authoring._load_registry()
    except Exception as exc:  # noqa: BLE001 — a registry we cannot read is unreachable, not empty
        receipt.update(state="unreachable", reason=f"registry_unreadable: {exc}",
                        examined=0, retired=[], kept_standing=0,
                        kept_in_force=[], unreachable=[], truncated=False)
        return receipt

    _reload = reload_registry or _authoring._load_registry
    _write = write_registry or (lambda doc: _authoring._atomic_write(path, doc))
    _lock = lock or _default_lock

    all_rows = [r for r in (reg.get("active") or [])
                if isinstance(r, dict) and r.get("id") and not _authoring._is_revoked(r)]
    rows = all_rows[:max_rows] if max_rows and max_rows > 0 else all_rows
    truncated = len(rows) < len(all_rows)

    call = api or _default_api
    retired: list[dict] = []
    kept_in_force: list[dict] = []
    unreachable: list[dict] = []
    kept_standing = 0
    examined = 0

    token_cache: dict[str, dict] = {}

    def _token_for(repo: str) -> dict:
        if repo not in token_cache:
            from . import github_app_credentials as gac

            token_cache[repo] = gac.mint_installation_token(repo)
        return token_cache[repo]

    started = time.monotonic()

    for row in rows:
        if time_budget_s and (time.monotonic() - started) >= time_budget_s:
            truncated = True
            break
        examined += 1
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
                if dry_run:
                    retired.append({"id": envelope_id, "verb": verb, "reason": "branch_gone",
                                    "repo": repo, "branch": branch})
                else:
                    outcome = _retire_locked(
                        envelope_id, reason="branch_gone", actor=actor, ledger=ledger,
                        reload_registry=_reload, write_registry=_write, lock=_lock,
                        registry_path=path,
                    )
                    if outcome["ok"]:
                        retired.append({"id": envelope_id, "verb": verb, "reason": "branch_gone",
                                        "repo": repo, "branch": branch})
                    else:
                        kept_in_force.append({"id": envelope_id, "verb": verb,
                                              "why": outcome["why"]})
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
        source = shape.get("use_count_source")
        if source != _TRUSTED_COUNT_SOURCE:
            unreachable.append({"id": envelope_id, "verb": verb,
                                "why": f"use_count_source={source!r} is not "
                                       f"{_TRUSTED_COUNT_SOURCE!r} — this sweep cannot verify it"})
            continue
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
            if dry_run:
                retired.append({"id": envelope_id, "verb": verb, "reason": "spent",
                                "count": count, "max_count": max_count})
            else:
                outcome = _retire_locked(
                    envelope_id, reason="spent", actor=actor, ledger=ledger,
                    reload_registry=_reload, write_registry=_write, lock=_lock,
                    registry_path=path,
                )
                if outcome["ok"]:
                    retired.append({"id": envelope_id, "verb": verb, "reason": "spent",
                                    "count": count, "max_count": max_count})
                else:
                    kept_in_force.append({"id": envelope_id, "verb": verb, "why": outcome["why"]})
        else:
            kept_in_force.append({"id": envelope_id, "verb": verb,
                                  "why": f"FRANK shows {count}/{max_count} granted uses"})

    if not all_rows:
        state = "empty"
    elif retired or kept_in_force or unreachable or kept_standing:
        state = "populated"
    else:
        state = "empty"  # pragma: no cover — unreachable given the branches above

    receipt.update(
        state=state,
        examined=examined,
        retired=retired,
        kept_standing=kept_standing,
        kept_in_force=kept_in_force,
        unreachable=unreachable,
        truncated=truncated,
    )
    return receipt
