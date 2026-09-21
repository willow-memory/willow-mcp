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

**Concurrency (rework of Loki's HIGH finding, BAA43543/9494D3AF).** The
first cut classified against one registry snapshot, made every network/FRANK
call, then wrote the WHOLE stale snapshot back at the end — an operator
revoke or a proposal written anywhere in that window was silently undone by
the final write (Loki's probe, task Y3TVZXUX). Retirement now happens
per-row, under an exclusive file lock (mirroring the "hold a lock, re-read
under it" shape :meth:`governance_ledger.GovernanceLedger.append_citation`
already uses for FRANK's own metering): classification runs off a snapshot
(cheap, read-only, no lock needed — it only decides WHICH ids to examine),
but the instant before a row is actually retired the lock is taken, the
registry is RE-READ fresh, and the write applies to that fresh copy — so any
proposal or operator action that landed mid-sweep survives untouched. If the
row is no longer active (already revoked by someone else, or gone) under the
fresh read, nothing is written and the row is reported, never silently
re-clobbered.

**What the lock does NOT cover (rework of Loki's LOW finding, D81165E5).**
The ``.lock`` file this module takes serializes SWEEP-VS-SWEEP only — two
concurrent :func:`sweep` calls (or a sweep and the CLI running it by hand).
:mod:`envelope_authoring` (``ratify``/``reject``/``revoke``, the operator's
own keyed writes) takes NO lock at all and is unchanged by this module. A
keyed write landing in the microsecond window between this module's
``reload_registry()`` and its ``write_registry()``'s own ``os.replace`` can
still race with it — that is a pre-existing gap in :mod:`envelope_authoring`
itself (every one of its writers reads, mutates, and calls
``_atomic_write`` with no lock), not something this sweep introduces or
closes. Fixing that is out of this module's scope; this docstring used to
overclaim "the same lock the keyed path takes" — it does not exist.

**Ordering (rework of Loki's LOW finding).** The registry write — the
durable, gate-visible state — happens BEFORE the FRANK ledger append, not
after: a crash in between leaves an under-logged retirement (row says
revoked, FRANK silent, still auditable from the row itself) rather than an
over-logged one (FRANK says revoked, the row is still active — the version
that actively misleads a reader). A registry WRITE FAILURE itself (disk
full, permission error) is caught where it happens and reported on that
row alone (``kept_in_force``, never raised) — a failure retiring row N must
not lose the receipt for rows already retired earlier in the same call
(rework of Loki's LOW finding, probe C, D81165E5).

**Bounding against the steward's 90s call budget (rework of Loki's MEDIUM
finding, twice reworked).** A live register with hundreds of
branch-bound/counted rows can need dozens of GitHub round trips and hundreds
of FRANK counts; the client that calls this tool
(``willow_bot.steward.mcp_client``) times the whole call out at 90s.
``time_budget_s`` (default 60s — well inside that 90s, and inside it by
design rather than by luck) stops examining FURTHER rows once elapsed
wall-clock crosses it, checked BETWEEN rows so nothing in flight is left
half-applied. Two more pieces close the gap D81165E5 found in the first
version of this bound:

* **A cursor**, so consecutive under-budget calls do not all examine the
  identical prefix and starve the tail. Rows are ordered by id and rotated
  to start just past the last id this sweep actually examined last time
  (persisted at :func:`_cursor_path` — a small text file beside the seal
  watch's own offset file, same convention). A cursor id no longer present
  (its row was retired or removed) resumes from the next id in sorted
  order rather than restarting at the top. ``max_rows`` (0 = unbounded) is
  an additional, independent row-count cap on top of the wall-clock bound.
* **A per-row deadline.** A single row's OWN network calls used to run at
  the shared client's full 20s timeout regardless of how little budget was
  left, so one hung row could overrun the tick by multiples of that 20s
  (Loki's probe: ~80s of urlopen timeouts possible in the worst case, ~140s
  past the 90s client). Each of :func:`_branch_state`'s HTTP calls is now
  given ``min(20, time remaining in the budget)`` as its OWN timeout
  (``github_app_credentials._api``'s new ``timeout`` kwarg), and a call
  whose remaining budget is already ``<= 0`` is never even started — it is
  reported ``unreachable`` with the reason named instead. This bounds a
  single row's overrun to at most one clipped call, not several calls at
  the shared 20s ceiling apiece. It does not make the check itself
  mid-call preemptive (no Python HTTP client can be interrupted mid-syscall
  without its own watchdog thread, which this module does not add) — it
  bounds how much timeout budget any one call is ever GIVEN.
"""
from __future__ import annotations

import bisect
import os
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

#: Round-robin cursor filename, same convention as the seal watch's own
#: offset file (``seal_daemon.default_offset_path`` — a small text file
#: under ``paths.store_root()``). Holds the last envelope id this module
#: actually EXAMINED (not necessarily retired) — the next call resumes just
#: past it, sorted by id, wrapping to the start once every row has had a
#: turn (rework of Loki's MEDIUM finding, D81165E5: without this, two
#: back-to-back under-budget calls examined the identical prefix and the
#: tail of a large register never got looked at).
_CURSOR_FILENAME = "envelope_retire_sweep.cursor"


def _cursor_path():
    from . import paths

    return paths.store_root() / _CURSOR_FILENAME


def _read_cursor() -> str:
    try:
        return _cursor_path().read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _write_cursor(envelope_id: str) -> None:
    path = _cursor_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(envelope_id, encoding="utf-8")
        os.replace(tmp, path)
    except OSError:  # pragma: no cover — a cursor we cannot persist just
        # means the next call starts from the top again; never fatal to
        # the sweep that already ran.
        pass


def _rotate_from_cursor(rows: list, cursor_id: str) -> list:
    """``rows`` sorted by id, rotated to start just past ``cursor_id``. An
    empty/unknown cursor starts at the top (index 0). A cursor id no
    longer present resumes from the next HIGHER id in sorted order
    (``bisect``), so a retired/removed row never causes the sweep to
    restart from the beginning."""
    if not cursor_id:
        return rows
    ids = [r.get("id") or "" for r in rows]
    idx = bisect.bisect_right(ids, cursor_id)
    if idx >= len(rows):
        return rows  # cursor was at or past the end — wrap to the start
    return rows[idx:] + rows[:idx]


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


def _default_api(method: str, url: str, *, bearer: str, body: dict | None = None,
                  timeout: int = 20) -> dict[str, Any]:
    from . import github_app_credentials as gac

    return gac._api(method, url, bearer=bearer, body=body, timeout=timeout)


#: Never give a single HTTP call less than this many seconds, even when the
#: overall budget is nearly gone — a 0s or 1s socket timeout is indistinguishable
#: from "never try" and would report every remaining row unreachable for no
#: real reason. Below this floor the call is skipped entirely instead (see
#: `_clipped_timeout`).
_MIN_CALL_TIMEOUT_S = 3


def _clipped_timeout(deadline: Optional[float]) -> Optional[int]:
    """``None`` (use the caller's own default) when there is no deadline;
    otherwise the whole seconds remaining, floored at `_MIN_CALL_TIMEOUT_S`
    and capped at 20 (the shared client's own ceiling) — or `0` when even
    the floor does not fit, meaning "do not start this call at all"
    (rework of Loki's MEDIUM finding, D81165E5: a per-row deadline, not
    just a between-rows check)."""
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining < _MIN_CALL_TIMEOUT_S:
        return 0
    return min(20, int(remaining))


def _branch_state(api: Callable, *, repo: str, branch: str, token: str,
                   api_base: str = "https://api.github.com",
                   deadline: Optional[float] = None) -> dict:
    """``{reachable: bool, branch_gone: bool, merged: bool}``. A non-2xx/
    non-404 response (network error, auth failure, rate limit) is
    ``reachable: False`` — never interpreted as "the branch is gone".

    ``deadline`` (a `time.monotonic()` target) clips EACH of this
    function's up-to-two HTTP calls to whatever remains of the sweep's own
    wall-clock budget, and skips a call entirely once nothing meaningful
    remains — the per-row deadline rework of Loki's MEDIUM finding
    (D81165E5): without it, a row already past budget could still spend a
    full 20s call (twice, if the branch check made it through and the
    pulls check did not)."""
    timeout = _clipped_timeout(deadline)
    if timeout == 0:
        return {"reachable": False, "branch_gone": None, "merged": None,
                "reason": "sweep time budget exhausted before this row's "
                          "branch check could start"}
    call_kwargs = {} if timeout is None else {"timeout": timeout}
    resp = api("GET", f"{api_base}/repos/{repo}/branches/{branch}", bearer=token, **call_kwargs)
    if resp.get("ok"):
        return {"reachable": True, "branch_gone": False, "merged": None}
    status = int(resp.get("status") or 0)
    if status != 404:
        return {"reachable": False, "branch_gone": None, "merged": None,
                "reason": f"HTTP {status}: {str(resp.get('reason', ''))[:200]}"}
    # Branch absent on the remote. Was there a merged PR from it? GitHub's
    # `head` filter matches by name regardless of whether the branch still
    # exists, so a deleted branch's PR history is still reachable this way.
    timeout = _clipped_timeout(deadline)
    if timeout == 0:
        return {"reachable": False, "branch_gone": True, "merged": None,
                "reason": "sweep time budget exhausted before this row's "
                          "PR-history check could start"}
    call_kwargs = {} if timeout is None else {"timeout": timeout}
    owner = repo.split("/", 1)[0]
    pulls = api(
        "GET",
        f"{api_base}/repos/{repo}/pulls?head={owner}:{branch}&state=closed&per_page=10",
        bearer=token, **call_kwargs,
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
        #
        # Caught, not raised (rework of Loki's LOW finding, probe C,
        # D81165E5): a write failure on THIS row must not propagate out of
        # `sweep()`'s loop and lose the receipt for rows already retired
        # earlier in the same call. The row is reported kept, not retired
        # — no FRANK row follows a write that never landed.
        try:
            write_registry(reg)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "why": f"registry write failed: {exc}"}
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
    read_cursor: Optional[Callable[[], str]] = None,
    write_cursor: Optional[Callable[[str], None]] = None,
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
    receipt's ``truncated`` says whether more rows were waiting. Rows are
    examined in a ROUND-ROBIN order driven by a persisted cursor
    (``read_cursor``/``write_cursor``, default a small file beside the seal
    watch's own offset file — see :func:`_cursor_path`): each call resumes
    just past the last id the PREVIOUS call examined, so consecutive
    under-budget calls sweep progressively further into the register
    instead of re-examining the same prefix forever. The cursor only
    advances on a live call (``dry_run=False``) — a by-hand dry run never
    perturbs the live tick's progress.

    A dry run performs every read (remote lookups, FRANK counts) and
    reports the SAME shape with ``retired`` meaning "would retire" —
    nothing is written to the registry, no FRANK row is appended, the
    cursor is not advanced, and the per-row lock/re-read is never taken.
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
    _read_cursor_fn = read_cursor or _read_cursor
    _write_cursor_fn = write_cursor or _write_cursor

    all_rows = [r for r in (reg.get("active") or [])
                if isinstance(r, dict) and r.get("id") and not _authoring._is_revoked(r)]
    all_rows_sorted = sorted(all_rows, key=lambda r: r.get("id") or "")
    ordered = _rotate_from_cursor(all_rows_sorted, _read_cursor_fn())
    rows = ordered[:max_rows] if max_rows and max_rows > 0 else ordered
    truncated = len(rows) < len(all_rows_sorted)

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
    deadline = (started + time_budget_s) if time_budget_s else None
    last_examined_id: Optional[str] = None

    for row in rows:
        if time_budget_s and (time.monotonic() - started) >= time_budget_s:
            truncated = True
            break
        examined += 1
        envelope_id = row.get("id")
        last_examined_id = envelope_id
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
            state = _branch_state(call, repo=repo, branch=branch, token=auth["token"],
                                  deadline=deadline)
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

    # Advance the round-robin cursor only on a live call (rework of Loki's
    # MEDIUM finding, D81165E5) — a dry run must never perturb the live
    # tick's progress through the register.
    if not dry_run and last_examined_id is not None:
        _write_cursor_fn(last_examined_id)

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
