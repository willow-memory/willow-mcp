"""What a seat cannot do right now, and why — computed at `session_enter`.

`session_enter` already answers "what is this project": ORIENT.md, standing
records, the latest handoff, the collection aliases. It says nothing about
what the *seat* is blocked on, so every gate is discovered the moment it
refuses, usually mid-task.

That is not hypothetical. In one session: the session was unattested and it
surfaced an hour in, when `envelope_propose` refused; the egress lease had
been dead for four days; the work root was read-only to the sandbox and it
surfaced at `cannot lock ref`; and the operator's own terminal was resolving
a retired home, which surfaced only after six granted permissions vanished.
All five were readable at entry.

**This module reads and never writes.** Every check calls a reader that
already exists — `lease.read_lease`, `consent.read_consent`,
`heartbeat.read_workers`, `db.get_pg` — the same functions `diagnostic_summary`
and `gates_panel` call. It adds no state and no authority. The precedent is
`server.py`'s own `envelope_proposals_pending` block, surfaced at seat entry
"not mid-dispatch when the queue has silently grown"; this is that argument
with a wider scope.

**Every check is individually wrapped.** Orientation is sugar. A reader that
raises must cost the caller one blocker entry, never the session — the same
rule the envelope-pending block already follows.

**This reports the CALLER's reachability, not the box's.** Measured: run in
the MCP server process on the operator box, `collect()` finds one blocker —
a dead lease. The identical call from inside the Kart sandbox finds four,
because the session record is not mounted there, Postgres has no socket, and
no worker heartbeat is visible across the PID namespace. Every one of those
is true *for the process that asked*, which is the point — a seat should learn
what it cannot do, not what someone else could. But do not read a sandbox-side
report as a claim about the box: "postgres_unreachable" from inside bwrap
means bwrap cannot reach it, not that the fleet is down.
"""
from __future__ import annotations

import os
from typing import Any, Callable

#: Reported on every call, blocker or not. A seat pointed at the wrong home
#: writes successfully into nothing, and the only cheap moment to notice is
#: before any work is done. See `paths.willow_home`'s retirement guard.
_HOME_KEY = "resolved_home"


def _item(id_: str, summary: str, effect: str, fix: str, **extra: Any) -> dict:
    """One blocker. `effect` names what will actually refuse — a blocker the
    reader cannot connect to a symptom gets skimmed past."""
    return {"id": id_, "summary": summary, "effect": effect, "fix": fix, **extra}


# ── the checks ───────────────────────────────────────────────────────────────

def _check_attestation(app_id: str, session_id: str) -> dict | None:
    """Ask the gate itself, rather than guessing from the session record.

    This check used to read ``verifier`` out of ``sessions/willow-<id>.json``
    and report the seat unattested whenever it was empty. It is always empty:
    ``sign-session`` writes a sidecar (``willow-<id>.attest.json`` + ``.sig``)
    and never touches the record, and since #313 the enforcing gate reads only
    that sidecar — deliberately, because ``session_bind`` rewrites the record
    on every ordinary state change and kept self-invalidating a signature taken
    over it.

    So the old check was wrong in both directions. It reported an attested
    session as unattested (observed 2026-09-09: operator signed at 20:52:54Z,
    the gate passed, this blocker still fired), and it would have reported an
    UNattested one as fine on any deployment with neither a keyring nor a PGP
    fingerprint configured, where the gate returns early and nothing refuses.

    ``mutate_cache=False``: a reporter consults the attribution cache so its
    answer agrees with the gate's, but must not warm it and must not clear it.
    """
    from . import human_session, remedy

    if not human_session.is_orchestrator_app(app_id) or not session_id:
        return None

    denial = human_session.session_attestation_denial(
        session_id, mutate_cache=False
    )
    if denial is None:
        return None

    invalid = "orchestrator_session_attestation_invalid" in denial
    return _item(
        "session_unattested",
        "this orchestrator session's attestation does not verify"
        if invalid
        else "this orchestrator session has never been attested",
        "envelope_propose and envelope_ratify refuse; nothing can be authored "
        "or granted until it is attested",
        remedy.attestation_command(session_id, keyring_on=remedy.keyring_on()),
        denial=denial,
    )


def _check_lease(app_id: str) -> dict | None:
    from . import lease

    row = lease.read_lease(app_id)
    status = row.get("status")
    if status == "active":
        return None
    detail = {
        "none": "no lease on disk",
        "expired": f"expired at {row.get('expires_at')}",
        "unreadable": (f"a lease exists at {row.get('path')} but this process "
                       f"cannot read it ({row.get('error') or 'permission denied'})"),
        "malformed": row.get("error") or "malformed",
        "mismatch": row.get("error") or "names a different app_id",
    }.get(status, str(status))
    # Two lanes need this lease and they fail differently, so both are named:
    # only one of them is unblocked by a lease alone. Federated jeles is the
    # open-web path since the operator retired willow_web_* on this seat
    # (KB 805162C1, 2026-09-01) — one organ, one confidence ladder.
    effect = (
        "federated jeles calls (corpus_*) refuse — they need this lease "
        "alongside mcp_federation and consent.federation. A Kart task carrying "
        "allow_net needs MORE than this lease: an operator-signed per-task "
        "envelope too, so granting the lease alone will not unblock git push"
    )
    if status == "unreadable":
        # Measured 2026-09-10 (gap d90246688413): a root-issued lease landed
        # 0600 root-owned; the seat read "malformed" and the advice was to
        # re-issue. Re-issuing as root reproduces the same file. The fix is a
        # mode, and saying so is the whole point of a distinct status.
        fix = (f"the lease is fine; its FILE MODE is not — from an operator "
               f"terminal: sudo chmod 644 {row.get('path')} (a lease is a public "
               f"grant, not a secret). Do NOT re-issue: a fresh grant-net from "
               f"the same shell writes the same unreadable file")
    else:
        fix = (f"willow-mcp grant-net {app_id} --ttl 30m --reason \"...\" — operator "
               f"only; a task also needs willow-mcp sign-net-task")
    return _item(
        "no_egress_lease",
        f"no active egress lease for {app_id!r} — {detail}",
        effect,
        fix,
        status=status,
        expires_at=row.get("expires_at"),
        path=row.get("path"),
    )


def _check_consent() -> dict | None:
    from . import consent

    check = consent.read_consent()
    if (check.get("consent") or {}).get("internet"):
        return None
    return _item(
        "consent_internet_off",
        "standing consent for internet is not granted",
        "sits underneath the lease — granting a lease will not help while this "
        "is off",
        f"edit the canonical settings at {check.get('canonical_path')}; note the "
        f"flat consent.json is a mirror and editing it does nothing",
        source=check.get("source"),
    )


def _check_worker() -> dict | None:
    from . import heartbeat

    check = heartbeat.read_workers()
    if check.get("alive"):
        return None
    return _item(
        "no_live_worker",
        "no Kart worker is publishing a heartbeat",
        "task_submit accepts the task and it stays pending forever — the queue "
        "does not refuse, it simply never drains",
        "start a worker, or run one pass with willow-mcp worker --once",
        readiness=check.get("readiness"),
        by_lane=check.get("by_lane"),
    )


def _check_postgres() -> dict | None:
    from . import db

    if db.get_pg() is not None:
        return None
    return _item(
        "postgres_unreachable",
        "the fleet Postgres is not reachable",
        "task_list, task_status, fleet_status, dispatch and every grove_* read "
        "return unavailable; the SQLite task fallback is used instead",
        "check the socket and WILLOW_PG_DB — the resolved dbname is named in "
        "the error below",
        error=db.last_pg_error(),
    )


#: (id, callable). Ordered by how early the blocker bites, not by severity:
#: an unattested session stops authoring before a dead lease stops pushing.
_CHECKS: tuple[tuple[str, Callable[..., dict | None]], ...] = (
    ("session_unattested", _check_attestation),
    ("no_egress_lease", _check_lease),
    ("consent_internet_off", _check_consent),
    ("no_live_worker", _check_worker),
    ("postgres_unreachable", _check_postgres),
)


def collect(app_id: str, session_id: str = "") -> dict:
    """Everything this seat is blocked on, newest concern first.

    Never raises. A check that fails is reported as its own entry rather than
    swallowed — "the lease reader threw" is itself worth knowing at entry, and
    a silent gap in this list would be worse than no list at all.
    """
    items: list[dict] = []
    for name, check in _CHECKS:
        try:
            if name == "session_unattested":
                found = check(app_id, session_id)
            elif name in ("no_egress_lease",):
                found = check(app_id)
            else:
                found = check()
        except Exception as e:
            items.append(_item(
                f"{name}_check_failed",
                f"the {name} check could not run: {e}",
                "this gate's state is unknown, not clear",
                "read the gate directly; do not assume it is open",
            ))
            continue
        if found:
            items.append(found)

    try:
        from . import paths

        home = str(paths.willow_home())
    except Exception as e:
        home = f"unresolved: {e}"
        items.append(_item(
            "home_unresolved",
            f"WILLOW_HOME could not be resolved: {e}",
            "every path this seat writes is in doubt",
            "set WILLOW_HOME explicitly to the live home",
        ))

    return {
        _HOME_KEY: home,
        "willow_home_env_set": bool(os.environ.get("WILLOW_HOME")),
        "count": len(items),
        "items": items,
    }
