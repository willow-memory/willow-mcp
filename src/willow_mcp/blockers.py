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
"""
from __future__ import annotations

import json
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
    from . import paths
    from .human_session import is_orchestrator_app

    if not is_orchestrator_app(app_id) or not session_id:
        return None
    try:
        record = json.loads(
            paths.session_path(app_id, session_id).read_text(encoding="utf-8")
        )
    except Exception:
        record = {}
    if (record.get("verifier") or "").strip():
        return None
    return _item(
        "session_unattested",
        "this orchestrator session has no verifier on record",
        "envelope_propose and envelope_ratify refuse; nothing can be authored "
        "or granted until it is attested",
        f"willow-mcp sign-session {session_id} --verifier NAME from an operator "
        f"terminal, then call session_enter again passing verifier, attested_at "
        f"and the hex contents of the .sig file",
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
        "malformed": row.get("error") or "malformed",
        "mismatch": row.get("error") or "names a different app_id",
    }.get(status, str(status))
    return _item(
        "no_egress_lease",
        f"no active egress lease for {app_id!r} — {detail}",
        "git push, net.fetch and any task carrying allow_net refuse; the task "
        "runs network-isolated instead of failing loudly",
        f"willow-mcp grant-net {app_id} --ttl 30m --reason \"...\" — operator only",
        status=status,
        expires_at=row.get("expires_at"),
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
