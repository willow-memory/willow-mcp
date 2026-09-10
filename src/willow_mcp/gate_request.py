"""willow_mcp/gate_request.py — the ask half of the approval broker.

`gates_panel` could always *render* a gate request and `gates_actions` could
always *approve* one. Nothing could *make* one: `encode_request` had no caller
outside the tests, so in a running server the queue never held a request row
for any prefix. The seam was built from the operator's end inward and stopped
one step short of the agent.

What that cost is recorded in `docs/design/egress-request-seam.md`: a lease
expired, an agent needed the network, "and the entire request mechanism was the
agent pasting a shell command into chat and hoping. Nothing was queued. Nothing
was recorded. Nothing resumed."

This module is that missing step, and only that step. **It grants nothing.** It
writes a row that says someone asked — the same row the operator was always
able to press, finally produced by the thing that needed it.

## Why there is no MCP tool here

The obvious shape would be an `agent_request_gate` tool. It is the wrong one.
The seam's own rule is that *an agent may REQUEST, never CONFIRM*, and a tool
whose whole purpose is to put a row in front of a tired operator is one
`full_access` typo away from being a phishing surface — which is why
`PERM_NEVER_REQUESTABLE` exists at all.

So the producer is the **denial site**, not the agent. A caller that is refused
for a missing lease has already proved it needed the thing; it does not have to
be trusted to say so. The ask is a side effect of the refusal, and the refusal
is unchanged.

## Fail-closed, always

Every entry point here returns a dict and never raises. A denial that fails to
enqueue is still a denial — `docs/design/egress-request-seam.md` is explicit
that "a request mechanism that swallows its own failure and proceeds is worse
than none." So callers use this for its side effect and ignore the result if
they like; what they must never do is let it change whether they refuse.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

#: Ceiling on how long an unanswered ask stays askable, from the operator's
#: decision of 2026-07-29: "TTL: 3 hours maximum, matching
#: `lease.max_ttl_seconds`. An unanswered egress ask expires rather than
#: sitting open forever. An expired request is a denial, never a grant."
#:
#: Read off `lease.MAX_TTL_SECONDS` rather than restated, so the request
#: ceiling cannot drift above the grant ceiling it is matched to.
def max_ttl_seconds() -> int:
    from . import lease

    return lease.MAX_TTL_SECONDS


def _refusal(reason: str) -> dict:
    return {"queued": False, "reason": reason}


def check_requestable(gate_id: str) -> Optional[str]:
    """Why `gate_id` may not be asked for, or None if it may.

    The allowlist is `gates_panel.REQUESTABLE_PREFIXES` — read, not restated.
    Until now that constant was documentation: nothing consulted it, while
    `gates_actions.describe()` carried the same list inline as an
    `if lease. / elif perm. / else` chain. Two copies of one security list,
    and the copy with the descriptive name was the one that decided nothing.
    """
    from . import gates_panel

    gate_id = (gate_id or "").strip()
    if not gate_id:
        return "a request must name a gate"
    if not gate_id.startswith(gates_panel.REQUESTABLE_PREFIXES):
        return (
            f"{gate_id!r} names no requestable gate — a request may ask for "
            f"{', '.join(gates_panel.REQUESTABLE_PREFIXES)} and nothing else"
        )
    if gate_id.startswith("perm."):
        _app, group = gates_panel.split_permission_gate(gate_id)
        if not group:
            return f"{gate_id!r} is not a well-formed perm.<app_id>.<group> gate"
        if group in gates_panel.PERM_NEVER_REQUESTABLE:
            # Deliberately the same refusal the approval path gives. An ask
            # that can be enqueued but never pressed is a row that teaches the
            # operator to press things that do nothing.
            return (
                f"{group!r} may never be requested — it grants authority over "
                f"the system rather than over the work, and adding it stays a "
                f"deliberate operator act with no agent in the loop"
            )
    return None


def _open_duplicate(store, gate_id: str, task_id: str) -> Optional[dict]:
    """An open, unexpired request already naming this (gate_id, task_id).

    Without this a denial inside a retry loop enqueues a row per attempt, and
    the queue an operator is supposed to watch becomes the thing they learn to
    ignore. Deduping on the pair rather than on `gate_id` alone follows the
    operator's decision that "the request names the exact task, not the app" —
    two tasks needing the same lease are two asks, one task retrying is one.
    """
    from . import gates_panel

    for item in gates_panel.open_requests(store):
        req = item.get("request") or {}
        if req.get("gate_id") != gate_id or req.get("task_id", "") != task_id:
            continue
        left = gates_panel._expiry_seconds(req.get("expires_at", ""))
        if left is None or left > 0:
            return item
    return None


def open_request(
    app_id: str,
    gate_id: str,
    *,
    task_id: str = "",
    reason: str = "",
    ttl_seconds: Optional[int] = None,
    store=None,
) -> dict:
    """Enqueue an ask for `gate_id`, or say why it was not enqueued.

    Returns `{"queued": bool, ...}` and never raises. `queued=False` carries a
    `reason`; it is not an error the caller has to handle, because the caller
    is already refusing.
    """
    try:
        refusal = check_requestable(gate_id)
        if refusal is not None:
            return _refusal(refusal)

        from . import gates_panel, human_loop
        from .db import Store

        if store is None:
            store = Store()

        existing = _open_duplicate(store, gate_id, task_id)
        if existing is not None:
            return {
                "queued": False,
                "reason": "an open request for this gate and task is already "
                          "in the queue",
                "id": existing.get("id"),
                "duplicate_of": existing.get("id"),
            }

        ceiling = max_ttl_seconds()
        ttl = ceiling if ttl_seconds is None else max(1, min(int(ttl_seconds), ceiling))
        expires_at = (
            datetime.now(timezone.utc) + timedelta(seconds=ttl)
        ).isoformat().replace("+00:00", "Z")

        title = f"Request: {gate_id}"
        summary = reason or f"{app_id or 'an app'} was refused for want of {gate_id}"
        item = human_loop.enqueue(
            store,
            kind=gates_panel.REQUEST_QUEUE_KIND,
            title=title,
            summary=summary,
            source_agent=app_id or "",
            source_ref=gates_panel.encode_request(
                gate_id=gate_id,
                task_id=task_id,
                nonce=secrets.token_hex(8),
                expires_at=expires_at,
            ),
        )
        return {"queued": True, "id": item.get("id"), "gate_id": gate_id,
                "expires_at": expires_at}
    except Exception as e:  # noqa: BLE001 — see the module docstring
        # The caller is mid-refusal. An exception raised here would turn a
        # clean denial into a traceback, which is the one outcome worse than
        # the ask not being recorded.
        return _refusal(f"could not enqueue the request ({e})")


def note_for_lease_denial(app_id: str, *, task_id: str = "", reason: str = "",
                          store=None) -> str:
    """Enqueue the ask, and return the sentence a `lease_denied` message adds.

    The four `lease_denied` sites differ only in which tool family they name,
    so they share this: one call, one appended sentence, and the denial itself
    untouched above it.

    Returns "" when nothing was queued — a failed enqueue must not put a claim
    in the operator's face that no row backs. The caller still refuses either
    way; that is the fail-closed half, and it is why this returns a string
    rather than something a caller could mistake for permission.
    """
    result = request_lease(app_id, task_id=task_id, reason=reason, store=store)
    if result.get("queued"):
        return (
            f" This ask has been queued for the operator as request "
            f"{result.get('id')} — it appears in `willow-mcp gates` and expires "
            f"{result.get('expires_at')}."
        )
    if result.get("duplicate_of"):
        return (
            f" An open request for this is already waiting on the operator "
            f"(request {result.get('duplicate_of')})."
        )
    return ""


def request_lease(app_id: str, *, task_id: str = "", reason: str = "",
                  store=None) -> dict:
    """Ask the operator for an egress lease on `app_id`.

    The shape every `lease_denied` site shares. Kept as its own function so
    those sites name what they want rather than assembling a gate id, and so
    the `lease.` prefix has one spelling in the tree.
    """
    return open_request(
        app_id,
        f"lease.{app_id}",
        task_id=task_id,
        reason=reason or (
            f"{app_id or 'an app'} was refused network access for want of an "
            f"unexpired egress lease"
        ),
        store=store,
    )
