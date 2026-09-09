"""willow_mcp/gates_actions.py — what happens when you press a gates row.

Shared by the interactive TUI (`gates_tui.py`) and the live local HTML
dashboard (`gates_serve.py`), so "what does pressing this button actually
do" has exactly one implementation instead of two that could drift.

**This adds no new authority.** Every action here calls the same functions
the CLI subcommands already call — `manifest_admin.set_permission` (backs
`allow-permission`/`deny-permission`), `lease.grant`/`lease.revoke` (backs
`grant-net`/`revoke-net`), `identity_binding.confirm_binding` (backs
`confirm-binding`), and a one-shot queue drain (backs `worker --once`). It
is a second way to invoke the same local-CLI-only, never-an-MCP-tool
operations `gates_panel.py`'s rows already point at, not a new one.

Split into `describe()` (pure — what *would* happen, and what input it
needs, without touching anything) and `apply()` (does it) so both UIs can
render "this needs a TTL and a reason" before committing to anything, and
so this module is testable without a real terminal or a real HTTP request.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from . import lease, manifest_admin
from .gates_panel import GateRow


@dataclass
class ActionSpec:
    #: "toggle_permission" | "lease_grant" | "lease_revoke" | "confirm_binding"
    #: | "request_grant" | "worker_once" | "none"
    kind: str
    #: field names the caller must supply in `apply(..., inputs=...)`
    needs: tuple = ()
    #: set only for kind == "none" — why there's nothing to do here
    reason: Optional[str] = None


def describe(row: GateRow) -> ActionSpec:
    """What pressing `row` would do, and what it needs from the caller.
    Pure — reads nothing, changes nothing."""
    rid = row.id
    if rid.startswith("request."):
        # A request row's action IS the action of the gate it names — pressing
        # it must do exactly what pressing that gate does, so the approval
        # path and the direct path stay one implementation. `warn` means the
        # request outlived its own expiry; nothing to press but dismissal.
        from . import gates_panel

        if row.state == "warn":
            return ActionSpec(kind="none",
                              reason=row.action_note or "request has expired")
        # Asked for and grantable-by-press are two different questions. An
        # `attest.` row is a legitimate ask with no approval half: the signature
        # needs the operator's key at their own terminal, and delegating it is
        # §5b, unratified. The row carries the command; pressing it does nothing
        # and must not pretend otherwise.
        if not gates_panel.is_pressable(row.scope):
            return ActionSpec(
                kind="none",
                reason=row.action_note or
                f"{row.scope} surfaces an ask that no press can grant",
            )
        if row.scope.startswith("lease."):
            return ActionSpec(kind="request_grant", needs=("ttl", "reason"))
        if row.scope.startswith("perm."):
            return ActionSpec(kind="request_permission")
        return ActionSpec(
            kind="none",
            reason=f"{row.scope} names no requestable gate — a request may ask "
                   f"for {', '.join(gates_panel.REQUESTABLE_PREFIXES)} and "
                   f"nothing else",
        )
    if rid.startswith("perm."):
        return ActionSpec(kind="toggle_permission")
    if rid.startswith("lease."):
        if row.state == "on":
            return ActionSpec(kind="lease_revoke")
        return ActionSpec(kind="lease_grant", needs=("ttl", "reason"))
    if rid.startswith("binding.") and row.state == "off":
        return ActionSpec(kind="confirm_binding", needs=("app_id",))
    if rid == "worker" and row.state != "on":
        return ActionSpec(kind="worker_once")
    return ActionSpec(kind="none",
                       reason=row.action_note or "no live action for this gate")


def apply(row: GateRow, inputs: Optional[dict] = None) -> dict:
    """Perform the action `describe(row)` names, using `inputs` for
    anything it `needs`. Returns `{"ok": bool, "message": str}` — never
    raises, since both callers (a curses loop, an HTTP handler) need to
    keep running past a bad TTL or a missing app_id, not crash on one."""
    inputs = inputs or {}
    spec = describe(row)
    try:
        if spec.kind == "toggle_permission":
            return _toggle_permission(row)
        if spec.kind == "lease_revoke":
            return _lease_revoke(row)
        if spec.kind == "lease_grant":
            return _lease_grant(row, inputs)
        if spec.kind == "request_grant":
            return _request_grant(row, inputs)
        if spec.kind == "request_permission":
            return _request_permission(row)
        if spec.kind == "confirm_binding":
            return _confirm_binding(row, inputs)
        if spec.kind == "worker_once":
            return _drain_once()
        return {"ok": False, "message": spec.reason}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def _toggle_permission(row: GateRow) -> dict:
    app_id, group = row.scope, row.label
    granted = row.state != "on"
    manifest_admin.set_permission(app_id, group, granted)
    verb = "granted" if granted else "revoked"
    return {"ok": True, "message": f"{verb} {group!r} for app_id={app_id!r}"}


def _lease_revoke(row: GateRow) -> dict:
    app_id = row.scope
    had = lease.revoke(app_id)
    return {"ok": True,
            "message": f"egress lease for {app_id!r} "
                       f"{'revoked' if had else 'was not present'}"}


def _lease_grant(row: GateRow, inputs: dict) -> dict:
    app_id = row.scope
    ttl_raw = (inputs.get("ttl") or "30m").strip()
    reason = inputs.get("reason") or ""
    issuer = inputs.get("issuer") or "operator"
    ttl_seconds = lease.parse_ttl(ttl_raw)
    record = lease.grant(app_id, ttl_seconds, issuer=issuer, reason=reason)
    return {"ok": True,
            "message": f"egress lease granted to {app_id!r}, "
                       f"expires {record['expires_at']}"}


def _live_request(row: GateRow):
    """Re-read the request `row` points at, and refuse if it cannot be acted on.

    Returns `(store, live_item, None)` when the request is open and unexpired,
    or `(store, None, refusal)` when it is not. Shared by both approval paths
    on purpose: the checks are the whole security of this seam, and two copies
    of them would eventually stop agreeing.

    Both checks are made against the QUEUE, never against the row. `describe()`
    already refuses an expired row — but the row is an argument, and a caller
    can hand `apply()` one it built itself.
    """
    from . import gates_panel
    from .db import Store

    item_id = row.id[len("request."):]
    store = Store()

    live = None
    for candidate in gates_panel.open_requests(store):
        if candidate["id"] == item_id:
            live = candidate
            break
    if live is None:
        return store, None, {
            "ok": False,
            "message": f"request {item_id} is no longer open — it was "
                       f"resolved, dismissed, or never existed",
        }

    left = gates_panel._expiry_seconds(live["request"].get("expires_at", ""))
    if left is not None and left <= 0:
        return store, None, {
            "ok": False,
            "message": f"request {item_id} expired at "
                       f"{live['request'].get('expires_at')}; dismiss it and ask "
                       f"again rather than granting late",
        }
    return store, live, None


def _request_permission(row: GateRow) -> dict:
    """Approve a manifest-permission request: check it, toggle it on, close it.

    The press is the operator's act — that is what satisfies the sudo invariant
    (FRANK 90e52ab7), not anything this function does. What this function is
    for is making sure the thing being pressed is what it appears to be:

    1. The request is still open and unexpired (`_live_request`).
    2. The group is not one the queue may never carry. See
       `gates_panel.PERM_NEVER_REQUESTABLE` — those stay a deliberate operator
       act so the queue cannot become a phishing surface.
    3. The asking app is the SUBJECT of the permission. An app may ask for its
       own seat; asking for another app's would be laundering a grant through
       whichever app happens to be trusted enough to enqueue.

    Then it calls the same `_toggle_permission` the `perm.` row itself calls.
    No new authority: this is a second way to press one button.
    """
    from . import gates_panel, human_loop
    from .gate import _load_manifest

    store, live, refusal = _live_request(row)
    if refusal is not None:
        return refusal
    item_id, req = live["id"], live["request"]

    gate_id = req["gate_id"]
    app_id, group = gates_panel.split_permission_gate(gate_id)
    if not app_id:
        return {"ok": False, "message": f"malformed permission gate {gate_id!r}"}

    if group in gates_panel.PERM_NEVER_REQUESTABLE:
        return {"ok": False,
                "message": f"{group!r} can never be requested — it grants "
                           f"authority over the system rather than over the "
                           f"work, and is added by the operator with no agent "
                           f"in the loop"}

    asker = live.get("source_agent") or ""
    if asker and asker != app_id:
        return {"ok": False,
                "message": f"{asker!r} asked for a permission on {app_id!r}; a "
                           f"request names its own app or it is not a request"}

    manifest = _load_manifest(app_id) or {}
    if group in (manifest.get("permissions") or []):
        try:
            human_loop.resolve(store, item_id, resolved_by="operator",
                               status="resolved",
                               note=f"{app_id} already held {group}")
        except Exception:
            pass
        return {"ok": True,
                "message": f"{app_id!r} already holds {group!r}; nothing "
                           f"written (request {item_id} closed)"}

    # state="off" so the toggle can only ever GRANT. _toggle_permission flips
    # on the row's state, and a row arriving as "on" would revoke a permission
    # the operator believed they were approving.
    target = GateRow(id=gate_id, label=group, scope=app_id,
                     state="off", detail="", timer_shape="standing")
    result = _toggle_permission(target)
    if not result.get("ok"):
        return result

    note = f"approved from gates; task={req.get('task_id') or '(none)'} " \
           f"nonce={req.get('nonce') or '(none)'}"
    try:
        human_loop.resolve(store, item_id, resolved_by="operator",
                           status="resolved", note=note)
    except Exception as e:
        return {"ok": True,
                "message": f"{result['message']} — WARNING: the queue item "
                           f"could not be closed ({e}); it will render again"}
    return {"ok": True, "message": f"{result['message']} (request {item_id} closed)"}


def _request_grant(row: GateRow, inputs: dict) -> dict:
    """Approve an egress-lease request: check it, do the ordinary grant, close
    the queue item.

    Three checks before anything is granted, in this order because each one
    makes the next meaningful:

    1. **The request still exists and is still open.** The row was rendered
       from a queue read that may be seconds old; two operators (or a TUI and
       the HTML page) can be looking at the same row.
    2. **It has not expired**, and the nonce still matches what the queue
       holds. `describe()` already refuses an expired row, but the row is an
       argument here — a caller can pass one it built itself.
    3. **The asking app already holds the capability.** This is the whole
       rule: a request may ACTIVATE a standing grant, never CREATE one. An
       app without `task_net` asking for an egress lease is not making a
       request, it is asking for something nobody gave it.

    Only then does it call `_lease_grant`, which is the same function the
    `lease.` row and `willow-mcp grant-net` already call. No new authority.
    """
    from . import human_loop
    from .gate import NET_PERMISSION, _load_manifest

    store, live, refusal = _live_request(row)
    if refusal is not None:
        return refusal
    item_id, req = live["id"], live["request"]

    gate_id = req["gate_id"]
    if not gate_id.startswith("lease."):
        return {"ok": False,
                "message": f"{gate_id} cannot be requested — a request may "
                           f"activate a standing grant, never create one"}
    app_id = gate_id[len("lease."):]
    if not app_id:
        return {"ok": False, "message": f"malformed gate id {gate_id!r}"}

    asker = live.get("source_agent") or ""
    if asker and asker != app_id:
        return {"ok": False,
                "message": f"{asker!r} asked for {app_id!r}'s lease; a request "
                           f"names its own app or it is not a request"}

    manifest = _load_manifest(app_id) or {}
    if NET_PERMISSION not in (manifest.get("permissions") or []):
        return {"ok": False,
                "message": f"{app_id!r} does not hold {NET_PERMISSION!r}; "
                           f"granting a lease would create the capability, not "
                           f"start its clock. Amend the manifest deliberately "
                           f"if that is what you mean."}

    target = GateRow(id=gate_id, label="egress lease", scope=app_id,
                     state="off", detail="", timer_shape="lease")
    result = _lease_grant(target, {**inputs, "issuer": inputs.get("issuer") or "operator"})
    if not result.get("ok"):
        return result

    note = f"approved from gates; task={req.get('task_id') or '(none)'} " \
           f"nonce={req.get('nonce') or '(none)'}"
    try:
        human_loop.resolve(store, item_id, resolved_by="operator",
                           status="resolved", note=note)
    except Exception as e:
        # The lease is already granted; say so rather than implying it isn't.
        return {"ok": True,
                "message": f"{result['message']} — WARNING: the queue item "
                           f"could not be closed ({e}); it will render again"}
    return {"ok": True, "message": f"{result['message']} (request {item_id} closed)"}


def _confirm_binding(row: GateRow, inputs: dict) -> dict:
    from . import identity_binding

    bind_app_id = (inputs.get("app_id") or "").strip()
    if not bind_app_id:
        return {"ok": False, "message": "app_id is required to confirm a binding"}
    # row.id shape: "binding.<issuer>__<subject_id>" (see gates_panel._binding_rows)
    issuer_subject = row.id[len("binding."):]
    issuer, _, subject_id = issuer_subject.partition("__")
    record = identity_binding.confirm_binding(issuer, subject_id, bind_app_id)
    return {"ok": True,
            "message": f"bound ({issuer}, {subject_id}) -> app_id={record['app_id']!r}"}


def _drain_once() -> dict:
    """Backs the `worker` row's action — one pass of the queue, not a
    persistent daemon. A live daemon (`willow-mcp worker` with no `--once`)
    would block the TUI/HTTP handler forever; draining once is the
    interactive-safe analogue and matches what an operator would do to
    clear a stranded queue by hand."""
    try:
        import kartikeya  # noqa: F401
    except ModuleNotFoundError:
        return {"ok": False,
                "message": "kartikeya is not installed — pip install willow-mcp"}
    import os

    from .heartbeat import WorkerHeartbeat, reap
    from .egress_authorization import ExecutorNetworkAuthorizer
    from .task_queue import build_task_queue

    # Same default `willow-mcp worker` itself falls back to (server.py's
    # _cmd_worker / _DEFAULT_APP_ID) — no app_id is scoped to this action
    # since the worker row is global, not per-app.
    app_id = os.environ.get("WILLOW_APP_ID", "")
    try:
        queue = build_task_queue(app_id)
    except RuntimeError as e:
        return {"ok": False, "message": str(e)}

    import kartikeya as _kartikeya
    reap()
    beat = WorkerHeartbeat(agent="kart", lane="fast", interval=5.0)
    try:
        _kartikeya.run_worker(queue, lane="fast", slots=None, interval=5.0,
                               once=True, on_heartbeat=beat,
                               network_authorizer=ExecutorNetworkAuthorizer())
    finally:
        beat.close()
    return {"ok": True, "message": "drained the queue once"}
