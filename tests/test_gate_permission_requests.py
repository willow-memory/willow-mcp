"""Approval broker, stage 1b — a request may name a permission, not only a lease.

Stage 1 allowed `lease.` gates only, on the rule "activate a standing grant,
never create one". That rule is right for a lease and was too broad as a
principle: the first real need was a new seat asking for the six groups it
takes to do its job, and the only way to ask was six commands typed by hand.

The line this file pins is the one that actually matters. It is not between
`lease.` and `perm.` — it is between **asking and confirming**, plus a set of
groups the queue may never carry at all. The press stays the operator's act;
these tests check that what gets pressed is what it appears to be.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from willow_mcp import gates_actions, gates_panel, human_loop
from willow_mcp.gates_panel import GateRow


def _iso(delta_seconds: int) -> str:
    return (datetime.now(timezone.utc)
            + timedelta(seconds=delta_seconds)).isoformat().replace("+00:00", "Z")


@pytest.fixture
def store(tmp_path):
    from willow_mcp.db import Store

    return Store(store_root=str(tmp_path / "store"))


@pytest.fixture
def apps_root(tmp_path, monkeypatch):
    root = tmp_path / "mcp_apps"
    root.mkdir()
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(root))
    return root


def _manifest(apps_root, app_id: str, permissions: list[str]) -> None:
    d = apps_root / app_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "manifest.json").write_text(
        json.dumps({"app_id": app_id, "permissions": permissions}), encoding="utf-8"
    )


def _ask(store, *, app_id="binder", group="store_write", subject=None,
         ttl_seconds=1800):
    subject = subject or app_id
    gate_id = f"perm.{subject}.{group}"
    return human_loop.enqueue(
        store,
        kind=gates_panel.REQUEST_QUEUE_KIND,
        title=f"{app_id} needs {gate_id}",
        summary="file a record",
        source_agent=app_id,
        source_ref=gates_panel.encode_request(
            gate_id=gate_id, task_id="T1", nonce="n1",
            expires_at=_iso(ttl_seconds),
        ),
    )


@pytest.fixture
def no_writes(monkeypatch, store):
    """Record every set_permission call; there should be none on a refusal."""
    calls = []
    monkeypatch.setattr(gates_actions.manifest_admin, "set_permission",
                        lambda *a, **k: calls.append(a))
    monkeypatch.setattr("willow_mcp.db.Store", lambda *a, **k: store)
    return calls


# ── gate id parsing ──────────────────────────────────────────────────────────

def test_split_permission_gate():
    assert gates_panel.split_permission_gate("perm.binder.store_write") == (
        "binder", "store_write")


@pytest.mark.parametrize("gate_id", [
    "", "perm.", "perm.binder", "lease.binder", "perm..store_write",
    "perm.binder.", "binder.store_write",
])
def test_split_permission_gate_rejects_malformed(gate_id):
    assert gates_panel.split_permission_gate(gate_id) == ("", "")


def test_a_group_containing_no_dot_survives_the_split():
    """Split is bounded at 2 so the group is whatever follows, intact."""
    app, group = gates_panel.split_permission_gate("perm.a.markdownai_directives")
    assert (app, group) == ("a", "markdownai_directives")


# ── describe ─────────────────────────────────────────────────────────────────

def test_a_permission_request_is_now_pressable(store):
    _ask(store)
    spec = gates_actions.describe(gates_panel._request_rows(store)[0])
    assert spec.kind == "request_permission"
    assert spec.needs == ()


def test_an_expired_permission_request_still_has_no_action(store):
    _ask(store, ttl_seconds=-60)
    row = gates_panel._request_rows(store)[0]
    assert row.state == "warn"
    assert gates_actions.describe(row).kind == "none"


def test_an_unknown_gate_kind_is_still_refused():
    row = GateRow(id="request.x", label="gate request", scope="binding.whatever",
                  state="off", detail="")
    spec = gates_actions.describe(row)
    assert spec.kind == "none"
    assert "nothing else" in spec.reason


# ── apply ────────────────────────────────────────────────────────────────────

def test_approving_grants_the_group_and_closes_the_item(
        store, apps_root, monkeypatch):
    _manifest(apps_root, "binder", ["store_read"])
    item = _ask(store)
    row = gates_panel._request_rows(store)[0]

    granted = {}
    monkeypatch.setattr(gates_actions.manifest_admin, "set_permission",
                        lambda app, perm, on: granted.update(app=app, perm=perm, on=on))
    monkeypatch.setattr("willow_mcp.db.Store", lambda *a, **k: store)

    out = gates_actions.apply(row)
    assert out["ok"], out
    assert granted == {"app": "binder", "perm": "store_write", "on": True}
    assert item["id"] in out["message"]
    assert gates_panel._request_rows(store) == []


def test_approval_can_only_ever_grant_never_revoke(store, apps_root, monkeypatch):
    """_toggle_permission flips on the row's state. The target row is built
    here, not carried in, so a request cannot arrive as a revocation wearing
    an approval's clothes."""
    _manifest(apps_root, "binder", ["store_read"])
    _ask(store)
    row = gates_panel._request_rows(store)[0]
    row.state = "on"          # as if the row claimed the permission was held

    granted = {}
    monkeypatch.setattr(gates_actions.manifest_admin, "set_permission",
                        lambda app, perm, on: granted.update(on=on))
    monkeypatch.setattr("willow_mcp.db.Store", lambda *a, **k: store)

    gates_actions.apply(row)
    assert granted["on"] is True


@pytest.mark.parametrize("group", [
    "full_access", "orchestrator", "envelope_apply", "frank_write",
    "binding", "schema_admin", "tool_oracle_seal", "task_db",
])
def test_the_never_requestable_groups_are_refused(
        store, apps_root, no_writes, group):
    """The queue must not become a phishing surface: an agent should not be
    able to put 'grant me full_access' in front of a tired operator."""
    _manifest(apps_root, "binder", [])
    _ask(store, group=group)
    row = gates_panel._request_rows(store)[0]

    out = gates_actions.apply(row)
    assert out["ok"] is False
    assert "can never be requested" in out["message"]
    assert no_writes == []


def test_the_network_capability_flags_are_refused(store, apps_root, no_writes):
    from willow_mcp.gate import NET_PERMISSION

    _manifest(apps_root, "binder", [])
    _ask(store, group=NET_PERMISSION)
    out = gates_actions.apply(gates_panel._request_rows(store)[0])
    assert out["ok"] is False
    assert no_writes == []


def test_an_app_cannot_request_a_permission_for_another_app(
        store, apps_root, no_writes):
    """Laundering a grant through whichever app is trusted enough to enqueue."""
    _manifest(apps_root, "willow", [])
    _ask(store, app_id="binder", subject="willow", group="store_write")
    out = gates_actions.apply(gates_panel._request_rows(store)[0])
    assert out["ok"] is False
    assert "names its own app" in out["message"]
    assert no_writes == []


def test_an_already_held_group_writes_nothing_and_closes(
        store, apps_root, no_writes):
    """set_permission is idempotent, but under signing enforcement a rewrite
    discards a valid signature and re-signs. Say so instead."""
    _manifest(apps_root, "binder", ["store_write"])
    _ask(store)
    out = gates_actions.apply(gates_panel._request_rows(store)[0])
    assert out["ok"] is True
    assert "already holds" in out["message"]
    assert no_writes == []
    assert gates_panel._request_rows(store) == []


def test_an_expired_request_is_refused_against_the_queue(
        store, apps_root, no_writes):
    _manifest(apps_root, "binder", [])
    item = _ask(store, ttl_seconds=-60)
    forged = GateRow(id=f"request.{item['id']}", label="gate request",
                     scope="perm.binder.store_write", state="off", detail="fine")
    out = gates_actions.apply(forged)
    assert out["ok"] is False
    assert "expired" in out["message"]
    assert no_writes == []


def test_a_resolved_request_cannot_be_replayed(store, apps_root, no_writes):
    _manifest(apps_root, "binder", [])
    item = _ask(store)
    row = gates_panel._request_rows(store)[0]
    human_loop.resolve(store, item["id"], resolved_by="operator")

    out = gates_actions.apply(row)
    assert out["ok"] is False
    assert "no longer open" in out["message"]
    assert no_writes == []


def test_lease_requests_still_work_after_the_widening(store, apps_root, monkeypatch):
    """Stage 1's path must not have drifted when the lookup was factored out."""
    from willow_mcp.gate import NET_PERMISSION

    _manifest(apps_root, "kart", [NET_PERMISSION])
    human_loop.enqueue(
        store, kind=gates_panel.REQUEST_QUEUE_KIND, title="kart needs egress",
        summary="push", source_agent="kart",
        source_ref=gates_panel.encode_request(
            gate_id="lease.kart", task_id="T9", nonce="n9",
            expires_at=_iso(1800)),
    )
    row = gates_panel._request_rows(store)[0]
    assert gates_actions.describe(row).kind == "request_grant"

    granted = {}
    monkeypatch.setattr(gates_actions.lease, "grant",
                        lambda app, ttl, **k: granted.update(app=app) or {"expires_at": "x"})
    monkeypatch.setattr("willow_mcp.db.Store", lambda *a, **k: store)

    out = gates_actions.apply(row, {"ttl": "30m", "reason": "push"})
    assert out["ok"], out
    assert granted["app"] == "kart"
