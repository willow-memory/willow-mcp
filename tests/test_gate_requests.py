"""Approval broker, stage 1 — a blocked caller can ask, and the ask is a row.

`docs/design/approval-broker.md` §6 in willows-grove. The property under test
is narrow and worth stating plainly: a request **activates a standing grant,
never creates one**. The manifest capability is the grant; the lease is the
clock on it. Everything else here is in service of that.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from willow_mcp import gates_actions, gates_panel, human_loop
from willow_mcp.gate import NET_PERMISSION
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


def _ask(store, *, app_id="kart", gate_id="lease.kart", task_id="ABCD1234",
         nonce="deadbeef", ttl_seconds=1800, summary="push the branch"):
    return human_loop.enqueue(
        store,
        kind=gates_panel.REQUEST_QUEUE_KIND,
        title=f"{app_id} needs {gate_id}",
        summary=summary,
        source_agent=app_id,
        source_ref=gates_panel.encode_request(
            gate_id=gate_id, task_id=task_id, nonce=nonce,
            expires_at=_iso(ttl_seconds),
        ),
    )


# ── encoding ─────────────────────────────────────────────────────────────────

def test_encode_decode_roundtrip():
    ref = gates_panel.encode_request(gate_id="lease.kart", task_id="T1",
                                     nonce="n1", expires_at="2026-09-09T09:00:00Z")
    assert gates_panel.decode_request(ref) == {
        "gate_id": "lease.kart", "task_id": "T1", "nonce": "n1",
        "expires_at": "2026-09-09T09:00:00Z",
    }


@pytest.mark.parametrize("ref", [
    "", "an ordinary source ref", "gate-request:", "gate-request:{not json",
    "gate-request:[]", 'gate-request:{"task_id":"T1"}',       # no gate_id
    'gate-request:{"gate_id":"","task_id":"T1"}',             # empty gate_id
])
def test_decode_returns_none_rather_than_raising(ref):
    """A queue reader must not die on a blob somebody hand-edited."""
    assert gates_panel.decode_request(ref) is None


def test_an_ordinary_queue_item_is_not_a_request(store):
    human_loop.enqueue(store, kind="review", title="look at this",
                       source_agent="willow", source_ref="pr/49")
    assert gates_panel.open_requests(store) == []


# ── rows ─────────────────────────────────────────────────────────────────────

def test_a_request_becomes_a_pressable_row(store):
    item = _ask(store)
    rows = gates_panel._request_rows(store)
    assert len(rows) == 1
    row = rows[0]
    assert row.id == f"request.{item['id']}"
    assert row.scope == "lease.kart"
    assert row.state == "off"
    assert row.category == "requests"
    assert "kart asks for lease.kart" in row.detail
    assert "push the branch" in row.detail
    assert "[task ABCD1234]" in row.detail
    assert row.remaining_seconds and row.remaining_seconds > 0


def test_requests_sort_into_their_own_category_first():
    assert gates_panel.CATEGORY_ORDER[0][0] == "requests"
    assert gates_panel._category("request.abc", "gate request") == "requests"


def test_state_label_reads_asked_not_off():
    assert gates_panel._state_label("request.abc", "off") == "ASKED"
    assert gates_panel._state_label("request.abc", "warn") == "STALE"


def test_an_expired_request_is_shown_stale_not_hidden(store):
    """A request that quietly vanished would teach the operator to distrust
    the queue. It goes `warn`, and it says why."""
    _ask(store, ttl_seconds=-60)
    row = gates_panel._request_rows(store)[0]
    assert row.state == "warn"
    assert "EXPIRED" in row.detail
    assert row.remaining_seconds is None
    assert gates_actions.describe(row).kind == "none"


def test_resolved_requests_stop_rendering(store):
    item = _ask(store)
    human_loop.resolve(store, item["id"], resolved_by="operator")
    assert gates_panel._request_rows(store) == []


# ── describe ─────────────────────────────────────────────────────────────────

def test_a_live_lease_request_needs_ttl_and_reason(store):
    _ask(store)
    spec = gates_actions.describe(gates_panel._request_rows(store)[0])
    assert spec.kind == "request_grant"
    assert spec.needs == ("ttl", "reason")


def test_a_permission_request_is_actionable_since_stage_1b():
    """Stage 1 refused every `perm.` request here, on "activate, never create".

    Stage 1b narrowed that: the line is between asking and confirming, not
    between a lease and a permission, because the press is the operator's act
    either way. What a permission request may and may not name is pinned in
    tests/test_gate_permission_requests.py — including the groups the queue may
    never carry. This test is left behind deliberately, so the rule that used
    to live here is visibly superseded rather than silently gone.
    """
    row = GateRow(id="request.x", label="gate request",
                  scope="perm.binder.store_write", state="off", detail="")
    assert gates_actions.describe(row).kind == "request_permission"


def test_a_gate_that_is_neither_lease_nor_permission_has_no_action():
    row = GateRow(id="request.x", label="gate request", scope="binding.whatever",
                  state="off", detail="")
    spec = gates_actions.describe(row)
    assert spec.kind == "none"
    assert "nothing else" in spec.reason


# ── apply ────────────────────────────────────────────────────────────────────

def test_approving_grants_the_lease_and_closes_the_item(store, apps_root, monkeypatch):
    _manifest(apps_root, "kart", [NET_PERMISSION])
    monkeypatch.setattr(gates_actions, "Store", None, raising=False)
    item = _ask(store)
    row = gates_panel._request_rows(store)[0]

    granted = {}

    def _fake_grant(app_id, ttl_seconds, *, issuer="", reason=""):
        granted.update(app_id=app_id, ttl=ttl_seconds, issuer=issuer, reason=reason)
        return {"expires_at": _iso(ttl_seconds)}

    monkeypatch.setattr(gates_actions.lease, "grant", _fake_grant)
    monkeypatch.setattr("willow_mcp.db.Store", lambda *a, **k: store)

    out = gates_actions.apply(row, {"ttl": "30m", "reason": "push #49"})
    assert out["ok"], out
    assert granted["app_id"] == "kart"
    assert granted["reason"] == "push #49"
    assert item["id"] in out["message"]
    # states-not-deletions: the row is closed, not removed
    assert gates_panel._request_rows(store) == []
    closed = human_loop.list_queue(store, status="resolved")
    assert closed and "ABCD1234" in closed[0]["note"]


def test_an_app_without_the_capability_is_refused(store, apps_root, monkeypatch):
    """The whole rule. `kart` here holds no task_net, so granting a lease
    would CREATE the capability rather than start its clock."""
    _manifest(apps_root, "kart", ["store_read"])
    _ask(store)
    row = gates_panel._request_rows(store)[0]

    called = []
    monkeypatch.setattr(gates_actions.lease, "grant",
                        lambda *a, **k: called.append(a))
    monkeypatch.setattr("willow_mcp.db.Store", lambda *a, **k: store)

    out = gates_actions.apply(row, {"ttl": "30m", "reason": "push"})
    assert out["ok"] is False
    assert NET_PERMISSION in out["message"]
    assert "create the capability" in out["message"]
    assert called == []


def test_an_app_cannot_ask_for_another_apps_lease(store, apps_root, monkeypatch):
    _manifest(apps_root, "kart", [NET_PERMISSION])
    _ask(store, app_id="jeles", gate_id="lease.kart")
    row = gates_panel._request_rows(store)[0]

    called = []
    monkeypatch.setattr(gates_actions.lease, "grant",
                        lambda *a, **k: called.append(a))
    monkeypatch.setattr("willow_mcp.db.Store", lambda *a, **k: store)

    out = gates_actions.apply(row, {"ttl": "30m", "reason": "push"})
    assert out["ok"] is False
    assert "names its own app" in out["message"]
    assert called == []


def test_an_expired_request_is_refused_even_if_the_row_says_otherwise(
        store, apps_root, monkeypatch):
    """`describe()` refuses a stale row, but the row is an argument — a caller
    can hand `apply()` one it built itself, so the expiry is re-checked
    against the queue rather than trusted from the row."""
    _manifest(apps_root, "kart", [NET_PERMISSION])
    item = _ask(store, ttl_seconds=-60)
    forged = GateRow(id=f"request.{item['id']}", label="gate request",
                     scope="lease.kart", state="off", detail="looks fine")

    called = []
    monkeypatch.setattr(gates_actions.lease, "grant",
                        lambda *a, **k: called.append(a))
    monkeypatch.setattr("willow_mcp.db.Store", lambda *a, **k: store)

    out = gates_actions.apply(forged, {"ttl": "30m", "reason": "push"})
    assert out["ok"] is False
    assert "expired" in out["message"]
    assert called == []


def test_a_request_that_is_no_longer_open_cannot_be_replayed(
        store, apps_root, monkeypatch):
    _manifest(apps_root, "kart", [NET_PERMISSION])
    item = _ask(store)
    row = gates_panel._request_rows(store)[0]
    human_loop.resolve(store, item["id"], resolved_by="operator")

    called = []
    monkeypatch.setattr(gates_actions.lease, "grant",
                        lambda *a, **k: called.append(a))
    monkeypatch.setattr("willow_mcp.db.Store", lambda *a, **k: store)

    out = gates_actions.apply(row, {"ttl": "30m", "reason": "push"})
    assert out["ok"] is False
    assert "no longer open" in out["message"]
    assert called == []
