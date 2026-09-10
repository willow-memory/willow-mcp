"""The denial site is the producer: being refused is what files the ask.

`docs/design/egress-request-seam.md` records what the missing producer cost —
"a lease expired 2026-07-21, an agent needed `gh pr create`, and the entire
request mechanism was the agent pasting a shell command into chat and hoping.
Nothing was queued. Nothing was recorded. Nothing resumed."

The design's answer is that the ask is a side effect of the refusal rather than
a tool an agent calls: a caller refused for a missing lease has already proved
it needed the thing, so it does not have to be trusted to say so. These tests
hold that the refusal still refuses, and that the row now exists.
"""
from __future__ import annotations

import json

import pytest

from willow_mcp import gates_panel
from willow_mcp.db import Store


@pytest.fixture()
def store(tmp_path):
    return Store(store_root=str(tmp_path / "store"))


def _denial_note(monkeypatch, store, app_id="kart"):
    """Run the shared denial-note path against an isolated store."""
    from willow_mcp import gate_request

    real = gate_request.request_lease
    monkeypatch.setattr(
        gate_request, "request_lease",
        lambda a, **kw: real(a, **{**kw, "store": store}),
    )
    return gate_request.note_for_lease_denial(app_id)


def test_the_denial_note_queues_a_row(monkeypatch, store):
    note = _denial_note(monkeypatch, store)

    assert "queued for the operator" in note
    rows = gates_panel.open_requests(store)
    assert len(rows) == 1
    assert rows[0]["request"]["gate_id"] == "lease.kart"


def test_the_note_names_the_request_the_operator_will_see(monkeypatch, store):
    note = _denial_note(monkeypatch, store)
    queued_id = gates_panel.open_requests(store)[0]["id"]

    # The id in the message must be the id in the queue, or the operator is
    # told to look for something that is not there.
    assert str(queued_id) in note


def test_a_second_denial_says_already_waiting(monkeypatch, store):
    first = _denial_note(monkeypatch, store)
    second = _denial_note(monkeypatch, store)

    assert "queued for the operator" in first
    assert "already waiting" in second
    assert len(gates_panel.open_requests(store)) == 1


# ── the refusal is unchanged ─────────────────────────────────────────────────

@pytest.fixture()
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path / "mcp_apps"))
    # These tests reach the real denial sites, which build their own Store()
    # rather than taking one — so WILLOW_HOME alone does not isolate the queue
    # they write to, and a row left here surfaces as a `requests` row in some
    # later test's panel. Pin the store root explicitly.
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    monkeypatch.delenv("WILLOW_SETTINGS_GLOBAL", raising=False)
    monkeypatch.delenv("WILLOW_MCP_STRICT_TRUST_ROOT", raising=False)
    monkeypatch.delenv("WILLOW_MCP_FLEET_PG_DB", raising=False)
    return tmp_path


def _app_wanting_egress(home, permission: str, app_id: str) -> str:
    """An app that holds the permission and the consent, but not the lease —
    the one state in which the lease branch is the branch that runs."""
    app_dir = home / "mcp_apps" / app_id
    app_dir.mkdir(parents=True, exist_ok=True)
    (app_dir / "manifest.json").write_text(json.dumps({"permissions": [permission]}))
    (home / "settings.global.json").write_text(
        json.dumps({"version": 1, "consent": {"internet": True}}))
    return app_id


def test_the_lease_denial_carries_the_queued_ask(home):
    """End to end at a real denial site: refused for want of a lease, and the
    refusal itself says an ask is now waiting."""
    from willow_mcp import gate, web_egress

    app = _app_wanting_egress(home, gate.WEB_NET_PERMISSION, "askapp-web")
    denial = web_egress.egress_denial(app)

    assert denial is not None
    assert denial["error"].startswith("lease_denied")
    assert "queued for the operator" in denial["error"]


def test_the_denial_still_refuses_when_the_queue_is_broken(home, monkeypatch):
    """The strongest form of fail-closed: the queue raises on every write and
    the caller still refuses cleanly, rather than a traceback coming out of a
    security check.

    `docs/design/egress-request-seam.md`: "The denial stays fail-closed. If
    enqueue fails, the call is still denied."
    """
    from willow_mcp import gate, human_loop, web_egress

    def _boom(*_a, **_k):
        raise RuntimeError("queue is on fire")

    monkeypatch.setattr(human_loop, "enqueue", _boom)

    app = _app_wanting_egress(home, gate.WEB_NET_PERMISSION, "askapp-broken-queue")
    denial = web_egress.egress_denial(app)

    assert denial is not None
    assert denial["error"].startswith("lease_denied")
    # No claim of a queued request, because there is no row to back it.
    assert "queued for the operator" not in denial["error"]


def test_integration_egress_denial_also_asks(home):
    from willow_mcp import gate, integrations

    app = _app_wanting_egress(home, gate.INTEGRATION_NET_PERMISSION, "askapp-integration")
    denial = integrations.egress_denial(app)

    assert denial is not None
    assert denial["error"].startswith("lease_denied")
    assert "queued for the operator" in denial["error"]
