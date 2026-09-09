"""`attest.<session_id>`: an ask that reaches the panel, and a press that grants
nothing.

The hard boundary this file exists to hold: session attestation is a signature
made with the operator's own key at their own terminal. Delegated signature is
§5b / approval-broker stage 2 and is NOT ratified. So the row must surface the
ask — the thing the operator actually watches — while remaining impossible to
approve by pressing.
"""
from __future__ import annotations

import pytest

from willow_mcp import gates_actions, gates_panel
from willow_mcp.gates_panel import GateRow


def _request_row(gate_id: str, *, state: str = "off", note: str | None = None) -> GateRow:
    return GateRow(id="request.42", label="gate request", scope=gate_id,
                   state=state, detail="", timer_shape="lease",
                   action_note=note)


def test_attest_is_requestable():
    assert "attest." in gates_panel.REQUESTABLE_PREFIXES


def test_attest_is_not_pressable():
    assert not gates_panel.is_pressable("attest.session_abc")
    assert gates_panel.is_pressable("lease.willow")
    assert gates_panel.is_pressable("perm.willow.task_net")


def test_pressing_an_attest_request_does_nothing():
    """kind='none' is the whole security property. Any other kind here would be
    a delegated signature, which nobody has ratified."""
    spec = gates_actions.describe(_request_row("attest.session_abc",
                                               note="run: willow-mcp ..."))
    assert spec.kind == "none"
    assert spec.needs == ()
    assert "willow-mcp" in spec.reason


def test_apply_refuses_and_does_not_raise():
    result = gates_actions.apply(_request_row("attest.session_abc", note="run: X"))
    assert result["ok"] is False


def test_a_lease_request_still_presses():
    """Regression guard on the new branch: it must not swallow the two gates
    that DO have an approval half."""
    assert gates_actions.describe(_request_row("lease.willow")).kind == "request_grant"
    assert gates_actions.describe(
        _request_row("perm.willow.task_net")).kind == "request_permission"


def test_an_expired_attest_row_still_reports_expiry_first():
    spec = gates_actions.describe(
        _request_row("attest.s", state="warn", note="expired — dismiss it"))
    assert spec.kind == "none"
    assert "expired" in spec.reason


def test_split_attest_gate_keeps_dots_in_the_session_id():
    """A session_id is opaque and may contain dots; only the first separator is
    structural."""
    assert gates_panel.split_attest_gate("attest.session_01.9So") == "session_01.9So"
    assert gates_panel.split_attest_gate("lease.willow") == ""


def test_the_row_carries_a_runnable_command(monkeypatch, tmp_path):
    """The point of the row: the operator sees the exact line to paste, built
    from the server's own resolved environment."""
    home = tmp_path / "box"
    home.mkdir()
    monkeypatch.setenv("WILLOW_HOME", str(home))
    monkeypatch.setenv("WILLOW_KEYRING", str(home / "verifiers.json"))

    item = {
        "id": "42",
        "source_agent": "willow",
        "summary": "seat is blocked on attestation",
        "source_ref": gates_panel.encode_request(
            gate_id="attest.session_abc", task_id="", nonce="n",
            expires_at="2099-01-01T00:00:00Z"),
    }
    monkeypatch.setattr(gates_panel, "open_requests",
                        lambda store=None: [{**item, "request":
                                             gates_panel.decode_request(item["source_ref"])}])

    row = gates_panel._request_rows()[0]
    assert row.state == "off"
    assert f"WILLOW_HOME={home}" in row.action_note
    assert "sign-session session_abc" in row.action_note
    assert "not pressable" in row.action_note
