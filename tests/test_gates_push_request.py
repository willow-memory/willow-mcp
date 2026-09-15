"""`push.<owner>/<repo>:<branch>`: an ask that reaches the gates panel, and a
press that grants nothing (yet).

The boundary this file holds: a brokered-push refusal (gap `5ecb87cfdf56`,
slice 2b) surfaces on the same seam as every other operator decision —
`gates_panel.REQUESTABLE_PREFIXES` — rather than in the `kind=review` queue
where the old `push_executor._file_ask` put it, invisible to `willow-mcp
gates`. But the row is INFORMATIONAL. One-press-to-ratify would need an
attributed operator session, which `gates_actions.apply()` does not run
inside; that wiring is a follow-up bite.
"""
from __future__ import annotations

from willow_mcp import gates_actions, gates_panel
from willow_mcp.gates_panel import GateRow


def _request_row(gate_id: str, *, state: str = "off", note: str | None = None) -> GateRow:
    return GateRow(id="request.42", label="gate request", scope=gate_id,
                   state=state, detail="", timer_shape="lease",
                   action_note=note)


def test_push_is_requestable():
    assert "push." in gates_panel.REQUESTABLE_PREFIXES


def test_push_is_not_pressable():
    assert not gates_panel.is_pressable("push.willow-memory/willow-bot:feat/x")
    # Regression guard for the other two seams' rows.
    assert gates_panel.is_pressable("lease.willow")
    assert gates_panel.is_pressable("perm.willow.task_net")


def test_pressing_a_push_request_does_nothing():
    """The row is informational — `kind='none'` here is the whole security
    property, same as `attest.`. Anything else would delegate propose+ratify
    to a caller that is not an attributed operator session."""
    spec = gates_actions.describe(
        _request_row("push.willow-memory/willow-bot:feat/x",
                     note="not pressable — propose then ratify"))
    assert spec.kind == "none"
    assert spec.needs == ()
    assert "not pressable" in spec.reason.lower() or "pressable" in spec.reason.lower()


def test_apply_refuses_and_does_not_raise():
    result = gates_actions.apply(
        _request_row("push.willow-memory/willow-bot:feat/x",
                     note="not pressable — propose then ratify"))
    assert result["ok"] is False


def test_an_expired_push_row_still_reports_expiry_first():
    spec = gates_actions.describe(
        _request_row("push.willow-memory/willow-bot:feat/x",
                     state="warn", note="expired — dismiss it"))
    assert spec.kind == "none"
    assert "expired" in spec.reason


def test_split_push_gate_parses_owner_repo_branch():
    """A well-formed gate id parses back into ``(repo, branch)`` and a
    malformed one parses to the empty pair — the read path treats bad input
    as absent, never as some plausible-looking half-shape."""
    assert gates_panel.split_push_gate(
        "push.willow-memory/willow-bot:feat/x") == ("willow-memory/willow-bot", "feat/x")
    # Branch may contain slashes (feature branches often do); the rightmost
    # ``:`` is structural.
    assert gates_panel.split_push_gate(
        "push.willow-memory/willow-bot:release/2.45.1") == (
            "willow-memory/willow-bot", "release/2.45.1")
    # Wrong prefix.
    assert gates_panel.split_push_gate("lease.willow") == ("", "")
    # No branch.
    assert gates_panel.split_push_gate("push.willow-memory/willow-bot:") == ("", "")
    # No colon at all.
    assert gates_panel.split_push_gate("push.willow-memory/willow-bot") == ("", "")
    # No `owner/` in the repo half — a `git.push` bound is always `org/name`.
    assert gates_panel.split_push_gate("push.bare:feat/x") == ("", "")


def test_the_row_carries_the_propose_and_ratify_ritual(monkeypatch, tmp_path):
    """The point of the row: the operator sees the exact two-step ritual
    (propose via the MCP tool, then `willow-mcp envelope ratify` from a
    shell), because `envelope propose` is orchestrator-attributed and has no
    bare-CLI form."""
    home = tmp_path / "box"
    home.mkdir()
    monkeypatch.setenv("WILLOW_HOME", str(home))

    item = {
        "id": "42",
        "source_agent": "kart",
        "summary": (
            "kart asked to push branch 'feat/x' of willow-memory/willow-bot "
            "to 'origin' and was refused: EAMBIG: outside the envelope's "
            "bounds (fields: branches). Ratify a git.push envelope with these "
            "bounds (repo='willow-memory/willow-bot', branches=['feat/x'], "
            "remote='origin', force=false) and the agent can ask again."
        ),
        "source_ref": gates_panel.encode_request(
            gate_id="push.willow-memory/willow-bot:feat/x",
            task_id="T1", nonce="n",
            expires_at="2099-01-01T00:00:00Z"),
    }
    monkeypatch.setattr(gates_panel, "open_requests",
                        lambda store=None: [{**item, "request":
                                             gates_panel.decode_request(item["source_ref"])}])

    row = gates_panel._request_rows()[0]
    assert row.state == "off"
    assert row.scope == "push.willow-memory/willow-bot:feat/x"
    assert "not pressable" in row.action_note
    # Both halves of the ritual are named — the propose has no CLI form and
    # the ratify does.
    assert "envelope_propose" in row.action_note
    assert "willow-mcp envelope ratify" in row.action_note
