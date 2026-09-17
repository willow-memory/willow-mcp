"""`pr.<owner>/<repo>:<base>`: an ask that reaches the gates panel, and a press
that grants nothing (yet).

Same posture as `push.<...>` (gap `5ecb87cfdf56`, slice 2b PR 1). The
`pr_executor` denial site was still producing a `kind=review` row that
`willow-mcp gates` did not consume; the migration to `gate_request` uses
`pr.<owner>/<repo>:<base>` because the ``pr.open`` envelope's bounds are
``base_branches`` — the head is task-specific and rides in the summary, not
the gate id.
"""
from __future__ import annotations

from willow_mcp import gates_actions, gates_panel
from willow_mcp.gates_panel import GateRow


def _request_row(gate_id: str, *, state: str = "off", note: str | None = None) -> GateRow:
    return GateRow(id="request.42", label="gate request", scope=gate_id,
                   state=state, detail="", timer_shape="lease",
                   action_note=note)


def test_pr_is_requestable():
    assert "pr." in gates_panel.REQUESTABLE_PREFIXES


def test_pr_is_not_pressable():
    assert not gates_panel.is_pressable("pr.willow-memory/willow-bot:master")
    # Regression guard for the pressable seams.
    assert gates_panel.is_pressable("lease.willow")
    assert gates_panel.is_pressable("perm.willow.task_net")


def test_pressing_a_pr_request_does_nothing():
    spec = gates_actions.describe(
        _request_row("pr.willow-memory/willow-bot:master",
                     note="not pressable — propose then ratify"))
    assert spec.kind == "none"
    assert spec.needs == ()


def test_apply_refuses_and_does_not_raise():
    result = gates_actions.apply(
        _request_row("pr.willow-memory/willow-bot:master",
                     note="not pressable — propose then ratify"))
    assert result["ok"] is False


def test_an_expired_pr_row_still_reports_expiry_first():
    spec = gates_actions.describe(
        _request_row("pr.willow-memory/willow-bot:master",
                     state="warn", note="expired — dismiss it"))
    assert spec.kind == "none"
    assert "expired" in spec.reason


def test_split_pr_gate_parses_owner_repo_base():
    """A well-formed gate id parses back into ``(repo, base)``; a malformed
    one parses to the empty pair. Base names may carry ``/`` (`release/*`
    picks a `release/2.45.1` base in practice) — same rightmost-``:``
    rule ``split_push_gate`` uses."""
    assert gates_panel.split_pr_gate(
        "pr.willow-memory/willow-bot:master") == ("willow-memory/willow-bot", "master")
    assert gates_panel.split_pr_gate(
        "pr.willow-memory/willow-bot:release/2.45.1") == (
            "willow-memory/willow-bot", "release/2.45.1")
    # Wrong prefix.
    assert gates_panel.split_pr_gate("lease.willow") == ("", "")
    # No base.
    assert gates_panel.split_pr_gate("pr.willow-memory/willow-bot:") == ("", "")
    # No colon at all.
    assert gates_panel.split_pr_gate("pr.willow-memory/willow-bot") == ("", "")
    # No `owner/` in the repo half.
    assert gates_panel.split_pr_gate("pr.bare:master") == ("", "")


def test_split_pr_update_gate_parses_owner_repo_number():
    """`pr.<owner>/<repo>#<number>` (verb 16, `pr.update`, sealed
    `783bab4e`) parses back into ``(repo, number)``; a malformed one parses
    to the empty pair. Shares the `pr.` prefix with `pr.open`'s `:<base>`
    shape, told apart by separator."""
    assert gates_panel.split_pr_update_gate(
        "pr.willow-memory/willow-bot#31") == ("willow-memory/willow-bot", "31")
    # Wrong prefix.
    assert gates_panel.split_pr_update_gate("lease.willow") == ("", "")
    # No number.
    assert gates_panel.split_pr_update_gate("pr.willow-memory/willow-bot#") == ("", "")
    # No `#` at all.
    assert gates_panel.split_pr_update_gate("pr.willow-memory/willow-bot") == ("", "")
    # No `owner/` in the repo half.
    assert gates_panel.split_pr_update_gate("pr.bare#31") == ("", "")
    # Non-numeric "number".
    assert gates_panel.split_pr_update_gate("pr.willow-memory/willow-bot#thirty-one") == ("", "")


def test_pr_update_gate_is_requestable_and_not_pressable():
    from willow_mcp import gate_request

    assert gate_request.check_requestable("pr.willow-memory/willow-bot#31") is None
    assert not gates_panel.is_pressable("pr.willow-memory/willow-bot#31")


def test_malformed_pr_gate_is_refused_by_neither_shape():
    from willow_mcp import gate_request

    refusal = gate_request.check_requestable("pr.willow-memory/willow-bot")
    assert refusal is not None
    assert "pr.<owner>/<repo>:<base>" in refusal and "pr.<owner>/<repo>#<number>" in refusal


def test_the_row_names_the_pr_update_envelope_for_the_hash_shape(monkeypatch, tmp_path):
    """The `#<number>` shape surfaces the `pr.update` ritual, not
    `pr.open`'s — the operator needs to know which envelope kind to
    propose."""
    home = tmp_path / "box"
    home.mkdir()
    monkeypatch.setenv("WILLOW_HOME", str(home))

    item = {
        "id": "43",
        "source_agent": "hanuman",
        "summary": (
            "hanuman asked to update pull request willow-memory/willow-bot#31 "
            "and was refused: EAMBIG: outside the envelope's bounds. Ratify a "
            "pr.update envelope with these bounds (repo="
            "'willow-memory/willow-bot', fields=[...]) and the agent can ask "
            "again."
        ),
        "source_ref": gates_panel.encode_request(
            gate_id="pr.willow-memory/willow-bot#31",
            task_id="T1", nonce="n",
            expires_at="2099-01-01T00:00:00Z"),
    }
    monkeypatch.setattr(gates_panel, "open_requests",
                        lambda store=None: [{**item, "request":
                                             gates_panel.decode_request(item["source_ref"])}])

    row = gates_panel._request_rows()[0]
    assert row.state == "off"
    assert row.scope == "pr.willow-memory/willow-bot#31"
    assert "not pressable" in row.action_note
    assert "pr.update envelope" in row.action_note
    assert "pr.open envelope" not in row.action_note
    assert "envelope_propose" in row.action_note
    assert "willow-mcp envelope ratify" in row.action_note


def test_the_row_names_the_pr_open_envelope_in_the_action_note(monkeypatch, tmp_path):
    """The two-step ritual the row surfaces is specifically ``pr.open`` (not
    ``push``), because `envelope_propose` needs to hear which envelope kind
    the operator is being asked to propose."""
    home = tmp_path / "box"
    home.mkdir()
    monkeypatch.setenv("WILLOW_HOME", str(home))

    item = {
        "id": "42",
        "source_agent": "kart",
        "summary": (
            "kart asked to open a pull request on willow-memory/willow-bot "
            "from 'feat/x' into 'master' and was refused: EAMBIG: outside "
            "the envelope's bounds. Ratify a pr.open envelope with these "
            "bounds (repo='willow-memory/willow-bot', base_branches=['master']) "
            "and the agent can ask again."
        ),
        "source_ref": gates_panel.encode_request(
            gate_id="pr.willow-memory/willow-bot:master",
            task_id="T1", nonce="n",
            expires_at="2099-01-01T00:00:00Z"),
    }
    monkeypatch.setattr(gates_panel, "open_requests",
                        lambda store=None: [{**item, "request":
                                             gates_panel.decode_request(item["source_ref"])}])

    row = gates_panel._request_rows()[0]
    assert row.state == "off"
    assert row.scope == "pr.willow-memory/willow-bot:master"
    assert "not pressable" in row.action_note
    assert "pr.open envelope" in row.action_note
    assert "envelope_propose" in row.action_note
    assert "willow-mcp envelope ratify" in row.action_note
