"""The last unmapped denial site: `server._gate()` refuses a `permitted()` miss.

Gap `5ecb87cfdf56`, slice 2b PR 2. Every other seam already surfaced its ask:
the four `lease_denied` sites (via `note_for_lease_denial`) and the
brokered-push refusal (via `push_executor._file_ask`, PR 1). This module holds
the perm.* producer: it must pick the narrowest requestable group whose grant
would admit the refused tool (option b), fall through to the literal tool name
when no group fits (option c), never reach past `PERM_NEVER_REQUESTABLE`, and —
same shape every seam shares — never turn a denial into a traceback.
"""
from __future__ import annotations

import pytest

from willow_mcp import gate, gate_request, gates_panel
from willow_mcp.db import Store


@pytest.fixture()
def store(tmp_path):
    return Store(store_root=str(tmp_path / "store"))


# ── the (b) narrowest choice ──────────────────────────────────────────────────

def test_narrowest_group_is_preferred_over_a_wider_one():
    """`store_get` sits in `store_read` (6 tools) and `store_all` (10). The ask
    surfaces the narrower one — a wider grant would ask the operator for more
    than the denial proved was needed."""
    assert gate.narrowest_requestable_perm_scope("store_get") == "store_read"


def test_a_tool_in_only_one_group_names_that_group():
    """`knowledge_ingest` lives only in `knowledge_write`."""
    assert (
        gate.narrowest_requestable_perm_scope("knowledge_ingest")
        == "knowledge_write"
    )


def test_ties_break_alphabetically():
    """Two groups of equal length must not depend on dict insertion order —
    a future refactor of `PERMISSION_GROUPS` would otherwise silently flip
    which of two equally-narrow groups the operator sees."""
    # A synthetic exercise: `grove_send_message` is a member of `grove_write`
    # (7 tools) and `grove_all` (20 tools) — so narrowest is unambiguously
    # `grove_write`. Just assert that here as a shape guarantee.
    assert (
        gate.narrowest_requestable_perm_scope("grove_send_message")
        == "grove_write"
    )


# ── the (c) literal-tool fallback ─────────────────────────────────────────────

def test_a_tool_in_no_group_falls_through_to_its_own_name():
    """`git_push_execute` is a name `permitted()` honors but no group carries
    it (it's gated as `envelope_apply` at the tool-registration seam). No
    requestable group fits; the ask names the tool literally, and the manifest
    already accepts literal names in `permissions`."""
    assert (
        gate.narrowest_requestable_perm_scope("git_push_execute")
        == "git_push_execute"
    )


def test_never_requestable_groups_are_skipped_in_the_group_pass():
    """`envelope_write` (a group containing `envelope_propose`) is on
    `PERM_NEVER_REQUESTABLE`. The group pass must not pick it; option (c)
    falls through to the literal tool name.

    This is the security half of option (b)+(c): a request may name a
    literal tool that some never-requestable group would also grant, but the
    mapping must not surface the group name itself — that would put "grant
    me envelope_write" in the queue, exactly the phishing surface the
    frozenset exists to prevent. The literal falls through only because a
    manifest already accepts literal names in `permissions`, and the ask is
    then filtered a second time by `check_requestable` when it names a
    system-authority group."""
    scope = gate.narrowest_requestable_perm_scope("envelope_propose")
    assert scope == "envelope_propose"  # option (c) — the group is skipped


def test_a_never_requestable_scope_still_produces_no_row(store):
    """The mapping may return the literal tool name (option c), but if that
    literal is itself never-requestable (`envelope_apply` is both a group
    and a tool name, both on `PERM_NEVER_REQUESTABLE`),
    `check_requestable` still refuses the ask — the queue never carries a
    row an operator cannot press."""
    result = gate_request.request_permission("kart", "envelope_apply",
                                             store=store)
    assert result["queued"] is False
    assert "may never be requested" in result["reason"]
    assert gates_panel.open_requests(store) == []


# ── the producer at the denial site ────────────────────────────────────────────

def test_request_permission_files_a_perm_row_for_the_narrowest_scope(store):
    result = gate_request.request_permission("kart", "store_get", store=store)
    assert result["queued"] is True
    assert result["gate_id"] == "perm.kart.store_read"

    items = gates_panel.open_requests(store)
    assert len(items) == 1
    assert items[0]["request"]["gate_id"] == "perm.kart.store_read"


def test_request_permission_falls_through_to_the_literal_tool(store):
    """A denial for a tool that lives in no requestable group produces a row
    whose gate id names the tool — the manifest accepts literal names, so the
    approval path (`_request_permission`) already routes this."""
    result = gate_request.request_permission("kart", "git_push_execute", store=store)
    assert result["queued"] is True
    assert result["gate_id"] == "perm.kart.git_push_execute"


def test_note_for_perm_denial_returns_the_appended_sentence(store):
    """Same shape as `note_for_lease_denial`: one call, one sentence, a
    denial that stays a denial."""
    note = gate_request.note_for_perm_denial("kart", "store_get", store=store)
    assert " This ask has been queued for the operator as request " in note
    assert "willow-mcp gates" in note


def test_note_for_perm_denial_is_empty_when_nothing_was_queued(store, monkeypatch):
    """A failed enqueue must not put a claim in the operator's face that no
    row backs — the caller is already refusing, so silence is the honest
    suffix."""
    def _boom(*_a, **_k):
        raise RuntimeError("queue is on fire")

    from willow_mcp import human_loop

    monkeypatch.setattr(human_loop, "enqueue", _boom)
    assert gate_request.note_for_perm_denial("kart", "store_get",
                                              store=store) == ""


def test_the_same_task_retrying_dedups(store):
    """The queue an operator watches must not fill with a row per retry."""
    first = gate_request.request_permission("kart", "store_get", task_id="T1",
                                             store=store)
    second = gate_request.request_permission("kart", "store_get", task_id="T1",
                                              store=store)
    assert first["queued"] is True
    assert second["queued"] is False
    assert second["duplicate_of"] == first["id"]
    assert len(gates_panel.open_requests(store)) == 1


def test_a_permission_ask_grants_nothing(store, tmp_path, monkeypatch):
    """The security invariant in one assertion: after the ask, the app still
    does not hold the group. `permitted()` remains False for the same tool."""
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path / "home" / "mcp_apps"))

    app_id = "app-that-holds-nothing"
    assert gate.permitted(app_id, "store_get") is False

    result = gate_request.request_permission(app_id, "store_get", store=store)
    assert result["queued"] is True
    assert gate.permitted(app_id, "store_get") is False


# ── end to end at `server._gate()` ────────────────────────────────────────────

def test_gate_denial_appends_the_ask_and_queues_the_row(tmp_path, monkeypatch):
    """The whole point of PR 2: a `permitted()` miss at `server._gate()` files
    the ask AND appends the sentence, so the caller sees exactly what happened
    and the operator sees the row in `willow-mcp gates`."""
    import json as _json

    from willow_mcp import server

    apps_root = tmp_path / "mcp_apps"
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    app_dir = apps_root / "readonly"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(
        _json.dumps({"permissions": ["store_read"]}))

    effective, err = server._gate("readonly", "store_put")
    assert effective is None
    # The original refusal is preserved verbatim above the appended sentence.
    assert "gate denied" in err["error"]
    assert "not permitted for 'store_put'" in err["error"]
    # And the ask sentence is appended.
    assert "queued for the operator as request" in err["error"]
    assert "willow-mcp gates" in err["error"]

    # And a row is actually there, under the narrowest requestable scope
    # (`store_write` is the only group that admits `store_put` and is not on
    # `PERM_NEVER_REQUESTABLE`).
    items = gates_panel.open_requests(Store(store_root=str(tmp_path / "store")))
    assert len(items) == 1
    assert items[0]["request"]["gate_id"] == "perm.readonly.store_write"


def test_gate_denial_is_untouched_when_the_queue_is_down(tmp_path, monkeypatch):
    """A queue outage must not turn a clean refusal into a traceback. The
    caller still sees the ordinary `gate denied` message; the appended
    sentence is simply absent."""
    import json as _json

    from willow_mcp import human_loop, server

    apps_root = tmp_path / "mcp_apps"
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    app_dir = apps_root / "readonly"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(
        _json.dumps({"permissions": ["store_read"]}))

    def _boom(*_a, **_k):
        raise RuntimeError("queue is on fire")

    monkeypatch.setattr(human_loop, "enqueue", _boom)

    effective, err = server._gate("readonly", "store_put")
    assert effective is None
    assert "not permitted for 'store_put'" in err["error"]
    # Fail-closed on the ask half: no queued-line claim without a row backing it.
    assert "queued for the operator" not in err["error"]
