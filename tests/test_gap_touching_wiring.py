"""gap_touching wiring, B1 §4.2 "Callers": dispatch_send and session_enter
(dispatch entry), reworked per Loki's audits A4836541 and 28B97C69:

- B1 (A4836541): session_enter's block is gated on the RECIPIENT holding
  `gap_touching` (EZTLPBXF: a seat without gap_read/gap_touching got full
  gap text at session_enter). A seat that lacks it gets a `withheld`
  state instead.
- B1b (28B97C69): dispatch_send returns NO gap text at all, ever. At
  most it returns a text-free summary (`state`, `total`, `tier2_health`
  -- no `items`), gated on the CALLER (the only reader of dispatch_send's
  return value), never the recipient. BFECHFHC: the old code gated on
  to_app but returned the block to app_id, so a sender with no gap
  permissions got full gap text back by addressing a recipient that had
  them.
- H1b (28B97C69): the packet's own `project` (and the paths extracted at
  send time) are recorded on the signed packet meta, so session_enter
  reads the PACKET's project, never the specialist's entering workspace.
- L4: the wiring's own `except Exception` (in `_gaps_touching_block` /
  `_gaps_touching_summary`) is covered directly, not just the
  gap-store-unreachable path.

`gaps._store` is a module-level singleton shared with `server.gap_backlog`
(same module object), so monkeypatching `gaps._store.all` here controls
what both dispatch_send and session_enter see, the same pattern
test_gap_touching.py uses.
"""

from __future__ import annotations

import json

from willow_mcp import dispatch, gaps, server
from willow_mcp.db import Store


def _manifest(tmp_path, monkeypatch, app, **overrides):
    root = tmp_path / "mcp_apps"
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(root))
    path = root / app / "manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"permissions": ["full_access"]}
    data.update(overrides)
    path.write_text(json.dumps(data))


def _row(gap_id, topic, question, status="open"):
    return {
        "_id": gap_id,
        "topic": topic,
        "question": question,
        "status": status,
        "asked_count": 1,
        "last_asked_at": "2026-09-28T00:00:00Z",
    }


_ASSIGNMENT = "# Build\n\nEdit src/willow_mcp/gaps.py to fix the tokenizer.\n"

_NO_GAP_PERMS = ["dispatch_read", "dispatch_write", "knowledge_read"]


# ── dispatch_send: text-free summary, gated on the CALLER ──────────────────

def test_dispatch_send_returns_textless_summary_when_caller_is_permitted(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    _manifest(tmp_path, monkeypatch, "willow", permissions=["orchestrator", "gap_read"])
    _manifest(tmp_path, monkeypatch, "hanuman")
    monkeypatch.setattr(server, "_store", Store(tmp_path / "store"))

    rows = [_row("aaa111111111", "willow-mcp", "src/willow_mcp/gaps.py needs a rewrite")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)

    sent = server.dispatch_send("willow", "hanuman", _ASSIGNMENT, summary="build")
    assert "error" not in sent
    block = sent["gaps_touching"]
    assert block["state"] == "populated"
    assert block["total"] == 1
    assert "tier2_health" in block
    # No gap TEXT ever rides dispatch_send's return -- neither an `items`
    # key nor the gap's own topic/question text anywhere in the payload.
    assert "items" not in block
    assert "willow-mcp" not in json.dumps(block)
    assert "rewrite" not in json.dumps(block)


def test_dispatch_send_withholds_summary_from_caller_lacking_permission_even_when_recipient_has_it(
    tmp_path, monkeypatch
):
    """B1b (BFECHFHC): the core fix. A sender with no gap permissions must
    get nothing back, even when addressing a recipient who DOES hold
    gap_touching -- the old bug gated on to_app (the recipient) and
    returned the block to app_id (the sender), so this exact shape leaked
    full gap text to a seat gap_list refuses. This test fails if the gate
    in dispatch_send's summary reverts to checking the recipient."""
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    _manifest(tmp_path, monkeypatch, "willow", permissions=["orchestrator"])
    _manifest(tmp_path, monkeypatch, "hanuman", permissions=_NO_GAP_PERMS)
    _manifest(tmp_path, monkeypatch, "binder", permissions=["gap_read"])
    monkeypatch.setattr(server, "_store", Store(tmp_path / "store"))

    rows = [_row("mmm111111111", "governance/secret-topic",
                  "src/willow_mcp/gaps.py needs review")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)

    # hanuman (no gap perms) dispatches to binder (has gap_read) -- binder
    # would see the block via ITS OWN session_enter, but the SENDER must
    # get nothing back regardless of what the recipient can see.
    sent = server.dispatch_send("hanuman", "binder", _ASSIGNMENT, summary="build")
    assert "error" not in sent
    block = sent["gaps_touching"]
    assert block["state"] == "withheld"
    assert "items" not in block
    assert "secret-topic" not in json.dumps(block)


def test_dispatch_send_succeeds_when_gap_store_unreachable(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    _manifest(tmp_path, monkeypatch, "willow", permissions=["orchestrator", "gap_read"])
    _manifest(tmp_path, monkeypatch, "hanuman")
    monkeypatch.setattr(server, "_store", Store(tmp_path / "store"))

    def raises(coll):
        raise RuntimeError("gap store is gone")

    monkeypatch.setattr(gaps._store, "all", raises)

    sent = server.dispatch_send("willow", "hanuman", _ASSIGNMENT, summary="build")
    assert "error" not in sent
    assert sent["dispatch_id"]
    assert sent["gaps_touching"]["state"] == "unreachable"


def test_dispatch_send_threads_project_into_tier3(tmp_path, monkeypatch):
    """H1: without `project`, tier 3 (project+stem) never fires. With it,
    a gap naming no file path at all IS reflected in the send-time
    summary's `total` (never in text -- dispatch_send carries no items)."""
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    _manifest(tmp_path, monkeypatch, "willow", permissions=["orchestrator", "gap_read"])
    _manifest(tmp_path, monkeypatch, "hanuman")
    monkeypatch.setattr(server, "_store", Store(tmp_path / "store"))

    rows = [_row(
        "07aa99036f09",
        "ratatosk/listener-home-pin-tests-and-crown-mcp-guard",
        "the listen goroutine never learned its home directory before the crown mcp guard landed",
    )]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)

    md = "# Build\n\nRewrite deploy/ratatosk-listen-loki.service.template.\n"

    without_project = server.dispatch_send("willow", "hanuman", md, summary="a")
    assert without_project["gaps_touching"]["state"] == "empty"

    with_project = server.dispatch_send(
        "willow", "hanuman", md, summary="b", project="ratatosk",
    )
    assert with_project["gaps_touching"]["state"] == "populated"
    assert with_project["gaps_touching"]["total"] == 1
    assert "items" not in with_project["gaps_touching"]


def test_dispatch_send_stores_project_and_paths_on_packet_meta(tmp_path, monkeypatch):
    """H1b: session_enter must be able to read the send-time project/paths
    back from the packet -- dispatch_read is the same door session_enter
    itself uses, so checking it here pins the actual on-disk contract."""
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    _manifest(tmp_path, monkeypatch, "willow", permissions=["orchestrator", "gap_read"])
    _manifest(tmp_path, monkeypatch, "hanuman")
    monkeypatch.setattr(server, "_store", Store(tmp_path / "store"))
    monkeypatch.setattr(gaps._store, "all", lambda coll: [])

    md = "# Build\n\nRewrite deploy/ratatosk-listen-loki.service.template.\n"
    sent = server.dispatch_send(
        "willow", "hanuman", md, summary="build", project="ratatosk",
    )
    pkt = dispatch.dispatch_read(sent["dispatch_id"])
    assert pkt["meta"]["gaps_project"] == "ratatosk"
    assert pkt["meta"]["gaps_paths"] == ["deploy/ratatosk-listen-loki.service.template"]


def test_dispatch_send_wiring_outer_except_is_covered(tmp_path, monkeypatch):
    """L4: the wiring's own except (in _gaps_touching_summary) must be
    exercised directly, not only reached via a gap-store failure."""
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    _manifest(tmp_path, monkeypatch, "willow", permissions=["orchestrator", "gap_read"])
    _manifest(tmp_path, monkeypatch, "hanuman")
    monkeypatch.setattr(server, "_store", Store(tmp_path / "store"))

    def boom(paths, project=""):
        raise ValueError("something unrelated to the store blew up")

    monkeypatch.setattr(server.gap_backlog, "touching", boom)

    sent = server.dispatch_send("willow", "hanuman", _ASSIGNMENT, summary="build")
    assert "error" not in sent
    assert sent["gaps_touching"]["state"] == "unreachable"
    assert "something unrelated" in sent["gaps_touching"]["reason"]


# ── session_enter (dispatch entry): full block, gated on the recipient ─────

def test_session_enter_dispatch_attaches_gaps_touching_block(tmp_path, monkeypatch):
    _manifest(tmp_path, monkeypatch, "hanuman")
    monkeypatch.setattr(server, "_store", Store(tmp_path / "store"))

    sent = dispatch.dispatch_send("willow", "hanuman", _ASSIGNMENT, summary="build")
    rows = [_row("aaa111111111", "willow-mcp", "src/willow_mcp/gaps.py needs a rewrite")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)

    project = tmp_path / "project"
    project.mkdir()
    entered = server.session_enter(
        app_id="hanuman",
        session_id="dispatch-session",
        dispatch_id=sent["dispatch_id"],
        project="project",
        workspace=str(project),
    )
    assert entered["entry_mode"] == "dispatch"
    assert entered["gaps_touching"]["state"] == "populated"
    assert entered["gaps_touching"]["items"][0]["id"] == "aaa111111111"


def test_session_enter_dispatch_succeeds_when_gap_store_unreachable(tmp_path, monkeypatch):
    _manifest(tmp_path, monkeypatch, "hanuman")
    monkeypatch.setattr(server, "_store", Store(tmp_path / "store"))

    sent = dispatch.dispatch_send("willow", "hanuman", _ASSIGNMENT, summary="build")

    def raises(coll):
        raise RuntimeError("gap store is gone")

    monkeypatch.setattr(gaps._store, "all", raises)

    project = tmp_path / "project"
    project.mkdir()
    entered = server.session_enter(
        app_id="hanuman",
        session_id="dispatch-session-2",
        dispatch_id=sent["dispatch_id"],
        project="project",
        workspace=str(project),
    )
    assert entered["entry_mode"] == "dispatch"
    assert "error" not in entered
    assert entered["gaps_touching"]["state"] == "unreachable"


def test_session_enter_threads_entering_project_into_tier3_as_a_fallback(tmp_path, monkeypatch):
    """H1b fallback path: a packet sent before this shipped (or sent via
    the low-level dispatch.dispatch_send with no gaps_project) carries no
    packet project. session_enter still falls back to the entering
    workspace's project, exactly as it did before H1b."""
    _manifest(tmp_path, monkeypatch, "hanuman")
    monkeypatch.setattr(server, "_store", Store(tmp_path / "store"))

    md = "# Build\n\nRewrite deploy/ratatosk-listen-loki.service.template.\n"
    sent = dispatch.dispatch_send("willow", "hanuman", md, summary="build")
    assert sent  # sanity: the low-level call carries no gaps_project

    rows = [_row(
        "07aa99036f09",
        "ratatosk/listener-home-pin-tests-and-crown-mcp-guard",
        "the listen goroutine never learned its home directory before the crown mcp guard landed",
    )]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)

    project = tmp_path / "ratatosk"
    project.mkdir()
    entered = server.session_enter(
        app_id="hanuman",
        session_id="dispatch-session-3",
        dispatch_id=sent["dispatch_id"],
        project="ratatosk",
        workspace=str(project),
    )
    assert entered["gaps_touching"]["state"] == "populated"
    assert entered["gaps_touching"]["items"][0]["id"] == "07aa99036f09"


def test_session_enter_uses_packets_project_over_a_different_entering_workspace(
    tmp_path, monkeypatch
):
    """H1b, the actual fix: Loki's probe found that entering a ratatosk
    packet from willows-grove drops the tier-3 match. Once dispatch_send
    records project on the packet, session_enter must use THAT, not the
    specialist's own entering workspace, which here is a different repo
    entirely."""
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    _manifest(tmp_path, monkeypatch, "willow", permissions=["orchestrator", "gap_read"])
    _manifest(tmp_path, monkeypatch, "hanuman")
    monkeypatch.setattr(server, "_store", Store(tmp_path / "store"))
    monkeypatch.setattr(gaps._store, "all", lambda coll: [])

    md = "# Build\n\nRewrite deploy/ratatosk-listen-loki.service.template.\n"
    sent = server.dispatch_send(
        "willow", "hanuman", md, summary="build", project="ratatosk",
    )

    rows = [_row(
        "07aa99036f09",
        "ratatosk/listener-home-pin-tests-and-crown-mcp-guard",
        "the listen goroutine never learned its home directory before the crown mcp guard landed",
    )]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)

    other_workspace = tmp_path / "willows-grove"
    other_workspace.mkdir()
    entered = server.session_enter(
        app_id="hanuman",
        session_id="dispatch-session-cross-workspace",
        dispatch_id=sent["dispatch_id"],
        project="willows-grove",  # a DIFFERENT project than the packet's own
        workspace=str(other_workspace),
    )
    assert entered["project"]["name"] == "willows-grove"
    assert entered["gaps_touching"]["state"] == "populated"
    assert entered["gaps_touching"]["items"][0]["id"] == "07aa99036f09"


def test_session_enter_withholds_block_from_recipient_without_gap_touching(tmp_path, monkeypatch):
    """B1 (EZTLPBXF): the exact case the audit found -- a seat scoped to
    [dispatch_read, dispatch_write, knowledge_read], no gap_read/
    gap_touching, must get 'withheld' at session_enter, not the gap's
    full topic and question text."""
    _manifest(tmp_path, monkeypatch, "hanuman", permissions=_NO_GAP_PERMS)
    monkeypatch.setattr(server, "_store", Store(tmp_path / "store"))

    sent = dispatch.dispatch_send("willow", "hanuman", _ASSIGNMENT, summary="build")
    rows = [_row("mmm222222222", "governance/secret-topic",
                  "src/willow_mcp/gaps.py needs review")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)

    project = tmp_path / "project"
    project.mkdir()
    entered = server.session_enter(
        app_id="hanuman",
        session_id="dispatch-session-4",
        dispatch_id=sent["dispatch_id"],
        project="project",
        workspace=str(project),
    )
    assert "error" not in entered
    block = entered["gaps_touching"]
    assert block["state"] == "withheld"
    assert block["items"] == []
    assert "secret-topic" not in json.dumps(block)


def test_session_enter_wiring_outer_except_is_covered(tmp_path, monkeypatch):
    """L4, session_enter side."""
    _manifest(tmp_path, monkeypatch, "hanuman")
    monkeypatch.setattr(server, "_store", Store(tmp_path / "store"))

    sent = dispatch.dispatch_send("willow", "hanuman", _ASSIGNMENT, summary="build")

    def boom(paths, project=""):
        raise ValueError("something unrelated to the store blew up")

    monkeypatch.setattr(server.gap_backlog, "touching", boom)

    project = tmp_path / "project"
    project.mkdir()
    entered = server.session_enter(
        app_id="hanuman",
        session_id="dispatch-session-5",
        dispatch_id=sent["dispatch_id"],
        project="project",
        workspace=str(project),
    )
    assert "error" not in entered
    assert entered["gaps_touching"]["state"] == "unreachable"
    assert "something unrelated" in entered["gaps_touching"]["reason"]


def test_session_enter_human_entry_has_no_gaps_touching_block(tmp_path, monkeypatch):
    """No dispatch_id, no assignment text -- nothing to scan, so the key
    is simply absent rather than an empty/unreachable placeholder."""
    _manifest(tmp_path, monkeypatch, "hanuman")
    monkeypatch.setattr(server, "_store", Store(tmp_path / "store"))

    project = tmp_path / "project"
    project.mkdir()
    entered = server.session_enter(
        app_id="hanuman",
        session_id="human-session",
        project="project",
        workspace=str(project),
    )
    assert entered["entry_mode"] == "human"
    assert "gaps_touching" not in entered
