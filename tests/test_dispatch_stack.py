"""Tests for dispatch packet stack (filesystem under WILLOW_HOME)."""

import json

import pytest

from willow_mcp import dispatch as ds
from willow_mcp import handoff as ho


@pytest.fixture
def orchestrator_app(home):
    apps = home / "mcp_apps" / "willow"
    apps.mkdir(parents=True)
    (apps / "manifest.json").write_text(
        json.dumps({"permissions": ["orchestrator"]})
    )
    return "willow"


def test_dispatch_send_and_read(home):
    md = """# Audit PR #786

## Checklist
- [ ] Read diff
"""
    sent = ds.dispatch_send(
        "willow", "loki", md, role="loki", summary="Audit PR #786"
    )
    assert "dispatch_id" in sent
    did = sent["dispatch_id"]

    pkt = ds.dispatch_read(did)
    assert pkt["meta"]["to_app"] == "loki"
    assert pkt["meta"]["role"] == "loki"
    assert pkt["meta"]["closeout"] == ds.DISPATCH_CLOSEOUT
    assert "reply_contract" not in pkt["meta"]
    assert "Audit PR #786" in pkt["assignment"]
    assert pkt["status"]["status"] == "pending"


def test_closeout_from_meta_reads_legacy_reply_contract():
    legacy = {"reply_contract": "handoff_v4", "to_app": "loki"}
    assert ds.closeout_from_meta(legacy) == ds.DISPATCH_CLOSEOUT


def test_handoff_write_v4_emits_handoff_v1_format_intentional(home):
    # BC504427: tool name reflects call-signature generation; on-disk format is v1.
    sent = ds.dispatch_send("willow", "loki", "# Task\n", summary="task")
    did = sent["dispatch_id"]
    ho.handoff_write_v4("loki", did, narrative="Done.")
    handoff = json.loads((home / "dispatch" / did / "handoff.json").read_text())
    assert handoff["format"] == "handoff_v1"


def test_handoff_write_v4_closeout_is_proper_mai(home):
    """closeout.md is a conforming @markdownai document (#155)."""
    sent = ds.dispatch_send(
        "willow", "loki", "# Task\n", role="loki", summary="task"
    )
    did = sent["dispatch_id"]
    ho.handoff_write_v4(
        "loki",
        did,
        findings=[{"id": "f1", "text": "note", "severity": "low", "evidence": []}],
        narrative="Shipped.",
    )
    closeout = (home / "dispatch" / did / "closeout.md").read_text(encoding="utf-8")
    assert closeout.startswith("---\n")
    assert "kind: closeout\n" in closeout
    assert f"dispatch_id: {json.dumps(did)}\n" in closeout
    body = closeout.split("---", 2)[2].lstrip("\n")
    assert body.startswith("@markdownai v1.0\n")

    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools.mai_lint import _load_schema, lint_file

    assert lint_file(
        home / "dispatch" / did / "closeout.md", _load_schema(), quiet=True
    )


def test_full_lifecycle(home):
    md = "# Task\n\nDo the audit.\n"
    sent = ds.dispatch_send("willow", "loki", md, role="loki")
    did = sent["dispatch_id"]

    acc = ds.dispatch_accept(did, "loki", session_id="sess-1")
    assert acc["status"]["status"] == "working"

    sess = ds.session_read("loki", "sess-1")
    assert sess["dispatch_id"] == did

    done = ho.handoff_write_v4(
        "loki",
        did,
        findings=[{"id": "g1", "text": "gap found", "severity": "high", "evidence": ["a.py:1"]}],
        narrative="Audited.",
    )
    assert done["status"] == "complete"

    v = ho.verify_handoff(did)
    assert v["verified"] is True
    assert v["status"] == "verified"

    cleared = ds.agent_clear("loki", did, session_id="sess-1")
    assert cleared["status"] == "cleared"

    sess2 = ds.session_read("loki", "sess-1")
    assert sess2["status"] == "idle"


def test_dispatch_list_filter(home):
    ds.dispatch_send("willow", "loki", "# A\n", summary="a")
    ds.dispatch_send("willow", "hanuman", "# B\n", summary="b")
    rows = ds.dispatch_list(to_app="loki")
    assert rows["total"] == 1
    assert rows["dispatches"][0]["to_app"] == "loki"


def test_wrong_recipient_rejected(home):
    sent = ds.dispatch_send("willow", "loki", "# x\n")
    did = sent["dispatch_id"]
    err = ds.dispatch_accept(did, "hanuman")
    assert err.get("error") == "wrong_recipient"


def test_session_enter_human_path(home):
    from willow_mcp import home_init as hi

    hi.ensure_home_layout()
    out = ds.session_enter("hanuman", "sess-human")
    assert out["entry_mode"] == "human"
    assert out["dispatch_id"] is None
    assert "session_handoff_write" in out["closeout_tools"]
    assert out.get("persona")
    assert "Hanuman" in out.get("persona", "") or out.get("display_name") == "Hanuman"
    assert out.get("persona_path") == "personas/hanuman.md"
    sess = ds.session_read("hanuman", "sess-human")
    assert sess["status"] == "idle"
    assert sess["dispatch_id"] == ""


def test_session_enter_dispatch_by_id(home):
    from willow_mcp import home_init as hi

    hi.ensure_home_layout()
    sent = ds.dispatch_send("willow", "loki", "# Build\n\nShip it.\n", summary="build")
    did = sent["dispatch_id"]
    out = ds.session_enter("loki", "sess-disp", dispatch_id=did)
    assert out["entry_mode"] == "dispatch"
    assert out["dispatch_id"] == did
    assert "Ship it" in out["assignment"]
    assert out["status"] == "working"
    assert out["closeout"] == ds.DISPATCH_CLOSEOUT
    assert out["closeout_tools"] == ["handoff_write_v4"]
    assert out.get("persona")
    assert out.get("display_name") == "Loki"


def test_session_enter_bare_lists_pending_and_does_not_bind(home):
    """Gap 22c8c1aab079: a bare session_enter names the seat's pending packets
    instead of silently claiming the oldest one; binding is explicit."""
    sent = ds.dispatch_send("willow", "ada", "# Monitor\n", summary="watch")
    did = sent["dispatch_id"]
    out = ds.session_enter("ada", "sess-auto")
    assert out["entry_mode"] == "human"
    assert out["dispatch_id"] is None
    assert out["pending_dispatches"] == [did]
    assert did in out["message"]
    # nothing moved: the packet is still pending, the session is not bound
    assert ds.dispatch_read(did)["status"]["status"] == "pending"
    assert ds.session_read("ada", "sess-auto").get("dispatch_id") in (None, "")
    # the explicit path still binds and flips the packet to working
    bound = ds.session_enter("ada", "sess-explicit", dispatch_id=did)
    assert bound["entry_mode"] == "dispatch"
    assert bound["dispatch_id"] == did
    assert ds.dispatch_read(did)["status"]["status"] == "working"


def test_session_handoff_write_human_closeout(home):
    ds.session_enter("hanuman", "sess-close")
    out = ds.session_handoff_write(
        "hanuman",
        "sess-close",
        narrative="Fixed consent docs.",
        summary="B-33 filed",
        next_bite="kart-sandbox bound_ro",
    )
    assert out["entry_mode"] == "human"
    assert "handoff_path" in out
    from pathlib import Path

    assert Path(out["handoff_path"]).exists()
    sess = ds.session_read("hanuman", "sess-close")
    assert sess["status"] == "idle"


# ── B-54/#242: is_dispatch_party ──────────────────────────────────────────

def test_is_dispatch_party_true_for_from_to_and_reply_to():
    meta = {"from_app": "hanuman", "to_app": "loki", "reply_to": "willow"}
    assert ds.is_dispatch_party("hanuman", meta) is True
    assert ds.is_dispatch_party("loki", meta) is True
    assert ds.is_dispatch_party("willow", meta) is True
    assert ds.is_dispatch_party("HANUMAN", meta) is True  # case-insensitive


def test_is_dispatch_party_false_for_unrelated_app():
    meta = {"from_app": "hanuman", "to_app": "loki", "reply_to": "willow"}
    assert ds.is_dispatch_party("jeles", meta) is False
    assert ds.is_dispatch_party("", meta) is False


# ── B-52/#241: dispatch packet meta.json signing ────────────────────────────


def _plant_forged_packet(home, dispatch_id="DEADBEEF", **overrides):
    """Hand-write a packet directory the way an operator-writable dispatch/
    lets an attacker do -- bypassing dispatch_send entirely, mimicking the
    red-team's original DEADBEEF demo."""
    root = home / "dispatch" / dispatch_id
    root.mkdir(parents=True)
    meta = {
        "format": "startup_packet_meta_v1",
        "dispatch_id": dispatch_id,
        "from_app": "attacker",
        "to_app": "willow",
        "status": "pending",
    }
    meta.update(overrides)
    (root / "meta.json").write_text(json.dumps(meta))
    (root / "assignment.md").write_text("evil\n")
    (root / "status.json").write_text(json.dumps({"status": "pending"}))
    return root


def test_dispatch_send_round_trip_signs_and_verifies(home):
    """A packet dispatch_send actually wrote carries a signature that
    verifies, and dispatch_list surfaces it as a normal trusted entry."""
    sent = ds.dispatch_send("willow", "loki", "# Task\n", summary="task")
    did = sent["dispatch_id"]

    pkt = ds.dispatch_read(did)
    assert "error" not in pkt
    assert pkt["signature_status"] == "valid"
    assert "signature" in pkt["meta"]

    rows = ds.dispatch_list()
    ids = [r["dispatch_id"] for r in rows["dispatches"]]
    assert did in ids
    assert rows["unverified_total"] == 0


def test_forged_packet_excluded_from_normal_list_and_flagged(home):
    """The DEADBEEF scenario: a hand-planted meta.json with no signature
    field satisfies _meta_is_well_formed but must not appear as a normal
    trusted dispatch -- it shows up in `unverified` instead."""
    sent = ds.dispatch_send("willow", "loki", "# Real\n", summary="real")
    did = sent["dispatch_id"]
    _plant_forged_packet(home)

    rows = ds.dispatch_list()
    trusted_ids = [r["dispatch_id"] for r in rows["dispatches"]]
    assert did in trusted_ids
    assert "DEADBEEF" not in trusted_ids
    assert rows["unverified_total"] == 1
    unv = rows["unverified"][0]
    assert unv["dispatch_id"] == "DEADBEEF"
    assert unv["unverified"] is True
    assert unv["signature_status"] == "legacy_unsigned"

    # dispatch_read still lets it through (back-compat: unsigned is not the
    # same as tampered) but flags it rather than pretending it's trusted.
    pkt = ds.dispatch_read("DEADBEEF")
    assert "error" not in pkt
    assert pkt["signature_status"] == "legacy_unsigned"


def test_forged_packet_hard_rejected_under_strict_mode(home, monkeypatch):
    _plant_forged_packet(home)
    monkeypatch.setenv("WILLOW_MCP_STRICT_TRUST_ROOT", "1")

    pkt = ds.dispatch_read("DEADBEEF")
    assert pkt.get("error") == "unsigned_packet_strict_mode"

    rows = ds.dispatch_list()
    assert rows["dispatches"] == []
    assert rows["unverified"] == []  # strict mode: not even surfaced


def test_tampering_signed_meta_invalidates_signature(home):
    """Editing any field of an already-signed meta.json (not through the
    dispatch lifecycle functions) invalidates its signature -- tamper
    evidence, refused on read regardless of strict mode."""
    sent = ds.dispatch_send("willow", "loki", "# Task\n", summary="task")
    did = sent["dispatch_id"]

    meta_path = home / "dispatch" / did / "meta.json"
    meta = json.loads(meta_path.read_text())
    meta["summary"] = "HACKED — not what dispatch_send wrote"
    meta_path.write_text(json.dumps(meta))

    pkt = ds.dispatch_read(did)
    assert pkt.get("error") == "invalid_signature"

    rows = ds.dispatch_list()
    trusted_ids = [r["dispatch_id"] for r in rows["dispatches"]]
    assert did not in trusted_ids
    assert rows["unverified_total"] == 1
    assert rows["unverified"][0]["signature_status"] == "invalid"


def test_status_transitions_resign_meta_and_stay_valid(home):
    """dispatch_accept/handoff_write_v4/agent_clear legitimately rewrite
    meta.json's status mirror -- that must re-sign, not self-invalidate."""
    sent = ds.dispatch_send("willow", "loki", "# Task\n", role="loki")
    did = sent["dispatch_id"]

    ds.dispatch_accept(did, "loki")
    mid = ds.dispatch_read(did)
    assert mid["signature_status"] == "valid"

    ho.handoff_write_v4("loki", did, narrative="Done.")
    done = ds.dispatch_read(did)
    assert done["signature_status"] == "valid"

    ds.agent_clear("loki", did)
    cleared = ds.dispatch_read(did)
    assert cleared["signature_status"] == "valid"


def test_legacy_unsigned_packet_gets_signed_on_lifecycle_transition(home):
    """A pre-existing unsigned packet (predates this fix) is not hard-broken
    -- accepting it through the real lifecycle signs it going forward."""
    root = _plant_forged_packet(home, dispatch_id="LEGACY01", to_app="loki")
    assert root.is_dir()

    acc = ds.dispatch_accept("LEGACY01", "loki")
    assert "error" not in acc

    pkt = ds.dispatch_read("LEGACY01")
    assert pkt["signature_status"] == "valid"
