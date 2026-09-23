"""desk_attention — capped review + awaiting-verify slice for desk orient."""
from __future__ import annotations

from willow_mcp import boot_context as bc
from willow_mcp import desk_attention as da


def test_collect_quiet_when_probes_empty(monkeypatch):
    monkeypatch.setattr(da, "_open_reviews", lambda **k: [])
    monkeypatch.setattr(da, "_complete_awaiting_verify", lambda *a, **k: [])
    out = da.collect_desk_attention("willow")
    assert out == {"review": [], "awaiting_verify": [], "count": 0}
    assert da.attention_boot_lines(out) == []


def test_collect_caps_and_names_review_items(monkeypatch):
    monkeypatch.setattr(
        da,
        "_open_reviews",
        lambda **k: [
            {
                "id": "ecfc8027",
                "title": "CI red: willow-memory/willow-mcp#626 — 1 leg(s): title",
                "priority": "normal",
                "source_ref": "https://example",
                "created_at": "2026-09-22T13:54:35Z",
            }
        ],
    )
    monkeypatch.setattr(
        da,
        "_complete_awaiting_verify",
        lambda *a, **k: [
            {
                "dispatch_id": "CE5F044B",
                "to_app": "loki",
                "summary": "Prove WAKE→run_wake",
                "reply_to": "willow",
                "created_at": "2026-09-22T23:40:06Z",
                "waiting_for": "verify_handoff",
            }
        ],
    )
    out = da.collect_desk_attention("willow")
    assert out["count"] == 2
    assert out["review"][0]["id"] == "ecfc8027"
    assert out["awaiting_verify"][0]["dispatch_id"] == "CE5F044B"
    lines = da.attention_boot_lines(out)
    joined = "\n".join(lines)
    assert "[DESK ATTENTION]" in joined
    assert "ecfc8027" in joined
    assert "626" in joined
    assert "CE5F044B" in joined
    assert "verify_handoff" in joined


def test_attention_boot_lines_silent_on_empty():
    assert da.attention_boot_lines(None) == []
    assert da.attention_boot_lines({}) == []
    assert da.attention_boot_lines({"count": 0, "review": [], "awaiting_verify": []}) == []


def test_build_boot_lines_includes_desk_attention(monkeypatch):
    _quiet_boot = __import__(
        "tests.test_boot_context", fromlist=["_quiet_boot"]
    )._quiet_boot
    _quiet_boot(monkeypatch)
    monkeypatch.setattr(bc, "commitment_boot_lines", lambda *a, **k: [])
    monkeypatch.setattr(bc, "_gap_lines", lambda *a, **k: [])
    monkeypatch.setattr(bc, "_trust_root_fault_lines", lambda *a, **k: [])
    from willow_mcp.nest import autointake as nest_autointake
    monkeypatch.setattr(nest_autointake, "boot_line", lambda *a, **k: None)

    enter = {
        "orientation": {
            "desk_attention": {
                "count": 1,
                "review": [
                    {
                        "id": "ecfc8027",
                        "title": "CI red: willow-memory/willow-mcp#626 — 1 leg(s): title",
                    }
                ],
                "awaiting_verify": [],
            }
        }
    }
    lines = bc.build_boot_lines("willow", "sess-desk-attn", "startup", enter)
    joined = "\n".join(lines)
    assert "[DESK ATTENTION]" in joined
    assert "ecfc8027" in joined
