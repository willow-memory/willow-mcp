"""Stage-1 pre-handoff instruments (sealed cdcd948c) — fail-open receipts."""

from __future__ import annotations

import json
from pathlib import Path

from willow_mcp import session_pre_handoff as sph
from willow_mcp import session_stop_hook as stop


def test_pre_handoff_writes_stub_receipts(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    out = sph.run_pre_handoff_instruments("willow", "sess-abc", transcript_path="")
    assert out["stage"] == 1
    receipt_dir = Path(out["receipt_dir"])
    assert (receipt_dir / "stage1.json").is_file()
    lens = json.loads((receipt_dir / "corpus-lens.json").read_text())
    assert lens["state"] == "skipped"
    recon = json.loads((receipt_dir / "reconciler.json").read_text())
    assert recon["state"] == "stub"
    assert recon["sealed_pair"].startswith("cdcd948c")


def test_pre_handoff_missing_transcript_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    missing = tmp_path / "nope.jsonl"
    out = sph.run_pre_handoff_instruments("willow", "s1", transcript_path=str(missing))
    lens = json.loads(Path(out["receipt_dir"], "corpus-lens.json").read_text())
    assert lens["state"] == "skipped"
    assert lens["reason"] == "transcript_missing"


def test_session_stop_hook_includes_pre_handoff(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_APP_ID", "willow")
    # Seat resolution needs .mcp.json — stub the resolver.
    monkeypatch.setattr(
        "willow_mcp.seat_identity.resolve_hook_app_id",
        lambda: ("willow", None),
    )
    monkeypatch.setattr(
        "willow_mcp.session_stop_hook.write_stack_snapshot",
        lambda app_id, session_id: {"ok": True},
    )
    monkeypatch.setattr(
        "willow_mcp.session_stop_hook.scan_session_for_friction",
        lambda session_id, transcript_path: {"skipped": "no_transcript_path"},
    )
    out = stop.handle({"session_id": "hook-sess-1"})
    assert "pre_handoff" in out
    assert out["pre_handoff"]["stage"] == 1
    assert out["friction_scan"]["skipped"] == "no_transcript_path"


def test_cursor_session_end_timeout_allows_instruments():
    hooks = Path(__file__).resolve().parents[1] / "deploy" / "cursor" / "hooks.json"
    data = json.loads(hooks.read_text())
    end = data["hooks"]["sessionEnd"][0]
    assert end["timeout"] >= 120
