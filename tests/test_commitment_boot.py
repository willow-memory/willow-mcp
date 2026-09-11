"""test_commitment_boot.py — SessionStart join for the commitment membrane's dew rule.

Covers commitments/boot.py directly (commitment_boot_lines) and its wiring into
boot_context.build_boot_lines. Mirrors the discipline already pinned for the
neighboring boot sections (gaps/blockers in test_boot_context.py): silent on a
clean boot, degrades to no line on any fault, never raises.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from willow_mcp import boot_context as bc
from willow_mcp import server
from willow_mcp.commitments import boot as commitment_boot
from willow_mcp.commitments.commitment_ledger import (
    CalendarEvent,
    CommitmentLedger,
    StubCalendarSource,
)

BASE = datetime(2026, 7, 20, 9, 0, 0)


def _ledger_with(events):
    ledger = CommitmentLedger(source=StubCalendarSource(events))
    ledger.ingest()
    return ledger


def test_commitment_boot_lines_silent_when_nothing_imminent(monkeypatch):
    # An active commitment far in the future, already acknowledged: the dew
    # rule has nothing to say, so the boot section must not appear at all.
    far_future = _ledger_with([
        CalendarEvent(uid="c1", title="Quarterly review", start=BASE + timedelta(days=30)),
    ])
    far_future.acknowledge("c1")
    monkeypatch.setattr(server, "_commitment_ledger_restored", lambda: far_future)

    lines = commitment_boot.commitment_boot_lines("hanuman", now=BASE)
    assert lines == []


def test_commitment_boot_lines_surfaces_imminent(monkeypatch):
    imminent = _ledger_with([
        CalendarEvent(uid="c1", title="Standup", start=BASE + timedelta(minutes=5),
                      end=BASE + timedelta(minutes=20)),
    ])
    imminent.acknowledge("c1")
    monkeypatch.setattr(server, "_commitment_ledger_restored", lambda: imminent)

    lines = commitment_boot.commitment_boot_lines("hanuman", now=BASE)
    assert lines, "expected a boot section for an imminent commitment"
    joined = "\n".join(lines)
    assert "[COMMITMENTS]" in joined
    assert "imminent" in joined
    assert "Standup" in joined


def test_commitment_boot_lines_surfaces_conflict(monkeypatch):
    overlapping = _ledger_with([
        CalendarEvent(uid="c1", title="1:1", start=BASE, end=BASE + timedelta(minutes=30)),
        CalendarEvent(uid="c2", title="Design review",
                      start=BASE + timedelta(minutes=10), end=BASE + timedelta(minutes=40)),
    ])
    overlapping.acknowledge("c1")
    overlapping.acknowledge("c2")
    monkeypatch.setattr(server, "_commitment_ledger_restored", lambda: overlapping)

    lines = commitment_boot.commitment_boot_lines("hanuman", now=BASE + timedelta(days=5))
    joined = "\n".join(lines)
    assert "[COMMITMENTS]" in joined
    assert "conflict" in joined


def test_commitment_boot_lines_surfaces_mismatch():
    # A freshly-ingested reschedule is unacknowledged by construction — the
    # split-stick halves disagree even though nothing is imminent.
    ledger = _ledger_with([
        CalendarEvent(uid="c1", title="Retro", start=BASE + timedelta(days=10)),
    ])
    ledger.source.set_events([
        CalendarEvent(uid="c1", title="Retro", start=BASE + timedelta(days=11)),
    ])
    ledger.ingest()

    from willow_mcp import server as server_mod
    orig = server_mod._commitment_ledger_restored
    server_mod._commitment_ledger_restored = lambda: ledger
    try:
        lines = commitment_boot.commitment_boot_lines("hanuman", now=BASE)
    finally:
        server_mod._commitment_ledger_restored = orig

    joined = "\n".join(lines)
    assert "[COMMITMENTS]" in joined
    assert "mismatch" in joined


def test_commitment_boot_lines_degrades_on_fault(monkeypatch):
    def boom():
        raise RuntimeError("store denied")

    monkeypatch.setattr(server, "_commitment_ledger_restored", boom)
    lines = commitment_boot.commitment_boot_lines("hanuman", now=BASE)
    assert lines == []


def test_build_boot_lines_includes_commitment_section_when_present(monkeypatch):
    monkeypatch.setattr(bc, "load_corpus_lanes", lambda: {})
    monkeypatch.setattr(bc, "read_stack_snapshot", lambda app_id: None)
    monkeypatch.setattr(bc, "degraded_boot_line", lambda app_id: None)
    monkeypatch.setattr(bc, "_blocker_lines", lambda *a, **k: [])
    monkeypatch.setattr(bc, "_gap_lines", lambda *a, **k: [])
    monkeypatch.setattr(bc, "commitment_boot_lines",
                         lambda app_id, **k: ["[COMMITMENTS] 1 need attention:",
                                              "  · [imminent] Standup @ 2026-07-20T09:05:00"])

    lines = bc.build_boot_lines("hanuman", "sess-commitments-present", "startup", {"orientation": {}})
    joined = "\n".join(lines)
    assert "[COMMITMENTS]" in joined
    assert "Standup" in joined


def test_build_boot_lines_omits_commitment_section_when_silent(monkeypatch):
    monkeypatch.setattr(bc, "load_corpus_lanes", lambda: {})
    monkeypatch.setattr(bc, "read_stack_snapshot", lambda app_id: None)
    monkeypatch.setattr(bc, "degraded_boot_line", lambda app_id: None)
    monkeypatch.setattr(bc, "_blocker_lines", lambda *a, **k: [])
    monkeypatch.setattr(bc, "_gap_lines", lambda *a, **k: [])
    monkeypatch.setattr(bc, "commitment_boot_lines", lambda app_id, **k: [])

    lines = bc.build_boot_lines("hanuman", "sess-commitments-absent", "startup", {"orientation": {}})
    assert "[COMMITMENTS]" not in "\n".join(lines)


def test_build_boot_lines_survives_commitment_fault(monkeypatch):
    """Wiring-level belt-and-suspenders: even if commitment_boot_lines itself
    somehow raised (it should not — see commitment_boot_lines_degrades_on_fault
    above), build_boot_lines must not blow up mid-composition."""
    monkeypatch.setattr(bc, "load_corpus_lanes", lambda: {})
    monkeypatch.setattr(bc, "read_stack_snapshot", lambda app_id: None)
    monkeypatch.setattr(bc, "degraded_boot_line", lambda app_id: None)
    monkeypatch.setattr(server, "_commitment_ledger_restored",
                         lambda: (_ for _ in ()).throw(RuntimeError("boom")))

    lines = bc.build_boot_lines("hanuman", "sess-commitments-fault", "startup", {"orientation": {}})
    assert "[COMMITMENTS]" not in "\n".join(lines)
