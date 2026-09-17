"""The seal-driven live-table sync (`constitutional.sync_syscall_table_from_bundle`).

`home_init.ensure_home_layout()` only ever copies the bundle syscall table
into `$WILLOW_HOME` when the live one is MISSING, so a verb the operator
ratifies into the shipped bundle never reaches an already-installed box's
live table on its own. This module applies exactly the additive case — the
bundle gained rows and changed none of the live table's existing ones —
atomically, with FRANK ink. Anything else is a refusal that leaves the live
table untouched.
"""
from __future__ import annotations

import json
import os
import stat

import pytest

from willow_mcp import constitutional


def _row(vid, verb="v", note="", **extra):
    row = {"id": vid, "verb": verb, "summary": "s", "bounds": {}, "enforcement": "soft",
           "enforced_by": None, "min_ring": "ENGINEER", "note": note}
    row.update(extra)
    return row


def _write_table(path, rows):
    path.write_text(json.dumps({"verbs": rows}, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


class _FakeLedger:
    def __init__(self):
        self.rows = []

    def append(self, project, event_type, content):
        self.rows.append({"project": project, "event_type": event_type, "content": content})
        return f"rec-{len(self.rows)}"


@pytest.fixture
def tables(tmp_path):
    tmp_path.chmod(0o700)
    live = tmp_path / "live" / "syscall-table.json"
    bundle = tmp_path / "bundle" / "syscall-table.json"
    live.parent.mkdir()
    bundle.parent.mkdir()
    return live, bundle


# ── the additive case: applied, with FRANK ink ────────────────────────────────

def test_bundle_superset_syncs_and_writes_frank_ink(tables):
    live, bundle = tables
    row14 = _row(14, "agent.lifecycle")
    row15 = _row(15, "unit.reload", note="sealed under decision (seal 06075e99)")
    _write_table(live, [row14])
    _write_table(bundle, [row14, row15])

    ledger = _FakeLedger()
    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, ledger=ledger, project="fleet")

    assert out["ok"] is True
    assert out["added"] == [15]
    assert out["verbs"] == ["unit.reload"]
    assert out["seals"] == {15: "06075e99"}

    written = json.loads(live.read_text())
    assert [r["id"] for r in written["verbs"]] == [14, 15]

    assert len(ledger.rows) == 1
    ev = ledger.rows[0]
    assert ev["event_type"] == "constitutional_sync"
    assert ev["content"]["added"] == [15]
    assert ev["content"]["seals"] == {15: "06075e99"}


def test_synced_live_table_is_group_other_unwritable(tables):
    live, bundle = tables
    row14 = _row(14)
    row15 = _row(15, "unit.reload")
    _write_table(live, [row14])
    _write_table(bundle, [row14, row15])

    constitutional.sync_syscall_table_from_bundle(live_path=live, bundle_path=bundle)

    mode = stat.S_IMODE(os.stat(live).st_mode)
    assert not (mode & 0o022), f"live table is group/other-writable: {oct(mode)}"


def test_no_ledger_still_syncs_without_writing_frank_ink(tables):
    live, bundle = tables
    row14 = _row(14)
    row15 = _row(15, "unit.reload")
    _write_table(live, [row14])
    _write_table(bundle, [row14, row15])

    out = constitutional.sync_syscall_table_from_bundle(live_path=live, bundle_path=bundle)
    assert out["ok"] is True and out["added"] == [15]


# ── the two refusal shapes: live untouched ────────────────────────────────────

def test_modified_existing_row_is_refused_live_untouched(tables):
    """A STRUCTURAL diff (bounds, here) is still a modification and still
    refuses — only `note`/`summary` are exempted (row 16, `pr.update`,
    sealed 783bab4e; see test_note_only_diff_on_an_existing_row_still_syncs
    below for the field that is NOT this)."""
    live, bundle = tables
    row3_live = _row(3, "git.push", bounds={"repo": "org/name"})
    row3_bundle = _row(3, "git.push", bounds={"repo": "org/other"})
    _write_table(live, [row3_live])
    _write_table(bundle, [row3_bundle])
    before = live.read_text()

    out = constitutional.sync_syscall_table_from_bundle(live_path=live, bundle_path=bundle)

    assert out["ok"] is False and out["refused"] is True
    assert "3" in out["reason"] or "[3]" in out["reason"]
    assert live.read_text() == before


def test_note_only_diff_on_an_existing_row_does_not_block_an_addition(tables):
    """The real shape row 16 introduced: row 15's own lineage note picked up
    a `PR #555` in the same commit that appended row 16. A note-only diff on
    an EXISTING row must not hold the new row's sync hostage — the bundle
    (prose-and-all) is what lands, not a partial write."""
    live, bundle = tables
    row14 = _row(14, "agent.lifecycle")
    row15_live = _row(15, "unit.reload", note="sealed under decision (seal 06075e99), PR <#>")
    row15_bundle = _row(15, "unit.reload", note="sealed under decision (seal 06075e99), PR #555")
    row16 = _row(16, "pr.update", note="sealed under decision (seal 783bab4e)")
    _write_table(live, [row14, row15_live])
    _write_table(bundle, [row14, row15_bundle, row16])

    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, ledger=_FakeLedger(), project="fleet")

    assert out["ok"] is True, out
    assert out["added"] == [16]
    assert out["seals"] == {16: "783bab4e"}
    written = json.loads(live.read_text())
    by_id = {r["id"]: r for r in written["verbs"]}
    # The bundle's corrected note for row 15 landed too — a successful sync
    # writes the whole bundle, prose included.
    assert by_id[15]["note"] == "sealed under decision (seal 06075e99), PR #555"
    assert by_id[16]["verb"] == "pr.update"


def test_note_only_diff_with_no_addition_is_a_clean_noop(tables):
    """No new row at all, just a reworded note on an existing one — nothing
    to add, so the sync is a no-op rather than a refusal or a write."""
    live, bundle = tables
    row15_live = _row(15, "unit.reload", note="old wording")
    row15_bundle = _row(15, "unit.reload", note="new wording")
    _write_table(live, [row15_live])
    _write_table(bundle, [row15_bundle])
    before = live.read_text()

    out = constitutional.sync_syscall_table_from_bundle(live_path=live, bundle_path=bundle)

    assert out["ok"] is True and out["added"] == []
    assert live.read_text() == before


def test_bundle_missing_a_live_row_is_refused_live_untouched(tables):
    live, bundle = tables
    row14 = _row(14)
    row15 = _row(15, "unit.reload")
    # Live already has 15 (say, a prior sync); the bundle regressed and lost it.
    _write_table(live, [row14, row15])
    _write_table(bundle, [row14])
    before = live.read_text()

    out = constitutional.sync_syscall_table_from_bundle(live_path=live, bundle_path=bundle)

    assert out["ok"] is False and out["refused"] is True
    assert live.read_text() == before


# ── no-op shapes ───────────────────────────────────────────────────────────────

def test_tables_already_agree_is_a_clean_noop(tables):
    live, bundle = tables
    rows = [_row(14), _row(15, "unit.reload")]
    _write_table(live, rows)
    _write_table(bundle, rows)

    out = constitutional.sync_syscall_table_from_bundle(live_path=live, bundle_path=bundle)
    assert out["ok"] is True and out["added"] == []


def test_no_live_table_yet_is_not_a_refusal(tables):
    live, bundle = tables
    _write_table(bundle, [_row(14)])
    # live_path deliberately left unwritten

    out = constitutional.sync_syscall_table_from_bundle(live_path=live, bundle_path=bundle)
    assert out["ok"] is True and out["added"] == []
    assert not live.exists()


def test_bundle_missing_entirely_is_refused(tables):
    live, bundle = tables
    _write_table(live, [_row(14)])
    # bundle_path deliberately left unwritten

    out = constitutional.sync_syscall_table_from_bundle(live_path=live, bundle_path=bundle)
    assert out["ok"] is False and out["refused"] is True


# ── the bundle is package code: read plainly, not through trusted_read ────────

def test_group_writable_bundle_still_syncs(tables):
    """The editable-install bug: an umask-002 checkout leaves the shipped
    bundle 775/664. That must not make the sync refuse — the bundle's trust
    is git history, not filesystem ownership bits."""
    live, bundle = tables
    row14 = _row(14)
    row15 = _row(15, "unit.reload")
    _write_table(live, [row14])
    _write_table(bundle, [row14, row15])
    bundle.parent.chmod(0o775)
    bundle.chmod(0o664)

    out = constitutional.sync_syscall_table_from_bundle(live_path=live, bundle_path=bundle)

    assert out["ok"] is True
    assert out["added"] == [15]


def test_group_writable_live_table_refuses_live_table_untrusted(tables):
    """The live table is a governance input; it stays behind trusted_read."""
    live, bundle = tables
    row14 = _row(14)
    row15 = _row(15, "unit.reload")
    _write_table(live, [row14])
    _write_table(bundle, [row14, row15])
    live.parent.chmod(0o775)
    live.chmod(0o664)

    ledger = _FakeLedger()
    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, ledger=ledger, project="fleet")

    assert out["ok"] is False and out["refused"] is True
    assert "live_table_untrusted" in out["reason"]

    assert len(ledger.rows) == 1
    ev = ledger.rows[0]
    assert ev["event_type"] == "constitutional_sync_refused"
    assert ev["content"]["reason"] == out["reason"]
    assert ev["content"]["live_path"] == str(live)
    assert ev["content"]["bundle_path"] == str(bundle)


# ── every refusal writes FRANK ink; the one honest silence is agreement ──────

def test_modified_existing_row_refusal_writes_frank_ink(tables):
    # A STRUCTURAL change on an existing row (here min_ring) refuses and
    # inks. A note-only change would not — that is `_structural`'s job and
    # its own test; this one must keep exercising the refusal path.
    live, bundle = tables
    row3_live = _row(3, "git.push", min_ring="ENGINEER")
    row3_bundle = _row(3, "git.push", min_ring="WORKER")
    _write_table(live, [row3_live])
    _write_table(bundle, [row3_bundle])

    ledger = _FakeLedger()
    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, ledger=ledger, project="fleet")

    assert out["ok"] is False and out["refused"] is True
    assert len(ledger.rows) == 1
    ev = ledger.rows[0]
    assert ev["event_type"] == "constitutional_sync_refused"
    assert ev["content"]["reason"] == out["reason"]
    assert ev["content"]["live_rows"] == 1
    assert ev["content"]["bundle_rows"] == 1


def test_bundle_missing_a_live_row_refusal_writes_frank_ink(tables):
    live, bundle = tables
    row14 = _row(14)
    row15 = _row(15, "unit.reload")
    _write_table(live, [row14, row15])
    _write_table(bundle, [row14])

    ledger = _FakeLedger()
    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, ledger=ledger, project="fleet")

    assert out["ok"] is False and out["refused"] is True
    assert len(ledger.rows) == 1
    ev = ledger.rows[0]
    assert ev["event_type"] == "constitutional_sync_refused"
    assert ev["content"]["reason"] == out["reason"]
    assert ev["content"]["live_rows"] == 2
    assert ev["content"]["bundle_rows"] == 1


def test_bundle_missing_entirely_refusal_writes_frank_ink(tables):
    live, bundle = tables
    _write_table(live, [_row(14)])
    # bundle_path deliberately left unwritten

    ledger = _FakeLedger()
    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, ledger=ledger, project="fleet")

    assert out["ok"] is False and out["refused"] is True
    assert len(ledger.rows) == 1
    assert ledger.rows[0]["event_type"] == "constitutional_sync_refused"


def test_identical_tables_write_no_frank_ink(tables):
    """The one honest silence: nothing to sync, nothing to ink."""
    live, bundle = tables
    rows = [_row(14), _row(15, "unit.reload")]
    _write_table(live, rows)
    _write_table(bundle, rows)

    ledger = _FakeLedger()
    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, ledger=ledger, project="fleet")

    assert out["ok"] is True and out["added"] == []
    assert ledger.rows == []
