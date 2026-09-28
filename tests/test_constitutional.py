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
import sqlite3
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


# -- sealed amendment path (gap 82022def338f, ruling A, pair 3445116c) --------

def _nestor_pair(db_path, pair_id, status="sealed", seal_sig="stub-seal-sig"):
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS tm_pairs (
            id TEXT PRIMARY KEY, source_text TEXT NOT NULL, source_norm TEXT NOT NULL,
            source_lang TEXT NOT NULL, target_text TEXT NOT NULL, target_lang TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft', verifier TEXT NOT NULL DEFAULT '',
            weight REAL NOT NULL DEFAULT 1.0, origin TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL, seal_sig TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '', superseded_by TEXT NOT NULL DEFAULT '',
            visibility TEXT NOT NULL DEFAULT 'internal'
        );
    """)
    conn.execute(
        "INSERT OR REPLACE INTO tm_pairs (id, source_text, source_norm, source_lang, "
        "target_text, target_lang, status, verifier, created_at, seal_sig) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (pair_id, "amend row 18?", "amend row 18?", "decision", "amend row 18: yes",
         "decision", status, "sean campbell", "2026-09-28T00:00:00Z", seal_sig),
    )
    conn.commit()
    conn.close()


class _FakeGovStore:
    """Minimal store stand-in: only .all() is used by the amendment path."""

    def __init__(self, records):
        self._records = records

    def all(self, collection):
        return list(self._records)


def _gov_record(**kw):
    base = {"_id": "gov1", "kind": "syscall_row_amend",
            "status": "sealed", "nestor_pair_id": "pairABC",
            "nestor_verifier": "sean campbell"}
    base.update(kw)
    return base


def test_sealed_amendment_with_matching_hashes_applies_the_change(tables, tmp_path):
    live, bundle = tables
    row18_live = _row(18, "manifest.grant", bounds={"apps": "old description"})
    row18_bundle = _row(18, "manifest.grant", bounds={"apps": "new description"})
    _write_table(live, [row18_live])
    _write_table(bundle, [row18_bundle])

    from_hash = constitutional._row_hash(row18_live)
    to_hash = constitutional._row_hash(row18_bundle)
    nestor_db = tmp_path / "nestor.db"
    _nestor_pair(nestor_db, "pairABC")
    gov = _FakeGovStore([_gov_record(id=18, verb="manifest.grant",
                                     from_sha256=from_hash, to_sha256=to_hash)])

    ledger = _FakeLedger()
    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, ledger=ledger, project="fleet",
        store=gov, nestor_db_path=nestor_db)

    assert out["ok"] is True, out
    assert out["amended"] == [{"id": 18, "verb": "manifest.grant",
                              "from_sha256": from_hash, "to_sha256": to_hash,
                              "pair_id": "pairABC"}]
    written = json.loads(live.read_text())
    assert written["verbs"][0]["bounds"] == {"apps": "new description"}
    assert len(ledger.rows) == 1
    assert ledger.rows[0]["content"]["amended"] == out["amended"]


def test_missing_row_with_no_amendment_at_all_is_refused(tables, tmp_path):
    """The 'refusal of a missing row' guard: no syscall_row_amend decision
    exists at all for the changed row -- refused exactly as before."""
    live, bundle = tables
    row18_live = _row(18, "manifest.grant", bounds={"apps": "old"})
    row18_bundle = _row(18, "manifest.grant", bounds={"apps": "new"})
    _write_table(live, [row18_live])
    _write_table(bundle, [row18_bundle])
    before = live.read_text()

    gov = _FakeGovStore([])  # nothing at all
    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, store=gov,
        nestor_db_path=tmp_path / "nestor.db")

    assert out["ok"] is False and out["refused"] is True
    assert "no sealed syscall_row_amend" in out["reason"]
    assert live.read_text() == before


def test_unsealed_amendment_is_refused(tables, tmp_path):
    """The seal-status guard: a matching decision exists but status is not
    'sealed' -- refused, live untouched."""
    live, bundle = tables
    row18_live = _row(18, "manifest.grant", bounds={"apps": "old"})
    row18_bundle = _row(18, "manifest.grant", bounds={"apps": "new"})
    _write_table(live, [row18_live])
    _write_table(bundle, [row18_bundle])
    before = live.read_text()

    from_hash = constitutional._row_hash(row18_live)
    to_hash = constitutional._row_hash(row18_bundle)
    gov = _FakeGovStore([_gov_record(id=18, verb="manifest.grant", status="proposed",
                                     from_sha256=from_hash, to_sha256=to_hash)])
    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, store=gov,
        nestor_db_path=tmp_path / "nestor.db")

    assert out["ok"] is False and out["refused"] is True
    assert "is not sealed" in out["reason"]
    assert live.read_text() == before


def test_amendment_with_wrong_from_hash_is_refused_by_name(tables, tmp_path):
    live, bundle = tables
    row18_live = _row(18, "manifest.grant", bounds={"apps": "old"})
    row18_bundle = _row(18, "manifest.grant", bounds={"apps": "new"})
    _write_table(live, [row18_live])
    _write_table(bundle, [row18_bundle])
    before = live.read_text()

    to_hash = constitutional._row_hash(row18_bundle)
    nestor_db = tmp_path / "nestor.db"
    _nestor_pair(nestor_db, "pairABC")
    gov = _FakeGovStore([_gov_record(id=18, verb="manifest.grant",
                                     from_sha256="deadbeef" * 8, to_sha256=to_hash)])
    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, store=gov, nestor_db_path=nestor_db)

    assert out["ok"] is False and out["refused"] is True
    assert "does not match the live row's own hash" in out["reason"]
    assert "refused by name" in out["reason"]
    assert live.read_text() == before


def test_amendment_with_wrong_to_hash_is_refused_by_name(tables, tmp_path):
    live, bundle = tables
    row18_live = _row(18, "manifest.grant", bounds={"apps": "old"})
    row18_bundle = _row(18, "manifest.grant", bounds={"apps": "new"})
    _write_table(live, [row18_live])
    _write_table(bundle, [row18_bundle])
    before = live.read_text()

    from_hash = constitutional._row_hash(row18_live)
    nestor_db = tmp_path / "nestor.db"
    _nestor_pair(nestor_db, "pairABC")
    gov = _FakeGovStore([_gov_record(id=18, verb="manifest.grant",
                                     from_sha256=from_hash, to_sha256="deadbeef" * 8)])
    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, store=gov, nestor_db_path=nestor_db)

    assert out["ok"] is False and out["refused"] is True
    assert "does not match the bundle row's own hash" in out["reason"]
    assert "refused by name" in out["reason"]
    assert live.read_text() == before


def test_amendment_id_verb_mismatch_is_refused_directly():
    """The id/verb-match guard, exercised directly on _confirm_amendment
    (the through-sync path always pre-filters on id/verb via
    _find_amendment, so this guard's own unit test calls the helper
    itself, same as the module's docstring names it)."""
    live_row = _row(18, "manifest.grant", bounds={"apps": "old"})
    bundle_row = _row(18, "manifest.grant", bounds={"apps": "new"})
    rec = _gov_record(id=19, verb="manifest.grant",
                      from_sha256=constitutional._row_hash(live_row),
                      to_sha256=constitutional._row_hash(bundle_row))
    ok, why = constitutional._confirm_amendment(rec, live_row=live_row, bundle_row=bundle_row)
    assert ok is False
    assert "names id=19" in why


def test_amendment_pair_not_confirmed_in_nestor_ledger_is_refused(tables, tmp_path):
    """The Nestor-ledger confirmation guard: the SOIL record says sealed but
    nestor.db disagrees (no such pair) -- refused, never trusted on the
    SOIL field alone."""
    live, bundle = tables
    row18_live = _row(18, "manifest.grant", bounds={"apps": "old"})
    row18_bundle = _row(18, "manifest.grant", bounds={"apps": "new"})
    _write_table(live, [row18_live])
    _write_table(bundle, [row18_bundle])
    before = live.read_text()

    from_hash = constitutional._row_hash(row18_live)
    to_hash = constitutional._row_hash(row18_bundle)
    nestor_db = tmp_path / "nestor.db"
    # nestor.db exists but has no row for this pair_id at all.
    _nestor_pair(nestor_db, "some-other-pair")
    gov = _FakeGovStore([_gov_record(id=18, verb="manifest.grant",
                                     from_sha256=from_hash, to_sha256=to_hash)])
    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, store=gov, nestor_db_path=nestor_db)

    assert out["ok"] is False and out["refused"] is True
    assert "not confirmed sealed in the Nestor ledger" in out["reason"]
    assert live.read_text() == before


def test_diff_changed_rows_preview_names_field_diff_and_hashes(tables):
    live, bundle = tables
    row18_live = _row(18, "manifest.grant", bounds={"apps": "old"})
    row18_bundle = _row(18, "manifest.grant", bounds={"apps": "new"})
    row14 = _row(14, "agent.lifecycle")
    _write_table(live, [row14, row18_live])
    _write_table(bundle, [row14, row18_bundle])

    out = constitutional.diff_changed_rows(live_path=live, bundle_path=bundle)

    assert out["ok"] is True
    assert len(out["rows"]) == 1
    row = out["rows"][0]
    assert row["id"] == 18 and row["verb"] == "manifest.grant"
    assert row["diff"] == {"bounds": {"from": {"apps": "old"}, "to": {"apps": "new"}}}
    assert row["from_sha256"] == constitutional._row_hash(row18_live)
    assert row["to_sha256"] == constitutional._row_hash(row18_bundle)


def test_diff_changed_rows_is_empty_when_tables_agree(tables):
    live, bundle = tables
    rows = [_row(14), _row(15, "unit.reload")]
    _write_table(live, rows)
    _write_table(bundle, rows)

    out = constitutional.diff_changed_rows(live_path=live, bundle_path=bundle)
    assert out == {"ok": True, "rows": []}
