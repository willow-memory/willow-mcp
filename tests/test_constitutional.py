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
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from willow_mcp import constitutional
from willow_mcp import keyring as keyring_mod
from willow_mcp import net_authority
from willow_mcp import net_signer as ns


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
#
# Rework after Loki 573273BD's FAIL: authority now comes from the SEALED
# TEXT itself (a "syscall-row-amend: id=... verb=... from=... to=..."
# line inside a REAL, verifiable sealed pair), never from a SOIL record's
# own status/nestor_verifier/id/verb/hash fields. Every test that needs an
# authorized amendment now signs a real nestor.db pair with a real ed25519
# key via the `ring_with_sean` fixture -- same pattern test_reloader.py's
# `ring_with_sean` uses for find_sealing_decision.

@pytest.fixture
def ring_with_sean(tmp_path):
    """A keyring with a REAL ed25519 "sean campbell" entry active -- what
    `_confirm_amendment` now verifies every candidate seal against. Yields
    the `Keyring` so a test can sign with its private half."""
    with keyring_mod.isolated():
        k = keyring_mod.Keyring(path=str(tmp_path / "keys.json"))
        k.add("sean campbell", kind="ed25519")
        k.save()
        keyring_mod.set_keyring(k)
        try:
            yield k
        finally:
            keyring_mod.set_keyring(None)


def _sign_seal(kr, name, source_norm, target_text):
    entry = kr.get(name)
    priv = Ed25519PrivateKey.from_private_bytes(entry.private)
    return priv.sign(ns.seal_message(source_norm, target_text, name)).hex()


def _nestor_pair(db_path, pair_id, *, source_norm="amend a syscall row",
                  target_text="amend a syscall row: yes", status="sealed",
                  verifier="sean campbell", seal_sig="stub-seal-sig",
                  superseded_by="", created_at="2026-09-28T00:00:00Z"):
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
        "target_text, target_lang, status, verifier, created_at, seal_sig, superseded_by) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (pair_id, source_norm, source_norm, "decision", target_text,
         "decision", status, verifier, created_at, seal_sig, superseded_by),
    )
    conn.commit()
    conn.close()


def _sealed_amend_pair(db_path, kr, pair_id, *, row_id, verb, from_hash, to_hash,
                        verifier="sean campbell", extra_lines=(),
                        source_norm="amend a syscall row", status="sealed"):
    """A REAL, verifiable sealed pair whose conclusion carries the exact
    syscall-row-amend line(s) given."""
    lines = [constitutional._amend_line(row_id, verb, from_hash, to_hash), *extra_lines]
    target_text = "\n".join(lines)
    sig = _sign_seal(kr, verifier, source_norm, target_text)
    _nestor_pair(db_path, pair_id, source_norm=source_norm, target_text=target_text,
                 status=status, verifier=verifier, seal_sig=sig)
    return target_text


class _FakeGovStore:
    """Minimal store stand-in: only .all() is used by the amendment path."""

    def __init__(self, records):
        self._records = records

    def all(self, collection):
        return list(self._records)


def _gov_record(**kw):
    base = {"_id": "gov1", "kind": "syscall_row_amend", "nestor_pair_id": "pairABC"}
    base.update(kw)
    return base


def test_sealed_amendment_with_matching_hashes_applies_the_change(tables, tmp_path, ring_with_sean):
    live, bundle = tables
    row18_live = _row(18, "manifest.grant", bounds={"apps": "old description"})
    row18_bundle = _row(18, "manifest.grant", bounds={"apps": "new description"})
    _write_table(live, [row18_live])
    _write_table(bundle, [row18_bundle])

    from_hash = constitutional._row_hash(row18_live)
    to_hash = constitutional._row_hash(row18_bundle)
    nestor_db = tmp_path / "nestor.db"
    _sealed_amend_pair(nestor_db, ring_with_sean, "pairABC",
                       row_id=18, verb="manifest.grant",
                       from_hash=from_hash, to_hash=to_hash)
    gov = _FakeGovStore([_gov_record(nestor_pair_id="pairABC")])

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


def test_kind_filter_does_not_authorize_a_wrong_kind_record(tables, tmp_path, ring_with_sean):
    """F3 (Loki 573273BD): a record of a different kind, even carrying a
    real sealed pair naming this exact row/verb/hashes, must not
    authorize -- only kind==AMENDMENT_KIND is ever even a candidate."""
    live, bundle = tables
    row18_live = _row(18, "manifest.grant", bounds={"apps": "old"})
    row18_bundle = _row(18, "manifest.grant", bounds={"apps": "new"})
    _write_table(live, [row18_live])
    _write_table(bundle, [row18_bundle])
    before = live.read_text()

    from_hash = constitutional._row_hash(row18_live)
    to_hash = constitutional._row_hash(row18_bundle)
    nestor_db = tmp_path / "nestor.db"
    _sealed_amend_pair(nestor_db, ring_with_sean, "pairABC",
                       row_id=18, verb="manifest.grant",
                       from_hash=from_hash, to_hash=to_hash)
    gov = _FakeGovStore([_gov_record(kind="something_else", nestor_pair_id="pairABC")])

    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, store=gov, nestor_db_path=nestor_db)

    assert out["ok"] is False and out["refused"] is True
    assert "no sealed syscall_row_amend" in out["reason"]
    assert live.read_text() == before


def test_multi_candidate_a_stale_record_first_does_not_block_a_valid_one(tables, tmp_path, ring_with_sean):
    """F4 (Loki 573273BD): every candidate is checked; a stale/planted
    record listed first must not shadow a valid one that follows."""
    live, bundle = tables
    row18_live = _row(18, "manifest.grant", bounds={"apps": "old"})
    row18_bundle = _row(18, "manifest.grant", bounds={"apps": "new"})
    _write_table(live, [row18_live])
    _write_table(bundle, [row18_bundle])

    from_hash = constitutional._row_hash(row18_live)
    to_hash = constitutional._row_hash(row18_bundle)
    nestor_db = tmp_path / "nestor.db"
    _sealed_amend_pair(nestor_db, ring_with_sean, "pairGOOD",
                       row_id=18, verb="manifest.grant",
                       from_hash=from_hash, to_hash=to_hash)
    stale = _gov_record(_id="stale", nestor_pair_id="pair-does-not-exist")
    valid = _gov_record(_id="good", nestor_pair_id="pairGOOD")
    gov = _FakeGovStore([stale, valid])

    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, store=gov, nestor_db_path=nestor_db)

    assert out["ok"] is True, out
    assert out["amended"] == [{"id": 18, "verb": "manifest.grant",
                              "from_sha256": from_hash, "to_sha256": to_hash,
                              "pair_id": "pairGOOD"}]


def test_unsealed_amendment_is_refused(tables, tmp_path, ring_with_sean):
    """The ledger-confirmation guard, isolated (Loki 573273BD F2): a real
    keyring and a real signature -- but the pair itself is not
    status='sealed' in Nestor's own ledger. Nothing else is left to
    refuse this."""
    live, bundle = tables
    row18_live = _row(18, "manifest.grant", bounds={"apps": "old"})
    row18_bundle = _row(18, "manifest.grant", bounds={"apps": "new"})
    _write_table(live, [row18_live])
    _write_table(bundle, [row18_bundle])
    before = live.read_text()

    from_hash = constitutional._row_hash(row18_live)
    to_hash = constitutional._row_hash(row18_bundle)
    nestor_db = tmp_path / "nestor.db"
    _sealed_amend_pair(nestor_db, ring_with_sean, "pairABC",
                       row_id=18, verb="manifest.grant",
                       from_hash=from_hash, to_hash=to_hash, status="proposed")
    gov = _FakeGovStore([_gov_record(nestor_pair_id="pairABC")])

    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, store=gov, nestor_db_path=nestor_db)

    assert out["ok"] is False and out["refused"] is True
    assert "not confirmed sealed in the Nestor ledger" in out["reason"]
    assert live.read_text() == before


def test_amendment_with_wrong_from_hash_is_refused_by_name(tables, tmp_path, ring_with_sean):
    live, bundle = tables
    row18_live = _row(18, "manifest.grant", bounds={"apps": "old"})
    row18_bundle = _row(18, "manifest.grant", bounds={"apps": "new"})
    _write_table(live, [row18_live])
    _write_table(bundle, [row18_bundle])
    before = live.read_text()

    to_hash = constitutional._row_hash(row18_bundle)
    nestor_db = tmp_path / "nestor.db"
    _sealed_amend_pair(nestor_db, ring_with_sean, "pairABC",
                       row_id=18, verb="manifest.grant",
                       from_hash="deadbeef" * 8, to_hash=to_hash)
    gov = _FakeGovStore([_gov_record(nestor_pair_id="pairABC")])
    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, store=gov, nestor_db_path=nestor_db)

    assert out["ok"] is False and out["refused"] is True
    assert "does not match the live row's own hash" in out["reason"]
    assert "refused by name" in out["reason"]
    assert live.read_text() == before


def test_amendment_with_wrong_to_hash_is_refused_by_name(tables, tmp_path, ring_with_sean):
    live, bundle = tables
    row18_live = _row(18, "manifest.grant", bounds={"apps": "old"})
    row18_bundle = _row(18, "manifest.grant", bounds={"apps": "new"})
    _write_table(live, [row18_live])
    _write_table(bundle, [row18_bundle])
    before = live.read_text()

    from_hash = constitutional._row_hash(row18_live)
    nestor_db = tmp_path / "nestor.db"
    _sealed_amend_pair(nestor_db, ring_with_sean, "pairABC",
                       row_id=18, verb="manifest.grant",
                       from_hash=from_hash, to_hash="deadbeef" * 8)
    gov = _FakeGovStore([_gov_record(nestor_pair_id="pairABC")])
    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, store=gov, nestor_db_path=nestor_db)

    assert out["ok"] is False and out["refused"] is True
    assert "does not match the bundle row's own hash" in out["reason"]
    assert "refused by name" in out["reason"]
    assert live.read_text() == before


def test_amendment_id_verb_mismatch_is_refused_directly(tmp_path, ring_with_sean):
    """The id/verb-match guard, isolated (Loki 573273BD F2): a real, fully
    verifiable sealed pair -- naming row 19, not the row 18 being checked.
    Nothing else is left to refuse this."""
    live_row = _row(18, "manifest.grant", bounds={"apps": "old"})
    bundle_row = _row(18, "manifest.grant", bounds={"apps": "new"})
    from_hash = constitutional._row_hash(live_row)
    to_hash = constitutional._row_hash(bundle_row)
    nestor_db = tmp_path / "nestor.db"
    _sealed_amend_pair(nestor_db, ring_with_sean, "pairABC",
                       row_id=19, verb="manifest.grant",
                       from_hash=from_hash, to_hash=to_hash)
    rec = _gov_record(nestor_pair_id="pairABC")

    ok, why = constitutional._confirm_amendment(
        rec, live_row=live_row, bundle_row=bundle_row, nestor_db_path=nestor_db)
    assert ok is False
    assert "names id=19" in why


def test_amendment_pair_not_confirmed_in_nestor_ledger_is_refused(tables, tmp_path):
    """The Nestor-ledger confirmation guard: the pointed-at pair_id simply
    does not exist in nestor.db -- refused, never trusted on a SOIL field
    alone. No keyring/signature is needed to prove this: the ledger check
    runs first and already refuses."""
    live, bundle = tables
    row18_live = _row(18, "manifest.grant", bounds={"apps": "old"})
    row18_bundle = _row(18, "manifest.grant", bounds={"apps": "new"})
    _write_table(live, [row18_live])
    _write_table(bundle, [row18_bundle])
    before = live.read_text()

    nestor_db = tmp_path / "nestor.db"
    _nestor_pair(nestor_db, "some-other-pair")  # exists, but not our pair_id
    gov = _FakeGovStore([_gov_record(nestor_pair_id="pairABC")])
    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, store=gov, nestor_db_path=nestor_db)

    assert out["ok"] is False and out["refused"] is True
    assert "not confirmed sealed in the Nestor ledger" in out["reason"]
    assert live.read_text() == before


def test_unrelated_sealed_pair_does_not_authorize(tables, tmp_path, ring_with_sean):
    """A real, fully sealed and verifiable pair -- about something else
    entirely, naming no syscall-row-amend line at all -- must not
    authorize any row change (Loki 573273BD F1, probe P1's shape)."""
    live, bundle = tables
    row18_live = _row(18, "manifest.grant", bounds={"apps": "old"})
    row18_bundle = _row(18, "manifest.grant", bounds={"apps": "new"})
    _write_table(live, [row18_live])
    _write_table(bundle, [row18_bundle])
    before = live.read_text()

    nestor_db = tmp_path / "nestor.db"
    source_norm = "what colour is the sky?"
    target_text = "blue."
    sig = _sign_seal(ring_with_sean, "sean campbell", source_norm, target_text)
    _nestor_pair(nestor_db, "pairABC", source_norm=source_norm,
                 target_text=target_text, verifier="sean campbell", seal_sig=sig)
    gov = _FakeGovStore([_gov_record(nestor_pair_id="pairABC")])

    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, store=gov, nestor_db_path=nestor_db)

    assert out["ok"] is False and out["refused"] is True
    assert "0 syscall-row-amend line" in out["reason"]
    assert live.read_text() == before


def test_bad_signature_does_not_authorize(tables, tmp_path, ring_with_sean):
    """A well-formed syscall-row-amend line, correctly targeted -- but the
    seal_sig does not verify. Loki 573273BD F1's exact gap: the old code
    never called verify_seal at all."""
    live, bundle = tables
    row18_live = _row(18, "manifest.grant", bounds={"apps": "old"})
    row18_bundle = _row(18, "manifest.grant", bounds={"apps": "new"})
    _write_table(live, [row18_live])
    _write_table(bundle, [row18_bundle])
    before = live.read_text()

    from_hash = constitutional._row_hash(row18_live)
    to_hash = constitutional._row_hash(row18_bundle)
    target_text = constitutional._amend_line(18, "manifest.grant", from_hash, to_hash)
    nestor_db = tmp_path / "nestor.db"
    _nestor_pair(nestor_db, "pairABC", source_norm="amend a syscall row",
                 target_text=target_text, verifier="sean campbell",
                 seal_sig="00" * 64)  # well-formed hex, does not verify
    gov = _FakeGovStore([_gov_record(nestor_pair_id="pairABC")])

    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, store=gov, nestor_db_path=nestor_db)

    assert out["ok"] is False and out["refused"] is True
    assert "does not verify" in out["reason"]
    assert live.read_text() == before


def test_unknown_verifier_does_not_authorize(tables, tmp_path, ring_with_sean):
    """A REAL ed25519 signature, just not from anyone in the ring -- proves
    the check is "is this verifier trusted", not merely "is this bytes
    valid hex that verifies against SOME key" (same shape as reloader's
    Loki E79FCAE7 F5 probe)."""
    live, bundle = tables
    row18_live = _row(18, "manifest.grant", bounds={"apps": "old"})
    row18_bundle = _row(18, "manifest.grant", bounds={"apps": "new"})
    _write_table(live, [row18_live])
    _write_table(bundle, [row18_bundle])
    before = live.read_text()

    from_hash = constitutional._row_hash(row18_live)
    to_hash = constitutional._row_hash(row18_bundle)
    target_text = constitutional._amend_line(18, "manifest.grant", from_hash, to_hash)
    outsider = Ed25519PrivateKey.generate()
    sig = outsider.sign(ns.seal_message("amend a syscall row", target_text, "mallory")).hex()
    nestor_db = tmp_path / "nestor.db"
    _nestor_pair(nestor_db, "pairABC", source_norm="amend a syscall row",
                 target_text=target_text, verifier="mallory", seal_sig=sig)
    gov = _FakeGovStore([_gov_record(nestor_pair_id="pairABC")])

    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, store=gov, nestor_db_path=nestor_db)

    assert out["ok"] is False and out["refused"] is True
    assert "does not verify" in out["reason"]
    assert live.read_text() == before


def test_one_pair_naming_two_rows_does_not_authorize_either(tables, tmp_path, ring_with_sean):
    """One sealed pair authorizes exactly one row change (Loki 573273BD F1,
    probe P3): a sealed text naming rows 18 AND 19 must not authorize row
    18 even though its own line is otherwise correct."""
    live, bundle = tables
    row18_live = _row(18, "manifest.grant", bounds={"apps": "old"})
    row18_bundle = _row(18, "manifest.grant", bounds={"apps": "new"})
    row19_live = _row(19, "package.upgrade")
    row19_bundle = _row(19, "package.upgrade", bounds={"pkg": "new"})
    _write_table(live, [row18_live, row19_live])
    _write_table(bundle, [row18_bundle, row19_bundle])
    before = live.read_text()

    from_hash18 = constitutional._row_hash(row18_live)
    to_hash18 = constitutional._row_hash(row18_bundle)
    from_hash19 = constitutional._row_hash(row19_live)
    to_hash19 = constitutional._row_hash(row19_bundle)
    nestor_db = tmp_path / "nestor.db"
    _sealed_amend_pair(
        nestor_db, ring_with_sean, "pairABC",
        row_id=18, verb="manifest.grant", from_hash=from_hash18, to_hash=to_hash18,
        extra_lines=[constitutional._amend_line(19, "package.upgrade", from_hash19, to_hash19)])
    gov = _FakeGovStore([_gov_record(nestor_pair_id="pairABC")])

    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, store=gov, nestor_db_path=nestor_db)

    assert out["ok"] is False and out["refused"] is True
    assert "not exactly one" in out["reason"]
    assert live.read_text() == before


def test_soil_record_disagreeing_with_sealed_text_is_refused(tables, tmp_path, ring_with_sean):
    """A SOIL record whose own side field disagrees with its OWN sealed
    pair's text is refused -- even though the sealed text (not this field)
    is what actually authorizes, a record that contradicts its own seal is
    a confusing artifact, not a substitute path to trust."""
    live, bundle = tables
    row18_live = _row(18, "manifest.grant", bounds={"apps": "old"})
    row18_bundle = _row(18, "manifest.grant", bounds={"apps": "new"})
    _write_table(live, [row18_live])
    _write_table(bundle, [row18_bundle])
    before = live.read_text()

    from_hash = constitutional._row_hash(row18_live)
    to_hash = constitutional._row_hash(row18_bundle)
    nestor_db = tmp_path / "nestor.db"
    _sealed_amend_pair(nestor_db, ring_with_sean, "pairABC",
                       row_id=18, verb="manifest.grant",
                       from_hash=from_hash, to_hash=to_hash)
    # The sealed pair's own text names 18/manifest.grant correctly -- but
    # this SOIL record's own side field claims a different id.
    gov = _FakeGovStore([_gov_record(nestor_pair_id="pairABC", id=99)])

    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, store=gov, nestor_db_path=nestor_db)

    assert out["ok"] is False and out["refused"] is True
    assert "disagrees with its own sealed text" in out["reason"]
    assert live.read_text() == before


def test_no_keyring_configured_does_not_authorize(tables, tmp_path):
    """No keyring at all -- a seal cannot be verified without a ring to
    verify it against, so this refuses exactly like an unverifiable seal,
    never like "no amendment exists"."""
    assert keyring_mod.get_keyring() is None  # sanity: no ring fixture in play
    live, bundle = tables
    row18_live = _row(18, "manifest.grant", bounds={"apps": "old"})
    row18_bundle = _row(18, "manifest.grant", bounds={"apps": "new"})
    _write_table(live, [row18_live])
    _write_table(bundle, [row18_bundle])
    before = live.read_text()

    from_hash = constitutional._row_hash(row18_live)
    to_hash = constitutional._row_hash(row18_bundle)
    target_text = constitutional._amend_line(18, "manifest.grant", from_hash, to_hash)
    nestor_db = tmp_path / "nestor.db"
    _nestor_pair(nestor_db, "pairABC", source_norm="amend a syscall row",
                 target_text=target_text, verifier="sean campbell",
                 seal_sig="deadbeef" * 8)
    gov = _FakeGovStore([_gov_record(nestor_pair_id="pairABC")])

    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, store=gov, nestor_db_path=nestor_db)

    assert out["ok"] is False and out["refused"] is True
    assert "no keyring configured" in out["reason"]
    assert live.read_text() == before


def test_governance_read_exception_is_refused_and_inked_not_raised(tables, tmp_path):
    """F5 (Loki 573273BD): an exception while gathering amendment
    candidates (here, the store itself raising) must fail the sync
    CLOSED, with FRANK ink, never escape as a traceback."""
    live, bundle = tables
    row18_live = _row(18, "manifest.grant", bounds={"apps": "old"})
    row18_bundle = _row(18, "manifest.grant", bounds={"apps": "new"})
    _write_table(live, [row18_live])
    _write_table(bundle, [row18_bundle])
    before = live.read_text()

    class _RaisingStore:
        def all(self, collection):
            raise RuntimeError("store unavailable")

    ledger = _FakeLedger()
    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, ledger=ledger, project="fleet",
        store=_RaisingStore(), nestor_db_path=tmp_path / "nestor.db")

    assert out["ok"] is False and out["refused"] is True
    assert "RuntimeError" in out["reason"]
    assert live.read_text() == before
    assert len(ledger.rows) == 1
    assert ledger.rows[0]["event_type"] == "constitutional_sync_refused"


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
    assert row["amend_line"] == constitutional._amend_line(
        18, "manifest.grant", row["from_sha256"], row["to_sha256"])


def test_diff_changed_rows_is_empty_when_tables_agree(tables):
    live, bundle = tables
    rows = [_row(14), _row(15, "unit.reload")]
    _write_table(live, rows)
    _write_table(bundle, rows)

    out = constitutional.diff_changed_rows(live_path=live, bundle_path=bundle)
    assert out == {"ok": True, "rows": []}


# ── L1 (Loki B940141B F-L1): the amend-line parser is no looser than the
# line it emits -- re.ASCII refuses non-ASCII digits, [ \t] in place of \s
# refuses a line split across newlines, while tabs, extra spaces, CRLF and
# uppercase hashes all still parse. ────────────────────────────────────────────

def test_amend_regex_rejects_fields_split_across_newlines():
    text = ("syscall-row-amend:\nid=18\nverb=manifest.grant\nfrom=" + "a" * 64
            + "\nto=" + "b" * 64)
    assert constitutional._AMEND_LINE_RE.search(text) is None


def test_amend_regex_rejects_non_ascii_digits():
    text = "syscall-row-amend: id=\u0661\u0668 verb=manifest.grant from=" + "a" * 64 + " to=" + "b" * 64
    assert constitutional._AMEND_LINE_RE.search(text) is None


def test_amend_regex_accepts_tabs():
    text = ("syscall-row-amend:\tid=18\tverb=manifest.grant\tfrom=" + "a" * 64
            + "\tto=" + "b" * 64)
    m = constitutional._AMEND_LINE_RE.search(text)
    assert m is not None and m.group(1) == "18"


def test_amend_regex_accepts_extra_spaces():
    text = ("syscall-row-amend:  id=18  verb=manifest.grant  from=" + "a" * 64
            + "  to=" + "b" * 64)
    assert constitutional._AMEND_LINE_RE.search(text) is not None


def test_amend_regex_accepts_crlf_line_ending():
    text = ("prose\r\nsyscall-row-amend: id=18 verb=manifest.grant from=" + "a" * 64
            + " to=" + "b" * 64 + "\r\nmore")
    assert constitutional._AMEND_LINE_RE.search(text) is not None


def test_amend_regex_accepts_uppercase_hashes():
    text = "syscall-row-amend: id=18 verb=manifest.grant from=" + "A" * 64 + " to=" + "B" * 64
    assert constitutional._AMEND_LINE_RE.search(text) is not None


# ── Loki B940141B isolation tests: one guard standing alone, adopted from
# Loki's B940141B Kart tasks (Z6CYQDFK, 5XBAVNSV). ────────────────────────

def _iso_rows():
    return (_row(18, "manifest.grant", bounds={"apps": "old"}),
            _row(18, "manifest.grant", bounds={"apps": "new"}))


def _iso_sync(tables, tmp_path, kr, *, target_text=None, rec=None, created_at=None, recs=None):
    live, bundle = tables
    lv, bv = _iso_rows()
    _write_table(live, [lv])
    _write_table(bundle, [bv])
    from_hash, to_hash = constitutional._row_hash(lv), constitutional._row_hash(bv)
    tt = target_text if target_text is not None else constitutional._amend_line(
        18, "manifest.grant", from_hash, to_hash)
    nestor_db = tmp_path / "nestor.db"
    sig = _sign_seal(kr, "sean campbell", "amend a syscall row", tt)
    kw = {"created_at": created_at} if created_at else {}
    _nestor_pair(nestor_db, "pairABC", source_norm="amend a syscall row",
                 target_text=tt, verifier="sean campbell", seal_sig=sig, **kw)
    before = live.read_text()
    ledger = _FakeLedger()
    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, ledger=ledger,
        store=_FakeGovStore(recs if recs is not None else [rec or _gov_record()]),
        nestor_db_path=nestor_db)
    return out, live.read_text() != before, ledger, (from_hash, to_hash)


def test_iso_verb_only_mismatch_is_refused(tables, tmp_path, ring_with_sean):
    """M1v: the verb check alone, id correct."""
    lv, bv = _iso_rows()
    tt = constitutional._amend_line(18, "other.verb",
                                     constitutional._row_hash(lv), constitutional._row_hash(bv))
    out, changed, _, _ = _iso_sync(tables, tmp_path, ring_with_sean, target_text=tt)
    assert out["ok"] is False and changed is False


def test_iso_kind_at_confirm_alone_refuses(tmp_path, ring_with_sean):
    """M8k: the kind check inside _confirm_amendment, isolated from the
    candidate-list kind filter (which would otherwise shadow it)."""
    lv, bv = _iso_rows()
    nestor_db = tmp_path / "nestor.db"
    _sealed_amend_pair(nestor_db, ring_with_sean, "pairABC", row_id=18, verb="manifest.grant",
                        from_hash=constitutional._row_hash(lv), to_hash=constitutional._row_hash(bv))
    ok, _why = constitutional._confirm_amendment(
        _gov_record(kind="other"), live_row=lv, bundle_row=bv, nestor_db_path=nestor_db)
    assert ok is False


def test_iso_soil_verb_disagrees_is_refused(tables, tmp_path, ring_with_sean):
    """M7v."""
    out, changed, _, _ = _iso_sync(tables, tmp_path, ring_with_sean, rec=_gov_record(verb="x"))
    assert out["ok"] is False and changed is False


def test_iso_soil_from_disagrees_is_refused(tables, tmp_path, ring_with_sean):
    """M7f."""
    out, changed, _, _ = _iso_sync(tables, tmp_path, ring_with_sean, rec=_gov_record(from_sha256="ab" * 32))
    assert out["ok"] is False and changed is False


def test_iso_soil_to_disagrees_is_refused(tables, tmp_path, ring_with_sean):
    """M7t."""
    out, changed, _, _ = _iso_sync(tables, tmp_path, ring_with_sean, rec=_gov_record(to_sha256="ab" * 32))
    assert out["ok"] is False and changed is False


def test_iso_soil_string_id_is_coerced_and_applies(tables, tmp_path, ring_with_sean):
    """M7c: a SOIL id given as the string '18' is coerced to compare equal."""
    out, changed, _, _ = _iso_sync(tables, tmp_path, ring_with_sean, rec=_gov_record(id="18"))
    assert out["ok"] is True and changed is True


def test_iso_old_seal_still_applies(tables, tmp_path, ring_with_sean):
    """M2a: verify_seal is called with max_age_s=None -- a seal sealed long
    ago (here 400 days) must still authorize at restart, not just at seal
    time. created_at is set explicitly here so 'today' cannot silently
    hide a dropped max_age_s=None."""
    old = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
    out, changed, _, _ = _iso_sync(tables, tmp_path, ring_with_sean, created_at=old)
    assert out["ok"] is True and changed is True, out


def test_iso_uppercase_hashes_still_apply(tables, tmp_path, ring_with_sean):
    """M10: the .lower() normalization of the amend line's hex hashes."""
    lv, bv = _iso_rows()
    tt = constitutional._amend_line(18, "manifest.grant",
                                     constitutional._row_hash(lv).upper(),
                                     constitutional._row_hash(bv).upper())
    out, changed, _, _ = _iso_sync(tables, tmp_path, ring_with_sean, target_text=tt)
    assert out["ok"] is True and changed is True, out


def test_iso_amend_line_prefixed_inline_in_a_sentence_is_refused(tables, tmp_path, ring_with_sean):
    """M11: the ^ anchor -- a line with text before it on the same line."""
    lv, bv = _iso_rows()
    tt = "I approve " + constitutional._amend_line(
        18, "manifest.grant", constitutional._row_hash(lv), constitutional._row_hash(bv))
    out, changed, _, _ = _iso_sync(tables, tmp_path, ring_with_sean, target_text=tt)
    assert out["ok"] is False and changed is False


def test_iso_amend_line_suffixed_inline_in_a_sentence_is_refused(tables, tmp_path, ring_with_sean):
    """M11b: the $ anchor -- a line with text after it on the same line."""
    lv, bv = _iso_rows()
    tt = constitutional._amend_line(
        18, "manifest.grant", constitutional._row_hash(lv), constitutional._row_hash(bv)) + " and also more"
    out, changed, _, _ = _iso_sync(tables, tmp_path, ring_with_sean, target_text=tt)
    assert out["ok"] is False and changed is False


def test_iso_raising_candidate_does_not_block_a_valid_one(tables, tmp_path, ring_with_sean, monkeypatch):
    """M9/M12: the per-candidate except -- a candidate whose
    read_sealed_pair call raises must not shadow a later valid candidate."""
    orig = net_authority.read_sealed_pair

    def boom(pid, db):
        if pid == "boom":
            raise RuntimeError("kaboom")
        return orig(pid, db)

    monkeypatch.setattr(net_authority, "read_sealed_pair", boom)
    out, changed, _, _ = _iso_sync(
        tables, tmp_path, ring_with_sean,
        recs=[_gov_record(_id="b", nestor_pair_id="boom"), _gov_record(_id="g")])
    assert out["ok"] is True and changed is True, out


def test_iso_raising_candidate_alone_is_refused_and_inked(tables, tmp_path, ring_with_sean, monkeypatch):
    """M12's twin: the raising candidate alone, with no valid one after
    it -- still refused and inked, never raised."""
    def boom(pid, db):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(net_authority, "read_sealed_pair", boom)
    out, changed, ledger, _ = _iso_sync(
        tables, tmp_path, ring_with_sean, recs=[_gov_record(nestor_pair_id="boom")])
    assert out["ok"] is False and changed is False
    assert [r["event_type"] for r in ledger.rows] == ["constitutional_sync_refused"]


def test_iso_unsealed_amendment_outcome_only(tables, tmp_path, ring_with_sean):
    """M4n, outcome-only twin of test_unsealed_amendment_is_refused: proves
    net_authority's status!=sealed guard at the outcome level rather than
    by matching refusal wording."""
    live, bundle = tables
    lv, bv = _iso_rows()
    _write_table(live, [lv])
    _write_table(bundle, [bv])
    nestor_db = tmp_path / "nestor.db"
    _sealed_amend_pair(nestor_db, ring_with_sean, "pairABC", row_id=18, verb="manifest.grant",
                        from_hash=constitutional._row_hash(lv), to_hash=constitutional._row_hash(bv),
                        status="proposed")
    before = live.read_text()
    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, store=_FakeGovStore([_gov_record()]),
        nestor_db_path=nestor_db)
    assert out["ok"] is False and live.read_text() == before


def test_iso_bad_signature_outcome_only(tables, tmp_path, ring_with_sean):
    """M2, outcome-only twin of test_bad_signature_does_not_authorize."""
    live, bundle = tables
    lv, bv = _iso_rows()
    _write_table(live, [lv])
    _write_table(bundle, [bv])
    tt = constitutional._amend_line(18, "manifest.grant",
                                     constitutional._row_hash(lv), constitutional._row_hash(bv))
    nestor_db = tmp_path / "nestor.db"
    _nestor_pair(nestor_db, "pairABC", source_norm="amend a syscall row",
                 target_text=tt, verifier="sean campbell", seal_sig="00" * 64)
    before = live.read_text()
    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live, bundle_path=bundle, store=_FakeGovStore([_gov_record()]),
        nestor_db_path=nestor_db)
    assert out["ok"] is False and live.read_text() == before
