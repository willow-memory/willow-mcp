"""Tests for willow_mcp.nest.autointake — the SessionStart join that runs the
drop-zone pipeline end-to-end so a dropped file is processed, not just staged.

Mirrors the env/store fixtures in test_nest_intake.py: isolate HOME,
$WILLOW_HOME, and the rules store into tmp so classification + destination
moves land in a throwaway tree.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from willow_mcp.db import Store
from willow_mcp.nest import autointake, intake, rules


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path / "wh"))
    monkeypatch.setenv("WILLOW_NEST_RULES", str(tmp_path / "nest_rules.json"))
    rules._reset_cache()
    drop = tmp_path / "Desktop" / "Nest"
    drop.mkdir(parents=True)
    return tmp_path, drop


@pytest.fixture
def store(tmp_path):
    return Store(str(tmp_path / "store"))


def test_fresh_drop_is_scanned_and_intook(env, store):
    """A fresh, cleanly-classifiable file: after the hook it is not just
    staged — it is filed out of the queue entirely."""
    _tmp, drop = env
    f = drop / "2024-05-01.md"
    f.write_text("dear diary")

    result = autointake.run(store, app_id="hook", folders=[drop])

    assert result["status"] == "ok"
    assert result["newly_staged"] == 1
    assert len(result["filed"]) == 1
    assert result["filed"][0]["track"] == "journal"
    assert not f.exists()  # moved out of the drop zone
    # The queue no longer holds it (this is the point — not just staged).
    assert intake.get_queue(store) == []


def test_low_confidence_and_secret_flagged_items_are_held(env, store):
    """An unclassifiable file (low confidence) and a file whose content trips
    the secrets sniff are both LEFT in the queue and surfaced — never forced
    through automatically."""
    _tmp, drop = env
    unknown = drop / "mystery.bin"
    unknown.write_text("no rule matches this filename")

    leaky = drop / "invoice_march.txt"  # classifies cleanly (financial)...
    leaky.write_text("total due\naws_key=AKIAABCDEFGHIJKLMNOP\n")  # ...but leaks a secret

    result = autointake.run(store, app_id="hook", folders=[drop])

    assert result["status"] == "ok"
    assert result["filed"] == []
    held_names = {h["filename"] for h in result["held"]}
    assert held_names == {"mystery.bin", "invoice_march.txt"}

    unknown_hold = next(h for h in result["held"] if h["filename"] == "mystery.bin")
    assert "low_confidence" in unknown_hold["reason"]
    leaky_hold = next(h for h in result["held"] if h["filename"] == "invoice_march.txt")
    assert "secrets:" in leaky_hold["reason"]
    assert "aws_access_key" in leaky_hold["reason"]

    # Both files are still on disk, unmoved, and still pending in the queue —
    # a human decision, never forced.
    assert unknown.exists() and leaky.exists()
    pending_ids = {it["id"] for it in intake.get_queue(store)}
    assert len(pending_ids) == 2

    # The boot line surfaces them rather than staying silent.
    line = autointake.boot_line(app_id="hook", folders=[drop], store=store)
    assert line is not None
    assert "need review" in line


def test_rerun_is_idempotent_no_double_intake(env, store):
    """Re-running the hook after a file was already filed processes nothing
    new — no double-intake, no error."""
    _tmp, drop = env
    f = drop / "2024-05-01.md"
    f.write_text("dear diary")

    first = autointake.run(store, app_id="hook", folders=[drop])
    assert len(first["filed"]) == 1
    moved_to = Path(first["filed"][0]["moved_to"])
    assert moved_to.exists()

    second = autointake.run(store, app_id="hook", folders=[drop])
    assert second["status"] == "ok"
    assert second["newly_staged"] == 0
    assert second["filed"] == []
    assert second["held"] == []
    # Still exactly one copy at the destination — no re-file, no duplicate.
    assert moved_to.exists()
    assert intake.get_queue(store) == []


def test_binary_body_with_secret_is_held_not_filed(env, store):
    """A non-UTF-8 binary carrier (a .pdf) with an embedded AWS key must not
    slip through just because strict UTF-8 decoding of the body would raise —
    the sniff now scans raw bytes leniently, so the secret is still caught."""
    _tmp, drop = env
    pdf = drop / "invoice_confidential.pdf"
    # %PDF header + non-UTF-8 bytes (0xFF/0xFE are invalid UTF-8 continuation
    # bytes on their own) + a live-shaped AWS key.
    pdf.write_bytes(b"%PDF-1.4\n\xff\xfe\x00\x01 AKIAABCDEFGHIJKLMNOP \xff\xfe\n")

    result = autointake.run(store, app_id="hook", folders=[drop])

    assert result["status"] == "ok"
    assert result["filed"] == []
    held = next(h for h in result["held"] if h["filename"] == "invoice_confidential.pdf")
    assert "secrets:" in held["reason"]
    assert "aws_access_key" in held["reason"]
    assert pdf.exists()
    assert len(intake.get_queue(store)) == 1


def test_filename_secret_is_held_even_with_clean_body(env, store):
    """A credential riding in the FILENAME, not the body, must still trip the
    gate — the sniff checks the name unconditionally, not just the content."""
    _tmp, drop = env
    leaky_name = drop / "invoice-AKIAABCDEFGHIJKLMNOP.md"
    leaky_name.write_text("nothing sensitive in here")

    result = autointake.run(store, app_id="hook", folders=[drop])

    assert result["status"] == "ok"
    assert result["filed"] == []
    held = next(h for h in result["held"] if h["filename"] == "invoice-AKIAABCDEFGHIJKLMNOP.md")
    assert "secrets:" in held["reason"]
    assert "aws_access_key" in held["reason"]
    assert leaky_name.exists()
    assert len(intake.get_queue(store)) == 1


def test_embedded_key_glued_to_letters_is_held_not_filed(env, store):
    """The word-boundary evasion from the re-audit: a live AWS key with no
    separator on either side (`wrapAKIA...wrap`) must still trip the gate —
    the old `\\b`-anchored scan let this sail through classified and
    auto-filed with the key intact."""
    _tmp, drop = env
    glued = "wrap" + "AKIA" + "Q" * 16 + "wrap"
    leaky = drop / "journal_entry.md"
    leaky.write_text(f"dear diary, today I saw {glued} on a screen")

    result = autointake.run(store, app_id="hook", folders=[drop])

    assert result["status"] == "ok"
    assert result["filed"] == []
    held = next(h for h in result["held"] if h["filename"] == "journal_entry.md")
    assert "secrets:" in held["reason"]
    assert "aws_access_key" in held["reason"]
    assert leaky.exists()
    assert len(intake.get_queue(store)) == 1


def test_secret_kinds_catches_a_credential_in_a_parent_directory_name(tmp_path):
    """Unit-level regression for the LOW: `_secret_kinds` used to scan only
    `path.name`, though its own comment claimed "the path travels" — a
    credential riding a PARENT directory component (e.g. a folder named
    after a leaked key) sailed through unscanned. It now scans every path
    component. (intake.scan's drop zone itself is flat/non-recursive, so
    this is exercised directly against `_secret_kinds` rather than through
    the full `autointake.run` pipeline.)"""
    leaky_dir = tmp_path / f"AKIA{'Q' * 16}-backup"
    leaky_dir.mkdir()
    clean_file = leaky_dir / "notes.md"
    clean_file.write_text("nothing sensitive in the body")

    kinds = autointake._secret_kinds(clean_file)

    assert "aws_access_key" in kinds


def test_secret_kinds_is_quiet_on_an_ordinary_parent_directory_name(tmp_path):
    """Non-regression: a normal parent directory name must not trip the
    gate just because path components are now scanned."""
    plain_dir = tmp_path / "invoices_2026"
    plain_dir.mkdir()
    clean_file = plain_dir / "march.md"
    clean_file.write_text("total due: 42.00")

    kinds = autointake._secret_kinds(clean_file)

    assert kinds == []


def test_oversized_file_is_held_not_filed_uninspected(env, store):
    """A file too large for the sniff cap cannot be affirmatively cleared —
    it must be HELD, never filed on the strength of an unread tail, even
    though it classifies cleanly by filename and carries a secret up front."""
    _tmp, drop = env
    big = drop / "invoice_bulk.txt"
    padding = b"x" * (autointake._MAX_SNIFF_BYTES + 1024)
    big.write_bytes(b"aws_key=AKIAABCDEFGHIJKLMNOP\n" + padding)

    result = autointake.run(store, app_id="hook", folders=[drop])

    assert result["status"] == "ok"
    assert result["filed"] == []
    held = next(h for h in result["held"] if h["filename"] == "invoice_bulk.txt")
    assert "secrets:" in held["reason"]
    assert "uninspectable" in held["reason"]
    assert big.exists()
    assert len(intake.get_queue(store)) == 1


def test_unreadable_file_holds_rather_than_clears(env, store):
    """A read failure (permission denied, etc.) must be reported as 'could
    not clear', not misread as 'clean' — fail closed, never fail open."""
    _tmp, drop = env
    unreadable = drop / "invoice_locked.txt"
    unreadable.write_text("aws_key=AKIAABCDEFGHIJKLMNOP\n")
    unreadable.chmod(0o000)

    try:
        result = autointake.run(store, app_id="hook", folders=[drop])
    finally:
        unreadable.chmod(0o644)  # restore so tmp_path cleanup can remove it

    assert result["status"] == "ok"
    assert result["filed"] == []
    held = next(h for h in result["held"] if h["filename"] == "invoice_locked.txt")
    assert "secrets:" in held["reason"]
    assert "uninspectable" in held["reason"]
    assert len(intake.get_queue(store)) == 1


def test_empty_drop_zone_is_a_clean_noop(env, store):
    """No files dropped: the hook is a clean no-op and never raises, even
    when the drop dir itself doesn't exist."""
    _tmp, drop = env  # drop exists but is empty

    result = autointake.run(store, app_id="hook", folders=[drop])
    assert result == {"status": "ok", "newly_staged": 0, "filed": [], "held": []}

    missing = drop.parent / "does-not-exist"
    result2 = autointake.run(store, app_id="hook", folders=[missing])
    assert result2 == {"status": "ok", "newly_staged": 0, "filed": [], "held": []}

    assert autointake.boot_line(app_id="hook", folders=[drop], store=store) is None
