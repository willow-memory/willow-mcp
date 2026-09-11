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
