"""Row 25 `package.upgrade` is in the shipped bundle table with the bounds
signature its own note states — {repo, tags, venv} — and the propose-time
signature check accepts exactly that shape; a bounds object missing one of
the three or carrying an extra key is `InvalidBoundsSignatureError`, the
same rule every other row lives under (test_syscall_row_17_unit_install.py's
own docstring, restated here for row 25).

Row 25 is UNSEALED (dispatch 28D6C18E, gap c1b4a8d006dc; see the row's own
note) — the one thing this row's tests do NOT assert is a Nestor pair id,
unlike every sibling row's test file, because none was ever produced for it.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from willow_mcp import envelope_authoring as ea

_BUNDLE = (
    Path(__file__).resolve().parents[1]
    / "src" / "willow_mcp" / "bundle" / "constitutional" / "syscall-table.json"
)


def _rows() -> dict[int, dict]:
    table = json.loads(_BUNDLE.read_text(encoding="utf-8"))
    return {int(r["id"]): r for r in table["verbs"]}


def test_row_25_is_package_upgrade_with_the_stated_shape():
    row = _rows()[25]
    assert row["verb"] == "package.upgrade"
    assert set(row["bounds"]) == {"repo", "tags", "venv"}
    assert row["enforcement"] == "soft"
    assert row["enforced_by"] is None
    assert row["min_ring"] == "ENGINEER"


def test_row_25_note_says_unsealed_and_names_the_gap():
    row = _rows()[25]
    assert "UNSEALED" in row["note"]
    assert "c1b4a8d006dc" in row["note"]
    assert "28D6C18E" in row["note"]


def test_row_ids_are_dense_through_25():
    ids = sorted(_rows())
    assert ids == list(range(1, 19)) + list(range(20, 27))  # 26: model.pull
    assert 19 not in ids
    assert 25 in ids


def test_bounds_signature_accepts_repo_tags_venv():
    verb_id = ea._validate_bounds_signature(
        "package.upgrade",
        {"repo": "willow-memory/kartikeya", "tags": ["v0.3.4"], "venv": "willow-mcp"},
        _rows(),
    )
    assert verb_id == 25


@pytest.mark.parametrize("bounds", [
    {"tags": ["v0.3.4"], "venv": "willow-mcp"},                       # missing repo
    {"repo": "o/r", "venv": "willow-mcp"},                            # missing tags
    {"repo": "o/r", "tags": ["v1"]},                                  # missing venv
    {"repo": "o/r", "tags": ["v1"], "venv": "willow-mcp", "mode": "x"},  # extra key
])
def test_bounds_signature_refuses_a_missing_or_extra_key(bounds):
    with pytest.raises(ea.InvalidBoundsSignatureError, match="bounds signature mismatch"):
        ea._validate_bounds_signature("package.upgrade", bounds, _rows())
