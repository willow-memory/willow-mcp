"""Row 17 `unit.install` (sealed `197aafa5`) is in the shipped bundle table
with the bounds signature the seal states, and the propose-time signature
check accepts exactly that shape — a bounds object missing `sources` or
carrying an extra key is `InvalidBoundsSignatureError`, the same rule every
other row lives under. The live-table sync (`constitutional.py`) picks the
row up on the next broker restart by the `seal <id>` convention in its note,
so the note is checked for that too.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from willow_mcp import constitutional, envelope_authoring as ea

_BUNDLE = (
    Path(__file__).resolve().parents[1]
    / "src" / "willow_mcp" / "bundle" / "constitutional" / "syscall-table.json"
)


def _rows() -> dict[int, dict]:
    table = json.loads(_BUNDLE.read_text(encoding="utf-8"))
    return {int(r["id"]): r for r in table["verbs"]}


def test_row_17_is_unit_install_with_the_sealed_shape():
    row = _rows()[17]
    assert row["verb"] == "unit.install"
    assert set(row["bounds"]) == {"units", "sources"}
    assert row["enforcement"] == "soft"
    assert row["enforced_by"] is None
    assert row["min_ring"] == "ENGINEER"
    # The broker-unit clause rides in the bounds note, as row 15's does.
    assert "broker" in row["bounds"]["units"]
    # `repo@path` and tracked-at-HEAD are the source bound's whole point.
    assert "repo@path" in row["bounds"]["sources"] and "HEAD" in row["bounds"]["sources"]


def test_row_17_note_names_the_seal_for_the_live_table_sync():
    row = _rows()[17]
    assert constitutional._extract_seal_id(row["note"]) == "197aafa5"
    assert "197aafa5-1904-4ec9-a5a6-f113f07047b4" in row["note"]
    assert "row 15" in row["note"]


def test_row_ids_are_dense_and_17_is_not_the_last_anymore():
    """Row 18 (manifest.grant, tests/test_manifest_grant.py) landed after this
    row, and rows 19-22 (envelope.revoke, manifest.retire, manifest.create,
    federation.ratify — tests/test_trust_owner_verbs.py, pair 1bd6fd29) landed
    after that — dense ids still hold, 17 is just no longer the tail."""
    ids = sorted(_rows())
    assert ids == list(range(1, 23))
    assert 17 in ids


def test_bounds_signature_accepts_units_and_sources():
    verb_id = ea._validate_bounds_signature(
        "unit.install",
        {"units": ["nestor-ui.service"], "sources": ["willow-memory/willow-mcp@deploy/nestor-ui.service.template"]},
        _rows(),
    )
    assert verb_id == 17


@pytest.mark.parametrize("bounds", [
    {"units": ["nestor-ui.service"]},                                   # missing sources
    {"units": ["a.service"], "sources": ["o/r@p"], "mode": "replace"},  # extra key
    {"sources": ["o/r@p"]},                                             # missing units
])
def test_bounds_signature_refuses_a_missing_or_extra_key(bounds):
    with pytest.raises(ea.InvalidBoundsSignatureError, match="bounds signature mismatch"):
        ea._validate_bounds_signature("unit.install", bounds, _rows())


def test_live_table_sync_applies_row_17_additively(tmp_path, monkeypatch):
    """A box whose live table stops at row 16 gains row 17 on sync — the
    strict-superset path — and the FRANK-facing result names the seal."""
    bundle = json.loads(_BUNDLE.read_text(encoding="utf-8"))
    live = {**bundle, "verbs": [r for r in bundle["verbs"] if r["id"] != 17]}
    home = tmp_path / "home"
    (home / "constitutional").mkdir(parents=True)
    live_path = home / "constitutional" / "syscall-table.json"
    live_path.write_text(json.dumps(live), encoding="utf-8")
    live_path.chmod(0o600)
    (home / "constitutional").chmod(0o700)
    out = constitutional.sync_syscall_table_from_bundle(
        live_path=live_path, bundle_path=_BUNDLE, ledger=None,
    )
    assert out["ok"] and out["added"] == [17], out
    assert out["verbs"] == ["unit.install"]
    assert out["seals"] == {17: "197aafa5"}
    assert 17 in {r["id"] for r in json.loads(live_path.read_text())["verbs"]}
