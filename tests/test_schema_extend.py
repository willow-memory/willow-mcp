"""Gap 24fed2f5c907 (apk/keyboard-act): a confirmed schema mapping extends to
a new seat on the same (database, table) when the fresh heuristic proposes
byte-identical fields — so a seat's first task_submit never refuses
``unconfirmed_schema`` for a table a human already confirmed for a sibling,
and nobody edits ``schema_maps/<app>/`` by hand again.

Uses the conftest ``home`` fixture (isolated $WILLOW_HOME) and the fake
connection shape from test_schema_profile.
"""
from __future__ import annotations

import json

from willow_mcp import sandbox_confirm as sc
from willow_mcp import schema_profile as sp

from tests.test_schema_profile import CANONICAL, KNOWLEDGE_LIKE_COLUMNS, _FakeConn


def _confirmed_artifact(fp: str, fields: dict, **extra) -> dict:
    rec = {
        "schema_version": sp.SCHEMA_VERSION,
        "database": fp,
        "table": "knowledge",
        "discovered_at": "2026-08-11T00:27:02+00:00",
        "confirmed": True,
        "confirmed_at": "2026-08-11T00:30:30+00:00",
        "fields": fields,
    }
    rec.update(extra)
    return rec


def _fresh_fields(conn) -> dict:
    cols = sp.introspect(conn, "knowledge")
    return sp.propose_mapping(cols, CANONICAL, sp.read_rings())


def test_extends_from_a_sibling_with_identical_fields(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    sp.save_mapping("willow", fp, "knowledge", _confirmed_artifact(fp, _fresh_fields(conn)))

    record = sp.resolve(conn, "loki", "knowledge", CANONICAL)

    assert record["confirmed"] is True
    assert record["confirmed_by"] == "extended"
    assert record["extended_from"] == "willow"
    assert record["source_confirmed_at"] == "2026-08-11T00:30:30+00:00"
    assert record["extended_at"]
    on_disk = json.loads(sp.mapping_path("loki", fp, "knowledge").read_text())
    assert on_disk["confirmed"] is True and on_disk["extended_from"] == "willow"
    # the sibling's own artifact is untouched
    src = json.loads(sp.mapping_path("willow", fp, "knowledge").read_text())
    assert "extended_from" not in src and src["confirmed"] is True


def test_refuses_with_field_names_when_a_sibling_differs(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    fields = _fresh_fields(conn)
    # the human mapped `source` to a different column than the heuristic sees
    fields["source"] = {"column": "title", "tier": "confirmed_override",
                        "confidence": 1.0, "data_type": "text"}
    sp.save_mapping("willow", fp, "knowledge", _confirmed_artifact(fp, fields))

    record = sp.resolve(conn, "loki", "knowledge", CANONICAL)

    assert record["confirmed"] is False
    assert record["extend_refused"] == [{"app_id": "willow", "differs_on": ["source"]}]
    # and the write gate names the disagreement
    from willow_mcp.server import _require_confirmed
    err = _require_confirmed(record)["error"]
    assert "unconfirmed_schema" in err
    assert "differs from willow's confirmed mapping on: ['source']" in err


def test_never_extends_from_an_unconfirmed_sibling(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    unconfirmed = _confirmed_artifact(fp, _fresh_fields(conn))
    unconfirmed["confirmed"] = False
    sp.save_mapping("willow", fp, "knowledge", unconfirmed)

    record = sp.resolve(conn, "loki", "knowledge", CANONICAL)

    assert record["confirmed"] is False
    assert "extended_from" not in record
    assert "extend_refused" not in record  # an unconfirmed sibling is not a refusal, it is nothing


def test_never_touches_an_existing_artifact_that_a_human_marked(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    sp.save_mapping("willow", fp, "knowledge", _confirmed_artifact(fp, _fresh_fields(conn)))
    # loki already has an unconfirmed draft a person annotated
    draft = {
        "schema_version": sp.SCHEMA_VERSION, "database": fp, "table": "knowledge",
        "discovered_at": "2026-09-21T01:34:22+00:00", "confirmed": False,
        "fields": _fresh_fields(conn), "operator_note": "checking source column first",
    }
    sp.save_mapping("loki", fp, "knowledge", draft)

    record = sp.resolve(conn, "loki", "knowledge", CANONICAL)

    assert record["confirmed"] is False
    assert "extended_from" not in record
    on_disk = json.loads(sp.mapping_path("loki", fp, "knowledge").read_text())
    assert on_disk["operator_note"] == "checking source column first"


def test_a_pristine_placeholder_is_replaced_by_the_extension(home):
    """The exact 2026-09-21 shape: loki's placeholder was written by a prior
    resolve() before anyone confirmed anything for it."""
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    first = sp.resolve(conn, "loki", "knowledge", CANONICAL)
    assert first["confirmed"] is False
    sp.save_mapping("willow", fp, "knowledge", _confirmed_artifact(fp, _fresh_fields(conn)))

    second = sp.resolve(conn, "loki", "knowledge", CANONICAL)

    assert second["confirmed"] is True and second["extended_from"] == "willow"


def test_source_note_travels_with_the_extension(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    sp.save_mapping("willow", fp, "knowledge", _confirmed_artifact(
        fp, _fresh_fields(conn), confirmed_note="operator 2026-08-11: content is prose here"))

    record = sp.resolve(conn, "loki", "knowledge", CANONICAL)

    assert record["confirmed"] is True
    assert record["source_note"] == "operator 2026-08-11: content is prose here"


def test_sibling_choice_is_deterministic_and_own_dir_is_skipped(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    for app in ("willow", "hanuman"):
        sp.save_mapping(app, fp, "knowledge", _confirmed_artifact(fp, _fresh_fields(conn)))

    record = sp.resolve(conn, "loki", "knowledge", CANONICAL)

    assert record["extended_from"] == "hanuman"  # sorted by app_id
    sibs = [a for a, _ in sp._confirmed_siblings("loki", fp, "knowledge")]
    assert sibs == ["hanuman", "willow"]
    assert "loki" not in sibs


def test_sandbox_guard_1_still_protects_an_extended_artifact(home):
    """An extended artifact is confirmed — guard 1 must leave it alone."""
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    sp.save_mapping("willow", fp, "knowledge", _confirmed_artifact(fp, _fresh_fields(conn)))
    record = sp.resolve(conn, "loki", "knowledge", CANONICAL)
    assert record["confirmed"] is True
    assert sc._is_pristine_placeholder(record) is False


def test_sandbox_guard_1_reads_a_resolve_placeholder_as_pristine(home):
    """resolve() has stamped manifest_sha256 on placeholders; guard 1 must
    still recognise that as machine-written, and extend_refused likewise."""
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    fields = _fresh_fields(conn)
    fields["source"] = {"column": "title", "tier": "confirmed_override",
                        "confidence": 1.0, "data_type": "text"}
    sp.save_mapping("willow", fp, "knowledge", _confirmed_artifact(fp, fields))

    record = sp.resolve(conn, "loki", "knowledge", CANONICAL)

    assert record["confirmed"] is False and record["extend_refused"]
    assert "manifest_sha256" in record
    assert sc._is_pristine_placeholder(record) is True
