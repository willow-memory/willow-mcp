"""Gap 24fed2f5c907 (apk/keyboard-act): a confirmed schema mapping extends to
a new seat on the same (database, table) when a seeded sibling seat's human
confirmation maps every canonical field to the same COLUMN the fresh
heuristic proposes — so a seat's first task_submit never refuses
``unconfirmed_schema`` for a table a human already confirmed, and nobody
edits ``schema_maps/<app>/`` by hand again.

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


def _seed_seat(home, app_id: str) -> None:
    """A sibling counts only when it is a seeded seat: mcp_apps/<app>/manifest.json."""
    d = home / "mcp_apps" / app_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "manifest.json").write_text(json.dumps({"permissions": ["store_read"]}))


def _seed_sibling(home, app_id: str, fp: str, record: dict) -> None:
    _seed_seat(home, app_id)
    sp.save_mapping(app_id, fp, "knowledge", record)


def _fresh_fields(conn) -> dict:
    cols = sp.introspect(conn, "knowledge")
    return sp.propose_mapping(cols, CANONICAL, sp.read_rings())


# ── extends ───────────────────────────────────────────────────────────────────

def test_extends_from_a_sibling_with_identical_fields(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    _seed_sibling(home, "willow", fp, _confirmed_artifact(fp, _fresh_fields(conn)))

    record = sp.resolve(conn, "loki", "knowledge", CANONICAL)

    assert record["confirmed"] is True
    assert record["confirmed_by"] == "extended"
    assert record["extended_from"] == "willow"
    assert record["source_confirmed_at"] == "2026-08-11T00:30:30+00:00"
    assert record["extended_at"]
    assert "extend_note" not in record  # identical, nothing to note
    on_disk = json.loads(sp.mapping_path("loki", fp, "knowledge").read_text())
    assert on_disk["confirmed"] is True and on_disk["extended_from"] == "willow"
    src = json.loads(sp.mapping_path("willow", fp, "knowledge").read_text())
    assert "extended_from" not in src and src["confirmed"] is True


def test_extends_when_columns_match_but_tier_and_confidence_differ(home):
    """The live 2026-08-11 shape (Loki 8A23D1AE): the human confirmed
    `source -> source_type` as alias/0.9; today's heuristic says the same
    column at a different tier/confidence. Columns agree, so extend, and note
    the metadata difference."""
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    old = _fresh_fields(conn)
    old["source"] = {**old["source"], "tier": "rooted", "confidence": 0.95}
    _seed_sibling(home, "willow", fp, _confirmed_artifact(fp, old))

    record = sp.resolve(conn, "loki", "knowledge", CANONICAL)

    assert record["confirmed"] is True and record["extended_from"] == "willow"
    assert record["extend_note"] == "columns match willow; tier/confidence differ on: ['source']"
    assert record["fields"] == _fresh_fields(conn)  # the fresh proposal, not the old metadata


def test_extends_when_an_older_sibling_lacks_a_canonical_field_that_is_unmapped_now(home):
    """hanuman's 08-11 artifact predates `db_authorization`; the fresh proposal
    carries it unmapped. Absent and unmapped are the same column fact."""
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    old = _fresh_fields(conn)
    assert old["tags"]["column"] is None  # unmapped in the fresh proposal
    del old["tags"]
    _seed_sibling(home, "hanuman", fp, _confirmed_artifact(fp, old))

    record = sp.resolve(conn, "loki", "knowledge", CANONICAL)

    assert record["confirmed"] is True and record["extended_from"] == "hanuman"
    assert record["fields"]["tags"]["column"] is None


# ── refuses ───────────────────────────────────────────────────────────────────

def test_refuses_with_field_names_when_a_column_differs(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    fields = _fresh_fields(conn)
    fields["source"] = {"column": "title", "tier": "confirmed_override",
                        "confidence": 1.0, "data_type": "text"}
    _seed_sibling(home, "willow", fp, _confirmed_artifact(fp, fields))

    record = sp.resolve(conn, "loki", "knowledge", CANONICAL)

    assert record["confirmed"] is False
    assert record["extend_refused"] == [{"app_id": "willow", "differs_on": ["source"]}]
    from willow_mcp.server import _require_confirmed
    err = _require_confirmed(record)["error"]
    assert "unconfirmed_schema" in err
    assert "differs from willow's confirmed mapping on: ['source']" in err


def test_refuses_when_an_older_sibling_lacks_a_field_that_is_mapped_now(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    old = _fresh_fields(conn)
    assert old["domain"]["column"] == "domain"
    del old["domain"]  # the human never confirmed a column for `domain`
    _seed_sibling(home, "willow", fp, _confirmed_artifact(fp, old))

    record = sp.resolve(conn, "loki", "knowledge", CANONICAL)

    assert record["confirmed"] is False
    assert record["extend_refused"] == [{"app_id": "willow", "differs_on": ["domain"]}]


def test_never_extends_from_an_unconfirmed_sibling(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    unconfirmed = _confirmed_artifact(fp, _fresh_fields(conn))
    unconfirmed["confirmed"] = False
    _seed_sibling(home, "willow", fp, unconfirmed)

    record = sp.resolve(conn, "loki", "knowledge", CANONICAL)

    assert record["confirmed"] is False
    assert "extended_from" not in record
    assert "extend_refused" not in record


def test_a_fake_dir_that_is_not_a_seeded_seat_is_not_a_sibling(home):
    """Loki 8A23D1AE: schema_maps/ is runtime-writable; a bare confirmed:true
    file under any directory name must not be evidence of a human decision."""
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    # no manifest under mcp_apps/zz-fake — write the artifact straight to disk
    sp.save_mapping("zz-fake", fp, "knowledge", _confirmed_artifact(fp, _fresh_fields(conn)))

    record = sp.resolve(conn, "loki", "knowledge", CANONICAL)

    assert record["confirmed"] is False
    assert "extended_from" not in record
    assert sp._confirmed_siblings("loki", fp, "knowledge") == []


def test_a_sibling_without_confirmed_at_is_not_a_source(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    rec = _confirmed_artifact(fp, _fresh_fields(conn))
    del rec["confirmed_at"]
    _seed_sibling(home, "willow", fp, rec)

    record = sp.resolve(conn, "loki", "knowledge", CANONICAL)

    assert record["confirmed"] is False and "extended_from" not in record


def test_an_extension_never_chains_from_an_extension(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    _seed_sibling(home, "willow", fp, _confirmed_artifact(fp, _fresh_fields(conn)))
    _seed_seat(home, "loki")
    first = sp.resolve(conn, "loki", "knowledge", CANONICAL)
    assert first["extended_from"] == "willow"
    # remove the human source; only loki's extension remains
    sp.mapping_path("willow", fp, "knowledge").unlink()

    record = sp.resolve(conn, "ada", "knowledge", CANONICAL)

    assert record["confirmed"] is False and "extended_from" not in record
    assert sp._confirmed_siblings("ada", fp, "knowledge") == []


def test_never_touches_an_existing_artifact_that_a_human_marked(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    _seed_sibling(home, "willow", fp, _confirmed_artifact(fp, _fresh_fields(conn)))
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


# ── shape ─────────────────────────────────────────────────────────────────────

def test_a_pristine_placeholder_is_replaced_by_the_extension(home):
    """The exact 2026-09-21 shape: loki's placeholder was written by a prior
    resolve() before anyone confirmed anything for it."""
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    first = sp.resolve(conn, "loki", "knowledge", CANONICAL)
    assert first["confirmed"] is False
    _seed_sibling(home, "willow", fp, _confirmed_artifact(fp, _fresh_fields(conn)))

    second = sp.resolve(conn, "loki", "knowledge", CANONICAL)

    assert second["confirmed"] is True and second["extended_from"] == "willow"


def test_source_note_travels_with_the_extension(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    _seed_sibling(home, "willow", fp, _confirmed_artifact(
        fp, _fresh_fields(conn), confirmed_note="operator 2026-08-11: content is prose here"))

    record = sp.resolve(conn, "loki", "knowledge", CANONICAL)

    assert record["confirmed"] is True
    assert record["source_note"] == "operator 2026-08-11: content is prose here"


def test_sibling_choice_is_deterministic_and_own_dir_is_skipped(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    for app in ("willow", "hanuman"):
        _seed_sibling(home, app, fp, _confirmed_artifact(fp, _fresh_fields(conn)))

    record = sp.resolve(conn, "loki", "knowledge", CANONICAL)

    assert record["extended_from"] == "hanuman"  # sorted by app_id
    sibs = [a for a, _ in sp._confirmed_siblings("loki", fp, "knowledge")]
    assert sibs == ["hanuman", "willow"]
    assert "loki" not in sibs


def test_sandbox_guard_1_still_protects_an_extended_artifact(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    _seed_sibling(home, "willow", fp, _confirmed_artifact(fp, _fresh_fields(conn)))
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
    _seed_sibling(home, "willow", fp, _confirmed_artifact(fp, fields))

    record = sp.resolve(conn, "loki", "knowledge", CANONICAL)

    assert record["confirmed"] is False and record["extend_refused"]
    assert "manifest_sha256" in record
    assert sc._is_pristine_placeholder(record) is True
