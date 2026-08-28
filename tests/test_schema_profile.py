"""Tests for schema_profile.py — introspection, heuristic mapping, and the
persisted mapping artifact (docs/design/schema-adaptation.md §3.1-§3.4).
"""
import json

import pytest
from willow_mcp import schema_profile as sp


# ── fakes: just enough of the psycopg2 connection/cursor surface ──────────

class _FakeCursor:
    def __init__(self, rows):
        self._rows = rows

    def execute(self, sql, params=None):
        pass

    def fetchall(self):
        return self._rows

    def close(self):
        pass


class _FakeConn:
    def __init__(self, columns: dict[str, str], host="localhost", dbname="testdb"):
        """columns: {column_name: data_type}, insertion order preserved."""
        self._columns = columns
        self._host = host
        self._dbname = dbname

    def cursor(self):
        rows = list(self._columns.items())
        return _FakeCursor(rows)

    def get_dsn_parameters(self):
        return {"host": self._host, "dbname": self._dbname}


KNOWLEDGE_LIKE_COLUMNS = {
    "id": "text",
    "title": "text",
    "summary": "text",
    "content": "jsonb",
    "source_type": "text",
    "domain": "text",
    "created_at": "timestamp with time zone",
}

CANONICAL = ["id", "content", "domain", "source", "tags"]


# ── introspect ──────────────────────────────────────────────────────────

def test_introspect_returns_columns():
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    cols = sp.introspect(conn, "knowledge")
    assert [c.name for c in cols] == list(KNOWLEDGE_LIKE_COLUMNS)
    assert cols[3].data_type == "jsonb"


def test_introspect_empty_table_returns_empty_list():
    conn = _FakeConn({})
    assert sp.introspect(conn, "nonexistent") == []


# ── propose_mapping ─────────────────────────────────────────────────────

def test_propose_mapping_exact_match():
    cols = sp.introspect(_FakeConn(KNOWLEDGE_LIKE_COLUMNS), "knowledge")
    mapping = sp.propose_mapping(cols, CANONICAL)
    assert mapping["id"] == {"column": "id", "tier": "exact", "confidence": 1.0, "data_type": "text"}
    assert mapping["domain"]["tier"] == "exact"


def test_propose_mapping_alias_match():
    cols = sp.introspect(_FakeConn(KNOWLEDGE_LIKE_COLUMNS), "knowledge")
    mapping = sp.propose_mapping(cols, CANONICAL)
    assert mapping["source"]["column"] == "source_type"
    assert mapping["source"]["tier"] == "alias"
    assert mapping["source"]["confidence"] == 0.9


def test_propose_mapping_unmapped_when_no_column_or_alias():
    cols = sp.introspect(_FakeConn(KNOWLEDGE_LIKE_COLUMNS), "knowledge")
    mapping = sp.propose_mapping(cols, CANONICAL)
    assert mapping["tags"] == {"column": None, "tier": "unmapped", "confidence": 0.0, "data_type": None}


def test_propose_mapping_ignores_extra_columns():
    cols = sp.introspect(_FakeConn(KNOWLEDGE_LIKE_COLUMNS), "knowledge")
    mapping = sp.propose_mapping(cols, ["id", "domain"])
    assert set(mapping) == {"id", "domain"}


def test_propose_mapping_is_pure_and_deterministic():
    cols = sp.introspect(_FakeConn(KNOWLEDGE_LIKE_COLUMNS), "knowledge")
    a = sp.propose_mapping(cols, CANONICAL)
    b = sp.propose_mapping(cols, CANONICAL)
    assert a == b


# ── legacy-alias mapping (2000s job-scheduler house style) ───────────────

TASK_CANON = ["task_id", "task", "submitted_by", "agent", "status", "result",
              "steps", "created_at", "completed_at"]

# A 2002 batch table: terse legacy names, a `task` column that holds a job
# CLASS (not a command), and both a surrogate `id` and a real key `jobno`.
LEGACY_TASKS_COLUMNS = {
    "id": "integer", "jobno": "character varying", "task": "character varying",
    "cmd_line": "text", "submitter": "character varying", "agent": "character varying",
    "stat": "character", "result": "text", "nsteps": "integer",
    "created_at": "timestamp without time zone", "fin_dt": "timestamp without time zone",
}


def test_legacy_aliases_map_terse_columns():
    cols = sp.introspect(_FakeConn(LEGACY_TASKS_COLUMNS), "tasks")
    m = sp.propose_mapping(cols, TASK_CANON)
    assert m["submitted_by"]["column"] == "submitter" and m["submitted_by"]["tier"] == "alias"
    assert m["status"]["column"] == "stat"
    assert m["steps"]["column"] == "nsteps"
    assert m["completed_at"]["column"] == "fin_dt"


def test_business_key_alias_outranks_bare_id():
    # jobno is listed before id in the task_id alias tuple, so it must win when
    # both are present — the real key beats the surrogate.
    cols = sp.introspect(_FakeConn(LEGACY_TASKS_COLUMNS), "tasks")
    m = sp.propose_mapping(cols, TASK_CANON)
    assert m["task_id"]["column"] == "jobno"


def test_bare_id_still_maps_task_id_when_no_business_key():
    # test_server's fake tasks table has only `id` — id remains a valid fallback.
    cols = sp.introspect(_FakeConn({"id": "text", "task": "text", "agent": "text"}), "tasks")
    m = sp.propose_mapping(cols, TASK_CANON)
    assert m["task_id"]["column"] == "id" and m["task_id"]["tier"] == "alias"


def test_exact_name_still_beats_alias_even_when_it_is_a_trap():
    # An exact `task` column wins over the `cmd_line` alias — which is exactly
    # why the name tiers can't catch this trap and the data-shape pass must.
    cols = sp.introspect(_FakeConn(LEGACY_TASKS_COLUMNS), "tasks")
    m = sp.propose_mapping(cols, TASK_CANON)
    assert m["task"]["column"] == "task" and m["task"]["tier"] == "exact"


# ── data-shape classifier ────────────────────────────────────────────────

def test_classify_shape_command():
    assert sp.classify_shape(["/usr/local/bin/eod.pl --batch", "perl gen.pl -m 200202"]) == "command"


def test_classify_shape_enum_and_flag():
    assert sp.classify_shape(["NIGHTLY", "ADHOC", "NIGHTLY"]) == "enum"
    assert sp.classify_shape(["P", "R", "C", "F"]) == "flag"


def test_classify_shape_identifier_integer_timestamp():
    assert sp.classify_shape(["JOB0041", "JOB0042"]) == "identifier"
    assert sp.classify_shape([1, 2, 3]) == "integer"
    assert sp.classify_shape(["2002-03-14 02:15:00"], data_type="timestamp without time zone") == "timestamp"


def test_classify_shape_empty_and_freetext():
    assert sp.classify_shape([None, None]) == "empty"
    assert sp.classify_shape(["settlement OK: 4,182 txns posted to the ledger today"]) == "freetext"


# ── data-shape refinement (the trap-catcher) ─────────────────────────────

class _FakeSQLConn:
    """Serves both the information_schema introspection and a `SELECT ... LIMIT`
    sample, dispatching on the SQL so refine_with_data sees real rows."""
    def __init__(self, columns: dict, rows: list, host="localhost", dbname="legacy2002"):
        self._columns = columns
        self._rows = rows
        self._host, self._dbname = host, dbname

    def cursor(self):
        return _FakeSQLConn._Cur(self)

    def get_dsn_parameters(self):
        return {"host": self._host, "dbname": self._dbname}

    class _Cur:
        def __init__(self, conn):
            self.conn, self._out = conn, []

        def execute(self, sql, params=None):
            if "information_schema.columns" in sql:
                self._out = list(self.conn._columns.items())
            else:
                self._out = list(self.conn._rows)

        def fetchall(self):
            return self._out

        def close(self):
            pass


# rows aligned to LEGACY_TASKS_COLUMNS insertion order
_LEGACY_ROWS = [
    (1, "JOB0041", "NIGHTLY", "/usr/local/bin/eod_settlement.pl --batch", "jsmith", "crond", "C", "settlement OK: 4182 txns posted", 7, "2002-03-14 02:15:00", "2002-03-14 02:47:33"),
    (2, "JOB0042", "NIGHTLY", "perl /opt/reports/gen_stmts.pl -m 200202", "jsmith", "crond", "C", "18904 statements spooled to LPT3", 3, "2002-03-14 03:00:00", "2002-03-14 03:52:10"),
    (3, "JOB0043", "ADHOC", "sh /home/mfg/reindex_parts.sh", "awong", "operator", "F", "ORA-01652 unable to extend temp segment", 2, "2002-03-15 11:22:41", "2002-03-15 11:23:05"),
]


def test_refine_flags_the_task_class_trap_and_suggests_the_command_column():
    conn = _FakeSQLConn(LEGACY_TASKS_COLUMNS, _LEGACY_ROWS)
    cols = sp.introspect(conn, "tasks")
    fields = sp.propose_mapping(cols, TASK_CANON)  # task -> task (the trap)
    refined = sp.refine_with_data(conn, "tasks", fields, TASK_CANON, columns=cols)

    task_sugg = [s for s in refined["suggestions"] if s["field"] == "task"]
    assert len(task_sugg) == 1
    assert task_sugg[0]["suggested_column"] == "cmd_line"
    assert task_sugg[0]["severity"] == "trap"
    assert refined["shapes"]["task"] == "enum"
    assert refined["shapes"]["cmd_line"] == "command"


def test_refine_does_not_poach_well_placed_columns():
    # Fields whose name-mapped column already fits its expected shape must not
    # generate spurious suggestions.
    conn = _FakeSQLConn(LEGACY_TASKS_COLUMNS, _LEGACY_ROWS)
    cols = sp.introspect(conn, "tasks")
    fields = sp.propose_mapping(cols, TASK_CANON)
    refined = sp.refine_with_data(conn, "tasks", fields, TASK_CANON, columns=cols)
    noisy = {s["field"] for s in refined["suggestions"]}
    assert "created_at" not in noisy and "result" not in noisy and "steps" not in noisy


def test_refine_degrades_to_empty_on_no_data():
    conn = _FakeSQLConn(LEGACY_TASKS_COLUMNS, [])  # no rows
    cols = sp.introspect(conn, "tasks")
    fields = sp.propose_mapping(cols, TASK_CANON)
    refined = sp.refine_with_data(conn, "tasks", fields, TASK_CANON, columns=cols)
    assert refined["suggestions"] == []


# ── guarded hints (2004-archive regression) ──────────────────────────────

KNOW_CANON = ["id", "content", "domain", "source", "tags"]

# A freetext-heavy archive table: many columns share the `freetext` shape, so an
# unguarded "first well-shaped column" hint fires confidently-wrong. `content`
# holds a citation (still freetext), the body is in `abstract`, and `lang` is a
# 2-letter noise column.
ARCHIVE_COLUMNS = {
    "rec_no": "integer", "accession": "character varying", "content": "text",
    "abstract": "text", "subj": "character varying", "provenance": "character varying",
    "kw": "text", "lang": "character", "added_on": "date",
}
_ARCHIVE_ROWS = [
    (1, "ACC-2004-0912", "Cormen, T. et al. (2001). Intro to Algorithms. OCLC#47297975.",
     "A comprehensive treatment of modern algorithms with rigorous proofs of correctness and running time.",
     "Computer Science", "Interlibrary Loan / MIT", "algorithms;complexity", "en", "2004-02-11"),
    (2, "ACC-2004-1033", "Knuth, D. (1997). TAOCP Vol.1. LoC QA76.6.K64.",
     "The foundational volume on fundamental algorithms and the analysis of basic programming techniques.",
     "Computer Science", "Donated by A. Turing Estate", "analysis;combinatorics", "en", "2004-03-04"),
]


def test_guarded_hints_stay_silent_on_freetext_heavy_table():
    # The 2004 regression: unguarded hints suggested lang/accession for
    # domain/source/tags. With the discriminating-shape + name-affinity guards,
    # a shape-poor table must produce NO hints rather than confident-wrong ones.
    conn = _FakeSQLConn(ARCHIVE_COLUMNS, _ARCHIVE_ROWS)
    cols = sp.introspect(conn, "knowledge")
    fields = sp.propose_mapping(cols, KNOW_CANON)
    refined = sp.refine_with_data(conn, "knowledge", fields, KNOW_CANON, columns=cols)
    hints = [s for s in refined["suggestions"] if s["severity"] == "hint"]
    assert hints == []


def test_trap_flag_survives_guards_and_keeps_its_replacement():
    # The tasks trap must still fire WITH a replacement: cmd_line is the only
    # command-shaped column (discriminating), and the trap path does not require
    # name affinity.
    conn = _FakeSQLConn(LEGACY_TASKS_COLUMNS, _LEGACY_ROWS)
    cols = sp.introspect(conn, "tasks")
    fields = sp.propose_mapping(cols, TASK_CANON)
    refined = sp.refine_with_data(conn, "tasks", fields, TASK_CANON, columns=cols)
    trap = [s for s in refined["suggestions"] if s["field"] == "task"]
    assert trap and trap[0]["severity"] == "trap" and trap[0]["suggested_column"] == "cmd_line"


# ── deployment-wide learned mappings ─────────────────────────────────────

@pytest.fixture
def rings_store(tmp_path, monkeypatch):
    p = tmp_path / "schema_rings.json"
    monkeypatch.setenv("WILLOW_MCP_SCHEMA_RINGS", str(p))
    return p


def test_propose_without_rings_is_unchanged(rings_store):
    # Purity/back-compat: omitting lessons must reproduce the name+alias result.
    cols = sp.introspect(_FakeConn(LEGACY_TASKS_COLUMNS), "tasks")
    assert sp.propose_mapping(cols, TASK_CANON) == sp.propose_mapping(cols, TASK_CANON, None)


def test_grow_ring_skips_trivial_matches(rings_store):
    fields = {
        "task_id": {"column": "jobno"},      # non-trivial -> learned
        "task": {"column": "task"},          # trivial (col == field) -> skipped
        "status": {"column": "stat"},        # non-trivial -> learned
    }
    sp.grow_ring(fields)
    lessons = sp.read_rings()
    assert lessons["jobno"] == {"task_id": 1}
    assert lessons["stat"] == {"status": 1}
    assert "task" not in lessons  # the trap self-match teaches nothing


def test_rooted_tier_maps_terse_columns_and_counts(rings_store):
    sp.grow_ring({"submitter": {"column": "submitter"}})  # trivial, ignored
    sp.grow_ring({"submitted_by": {"column": "requestor"}})
    sp.grow_ring({"submitted_by": {"column": "requestor"}})  # count -> 2
    cols = sp.introspect(_FakeConn({"requestor": "text", "task": "text"}), "tasks")
    m = sp.propose_mapping(cols, TASK_CANON, sp.read_rings())
    assert m["submitted_by"]["column"] == "requestor"
    assert m["submitted_by"]["tier"] == "rooted"
    assert m["submitted_by"]["confidence"] == 0.95


def test_rings_apply_across_tables_deployment_wide(rings_store):
    # Lessons are keyed by column name, not by table/db — a lesson learned on
    # one table maps a same-named column on a different one.
    sp.grow_ring({"domain": {"column": "subj"}})
    cols = sp.introspect(_FakeConn({"subj": "character varying", "content": "text"}), "other_table")
    m = sp.propose_mapping(cols, KNOW_CANON, sp.read_rings())
    assert m["domain"]["column"] == "subj" and m["domain"]["tier"] == "rooted"


def test_exact_name_still_outranks_rooted(rings_store):
    # A learned lesson must not override an exact-named column — the content
    # trap residual is honest: only data can beat an exact-name collision.
    sp.grow_ring({"content": {"column": "abstract"}})
    cols = sp.introspect(_FakeConn({"content": "text", "abstract": "text"}), "knowledge")
    m = sp.propose_mapping(cols, KNOW_CANON, sp.read_rings())
    assert m["content"]["column"] == "content" and m["content"]["tier"] == "exact"


def test_confirm_grows_a_ring(home, rings_store):
    conn = _FakeConn(LEGACY_TASKS_COLUMNS)
    sp.confirm(conn, "app", "tasks", TASK_CANON,
               overrides={"task": "cmd_line", "submitted_by": "submitter"})
    lessons = sp.read_rings()
    assert lessons["cmd_line"]["task"] == 1
    assert lessons["submitter"]["submitted_by"] == 1


# ── bound & prune ─────────────────────────────────────────────────────────

def test_canopy_is_bounded_by_cap(rings_store, monkeypatch):
    monkeypatch.setenv("WILLOW_MCP_SCHEMA_RINGS_MAX", "10")
    for i in range(50):  # 50 distinct one-off column names -> would be 50 pairs
        sp.grow_ring({"task_id": {"column": f"legacy_id_{i}"}})
    stats = sp.girth()
    assert stats["pairs"] <= 10  # never exceeds the cap
    assert stats["cap"] == 10


def test_prune_cuts_thinnest_rings_first(rings_store, monkeypatch):
    monkeypatch.setenv("WILLOW_MCP_SCHEMA_RINGS_MAX", "5")
    # A frequently-confirmed common name...
    for _ in range(20):
        sp.grow_ring({"submitted_by": {"column": "submitter"}})
    # ...then a flood of one-off names to force eviction.
    for i in range(40):
        sp.grow_ring({"submitted_by": {"column": f"oneoff_{i}"}})
    lessons = sp.read_rings()
    assert "submitter" in lessons  # high-count survivor is never evicted
    assert lessons["submitter"]["submitted_by"] == 20
    assert sp.girth()["pairs"] <= 5


def test_prune_keeps_recent_among_equal_rings(rings_store, monkeypatch):
    monkeypatch.setenv("WILLOW_MCP_SCHEMA_RINGS_MAX", "3")
    order = ["a", "b", "c", "d", "e", "f"]  # each count-1, ascending recency
    for name in order:
        sp.grow_ring({"status": {"column": name}})
    survivors = set(sp.read_rings().keys())
    # oldest count-1 names evicted first; the most-recent survive
    assert "f" in survivors and "a" not in survivors


# ── citation-vs-prose (the exact-name content trap) ──────────────────────

_CITATIONS = [
    "Cormen, T. et al. (2001). Introduction to Algorithms, 2nd ed. MIT Press. OCLC#47297975.",
    "Shannon, C. (1948). A Mathematical Theory of Communication. Bell Sys. Tech. J. 27:379-423.",
]
_PROSE = [
    "A comprehensive treatment of modern algorithms including divide and conquer, dynamic "
    "programming, and graph methods, with rigorous proofs of correctness and running-time bounds.",
    "Establishes the mathematical foundations of information theory, introducing entropy as a "
    "measure of information and the noisy-channel coding theorem that underpins digital communication.",
]


def test_classify_shape_reference_vs_prose():
    assert sp.classify_shape(_CITATIONS) == "reference"
    assert sp.classify_shape(_PROSE) == "prose"


def test_short_or_ambiguous_freetext_stays_freetext():
    # The guard: don't mislabel ordinary short freetext as prose/reference.
    assert sp.classify_shape(["settlement OK: 4,182 txns posted to the ledger today"]) == "freetext"
    assert sp.classify_shape(["Interlibrary Loan / MIT Libraries", "Bell Labs microfiche"]) == "freetext"


# A knowledge table where the exact-named `content` column holds CITATIONS and
# the real body is in `abstract` — the design doc's marquee trap.
_KNOW_TRAP_COLUMNS = {
    "rec_no": "integer", "accession": "character varying",
    "content": "text", "abstract": "text", "subj": "character varying",
}
_KNOW_TRAP_ROWS = [
    (1, "ACC-1", _CITATIONS[0], _PROSE[0], "Computer Science"),
    (2, "ACC-2", _CITATIONS[1], _PROSE[1], "Information Theory"),
]


def test_content_citation_trap_is_finally_caught():
    conn = _FakeSQLConn(_KNOW_TRAP_COLUMNS, _KNOW_TRAP_ROWS)
    cols = sp.introspect(conn, "knowledge")
    fields = sp.propose_mapping(cols, KNOW_CANON)  # content -> content (exact, the trap)
    refined = sp.refine_with_data(conn, "knowledge", fields, KNOW_CANON, columns=cols)
    assert refined["shapes"]["content"] == "reference"
    assert refined["shapes"]["abstract"] == "prose"
    trap = [s for s in refined["suggestions"] if s["field"] == "content"]
    assert trap and trap[0]["severity"] == "trap"
    assert trap[0]["suggested_column"] == "abstract"


def test_correct_content_column_does_not_false_trap():
    # If `content` actually holds the prose body, no trap should fire.
    cols_ok = {"rec_no": "integer", "content": "text", "subj": "character varying"}
    rows_ok = [(1, _PROSE[0], "Computer Science"), (2, _PROSE[1], "Information Theory")]
    conn = _FakeSQLConn(cols_ok, rows_ok)
    cols = sp.introspect(conn, "knowledge")
    fields = sp.propose_mapping(cols, KNOW_CANON)
    refined = sp.refine_with_data(conn, "knowledge", fields, KNOW_CANON, columns=cols)
    assert [s for s in refined["suggestions"] if s["field"] == "content"] == []


def test_legacy_v1_store_is_read_and_upgraded(rings_store):
    # An old int-valued store must load and keep working, then upgrade on write.
    import json
    rings_store.write_text(json.dumps({
        "format": "schema_lessons_v1",
        "columns": {"submitter": {"submitted_by": 3}},
    }))
    assert sp.read_rings()["submitter"]["submitted_by"] == 3  # int contract intact
    sp.grow_ring({"status": {"column": "stat"}})           # triggers upgrade
    data = json.loads(rings_store.read_text())
    assert data["format"] == "growth_rings_v1"
    assert data["columns"]["submitter"]["submitted_by"]["n"] == 3  # count preserved
    assert sp.read_rings()["stat"]["status"] == 1


# ── db_fingerprint ──────────────────────────────────────────────────────

def test_db_fingerprint_stable_for_same_host_dbname():
    a = sp.db_fingerprint(_FakeConn(KNOWLEDGE_LIKE_COLUMNS, host="h1", dbname="willow"))
    b = sp.db_fingerprint(_FakeConn({}, host="h1", dbname="willow"))
    assert a == b


def test_db_fingerprint_differs_for_different_dbname():
    a = sp.db_fingerprint(_FakeConn(KNOWLEDGE_LIKE_COLUMNS, host="h1", dbname="willow"))
    b = sp.db_fingerprint(_FakeConn(KNOWLEDGE_LIKE_COLUMNS, host="h1", dbname="other"))
    assert a != b


def test_db_fingerprint_never_leaks_dsn_secrets():
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS, host="h1", dbname="willow")
    fp = sp.db_fingerprint(conn)
    # A fingerprint is a hex digest — by construction it can't contain the
    # raw host/dbname string, but assert the shape anyway as a regression
    # guard against someone later returning the raw key instead of hashing it.
    assert len(fp) == 16
    int(fp, 16)  # raises if it's not hex


# ── mapping artifact persistence ────────────────────────────────────────

def test_resolve_writes_new_unconfirmed_artifact(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    record = sp.resolve(conn, "testapp", "knowledge", CANONICAL)
    assert record["confirmed"] is False
    assert record["schema_version"] == sp.SCHEMA_VERSION
    assert record["fields"]["source"]["column"] == "source_type"

    fp = sp.db_fingerprint(conn)
    path = sp.mapping_path("testapp", fp, "knowledge")
    assert path.exists()
    on_disk = json.loads(path.read_text())
    assert on_disk == record


def test_resolve_table_not_found(home):
    conn = _FakeConn({})
    record = sp.resolve(conn, "testapp", "ghost_table", CANONICAL)
    assert record == {"error": "table_not_found", "table": "ghost_table"}


def test_resolve_confirmed_mapping_wins_over_fresh_heuristic(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    hand_edited = {
        "schema_version": 1,
        "database": fp,
        "table": "knowledge",
        "discovered_at": "2026-01-01T00:00:00Z",
        "confirmed": True,
        "fields": {
            "id": {"column": "id", "tier": "exact", "confidence": 1.0, "data_type": "text"},
            "content": {"column": "content", "tier": "exact", "confidence": 1.0, "data_type": "jsonb"},
            "domain": {"column": "domain", "tier": "exact", "confidence": 1.0, "data_type": "text"},
            "source": {"column": "source_type", "tier": "alias", "confidence": 0.9, "data_type": "text"},
            "tags": {"column": None, "tier": "unmapped", "confidence": 0.0, "data_type": None},
        },
    }
    sp.save_mapping("testapp", fp, "knowledge", hand_edited)

    record = sp.resolve(conn, "testapp", "knowledge", CANONICAL)
    assert record["confirmed"] is True
    assert record["fields"] == hand_edited["fields"]


def test_resolve_downgrades_confirmed_on_schema_drift(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    fp = sp.db_fingerprint(conn)
    confirmed_but_now_wrong = {
        "schema_version": 1,
        "database": fp,
        "table": "knowledge",
        "discovered_at": "2026-01-01T00:00:00Z",
        "confirmed": True,
        "fields": {
            "id": {"column": "id", "tier": "exact", "confidence": 1.0, "data_type": "text"},
            # 'renamed_col' does not exist in KNOWLEDGE_LIKE_COLUMNS — simulates
            # the host having dropped/renamed a column after confirmation.
            "content": {"column": "renamed_col", "tier": "exact", "confidence": 1.0, "data_type": "text"},
        },
    }
    sp.save_mapping("testapp", fp, "knowledge", confirmed_but_now_wrong)

    record = sp.resolve(conn, "testapp", "knowledge", ["id", "content"])
    assert record["confirmed"] is False
    assert record["schema_drift"] is True
    # re-proposed fresh from the real, current columns
    assert record["fields"]["content"]["column"] == "content"


def test_resolve_unconfirmed_recomputes_without_error(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    first = sp.resolve(conn, "testapp", "knowledge", CANONICAL)
    second = sp.resolve(conn, "testapp", "knowledge", CANONICAL)
    assert first["fields"] == second["fields"]
    assert second["confirmed"] is False


# ── confirm ─────────────────────────────────────────────────────────────

def test_confirm_from_scratch_marks_confirmed_and_persists(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    record = sp.confirm(conn, "testapp", "knowledge", CANONICAL)
    assert record["confirmed"] is True
    assert "confirmed_at" in record
    assert record["fields"]["source"]["column"] == "source_type"

    fp = sp.db_fingerprint(conn)
    on_disk = sp.load_mapping("testapp", fp, "knowledge")
    assert on_disk == record


def test_confirm_table_not_found(home):
    conn = _FakeConn({})
    record = sp.confirm(conn, "testapp", "ghost_table", CANONICAL)
    assert record == {"error": "table_not_found", "table": "ghost_table"}


def test_confirm_preserves_prior_unconfirmed_heuristic_as_base(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    heuristic = sp.resolve(conn, "testapp", "knowledge", CANONICAL)
    assert heuristic["confirmed"] is False

    confirmed = sp.confirm(conn, "testapp", "knowledge", CANONICAL)
    assert confirmed["confirmed"] is True
    assert confirmed["fields"] == heuristic["fields"]
    assert confirmed["discovered_at"] == heuristic["discovered_at"]


def test_confirm_applies_valid_override(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    record = sp.confirm(conn, "testapp2", "knowledge", CANONICAL, overrides={"source": "source_type"})
    assert record["fields"]["source"] == {
        "column": "source_type", "tier": "confirmed_override",
        "confidence": 1.0, "data_type": "text",
    }


def test_confirm_override_to_none_marks_unmapped(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    record = sp.confirm(conn, "testapp3", "knowledge", CANONICAL, overrides={"domain": None})
    assert record["fields"]["domain"] == {"column": None, "tier": "unmapped", "confidence": 0.0, "data_type": None}


def test_confirm_rejects_override_to_nonexistent_column(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    record = sp.confirm(conn, "testapp4", "knowledge", CANONICAL, overrides={"tags": "no_such_column"})
    assert record == {
        "error": "override_invalid", "field": "tags", "column": "no_such_column", "table": "knowledge",
    }


def test_confirm_rejects_override_for_unknown_field(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    record = sp.confirm(conn, "testapp5", "knowledge", CANONICAL, overrides={"not_a_field": "id"})
    assert record == {"error": "unknown_field", "field": "not_a_field", "table": "knowledge"}


def test_confirm_is_idempotent_and_reconfirmable(home):
    conn = _FakeConn(KNOWLEDGE_LIKE_COLUMNS)
    first = sp.confirm(conn, "testapp6", "knowledge", CANONICAL)
    second = sp.confirm(conn, "testapp6", "knowledge", CANONICAL, overrides={"tags": None})
    assert first["confirmed"] is True
    assert second["confirmed"] is True
    assert second["fields"]["tags"]["tier"] == "unmapped"
    # non-overridden fields carried forward unchanged
    assert second["fields"]["id"] == first["fields"]["id"]


# ── cast_for_ilike ──────────────────────────────────────────────────────

def test_cast_for_ilike_casts_jsonb():
    field = {"column": "content", "data_type": "jsonb"}
    assert sp.cast_for_ilike(field) == '"content"::text'


def test_cast_for_ilike_no_cast_for_text():
    field = {"column": "summary", "data_type": "text"}
    assert sp.cast_for_ilike(field) == '"summary"'


# ── mapping_path / table name safety ────────────────────────────────────

def test_mapping_path_rejects_unsafe_table_name(home):
    with pytest.raises(ValueError):
        sp.mapping_path("testapp", "fingerprint123", "../../etc/passwd")


# ── render_sample / preview: evidence, not assertion ────────────────────

class _DataCursor:
    """Distinguishes introspection (information_schema) queries — which return
    the column list — from data SELECTs, which return canned rows."""

    def __init__(self, columns, data_rows):
        self._columns = columns
        self._data_rows = data_rows
        self._introspecting = False

    def execute(self, sql, params=None):
        self._introspecting = "information_schema" in sql

    def fetchall(self):
        return list(self._columns.items()) if self._introspecting else self._data_rows

    def close(self):
        pass


class _DataConn:
    def __init__(self, columns, data_rows, host="localhost", dbname="testdb"):
        self._columns = columns
        self._data_rows = data_rows
        self._host = host
        self._dbname = dbname

    def cursor(self):
        return _DataCursor(self._columns, self._data_rows)

    def get_dsn_parameters(self):
        return {"host": self._host, "dbname": self._dbname}


# The false-friend row: `content` is a provenance blob, the real knowledge is
# in title/summary — the exact schema that fooled a name-match confirm.
_BLOB_ROW = ("A1", {"tags": ["identity"], "source_id": "mcp:willow:..."}, "willow", "mcp")


def test_render_sample_projects_real_values_through_mapping():
    conn = _DataConn(KNOWLEDGE_LIKE_COLUMNS, [_BLOB_ROW])
    fields = sp.propose_mapping(sp.introspect(conn, "knowledge"), CANONICAL)
    sample = sp.render_sample(conn, "knowledge", fields)
    # content resolves to the provenance blob — the evidence a name match hides
    assert "source_id" in sample[0]["content"]
    # tags is unmapped, so it is not selected at all
    assert "tags" not in sample[0]
    assert sample[0]["id"] == "A1"


def test_render_sample_empty_when_nothing_mapped():
    conn = _DataConn(KNOWLEDGE_LIKE_COLUMNS, [_BLOB_ROW])
    all_unmapped = {f: {"column": None} for f in CANONICAL}
    assert sp.render_sample(conn, "knowledge", all_unmapped) == []


def test_render_sample_truncates_long_values():
    long_val = "x" * 500
    conn = _DataConn(KNOWLEDGE_LIKE_COLUMNS, [("A1", long_val, "willow", "mcp")])
    fields = sp.propose_mapping(sp.introspect(conn, "knowledge"), CANONICAL)
    sample = sp.render_sample(conn, "knowledge", fields)
    assert sample[0]["content"].endswith("…")
    assert len(sample[0]["content"]) <= 201


def test_preview_returns_sample_and_writes_nothing(home):
    conn = _DataConn(KNOWLEDGE_LIKE_COLUMNS, [_BLOB_ROW])
    res = sp.preview(conn, "app", "knowledge", CANONICAL)
    assert res["preview"] is True
    assert res["confirmed"] is False
    assert "source_id" in res["sample"][0]["content"]
    # dry run: no artifact persisted
    fp = sp.db_fingerprint(conn)
    assert sp.load_mapping("app", fp, "knowledge") is None


def test_preview_applies_overrides_in_memory(home):
    conn = _DataConn(KNOWLEDGE_LIKE_COLUMNS, [_BLOB_ROW])
    res = sp.preview(conn, "app", "knowledge", CANONICAL, overrides={"source": "source_type"})
    assert res["fields"]["source"]["tier"] == "confirmed_override"
    assert sp.load_mapping("app", sp.db_fingerprint(conn), "knowledge") is None


def test_preview_bad_override_reports_table(home):
    conn = _DataConn(KNOWLEDGE_LIKE_COLUMNS, [_BLOB_ROW])
    res = sp.preview(conn, "app", "knowledge", CANONICAL, overrides={"tags": "no_such_col"})
    assert res == {"error": "override_invalid", "field": "tags",
                   "column": "no_such_col", "table": "knowledge"}


def test_preview_table_not_found():
    conn = _DataConn({}, [])
    assert sp.preview(conn, "app", "ghost", CANONICAL) == {"error": "table_not_found", "table": "ghost"}


# ── container names are not app_ids ─────────────────────────────────────────

def test_container_dir_names_are_rejected_as_app_ids(home):
    """`_APP_ID_RE` admits any word, so an app_id equal to its own container
    built `<container>/<container>` and every per-app walk reported a phantom
    app. It happened twice in the fleet tree: mcp_apps/schema_maps/ before the
    B-50 relocation and schema_maps/schema_maps/ after it."""
    import pytest
    from willow_mcp import paths

    for reserved in ("schema_maps", "mcp_apps", "handoffs", "sessions"):
        for build in (paths.schema_maps_dir, paths.mcp_app_dir, paths.handoffs_dir):
            with pytest.raises(ValueError, match="container directory"):
                build(reserved)


def test_ordinary_app_ids_still_resolve(home):
    from willow_mcp import paths

    assert paths.schema_maps_dir("willow").name == "willow"
    assert paths.mcp_app_dir("heimdallr").name == "heimdallr"
    assert paths.handoffs_dir("nestor").name == "nestor"


# ── B-50/#238: schema_maps/ must never live under mcp_apps/ ─────────────────

def test_schema_maps_dir_is_not_under_mcp_apps_root(home):
    from willow_mcp import paths

    schema_maps = paths.schema_maps_dir("testapp").resolve()
    mcp_apps = paths.mcp_apps_root().resolve()
    assert mcp_apps not in schema_maps.parents


def test_mapping_path_never_touches_mcp_apps_root(home):
    """The actual bug: schema_maps/ used to live under mcp_apps/<app_id>/,
    which trust-root hardening chowns to the operator at 0755 -- on a
    uid-separated install the runtime process could never create it there,
    parent-directory permissions block that regardless of what's excluded
    from any chown sweep. A chmod-based proof can't demonstrate this in a
    test process running as root (root ignores DAC permission bits, so a
    read-only mcp_apps/ wouldn't actually block a regression here) -- so
    the structural proof instead: mcp_apps_root() doesn't exist before the
    call, and mapping_path() must not create it as a side effect, on any
    uid, because it no longer touches that tree at all."""
    from willow_mcp import paths

    apps_root = paths.mcp_apps_root()
    assert not apps_root.exists()

    path = sp.mapping_path("testapp", "deadbeef", "knowledge")
    path.write_text("{}")

    assert path.exists()
    assert not apps_root.exists(), "mapping_path() must never create mcp_apps_root()"
    assert path.parent == paths.schema_maps_dir("testapp")
