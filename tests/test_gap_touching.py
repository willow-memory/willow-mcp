"""gaps.touching() — B1 of docs/design/gaps-in-soil.md, §4.2, reworked per
Loki's audit A4836541 (B1 permission gate lives in server.py's wiring, see
test_gap_touching_wiring.py; this file covers gaps.touching() itself: the
three tiers, tier-2's bounded cost and health reporting, M2's cross-repo
verification, M3's bare/qualified path handling, and the byte/row bounds).

Every test controls the backlog by monkeypatching ``gaps._store.all``
directly rather than logging real gaps into the shared session-wide
Store() singleton (see test_gaps.py's module docstring) — `touching()`
scans the WHOLE live backlog on every call (it has no topic filter), so
sharing state with the rest of the suite would make these tests order-
dependent. The code_graph DB path is controlled the same way, via
``gaps._code_graph_db_for``, which now returns `(path, source)`.
"""

from __future__ import annotations

import sqlite3
import time

from willow_mcp import gaps


def _row(gap_id, topic, question, status="open"):
    return {
        "_id": gap_id,
        "topic": topic,
        "question": question,
        "status": status,
        "asked_count": 1,
        "last_asked_at": "2026-09-28T00:00:00Z",
    }


def _make_symbol_db(tmp_path, rows, name="graph.db"):
    """rows: list of (fqn, name, file_path)."""
    db_path = tmp_path / name
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE symbols (fqn TEXT PRIMARY KEY, name TEXT NOT NULL, "
        "kind TEXT NOT NULL, file_path TEXT NOT NULL, start_line INTEGER "
        "DEFAULT 0, end_line INTEGER DEFAULT 0, signature TEXT DEFAULT '', "
        "byte_size INTEGER DEFAULT 0)"
    )
    conn.execute("CREATE INDEX idx_symbols_name ON symbols(name)")
    for fqn, name_, file_path in rows:
        conn.execute(
            "INSERT INTO symbols (fqn, name, kind, file_path) VALUES (?, ?, 'function', ?)",
            (fqn, name_, file_path),
        )
    conn.commit()
    conn.close()
    return db_path


# ── Tier 1: exact path match (qualified paths only — M3) ───────────────────

def test_tier1_exact_path_match_on_a_qualified_path(monkeypatch):
    rows = [_row("aaa111111111", "willow-bot",
                  "willow_bot/tick.py:3011 has a bug in the steward loop")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    out = gaps.touching(["willow_bot/tick.py"])
    assert out["state"] == "populated"
    assert out["items"][0]["id"] == "aaa111111111"
    assert out["items"][0]["why"].startswith("exact:")


def test_tier1_directory_prefix_match(monkeypatch):
    rows = [_row("bbb222222222", "deploy", "deploy/ratatosk-listen-loki.service.template broke")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    out = gaps.touching(["deploy/"])
    assert out["state"] == "populated"
    assert out["items"][0]["id"] == "bbb222222222"


def test_tier1_promoted_gaps_are_excluded(monkeypatch):
    rows = [_row("ccc333333333", "x", "src/willow_mcp/gaps.py:31 needs a rewrite",
                  status="promoted")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    out = gaps.touching(["src/willow_mcp/gaps.py"])
    assert out["state"] == "empty"
    assert out["items"] == []


# ── M3: bare paths never give tier 1 "exact" ────────────────────────────────

def test_m3_bare_input_path_never_gives_tier1_exact(monkeypatch):
    """A bare `paths` entry like tick.py is ambiguous across every repo
    that has one — Loki A4836541 M3. It must not become 'exact' even
    though it appears verbatim in the gap text."""
    rows = [_row("aaa111111112", "willow-bot", "tick.py has a bug in the steward loop")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    monkeypatch.setattr(gaps, "_code_graph_db_for", lambda project: (None, "none"))
    out = gaps.touching(["tick.py"])
    # No project given -> tier 3 (the only tier a bare path can reach) never
    # fires either, so this must NOT show up as populated via tier 1.
    assert out["state"] == "empty"


def test_m3_bare_gap_text_reaches_qualified_input_via_tier3_not_tier1(monkeypatch):
    """Gap text names a bare filename ('server.py'), the caller's input path
    is qualified ('src/willow_mcp/server.py') — real-world mismatch M3
    documents (13 bare 'server.py' vs 0 full-path hits on the live
    backlog). With a project pinned, this is found through tier 3's
    basename-stem match, weaker-labelled, never 'exact'."""
    rows = [_row("aaa111111113", "willow-mcp", "server.py needs a review")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    monkeypatch.setattr(gaps, "_code_graph_db_for", lambda project: (None, "none"))
    out = gaps.touching(["src/willow_mcp/server.py"], project="willow-mcp")
    assert out["state"] == "populated"
    assert out["items"][0]["why"].startswith("project+stem:")


# ── Tier 2: symbol match, bounded and health-reported ───────────────────────

def test_tier2_symbol_match_resolves_through_code_graph(tmp_path, monkeypatch):
    rows = [_row("ddd444444444", "willow-mcp", "the `_gap_lines` helper swallows every failure")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    db_path = _make_symbol_db(
        tmp_path, [("willow_mcp.boot_context._gap_lines", "_gap_lines", "boot_context.py")]
    )
    monkeypatch.setattr(gaps, "_code_graph_db_for", lambda project: (db_path, "per_project"))
    out = gaps.touching(["boot_context.py"], project="willow-mcp")
    assert out["state"] == "populated"
    assert out["items"][0]["id"] == "ddd444444444"
    assert out["items"][0]["why"] == "symbol:_gap_lines"
    assert out["tier2_health"] == "indexed"


def test_tier2_ambiguous_symbol_does_not_match(tmp_path, monkeypatch):
    rows = [_row("eee555555555", "willow-mcp", "what does `helper` actually do here")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    db_path = _make_symbol_db(
        tmp_path,
        [
            ("mod_a.helper", "helper", "a.py"),
            ("mod_b.helper", "helper", "b.py"),
        ],
    )
    monkeypatch.setattr(gaps, "_code_graph_db_for", lambda project: (db_path, "per_project"))
    out = gaps.touching(["a.py"], project="willow-mcp")
    # two fqns share the name "helper" -- not exactly one match, so tier 2
    # never fires, and there is no path/stem hit either.
    assert out["state"] == "empty"


def test_tier2_case_sensitive_exact_name_match(tmp_path, monkeypatch):
    """Loki A4836541 B2: the query is `name = ?` (no LOWER()), so it uses
    idx_symbols_name. A differently-cased identifier simply does not match
    -- that is the intended, documented behavior now (exact name, not
    case-folded), not a regression."""
    rows = [_row("fff666666666", "willow-mcp", "the `_Gap_Lines` helper needs review")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    db_path = _make_symbol_db(tmp_path, [("m._gap_lines", "_gap_lines", "boot_context.py")])
    monkeypatch.setattr(gaps, "_code_graph_db_for", lambda project: (db_path, "per_project"))
    out = gaps.touching(["boot_context.py"], project="willow-mcp")
    assert out["state"] == "empty"


def test_tier2_health_unindexed_when_no_db(monkeypatch):
    rows = [_row("ggg777777777", "willow-mcp", "the `_gap_lines` helper swallows every failure")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    monkeypatch.setattr(gaps, "_code_graph_db_for", lambda project: (None, "none"))
    out = gaps.touching(["boot_context.py"], project="willow-mcp")
    assert out["tier2_health"] == "unindexed"


def test_tier2_health_unreachable_when_db_is_corrupt(tmp_path, monkeypatch):
    bad_db = tmp_path / "graph.db"
    bad_db.write_text("not a sqlite database")
    rows = [_row("hhh888888888", "willow-mcp", "the `_gap_lines` helper swallows every failure")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    monkeypatch.setattr(gaps, "_code_graph_db_for", lambda project: (bad_db, "per_project"))
    out = gaps.touching(["boot_context.py"], project="willow-mcp")
    assert out["tier2_health"] == "unreachable"
    # A degraded graph must not read as an honestly-empty backlog (M1).
    assert out["state"] != "unreachable"  # the GAP STORE read still succeeded


def test_tier2_health_not_attempted_when_backlog_is_unreachable(monkeypatch):
    def raises(coll):
        raise RuntimeError("disk gone")

    monkeypatch.setattr(gaps._store, "all", raises)
    out = gaps.touching(["anything.py"])
    assert out["tier2_health"] == "not_attempted"


def test_tier2_budget_exhausted_is_reported_not_silently_truncated(tmp_path, monkeypatch):
    rows = [
        _row(f"i{i:011x}", "willow-mcp", f"symbol_{i}_needs_review discussion")
        for i in range(5)
    ]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    db_path = _make_symbol_db(
        tmp_path, [(f"m.symbol_{i}_needs_review", f"symbol_{i}_needs_review", "x.py")
                   for i in range(5)]
    )
    monkeypatch.setattr(gaps, "_code_graph_db_for", lambda project: (db_path, "per_project"))
    monkeypatch.setattr(gaps, "MAX_TIER2_LOOKUPS", 2)
    out = gaps.touching(["x.py"], project="willow-mcp")
    assert out["tier2_health"] == "budget_exhausted"


def test_tier2_time_budget_exhausts_via_injected_clock(tmp_path, monkeypatch):
    """Loki 28B97C69 fold-in (B2b): the 2.0s wall-clock budget is exercised
    directly with an injected clock, independent of MAX_TIER2_LOOKUPS --
    the lookup-count budget alone (already covered above) never proves the
    time budget is actually wired up."""
    rows = [
        _row(f"t{i:011x}", "willow-mcp", f"symbol_{i}_needs_review discussion")
        for i in range(3)
    ]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    db_path = _make_symbol_db(
        tmp_path, [(f"m.symbol_{i}_needs_review", f"symbol_{i}_needs_review", "x.py")
                   for i in range(3)]
    )
    monkeypatch.setattr(gaps, "_code_graph_db_for", lambda project: (db_path, "per_project"))

    import time as time_mod
    calls = {"n": 0}
    real_monotonic = time_mod.monotonic

    def fake_monotonic():
        calls["n"] += 1
        # First call is `start`; every call after that reads as far past
        # MAX_TIER2_SECONDS, regardless of how fast the test actually runs.
        return 0.0 if calls["n"] == 1 else gaps.MAX_TIER2_SECONDS + 1000.0

    monkeypatch.setattr(time_mod, "monotonic", fake_monotonic)
    try:
        out = gaps.touching(["x.py"], project="willow-mcp")
    finally:
        monkeypatch.setattr(time_mod, "monotonic", real_monotonic)
    assert out["tier2_health"] == "budget_exhausted"


def test_tier2_identifier_order_is_deterministic_not_hash_seed_dependent(monkeypatch):
    """Loki 28B97C69 M4: the live backlog has more unique identifiers than
    the tier-2 budget, so WHICH ones get resolved (and thus labelled)
    must not depend on PYTHONHASHSEED-randomized set iteration. Rows are
    ordered by last_asked_at descending, ids as a tiebreaker; identifiers
    within each row keep their extraction order, first-seen-wins."""
    rows = [
        {"_id": "aaa", "topic": "t", "question": "alpha_one and alpha_two here",
         "status": "open", "last_asked_at": "2026-09-01T00:00:00Z"},
        {"_id": "bbb", "topic": "t", "question": "beta_one and alpha_one again",
         "status": "open", "last_asked_at": "2026-09-03T00:00:00Z"},
        {"_id": "ccc", "topic": "t", "question": "gamma_one only",
         "status": "open", "last_asked_at": "2026-09-02T00:00:00Z"},
    ]
    order1 = gaps._ordered_unique_identifiers(rows)
    order2 = gaps._ordered_unique_identifiers(list(reversed(rows)))
    # Same regardless of the INPUT list's own order -- sorting by
    # last_asked_at is what fixes it, not incidental list order.
    assert order1 == order2
    # Most-recently-asked row (bbb, 09-03) first: beta_one, then alpha_one
    # (already seen from bbb, not re-added); then ccc's gamma_one; then
    # aaa's alpha_one (already seen) and alpha_two.
    assert order1 == ["beta_one", "alpha_one", "gamma_one", "alpha_two"]


# ── L6/L6b: the real per-project/flat/none resolution, not a stub ──────────

def test_real_db_resolution_prefers_per_project_over_flat(tmp_path, monkeypatch):
    """Loki 28B97C69 B3: every other tier-2 test stubs
    `_code_graph_db_for` -- this one lets the REAL resolution run against
    a real $WILLOW_HOME/code_graph tree. A mutant that drops the
    per-project branch (L6b) or the flat branch (L6) must fail this and
    the two tests below."""
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    per_project_dir = tmp_path / "code_graph" / "willow-mcp"
    per_project_dir.mkdir(parents=True)
    _make_symbol_db(per_project_dir, [("m.only_in_per_project", "only_in_per_project", "x.py")],
                     name="graph.db")
    flat_dir = tmp_path / "code_graph"
    _make_symbol_db(flat_dir, [("m.only_in_flat", "only_in_flat", "x.py")], name="graph.db")

    rows = [_row("real1", "willow-mcp", "`only_in_per_project` needs a look, "
                                          "so does `only_in_flat`")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    out = gaps.touching(["x.py"], project="willow-mcp")
    assert out["state"] == "populated"
    assert out["items"][0]["why"] == "symbol:only_in_per_project"


def test_real_db_resolution_falls_back_to_flat_when_no_per_project_db(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    flat_dir = tmp_path / "code_graph"
    flat_dir.mkdir(parents=True)
    _make_symbol_db(flat_dir, [("m.only_in_flat", "only_in_flat", "x.py")], name="graph.db")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "x.py").write_text("def only_in_flat():\n    pass\n")

    rows = [_row("real2", "willow-mcp", "`only_in_flat` needs a look")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    monkeypatch.setattr(gaps, "_project_root", lambda project: checkout)
    out = gaps.touching(["x.py"], project="willow-mcp")
    assert out["state"] == "populated"
    assert out["items"][0]["why"] == "symbol:only_in_flat"


def test_real_db_resolution_none_when_neither_db_exists(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    rows = [_row("real3", "willow-mcp", "`whatever_symbol` needs a look")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    out = gaps.touching(["x.py"], project="willow-mcp")
    assert out["tier2_health"] == "unindexed"


def test_tier2_single_connection_regardless_of_row_or_identifier_count(tmp_path, monkeypatch):
    """Loki A4836541 B2: ONE sqlite3.connect() call for the whole
    touching() call, not one per (row, identifier) pair."""
    rows = [
        _row(f"j{i:011x}", "willow-mcp", f"symbol_{i}_alpha and symbol_{i}_beta both need review")
        for i in range(30)
    ]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    db_path = _make_symbol_db(tmp_path, [("m.x", "symbol_0_alpha", "x.py")])
    monkeypatch.setattr(gaps, "_code_graph_db_for", lambda project: (db_path, "per_project"))

    calls = []
    real_connect = sqlite3.connect

    def counting_connect(*a, **k):
        calls.append(1)
        return real_connect(*a, **k)

    monkeypatch.setattr(sqlite3, "connect", counting_connect)
    gaps.touching(["x.py"], project="willow-mcp")
    assert len(calls) == 1


def test_tier2_large_synthetic_graph_completes_well_inside_budget(tmp_path, monkeypatch):
    """Loki B9F28JGJ: the OLD code exceeded 60s on a 20k-symbol graph via
    LOWER()-defeated full scans, one fresh connection per (row,
    identifier). This is the regression test: a real index-backed graph at
    real scale (2,000 symbols, 300 gaps each with 2 identifiers -- 600
    distinct identifiers, comfortably inside MAX_TIER2_LOOKUPS) must finish
    in low single-digit seconds and report 'indexed', not
    'budget_exhausted'."""
    n_gaps = 300
    rows = [
        _row(f"k{i:011x}", "willow-mcp", f"symbol_{i}_alpha needs review")
        for i in range(n_gaps)
    ]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    symbol_rows = [
        (f"m.symbol_{i}", f"symbol_{i}_alpha", "x.py") for i in range(n_gaps)
    ] + [
        (f"m.noise_{i}", f"noise_symbol_{i}", f"noise_{i}.py") for i in range(1700)
    ]
    db_path = _make_symbol_db(tmp_path, symbol_rows)
    monkeypatch.setattr(gaps, "_code_graph_db_for", lambda project: (db_path, "per_project"))

    start = time.monotonic()
    out = gaps.touching(["x.py"], project="willow-mcp", limit=gaps.MAX_TOUCHING_ROWS)
    elapsed = time.monotonic() - start

    assert out["tier2_health"] == "indexed"
    assert elapsed < 10.0, f"tier 2 took {elapsed:.2f}s over a 2000-symbol graph"


# ── M2: flat-DB fallback must not mislabel across repos ─────────────────────

def test_m2_flat_db_match_discarded_when_project_root_unresolvable(tmp_path, monkeypatch):
    rows = [_row("lll000000001", "willow-mcp", "the `_gap_lines` helper needs review")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    db_path = _make_symbol_db(tmp_path, [("m._gap_lines", "_gap_lines", "boot_context.py")])
    monkeypatch.setattr(gaps, "_code_graph_db_for", lambda project: (db_path, "flat"))
    monkeypatch.setattr(gaps, "_project_root", lambda project: None)
    out = gaps.touching(["boot_context.py"], project="unregistered-project")
    assert out["state"] == "empty"


def test_m2_flat_db_match_verified_against_project_checkout(tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "boot_context.py").write_text("def _gap_lines():\n    return []\n")
    rows = [_row("lll000000002", "willow-mcp", "the `_gap_lines` helper needs review")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    db_path = _make_symbol_db(tmp_path, [("m._gap_lines", "_gap_lines", "boot_context.py")],
                               name="flat.db")
    monkeypatch.setattr(gaps, "_code_graph_db_for", lambda project: (db_path, "flat"))
    monkeypatch.setattr(gaps, "_project_root", lambda project: checkout)
    out = gaps.touching(["boot_context.py"], project="willow-mcp")
    assert out["state"] == "populated"
    assert out["items"][0]["why"] == "symbol:_gap_lines"


def test_m2_flat_db_match_discarded_when_file_absent_from_checkout(tmp_path, monkeypatch):
    """The classic cross-repo mislabel M2 names: two repos share a
    relative path, the flat DB resolves a symbol in the OTHER repo, and
    without verification it would be labelled tier 2 for THIS project."""
    checkout = tmp_path / "checkout"
    checkout.mkdir()  # boot_context.py does NOT exist here -- another repo's file
    rows = [_row("lll000000003", "willow-mcp", "the `_gap_lines` helper needs review")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    db_path = _make_symbol_db(tmp_path, [("other_repo.m._gap_lines", "_gap_lines",
                                           "boot_context.py")], name="flat2.db")
    monkeypatch.setattr(gaps, "_code_graph_db_for", lambda project: (db_path, "flat"))
    monkeypatch.setattr(gaps, "_project_root", lambda project: checkout)
    out = gaps.touching(["boot_context.py"], project="willow-mcp")
    assert out["state"] == "empty"


def test_m2_flat_db_match_discarded_when_file_exists_but_does_not_define_symbol(
    tmp_path, monkeypatch
):
    """Loki 28B97C69 Q4 exactly: willow-bot's `_guarded_home` row resolves
    against willow-mcp's OWN tests/conftest.py (the file exists in this
    project's checkout) but that file never defines `_guarded_home` --
    the tightened M2 check (file exists AND actually defines the symbol)
    must drop this, not just check existence."""
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    # The file is real in THIS project's checkout, but doesn't define the
    # symbol the flat DB row claims -- it belongs to a different repo.
    (checkout / "tests" / "conftest.py").parent.mkdir(parents=True)
    (checkout / "tests" / "conftest.py").write_text("import pytest\n")
    rows = [_row("lll000000004", "willow-mcp", "what does `_guarded_home` actually do")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    db_path = _make_symbol_db(
        tmp_path,
        [("willow_bot.tests.conftest._guarded_home", "_guarded_home", "tests/conftest.py")],
        name="flat3.db",
    )
    monkeypatch.setattr(gaps, "_code_graph_db_for", lambda project: (db_path, "flat"))
    monkeypatch.setattr(gaps, "_project_root", lambda project: checkout)
    out = gaps.touching(["tests/conftest.py"], project="willow-mcp")
    assert out["state"] == "empty"


# ── Tier 3: project + stem (the 07aa99036f09 shape) ────────────────────────

def test_tier3_project_and_stem_finds_07aa99036f09_shape(monkeypatch):
    rows = [
        _row(
            "07aa99036f09",
            "ratatosk/listener-home-pin-tests-and-crown-mcp-guard",
            "the listen goroutine never learned its home directory before the crown mcp guard landed",
        )
    ]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    monkeypatch.setattr(gaps, "_code_graph_db_for", lambda project: (None, "none"))
    out = gaps.touching(
        ["deploy/ratatosk-listen-loki.service.template"], project="ratatosk"
    )
    assert out["state"] == "populated"
    assert out["items"][0]["id"] == "07aa99036f09"
    assert out["items"][0]["why"].startswith("project+stem:")


def test_tier3_requires_project_pin(monkeypatch):
    rows = [
        _row(
            "07aa99036f09",
            "ratatosk/listener-home-pin-tests-and-crown-mcp-guard",
            "the listen goroutine never learned its home directory",
        )
    ]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    monkeypatch.setattr(gaps, "_code_graph_db_for", lambda project: (None, "none"))
    # No project passed -- tier 3 never fires even though the stem overlaps.
    out = gaps.touching(["deploy/ratatosk-listen-loki.service.template"])
    assert out["state"] == "empty"


def test_tier3_capped_at_five_rows_but_total_counts_all_of_them(monkeypatch):
    rows = [
        _row(f"f{i:011x}", "ratatosk/many-listener-gaps", f"listener gap number {i}")
        for i in range(8)
    ]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    monkeypatch.setattr(gaps, "_code_graph_db_for", lambda project: (None, "none"))
    out = gaps.touching(["some/listener-thing.service.template"], project="ratatosk")
    assert len(out["items"]) == gaps.MAX_TOUCHING_TIER3_ROWS
    # L1a: total is counted BEFORE the tier-3 cap, so it still reflects all
    # 8 real matches, not just the 5 that made the page.
    assert out["total"] == 8
    # NITS(a): the tier-3 cap itself is a truncation, even though the page
    # (5 small rows) never comes close to the row/byte bounds.
    assert out["truncated"] is True


# ── Three-state: unreachable vs. empty ─────────────────────────────────────

def test_unreachable_store_is_not_folded_into_empty(monkeypatch):
    def raises(coll):
        raise RuntimeError("disk gone")

    monkeypatch.setattr(gaps._store, "all", raises)
    out = gaps.touching(["anything.py"])
    assert out["state"] == "unreachable"
    assert "disk gone" in out["reason"]
    assert out["items"] == []


def test_no_matches_is_empty_not_unreachable(monkeypatch):
    rows = [_row("aaa000000001", "unrelated", "nothing here touches your paths")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    monkeypatch.setattr(gaps, "_code_graph_db_for", lambda project: (None, "none"))
    out = gaps.touching(["completely/unrelated/path.py"])
    assert out["state"] == "empty"
    assert out["items"] == []


def test_no_input_paths_is_empty(monkeypatch):
    rows = [_row("aaa000000002", "x", "topic.py exists")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    out = gaps.touching([])
    assert out["state"] == "empty"


# ── Bounds: row cap and byte ceiling ────────────────────────────────────────

def test_row_cap_at_twenty_five(monkeypatch):
    rows = [_row(f"a{i:011x}", "t", f"path/to/file{i}.py exists") for i in range(40)]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    paths = [f"path/to/file{i}.py" for i in range(40)]
    out = gaps.touching(paths, limit=100)
    assert len(out["items"]) == gaps.MAX_TOUCHING_ROWS
    assert out["truncated"] is True


def test_byte_ceiling_ends_the_page_early(monkeypatch):
    # `_brief_view` truncates `question` to 200 chars but NOT `topic` --
    # inflate `topic` so each brief row is ~1 KB, well under the 25-row
    # cap but over the 16 KB page ceiling after ~16 rows.
    big_topic = "t" * 1000
    rows = [_row(f"b{i:011x}", big_topic, "path/to/bigfile.py exists") for i in range(20)]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    out = gaps.touching(["path/to/bigfile.py"], limit=gaps.MAX_TOUCHING_ROWS)
    assert len(out["items"]) < gaps.MAX_TOUCHING_ROWS
    assert out["truncated"] is True


def test_no_next_cursor_key_the_verb_cannot_support(monkeypatch):
    """L1a: next_cursor was removed rather than shipped as a promise the
    verb (no cursor parameter) cannot keep."""
    rows = [_row("aaa000000004", "t", "path/to/file.py exists")]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    out = gaps.touching(["path/to/file.py"])
    assert "next_cursor" not in out


# ── Regex robustness (Loki A4836541 L1c) ────────────────────────────────────

def test_path_regex_does_not_backtrack_pathologically(monkeypatch):
    """A long unbroken run of path-class characters with no valid
    extension at the end must not make extraction pathologically slow --
    each segment is length-bounded and the whole pattern is \\b-anchored."""
    hostile = "a" * 5000 + " normal text after it with no extension anywhere"
    rows = [_row("aaa000000005", "t", hostile)]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    start = time.monotonic()
    out = gaps.touching(["path/to/file.py"])
    elapsed = time.monotonic() - start
    assert elapsed < 2.0, f"path extraction took {elapsed:.2f}s over a hostile token"
    assert out["state"] == "empty"


# ── Mutation-proof anchors (see docs in the handoff for the red results) ──

def test_tier3_is_the_only_route_to_07aa99036f09_shaped_gaps(monkeypatch):
    """Names the exact behavior a 'drop tier 3' mutation breaks: a gap
    naming no file path at all is found ONLY through project+stem."""
    rows = [
        _row(
            "07aa99036f09",
            "ratatosk/listener-home-pin-tests-and-crown-mcp-guard",
            "the listen goroutine never learned its home directory before the crown mcp guard landed",
        )
    ]
    monkeypatch.setattr(gaps._store, "all", lambda coll: rows)
    monkeypatch.setattr(gaps, "_code_graph_db_for", lambda project: (None, "none"))
    out = gaps.touching(
        ["deploy/ratatosk-listen-loki.service.template"], project="ratatosk"
    )
    assert out["total"] == 1
    assert out["items"][0]["why"].startswith("project+stem:")
