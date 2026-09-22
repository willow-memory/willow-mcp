"""Fleet-wide gap backlog: log/list/resolve, dedup, and stopword handling.

willow_mcp.gaps holds a module-level Store() singleton created at import
time (same pattern as server.py's _store — see conftest.py's docstring),
so WILLOW_STORE_ROOT is fixed for the whole test session, not per-test.
Isolation here comes from giving each test its own unique `topic`, the
same way the rest of the suite uses unique app_ids, rather than swapping
WILLOW_STORE_ROOT per test (which the already-imported singleton would
never see).
"""

from __future__ import annotations

from willow_mcp import gaps


def test_log_requires_topic_and_question():
    assert "error" in gaps.log("", "some question")
    assert "error" in gaps.log("topic", "")


def test_log_creates_open_gap():
    result = gaps.log("t-basic", "What is the accent color in Nord?")
    assert result["status"] == "open"
    assert result["asked_count"] == 1


def test_log_repeated_question_bumps_count_not_duplicates():
    gaps.log("t-dedup", "What is the accent color in Nord?")
    gaps.log("t-dedup", "what is the accent color in nord")
    rows = gaps.list_gaps(topic="t-dedup")["items"]
    assert len(rows) == 1
    assert rows[0]["asked_count"] == 2


def test_log_same_question_different_topic_is_separate():
    gaps.log("t-cross-a", "What is the primary color?")
    gaps.log("t-cross-b", "What is the primary color?")
    assert len(gaps.list_gaps(topic="t-cross-a")["items"]) == 1
    assert len(gaps.list_gaps(topic="t-cross-b")["items"]) == 1


def test_list_gaps_ranks_by_asked_count():
    gaps.log("t-rank", "low priority question")
    for _ in range(3):
        gaps.log("t-rank", "high priority question")
    rows = gaps.list_gaps(topic="t-rank")["items"]
    assert rows[0]["question"] == "high priority question"
    assert rows[0]["asked_count"] == 3


def test_list_gaps_filters_by_status():
    a = gaps.log("t-status", "What is the accent color in Nord?")
    gaps.log("t-status", "What is the border radius in Grove?")
    gaps.resolve(a["id"])
    open_rows = gaps.list_gaps(topic="t-status", status="open")["items"]
    resolved_rows = gaps.list_gaps(topic="t-status", status="resolved")["items"]
    assert len(open_rows) == 1
    assert len(resolved_rows) == 1
    assert resolved_rows[0]["question"] == "What is the accent color in Nord?"


def test_resolve_missing_gap_errors():
    assert gaps.resolve("does-not-exist-xyz") == {"error": "not_found"}


def test_resolve_is_bookkeeping_only():
    logged = gaps.log("t-resolve", "question a")
    result = gaps.resolve(logged["id"], note="drafted an answer")
    assert result["status"] == "resolved"
    row = gaps.get(logged["id"])
    assert row["status"] == "resolved"
    assert row["resolution_note"] == "drafted an answer"
    assert row.get("promoted_to") is None


def test_mark_promoted_sets_status_and_target():
    logged = gaps.log("t-promote", "question a")
    gaps.mark_promoted(logged["id"], "KID1234")
    row = gaps.get(logged["id"])
    assert row["status"] == "promoted"
    assert row["promoted_to"] == "KID1234"


def test_resolve_already_promoted_gap_errors():
    logged = gaps.log("t-promote-resolve", "question a")
    gaps.mark_promoted(logged["id"], "KID1234")
    result = gaps.resolve(logged["id"])
    assert result == {"error": "already_promoted", "promoted_to": "KID1234"}


def test_log_after_promoted_reports_promoted_without_reopening():
    logged = gaps.log("t-promote-relog", "question a")
    gaps.mark_promoted(logged["id"], "KID1234")
    result = gaps.log("t-promote-relog", "question a")
    assert result["status"] == "promoted"
    assert result["promoted_to"] == "KID1234"
    row = gaps.get(logged["id"])
    assert row["status"] == "promoted"


# ── the read door: gap_get / gap_list query/since/topic-prefix/brief/cap
# (gap 1477ebb2bc35) ──────────────────────────────────────────────────────

def test_get_gap_hit_returns_full_record():
    logged = gaps.log("t-get-hit", "What color is the sky?")
    record = gaps.get_gap(logged["id"])
    assert record["_id"] == logged["id"]
    assert record["topic"] == "t-get-hit"
    assert record["question"] == "What color is the sky?"
    assert record["status"] == "open"


def test_get_gap_miss_returns_not_found():
    assert gaps.get_gap("does-not-exist-xyz") == {"error": "not_found", "id": "does-not-exist-xyz"}


def test_list_gaps_query_narrows_by_substring_over_topic_and_question():
    gaps.log("t-query", "How does the render pipeline work?")
    gaps.log("t-query", "What is the deploy schedule?")
    rows = gaps.list_gaps(topic="t-query", query="render pipeline")["items"]
    assert len(rows) == 1
    assert "render pipeline" in rows[0]["question"].lower()


def test_list_gaps_query_is_and_not_or():
    gaps.log("t-query-and", "alpha bravo question")
    gaps.log("t-query-and", "alpha only question")
    rows = gaps.list_gaps(topic="t-query-and", query="alpha bravo")["items"]
    assert len(rows) == 1
    assert "bravo" in rows[0]["question"]


def test_list_gaps_query_matches_topic_too():
    gaps.log("t-query-topic-marker", "an unrelated question body")
    rows = gaps.list_gaps(query="query-topic-marker")["items"]
    assert any(r["topic"] == "t-query-topic-marker" for r in rows)


def test_list_gaps_since_narrows_to_recently_asked():
    gaps.log("t-since", "an old-ish question")
    from datetime import datetime, timedelta, timezone
    future = (datetime.now(timezone.utc) + timedelta(days=3650)).isoformat()
    rows = gaps.list_gaps(topic="t-since", since=future)["items"]
    assert rows == []
    rows_all = gaps.list_gaps(topic="t-since")["items"]
    assert len(rows_all) == 1


def test_list_gaps_topic_prefix_matches_nested_namespace():
    gaps.log("t-prefix/child", "a nested question")
    gaps.log("t-prefix-other", "not nested, just similarly named")
    rows = gaps.list_gaps(topic="t-prefix")["items"]
    topics = {r["topic"] for r in rows}
    assert "t-prefix/child" in topics
    assert "t-prefix-other" not in topics


def test_list_gaps_topic_exact_still_matches():
    gaps.log("t-prefix-exact", "an exact-topic question")
    rows = gaps.list_gaps(topic="t-prefix-exact")["items"]
    assert len(rows) == 1


def test_list_gaps_page_cap_is_25_even_when_more_is_asked():
    # `log`'s dedup key drops tokens under 3 chars (see gaps._tokens), so a
    # bare digit like "0"/"1" would collapse every question into one row --
    # each token here is >=3 chars and unique per iteration.
    for i in range(30):
        gaps.log("t-cap", f"unique caps question variant q{i:03d}x")
    rows = gaps.list_gaps(topic="t-cap", limit=1000)["items"]
    assert len(rows) == gaps.MAX_LIST_LIMIT == 25


def test_list_gaps_brief_default_shape():
    logged = gaps.log("t-brief", "x" * 400)
    rows = gaps.list_gaps(topic="t-brief")["items"]
    row = rows[0]
    assert set(row.keys()) == {"id", "topic", "status", "asked_count", "last_asked_at", "question"}
    assert row["id"] == logged["id"]
    assert len(row["question"]) == 200


def test_list_gaps_brief_false_returns_full_record():
    gaps.log("t-full", "a full record question")
    rows = gaps.list_gaps(topic="t-full", brief=False)["items"]
    row = rows[0]
    assert "first_asked_at" in row
    assert "_id" in row
    assert row["question"] == "a full record question"
