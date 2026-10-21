"""Tests for web_search — DDG parse + search_web."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from fake_transport import transport

from willow_mcp import web_fetch, web_search


def test_parse_ddg_html_extracts_links():
    html = '''
    <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2F">Example</a>
    <td class="result__snippet">A snippet here</td>
    '''
    hits = web_search._parse_ddg_html(html, max_results=5)
    assert len(hits) == 1
    assert hits[0]["url"] == "https://example.com/"
    assert hits[0]["title"] == "Example"


def test_search_web_returns_empty_for_blank_query():
    assert web_search.search_web("   ") == []


@patch("willow_mcp.web_search._search_providers")
def test_search_web_delegates_to_providers(mock_providers):
    mock_providers.return_value = [{"title": "T", "url": "https://x.test", "snippet": "",
                                    "source": "x.test", "source_id": "web", "date": "",
                                    "hostname": "x.test"}]
    hits = web_search.search_web("hello", max_results=3, cache=False)
    assert len(hits) == 1
    assert hits[0]["url"] == "https://x.test"


# ── trusted_only was wrong in both directions ────────────────────────────────
#
# `trusted_only=True` is a parameter on the `willow_web_search` MCP tool, so
# this label is handed to a model as a reason to believe a page. It was:
#
#   * spoofable — `host.endswith(suffix)` had no notion of a label boundary, so
#     any registrable domain ending in a trusted string inherited its trust.
#     `evilnature.com`, `notarxiv.org`, `myjstor.org`, `evildp.la` all passed,
#     and every one of those is an open registration anyone can buy.
#   * broken for two of its own entries — `.lstrip("www.")` strips leading
#     *characters* from {w, .}, not the prefix, so `wikipedia.org` became
#     `ikipedia.org` and `wikidata.org` became `ikidata.org`.
#
# The two bugs partly masked each other: `web.archive.org` was mangled to
# `eb.archive.org` and then rescued by the loose `endswith`.


def _old_trusted_host(hostname: str) -> bool:
    """The previous implementation, kept so these tests show a real delta."""
    host = (hostname or "").lower().lstrip("www.")
    if not host:
        return False
    for suffix in web_search._TRUSTED_SUFFIXES:
        if host == suffix or host.endswith("." + suffix) or host.endswith(suffix):
            return True
    return False


def test_a_lookalike_domain_is_not_trusted():
    """The security half. Each of these is an open registration."""
    for host in ("evilnature.com", "notarxiv.org", "myjstor.org", "evildp.la",
                 "attacker-europa.eu", "fakemusicbrainz.org"):
        assert _old_trusted_host(host) is True, f"{host} used to pass"
        assert web_search._trusted_host(host) is False, host


def test_every_listed_suffix_trusts_itself():
    """The correctness half. `wikipedia.org` and `wikidata.org` are on the list
    and were rejected by it."""
    rejected = [s for s in web_search._TRUSTED_SUFFIXES
                if not web_search._trusted_host(s)]
    assert rejected == [], rejected
    assert not _old_trusted_host("wikipedia.org"), "the bug this pins"
    assert web_search._trusted_host("wikipedia.org")


def test_subdomains_and_www_still_match():
    for host in ("www.nature.com", "api.crossref.org", "web.archive.org",
                 "some.dept.edu", "WWW.LOC.GOV", "arxiv.org."):
        assert web_search._trusted_host(host) is True, host


def test_restricted_registries_stay_broadly_trusted():
    """`.gov`, `.edu`, `.ac.uk` and friends are restricted registries — a
    lookalike under them is not something an attacker can register, so the
    broad TLD entries remain a real claim about who registered the name."""
    for host in ("nih.gov", "phishing-nih.gov", "evilvam.ac.uk"):
        assert web_search._trusted_host(host) is True, host


def test_an_empty_or_junk_host_is_not_trusted():
    for host in ("", None, ".", "www.", "localhost"):
        assert web_search._trusted_host(host) is False, host


# ── HALF_OPEN admitted everyone ──────────────────────────────────────────────
#
# `allow()` ended with:
#
#     return True  # HALF_OPEN — allow the single probe
#
# and the comment was the only thing enforcing "single". Every caller arriving
# in HALF_OPEN was let through, so the instant a dead provider's cooldown
# elapsed the whole waiting backlog hit it at once — a thundering herd pointed
# at the one service already known to be failing.


class _Clock:
    """Manual monotonic clock. Time only moves when a test says so."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _tripped(clock, **kw):
    """A breaker sitting in OPEN, one cooldown ago — the next `allow()` moves
    it to HALF_OPEN."""
    cb = web_search.CircuitBreaker(fail_threshold=2, base_cooldown=30.0,
                                   max_cooldown=300.0, clock=clock, **kw)
    cb.record_failure()
    cb.record_failure()
    assert cb.state == "OPEN"
    clock.advance(30.0)
    return cb


def test_half_open_admits_one_probe_not_the_whole_backlog():
    clock = _Clock()
    cb = _tripped(clock)

    admitted = sum(cb.allow() for _ in range(50))

    assert cb.state == "HALF_OPEN"
    assert admitted == 1, f"{admitted} of 50 callers got through (was 50 of 50)"


def test_the_probe_reports_back_and_the_breaker_moves():
    """A probe is only useful if its verdict lands. Success closes the breaker;
    failure reopens it with the doubled cooldown."""
    clock = _Clock()
    cb = _tripped(clock)
    assert cb.allow() is True
    cb.record_success()
    assert cb.state == "CLOSED"
    assert cb.allow() is True

    clock = _Clock()
    cb = _tripped(clock)
    assert cb.allow() is True
    cb.record_failure()
    assert cb.state == "OPEN"
    # Doubled: 30 -> 60. Still shut at 30s, open for a probe at 60s.
    clock.advance(30.0)
    assert cb.allow() is False
    clock.advance(30.0)
    assert cb.allow() is True


def test_a_second_probe_follows_the_first_once_it_reports():
    """Refusal is per outstanding probe, not per state. A failed probe reopens
    and a later one is admitted; the flag does not accumulate."""
    clock = _Clock()
    cb = _tripped(clock)
    for round_ in range(3):
        assert cb.allow() is True, f"round {round_}: no probe admitted"
        assert cb.allow() is False, f"round {round_}: a second probe got out"
        cb.record_failure()
        clock.advance(cb._cooldown)


def test_a_lost_probe_does_not_wedge_the_breaker_forever():
    """The failure mode this fix could have introduced, and the reason there is
    a deadline. `_search_providers` reports every probe back from
    `except Exception` — which a BaseException walks straight past, returning
    no verdict. A probe with no expiry would then hold this provider at
    "refused" for the life of the process, silently.

    So an unreported probe is treated as lost after one cooldown."""
    clock = _Clock()
    cb = _tripped(clock)
    assert cb.allow() is True          # handed out, and never reported back

    clock.advance(29.0)
    assert cb.allow() is False, "a live probe should still hold the door"

    clock.advance(1.0)
    assert cb.allow() is True, "a lost probe wedged the breaker permanently"
    assert cb.state == "HALF_OPEN"


def test_the_transition_out_of_open_spends_the_probe():
    """The caller that trips OPEN -> HALF_OPEN *is* the probe. If that
    transition did not claim it, the first arrival would take one and the
    second would take another."""
    clock = _Clock()
    cb = _tripped(clock)
    assert cb.state == "OPEN"
    assert cb.allow() is True
    assert cb.state == "HALF_OPEN"
    assert cb.allow() is False


def test_a_closed_breaker_is_never_gated():
    """The probe bookkeeping must not leak into the healthy path."""
    clock = _Clock()
    cb = web_search.CircuitBreaker(fail_threshold=2, base_cooldown=30.0, clock=clock)
    assert all(cb.allow() for _ in range(50))
    cb.record_failure()
    assert cb.state == "CLOSED"
    assert all(cb.allow() for _ in range(50))


# ── snippets were attributed to the wrong result ─────────────────────────────
#
# `_parse_ddg_html` ran two independent regexes over the whole document and
# then paired them by list index: `snippets[idx]` against `links[idx]`. That
# holds only if every result carries a `result__snippet`. DDG omits it for ad,
# video and news-module blocks, and for results with an empty description — and
# one omission shifts every later snippet onto the wrong URL.


_ONE_RESULT_HAS_NO_SNIPPET = '''
<div class="result results_links">
  <a class="result__a" href="https://first.example/page">First result</a>
</div>
<div class="result results_links">
  <a class="result__a" href="https://second.example/page">Second result</a>
  <td class="result__snippet">This text describes the SECOND result.</td>
</div>
'''


def test_a_result_with_no_snippet_does_not_steal_the_next_ones():
    """The wrong-answer half. Before: the second result's description came back
    attached to the first result's URL — which is what a model is then told
    that page contains."""
    hits = web_search._parse_ddg_html(_ONE_RESULT_HAS_NO_SNIPPET, max_results=5)
    by_url = {h["url"]: h["snippet"] for h in hits}
    assert by_url["https://first.example/page"] == ""
    assert by_url["https://second.example/page"] == "This text describes the SECOND result."


def test_snippets_still_land_on_the_right_result_in_the_ordinary_case():
    """The regression half — positional matching must not break the normal page
    where every result does have a snippet."""
    html = "".join(
        f'<div class="result"><a class="result__a" href="https://s{i}.example/">T{i}</a>'
        f'<td class="result__snippet">snippet {i}</td></div>'
        for i in range(5)
    )
    hits = web_search._parse_ddg_html(html, max_results=5)
    assert [h["snippet"] for h in hits] == [f"snippet {i}" for i in range(5)]
    assert [h["url"] for h in hits] == [f"https://s{i}.example/" for i in range(5)]


def test_a_trailing_snippet_belongs_to_the_last_result():
    """The final result's span runs to the end of the document, not to a next
    link that isn't there."""
    html = ('<a class="result__a" href="https://only.example/">Only</a>'
            '<td class="result__snippet">the only snippet</td>')
    hits = web_search._parse_ddg_html(html, max_results=5)
    assert hits[0]["snippet"] == "the only snippet"


# ── trusted_only leaked untrusted hosts, and the cache leaked its own dicts ───


def _fake_hit(host="arxiv.org"):
    return {"title": "T", "url": f"https://{host}/x", "snippet": "", "source": host,
            "source_id": "web", "date": "", "hostname": host}


def test_trusted_only_also_filters_the_handoffs():
    """`willow_web_search`'s own description promises "keep verified
    institutional domain suffixes only", and the handoffs bypassed the filter —
    so `trusted_only=True` returned google.com and duckduckgo.com. They arrive
    in one flat `results` list with nothing marking them as synthetic, so a
    model has no way to tell them from a filtered hit."""
    web_search.reset_search_cache()
    with patch.object(web_search, "_search_providers", return_value=[_fake_hit()]):
        hits = web_search.search_web("pizza near me", trusted_only=True,
                                     include_handoffs=True, cache=False)
    hosts = [h["hostname"] for h in hits]
    assert "google.com" not in hosts and "duckduckgo.com" not in hosts, hosts
    # openstreetmap.org is on the trusted list and legitimately survives.
    assert hosts == ["openstreetmap.org", "arxiv.org"], hosts


def test_untrusted_handoffs_still_come_through_when_not_filtering():
    """The other direction: with `trusted_only=False` the handoffs are the
    whole point and must all still be there."""
    web_search.reset_search_cache()
    with patch.object(web_search, "_search_providers", return_value=[]):
        hits = web_search.search_web("pizza near me", include_handoffs=True, cache=False)
    assert [h["hostname"] for h in hits] == [
        "openstreetmap.org", "google.com", "duckduckgo.com"]


def test_a_caller_cannot_mutate_what_the_next_caller_reads():
    """`return list(cached)` copied the list and shared every dict in it, so
    annotating a result in place rewrote the cache for everyone after."""
    web_search.reset_search_cache()
    with patch.object(web_search, "_search_providers", return_value=[_fake_hit()]):
        first = web_search.search_web("same query", cache=True)
    first[0]["title"] = "MUTATED BY CALLER"

    # No provider this time — a hit here can only have come from the cache.
    with patch.object(web_search, "_search_providers", return_value=[]) as never:
        second = web_search.search_web("same query", cache=True)
    assert never.call_count == 0, "expected a cache hit"
    assert second[0]["title"] == "T", second[0]["title"]

    second[0]["title"] = "MUTATED AGAIN"
    with patch.object(web_search, "_search_providers", return_value=[]):
        third = web_search.search_web("same query", cache=True)
    assert third[0]["title"] == "T", third[0]["title"]


# ── the retry budget does not bound total time, whatever it said ─────────────


def test_the_retry_budget_bounds_a_new_attempt_not_total_elapsed():
    """`_with_retry`'s docstring claimed "the whole sequence is capped by a
    total time budget". It is not: the only check is against the *sleep*, so an
    attempt that runs long starts freely and then overruns.

    This pins the real behaviour and the real bound — `budget + one attempt` —
    so that a future change either keeps it or has to come here and say why."""
    budget, attempt_cost = 15.0, 12.0     # the defaults: budget, HTTP timeout
    now = [0.0]
    starts = []

    def clock():
        return now[0]

    def sleep(d):
        now[0] += d

    def slow_failure():
        starts.append(now[0])
        now[0] += attempt_cost
        raise web_search.TransientSearchError("timeout")

    with pytest.raises(web_search.SearchError):
        web_search._with_retry(slow_failure, max_attempts=3, budget=budget,
                               base_backoff=1.0, sleep=sleep, clock=clock)

    assert now[0] > budget, "if this ever fails the budget became a real wall"
    assert now[0] <= budget + attempt_cost, (
        f"elapsed {now[0]:.1f}s exceeds the documented bound of "
        f"budget + one attempt ({budget + attempt_cost}s)"
    )
    assert all(s < budget for s in starts), (
        f"an attempt started after the budget was spent: {starts}")


def test_the_http_timeout_is_a_knob_because_it_bounds_the_overrun():
    """It was the literal `timeout=12`. Since it is the only thing bounding how
    far one attempt can overrun the retry budget, an operator has to be able to
    move it."""
    captured = {}

    class _Resp:
        status_code = 200
        encoding = "utf-8"

    def spy(url, **kwargs):
        captured.update(kwargs)
        return _Resp(), b"", []

    with patch.object(web_search.web_fetch, "fetch_guarded", spy):
        with patch.dict("os.environ", {"WILLOW_SEARCH_HTTP_TIMEOUT": "3.5"}):
            web_search._ddg_fetch("q")
        assert captured["timeout"] == 3.5
        captured.clear()
        with patch.dict("os.environ", {}, clear=False):
            os.environ.pop("WILLOW_SEARCH_HTTP_TIMEOUT", None)
            web_search._ddg_fetch("q")
        assert captured["timeout"] == 12.0


# --------------------------------------------------------------------------- #
# Destination guard on the scrape
#
# `_ddg_fetch` was a bare `requests.post` with no `allow_redirects=False` and no
# destination check anywhere in the module, so requests followed the whole chain
# inside `post()`. `willow_web_search` sits on the same `web_read` grant as
# `willow_web_fetch` (gate.py), which had exactly this fixed — a grant is only
# as strong as its weakest tool, so the scrape now enters through
# `web_fetch.fetch_guarded` too.
#
# `fake_transport` is a real requests stack over a fake adapter; nothing here
# opens a socket.
# --------------------------------------------------------------------------- #

_HTML = {"Content-Type": "text/html"}
_RESULT = (b'<a class="result__a" href="https://arxiv.org/abs/1">A paper</a>'
           b'<td class="result__snippet">about things</td>')


@pytest.fixture
def offline(monkeypatch):
    """No live DNS and no ambient proxy — the guard must decide, not the box."""
    monkeypatch.setattr(web_fetch.urllib.request, "getproxies", lambda: {})
    public = {"html.duckduckgo.com": "20.43.161.105", "arxiv.org": "151.101.3.42"}

    def fake(host, port=0, *a, **k):
        if host in public:
            return [(2, 1, 6, "", (public[host], port or 0))]
        raise OSError(f"unstubbed lookup of {host!r}")

    monkeypatch.setattr(web_fetch.socket, "getaddrinfo", fake)


def _scrape(script, query="anything"):
    """Drive one scrape over a scripted chain.

    Both seams are routed: `web_fetch._require_requests`, which is where the
    request goes now, and this module's own `requests` binding, which is where
    it went before. Pointing the same script at both is what lets these tests
    be run against the unfixed tree and fail on behaviour rather than on a
    missing attribute.
    """
    shim, adapter = transport(script)
    with patch.object(web_fetch, "_require_requests", lambda: shim), \
         patch.object(web_search, "requests", shim):
        try:
            return web_search._ddg_fetch(query), adapter, None
        except web_search.SearchError as exc:
            return None, adapter, exc


def test_a_redirect_from_the_search_endpoint_to_the_metadata_host_is_refused(offline):
    """Measured against the old code: the 302 was followed and the metadata
    endpoint's body came back through `_parse_ddg_html` as a search *result*,
    with a title, a link and a snippet — the shape a model is meant to believe."""
    hits, adapter, exc = _scrape([
        (302, {"Location": "https://169.254.169.254/latest/meta-data/iam/"}, b""),
        (200, _HTML, _RESULT),
    ])
    assert hits is None
    assert "169.254.169.254" in str(exc)
    assert len(adapter.dialled) == 1, "the redirect was taken anyway"


def test_the_scrape_refusal_is_not_retryable(offline):
    """A refused destination is refused every time. Raising the transient class
    would spend the retry budget re-reaching the same address."""
    _, _, exc = _scrape([(302, {"Location": "http://127.0.0.1:8080/"}, b"")])
    assert isinstance(exc, web_search.SearchError)
    assert not isinstance(exc, web_search.TransientSearchError)


def test_a_redirect_to_a_public_host_is_still_followed_as_a_get(offline):
    """The other half — and the POST must not be replayed at a target the
    responder chose."""
    hits, adapter, exc = _scrape([
        (302, {"Location": "https://arxiv.org/html/"}, b""),
        (200, _HTML, _RESULT),
    ])
    assert exc is None
    assert [h["url"] for h in hits] == ["https://arxiv.org/abs/1"]
    assert [m for m, _ in adapter.dialled] == ["POST", "GET"]


def test_the_scraped_body_is_capped(offline):
    """`resp.text` had no bound: whatever answered decided how much memory this
    process spent. A real results page is tens of KB."""
    _, adapter, _ = _scrape([(200, _HTML, 50 * 1024 * 1024)])
    read = adapter.raws[-1].read_bytes
    # An absolute bound first, and deliberately: asserting only against
    # `_MAX_BODY_BYTES` would move with the constant, so raising the cap to
    # 500MB would still "pass". A results page is tens of KB.
    assert read < 5 * 1024 * 1024, f"read {read} bytes scraping a search page"
    assert read <= web_search._MAX_BODY_BYTES + web_fetch._CHUNK_BYTES


def test_an_ordinary_scrape_still_parses(offline):
    """The whole point of the guard is that the normal path is unchanged."""
    hits, adapter, exc = _scrape([(200, _HTML, _RESULT)])
    assert exc is None
    assert hits == [{
        "title": "A paper", "url": "https://arxiv.org/abs/1",
        "snippet": "about things", "source": "arxiv.org",
        "source_id": "web", "date": "", "hostname": "arxiv.org",
    }]
    assert adapter.dialled == [("POST", web_search._DDG_URL)]


def test_the_http_status_classification_survives_the_move(offline):
    """403/429 still land in the right exception classes now that the response
    arrives via fetch_guarded rather than requests.post."""
    for status, cls in ((403, web_search.HardBlockError),
                        (429, web_search.TransientSearchError),
                        (500, web_search.SearchError)):
        _, _, exc = _scrape([(status, _HTML, b"")])
        assert isinstance(exc, cls), f"HTTP {status} -> {exc!r}"


def test_the_search_module_makes_no_unguarded_network_call():
    """The defect was one call site. This is the check that a second one cannot
    quietly appear beside it."""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(web_search))
    calls = [
        f"{node.func.value.id}.{node.func.attr} (line {node.lineno})"
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in ("requests", "urllib", "http", "socket")
    ]
    assert calls == [], f"unguarded transport calls in web_search: {calls}"


def test_ddg_links_are_dropped_by_host_not_by_substring():
    """A result whose query names duckduckgo.com is still a result; only
    DuckDuckGo's own hosts are skipped (CodeQL: incomplete URL substring check)."""
    assert web_search._is_ddg_host("https://duckduckgo.com/settings")
    assert web_search._is_ddg_host("https://html.duckduckgo.com/html/?q=x")
    assert not web_search._is_ddg_host("https://example.com/?ref=duckduckgo.com")
    assert not web_search._is_ddg_host("https://notduckduckgo.com/")
