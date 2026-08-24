"""General web search — DuckDuckGo HTML scrape + navigational map handoffs."""

from __future__ import annotations

import hashlib
import html
import json
import logging
import os
import random
import re
import threading
import time
from collections import OrderedDict
from typing import Any, Protocol, runtime_checkable
from urllib.parse import parse_qs, quote_plus, unquote, urlparse

import requests

from . import web_fetch

log = logging.getLogger("willow_mcp.web_search")

_USER_AGENT = "Mozilla/5.0 (compatible; Willow-mcp/2.0; +https://github.com/willow-memory/willow-mcp)"
_DDG_URL = "https://html.duckduckgo.com/html/"
_LINK_RE = re.compile(
    r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
_SNIP_RE = re.compile(
    r'class="result__snippet"[^>]*>(.*?)</(?:a|td|span|div)>',
    re.IGNORECASE | re.DOTALL,
)
_TAG_RE = re.compile(r"<[^>]+>")

# Hostname suffixes for trusted-source filtering.
#
# This said "Covers all sources registered in core/jeles_sources.py SOURCES
# dict." Three things were wrong with that: `core/jeles_sources.py` is not a
# file in this repository, nothing checked the claim, and the list had drifted
# from the registry it named — missing `doi.org`, which nine registered sources
# cite through, while carrying `www.w3.org`, which is arXiv's Atom *namespace*
# identifier and not a source at all.
#
# `jeles.sources.registered_hosts()` was then made the authority, and that was
# also wrong, in a subtler way: it answers "which hosts does jeles *contact*",
# not "can a link to this host be *cited*" — 48 of jeles' 84 registered hosts
# (query-only endpoints, plus XML namespace URIs like `www.loc.gov` that are
# not a network relationship at all) can never be a search-result URL, so a
# trust verdict was never owed on them. See jeles' `docs/design/host-cards.md`
# for the measurement and `_card_axis_verdict()` below for what replaces it.
#
# The axis a verdict actually turns on, measured against this list rather than
# assumed: **system of record vs. wrapper.** It trusts the reference work of a
# domain whoever may edit it (Wikipedia, MusicBrainz, OpenStreetMap, IMDb,
# ISFDB) and refuses wrappers over someone else's record (`gutendex.com`,
# `omdbapi.com`) or utilities that are not authorities (`frankfurter.app`,
# `open-meteo.com`). It is *not* "does a named institution hold editorial
# custody" — that rule, tried and measured, flips 11 of the 12 `custody:
# community` hosts this repo has trusted for years. `tests/test_trusted_sources.py`
# still checks this list against `jeles.sources.registered_hosts()` for drift
# (a new source arriving with no stated position); `_card_axis_verdict()` below
# is the newer, narrower check, scoped to hosts jeles can actually cite through.
#
# It is still a hand-curated list, and that is deliberate rather than lazy:
# "jeles queries this host" and "a link to this host can be believed" are
# different claims. A generated list would have to reduce `patents.google.com`
# to a registrable domain and trust the whole of google.com. The registry says
# what changed; a human still says whether it counts.
_TRUSTED_SUFFIXES = (
    # Broad TLD catches (.gov, .edu, .museum, .go.jp for NDL, .ac.uk for CORE)
    "gov", "edu", "museum", "go.jp", "ac.uk",
    # Already-present institutions
    "si.edu", "loc.gov", "archive.org", "louvre.fr", "nasa.gov", "nih.gov",
    "unesco.org", "europeana.eu", "metmuseum.org", "vam.ac.uk", "britishmuseum.org",
    "nature.com", "jstor.org", "wikipedia.org", "stanford.edu", "britannica.com",
    # Academic / open-access repositories
    "openalex.org", "crossref.org", "europepmc.org", "semanticscholar.org",
    "arxiv.org", "zenodo.org", "datacite.org", "doaj.org", "openaire.eu",
    "base-search.net", "dblp.org",
    # Reference / encyclopedic
    "wikidata.org", "eol.org",
    # Museums / cultural heritage
    "clevelandart.org", "rijksmuseum.nl",
    # Libraries / archives
    "openlibrary.org", "gutenberg.org", "biodiversitylibrary.org",
    "dp.la", "bnf.fr", "archives-ouvertes.fr", "hal.science",
    # International
    "scielo.org", "europa.eu",
    # Music
    "musicbrainz.org",
    # Film / fiction bibliographic references. IMDb is community-fed but
    # editorially vetted and the de-facto filmography authority — the same
    # standing wikipedia.org and musicbrainz.org already have here. ISFDb is
    # the long-running community bibliography of speculative fiction, the
    # dblp/openlibrary of its field.
    "imdb.com", "isfdb.org",
    # Species / ecology / geography
    "gbif.org", "inaturalist.org", "openstreetmap.org",
    # Law
    "courtlistener.com",
    # Clinical trade press / science misc
    "psychiatrictimes.com", "improbable.com",
    # Registered in jeles but absent here until the registry was checked against
    # this list. `doi.org` is the notable one — nine sources (Crossref,
    # DataCite, DOAJ, Europe PMC, INSPIRE-HEP, OpenAIRE, Semantic Scholar, USGS,
    # Zenodo) resolve their citations through it, and it was not trusted.
    "doi.org", "who.int", "imf.org", "worldbank.org", "legislation.gov.uk",
    "inspirehep.net", "osf.io", "scielo.br", "patentsview.org",
    "gdeltproject.org", "carbonintensity.org.uk", "openfoodfacts.org",
    # Full host, not the registrable domain: `google.com` would trust every
    # Blogspot and Google Sites page ever published.
    "patents.google.com",
)

# Hosts jeles contacts that are deliberately NOT trust evidence, with the reason
# kept next to the decision. `tests/test_trusted_sources.py` requires every
# registered host to be either trusted above or excluded here, so a new source
# in jeles fails CI until someone decides which of the two it is — rather than
# being silently absent, which is how this list drifted in the first place.
_NOT_TRUST_EVIDENCE = {
    "azureedge.net":
        "ghoapi.azureedge.net is WHO's API on a shared Azure CDN. Anyone can "
        "host on azureedge.net, and the results themselves point at who.int, "
        "which is trusted above.",
    "gutendex.com":
        "A third-party API over Project Gutenberg's catalogue, not the "
        "publisher. Its results point at gutenberg.org, which is trusted.",
    "frankfurter.app":
        "Exchange-rate API. Useful, not an institution — a rate quoted here is "
        "not a citable source in the sense trusted_only is claiming.",
    "open-meteo.com":
        "Weather API, same reasoning as frankfurter.app.",
    "thesportsdb.com":
        "Community-edited sports database on the demo tier. Explicitly not an "
        "authority.",
    "omdbapi.com":
        "A third-party API over IMDb's data, not the publisher — the gutendex "
        "precedent exactly. Its results point at imdb.com, which is trusted "
        "above.",
}


# System-of-record overrides — the "short named override list for genuinely
# contested calls" jeles' host-cards.md asks this repo to keep. Every entry
# here is a citation-role jeles host whose `custody` is *not* `institutional`,
# so `_card_axis_verdict()` cannot decide it from the card alone (see below)
# and a person has to. Measured against jeles 0.7 (see the worktree's own
# verification, not reproduced here): every non-institutional citation host
# this repo currently trusts appears below as True, and the two it withholds
# — despite a citation role — appear as False. Nothing here changes an
# existing verdict; it names the ones that were always implicit in
# `_TRUSTED_SUFFIXES`/`_NOT_TRUST_EVIDENCE` below.
_SYSTEM_OF_RECORD_OVERRIDES: dict[str, bool] = {
    # Community-editable, and still the reference work of the domain — the
    # same standing this repo has always given Wikipedia and MusicBrainz.
    "en.wikipedia.org": True,
    "www.wikidata.org": True,
    "musicbrainz.org": True,
    "openlibrary.org": True,
    "www.openstreetmap.org": True,
    "www.inaturalist.org": True,
    "world.openfoodfacts.org": True,
    "www.imdb.com": True,   # de-facto filmography authority; see _NOT_TRUST_EVIDENCE-style
                            # reasoning in the suffix list above for the parallel with ISFDB.
    "www.isfdb.org": True,  # the dblp/openlibrary of speculative-fiction bibliography.
    # Aggregator custody: indexes someone else's record, but the index itself
    # is the system of record for the identifier it mints or the search it runs.
    "doi.org": True,        # the resolver, not the destination — host-cards.md §6.5.
    "eol.org": True,
    "www.gbif.org": True,
    "patents.google.com": True,  # full host only; see the google.com exclusion in
                                  # tests/test_trusted_sources.py.
    # Commercial custody, decided on domain standing rather than custody.
    "www.psychiatrictimes.com": True,
    # Decided False despite a citation role: not a system of record.
    "www.thesportsdb.com": False,  # demo tier — the card's own notes agree:
                                    # "Explicitly not an authority."
    "open-meteo.com": False,       # a company's own feed, no editorial record.
}


def _card_axis_verdict(host: str) -> bool | None:
    """Citability verdict for `host` from jeles' card catalog, decided on the
    system-of-record axis rather than from `custody` directly.

    Returns `None` — "no opinion, fall through to the suffix heuristic below"
    — unless a card settles it:

    * No card, or a card whose `roles` does not include `citation`: `None`,
      never `False`. jeles' `roles` field is generated from a static scan of
      its own source code and is a documented **lower bound** on
      citation-capability (host-cards.md §1) — a host it misses is a gap in
      that scan, not proof the host is uncitable. This function must never
      take trust away from a host the suffix list below grants for its own,
      independent reasons (`www.loc.gov` is exactly this case: its card is
      `roles: ["namespace", "query"]`, and it stays trusted via the `.gov`
      suffix, on its own standing as the Library of Congress).
    * `custody == "institutional"`: `True`. A named institution holding
      editorial responsibility for the record is definitionally a system of
      record. This direction of the custody axis is the one that *is*
      predictive — every institutional-custody citation host jeles ships a
      card for is already trusted by this module today.
    * Anything else: `_SYSTEM_OF_RECORD_OVERRIDES.get(host)` — a named call,
      or `None` if this host has not been reviewed and the suffix heuristic
      keeps deciding, same as it always has.
    """
    try:
        from jeles import cards
    except ImportError:
        return None
    card = cards.card(host)
    if card is None or "citation" not in card.get("roles", ()):
        return None
    if card.get("custody") == "institutional":
        return True
    return _SYSTEM_OF_RECORD_OVERRIDES.get(host)


def _hostname(url: str) -> str:
    try:
        return urlparse(url).netloc or "web"
    except Exception:
        return "web"


def _strip_tags(text: str) -> str:
    return html.unescape(_TAG_RE.sub("", text or "")).strip()


def _unwrap_ddg(href: str) -> str:
    href = (href or "").strip()
    if not href:
        return ""
    if href.startswith("//"):
        href = "https:" + href
    if "uddg=" in href:
        try:
            qs = parse_qs(urlparse(href).query)
            if qs.get("uddg"):
                return unquote(qs["uddg"][0])
        except Exception:
            log.debug("uddg extraction failed for %s", href, exc_info=True)
    return href


def _trusted_host(hostname: str) -> bool:
    """Does this host sit at or under one of the trusted suffixes?

    Match on **label boundaries only**. The bare `host.endswith(suffix)` this
    used to also accept had no notion of a dot, so any registrable domain
    ending in a trusted string inherited its trust — `evilnature.com`,
    `notarxiv.org`, `myjstor.org`, `evildp.la` all came back trusted, and every
    one of those is an open registration anyone can buy. `trusted_only=True` is
    a parameter on the `willow_web_search` tool, so that label was being handed
    to a model as a reason to believe a page.

    (The broad TLD entries — gov, edu, museum, go.jp, ac.uk — stay, and remain
    defensible: those registries are restricted, so `.gov` really is a claim
    about who registered it. The spoofable ones were the open-registration
    suffixes matched without a boundary.)

    The prefix strip was `.lstrip("www.")`, which removes leading *characters*
    from the set {w, .} rather than the prefix — so `wikipedia.org` became
    `ikipedia.org` and `worldbank.org` became `orldbank.org`, and neither
    matched the list they are explicitly on. The list was simultaneously too
    permissive and too strict.

    jeles' card catalog is consulted first, on the exact (unstripped) host —
    `_card_axis_verdict()` — because a card's key can be a specific subdomain
    (`www.imdb.com`, `en.wikipedia.org`) that the www-stripped registrable
    domain below would still match anyway, but a card can also *withhold* a
    verdict, and that withholding must never widen what the suffix list
    already grants. A card verdict of `None` falls through to the suffix
    check unchanged; only a card that actually settles the question — the
    `institutional`-custody rule or a named override — returns early.
    """
    host = (hostname or "").strip().lower().rstrip(".")
    if not host:
        return False
    card_verdict = _card_axis_verdict(host)
    if card_verdict is not None:
        return card_verdict
    if host.startswith("www."):
        host = host[4:]
    if not host:
        return False
    return any(host == suffix or host.endswith("." + suffix)
               for suffix in _TRUSTED_SUFFIXES)


def navigational_handoffs(query: str) -> list[dict[str, Any]]:
    """Synthetic map/search URLs for local/navigational queries."""
    q = query.strip()
    if not q:
        return []
    enc = quote_plus(q)
    return [
        {
            "title": f"OpenStreetMap: {q}",
            "url": f"https://www.openstreetmap.org/search?query={enc}",
            "snippet": "Search OpenStreetMap for places matching your query.",
            "source": "OpenStreetMap",
            "source_id": "maps_osm",
            "date": "",
            "hostname": "openstreetmap.org",
        },
        {
            "title": f"Google Maps: {q}",
            "url": f"https://www.google.com/maps/search/{enc}",
            "snippet": "Open Google Maps with this search.",
            "source": "Google Maps",
            "source_id": "maps_google",
            "date": "",
            "hostname": "google.com",
        },
        {
            "title": f"Web search: {q}",
            "url": f"https://duckduckgo.com/?q={enc}",
            "snippet": "Full DuckDuckGo results in your browser.",
            "source": "DuckDuckGo",
            "source_id": "web_ddg",
            "date": "",
            "hostname": "duckduckgo.com",
        },
    ]


class SearchError(Exception):
    """Base class for provider search failures."""


class TransientSearchError(SearchError):
    """Retryable failure — rate limit, 5xx, connection error, timeout."""


class HardBlockError(SearchError):
    """Non-retryable block (403/407) — retrying the same path won't help."""


# HTTP status classification for retry vs. hard-block decisions.
_RETRYABLE_STATUS = frozenset({429, 503, 504})
_HARD_BLOCK_STATUS = frozenset({403, 407})


def _parse_ddg_html(text: str, max_results: int) -> list[dict[str, Any]]:
    """Parse DuckDuckGo HTML into result dicts.

    Links and snippets are matched to each other **by position in the
    document**, not by index into two independent lists. The previous version
    did `snippets[idx]` against `links[idx]`, which silently assumed every
    result carries a `result__snippet`. When one does not — DDG omits it for
    ad, video and news-module blocks, and for results whose description is
    empty — every later snippet shifts up by one and is attributed to the wrong
    URL. Demonstrated on a two-result page where the first had no snippet: the
    second result's description came back attached to the first result's link.

    That is a wrong answer rather than a missing one, and it is handed to a
    model as the description of a page it can go and fetch.
    """
    body = text or ""
    links = list(_LINK_RE.finditer(body))
    snippets = [(m.start(), m.group(1)) for m in _SNIP_RE.finditer(body)]
    hits: list[dict[str, Any]] = []
    for idx, match in enumerate(links[: max_results + 4]):
        url = _unwrap_ddg(match.group(1))
        if not url or "duckduckgo.com" in url:
            continue
        title = _strip_tags(match.group(2)) or url
        # This result owns the span from its link up to the next link; a result
        # with no snippet in that span gets "" and takes nothing from anyone.
        span_end = links[idx + 1].start() if idx + 1 < len(links) else len(body)
        raw_snippet = next(
            (s for pos, s in snippets if match.end() <= pos < span_end), ""
        )
        snippet = _strip_tags(raw_snippet)
        host = _hostname(url)
        hits.append(
            {
                "title": title[:200],
                "url": url,
                "snippet": snippet[:400],
                "source": host,
                "source_id": "web",
                "date": "",
                "hostname": host,
            }
        )
        if len(hits) >= max_results:
            break
    return hits


# Below this body size a 200-OK page with 0 parsed links is treated as a genuine
# empty/blocked response, not a structure change. A real DDG results page is tens
# of KB; a "no results"/interstitial page is small.
_PARSER_MISS_MIN_BODY = 2000

#: Cap on the scraped body. A real DDG results page is tens of KB, and this is
#: read from whatever answered the request — `resp.text` had no bound at all,
#: so a 50MB answer was 50MB of resident string before a regex ever ran.
_MAX_BODY_BYTES = 2_000_000


def _looks_like_results_page(html_text: str) -> bool:
    """Heuristic: did DDG return a substantial results-style page (vs. an empty
    or interstitial one)? Used to flag a parser miss as likely HTML drift rather
    than a legitimately empty result set."""
    body = html_text or ""
    if len(body) < _PARSER_MISS_MIN_BODY:
        return False
    return "result" in body.lower()


def _ddg_fetch(query: str, max_results: int = 8) -> list[dict[str, Any]]:
    """Fetch + parse DuckDuckGo HTML, raising typed errors on failure.

    Raises TransientSearchError (retryable) for timeouts, connection errors,
    and 429/503/504; HardBlockError for 403/407; SearchError for other HTTP
    failures. Used by the provider chain so retry/circuit-breaker logic can
    distinguish failure classes. `ddg_html_search()` wraps this and swallows.

    A 200-OK results-style page that parses to 0 links is logged as a
    `parser_miss` (likely DDG HTML structure drift) — detection only; the call
    still returns [] and the chain's retry/fallback handle the empty result.

    **The POST goes through `web_fetch.fetch_guarded`, not `requests` directly.**
    It used to be a bare `requests.post` with no `allow_redirects=False` and no
    destination check anywhere in this module, so `requests` followed the whole
    chain inside `post()`: one 302 from the search endpoint and the body being
    scraped came from wherever the `Location:` pointed. Reproduced against the
    real requests stack — a redirect to `169.254.169.254` was followed and its
    contents came back through `_parse_ddg_html` as a search result, complete
    with a link and a snippet, which is a worse shape for this to arrive in than
    a raw body: results are what a model is meant to believe.

    `willow_web_search` sits on the same `web_read` grant as `willow_web_fetch`
    (gate.py), which had this exact defect fixed. A grant is only as strong as
    its weakest tool, so this now calls the same guard rather than a copy of it.
    """
    q = query.strip()
    if not q:
        return []
    try:
        resp, raw, _ = web_fetch.fetch_guarded(
            _DDG_URL,
            method="POST",
            data={"q": q, "b": "", "kl": "us-en"},
            headers={"User-Agent": _USER_AGENT},
            # This is the one thing bounding how far a single attempt can
            # overrun the retry budget (see `_with_retry`), so it is a knob
            # rather than a literal.
            timeout=_env_float("WILLOW_SEARCH_HTTP_TIMEOUT", 12.0),
            max_bytes=_MAX_BODY_BYTES,
        )
    except web_fetch.RefusedFetch as exc:
        # Not transient: retrying reaches the same refused destination. Let the
        # chain advance to the next provider instead of hammering this one.
        raise SearchError(f"destination refused: {exc}") from exc
    except requests.Timeout as exc:
        raise TransientSearchError(f"timeout: {exc}") from exc
    except requests.ConnectionError as exc:
        raise TransientSearchError(f"connection error: {exc}") from exc
    except requests.RequestException as exc:
        raise SearchError(f"request failed: {exc}") from exc

    # `resp.text` is unavailable — the body was streamed and capped, and the
    # response is closed. Decoding by the declared charset is what `.text` does
    # first; its chardet fallback is not worth carrying for a scrape.
    body = raw.decode(resp.encoding or "utf-8", errors="replace")
    status = resp.status_code
    if status in _HARD_BLOCK_STATUS:
        raise HardBlockError(f"hard block (HTTP {status})")
    if status in _RETRYABLE_STATUS:
        raise TransientSearchError(f"retryable (HTTP {status})")
    if status >= 400:
        raise SearchError(f"HTTP {status}")

    hits = _parse_ddg_html(body, max_results)
    if not hits and _looks_like_results_page(body):
        _log_search_event(
            query_hash=_query_hash(q), provider="ddg_html", status="parser_miss",
            result_count=0, body_bytes=len(body), cache_hit=False,
        )
        log.warning(
            "ddg parser miss — HTTP 200, %d-byte results-like body, 0 links parsed; "
            "DDG HTML structure may have changed (_LINK_RE)", len(body),
        )
    return hits


def ddg_html_search(query: str, max_results: int = 8) -> list[dict[str, Any]]:
    """Fetch DuckDuckGo HTML results (no API key).

    Back-compat surface: never raises — returns [] on any error. The provider
    chain calls `_ddg_fetch()` directly so it can see typed failures; direct
    callers of this function keep the original swallow-and-return-[] contract.
    """
    try:
        return _ddg_fetch(query, max_results=max_results)
    except SearchError as exc:
        log.warning("ddg search failed: %s", exc)
        return []
    except Exception as exc:  # pragma: no cover - defensive catch-all
        log.warning("ddg search failed: %s", exc)
        return []


# --------------------------------------------------------------------------- #
# Provider seam
#
# `search_web()` historically conflated "search" with "DuckDuckGo HTML scrape."
# The seam below separates the two without changing default behavior: the
# default provider chain is `[DDGHtmlProvider]`, so an unconfigured call returns
# exactly what `ddg_html_search()` returned before. Additional providers
# (Brave/Bing/SerpAPI) slot in via `WILLOW_SEARCH_PROVIDER_ORDER` once their
# implementations land — DDG stays the default and last-resort fallback.
# --------------------------------------------------------------------------- #


@runtime_checkable
class SearchProvider(Protocol):
    """A pluggable search backend returning Willow's standard result dicts."""

    name: str

    def available(self) -> bool:
        """Cheap readiness/credential check — False means skip without calling."""
        ...

    def search(self, query: str, max_results: int) -> list[dict[str, Any]]:
        """Return result dicts (title/url/snippet/source/source_id/date/hostname)."""
        ...


class DDGHtmlProvider:
    """Current implementation — DuckDuckGo HTML scrape, no API key required.

    Default primary provider and the last-resort fallback for the chain.
    """

    name = "ddg_html"

    def available(self) -> bool:
        return True

    def search(self, query: str, max_results: int) -> list[dict[str, Any]]:
        # Calls the raising fetch (not ddg_html_search) so the chain's retry +
        # circuit-breaker layer can distinguish transient from hard failures.
        return _ddg_fetch(query, max_results=max_results)


class BraveSearchProvider:
    """Brave Search JSON API provider — key-gated seam stub.

    Phase 1 ships the seam only: the class is present and discoverable but is
    not in the default chain, and `available()` stays False until both an API
    key is configured and the real call is implemented in a follow-up. Wiring
    it early (setting BRAVE_API_KEY) cannot change behavior because `available()`
    gates on `_IMPLEMENTED` as well.
    """

    name = "brave"
    _IMPLEMENTED = False

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key or os.getenv("BRAVE_API_KEY", "")

    def available(self) -> bool:
        return self._IMPLEMENTED and bool(self._api_key)

    def search(self, query: str, max_results: int) -> list[dict[str, Any]]:
        # Real Brave call lands in the provider-implementation follow-up.
        log.debug("brave provider not yet implemented — returning []")
        return []


# Registry of constructable providers by name. Factories are nullary so the
# chain can be (re)built per call without shared mutable state.
_PROVIDER_FACTORY: dict[str, Any] = {
    "ddg_html": DDGHtmlProvider,
    "brave": BraveSearchProvider,
}

_DEFAULT_PROVIDER_ORDER = "ddg_html"


def _provider_order() -> list[str]:
    """Provider chain from env (`WILLOW_SEARCH_PROVIDER_ORDER`), DDG by default."""
    raw = os.getenv("WILLOW_SEARCH_PROVIDER_ORDER", _DEFAULT_PROVIDER_ORDER)
    return [name.strip() for name in raw.split(",") if name.strip()]


def build_providers(order: list[str] | None = None) -> list[SearchProvider]:
    """Construct the provider chain in priority order, skipping unknown names."""
    providers: list[SearchProvider] = []
    for name in order or _provider_order():
        factory = _PROVIDER_FACTORY.get(name)
        if factory is None:
            log.warning("unknown search provider %r — skipping", name)
            continue
        providers.append(factory())
    return providers


# --------------------------------------------------------------------------- #
# Retry + circuit breaker
#
# The old code made one attempt and silently returned [] on any error. The
# retry layer recovers from transient failures (rate limits, 5xx, timeouts)
# within a bounded budget; the per-provider circuit breaker fast-fails a
# provider that is consistently down so the chain advances without waiting.
# --------------------------------------------------------------------------- #


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in ("0", "false", "no", "off", "")


def _retry_config() -> dict[str, float]:
    return {
        "max_attempts": _env_int("WILLOW_SEARCH_MAX_ATTEMPTS", 3),
        "budget": _env_float("WILLOW_SEARCH_RETRY_BUDGET", 15.0),
        "base_backoff": _env_float("WILLOW_SEARCH_BACKOFF_BASE", 1.0),
    }


def _with_retry(
    fn,
    *,
    max_attempts: int | None = None,
    budget: float | None = None,
    base_backoff: float | None = None,
    sleep=time.sleep,
    clock=time.monotonic,
):
    """Call `fn`, retrying on TransientSearchError with exponential backoff.

    Backoff is jittered (delay in [d, 2d] where d = base * 2**(attempt-1)).
    HardBlockError and any other exception propagate immediately — only
    transient errors are retried.

    **The budget bounds when a new attempt may start, not total elapsed time.**
    This docstring used to say "the whole sequence is capped by a total time
    budget", and that was not true in the case the budget exists for. The only
    check was against the *sleep*, so an attempt that itself ran long was free
    to start and then overrun without limit. Measured with the defaults (15s
    budget, 3 attempts) against a provider that times out at 12s: two attempts,
    25.2s elapsed. Nothing logged, because nothing had gone wrong by the code's
    own reckoning.

    The bound it can actually offer is `budget + one attempt`, and the attempt
    is bounded by the provider's own HTTP timeout (`WILLOW_SEARCH_HTTP_TIMEOUT`,
    12s) — so ~27s worst case with the defaults, pinned by a test. That knob
    exists so the overrun is an operator's to bound; it used to be the literal
    `timeout=12` in `_ddg_fetch`.

    The check below is in the right place and no extra guard belongs beside it:
    a pre-attempt "is the budget already spent?" test cannot fire, because
    reaching attempt N at all required attempt N-1 to pass `elapsed + delay <=
    budget` and then sleep exactly `delay`. One was written here and removed
    again for that reason. Making the budget a hard wall needs the remaining
    time threaded down into the request timeout, which means putting it on the
    `SearchProvider` protocol — a seam change, not something to smuggle in.
    """
    cfg = _retry_config()
    max_attempts = int(cfg["max_attempts"] if max_attempts is None else max_attempts)
    budget = cfg["budget"] if budget is None else budget
    base = cfg["base_backoff"] if base_backoff is None else base_backoff
    start = clock()
    last_exc: Exception | None = None
    for attempt in range(1, max(1, max_attempts) + 1):
        try:
            return fn()
        except TransientSearchError as exc:
            last_exc = exc
            if attempt >= max_attempts:
                break
            d = base * (2 ** (attempt - 1))
            delay = random.uniform(d, 2 * d)
            if (clock() - start) + delay > budget:
                log.info("retry budget exhausted after attempt %d: %s", attempt, exc)
                break
            log.info("search retry %d/%d in %.1fs: %s", attempt, max_attempts, delay, exc)
            sleep(delay)
    raise last_exc if last_exc is not None else SearchError("retry exhausted")


class CircuitBreaker:
    """Per-provider circuit breaker: CLOSED → OPEN → HALF_OPEN.

    Trips OPEN after `fail_threshold` consecutive failures and fast-fails for a
    cooldown that doubles each time a half-open probe fails (capped at
    `max_cooldown`). A success resets it fully.

    HALF_OPEN admits **one caller**. That is the whole point of the state — it
    asks "has the provider recovered?" with a single probe rather than with the
    whole backlog. (One caller, not one HTTP request: `_with_retry` sits inside
    the probe, so a probe against a timing-out provider is still up to
    `WILLOW_SEARCH_MAX_ATTEMPTS` requests. The breaker bounds concurrency here,
    not total traffic.) `allow()` used to return True unconditionally in HALF_OPEN
    while the comment beside it said "allow the single probe": measured, 50 of
    50 callers were let through. So the moment a dead provider's cooldown
    elapsed, every waiting caller hit it at once — a thundering herd aimed at
    the one service already known to be failing, which is close to the opposite
    of what a breaker is for.

    Withholding permission needs an expiry, or the fix is worse than the bug.
    `_search_providers` reports every probe back via `record_success` /
    `record_failure`, but it does so from `except Exception`, so a BaseException
    — SystemExit, or a cancellation delivered into the worker thread — returns
    no verdict. Without a deadline that would pin this provider at "refused",
    permanently and silently, for the life of the process; the only way out
    would be `reset_circuit_breakers()`. So a probe that has not reported back
    within one cooldown is treated as lost and another is issued. Worst case
    that leaks one request per cooldown, which is the same rate OPEN already
    allows itself, and it self-heals the moment any probe does report.
    """

    def __init__(
        self,
        fail_threshold: int = 5,
        base_cooldown: float = 30.0,
        max_cooldown: float = 300.0,
        clock=time.monotonic,
    ) -> None:
        self._threshold = fail_threshold
        self._base_cooldown = base_cooldown
        self._max_cooldown = max_cooldown
        self._clock = clock
        self.state = "CLOSED"
        self._failures = 0
        self._opened_at: float | None = None
        self._cooldown = base_cooldown
        # When the outstanding half-open probe was handed out; None = none out.
        self._probe_at: float | None = None

    def allow(self) -> bool:
        """Whether a request may proceed now."""
        now = self._clock()
        if self.state == "CLOSED":
            return True
        if self.state == "OPEN":
            if self._opened_at is not None and (now - self._opened_at) >= self._cooldown:
                self.state = "HALF_OPEN"
                self._probe_at = now
                return True
            return False
        # HALF_OPEN — one probe at a time, until it reports back or times out.
        if self._probe_at is not None and (now - self._probe_at) < self._cooldown:
            return False
        self._probe_at = now
        return True

    def record_success(self) -> None:
        self.state = "CLOSED"
        self._failures = 0
        self._opened_at = None
        self._cooldown = self._base_cooldown
        self._probe_at = None

    def record_failure(self) -> None:
        self._probe_at = None
        if self.state == "HALF_OPEN":
            # Probe failed — reopen with a longer cooldown.
            self._cooldown = min(self._cooldown * 2, self._max_cooldown)
            self.state = "OPEN"
            self._opened_at = self._clock()
            return
        self._failures += 1
        if self._failures >= self._threshold:
            self.state = "OPEN"
            self._opened_at = self._clock()


_BREAKERS: dict[str, CircuitBreaker] = {}


def _get_breaker(name: str) -> CircuitBreaker:
    cb = _BREAKERS.get(name)
    if cb is None:
        cb = CircuitBreaker(
            fail_threshold=_env_int("WILLOW_SEARCH_CB_THRESHOLD", 5),
            base_cooldown=_env_float("WILLOW_SEARCH_CB_COOLDOWN", 30.0),
            max_cooldown=_env_float("WILLOW_SEARCH_CB_MAX_COOLDOWN", 300.0),
        )
        _BREAKERS[name] = cb
    return cb


def reset_circuit_breakers() -> None:
    """Clear all circuit-breaker state (test helper / operator reset)."""
    _BREAKERS.clear()


# --------------------------------------------------------------------------- #
# Structured logging
#
# One structured record per search outcome on the existing `willow_mcp.web_search` logger.
# Privacy: the raw query never appears — only a `query_hash` (so cache hits and
# provider attempts for the same query correlate without leaking the text).
# Right-sized for single-host local-first: a single JSON line on the logger we
# already run, NOT a Prometheus/metrics sink (the spec's metrics surface and
# proxy_id/proxy_tier fields don't fit — there is no proxy fleet).
# --------------------------------------------------------------------------- #


def _query_hash(query: str) -> str:
    """Stable short hash of the normalized query — for logs, never the raw text."""
    norm = " ".join((query or "").lower().split())
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16]


def _elapsed_ms(start: float) -> float:
    return round((time.monotonic() - start) * 1000, 1)


def _log_search_event(**fields: Any) -> None:
    """Emit one structured, privacy-safe `web_search` record on willow_mcp.web_search."""
    record = {"event": "web_search", **fields}
    log.info("web_search %s", json.dumps(record, sort_keys=True))


class _AttemptCounter:
    """Wrap a nullary call and count invocations (retry attempts).

    Module-level (not a per-iteration closure) so the provider chain can read
    `.attempts` after `_with_retry` returns without a loop-binding lint trap.
    """

    def __init__(self, fn) -> None:
        self._fn = fn
        self.attempts = 0

    def __call__(self):
        self.attempts += 1
        return self._fn()


def _search_providers(
    query: str,
    max_results: int,
    providers: list[SearchProvider] | None = None,
) -> list[dict[str, Any]]:
    """Run the provider chain, advancing on unavailable/open/empty/error.

    Each provider call is retried on transient failure within the retry budget
    and gated by its circuit breaker. The chain resets per query; each advance
    is logged with a reason. Returns the first non-empty result set, or [] if
    every provider is exhausted.
    """
    chain = build_providers() if providers is None else providers
    qhash = _query_hash(query)
    for provider in chain:
        breaker = _get_breaker(provider.name)
        counter = _AttemptCounter(lambda p=provider: p.search(query, max_results))
        start = time.monotonic()
        try:
            if not provider.available():
                log.debug("provider %s unavailable — advancing", provider.name)
                continue
            if not breaker.allow():
                log.info("provider %s circuit open — advancing", provider.name)
                continue
            results = _with_retry(counter)
        except SearchError as exc:
            breaker.record_failure()
            _log_search_event(query_hash=qhash, provider=provider.name, status="error",
                              result_count=0, latency_ms=_elapsed_ms(start),
                              cache_hit=False, attempt=counter.attempts)
            log.warning("provider %s failed: %s — advancing", provider.name, exc)
            continue
        except Exception as exc:
            breaker.record_failure()
            _log_search_event(query_hash=qhash, provider=provider.name, status="error",
                              result_count=0, latency_ms=_elapsed_ms(start),
                              cache_hit=False, attempt=counter.attempts)
            log.warning("provider %s error: %s — advancing", provider.name, exc)
            continue
        breaker.record_success()
        _log_search_event(query_hash=qhash, provider=provider.name,
                          status="ok" if results else "empty", result_count=len(results),
                          latency_ms=_elapsed_ms(start), cache_hit=False,
                          attempt=counter.attempts)
        if results:
            return results
        log.info("provider %s returned 0 results — advancing", provider.name)
    return []


# --------------------------------------------------------------------------- #
# Query cache
#
# In-process LRU + per-entry TTL over assembled result sets. A repeated query
# inside the TTL window returns immediately without touching the provider chain.
# Right-sized for Willow's single-host reality: in-process only, no Redis (the
# spec's multi-process backend doesn't fit). Current-events queries ("latest",
# "breaking", a date, ...) get a short TTL so fast-moving topics stay fresh.
# Opt-out per call via search_web(cache=False); disable globally with
# WILLOW_SEARCH_CACHE=0. Only non-empty results are cached — caching a [] would
# pin a transient all-providers-down failure for the full TTL.
# --------------------------------------------------------------------------- #


_CURRENT_EVENTS_MARKERS = (
    "latest", "breaking", "just now", "just announced", "right now",
    "live", "today", "this morning", "this week", "current",
)


def _cache_config() -> dict[str, Any]:
    return {
        "enabled": _env_bool("WILLOW_SEARCH_CACHE", True),
        "ttl": _env_float("WILLOW_SEARCH_CACHE_TTL", 300.0),
        "ttl_news": _env_float("WILLOW_SEARCH_CACHE_TTL_NEWS", 60.0),
    }


def _is_current_events(query: str) -> bool:
    """Heuristic: does this query chase fast-moving / time-sensitive results?"""
    q = (query or "").lower()
    return any(marker in q for marker in _CURRENT_EVENTS_MARKERS)


def _cache_key(
    query: str,
    max_results: int,
    trusted_only: bool,
    include_handoffs: bool,
    order: list[str],
) -> str:
    """sha256 over normalized query + the params that change the result set."""
    norm = " ".join((query or "").lower().split())
    raw = f"{norm}|{max_results}|{int(trusted_only)}|{int(include_handoffs)}|{','.join(order)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class _TTLCache:
    """Bounded LRU cache with per-entry TTL, guarded by a lock.

    Eviction is least-recently-used once `maxsize` is exceeded; expired entries
    are dropped lazily on access.

    This used to say "not thread-safe by design — Willow's MCP server services
    search calls serially per session, so a lock would only add contention."
    Both halves of that were wrong. `_SEARCH_CACHE` is one module-level object
    shared by every session, so a per-session guarantee would not cover it even
    if there were one; and there is not, because `willow_web_search` is a `def`
    rather than an `async def`, and the MCP SDK hands sync tools to
    `anyio.to_thread.run_sync`. Under `streamable-http` (server.py's transport)
    two concurrent searches are therefore two OS threads in this dict.

    What that exposes is small and real: `get` reads an entry, then `del`s it
    if expired, and two threads arriving together can both pass the check and
    the second `del` raises KeyError; `move_to_end` can likewise race a
    concurrent `set`'s eviction of the same key. Both windows are a bytecode or
    two wide, and neither reproduced — 300 rounds of 16 threads on a barrier
    produced zero errors, because the GIL rarely switches there. So this is a
    correction to reasoning that was false, not a fix for a failure anyone saw.

    The lock is here because the argument for omitting it was the contention
    cost, and that cost is roughly 50ns on a path whose alternative outcome is
    an HTTP request. There is nothing to trade.
    """

    def __init__(self, maxsize: int = 256, clock=time.monotonic) -> None:
        self._maxsize = max(1, maxsize)
        self._clock = clock
        self._data: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> Any | None:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if self._clock() >= expires_at:
                self._data.pop(key, None)
                return None
            self._data.move_to_end(key)
            return value

    def set(self, key: str, value: Any, ttl: float) -> None:
        with self._lock:
            self._data[key] = (self._clock() + ttl, value)
            self._data.move_to_end(key)
            while len(self._data) > self._maxsize:
                self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)


_SEARCH_CACHE = _TTLCache(maxsize=_env_int("WILLOW_SEARCH_CACHE_SIZE", 256))
_SEARCH_CACHE_LOCK = threading.Lock()


def reset_search_cache() -> None:
    """Clear the query cache and re-read its size from env (test/operator reset)."""
    global _SEARCH_CACHE
    with _SEARCH_CACHE_LOCK:
        _SEARCH_CACHE = _TTLCache(maxsize=_env_int("WILLOW_SEARCH_CACHE_SIZE", 256))


def search_web(
    query: str,
    *,
    max_results: int = 8,
    trusted_only: bool = False,
    include_handoffs: bool = False,
    cache: bool = True,
    providers: list[SearchProvider] | None = None,
) -> list[dict[str, Any]]:
    """
    General open web search for Willow.

    trusted_only: heuristic filter on hostname suffix (not verification).
    include_handoffs: prepend map/search URLs for navigational queries.
    cache: serve/store via the in-process LRU+TTL cache (opt-out per call;
        WILLOW_SEARCH_CACHE=0 disables globally). Current-events queries get a
        short TTL automatically.
    providers: explicit provider chain (default: built from
        WILLOW_SEARCH_PROVIDER_ORDER, falling back to DDG HTML).
    """
    cfg = _cache_config()
    order = [p.name for p in providers] if providers is not None else _provider_order()
    use_cache = cache and cfg["enabled"]
    with _SEARCH_CACHE_LOCK:
        local_cache = _SEARCH_CACHE
    key = (
        _cache_key(query, max_results, trusted_only, include_handoffs, order)
        if use_cache
        else None
    )
    if key is not None:
        cached = local_cache.get(key)
        if cached is not None:
            _log_search_event(query_hash=_query_hash(query), provider="cache",
                              status="ok", result_count=len(cached), latency_ms=0.0,
                              cache_hit=True, attempt=0)
            # Copy the dicts, not just the list. `list(cached)` handed every
            # caller the cache's own dict objects, so one caller annotating a
            # hit in place rewrote what the next caller read back — verified by
            # setting a title on one result and seeing it on the next call.
            return [dict(h) for h in cached]

    hits: list[dict[str, Any]] = []
    if include_handoffs:
        hits.extend(navigational_handoffs(query))

    raw = _search_providers(query, max_results, providers)
    if trusted_only:
        # The handoffs go through the same filter. They were exempt, so
        # `trusted_only=True` returned google.com and duckduckgo.com — mixed
        # into one flat `results` list that gives a model no way to tell
        # filtered from unfiltered.
        hits = [h for h in hits if _trusted_host(h.get("hostname", ""))]
        raw = [h for h in raw if _trusted_host(h.get("hostname", ""))]

    seen = {h["url"] for h in hits if h.get("url")}
    for hit in raw:
        url = hit.get("url") or ""
        if url and url not in seen:
            seen.add(url)
            hits.append(hit)
    result = hits[: max_results + (3 if include_handoffs else 0)]

    # Cache only non-empty provider hits — an empty `raw` means every provider
    # failed or was filtered out, and pinning that for the TTL would mask recovery.
    if key is not None and raw:
        ttl = cfg["ttl_news"] if _is_current_events(query) else cfg["ttl"]
        # Copies on the way in too — `result` is what this caller is about to
        # be handed, so storing those same objects would let them mutate it.
        local_cache.set(key, [dict(h) for h in result], ttl)
    return result
