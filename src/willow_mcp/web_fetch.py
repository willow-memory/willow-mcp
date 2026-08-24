"""Guarded HTTP fetch for agents — destination guard + external-guard scan.

The destination half of this file was rewritten after an audit of the sibling
guard in `jeles._egress` turned up the same defects here, larger. Three, and
each one alone was enough to reach the cloud metadata endpoint:

* **The literal host was the only thing inspected.** No name was ever resolved,
  so `https://totally-legit.example/` with an A record of `127.0.0.1` walked
  straight through — measured, `validate_fetch_url` returned None.
* **`allow_redirects=True` was passed to `requests`,** which follows the chain
  inside `get()`. So even the literal check only ever applied to the *first*
  URL, and a 302 to `169.254.169.254` was followed unchecked. This is the one
  that matters, because the first URL is chosen by the operator's agent and the
  redirect target is chosen by whatever answered.
* **Two parsers disagreed about the hostname.** `urlparse` and
  `urllib3.util.parse_url` both read `https://169.254.169%2e254/` as the opaque
  name `169.254.169%2e254`; urllib3's connection layer decodes it before
  dialling. Measured: `connect(('169.254.169.254', 443))`.

`willow_web_fetch` shares the `web_read` permission line with
`willow_institutional_search` (gate.py), so these were one grant with the
weaker path setting the ceiling.

Kept deliberately separate from jeles' copy rather than shared: that one guards
`urllib`, this one guards `requests`/`urllib3`, and the whole class of bug here
is transport-specific parsing. A shared abstraction would have to be right
about both connectors at once, which is how the disagreement got missed the
first time.

**This module is now the single egress path for that grant, not one of three.**
A later pass found the same permission line still bounded by weaker code:
`web_search._ddg_fetch` posted with redirects followed inside `requests`, and
`mai/parser._http_host_blocked` was a third, independent host guard — a bare
hostname regex in front of `urllib.request.urlopen` on the default opener. Both
now call `fetch_guarded` here. What is shared is the *policy* (which
destinations are refused) and the *transport* it was written against
(`requests`); nothing was copied. That is the same argument as the paragraph
above, applied the other way: jeles stays separate because its connector is
different, and these two joined because theirs is not.

Two bounds that the rewrite above did not have and this one does:

* **A body was never capped.** `requests.get` without `stream=True` reads the
  whole response inside `Session.send`, so `resp.content[:max_bytes]` truncated
  a string that was already resident. Measured: 50MB buffered against a
  512_000-byte `max_bytes`, and a 50MB body on a *redirect* hop — one nothing
  ever reads — buffered in full. Every request is now streamed and read through
  `_read_capped`.
* **The final response was never closed.** Intermediates were; the one whose
  body is actually read was left to the collector. `_read_capped` closes in a
  `finally`, so the connection is returned on the error paths too.
"""

from __future__ import annotations

import html
import ipaddress
import logging
import re
import socket
import urllib.request
from typing import Any
from urllib.parse import unquote, urljoin, urlparse

log = logging.getLogger("willow_mcp.web_fetch")

_USER_AGENT = "Mozilla/5.0 (compatible; Willow-mcp/2.0; +https://github.com/willow-memory/willow-mcp)"
_DEFAULT_MAX_BYTES = 512_000
_DEFAULT_MAX_CHARS = 80_000
#: requests defaults to 30. A fetch tool does not need a chain that long, and
#: every hop is another destination check and another resolver round trip.
_MAX_REDIRECTS = 5
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
#: Read granularity, not a limit. Small enough that the cap overshoots by at
#: most this much, large enough not to make a syscall per kilobyte.
_CHUNK_BYTES = 8192
_TAG_RE = re.compile(r"<[^>]+>")


def _require_requests():
    try:
        import requests  # noqa: WPS433 — optional at import, required at call
    except ImportError as exc:
        raise RuntimeError(
            "willow_web_fetch requires the 'requests' package — "
            "pip install 'willow-mcp[web]' or pip install requests"
        ) from exc
    return requests


def _strip_html(text: str) -> str:
    return html.unescape(_TAG_RE.sub(" ", text or ""))


def _as_address(host: str) -> str | None:
    """The host read as a literal address, or None if it is a name.

    `inet_aton` is here because `ip_address` is stricter than every resolver:
    it rejects `2130706433`, `0177.0.0.1`, `0x7f.0.0.1` and `127.1`. urllib3
    hands all four to the socket untouched and `getaddrinfo` reads every one of
    them as `127.0.0.1` — measured. Doing that arithmetic locally is what keeps
    them refused on the two paths with no DNS lookup: behind a proxy, and
    offline.
    """
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        return socket.inet_ntoa(socket.inet_aton(host))
    except OSError:
        return None


def _dialled_hosts(hostname: str) -> list[str]:
    """Every host string this URL could end up dialling.

    Both parsers in front of the socket keep percent-escapes; the connection
    layer decodes them. Checking only what `urlparse` reports is what let
    `https://169.254.169%2e254/` through, so the decoded view is checked too
    and either one being private refuses.
    """
    seen: list[str] = []
    for raw in (hostname, unquote(hostname or "")):
        h = (raw or "").strip().strip("[]").lower().rstrip(".")
        if h and h not in seen:
            seen.append(h)
    return seen


def _proxy_dials_for(url: str) -> bool:
    """Whether a proxy, not this process, will resolve and dial the destination.

    `requests` reads the same environment (`trust_env` -> `getproxies`), so this
    agrees with what the transport will do. It matters because a proxied request
    never resolves the destination here — the TCP peer is the proxy and the
    hostname travels to it in a CONNECT line. Resolving anyway is wrong in both
    directions, and the direction that bites is the false refusal: under
    split-horizon DNS a legitimate public host answers with an RFC1918 address
    and the fetch is refused for a reason that is not true.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if not urllib.request.getproxies().get((parsed.scheme or "").lower()):
        return False
    try:
        return not urllib.request.proxy_bypass(parsed.hostname or "")
    except (OSError, ValueError):
        return True


def _is_blocked_host(hostname: str, *, resolve: bool = True) -> bool:
    hosts = _dialled_hosts(hostname)
    if not hosts:
        return True
    for host in hosts:
        if host in ("localhost", "localhost.localdomain", "ip6-localhost"):
            return True
        if host.endswith(".local") or host.endswith(".internal"):
            return True

        literal = _as_address(host)
        if literal is not None:
            candidates = [literal]
        elif resolve:
            try:
                candidates = [info[4][0] for info in socket.getaddrinfo(host, None)]
            except OSError:
                # About to fail on its own. Refusing here would report a
                # security decision for what is really a DNS failure.
                continue
        else:
            continue

        for raw in candidates:
            try:
                addr = ipaddress.ip_address(raw)
            except ValueError:
                continue
            # `not is_global` is appended, not substituted. On its own it would
            # allow IPv4 and IPv6 multicast and the NAT64 well-known prefix —
            # and `64:ff9b::a9fe:a9fe` reaches 169.254.169.254 on a NAT64
            # network. The explicit list on its own allowed all of
            # 100.64.0.0/10, which is what cloud and ISP internals are numbered
            # from. Each half covers what the other misses.
            if (
                addr.is_private
                or addr.is_loopback
                or addr.is_link_local
                or addr.is_reserved
                or addr.is_multicast
                or addr.is_unspecified
                or not addr.is_global
            ):
                return True
    return False


def validate_fetch_url(url: str) -> str | None:
    """Why this URL must not be fetched, or None.

    Hostnames are resolved, not just pattern-matched. A name-only check is the
    obvious thing to write and is defeated by pointing a public name at
    `127.0.0.1`; this one used to be exactly that.

    **Residual, stated rather than papered over.** Resolving here and connecting
    afterwards are two separate lookups, so a name that answers public now and
    private a moment later still gets through. Closing that needs the connection
    pinned to the address that was checked, which requests does not expose. It
    raises the cost from "set a DNS record" to "win a race". Behind a proxy the
    name is not resolved here at all, so a name only the proxy can resolve to a
    private address is the proxy's ACL to enforce — literal addresses are still
    refused either way, because the proxy will CONNECT to whatever it is named.
    """
    raw = (url or "").strip()
    try:
        parsed = urlparse(raw)
    except ValueError:
        return "unparseable URL"
    if parsed.scheme not in ("http", "https"):
        return f"unsupported scheme: {parsed.scheme!r} (http/https only)"
    if not parsed.netloc:
        return "missing hostname"
    try:
        hostname = parsed.hostname
    except ValueError:
        # A bracketed netloc that is not an IP literal. Neither view can say
        # where this goes, and "nobody could tell" is not permission.
        return "blocked host: cannot be parsed"
    if _is_blocked_host(hostname or "", resolve=not _proxy_dials_for(raw)):
        return f"blocked host: {parsed.hostname}"
    return None


def validate_hop(previous_url: str, next_url: str) -> str | None:
    """Why this redirect must not be taken, or None.

    Everything `validate_fetch_url` refuses, plus the one rule that only exists
    between two URLs: **https must not become http.**

    That rule is here rather than in `validate_fetch_url` because it is not a
    property of the destination — `http://example.com/` is a perfectly ordinary
    URL for a caller to ask for, and this tool still fetches it. It stops being
    ordinary when the caller asked for `https://` and the *responder* chose the
    downgrade, which is the same asymmetry the whole redirect check is about:
    the first URL comes from the operator's agent, every hop after it comes
    from whatever answered. A downgrade hands the rest of the chain, and the
    body that a model is about to read, to anyone on the path — including the
    right to redirect it again.

    The cost of refusing is close to nothing: canonical redirects run the other
    way (http -> https), which stays allowed, as does http -> http, where the
    caller already chose plaintext with their eyes open.
    """
    err = validate_fetch_url(next_url)
    if err:
        return err
    try:
        was = (urlparse(previous_url).scheme or "").lower()
        now = (urlparse(next_url).scheme or "").lower()
    except ValueError:
        return "unparseable URL"
    if was == "https" and now != "https":
        return f"refusing https -> {now} downgrade"
    return None


class RefusedFetch(Exception):
    """The URL, or a hop in its redirect chain, failed the destination check."""


def _read_capped(resp, max_bytes: int) -> bytes:
    """At most `max_bytes` of the body, and the response closed either way.

    `max_bytes` used to bound nothing at all. `requests.get` without
    `stream=True` reads the entire body inside `Session.send`, so by the time
    `resp.content[:max_bytes]` ran the whole thing was already in memory —
    measured at 50MB against a 512_000-byte cap. Streaming and stopping is the
    only version of that limit that is a limit.

    The `close()` is in a `finally` because this is also where the final
    response gets released. Intermediate responses were closed in the hop loop
    and the one whose body is actually read was not, so a fetch that ended in an
    external-guard block, or in a decode error, held its connection until the
    collector got to it.
    """
    chunks: list[bytes] = []
    total = 0
    try:
        for chunk in resp.iter_content(chunk_size=_CHUNK_BYTES):
            if not chunk:  # keep-alive padding
                continue
            chunks.append(chunk)
            total += len(chunk)
            if total >= max_bytes:
                break
    finally:
        resp.close()
    return b"".join(chunks)[:max_bytes]


def _method_after(method: str, code: int) -> str:
    """The method `requests` itself would use on the next hop.

    Mirrors `Session.rebuild_method`. It matters because this module now carries
    a POST (the search scrape) as well as GETs: replaying a POST body at a 302
    target would be both wrong and, for a redirect chosen by the responder, a
    way to get the caller's form data delivered somewhere it never addressed.
    """
    m = (method or "GET").upper()
    if code in (302, 303) and m != "HEAD":
        return "GET"
    if code == 301 and m == "POST":
        return "GET"
    return m


def _no_redirect_session(requests):
    """A `requests.Session` that will not compute a redirect target.

    `allow_redirects=False` stops the chain being *followed*. It does not stop
    `Session.send` from calling `resolve_redirects(..., yield_requests=True)` to
    fill in `Response._next` — and the first thing that generator does is
    `resp.content`, commented "Consume socket so it can be released". So the
    body of a 3xx is read in full even under `stream=True`, for a hop nobody was
    ever going to take: measured, 50MB resident from one redirect. Yielding
    nothing removes the only reason that read happens.

    It also means this session cannot follow a redirect even if a future caller
    passes `allow_redirects=True` — the transport has no redirect machinery
    left. That is the property this module wants pinned at the transport, not
    just requested at the call site.

    The class is built per call rather than cached: it is a few microseconds in
    front of an HTTP request, and a module-level cache would have to be keyed on
    a `Session` class the caller owns (the test transports each supply their
    own) and would outlive it.
    """
    class _NoRedirectSession(requests.Session):
        def resolve_redirects(self, *args, **kwargs):
            return iter(())

    return _NoRedirectSession()


def _request_checking_every_hop(session, method: str, url: str, *,
                                timeout: float, headers=None, data=None):
    """Follow the redirect chain by hand, validating each hop before taking it.

    `allow_redirects=True` follows the chain inside `requests.get`, where no
    check of ours runs — so the destination guard applied only to the first URL,
    the one hop nobody else chooses. An upstream returning
    `Location: https://169.254.169.254/latest/meta-data/` was followed, and the
    body came back through the tool.

    Returns `(final_response, [urls followed])`. Intermediate responses are
    closed rather than left to the collector, since only their headers are read;
    with `stream=True` that now also means their bodies are never pulled off the
    socket at all.
    """
    hdrs = {"User-Agent": _USER_AGENT}
    if headers:
        hdrs.update(headers)
    current, current_method, current_data = url, (method or "GET").upper(), data
    followed: list[str] = []
    for _ in range(_MAX_REDIRECTS + 1):
        resp = session.request(current_method, current, headers=hdrs,
                               data=current_data, timeout=timeout,
                               allow_redirects=False, stream=True)
        location = (resp.headers.get("Location") if resp.status_code
                    in _REDIRECT_CODES else None)
        if not location:
            return resp, followed
        resp.close()
        # Relative Locations are the common case and are resolved against the
        # URL that issued them, exactly as requests would.
        nxt = urljoin(current, location)
        err = validate_hop(current, nxt)
        if err:
            raise RefusedFetch(
                f"refusing redirect from {current} — {err}")
        nxt_method = _method_after(current_method, resp.status_code)
        followed.append(nxt)
        current, current_data = nxt, (current_data if nxt_method == current_method
                                      else None)
        current_method = nxt_method
    raise RefusedFetch(
        f"more than {_MAX_REDIRECTS} redirects starting at {url}")


def _fetch_validated(url: str, *, method: str = "GET", data=None, headers=None,
                     timeout: float = 20.0, max_bytes: int = _DEFAULT_MAX_BYTES):
    """`fetch_guarded` for a first URL that has already passed the guard.

    One session for the whole chain, closed once the body has been read — so
    the pooled connection is released on the refusal and error paths too, and
    hops to the same host reuse it.
    """
    requests = _require_requests()
    session = _no_redirect_session(requests)
    try:
        resp, followed = _request_checking_every_hop(
            session, method, url, timeout=timeout, headers=headers, data=data)
        return resp, _read_capped(resp, max_bytes), followed
    finally:
        session.close()


def fetch_guarded(url: str, *, method: str = "GET", data=None, headers=None,
                  timeout: float = 20.0, max_bytes: int = _DEFAULT_MAX_BYTES):
    """The one guarded egress path behind the `web_read` grant.

    Destination check on the first URL and on every redirect hop, redirects
    never followed by the transport, body capped, response closed.

    Returns `(response, body_bytes, [urls followed])`. The response comes back
    already read and closed, so `.content` is gone; `.status_code`, `.headers`,
    `.encoding` and `.url` are not. Raises `RefusedFetch` when the first URL or
    any hop is refused, and `requests.RequestException` for transport failures.

    `web_search` and `mai/parser` call this rather than reaching for `requests`
    or `urllib` themselves. Each of them used to have its own idea of what a
    forbidden destination was, and the weakest of the three set the ceiling for
    a permission line all of them sit on.
    """
    err = validate_fetch_url(url)
    if err:
        raise RefusedFetch(err)
    return _fetch_validated(url, method=method, data=data, headers=headers,
                            timeout=timeout, max_bytes=max_bytes)


def fetch_url(
    url: str,
    *,
    wrap: bool = True,
    max_bytes: int = _DEFAULT_MAX_BYTES,
    max_chars: int = _DEFAULT_MAX_CHARS,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """Fetch URL body with size limits, guard scan, optional sandwich wrap.

    `max_bytes` bounds what is read off the socket, not just what is kept —
    see `_read_capped`. `max_chars` still bounds the decoded text afterwards.
    """
    from . import external_guard

    err = validate_fetch_url(url)
    if err:
        return {"ok": False, "url": url, "error": err}

    requests = _require_requests()
    try:
        resp, raw, redirects = _fetch_validated(url, timeout=timeout,
                                                max_bytes=max_bytes)
    except RefusedFetch as exc:
        log.warning("fetch refused %s: %s", url, exc)
        return {"ok": False, "url": url, "error": str(exc)}
    except requests.RequestException as exc:
        log.warning("fetch failed %s: %s", url, exc)
        return {"ok": False, "url": url, "error": str(exc)}

    charset = resp.encoding or "utf-8"
    try:
        text = raw.decode(charset, errors="replace")
    except Exception:
        text = raw.decode("utf-8", errors="replace")

    content_type = (resp.headers.get("Content-Type") or "").lower()
    if "html" in content_type or text.lstrip().startswith("<"):
        text = _strip_html(text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_chars:
        text = text[:max_chars] + "…"

    hits = external_guard.scan(text)
    guard = external_guard.verdict(hits)
    if guard == "BLOCKED":
        label = hits[0]["label"] if hits else "injection pattern"
        return {
            "ok": False,
            "url": url,
            "status_code": resp.status_code,
            "guard": guard,
            "guard_hits": hits,
            "error": f"external-guard BLOCKED: {label}",
        }

    body = external_guard.SANDWICH_TEMPLATE.format(content=text) if wrap else text
    return {
        "ok": True,
        "url": url,
        "final_url": str(resp.url),
        # The chain, so a caller can see where the content actually came from.
        # Previously requests followed it silently and only `final_url` hinted.
        "redirects": redirects,
        "status_code": resp.status_code,
        "content_type": content_type,
        "guard": guard,
        "guard_hits": hits,
        "chars": len(text),
        "content": body,
        "wrapped": wrap,
    }
