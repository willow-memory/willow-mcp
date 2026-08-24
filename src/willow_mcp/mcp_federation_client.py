"""The federated MCP client: outbound stdio sessions to ratified downstream
servers.

Complements `signing.py` rather than duplicating it — that module is the
harness a caller of *this* server embeds; this module is what *this server*
embeds to call others. The only other `ClientSession` construction anywhere
in `src/` before this file was `SigningClientSession`, which wraps a session
it does not itself own. This module owns the session.

One `_ServerConnection` per ratified `server_id`: its own asyncio event loop
on its own daemon thread, so one downstream server's slow or hung tool call
can never stall another server's connection or the rest of this (synchronous)
process — the same isolation a per-app egress lease gives identities, applied
here to downstream processes. `list_tools()` is cached eagerly at connect
time (capability aggregation: this is how an orchestrator would answer "what
can I reach across the fleet" without a round trip per server), and both the
cached listing and every call result are run through `external_guard` before
they reach a caller — Decision 4(c): a downstream server's tool names and
descriptions are untrusted input that arrives *before* any output does, so
listings are scanned at listing time, not only results at call time.

Every public function here takes `server_id` and re-derives the connection
from the ratified registry rather than trusting a value cached at connect
time — mirrors `web_fetch.validate_hop` re-validating every redirect instead
of the first resolution (Decision 5).
"""
from __future__ import annotations

import asyncio
import logging
import queue
import threading
import time
from concurrent import futures
from contextlib import asynccontextmanager
from typing import Any, Optional

import httpx2 as httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

from . import external_guard, mcp_federation, signing, tier_policy

logger = logging.getLogger("willow_mcp.mcp_federation_client")

#: How long a single stdio round trip (connect, list_tools, or one call_tool)
#: may take before this side gives up on it. A hung child must not hang the
#: calling tool forever.
CALL_TIMEOUT_SECONDS = 30.0
#: How long to wait for a freshly-started thread to publish its event loop.
_LOOP_START_TIMEOUT_SECONDS = 5.0
#: TCP connect budget for a remote peer — short, because an unreachable host
#: should fail fast rather than hold a federation slot for the call timeout.
_HTTP_CONNECT_TIMEOUT_SECONDS = 10.0


class FederationClientError(Exception):
    """A connect/call failure that is this module's to report, distinct from
    a gate denial (which is a dict, not an exception — see server.py's
    _guarded convention) and from an MCP protocol error (which the SDK itself
    raises and this module lets propagate)."""


def _unwrap(exc: BaseException) -> BaseException:
    """Peel single-exception ExceptionGroups.

    anyio wraps whatever escapes `stdio_client` / `ClientSession` in a
    TaskGroup's ExceptionGroup, so the error a caller of `connect_server` sees
    is a group whose only member is the real cause — un-catchable by type, which
    matters now that a signed link raises a specific, catchable failure. Only
    single-member groups are peeled: a genuine multi-error group is information,
    not noise.
    """
    while isinstance(exc, BaseExceptionGroup) and len(exc.exceptions) == 1:
        exc = exc.exceptions[0]
    return exc


def _scan_text(text: str) -> tuple[str, list[dict]]:
    hits = external_guard.scan(text or "")
    return external_guard.verdict(hits), hits


def _guard_tool_listing(tools: list[Any]) -> list[dict]:
    """Scan every tool's name + description before it ever reaches a caller's
    context — Decision 4(c). A BLOCKED listing entry keeps its `name` (a
    caller must still be able to name what it is refusing) but its
    description is replaced by the sandwich wrap around the flagged text,
    never spliced in verbatim."""
    guarded: list[dict] = []
    for t in tools:
        name = getattr(t, "name", "")
        description = getattr(t, "description", "") or ""
        verdict, hits = _scan_text(f"{name} {description}")
        entry = {
            "name": name,
            "description": description,
            "input_schema": getattr(t, "inputSchema", None),
            "guard_verdict": verdict,
            "guard_hits": hits,
        }
        if verdict == "BLOCKED":
            entry["description"] = external_guard.SANDWICH_TEMPLATE.format(content=description)
        guarded.append(entry)
    return guarded


class _ServerConnection:
    """One downstream server's live stdio session, isolated on its own loop
    and thread. Not constructed directly by callers — see `_get_connection`.
    """

    def __init__(self, server_id: str, entry: dict[str, Any]):
        self.server_id = server_id
        self.entry = entry
        self._thread: Optional[threading.Thread] = None
        self._tools_cache: list[dict] = []
        self.connected_at: Optional[float] = None
        # Thread-safe handoff between the calling (sync) thread and this
        # connection's dedicated asyncio task. `_requests` carries
        # (kind, payload, reply_future) tuples; `concurrent.futures.Future`
        # (NOT asyncio.Future) is the reply channel because it is the one
        # future type safe to touch from both sides of the thread boundary.
        self._requests: "queue.Queue[tuple[str, Any, futures.Future]]" = queue.Queue()
        self._ready = threading.Event()
        self._ready_error: Optional[BaseException] = None
        # Outbound willow-gate binding. `_signer` is None for an unsigned link,
        # which is the default and the pre-existing behaviour. `_tools_called`
        # feeds the check-out declaration at disconnect; it is only touched from
        # this connection's own task, so it needs no lock.
        self._signer: Optional[signing.ClientSigner] = None
        self._signing_secret: Optional[bytes] = None
        self._tools_called: set[str] = set()
        self._start_lock = threading.Lock()

    # -- lifecycle: ONE task owns connect, every call, and disconnect ----
    #
    # anyio's cancel scopes (which stdio_client / ClientSession use
    # internally) are tied to the asyncio Task that entered them — exiting
    # from a *different* task raises "Attempted to exit cancel scope in a
    # different task than it was entered in". Submitting `_connect_async`
    # and `_disconnect_async` as two separate `run_coroutine_threadsafe`
    # calls (even to the same loop) creates two different Tasks and hits
    # exactly that. So: one coroutine, one Task, running for the whole
    # connection's life, fed a queue of requests and replying through
    # thread-safe futures — the standard shape for owning an anyio resource
    # from a background thread.
    def _run(self) -> None:
        try:
            asyncio.run(self._main())
        except Exception as e:  # pragma: no cover - asyncio.run's own failure
            self._ready_error = e
            self._ready.set()

    @asynccontextmanager
    async def _transport(self, spec: "mcp_federation.McpServerSpec"):
        """The read/write stream pair for this entry's transport.

        Both `stdio_client` and `streamable_http_client` yield `(read, write)`,
        so the only real difference is what has to be true before dialling.
        """
        if spec.transport == "stdio":
            params = StdioServerParameters(
                command=spec.command, args=list(spec.args),
                env=mcp_federation.load_server_env(self.entry), cwd=spec.cwd,
            )
            async with stdio_client(params) as streams:
                yield streams
            return

        if not mcp_federation.is_http_transport(spec.transport):
            raise FederationClientError(
                f"server {self.server_id!r}: transport {spec.transport!r} is not "
                f"supported (stdio or one of {mcp_federation.HTTP_TRANSPORTS})")

        # Re-validated HERE, not only at ratification. The registry records a URL;
        # DNS decides where a name points, and it can be re-pointed at loopback or
        # cloud metadata long after an operator ratified a public host. Same rule
        # federation_egress applies to its own locks: read the fact at call time,
        # never trust a decision cached at connect.
        err = mcp_federation.validate_remote_url(self.entry)
        if err:
            raise FederationClientError(
                f"server {self.server_id!r}: refusing to dial — {err}")

        url = str(self.entry.get("url") or "").strip()
        http_client = create_mcp_http_client(
            headers=mcp_federation.load_auth_headers(self.entry) or None,
            timeout=httpx.Timeout(CALL_TIMEOUT_SECONDS, connect=_HTTP_CONNECT_TIMEOUT_SECONDS),
        )
        async with http_client:
            async with streamable_http_client(url, http_client=http_client) as streams:
                # TransportStreams is a 2-tuple like stdio's yield; a third
                # element (the session-id callback) is not part of this SDK's
                # shape, so unpack defensively rather than by fixed arity.
                yield (streams[0], streams[1])

    async def _main(self) -> None:
        loop = asyncio.get_running_loop()
        spec = mcp_federation.McpServerSpec.from_dict(self.entry)
        # Resolve the signing identity BEFORE spawning anything. A link that
        # cannot sign must not reach the point of starting a child process it
        # would then have to tear down — and a config error raised out here is a
        # plain exception, not one anyio has wrapped in a TaskGroup group.
        try:
            self._signing_secret = (
                mcp_federation.load_signing_secret(self.entry)
                if mcp_federation.signing_config(self.entry) is not None else None)
        except mcp_federation.SigningConfigError as e:
            self._ready_error = e
            self._ready.set()
            return
        try:
            async with self._transport(spec) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    await self._bind_if_signed(session)
                    listing = await session.list_tools()
                    self._tools_cache = _guard_tool_listing(listing.tools)
                    self._ready.set()
                    await self._serve_requests(loop, session)
        except Exception as e:
            if not self._ready.is_set():
                self._ready_error = _unwrap(e)
                self._ready.set()
            else:
                logger.warning("mcp_federation_client: %s: session ended with "
                               "an error", self.server_id, exc_info=True)

    async def _bind_if_signed(self, session: ClientSession) -> None:
        """Check in to a downstream that enforces willow-gate binding, arming the
        per-call signer. No-op for an unsigned link.

        What this buys, stated plainly so it is not over-read: when the downstream
        is another willow-mcp with `WILLOW_MCP_ENFORCE_BINDING=1`, our calls arrive
        as a *bound identity at a declared tier* rather than as a bare `app_id`
        string — so the downstream's tier ceiling applies to us, its receipt log
        attributes our calls, and check-out reconciles what we declared against
        what its own log says we did. Against a downstream we spawn ourselves it is
        least-privilege and audit, not authentication: we already chose that
        process's binary and environment. It becomes authentication the day the
        transport reaches a peer this process did not start.

        Fail-closed: a link that asks to sign and cannot — missing secret, refused
        header, a downstream with no `session_bind` — raises rather than silently
        connecting unsigned. Downgrading here would defeat the point of asking.
        """
        cfg = mcp_federation.signing_config(self.entry)
        if cfg is None:
            return
        secret = self._signing_secret
        if secret is None:  # pragma: no cover - _main resolves this first
            raise FederationClientError(
                f"server {self.server_id!r}: signing configured but no secret resolved")
        # Declare the classes we could exercise at this tier. The downstream caps
        # the claim at our registered ceiling, so claiming is not granting.
        declared = sorted(tier_policy.classes_for_tier(cfg["trust_level"]))
        header = signing.build_checkin_header(
            secret, cfg["agent_id"], cfg["trust_level"], tools=declared)
        result = await session.call_tool(
            "session_bind", {"app_id": cfg["agent_id"], "header": header})
        data = signing._result_dict(result)
        if "error" in data or "session_id" not in data:
            raise FederationClientError(
                f"server {self.server_id!r}: signed link refused at check-in as "
                f"{cfg['agent_id']!r}: {data.get('error') or data or 'no result'}")
        self._signer = signing.ClientSigner(cfg["agent_id"], secret, data["session_id"])
        logger.info("mcp_federation_client: %s: bound as %s (tier %s, session %s…)",
                    self.server_id, cfg["agent_id"], cfg["trust_level"],
                    str(data["session_id"])[:8])

    async def _reconcile_if_signed(self, session: ClientSession) -> None:
        """Check out of a signed link, declaring the classes we actually called.

        Best-effort by design: we are shutting down either way, and a downstream
        that has already dropped the session must not turn teardown into an error.
        Worth doing rather than skipping — check-out is what frees the session's
        single-use nonce set downstream, so a long-lived federation link that never
        checks out grows that set for the life of the downstream process.
        """
        if self._signer is None:
            return
        used = sorted({tier_policy.classify(t) or "read" for t in self._tools_called})
        try:
            await session.call_tool(
                "session_reconcile",
                {"app_id": self._signer.agent_id,
                 "exit_declaration": {"tools": used, "pass_count": 0, "fail_count": 0,
                                      "drift": 0, "state_hash": ""}},
                meta=self._signer.meta_for("session_reconcile"))
        except Exception:
            logger.warning("mcp_federation_client: %s: check-out failed; the "
                           "downstream will drop the session on its own",
                           self.server_id, exc_info=True)
        finally:
            self._signer = None

    async def _serve_requests(self, loop: asyncio.AbstractEventLoop, session: ClientSession) -> None:
        """Drain `_requests` until a `shutdown` arrives. The blocking
        `Queue.get` runs in the default executor so it never blocks this
        task's own event loop — the stdio transport's background read task
        shares that loop and must keep running while we wait."""
        while True:
            kind, payload, reply = await loop.run_in_executor(None, self._requests.get)
            if kind == "shutdown":
                await self._reconcile_if_signed(session)
                reply.set_result(None)
                return
            try:
                if kind == "call":
                    tool, arguments = payload
                    if self._signer is not None:
                        # The credential rides `_meta`, out of band — the tool's own
                        # arguments are untouched, so a signed link and an unsigned
                        # one send identical `arguments` for the same call.
                        self._tools_called.add(tool)
                        reply.set_result(await session.call_tool(
                            tool, arguments, meta=self._signer.meta_for(tool)))
                    else:
                        reply.set_result(await session.call_tool(tool, arguments))
                elif kind == "list_tools":
                    listing = await session.list_tools()
                    self._tools_cache = _guard_tool_listing(listing.tools)
                    reply.set_result(self._tools_cache)
                else:  # pragma: no cover - internal misuse only
                    reply.set_exception(FederationClientError(f"unknown request {kind!r}"))
            except Exception as e:
                reply.set_exception(e)

    def _ensure_started(self) -> None:
        with self._start_lock:
            if self._thread is not None:
                if self._ready_error is not None:
                    raise self._ready_error
                return
            self._thread = threading.Thread(
                target=self._run, name=f"mcp-fed-{self.server_id}", daemon=True,
            )
            self._thread.start()
            if not self._ready.wait(timeout=_LOOP_START_TIMEOUT_SECONDS):
                raise FederationClientError(
                    f"server {self.server_id!r}: did not become ready in "
                    f"{_LOOP_START_TIMEOUT_SECONDS}s")
            if self._ready_error is not None:
                raise self._ready_error
            self.connected_at = time.time()

    def _request(self, kind: str, payload: Any, timeout: float = CALL_TIMEOUT_SECONDS) -> Any:
        self._ensure_started()
        reply: futures.Future = futures.Future()
        self._requests.put((kind, payload, reply))
        return reply.result(timeout=timeout)

    # -- sync-facing API --------------------------------------------------
    def connect(self) -> list[dict]:
        self._ensure_started()
        return self._tools_cache

    def list_tools(self, *, refresh: bool = False) -> list[dict]:
        if refresh:
            return self._request("list_tools", None)
        self._ensure_started()
        return self._tools_cache

    def call_tool(self, tool: str, arguments: dict[str, Any]) -> dict:
        result = self._request("call", (tool, arguments))
        text = "".join(
            getattr(block, "text", "") or "" for block in (result.content or [])
        )
        verdict, hits = _scan_text(text)
        content_text = text
        if verdict == "BLOCKED":
            content_text = external_guard.SANDWICH_TEMPLATE.format(content=text)
        return {
            "is_error": bool(getattr(result, "isError", False)),
            "content_text": content_text,
            "guard_verdict": verdict,
            "guard_hits": hits,
        }

    def disconnect(self) -> None:
        if self._thread is None:
            return
        try:
            self._request("shutdown", None, timeout=CALL_TIMEOUT_SECONDS)
        except Exception:
            logger.warning("mcp_federation_client: %s: shutdown request failed",
                           self.server_id, exc_info=True)
        self._thread.join(timeout=CALL_TIMEOUT_SECONDS)
        self._thread = None
        self._ready = threading.Event()
        self._ready_error = None


_connections: dict[str, _ServerConnection] = {}
_registry_lock = threading.Lock()


def _get_connection(server_id: str) -> _ServerConnection:
    """Resolve (or start) this server's connection. Re-reads the ratified
    registry every time rather than trusting a value cached at first connect
    — a server ratified once and later revoked must not keep answering calls
    through a stale in-memory entry (Decision 5)."""
    entry = mcp_federation.get_ratified(server_id)
    if entry is None:
        raise FederationClientError(
            f"server {server_id!r} is not (or is no longer) in the ratified "
            "registry — a live connection does not outlive ratification")
    with _registry_lock:
        conn = _connections.get(server_id)
        if conn is None:
            conn = _ServerConnection(server_id, entry)
            _connections[server_id] = conn
        else:
            conn.entry = entry
        return conn


def connect_server(server_id: str) -> list[dict]:
    """Connect (or reuse an existing connection) and return the guarded tool
    listing."""
    return _get_connection(server_id).connect()


def list_server_tools(server_id: str, *, refresh: bool = False) -> list[dict]:
    """The cached (or freshly connected) guarded tool listing for one
    server."""
    return _get_connection(server_id).list_tools(refresh=refresh)


def call_tool(server_id: str, tool: str, arguments: Optional[dict[str, Any]] = None) -> dict:
    """Call one tool on one connected-or-connecting server. Callers are
    expected to have already cleared `federation_egress.egress_denial` —
    this module has no gate of its own, exactly as `mcp_generic.py`'s
    upstream ancestor did not: connection-layer code is not where
    authorization decisions belong."""
    return _get_connection(server_id).call_tool(tool, dict(arguments or {}))


def disconnect_server(server_id: str) -> bool:
    with _registry_lock:
        conn = _connections.pop(server_id, None)
    if conn is None:
        return False
    conn.disconnect()
    return True


def shutdown_all() -> None:
    """Disconnect every live connection — process teardown / test cleanup."""
    with _registry_lock:
        conns = list(_connections.values())
        _connections.clear()
    for conn in conns:
        conn.disconnect()
