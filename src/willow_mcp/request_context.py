"""The per-request context, made reachable from code the SDK does not inject into.

SDK 1.x exposed an ambient `mcp.server.lowlevel.server.request_ctx` ContextVar,
and `server._read_call_credential()` read the signing client's out-of-band
`_meta` from it. SDK 2.0 removed that: the ambient request context is gone on
purpose, `Context` is injected into tool functions as a parameter, and the only
ContextVar left in the SDK is `auth_context_var` for OAuth.

That injection does not reach us. `_guarded` wraps 135 tools and the credential
check lives in the wrapper, not in any tool body — so "declare `ctx: Context`"
would mean editing 109 signatures to thread a value none of them use, and
rewriting the wrapper's `sig.bind` machinery around a parameter that must be
consumed rather than forwarded.

So this restores an ambient handle at OUR boundary, from a documented SDK
extension point rather than a private symbol. `ServerMiddleware` is
`(ctx, call_next) -> result`, runs at the top of every inbound request "after
`ctx` is built but before any validation, lookup, or handshake", and receives
the `ServerRequestContext` directly — the same object that carries `.meta`.

WHY THIS IS NOT THE OLD HACK AGAIN
----------------------------------
The thing that made the old code fragile was not the ContextVar. It was that the
ContextVar was *the SDK's private one*, read under a blanket `except`, so when
the SDK moved it the failure was silent and indistinguishable from "no client is
signing yet" — which is exactly what happened on 2.0.

This ContextVar is ours. The SDK cannot move it. The seam we depend on is
`ServerMiddleware`, which is public and documented, and if it ever changes the
middleware fails to register loudly at startup rather than degrading to a quiet
`None` at call time. `current_meta()` still returns `None` outside a request,
because "no request in progress" is a real answer and not a failure.
"""

from __future__ import annotations

import contextlib
import contextvars
import logging
import os
from typing import Any, Iterator, Optional

from . import advertise as _advertise

logger = logging.getLogger(__name__)

#: Set by `RequestContextMiddleware` for the duration of each inbound request.
#: `None` outside one — a CLI invocation, a test calling a tool directly, or
#: anything running before the transport is up.
_current: contextvars.ContextVar[Optional[Any]] = contextvars.ContextVar(
    "willow_mcp_request_context", default=None
)


@contextlib.contextmanager
def active(ctx: Any) -> Iterator[None]:
    """Bind `ctx` as the current request context for the duration of the block.

    The single binding primitive: the middleware uses it in production and tests
    use it to stand in for a request. Sharing one implementation is the point —
    a test that set the ContextVar itself would be exercising its own plumbing
    rather than the code path a real call takes.
    """
    token = _current.set(ctx)
    try:
        yield
    finally:
        # Reset rather than clear: concurrent requests each hold their own
        # token, and contextvars are per-task, so restoring the previous value
        # is the only correct teardown.
        _current.reset(token)


class RequestContextMiddleware:
    """Publish the per-request `ServerRequestContext` on a ContextVar we own.

    Registered outermost on `MCPServer(middleware=[...])`, so it wraps params
    validation and the handler call alike; a denial raised deeper still unwinds
    through the `finally` below.
    """

    async def __call__(self, ctx: Any, call_next: Any) -> Any:
        with active(ctx):
            return await call_next(ctx)


def _list_identity_app_id() -> Optional[str]:
    """App id that owns this ``tools/list`` response.

    Stdio: process ``WILLOW_APP_ID`` (one seat per MCP process).
    Serve: OAuth-bound identity via ``server._resolve_serve_identity``.
    Missing identity in serve mode → ``None`` (fail closed to empty list).
    """
    from . import server as _server

    if _server._serve_mode():
        bound, _err = _server._resolve_serve_identity()
        return bound
    return (os.environ.get("WILLOW_APP_ID") or "").strip() or None


def _filter_list_tools_result(result: Any, allowed: set[str]) -> Any:
    """Return ``result`` with ``tools`` filtered to ``allowed`` names."""
    if result is None:
        return result
    if isinstance(result, dict):
        tools = result.get("tools")
        if isinstance(tools, list):
            return {
                **result,
                "tools": _advertise.filter_tool_iterable(tools, allowed),
            }
        return result
    tools = getattr(result, "tools", None)
    if tools is None:
        return result
    filtered = _advertise.filter_tool_iterable(tools, allowed)
    model_copy = getattr(result, "model_copy", None)
    if callable(model_copy):
        return model_copy(update={"tools": filtered})
    try:
        result.tools = filtered  # type: ignore[attr-defined]
    except Exception:
        logger.exception("advertise: could not rewrite list_tools result in place")
    return result


class AdvertiseFilterMiddleware:
    """Shrink ``tools/list`` to the seat's advertised set (desk_core / ACL).

    Does not change call ACL — a permitted but non-advertised tool remains
    callable when named. See ``willow_mcp.advertise``.
    """

    async def __call__(self, ctx: Any, call_next: Any) -> Any:
        result = await call_next(ctx)
        method = getattr(ctx, "method", None)
        if method != "tools/list":
            return result
        from . import server as _server

        app_id = _list_identity_app_id()
        if not app_id:
            # Serve with no binding, or stdio with unset WILLOW_APP_ID:
            # advertise nothing rather than the full kitchen sink.
            logger.warning(
                "advertise: tools/list with no seat identity — returning empty list"
            )
            return _filter_list_tools_result(result, set())
        catalogue = _server._gate_tool_catalogue()
        names, mode = _advertise.advertised_tools(app_id, catalogue)
        if mode == "full":
            return result
        allowed = set(names)
        if mode == "manifest":
            # Keep ungated tools (registered but not in the gate catalogue).
            tools = getattr(result, "tools", None)
            if tools is None and isinstance(result, dict):
                tools = result.get("tools") or []
            for tool in tools or []:
                name = getattr(tool, "name", None)
                if name is None and isinstance(tool, dict):
                    name = tool.get("name")
                if name and name not in catalogue:
                    allowed.add(name)
        logger.debug(
            "advertise: tools/list app_id=%s mode=%s count=%d",
            app_id,
            mode,
            len(allowed),
        )
        return _filter_list_tools_result(result, allowed)


def current() -> Optional[Any]:
    """The `ServerRequestContext` for the request in flight, or None."""
    return _current.get()


def current_meta() -> Optional[Any]:
    """The inbound request's `_meta`, or None.

    `ServerRequestContext.meta` is `RequestParamsMeta | None` — the official
    carrier for out-of-band per-request data, and as of SEP-2575 the carrier for
    client info and capabilities on *every* request now that the initialize
    handshake is gone. The per-call credential rides here.
    """
    ctx = _current.get()
    return getattr(ctx, "meta", None) if ctx is not None else None
