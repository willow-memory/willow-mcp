"""The per-request context handle that replaced the SDK's removed contextvar.

SDK 2.0 deleted `mcp.server.lowlevel.server.request_ctx` and injects `Context`
into tool functions instead — an injection that does not reach `_guarded`, which
wraps 119 tools and reads the per-call credential in the wrapper. So
`request_context` republishes the `ServerRequestContext` on a ContextVar we own,
fed by a `ServerMiddleware`.

The defect being guarded against is specific and has already happened once: the
old code read a PRIVATE SDK symbol under a blanket `except`, so when the SDK
moved it the failure was silent and looked exactly like "no client is signing
yet". These tests pin the properties that make the replacement not-that —
above all that "no request in progress" and "the credential is missing" stay
distinguishable from each other, and neither is an error.
"""
from __future__ import annotations

import asyncio
import types

import pytest

from willow_mcp import request_context


def _ctx(meta):
    return types.SimpleNamespace(meta=meta)


def test_no_context_outside_a_request():
    """Not "unknown", not an exception — None, meaning no request in progress.

    A CLI invocation and a test calling a tool directly both land here, and both
    are legitimate. This is the one case where absence really is the answer.
    """
    assert request_context.current() is None
    assert request_context.current_meta() is None


def test_active_binds_and_restores():
    with request_context.active(_ctx({"k": "v"})):
        assert request_context.current_meta() == {"k": "v"}
    assert request_context.current() is None


def test_active_restores_the_previous_value_not_none():
    """Reset, not clear. Nesting must restore the OUTER context, because
    contextvars are per-task and a naive `set(None)` teardown would silently
    unbind a request that is still in flight."""
    with request_context.active(_ctx({"outer": True})):
        with request_context.active(_ctx({"inner": True})):
            assert request_context.current_meta() == {"inner": True}
        assert request_context.current_meta() == {"outer": True}


def test_active_restores_even_when_the_body_raises():
    with pytest.raises(RuntimeError):
        with request_context.active(_ctx({"k": "v"})):
            raise RuntimeError("handler blew up")
    assert request_context.current() is None, "a failed request left its context bound"


def test_meta_is_none_when_the_context_carries_none():
    """A request with no `_meta` is a request, not an absent one. `current()`
    must still report the context so a caller can tell the two apart."""
    with request_context.active(_ctx(None)):
        assert request_context.current() is not None
        assert request_context.current_meta() is None


def test_middleware_binds_for_the_duration_of_the_call():
    seen = {}

    async def handler(ctx):
        seen["meta"] = request_context.current_meta()
        return "result"

    mw = request_context.RequestContextMiddleware()
    out = asyncio.run(mw(_ctx({"cred": 1}), handler))

    assert out == "result", "middleware must return the handler's result unchanged"
    assert seen["meta"] == {"cred": 1}
    assert request_context.current() is None, "middleware leaked the context"


def test_middleware_unbinds_when_the_handler_raises():
    """A denial raised deeper in the chain still has to unwind cleanly, or the
    next request on this task inherits a stale context."""

    async def handler(ctx):
        raise ValueError("denied")

    mw = request_context.RequestContextMiddleware()
    with pytest.raises(ValueError):
        asyncio.run(mw(_ctx({"cred": 1}), handler))
    assert request_context.current() is None


def test_concurrent_tasks_do_not_see_each_others_context():
    """The property a module-level global would fail. Two requests in flight on
    one event loop must each read their own `_meta`."""
    order = []

    async def one(tag, delay):
        async def handler(ctx):
            await asyncio.sleep(delay)
            order.append((tag, request_context.current_meta()))
            return tag

        return await request_context.RequestContextMiddleware()(_ctx({"tag": tag}), handler)

    async def main():
        return await asyncio.gather(one("a", 0.02), one("b", 0.0))

    asyncio.run(main())
    assert dict(order) == {"a": {"tag": "a"}, "b": {"tag": "b"}}


def test_credential_reaches_read_call_credential_through_the_middleware():
    """End to end on the real path: the middleware publishes, and the reader in
    `server` finds the credential without any SDK contextvar existing."""
    from willow_mcp import server

    cred = {"session_id": "S1", "call_nonce": "N1", "sig": "deadbeef"}

    assert server._read_call_credential() is None
    with request_context.active(_ctx({server.CREDENTIAL_META_KEY: cred})):
        assert server._read_call_credential() == cred
    assert server._read_call_credential() is None


def test_malformed_credential_reads_as_absent_not_as_an_error():
    from willow_mcp import server

    for bad in ({"session_id": "S1"}, "not-a-dict", None, {}):
        with request_context.active(_ctx({server.CREDENTIAL_META_KEY: bad})):
            assert server._read_call_credential() is None, bad
