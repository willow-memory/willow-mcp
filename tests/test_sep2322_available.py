"""The SDK this build resolved must actually carry SEP-2322.

`pyproject.toml` declares `mcp>=2.0.0,<3.0.0`, and CI installs with
`pip install -e ".[test]"` — so the mcp version a run gets is whatever pip
resolves inside that range, not a pinned one.

`egress_pause` needs SEP-2322's types (`InputRequiredResult` and the
`ElicitRequest` form params it carries). It imports them *inside* the function
and returns None on any exception, which is deliberate — pausing is an
enhancement over denying, and an enhancement that breaks must fall back rather
than take the denial down with it.

That fail-safe is what this file exists to watch. In PRODUCTION a too-old SDK
is completely silent: `pause_for_lease` catches the ImportError, returns None,
and every call degrades to a plain `lease_denied` — correct, secure, and
invisible. The pause feature simply stops existing, and the first anyone knows
of it is an operator wondering why calls no longer wait for them.

To be accurate about what this adds: the suite is NOT silent on that. The
positive cases in `test_egress_pause.py` construct a real pause and fail too
(measured: 5 failures when the SEP-2322 import is made to raise). So this file
is not the only thing standing between a bad resolution and a green build.

What it adds is a failure that names its own cause. A dependency-resolution
problem surfacing as a handful of assertion errors inside the feature's own
tests reads like the feature is broken; the fix is in `pyproject.toml`, which
is not where that failure points. These tests say so directly.

The floor in `pyproject.toml` is the better fix and is deliberately not
guessed at here: establishing which 2.x first shipped these types needs a
networked machine to install and check, and a floor invented without that
would be a pin nobody had verified. This test holds the property in the
meantime, and keeps holding it afterwards.
"""
from __future__ import annotations

import pytest

#: What `egress_pause` imports, and the module path it imports them from.
REQUIRED_TYPES = (
    "InputRequiredResult",
    "ElicitRequest",
    "ElicitRequestFormParams",
)


def test_the_resolved_sdk_carries_the_sep2322_types():
    import mcp_types

    missing = [n for n in REQUIRED_TYPES if not hasattr(mcp_types, n)]
    assert not missing, (
        f"the resolved mcp SDK is missing {missing} — SEP-2322 types that "
        f"willow_mcp.egress_pause needs. `pyproject.toml` allows "
        f"mcp>=2.0.0,<3.0.0 and this build resolved something too old. "
        f"In production egress_pause falls back to a plain denial silently, "
        f"so raise the floor in pyproject.toml to the version that ships "
        f"them — the fix is the dependency pin, not this test or the feature."
    )


def test_the_pause_path_is_reachable_not_merely_importable():
    """Stronger than an import check: build a real pause.

    `pause_for_lease` swallows every exception, so "the types import" and "the
    pause can actually be constructed" are different claims. A signature change
    inside the allowed version range would satisfy the first and fail the
    second, and would be just as silent in production.
    """
    from willow_mcp import egress_pause, request_context

    class _Session:
        def check_client_capability(self, _c):
            return True

    class _Ctx:
        session = _Session()
        params: dict = {}

    saved = request_context.current
    try:
        request_context.current = lambda: _Ctx()      # type: ignore[assignment]
        paused = egress_pause.pause_for_lease("kart", task_id="T1", request_id="R1")
    finally:
        request_context.current = saved              # type: ignore[assignment]

    assert paused is not None, (
        "egress_pause.pause_for_lease() returned None for a client that "
        "advertises elicitation — the pause path is broken and failing safe, "
        "which is silent by design. Check the SEP-2322 types against the "
        "resolved mcp SDK."
    )
    assert paused.request_state
    assert paused.input_requests


@pytest.mark.parametrize("name", REQUIRED_TYPES)
def test_each_required_type_is_named_individually(name):
    """One failure per missing type, so the report names them rather than
    making a reader diff two lists."""
    import mcp_types

    assert hasattr(mcp_types, name), f"mcp SDK is missing {name}"
