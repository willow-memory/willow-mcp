"""486CDA98/7D8096B0: a DETERMINISTIC proof that the autouse rate-limit
reset (`server.reset_rate_limits()`, called from `conftest.py`'s
`_reset_rate_limits` fixture) actually isolates tests from each other --
no real subprocess, no network, no sleep, no dependence on wall-clock
timing at all.

Test A drains a named app's bucket directly, by calling
`server._check_rate` enough times to exhaust it (burst is 10; 20 calls
is a comfortable margin regardless of how much real time the calls
themselves take). Test B, which pytest runs immediately after A within
this same file (module-level definition order), asserts that the SAME
app's bucket starts full. With the autouse reset in place, the fixture
clears `server._buckets` before B's body ever runs, so B always sees a
fresh (or absent, which is equivalent -- a fresh bucket is created on
first use) bucket regardless of what A did. With the reset REMOVED, A's
drained bucket is still sitting in `server._buckets` when B runs, and B
fails -- deterministically, not "usually" or "on unlucky timing".

This is the class-level proof the earlier 20-run federation reproduction
could not be: that run was inconclusive because the flake it was chasing
is CI-timing-dependent and did not reproduce locally either with or
without the fix. This file needs no such luck.
"""
from __future__ import annotations

from willow_mcp import server

_APP = "rate-bucket-isolation-proof"


def test_a_drains_the_bucket_directly():
    """No subprocess, no network, no sleep -- just enough direct calls
    to `_check_rate` to exhaust the burst capacity (10) for `_APP`."""
    for _ in range(20):
        server._check_rate(_APP)
    bucket = server._buckets.get(_APP)
    assert bucket is not None, "the bucket must exist after being used"
    assert bucket.tokens < 1.0, (
        f"expected the bucket to be drained below 1 token, got {bucket.tokens}"
    )


def test_b_bucket_starts_full():
    """Runs immediately after A, in the same pytest session. With the
    autouse `_reset_rate_limits` fixture in place, `_APP`'s bucket must
    start FULL (or simply absent, which is the same guarantee -- a fresh
    bucket is created at full burst on first use) regardless of what A
    left behind. Removing the reset makes this fail every single time,
    with zero timing involved: A's drained bucket is still there."""
    bucket = server._buckets.get(_APP)
    assert bucket is None or bucket.tokens >= server._BURST, (
        f"the bucket must start full (or absent) for test isolation to "
        f"hold -- got tokens={getattr(bucket, 'tokens', None)!r}, "
        f"which means test A's drain leaked into this test"
    )
