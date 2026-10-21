"""Every clock helper in willow-mcp now asks the one script (flatten-2 F8; the
operator: "Using the onescript at every path."). With ``ONESCRIPT_NOW`` pinned,
each returns the pinned instant in its NAMED format, byte for byte what the
helper it replaced wrote (D-e: those strings are signed, mirrored and hashed).

``seconds_z`` is ``2026-10-20T12:00:00Z``; ``isoformat_utc`` keeps the
microseconds and ``+00:00``. With the one script absent a helper raises
``Unreachable`` naming ``ONESCRIPT_HOME``; it has no copy to fall back to.

Locally, with no willow-bot beside, these skip and say so; in CI (``CI`` is
set) they fail instead, because the CI checks willow-bot out for this.
"""

import importlib
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from willow_mcp import onescript_reach

PIN = "2026-10-20T12:00:00.123456Z"
SECONDS_Z = "2026-10-20T12:00:00Z"
ISO_UTC = "2026-10-20T12:00:00.123456+00:00"

SECONDS_Z_HELPERS = [
    ("willow_mcp.sign_session_cli", "_now_iso_z"),
    ("willow_mcp.enforcement_posture", "_utc_now"),
    ("willow_mcp.dispatch", "_utc_now"),
    ("willow_mcp.seed_kb", "_utc_now"),
    ("willow_mcp.seed_sign", "_utc_now"),
    ("willow_mcp.seed_mirror", "_utc_now"),
    ("willow_mcp.handoff", "_utc_now"),
    ("willow_mcp.kb_curate", "_utc_now"),
]
ISO_UTC_HELPERS = [
    ("willow_mcp.training_corpus", "_now_iso"),
    ("willow_mcp.kb_verify", "_now_iso"),
]


# Left on purpose: they run as root / the trust owner, from the root-owned venv,
# where a sibling checkout's code is never executed. Their bytes are pinned equal.
PRIVILEGED_LEFT = [
    ("willow_mcp.envelope_authoring", "_now_iso", SECONDS_Z),
    ("willow_mcp.install_steps.seed_envelope_ratify", "_now_iso", ISO_UTC),
    ("willow_mcp.manifest_grant_executor", "_now_iso", ISO_UTC),
]


@pytest.fixture(autouse=True)
def _one_script_or_say_why(monkeypatch):
    home = onescript_reach.where()["onescript"]
    if home is None or not (Path(home) / "onescript" / "clock.py").is_file():
        if os.environ.get("CI"):
            pytest.fail(f"CI has no willow-bot with a clock beside: {home}")
        pytest.skip(f"no willow-bot beside (set ONESCRIPT_HOME): {home}")
    monkeypatch.setenv("ONESCRIPT_NOW", PIN)


@pytest.mark.parametrize("mod,name", SECONDS_Z_HELPERS)
def test_seconds_z_helpers_return_the_pinned_instant(mod, name):
    assert getattr(importlib.import_module(mod), name)() == SECONDS_Z


@pytest.mark.parametrize("mod,name", ISO_UTC_HELPERS)
def test_isoformat_utc_helpers_return_the_pinned_instant(mod, name):
    assert getattr(importlib.import_module(mod), name)() == ISO_UTC


def test_bound_receipt_clock_and_stamp_format():
    from willow_mcp import bound_receipt

    assert bound_receipt._utc_now() == datetime(2026, 10, 20, 12, 0, 0, 123456, tzinfo=timezone.utc)
    assert bound_receipt._format_ts(bound_receipt._utc_now()) == ISO_UTC
    # the same instant seen from another offset is still written in UTC
    other = datetime.fromisoformat("2026-10-20T05:00:00.123456-07:00")
    assert bound_receipt._format_ts(other) == ISO_UTC


@pytest.mark.parametrize("mod,name", SECONDS_Z_HELPERS + ISO_UTC_HELPERS)
def test_no_one_script_is_unreachable_with_why(mod, name, monkeypatch, tmp_path):
    monkeypatch.setenv("ONESCRIPT_HOME", str(tmp_path / "nowhere"))
    with pytest.raises(onescript_reach.Unreachable, match="ONESCRIPT_HOME"):
        getattr(importlib.import_module(mod), name)()


@pytest.mark.parametrize("mod,name,named", PRIVILEGED_LEFT)
def test_privileged_helpers_keep_the_bytes_of_the_named_format(mod, name, named, monkeypatch):
    """They do not reach the one script, so the pin does not move them; what is
    held is that each still writes the shape of the format it is named for."""
    monkeypatch.delenv("ONESCRIPT_NOW", raising=False)
    got = getattr(importlib.import_module(mod), name)()
    if named == SECONDS_Z:
        assert len(got) == 20 and got.endswith("Z") and "." not in got
    else:
        assert got.endswith("+00:00") and "." in got.split("T")[1]
