"""Time-boxed build leases — the earn-first key.

Mirrors `test_lease.py` on the property under test: **only a well-formed,
matching, unexpired lease authorizes anything.** Everything else — absent,
unparseable, over-ceiling, naive-timestamped, or naming a different tool —
is *no lease*, in the same fail-closed spirit as `consent.py` and `lease.py`.

The residual keys / self-writable-trust-paths surface is deliberately not
mirrored: build_lease.py lives under the same `mcp_apps/` root as
`_net_leases/`, so B-32's uid-separation story already covers the file that
holds a build lease. There is nothing new to check here that lease.py does
not already check for the whole root.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from willow_mcp import build_lease


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path / "mcp_apps"))
    return tmp_path


def _write_raw(tool, record):
    path = build_lease.lease_path(tool, create_root=True)
    path.write_text(record if isinstance(record, str) else json.dumps(record))
    return path


# ── ttl parsing / ceiling ────────────────────────────────────────────────────

@pytest.mark.parametrize("text,expected", [
    ("900s", 900), ("30m", 1800), ("2h", 7200), ("45", 45), (" 10m ", 600), ("2H", 7200),
])
def test_parse_ttl_accepts_units(text, expected):
    assert build_lease.parse_ttl(text) == expected


@pytest.mark.parametrize("text", ["", "abc", "-5m", "0", "0s", "3.5h", "10d"])
def test_parse_ttl_rejects_garbage(text):
    with pytest.raises(ValueError):
        build_lease.parse_ttl(text)


def test_parse_ttl_enforces_the_three_hour_ceiling():
    """Same 3h ceiling as `lease.py` — FRANK `cc553729`."""
    assert build_lease.parse_ttl("3h") == build_lease.MAX_TTL_SECONDS
    with pytest.raises(ValueError, match="ceiling"):
        build_lease.parse_ttl("4h")


def test_grant_rejects_ttl_above_ceiling(home):
    with pytest.raises(ValueError, match="ceiling"):
        build_lease.grant("workflow", build_lease.MAX_TTL_SECONDS + 1, issuer="op")


def test_grant_requires_an_issuer(home):
    """An unattributed grant is not a grant — the rule this seal opens is
    'the operator asks AND agrees,' and an empty issuer has no operator."""
    with pytest.raises(ValueError, match="issuer"):
        build_lease.grant("workflow", 60, issuer="")


def test_grant_rejects_bool_ttl(home):
    # bool is an int in Python; True would otherwise mean "1 second".
    with pytest.raises(ValueError):
        build_lease.grant("workflow", True, issuer="op")


# ── the happy path ───────────────────────────────────────────────────────────

def test_grant_then_active(home):
    record = build_lease.grant(
        "workflow", 1800, issuer="op",
        reason="ship the multi-phase engine so kart tasks compose",
    )
    assert record["tool"] == "workflow"
    assert record["ttl_seconds"] == 1800
    assert build_lease.active("workflow") is True

    state = build_lease.read_lease("workflow")
    assert state["status"] == "active"
    assert state["issuer"] == "op"
    assert "compose" in state["reason"]
    assert 0 < state["remaining_seconds"] <= 1800


def test_regrant_can_shorten(home):
    """Re-granting is how an operator extends — and it must also be able to cut short."""
    build_lease.grant("workflow", 3000, issuer="op")
    build_lease.grant("workflow", 60, issuer="op")
    assert build_lease.read_lease("workflow")["remaining_seconds"] <= 60


def test_revoke(home):
    build_lease.grant("workflow", 600, issuer="op")
    assert build_lease.revoke("workflow") is True
    assert build_lease.active("workflow") is False
    assert build_lease.read_lease("workflow")["status"] == "none"
    assert build_lease.revoke("workflow") is False  # idempotent


def test_no_lease_file_is_no_lease(home):
    assert build_lease.active("neverissued") is False
    assert build_lease.read_lease("neverissued")["status"] == "none"


# ── fail-closed reads ────────────────────────────────────────────────────────

def test_expired_lease_denies(home):
    build_lease.grant("workflow", 600, issuer="op")
    path = build_lease.lease_path("workflow")
    record = json.loads(path.read_text())
    record["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    path.write_text(json.dumps(record))
    assert build_lease.active("workflow") is False
    assert build_lease.read_lease("workflow")["status"] == "expired"


def test_unparseable_lease_denies(home):
    _write_raw("workflow", "{ not json")
    assert build_lease.active("workflow") is False
    assert build_lease.read_lease("workflow")["status"] == "malformed"


def test_non_object_lease_denies(home):
    _write_raw("workflow", "[1, 2, 3]")
    assert build_lease.read_lease("workflow")["status"] == "malformed"


def test_lease_naming_another_tool_denies(home):
    """A name is not an identity: the filename says where we looked; the
    record says what it claims. Only the claim counts."""
    build_lease.grant("workflow", 600, issuer="op")
    path = build_lease.lease_path("workflow")
    record = json.loads(path.read_text())
    record["tool"] = "intake"
    path.write_text(json.dumps(record))

    state = build_lease.read_lease("workflow")
    assert state["status"] == "mismatch"
    assert build_lease.active("workflow") is False


def test_naive_expires_at_denies(home):
    """A deadline without a timezone is not a deadline. Guessing extends the lease."""
    build_lease.grant("workflow", 600, issuer="op")
    path = build_lease.lease_path("workflow")
    record = json.loads(path.read_text())
    record["expires_at"] = "2099-01-01T00:00:00"  # no offset
    path.write_text(json.dumps(record))
    assert build_lease.active("workflow") is False
    assert "timezone" in build_lease.read_lease("workflow")["error"]


def test_missing_expires_at_denies(home):
    build_lease.grant("workflow", 600, issuer="op")
    path = build_lease.lease_path("workflow")
    record = json.loads(path.read_text())
    del record["expires_at"]
    path.write_text(json.dumps(record))
    assert build_lease.active("workflow") is False


@pytest.mark.parametrize(
    "ttl",
    [0, -1, "1800", None, True, build_lease.MAX_TTL_SECONDS + 1],
)
def test_ttl_outside_the_ceiling_denies_on_read(home, ttl):
    """A file edited past the ceiling after it was issued must not be honored
    just because `grant` would have refused to write it."""
    build_lease.grant("workflow", 600, issuer="op")
    path = build_lease.lease_path("workflow")
    record = json.loads(path.read_text())
    record["ttl_seconds"] = ttl
    record["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    path.write_text(json.dumps(record))
    assert build_lease.active("workflow") is False
    assert build_lease.read_lease("workflow")["status"] == "malformed"


def test_a_far_future_deadline_within_ceiling_ttl_is_still_read(home):
    """Guard against over-correcting: ttl_seconds is the ceiling check,
    expires_at is the clock. A valid ttl with a future deadline is a valid lease."""
    build_lease.grant("workflow", build_lease.MAX_TTL_SECONDS, issuer="op")
    assert build_lease.active("workflow") is True


def test_invalid_tool_name_denies(home):
    state = build_lease.read_lease("../etc/passwd")
    assert state["status"] == "malformed"
    assert build_lease.active("../etc/passwd") is False


def test_grant_rejects_invalid_tool_name(home):
    with pytest.raises(ValueError, match="Invalid tool name"):
        build_lease.grant("../etc/passwd", 600, issuer="op")


# ── listing ──────────────────────────────────────────────────────────────────

def test_list_leases_includes_expired_and_malformed(home):
    build_lease.grant("workflow", 600, issuer="op")
    _write_raw("bad", "{ not json")
    states = {s["tool"]: s["status"] for s in build_lease.list_leases()}
    assert states == {"workflow": "active", "bad": "malformed"}


def test_list_leases_empty_when_no_directory(home):
    assert build_lease.list_leases() == []


# ── the doctrine: build-lease and net-lease live in sibling roots ────────────

def test_build_lease_root_is_a_sibling_of_net_lease_root(home):
    """Both live under mcp_apps/. B-14's bound_ro sandbox mount already covers
    that parent, so a Kart task cannot mint a build lease any more than it can
    mint an egress one."""
    from willow_mcp import lease, paths
    build_root = build_lease._leases_root()
    net_root = lease._leases_root()
    assert build_root.parent == net_root.parent == paths.mcp_apps_root()
    assert build_root.name == "_build_leases"
    assert net_root.name == "_net_leases"
