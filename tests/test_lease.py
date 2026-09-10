"""Time-boxed egress leases — the third key (B-32).

The property under test: **only a well-formed, matching, unexpired lease
authorizes anything.** Everything else — absent, unparseable, naive-timestamped,
over-ceiling, or naming a different app — is *no lease*, in the same fail-closed
spirit as `consent.py`.

The `self_writable_trust_paths` tests pin the honest part: on a single-uid host
this module reports that the process reading the lease could also have written
it. That report is the whole difference between a control and a costume.
"""
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from willow_mcp import lease


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path / "mcp_apps"))
    monkeypatch.delenv("WILLOW_MCP_STRICT_TRUST_ROOT", raising=False)
    return tmp_path


def _write_raw(app_id, record):
    path = lease.lease_path(app_id, create_root=True)
    path.write_text(record if isinstance(record, str) else json.dumps(record))
    return path


# ── ttl parsing / ceiling ────────────────────────────────────────────────────

@pytest.mark.parametrize("text,expected", [
    ("900s", 900), ("30m", 1800), ("2h", 7200), ("45", 45), (" 10m ", 600), ("2H", 7200),
])
def test_parse_ttl_accepts_units(text, expected):
    assert lease.parse_ttl(text) == expected


@pytest.mark.parametrize("text", ["", "abc", "-5m", "0", "0s", "3.5h", "10d"])
def test_parse_ttl_rejects_garbage(text):
    with pytest.raises(ValueError):
        lease.parse_ttl(text)


def test_parse_ttl_enforces_the_three_hour_ceiling():
    assert lease.parse_ttl("3h") == lease.MAX_TTL_SECONDS
    with pytest.raises(ValueError, match="ceiling"):
        lease.parse_ttl("4h")


def test_grant_rejects_ttl_above_ceiling(home):
    with pytest.raises(ValueError, match="ceiling"):
        lease.grant("app", lease.MAX_TTL_SECONDS + 1, issuer="op")


def test_grant_requires_an_issuer(home):
    """An unattributed grant is not a grant — there is no one to ask about it."""
    with pytest.raises(ValueError, match="issuer"):
        lease.grant("app", 60, issuer="")


def test_grant_rejects_bool_ttl(home):
    # bool is an int in Python; True would otherwise mean "1 second".
    with pytest.raises(ValueError):
        lease.grant("app", True, issuer="op")


# ── the happy path ───────────────────────────────────────────────────────────

def test_grant_then_active(home):
    record = lease.grant("app", 1800, issuer="op", reason="push a branch")
    assert record["app_id"] == "app"
    assert record["ttl_seconds"] == 1800
    assert lease.active("app") is True

    state = lease.read_lease("app")
    assert state["status"] == "active"
    assert state["issuer"] == "op"
    assert state["reason"] == "push a branch"
    assert 0 < state["remaining_seconds"] <= 1800


def test_regrant_can_shorten(home):
    """Re-granting is how an operator extends — and it must also be able to cut short."""
    lease.grant("app", 3000, issuer="op")
    lease.grant("app", 60, issuer="op")
    assert lease.read_lease("app")["remaining_seconds"] <= 60


def test_revoke(home):
    lease.grant("app", 600, issuer="op")
    assert lease.revoke("app") is True
    assert lease.active("app") is False
    assert lease.read_lease("app")["status"] == "none"


# ── a lease is a public grant: readable by the process it authorizes ─────────
#
# Gap d90246688413 (2026-09-10): `sudo … grant-net` printed success; the seat
# then read "Permission denied" on the file. Root's umask made a 0600 root-
# owned lease inside the 994-owned lease root. Correct on disk, invisible to
# the process it authorized, and reported as "malformed" with advice to
# re-issue — which reproduces the same file.

def test_grant_leaves_the_lease_world_readable_regardless_of_umask(home):
    import os
    import stat

    old = os.umask(0o077)
    try:
        lease.grant("app", 600, issuer="op")
    finally:
        os.umask(old)
    mode = stat.S_IMODE(lease.lease_path("app").stat().st_mode)
    assert mode == 0o644, f"lease landed at {oct(mode)}; must be readable by the seat"
    assert lease.read_lease("app")["status"] == "active"


@pytest.mark.skipif(__import__("os").geteuid() == 0, reason="root can read anything")
def test_an_unreadable_lease_reports_unreadable_not_malformed(home):
    lease.grant("app", 600, issuer="op")
    path = lease.lease_path("app")
    path.chmod(0o000)
    try:
        state = lease.read_lease("app")
        authorizes = lease.active("app")
    finally:
        path.chmod(0o644)
    assert state["status"] == "unreadable", state
    assert "permission denied" in state["error"]
    assert state["path"] == str(path)
    assert authorizes is False


def test_unparseable_is_still_malformed_not_unreadable(home):
    """The two states must not collapse: garbage is malformed, refused is unreadable."""
    path = lease.lease_path("app", create_root=True)
    path.write_text("{not json", encoding="utf-8")
    assert lease.read_lease("app")["status"] == "malformed"


def test_no_lease_file_is_no_lease(home):
    assert lease.active("neverissued") is False
    assert lease.read_lease("neverissued")["status"] == "none"


# ── fail-closed reads ────────────────────────────────────────────────────────

def test_expired_lease_denies(home):
    lease.grant("app", 600, issuer="op")
    path = lease.lease_path("app")
    record = json.loads(path.read_text())
    record["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    path.write_text(json.dumps(record))
    assert lease.active("app") is False
    assert lease.read_lease("app")["status"] == "expired"


def test_unparseable_lease_denies(home):
    _write_raw("app", "{ not json")
    assert lease.active("app") is False
    assert lease.read_lease("app")["status"] == "malformed"


def test_non_object_lease_denies(home):
    _write_raw("app", "[1, 2, 3]")
    assert lease.read_lease("app")["status"] == "malformed"


def test_lease_naming_another_app_denies(home):
    """A name is not an identity: the filename is where we looked, not the claim."""
    lease.grant("app", 600, issuer="op")
    path = lease.lease_path("app")
    record = json.loads(path.read_text())
    record["app_id"] = "other"
    path.write_text(json.dumps(record))

    state = lease.read_lease("app")
    assert state["status"] == "mismatch"
    assert lease.active("app") is False


def test_naive_expires_at_denies(home):
    """A deadline without a timezone is not a deadline. Guessing extends the lease."""
    lease.grant("app", 600, issuer="op")
    path = lease.lease_path("app")
    record = json.loads(path.read_text())
    record["expires_at"] = "2099-01-01T00:00:00"  # no offset
    path.write_text(json.dumps(record))
    assert lease.active("app") is False
    assert "timezone" in lease.read_lease("app")["error"]


def test_missing_expires_at_denies(home):
    lease.grant("app", 600, issuer="op")
    path = lease.lease_path("app")
    record = json.loads(path.read_text())
    del record["expires_at"]
    path.write_text(json.dumps(record))
    assert lease.active("app") is False


@pytest.mark.parametrize("ttl", [0, -1, "1800", None, True, lease.MAX_TTL_SECONDS + 1])
def test_ttl_outside_the_ceiling_denies_on_read(home, ttl):
    """A file edited past the ceiling after it was issued must not be honored just
    because `grant` would have refused to write it."""
    lease.grant("app", 600, issuer="op")
    path = lease.lease_path("app")
    record = json.loads(path.read_text())
    record["ttl_seconds"] = ttl
    record["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    path.write_text(json.dumps(record))
    assert lease.active("app") is False
    assert lease.read_lease("app")["status"] == "malformed"


def test_a_far_future_deadline_within_ceiling_ttl_is_still_read(home):
    """Guard against over-correcting: ttl_seconds is the ceiling check, expires_at
    is the clock. A valid ttl with a future deadline is a valid lease."""
    lease.grant("app", lease.MAX_TTL_SECONDS, issuer="op")
    assert lease.active("app") is True


def test_invalid_app_id_denies(home):
    state = lease.read_lease("../etc/passwd")
    assert state["status"] == "malformed"
    assert lease.active("../etc/passwd") is False


# ── listing ──────────────────────────────────────────────────────────────────

def test_list_leases_includes_expired_and_malformed(home):
    lease.grant("good", 600, issuer="op")
    _write_raw("bad", "{ not json")
    states = {s["app_id"]: s["status"] for s in lease.list_leases()}
    assert states == {"good": "active", "bad": "malformed"}


# ── the residual: who could forge these keys? ────────────────────────────────

def test_self_writable_reports_the_lease_root_on_a_single_uid_host(home):
    """The honest measure of B-32: this process can write the directory holding
    the file that authorizes it."""
    found = lease.self_writable_trust_paths()
    assert [f["key"] for f in found] == ["lease_root"]


def test_self_writable_includes_the_manifest_when_present(home):
    app_dir = home / "mcp_apps" / "app"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(json.dumps({"permissions": ["task_net"]}))
    keys = {f["key"] for f in lease.self_writable_trust_paths("app")}
    assert keys == {"lease_root", "manifest"}


def test_self_writable_skips_a_manifest_that_does_not_exist(home):
    keys = {f["key"] for f in lease.self_writable_trust_paths("ghost")}
    assert keys == {"lease_root"}


def test_self_writable_is_empty_when_full_path_is_protected(home, monkeypatch):
    """Every pathname component must be outside the actor's write reach."""
    lease.grant("app", 600, issuer="op")  # creates the root
    monkeypatch.setattr(lease.os, "access", lambda *_: False)
    assert lease.self_writable_trust_paths() == []


def test_read_only_leaf_beneath_writable_parent_is_replaceable(home, monkeypatch):
    lease.grant("app", 600, issuer="op")
    root = lease._leases_root()
    parent = root.parent
    monkeypatch.setattr(
        lease.os,
        "access",
        lambda path, _mode: Path(path) == parent,
    )
    assert lease.path_is_self_writable_or_replaceable(root) is True
    assert [f["key"] for f in lease.self_writable_trust_paths()] == ["lease_root"]


def test_self_writable_ignores_writable_home_ancestor(home, monkeypatch):
    """Hardened mcp_apps owned by another uid is not forgeable via .willow parent."""
    lease.grant("app", 600, issuer="op")
    monkeypatch.setattr(lease, "path_is_directly_writable_for_trust", lambda path: False)
    assert lease.self_writable_trust_paths("app") == []


def test_a_read_only_lease_root_is_still_readable(home):
    """The hardened deployment must still be able to *check* a lease. Reads deny or
    allow; they never blow up because the trust root refused a write."""
    if os.geteuid() == 0:
        pytest.skip("root bypasses mode bits")
    lease.grant("app", 600, issuer="op")
    root = lease._leases_root()
    root.chmod(0o500)
    try:
        assert lease.active("app") is True          # the lease still reads
        assert lease.read_lease("ghost")["status"] == "none"
        assert [s["app_id"] for s in lease.list_leases()] == ["app"]
    finally:
        root.chmod(0o700)


def test_readers_never_create_the_lease_root(home):
    """A read path that mkdirs the trust root would raise OSError(EROFS) on exactly
    the read-only deployment this module argues for."""
    root = lease._leases_root()
    assert not root.exists()

    assert lease.read_lease("app")["status"] == "none"
    assert lease.active("app") is False
    assert lease.list_leases() == []
    assert lease.revoke("app") is False
    lease.self_writable_trust_paths("app")

    assert not root.exists(), "a reader created the lease root"

    lease.grant("app", 60, issuer="op")  # only the issuer creates it
    assert root.is_dir()


def test_self_writable_reports_an_absent_root_this_process_could_create(home):
    """An absent directory is not hardening. If we could create it, the key is
    forgeable, and saying otherwise would read as a control that isn't there."""
    assert not lease._leases_root().exists()
    assert [f["key"] for f in lease.self_writable_trust_paths()] == ["lease_root"]


@pytest.mark.parametrize("value,expected", [
    ("1", True), ("true", True), ("YES", True), ("", False), ("0", False), ("no", False),
])
def test_strict_trust_root_env(home, monkeypatch, value, expected):
    monkeypatch.setenv("WILLOW_MCP_STRICT_TRUST_ROOT", value)
    assert lease.strict_trust_root() is expected


def test_strict_trust_root_defaults_off(home):
    """Default off is a statement about deployments, not about policy: on a
    single-uid host, on-by-default would deny every existing install's egress."""
    assert lease.strict_trust_root() is False


# ── path_is_self_readable / egress_key_readable_by_self (#182) ──────────────

def test_path_is_self_readable_true_for_a_file_this_process_can_read(tmp_path):
    f = tmp_path / "readable.txt"
    f.write_text("x")
    assert lease.path_is_self_readable(f) is True


def test_path_is_self_readable_false_for_a_missing_file(tmp_path):
    assert lease.path_is_self_readable(tmp_path / "ghost.txt") is False


def test_path_is_self_readable_false_for_a_directory(tmp_path):
    """Leaf must be a file — a directory is not 'the key', it's where it lives."""
    assert lease.path_is_self_readable(tmp_path) is False


def test_path_is_self_readable_respects_os_access(tmp_path, monkeypatch):
    f = tmp_path / "locked.pem"
    f.write_text("secret")
    monkeypatch.setattr(lease.os, "access", lambda *_: False)
    assert lease.path_is_self_readable(f) is False


def test_egress_key_not_readable_when_no_key_is_configured(home, monkeypatch):
    from willow_mcp import egress_setup
    monkeypatch.setattr(egress_setup, "resolve_private_key_path", lambda: None)
    assert lease.egress_key_readable_by_self() is False


def test_egress_key_readable_when_this_process_can_read_it(home, monkeypatch):
    """The core #182 finding, reproduced: a key chmod 600 on a single-uid host
    is readable by the very process the gate is supposed to keep it from."""
    from willow_mcp import egress_setup
    key = home / "egress" / "private.pem"
    key.parent.mkdir(parents=True)
    key.write_text("-----BEGIN PRIVATE KEY-----\n...")
    key.chmod(0o600)
    monkeypatch.setattr(egress_setup, "resolve_private_key_path", lambda: key)
    assert lease.egress_key_readable_by_self() is True


def test_egress_key_not_readable_when_this_process_cannot_read_it(home, monkeypatch):
    from willow_mcp import egress_setup
    key = home / "egress" / "private.pem"
    key.parent.mkdir(parents=True)
    key.write_text("-----BEGIN PRIVATE KEY-----\n...")
    monkeypatch.setattr(egress_setup, "resolve_private_key_path", lambda: key)
    monkeypatch.setattr(lease.os, "access", lambda *_: False)
    assert lease.egress_key_readable_by_self() is False


# ── no MCP tool may mint a lease ─────────────────────────────────────────────

def test_lease_is_not_reachable_as_an_mcp_tool():
    """The sudo invariant, asserted: request and confirm are separate authorities,
    so the confirm side has no tool surface at all. Issuing a lease is CLI-only,
    exactly as `confirm_binding` is (L-AUTH-02)."""
    from willow_mcp import server
    for name in ("grant_net", "revoke_net", "net_status", "grant", "revoke"):
        assert not hasattr(server, name), f"server exports {name!r} — a lease must never be mintable by a caller"
