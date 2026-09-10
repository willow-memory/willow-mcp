"""diagnostic_summary must tell an unreadable lease from a malformed one.

Gap d90246688413, measured 2026-09-10: a root-issued `grant-net` landed a
0600 root-owned lease inside the 994-owned lease root. `_derive_problems`
called it malformed and said "this one was not [written by grant-net], or was
edited after" — both false — and told the operator to remove it and re-issue,
which from the same root shell reproduces the same unreadable file. The
distinct status carries the distinct fix: a mode change, not a re-grant.
"""
from __future__ import annotations

from willow_mcp import server


def _net_lease(status: str, error: str = "") -> dict:
    lease = {
        "app_id": "willow",
        "status": status,
        "path": "/box/mcp_apps/_net_leases/willow.json",
        "expires_at": None,
        "remaining_seconds": None,
    }
    if error:
        lease["error"] = error
    return {
        "app_id": "willow",
        "lease": lease,
        "self_writable": [],
        "strict_trust_root": False,
        "private_key_readable": False,
    }


def _lease_problems(net_lease: dict) -> list[dict]:
    problems = server._derive_problems(
        {"status": "ok"}, {"status": "ok"}, {"status": "ok"}, "stdio",
        None, None, net_lease,
    )
    return [p for p in problems if p["check"] == "net_lease"]


def test_unreadable_lease_gets_a_chmod_fix_not_a_regrant():
    [p] = _lease_problems(_net_lease("unreadable", "permission denied: [Errno 13]"))
    assert p["severity"] == "warn"
    assert "cannot read it" in p["detail"]
    assert "permission denied" in p["detail"]
    # The two false claims the old text made must be gone.
    assert "was not" not in p["detail"]
    assert "edited after" not in p["detail"]
    assert "chmod 644 /box/mcp_apps/_net_leases/willow.json" in p["fix"]
    assert "re-issue" in p["fix"] and "do not re-issue" in p["fix"].lower()


def test_malformed_lease_still_says_remove_and_reissue():
    """The old branch is unchanged for genuinely bad files."""
    [p] = _lease_problems(_net_lease("malformed", "unparseable: Expecting value"))
    assert "malformed" in p["detail"]
    assert "re-issue" in p["fix"]
    assert "chmod" not in p["fix"]


def test_an_active_lease_raises_no_lease_problem():
    assert _lease_problems(_net_lease("active")) == []
