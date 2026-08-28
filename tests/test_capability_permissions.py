"""Every capability permission the gate enforces must be one an operator can grant.

This test exists because of a defect it would have caught. `gate.py` defines six
capability permissions — `task_net`, `task_db`, `integration_net`, `web_net`,
`mcp_federation`, `grove_relay` — each deliberately kept out of
`PERMISSION_GROUPS` and out of `full_access`, so that a broad grant never
silently carries an escalated lane with it. Each is checked by `gate.permitted()`
at the point of use.

`manifest_admin.KNOWN_PERMISSIONS` restated three of those six by hand. The
other three were enforced and ungrantable: `willow-mcp allow-permission willow
mcp_federation` refused a correctly spelled name as unknown, and there was no
other supported path, so the federated-MCP lane could not be opened by anyone
from the day it was written. `federation_list_servers` returning `[]` read as
nobody having gotten to it; it was the only answer the code could give.

The general lesson is the one the fleet keeps arriving at: **a list that must be
maintained by hand is a list that will silently go stale**, and a guard that
refuses a valid name is not a stricter guard, it is a broken one. So the set is
derived from the module's own constants rather than restated a third time here.

Two assertions, kept apart because they fail for different reasons:

1. the canonical set covers every constant the module defines, and
2. every member of it is actually grantable through the operator's CLI path.

Neither alone is sufficient. A complete `CAPABILITY_PERMISSIONS` that
`manifest_admin` does not consult is the exact defect above wearing a fix; a
`KNOWN_PERMISSIONS` built from a complete set that has itself fallen behind
`gate.py` is the same defect one level up.
"""
from __future__ import annotations

import pytest

from willow_mcp import gate, manifest_admin


def _declared_permission_constants() -> dict[str, str]:
    """Every ``*_PERMISSION`` string constant `gate` defines.

    Read from the module rather than from a roster kept in this file, so a new
    capability is covered the moment it is written — a roster here would be one
    more list to forget, which is the shape of the bug being guarded against.
    """
    return {
        name: value
        for name, value in vars(gate).items()
        if name.endswith("_PERMISSION") and isinstance(value, str)
    }


def test_the_roster_is_not_empty():
    """Non-vacuity: a rename of the constants would otherwise leave every
    assertion below trivially true."""
    declared = _declared_permission_constants()
    assert len(declared) >= 6, f"expected at least six, found {sorted(declared)}"


def test_every_declared_capability_is_in_the_canonical_set():
    missing = {
        name: value
        for name, value in _declared_permission_constants().items()
        if value not in gate.CAPABILITY_PERMISSIONS
    }
    assert not missing, (
        f"declared in gate.py but absent from CAPABILITY_PERMISSIONS: {missing}. "
        f"A capability outside the set is enforceable and ungrantable."
    )


def test_every_capability_is_grantable_by_an_operator():
    """The regression that actually happened: enforced by `permitted()`, refused
    by `allow-permission`."""
    ungrantable = sorted(gate.CAPABILITY_PERMISSIONS - manifest_admin.KNOWN_PERMISSIONS)
    assert not ungrantable, (
        f"gate.permitted() honors these and `willow-mcp allow-permission` "
        f"refuses them: {ungrantable}"
    )


@pytest.mark.parametrize(
    "perm",
    ["task_net", "task_db", "integration_net", "web_net", "mcp_federation", "grove_relay"],
)
def test_each_capability_validates_by_name(perm):
    """Named individually as well as derived, so the failure message says which
    lane is shut rather than reporting a set difference."""
    assert manifest_admin.validate_permission(perm) == perm


def test_the_historical_allowlist_would_fail_this_guard():
    """Prove-it-can-fail, against the real pre-fix value rather than a synthetic
    one. Without this, a rewrite of `KNOWN_PERMISSIONS` that returned everything
    would leave the assertions above green forever."""
    historical = frozenset(gate.PERMISSION_GROUPS) | {
        gate.NET_PERMISSION,
        gate.INTEGRATION_NET_PERMISSION,
        gate.WEB_NET_PERMISSION,
    }
    still_shut = sorted(gate.CAPABILITY_PERMISSIONS - historical)
    assert still_shut == ["grove_relay", "mcp_federation", "task_db"], (
        f"expected the three historically ungrantable lanes, got {still_shut}"
    )


def test_a_misspelled_permission_is_still_refused():
    """The typo guard the allowlist exists for must survive the widening."""
    with pytest.raises(ValueError, match="unknown permission"):
        manifest_admin.validate_permission("mcp_federatoin")


def test_a_federated_grant_for_an_unratified_server_is_refused():
    """A grant naming a server nobody ratified would sit in a manifest looking
    effective and deny at every call — the silent shape, refused up front."""
    with pytest.raises(ValueError, match="no ratified server"):
        manifest_admin.validate_permission("mcp:0000000000ff:corpus_ask")


@pytest.mark.parametrize("perm", ["mcp:", "mcp::corpus_ask", "mcp:abc:", "mcp:a:b:c"])
def test_a_malformed_federated_grant_is_refused(perm):
    with pytest.raises(ValueError, match="malformed federated permission"):
        manifest_admin.validate_permission(perm)
