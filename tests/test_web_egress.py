"""Tests for web_egress gate."""

import json


from willow_mcp import web_egress


def test_egress_denied_without_web_net(home):
    apps = home / "mcp_apps" / "reader"
    apps.mkdir(parents=True)
    (apps / "manifest.json").write_text(json.dumps({"permissions": ["web_read"]}))
    denial = web_egress.egress_denial("reader")
    assert denial is not None
    assert "net_denied" in denial["error"]


def test_egress_denied_without_lease(home, monkeypatch):
    apps = home / "mcp_apps" / "webby"
    apps.mkdir(parents=True)
    (apps / "manifest.json").write_text(
        json.dumps({"permissions": ["web_read", "web_net"]})
    )
    monkeypatch.setattr("willow_mcp.consent.internet_permitted", lambda: True)
    denial = web_egress.egress_denial("webby")
    assert denial is not None
    assert "lease_denied" in denial["error"]
    # Gap b3b9a03e7348: the refusal names the ask path, not a terminal-only one.
    assert "`lease_request`" in denial["error"]
    assert "net_authority_drain" in denial["error"]
    assert "No MCP tool can mint" not in denial["error"]


# ── egress_status: the read-only, all-four-keys diagnostic (#287) ────────────

def test_egress_status_reports_every_key_denied_when_nothing_is_granted(home):
    status = web_egress.egress_status("ghost")
    assert status["app_id"] == "ghost"
    assert status["egress_permitted"] is False
    keys = status["keys"]
    assert keys["manifest_permission"]["granted"] is False
    assert keys["operator_consent"]["granted"] is False
    assert keys["egress_lease"]["granted"] is False
    assert keys["egress_lease"]["status"] == "none"
    # Strict trust root is off by default (see lease.strict_trust_root) — its
    # absence must never itself read as a denial.
    assert keys["strict_trust_root"]["enabled"] is False
    assert keys["strict_trust_root"]["ok"] is True


def test_egress_status_never_stops_at_the_first_closed_lock(home, monkeypatch):
    """Unlike egress_denial, egress_status reports every closed key at once —
    the whole point of the diagnostic over the gate."""
    apps = home / "mcp_apps" / "reader"
    apps.mkdir(parents=True)
    (apps / "manifest.json").write_text(json.dumps({"permissions": ["web_read"]}))
    monkeypatch.setattr("willow_mcp.consent.internet_permitted", lambda: False)

    status = web_egress.egress_status("reader")
    # Both the manifest permission AND the lease (AND consent) are closed
    # simultaneously — egress_denial would only ever have surfaced the first.
    assert status["keys"]["manifest_permission"]["granted"] is False
    assert status["keys"]["operator_consent"]["granted"] is False
    assert status["keys"]["egress_lease"]["granted"] is False
    assert status["egress_permitted"] is False


def test_egress_status_all_four_keys_granted(home, monkeypatch):
    from willow_mcp import lease

    apps = home / "mcp_apps" / "granted"
    apps.mkdir(parents=True)
    (apps / "manifest.json").write_text(
        json.dumps({"permissions": ["web_read", "web_net"]})
    )
    monkeypatch.setattr("willow_mcp.consent.internet_permitted", lambda: True)
    lease.grant("granted", 1800, issuer="operator", reason="test")

    status = web_egress.egress_status("granted")
    assert status["egress_permitted"] is True
    keys = status["keys"]
    assert keys["manifest_permission"]["granted"] is True
    assert keys["operator_consent"]["granted"] is True
    assert keys["egress_lease"]["granted"] is True
    assert keys["egress_lease"]["status"] == "active"
    assert keys["strict_trust_root"]["ok"] is True


def test_egress_status_strict_trust_root_forgeable_denies_even_with_other_keys_granted(
    home, monkeypatch
):
    """Mirrors egress_denial's own trust-root check: strict mode + a forgeable
    key must read as not-ok even when the other three keys are granted."""
    from willow_mcp import lease

    apps = home / "mcp_apps" / "granted"
    apps.mkdir(parents=True)
    (apps / "manifest.json").write_text(
        json.dumps({"permissions": ["web_read", "web_net"]})
    )
    monkeypatch.setattr("willow_mcp.consent.internet_permitted", lambda: True)
    lease.grant("granted", 1800, issuer="operator", reason="test")
    monkeypatch.setattr("willow_mcp.lease.strict_trust_root", lambda: True)
    monkeypatch.setattr(
        "willow_mcp.lease.self_writable_trust_paths",
        lambda app_id="": [{"key": "lease_root", "path": "/wherever"}],
    )

    status = web_egress.egress_status("granted")
    assert status["keys"]["strict_trust_root"]["enabled"] is True
    assert status["keys"]["strict_trust_root"]["ok"] is False
    assert status["keys"]["strict_trust_root"]["forgeable"]
    assert status["egress_permitted"] is False


def test_egress_status_strict_trust_root_on_but_not_forgeable_is_ok(home, monkeypatch):
    """Strict mode on its own is informational, not a denial — only an
    actually-forgeable key under strict mode should flip `ok` to False."""
    monkeypatch.setattr("willow_mcp.lease.strict_trust_root", lambda: True)
    monkeypatch.setattr(
        "willow_mcp.lease.self_writable_trust_paths", lambda app_id="": []
    )
    status = web_egress.egress_status("someapp")
    assert status["keys"]["strict_trust_root"]["enabled"] is True
    assert status["keys"]["strict_trust_root"]["ok"] is True


def test_egress_status_never_raises_on_a_malformed_app_id(home):
    # gate.permitted, lease.read_lease, and self_writable_trust_paths are all
    # documented fail-closed/never-raise — egress_status must inherit that.
    status = web_egress.egress_status("../not a valid app id!!")
    assert status["egress_permitted"] is False
