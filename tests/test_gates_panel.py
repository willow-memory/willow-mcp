"""Tests for gates_panel.py — the unified on/off view over every gate.

Focuses on the read model (`collect`) staying honest about what each
underlying module (`consent`, `lease`, `gate`, `heartbeat`, identity
bindings) reports, and on the two renderers not blowing up or mangling
their input.
"""
import json

import pytest

from willow_mcp import build_lease, consent, gates_panel, lease, manifest_admin
from willow_mcp.gate import (
    INTEGRATION_NET_PERMISSION,
    NET_PERMISSION,
    PERMISSION_GROUPS,
)


@pytest.fixture
def apps_root(tmp_path, monkeypatch):
    root = tmp_path / "mcp_apps"
    root.mkdir()
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(root))
    monkeypatch.delenv("WILLOW_MCP_STRICT_TRUST_ROOT", raising=False)
    monkeypatch.delenv("WILLOW_HUMAN_ORCHESTRATOR", raising=False)
    monkeypatch.delenv("WILLOW_MCP_FLEET_HOME", raising=False)
    monkeypatch.delenv("WILLOW_MCP_FLEET_PG_DB", raising=False)
    return root


def _row(rows, row_id):
    return next(r for r in rows if r.id == row_id)


def test_list_app_ids_skips_reserved_dirs(apps_root):
    (apps_root / "real_app").mkdir()
    (apps_root / "_net_leases").mkdir()
    (apps_root / "_identity_bindings").mkdir()
    assert gates_panel.list_app_ids() == ["real_app"]


def test_collect_reflects_manifest_permission_state(apps_root):
    manifest_admin.set_permission("testapp", "store_read", True)
    rows = gates_panel.collect("testapp")
    on = _row(rows, "perm.testapp.store_read")
    off = _row(rows, "perm.testapp.store_write")
    assert on.state == "on"
    assert off.state == "off"
    assert off.action_cli == "willow-mcp allow-permission testapp store_write"
    assert on.action_cli == "willow-mcp deny-permission testapp store_read"


def test_collect_reflects_active_lease_with_timer(apps_root):
    lease.grant("testapp", 1800, issuer="operator", reason="testing")
    row = _row(gates_panel.collect("testapp"), "lease.testapp")
    assert row.state == "on"
    assert row.timer_shape == "lease"
    assert row.remaining_seconds is not None and row.remaining_seconds <= 1800
    assert row.action_cli == "willow-mcp revoke-net testapp"


def test_collect_reflects_absent_lease(apps_root):
    row = _row(gates_panel.collect("testapp"), "lease.testapp")
    assert row.state == "off"
    assert "grant-net" in row.action_cli


def test_collect_consent_rows_are_never_actionable_via_cli(apps_root):
    """consent.py is a read-only consumer by design — the panel must never
    offer a CLI command that would write settings.global.json from here."""
    rows = gates_panel.collect()
    for key in consent.CONSENT_KEYS:
        row = _row(rows, f"consent.{key}")
        assert row.action_cli is None
        assert row.action_note is not None


def test_a_retired_consent_key_gets_no_panel_row(apps_root):
    """A key nothing honours must not be rendered as a switch. `lan` was
    displayed for months while gating nothing; the panel is where an operator
    would have believed it."""
    rows = gates_panel.collect()
    ids = {r.id for r in rows}
    for key in consent._REMOVED_KEYS:
        assert f"consent.{key}" not in ids
        assert f"consent.{key}" not in gates_panel.FRIENDLY_LABELS


def test_collect_env_gates_are_process_lifetime_not_actionable(apps_root):
    rows = gates_panel.collect()
    for gate_id in ("strict_trust_root", "severance", "human_orchestrator"):
        row = _row(rows, gate_id)
        assert row.action_cli is None
        assert "restart" in row.action_note


def test_collect_defaults_to_every_app(apps_root):
    manifest_admin.set_permission("app_a", "store_read", True)
    manifest_admin.set_permission("app_b", "store_read", True)
    rows = gates_panel.collect()
    scopes = {r.scope for r in rows}
    assert "app_a" in scopes and "app_b" in scopes


def test_collect_scoped_to_one_app_excludes_others(apps_root):
    manifest_admin.set_permission("app_a", "store_read", True)
    manifest_admin.set_permission("app_b", "store_read", True)
    rows = gates_panel.collect("app_a")
    scopes = {r.scope for r in rows if r.id.startswith("perm.")}
    assert scopes == {"app_a"}


def test_render_tui_includes_every_row_label(apps_root):
    manifest_admin.set_permission("testapp", "store_read", True)
    rows = gates_panel.collect("testapp")
    out = gates_panel.render_tui(rows, color=False)
    for row in rows:
        assert row.label in out


def test_render_html_is_self_contained_and_escapes_script_boundary(apps_root):
    manifest_admin.set_permission("testapp", "store_read", True)
    rows = gates_panel.collect("testapp")
    html = gates_panel.render_html(rows, "2026-01-01T00:00:00+00:00")
    assert "<!doctype html>" in html
    assert html.count("<script>") == html.count("</script>") == 1
    # The embedded JSON payload must be parseable back out.
    start = html.index("const ROWS = ") + len("const ROWS = ")
    end = html.index(";\n", start)
    payload = json.loads(html[start:end])
    assert any(r["id"] == "perm.testapp.store_read" for r in payload)


def test_render_html_escapes_embedded_script_close_tag(apps_root):
    """A detail/reason string containing a literal '</script>' must not be
    able to break out of the inline <script> block."""
    lease.grant("testapp", 60, issuer="op", reason="</script><script>evil()</script>")
    rows = gates_panel.collect("testapp")
    html = gates_panel.render_html(rows, "2026-01-01T00:00:00+00:00")
    # A stray literal "<script>" in embedded text data is inert (the HTML
    # tokenizer inside a script element only looks for the closing tag), but
    # an unescaped "</script>" would end the block early and let the rest of
    # the payload be parsed as HTML/script — that's the one occurrence that
    # must not survive render_html's escaping.
    assert html.count("</script>") == 1  # only the template's own closing tag
    assert "<\\/script>" in html  # the payload's literal close-tag was neutralized


# ── friendly labels — display-only translation, never the acted-on identity ──

def test_every_permission_group_and_capability_has_a_friendly_label():
    """Regression: a permission group added to gate.py without a matching
    FRIENDLY_LABELS entry silently falls back to _humanize() — not wrong,
    but worth catching so translations don't quietly lag the real gate list."""
    all_names = set(PERMISSION_GROUPS) | {NET_PERMISSION, INTEGRATION_NET_PERMISSION}
    missing = all_names - set(gates_panel.FRIENDLY_LABELS)
    assert not missing, f"no FRIENDLY_LABELS entry for: {sorted(missing)}"


def test_friendly_defaults_from_label_when_not_given():
    row = gates_panel.GateRow(id="x", label="store_read", scope="app", state="off", detail="")
    assert row.friendly == "View saved notes"


def test_friendly_explicit_override_wins():
    row = gates_panel.GateRow(id="x", label="raw", scope="app", state="off", detail="",
                               friendly="Custom text")
    assert row.friendly == "Custom text"


def test_humanize_fallback_for_unmapped_name():
    row = gates_panel.GateRow(id="x", label="some_future_group", scope="app",
                               state="off", detail="")
    assert row.friendly == "Some future group"


def test_collect_rows_all_have_friendly_text(apps_root):
    manifest_admin.set_permission("testapp", "full_access", True)
    rows = gates_panel.collect("testapp")
    assert all(r.friendly for r in rows)


def test_binding_row_friendly_names_the_issuer(apps_root):
    from willow_mcp import identity_binding

    identity_binding.propose_binding("google", "sub1", "u@e.com")
    row = _row(gates_panel.collect("testapp"), "binding.google__sub1")
    assert "google" in row.friendly.lower()
    assert row.label == "identity binding (google)"  # exact technical form kept


def test_render_tui_includes_friendly_names_and_raw_labels(apps_root):
    manifest_admin.set_permission("testapp", "store_read", True)
    rows = gates_panel.collect("testapp")
    out = gates_panel.render_tui(rows, color=False)
    assert "View saved notes" in out
    assert "store_read" in out  # raw name still visible for CLI/scripting use


def test_render_html_payload_includes_friendly_field(apps_root):
    manifest_admin.set_permission("testapp", "store_read", True)
    rows = gates_panel.collect("testapp")
    html = gates_panel.render_html(rows, "2026-01-01T00:00:00+00:00")
    start = html.index("const ROWS = ") + len("const ROWS = ")
    end = html.index(";\n", start)
    payload = json.loads(html[start:end])
    row = next(r for r in payload if r["id"] == "perm.testapp.store_read")
    assert row["friendly"] == "View saved notes"
    assert row["label"] == "store_read"


# ── category grouping ────────────────────────────────────────────────────────

def test_category_permission_group():
    row = gates_panel.GateRow(id="perm.app.store_read", label="store_read",
                               scope="app", state="off", detail="")
    assert row.category == "permissions"


def test_category_task_net_and_integration_net_are_egress_not_permissions():
    """task_net/integration_net are perm.* by id shape but belong with the
    lease and consent — they're the capability half of the egress decision."""
    for label in (NET_PERMISSION, INTEGRATION_NET_PERMISSION):
        row = gates_panel.GateRow(id=f"perm.app.{label}", label=label,
                                   scope="app", state="off", detail="")
        assert row.category == "egress"


def test_category_consent_and_lease_are_egress():
    consent_row = gates_panel.GateRow(id="consent.internet", label="consent.internet",
                                       scope="global", state="off", detail="")
    lease_row = gates_panel.GateRow(id="lease.app", label="egress lease",
                                     scope="app", state="off", detail="")
    assert consent_row.category == "egress"
    assert lease_row.category == "egress"


def test_category_binding_is_identity():
    row = gates_panel.GateRow(id="binding.google__sub1", label="identity binding (google)",
                               scope="app", state="off", detail="")
    assert row.category == "identity"


def test_category_worker_and_env_flags_are_system():
    for row_id in ("worker", "strict_trust_root", "severance", "human_orchestrator"):
        row = gates_panel.GateRow(id=row_id, label=row_id, scope="global",
                                   state="off", detail="")
        assert row.category == "system"


def test_group_by_category_skips_empty_categories_and_follows_order(apps_root):
    manifest_admin.set_permission("testapp", "store_read", True)
    rows = gates_panel.collect("testapp")
    grouped = gates_panel.group_by_category(rows)
    keys = [key for key, _, _ in grouped]
    assert keys == sorted(keys, key=lambda k: [c for c, _ in gates_panel.CATEGORY_ORDER].index(k))
    assert set(keys) <= {"egress", "build", "system", "identity", "permissions"}
    assert all(group for _, _, group in grouped)  # no empty buckets


# ── build leases ─────────────────────────────────────────────────────────────

def test_collect_emits_a_row_per_earn_first_family(apps_root):
    """Every family in the roster gets a row, dry or leased."""
    rows = gates_panel.collect()
    family_row_ids = {r.id for r in rows if r.id.startswith("build.")}
    expected = {f"build.{fam}" for fam, _ in build_lease.EARN_FIRST_ROSTER}
    assert expected.issubset(family_row_ids)


def test_dry_family_row_is_off_with_grant_build_action(apps_root):
    row = _row(gates_panel.collect(), "build.workflow")
    assert row.state == "off"
    assert row.timer_shape == "lease"
    assert row.action_cli and "grant-build workflow" in row.action_cli
    assert row.category == "build"


def test_active_build_lease_flips_the_row_to_on_with_a_timer(apps_root):
    build_lease.grant("workflow", 1800, issuer="operator",
                      reason="ship the multi-phase engine")
    row = _row(gates_panel.collect(), "build.workflow")
    assert row.state == "on"
    assert row.timer_shape == "lease"
    assert row.remaining_seconds is not None and row.remaining_seconds <= 1800
    assert row.expires_at
    assert row.action_cli == "willow-mcp revoke-build workflow"
    assert "operator" in row.detail
    assert "multi-phase" in row.detail


def test_build_lease_outside_the_roster_is_still_surfaced(apps_root):
    """Silent invisibility is what a status readout must not do — a lease
    granted on a family not yet in the doc still appears."""
    build_lease.grant("brand-new-family", 600, issuer="op",
                      reason="one-off")
    row = _row(gates_panel.collect(), "build.brand-new-family")
    assert row.state == "on"
    assert "not in EARN_FIRST_ROSTER" in row.detail


def test_state_label_build_active(apps_root):
    row = gates_panel.GateRow(id="build.workflow", label="build lease",
                              scope="workflow", state="on", detail="")
    assert row.state_label == "ACTIVE"


def test_state_label_build_off(apps_root):
    row = gates_panel.GateRow(id="build.workflow", label="build lease",
                              scope="workflow", state="off", detail="")
    assert row.state_label == "NONE"


def test_render_tui_carries_the_build_heading(apps_root):
    out = gates_panel.render_tui(gates_panel.collect(), color=False)
    assert "Earn-first build leases" in out
    assert "build lease" in out


# ── state_label — what "on"/"off" means, in words ───────────────────────────

@pytest.mark.parametrize("row_id,state,expected", [
    ("perm.app.store_read", "on", "GRANTED"),
    ("perm.app.store_read", "off", "NOT GRANTED"),
    ("consent.internet", "on", "ALLOWED"),
    ("consent.internet", "off", "BLOCKED"),
    ("lease.app", "on", "ACTIVE"),
    ("lease.app", "off", "NONE"),
    ("binding.google__sub1", "on", "CONFIRMED"),
    ("binding.google__sub1", "off", "PENDING"),
    ("worker", "on", "RUNNING"),
    ("worker", "warn", "STALLED"),
    ("worker", "off", "STOPPED"),
    ("strict_trust_root", "on", "ENABLED"),
    ("strict_trust_root", "off", "DISABLED"),
])
def test_state_label_says_what_on_off_means(row_id, state, expected):
    row = gates_panel.GateRow(id=row_id, label=row_id, scope="x", state=state, detail="")
    assert row.state_label == expected


def test_state_label_explicit_override_wins():
    row = gates_panel.GateRow(id="perm.app.x", label="x", scope="app", state="on",
                               detail="", state_label="CUSTOM")
    assert row.state_label == "CUSTOM"


def test_render_tui_groups_by_category_with_headings(apps_root):
    manifest_admin.set_permission("testapp", "store_read", True)
    rows = gates_panel.collect("testapp")
    out = gates_panel.render_tui(rows, color=False)
    assert "Egress & network" in out
    assert "Permissions" in out
    assert "GRANTED" in out or "NOT GRANTED" in out


def test_render_html_payload_includes_category_and_state_label(apps_root):
    manifest_admin.set_permission("testapp", "store_read", True)
    rows = gates_panel.collect("testapp")
    html = gates_panel.render_html(rows, "2026-01-01T00:00:00+00:00")
    start = html.index("const ROWS = ") + len("const ROWS = ")
    end = html.index(";\n", start)
    payload = json.loads(html[start:end])
    row = next(r for r in payload if r["id"] == "perm.testapp.store_read")
    assert row["category"] == "permissions"
    assert row["state_label"] == "GRANTED"


def test_render_html_uses_shared_dashboard_renderer(apps_root):
    manifest_admin.set_permission("testapp", "store_read", True)
    rows = gates_panel.collect("testapp")
    html = gates_panel.render_html(rows, "2026-01-01T00:00:00+00:00")
    assert "renderDashboard(" in html
    assert 'id="toast"' in html
