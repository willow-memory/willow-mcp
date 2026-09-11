"""whoami's tools_allowed must be a REUSE of the gate's own per-call predicate
(gate.permitted), not a second, independent expansion of PERMISSION_GROUPS.

Before this fix, whoami derived tools_allowed by expanding PERMISSION_GROUPS
and subtracting deny_tools. A tool gated by a name-level check that is a
member of no permission group — git_push_execute, gated as envelope_apply via
`@_guarded("envelope_apply")` — passed the real gate (gate.permitted) but was
invisible to that derivation: no group's frozenset contains the literal
"git_push_execute", so it never appeared in tools_allowed, even for a manifest
that could actually call it. Gap 1f7d1d62207b, slice 2 of 5ecb87cfdf56.
"""
import json

import pytest

from willow_mcp import server, gate


@pytest.fixture
def apps_root(tmp_path, monkeypatch):
    root = tmp_path / "mcp_apps"
    root.mkdir()
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(root))
    monkeypatch.delenv("WILLOW_MCP_ENFORCE_BINDING", raising=False)
    server._CALL_CREDENTIAL.set(None)
    return root


def _write_manifest(apps_root, app_id, permissions, deny_tools=None, **extra):
    app_dir = apps_root / app_id
    app_dir.mkdir(parents=True, exist_ok=True)
    manifest = {"permissions": permissions, **extra}
    if deny_tools is not None:
        manifest["deny_tools"] = deny_tools
    (app_dir / "manifest.json").write_text(json.dumps(manifest))


def _whoami(**kwargs):
    fn = getattr(server.whoami, "fn", server.whoami)
    return fn(**kwargs)


# ── the git_push_execute gap ────────────────────────────────────────────────

def test_git_push_execute_is_gated_as_envelope_apply_by_name():
    # Pins the exact mechanism the rest of this file exercises: git_push_execute
    # is registered under its own name but the gate checks "envelope_apply" for
    # it — a name-level stand-in check, not membership in any group.
    catalogue = server._gate_tool_catalogue()
    assert catalogue["git_push_execute"] == "envelope_apply"
    assert "git_push_execute" not in {
        name for group in gate.PERMISSION_GROUPS.values() for name in group
    }


def test_gate_permitted_admits_git_push_execute_via_envelope_apply(apps_root):
    _write_manifest(apps_root, "pusher", ["envelope_apply"])
    # The real per-call predicate the dispatch pipeline runs: _guarded stores
    # "envelope_apply" as the gate-check name for git_push_execute.
    assert gate.permitted("pusher", "envelope_apply") is True


def test_whoami_lists_git_push_execute_when_gate_admits_it(apps_root):
    _write_manifest(apps_root, "pusher", ["envelope_apply"])
    out = _whoami(app_id="pusher")
    assert "git_push_execute" in out["tools_allowed"]


def test_whoami_names_git_push_execute_as_a_name_gated_orphan(apps_root):
    _write_manifest(apps_root, "pusher", ["envelope_apply"])
    out = _whoami(app_id="pusher")
    assert "git_push_execute" in out["name_gated_orphans"]
    # Reporting-only: orphan membership doesn't remove it from tools_allowed.
    assert "git_push_execute" in out["tools_allowed"]


def test_whoami_omits_git_push_execute_without_the_grant(apps_root):
    _write_manifest(apps_root, "reader", ["store_read"])
    out = _whoami(app_id="reader")
    assert "git_push_execute" not in out["tools_allowed"]
    assert "git_push_execute" not in out["name_gated_orphans"]


# ── listing == what the gate admits, for a representative manifest ─────────

def test_tools_allowed_equals_gate_admitted_set_for_full_access(apps_root):
    _write_manifest(apps_root, "boss", ["full_access", "envelope_apply"])
    out = _whoami(app_id="boss")
    catalogue = server._gate_tool_catalogue()
    expected = {
        registered
        for registered, gate_name in catalogue.items()
        if gate.permitted("boss", gate_name)
    }
    assert set(out["tools_allowed"]) == expected
    assert expected  # sanity: this manifest actually admits something


def test_tools_allowed_equals_gate_admitted_set_for_narrow_manifest(apps_root):
    _write_manifest(apps_root, "narrow", ["store_read", "fleet_status"])
    out = _whoami(app_id="narrow")
    catalogue = server._gate_tool_catalogue()
    expected = {
        registered
        for registered, gate_name in catalogue.items()
        if gate.permitted("narrow", gate_name)
    }
    assert set(out["tools_allowed"]) == expected


# ── deny_tools still subtracts from the listing ─────────────────────────────

def test_deny_tools_still_removes_a_tool_from_the_listing(apps_root):
    _write_manifest(apps_root, "denied", ["store_read"], deny_tools=["store_get"])
    out = _whoami(app_id="denied")
    assert "store_get" not in out["tools_allowed"]
    assert "store_search" in out["tools_allowed"]  # sibling in the same group stays


def test_deny_tools_removes_git_push_execute_even_via_the_orphan_path(apps_root):
    # deny_tools names the registered tool, not the gate-check name it maps
    # to — gate.permitted() applies deny_tools against tool_name, i.e. the
    # gate-check name ("envelope_apply"), so denying "envelope_apply" is what
    # actually removes git_push_execute here (it shares that check).
    _write_manifest(apps_root, "pusher", ["envelope_apply"], deny_tools=["envelope_apply"])
    out = _whoami(app_id="pusher")
    assert "git_push_execute" not in out["tools_allowed"]
    assert "git_push_execute" not in out["name_gated_orphans"]
    assert "envelope_apply" not in out["tools_allowed"]
