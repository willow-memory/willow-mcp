"""Tests for the steward as its own principal (sealed 163b9a70, dispatch
4326FDFE): app_id willow-bot, its own permission groups, never orchestrator,
never grove_relay. No test touches a live WILLOW_HOME — the `apps_root`
fixture (mirroring tests/test_gate.py's own) points WILLOW_MCP_APPS_ROOT at
a throwaway tmp_path for every test in this module.
"""

import json

import pytest

from willow_mcp import gate, grove_tools, human_session


@pytest.fixture
def apps_root(tmp_path, monkeypatch):
    root = tmp_path / "mcp_apps"
    root.mkdir()
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(root))
    return root


def _write_manifest(apps_root, app_id, permissions, store_scope=None):
    app_dir = apps_root / app_id
    app_dir.mkdir(parents=True, exist_ok=True)
    manifest = {"permissions": permissions}
    if store_scope is not None:
        manifest["store_scope"] = store_scope
    (app_dir / "manifest.json").write_text(json.dumps(manifest))


# ── STEWARD_APP_ID / is_orchestrator_app ────────────────────────────────

def test_steward_app_id_is_willow_bot():
    assert human_session.STEWARD_APP_ID == "willow-bot"


def test_steward_is_never_the_orchestrator_app():
    """willow-bot must never satisfy is_orchestrator_app — it is a named
    SECOND principal, not a synonym or alias for the human seat."""
    assert human_session.is_orchestrator_app(human_session.STEWARD_APP_ID) is False


def test_orchestrator_write_denial_never_fires_for_the_steward():
    """orchestrator_write_denial only ever gates app_id == 'willow' (see its
    own `if not is_orchestrator_app(app_id): return None` guard) — a steward
    call is never subject to the human-attestation wall built for
    prompt-injection defense of the willow seat; its authority is entirely
    manifest/group driven through gate.permitted instead."""
    for tool in ("dispatch_send", "envelope_apply", "frank_append"):
        assert human_session.orchestrator_write_denial(
            human_session.STEWARD_APP_ID, tool, serve_mode=False,
        ) is None


# ── steward_sweep ────────────────────────────────────────────────────────

STEWARD_SWEEP_TOOLS = (
    "seal_drain", "net_authority_drain", "envelope_retire_sweep",
    "gitsync_sweep", "git_pull_execute",
)


def test_steward_sweep_group_contains_exactly_the_tick_verbs():
    assert gate.PERMISSION_GROUPS["steward_sweep"] == frozenset(STEWARD_SWEEP_TOOLS)


@pytest.mark.parametrize("tool", STEWARD_SWEEP_TOOLS)
def test_steward_under_steward_sweep_group_passes(apps_root, tool):
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, ["steward_sweep"])
    assert gate.permitted(human_session.STEWARD_APP_ID, tool) is True


@pytest.mark.parametrize("tool", STEWARD_SWEEP_TOOLS)
def test_steward_without_steward_sweep_group_is_eperm(apps_root, tool):
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, ["grove_read"])
    assert gate.permitted(human_session.STEWARD_APP_ID, tool) is False


def test_gitsync_sweep_and_git_pull_execute_no_longer_ride_envelope_apply():
    """Pair 163b9a70 split these two off the shared `envelope_apply` gate
    name (server.py) so a manifest granting steward_sweep never also
    unlocks envelope authoring / unit.install / unit.reload / PR open or
    update the way granting the old shared `envelope_apply` group would
    have. Pin both directions of the split."""
    assert "gitsync_sweep" not in gate.PERMISSION_GROUPS["envelope_apply"]
    assert "git_pull_execute" not in gate.PERMISSION_GROUPS["envelope_apply"]
    # The human orchestrator seat must be unaffected by the split: both
    # names ride `orchestrator` and `full_access` alongside the old
    # `envelope_apply` entry.
    assert {"gitsync_sweep", "git_pull_execute"} <= gate.PERMISSION_GROUPS["orchestrator"]
    assert {"gitsync_sweep", "git_pull_execute"} <= gate.PERMISSION_GROUPS["full_access"]


def test_steward_sweep_grants_nothing_beyond_its_five_verbs(apps_root):
    """Granting steward_sweep must not incidentally unlock envelope
    authoring, dispatch, or anything orchestrator-only."""
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, ["steward_sweep"])
    for forbidden in ("envelope_apply", "dispatch_send", "frank_append",
                      "unit_install_execute", "unit_reload_execute",
                      "pr_open_execute", "pr_update_execute"):
        assert gate.permitted(human_session.STEWARD_APP_ID, forbidden) is False


# ── steward_read / steward_enqueue ──────────────────────────────────────

def test_steward_read_group_is_human_required_list_only():
    assert gate.PERMISSION_GROUPS["steward_read"] == frozenset({"human_required_list"})


def test_steward_enqueue_group_is_human_required_enqueue_only():
    assert gate.PERMISSION_GROUPS["steward_enqueue"] == frozenset({"human_required_enqueue"})


def test_steward_under_steward_read_passes_human_required_list(apps_root):
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, ["steward_read"])
    assert gate.permitted(human_session.STEWARD_APP_ID, "human_required_list") is True


def test_steward_without_steward_read_is_eperm_on_human_required_list(apps_root):
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, ["steward_sweep"])
    assert gate.permitted(human_session.STEWARD_APP_ID, "human_required_list") is False


def test_steward_under_steward_enqueue_passes_human_required_enqueue(apps_root):
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, ["steward_enqueue"])
    assert gate.permitted(human_session.STEWARD_APP_ID, "human_required_enqueue") is True


def test_steward_enqueue_does_not_grant_resolve_or_attest(apps_root):
    """The steward raises a hand; it never clears its own queue item or
    attests on anyone's behalf (human_loop_write's other two members)."""
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, ["steward_enqueue"])
    assert gate.permitted(human_session.STEWARD_APP_ID, "human_required_resolve") is False
    assert gate.permitted(human_session.STEWARD_APP_ID, "human_attestation_create") is False


# ── never orchestrator, never full_access, never grove_relay ───────────

def test_steward_full_grant_still_excludes_orchestrator_powers(apps_root):
    _write_manifest(
        apps_root, human_session.STEWARD_APP_ID,
        ["steward_sweep", "steward_read", "steward_enqueue", "grove_read", "grove_write"],
    )
    for forbidden in ("dispatch_send", "dispatch_accept", "handoff_write_v4",
                      "verify_handoff", "agent_clear", "envelope_apply",
                      "frank_append", "envelope_propose", "envelope_ratify"):
        assert gate.permitted(human_session.STEWARD_APP_ID, forbidden) is False


def test_steward_manifest_never_lists_grove_relay(apps_root):
    """grove_relay is a capability flag, not a permission-group tool name
    (test_authority_surface.py's test_no_capability_flag_is_a_member_of_any_
    permission_group already pins that no group anywhere carries it) — the
    steward's own template must not list it either."""
    _write_manifest(
        apps_root, human_session.STEWARD_APP_ID,
        ["steward_sweep", "steward_read", "steward_enqueue", "grove_read", "grove_write"],
    )
    assert gate.grove_relay_permitted(human_session.STEWARD_APP_ID) is False


# ── Grove sender resolution / FRANK actor ───────────────────────────────

def test_resolve_grove_sender_for_steward_is_willow_bot():
    """No specialist registry row for willow-bot in a fresh environment —
    resolve_grove_sender falls back to app_id itself, so a message a human
    reads on #willow from the steward says willow-bot, never 'willow' and
    never 'Auto'."""
    assert grove_tools.resolve_grove_sender(human_session.STEWARD_APP_ID) == "willow-bot"


def test_steward_grove_send_message_sender_override_matches_self_is_free(apps_root, monkeypatch):
    """The steward posting with sender='willow-bot' (its own default,
    `_GROVE_SENDER_DEFAULT` in the live tick.py) is the free, no-override
    case in _resolve_sender_checked — it needs no grove_relay."""
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, ["grove_write"])
    monkeypatch.setattr(grove_tools, "get_pg", lambda: None)  # never reached
    who, err = grove_tools._resolve_sender_checked(
        human_session.STEWARD_APP_ID, "willow-bot",
    )
    assert err is None
    assert who == "willow-bot"


def test_steward_grove_send_message_as_willow_is_refused(apps_root, monkeypatch):
    """A steward call that passes sender= something other than its own
    resolved identity is refused without grove_relay — it must not be able
    to post AS 'willow', the operator's own seat name."""
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, ["grove_write"])
    who, err = grove_tools._resolve_sender_checked(
        human_session.STEWARD_APP_ID, "willow",
    )
    assert who is None
    assert err is not None
    assert err.get("error") == "sender_forbidden"


# ── item 5: dispatch_send is deliberately absent from every steward group ─

def test_dispatch_send_is_not_a_member_of_any_steward_group():
    for group in ("steward_sweep", "steward_read", "steward_enqueue"):
        assert "dispatch_send" not in gate.PERMISSION_GROUPS[group]


def test_steward_full_grant_cannot_dispatch(apps_root):
    _write_manifest(
        apps_root, human_session.STEWARD_APP_ID,
        ["steward_sweep", "steward_read", "steward_enqueue", "grove_read", "grove_write"],
    )
    assert gate.permitted(human_session.STEWARD_APP_ID, "dispatch_send") is False
