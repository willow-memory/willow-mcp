"""Tests for the steward as its own principal (sealed 163b9a70, dispatch
4326FDFE; reworked dispatch D7BD9FE2 per Loki's audit 207B3590). app_id
willow-bot, its own permission groups, never orchestrator, never
grove_relay. No test touches a live WILLOW_HOME — the `apps_root` fixture
(mirroring tests/test_gate.py's own) points WILLOW_MCP_APPS_ROOT at a
throwaway tmp_path for every test in this module.
"""

import json
import re

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


# ── the 13-verb / 17-site table Loki re-derived (207B3590 F1), pinned ────
#
# (verb, "file.py:line[,line...]", steward group it must live in). One row
# per DISTINCT verb (17 call sites collapse onto 13 verbs); diagnostic_summary
# is deliberately absent — it is ungated (no @_guarded) so it needs no group.
# Line numbers are willow-bot main (3a34f46); D56B17E7's tree has the same
# call sites at different (cited-in-207B3590) line numbers — content
# identical, only shifted.
STEWARD_TICK_VERBS = [
    ("human_required_list", "heartbeat.py:30", "steward_read"),
    ("seal_drain", "heartbeat.py:32", "steward_sweep"),
    ("net_authority_drain", "heartbeat.py:33", "steward_sweep"),
    ("fleet_health", "heartbeat.py:28", "steward_read"),
    ("commitment_surface", "heartbeat.py:29", "steward_read"),
    ("envelope_retire_sweep", "heartbeat.py:41", "steward_sweep"),
    ("gitsync_sweep", "tick.py:2745", "steward_sweep"),
    ("human_required_enqueue", "tick.py:2100,1511", "steward_human_loop"),
    ("human_required_resolve", "tick.py:2141,2360,2476", "steward_human_loop"),
    ("store_put", "tick.py:464,2914; deposits.py:518", "steward_store_write"),
    ("store_delete", "tick.py:442", "steward_store_write"),
    ("gap_resolve", "tick.py:2932", "steward_gap_resolve"),
    # dispatch_send is a real tick-time verb (run_audit, tick.py:295/311) but
    # its group is the desk's open policy question — see steward_dispatch's
    # own tests below. Grove writes (grove_send_message etc.) ride
    # grove_write, granted by a separate pair (f46474ee), not a steward_*
    # group, so they are out of this table's scope.
]


@pytest.mark.parametrize("verb,site,group", STEWARD_TICK_VERBS, ids=[v for v, _, _ in STEWARD_TICK_VERBS])
def test_every_steward_tick_verb_is_in_its_named_group(verb, site, group):
    assert verb in gate.PERMISSION_GROUPS[group], (
        f"{verb} (steward call site {site}) must be in gate.PERMISSION_GROUPS[{group!r}]"
    )


def test_steward_full_grant_reaches_every_tick_verb_except_dispatch(apps_root):
    """The manifest the template ships (minus steward_dispatch, the open
    question) must let willow-bot actually make every one of Loki's 13
    calls except dispatch_send."""
    _write_manifest(
        apps_root, human_session.STEWARD_APP_ID,
        ["steward_sweep", "steward_read", "steward_human_loop",
         "steward_store_write", "steward_gap_resolve", "grove_read", "grove_write"],
    )
    for verb, site, _group in STEWARD_TICK_VERBS:
        assert gate.permitted(human_session.STEWARD_APP_ID, verb) is True, (
            f"{verb} (steward call site {site}) must be reachable under the shipped template"
        )


# ── steward_sweep ────────────────────────────────────────────────────────

STEWARD_SWEEP_TOOLS = (
    "seal_drain", "net_authority_drain", "envelope_retire_sweep",
    "gitsync_sweep",
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


def test_gitsync_sweep_no_longer_rides_envelope_apply():
    """Pair 163b9a70 split gitsync_sweep off the shared `envelope_apply`
    gate name (server.py) so a manifest granting steward_sweep never also
    unlocks envelope authoring / unit.install / unit.reload / PR open or
    update the way granting the old shared `envelope_apply` group would
    have. Pin both directions of the split."""
    assert "gitsync_sweep" not in gate.PERMISSION_GROUPS["envelope_apply"]
    # The human orchestrator seat must be unaffected by the split.
    assert "gitsync_sweep" in gate.PERMISSION_GROUPS["orchestrator"]
    assert "gitsync_sweep" in gate.PERMISSION_GROUPS["full_access"]


def test_git_pull_execute_is_not_in_steward_sweep():
    """Loki F2: no willow-bot call site reaches git_pull_execute
    (gitsync_sweep calls pull_executor.sweep_triggers directly, server-side)
    — the first cut granted an unused EXECUTE-class verb; dropped. It stays
    reachable via orchestrator/full_access for the human seat, unchanged."""
    assert "git_pull_execute" not in gate.PERMISSION_GROUPS["steward_sweep"]
    assert "git_pull_execute" in gate.PERMISSION_GROUPS["orchestrator"]
    assert "git_pull_execute" in gate.PERMISSION_GROUPS["full_access"]


def test_steward_sweep_grants_nothing_beyond_its_four_verbs(apps_root):
    """Granting steward_sweep must not incidentally unlock envelope
    authoring, dispatch, git_pull_execute, or anything orchestrator-only."""
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, ["steward_sweep"])
    for forbidden in ("envelope_apply", "dispatch_send", "frank_append",
                      "unit_install_execute", "unit_reload_execute",
                      "pr_open_execute", "pr_update_execute", "git_pull_execute"):
        assert gate.permitted(human_session.STEWARD_APP_ID, forbidden) is False


# ── steward_read ─────────────────────────────────────────────────────────

def test_steward_read_group_covers_every_heartbeat_read():
    assert gate.PERMISSION_GROUPS["steward_read"] == frozenset({
        "human_required_list", "fleet_health", "commitment_surface",
    })


@pytest.mark.parametrize("tool", ["human_required_list", "fleet_health", "commitment_surface"])
def test_steward_under_steward_read_passes(apps_root, tool):
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, ["steward_read"])
    assert gate.permitted(human_session.STEWARD_APP_ID, tool) is True


@pytest.mark.parametrize("tool", ["human_required_list", "fleet_health", "commitment_surface"])
def test_steward_without_steward_read_is_eperm(apps_root, tool):
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, ["steward_sweep"])
    assert gate.permitted(human_session.STEWARD_APP_ID, tool) is False


def test_steward_read_does_not_grant_the_siblings_of_its_source_groups(apps_root):
    """Deliberately narrower than human_loop_read/fleet_read/commitment_read
    — human_attestation_list, frank_read, frank_verify, bot_status,
    pr_checks_read, commitment_list are none of them tick-path calls."""
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, ["steward_read"])
    for forbidden in ("human_attestation_list", "frank_read", "frank_verify",
                      "bot_status", "pr_checks_read", "commitment_list"):
        assert gate.permitted(human_session.STEWARD_APP_ID, forbidden) is False


# ── steward_human_loop ───────────────────────────────────────────────────

def test_steward_human_loop_group_is_enqueue_and_resolve_only():
    assert gate.PERMISSION_GROUPS["steward_human_loop"] == frozenset({
        "human_required_enqueue", "human_required_resolve",
    })


def test_steward_under_steward_human_loop_passes_enqueue_and_resolve(apps_root):
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, ["steward_human_loop"])
    assert gate.permitted(human_session.STEWARD_APP_ID, "human_required_enqueue") is True
    assert gate.permitted(human_session.STEWARD_APP_ID, "human_required_resolve") is True


def test_steward_without_steward_human_loop_is_eperm(apps_root):
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, ["steward_sweep"])
    assert gate.permitted(human_session.STEWARD_APP_ID, "human_required_enqueue") is False
    assert gate.permitted(human_session.STEWARD_APP_ID, "human_required_resolve") is False


def test_steward_human_loop_does_not_grant_attestation_create(apps_root):
    """The steward raises and clears its own hand; it never attests on
    anyone's behalf (human_loop_write's third member)."""
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, ["steward_human_loop"])
    assert gate.permitted(human_session.STEWARD_APP_ID, "human_attestation_create") is False


# ── steward_store_write ──────────────────────────────────────────────────

def test_steward_store_write_group_is_put_and_delete_only():
    assert gate.PERMISSION_GROUPS["steward_store_write"] == frozenset({
        "store_put", "store_delete",
    })


def test_steward_under_steward_store_write_passes(apps_root):
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, ["steward_store_write"])
    assert gate.permitted(human_session.STEWARD_APP_ID, "store_put") is True
    assert gate.permitted(human_session.STEWARD_APP_ID, "store_delete") is True


def test_steward_without_steward_store_write_is_eperm(apps_root):
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, ["steward_sweep"])
    assert gate.permitted(human_session.STEWARD_APP_ID, "store_put") is False
    assert gate.permitted(human_session.STEWARD_APP_ID, "store_delete") is False


def test_steward_store_write_excludes_update_purge_and_seed_mirror(apps_root):
    """Narrower than the general store_write group — store_update,
    store_purge_collection, agent_seed_mirror are none of them tick calls."""
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, ["steward_store_write"])
    for forbidden in ("store_update", "store_purge_collection", "agent_seed_mirror"):
        assert gate.permitted(human_session.STEWARD_APP_ID, forbidden) is False


def test_steward_store_scope_is_the_two_real_collections():
    """The shipped template scopes store access to exactly the two
    collections the tick writes — willow_bot_ci_deposits (deposits.py:33)
    and idea_landings (tick.py:2784) — never a hyphenated 'willow-bot_*'
    glob that matched neither (Loki F1c)."""
    import pathlib

    manifest_path = (
        pathlib.Path(__file__).resolve().parent.parent
        / "src" / "willow_mcp" / "bundle" / "config" / "seats" / "willow-bot.manifest.json"
    )
    data = json.loads(manifest_path.read_text())
    assert set(data["store_scope"]) == {"willow_bot_ci_deposits", "idea_landings"}
    assert set(data["store_write"]) == {"willow_bot_ci_deposits", "idea_landings"}


# ── steward_gap_resolve ──────────────────────────────────────────────────

def test_steward_gap_resolve_group_is_gap_resolve_only():
    assert gate.PERMISSION_GROUPS["steward_gap_resolve"] == frozenset({"gap_resolve"})


def test_steward_under_steward_gap_resolve_passes(apps_root):
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, ["steward_gap_resolve"])
    assert gate.permitted(human_session.STEWARD_APP_ID, "gap_resolve") is True


def test_steward_without_steward_gap_resolve_is_eperm(apps_root):
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, ["steward_sweep"])
    assert gate.permitted(human_session.STEWARD_APP_ID, "gap_resolve") is False


def test_steward_gap_resolve_excludes_log_delete_and_purge(apps_root):
    """Narrower than gap_write — gap_log/gap_delete/gap_purge_topic/
    gap_retopic are none of them tick calls; same reasoning as
    gap_promote/schema_admin staying off gap_write."""
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, ["steward_gap_resolve"])
    for forbidden in ("gap_log", "gap_delete", "gap_purge_topic", "gap_retopic"):
        assert gate.permitted(human_session.STEWARD_APP_ID, forbidden) is False


# ── steward_dispatch — the desk's open policy question ──────────────────

def test_steward_dispatch_group_exists_and_is_dispatch_send_only():
    """Loki F4: dispatch_send IS a verb the steward ticks (run_audit); the
    group is BUILT so it is not silently unreachable while the desk
    decides, but it is deliberately NOT in the shipped template's default
    permissions (see the manifest template's own 'question for the desk'
    comment and this dispatch's handoff) — granting it is a sealed-pair
    decision, not this rework's to make."""
    assert gate.PERMISSION_GROUPS["steward_dispatch"] == frozenset({"dispatch_send"})


def test_steward_under_steward_dispatch_group_would_pass_if_granted(apps_root):
    """The group mechanically works — gate.permitted() has no argument-level
    bounds, so this also demonstrates the UNBOUNDED nature of the grant
    (no to_app/role restriction is enforced here or anywhere else today)."""
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, ["steward_dispatch"])
    assert gate.permitted(human_session.STEWARD_APP_ID, "dispatch_send") is True


def test_shipped_template_does_not_grant_steward_dispatch():
    """The open policy question stays open: the template this pair ships
    must not itself decide it by including steward_dispatch in the default
    permission set."""
    import pathlib

    manifest_path = (
        pathlib.Path(__file__).resolve().parent.parent
        / "src" / "willow_mcp" / "bundle" / "config" / "seats" / "willow-bot.manifest.json"
    )
    data = json.loads(manifest_path.read_text())
    assert "steward_dispatch" not in data["permissions"]
    assert "dispatch_send" not in data["permissions"]


# ── never orchestrator, never full_access, never grove_relay ───────────

_FULL_STEWARD_GRANT = [
    "steward_sweep", "steward_read", "steward_human_loop",
    "steward_store_write", "steward_gap_resolve", "grove_read", "grove_write",
]


def test_steward_full_grant_still_excludes_orchestrator_powers(apps_root):
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, _FULL_STEWARD_GRANT)
    for forbidden in ("dispatch_accept", "handoff_write_v4",
                      "verify_handoff", "agent_clear", "envelope_apply",
                      "frank_append", "envelope_propose", "envelope_ratify"):
        assert gate.permitted(human_session.STEWARD_APP_ID, forbidden) is False


def test_steward_manifest_never_lists_grove_relay(apps_root):
    """grove_relay is a capability flag, not a permission-group tool name
    (test_authority_surface.py's test_no_capability_flag_is_a_member_of_any_
    permission_group already pins that no group anywhere carries it) — the
    steward's own template must not list it either."""
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, _FULL_STEWARD_GRANT)
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


# ── F3: the manifest.create fixture line parses under trust_owner_verbs'
# own grammar ──────────────────────────────────────────────────────────
#
# worktrees/feat-trust-owner-verbs is a SIBLING branch this dispatch may not
# edit or import from (cross-worktree import is not possible for an
# unmerged branch either). The regex below is a literal COPY of
# trust_owner_verbs._CREATE_RE, sha e77caf58ebff156f8b96daf38532e78a8e1e8299
# (src/willow_mcp/trust_owner_verbs.py:489-494, HEAD of
# worktrees/feat-trust-owner-verbs as of dispatch D7BD9FE2) — read-only, cited
# so drift between the two copies is visible the next time either changes.
_CREATE_RE_COPY = re.compile(
    r"^create seat (?P<app_id>[A-Za-z0-9_\-]+) "
    r"store_scope \[(?P<store_scope>[^\]]*)\] "
    r"store_write \[(?P<store_write>[^\]]*)\] "
    r"permissions \[(?P<permissions>[^\]]*)\]$"
)


def _parse_list(raw: str) -> list[str]:
    return [p.strip() for p in raw.split(",") if p.strip()]


def test_manifest_create_fixture_line_parses_under_the_create_grammar():
    line = (
        "create seat willow-bot "
        "store_scope [willow_bot_ci_deposits, idea_landings] "
        "store_write [willow_bot_ci_deposits, idea_landings] "
        "permissions [steward_sweep, steward_read, steward_human_loop, "
        "steward_store_write, steward_gap_resolve, grove_read, grove_write]"
    )
    m = _CREATE_RE_COPY.match(line)
    assert m is not None, "the template's manifest.create fixture line must parse"
    assert m.group("app_id") == "willow-bot"
    assert _parse_list(m.group("store_scope")) == ["willow_bot_ci_deposits", "idea_landings"]
    assert _parse_list(m.group("store_write")) == ["willow_bot_ci_deposits", "idea_landings"]
    perms = _parse_list(m.group("permissions"))
    assert set(perms) == {
        "steward_sweep", "steward_read", "steward_human_loop",
        "steward_store_write", "steward_gap_resolve", "grove_read", "grove_write",
    }
    # steward_dispatch must not ride the create line either — same open
    # question as the JSON template itself.
    assert "steward_dispatch" not in perms
    assert "dispatch_send" not in perms


def test_shipped_manifest_json_permissions_match_the_create_fixture_permissions():
    """The JSON template's permissions/store_scope/store_write must be the
    SAME set the create fixture line names — one drifting from the other is
    exactly the F3 defect this rework fixes. Compared as plain data (no
    regex re-parse of file content — that shape is what test_scans_fire.py's
    inline-scan house rule flags as needing a planted helper, and a second
    parse of self-built text from the same dict is circular anyway; the
    grammar itself is already exercised on a hand-written line above)."""
    import pathlib

    manifest_path = (
        pathlib.Path(__file__).resolve().parent.parent
        / "src" / "willow_mcp" / "bundle" / "config" / "seats" / "willow-bot.manifest.json"
    )
    data = json.loads(manifest_path.read_text())
    assert set(data["permissions"]) == {
        "steward_sweep", "steward_read", "steward_human_loop",
        "steward_store_write", "steward_gap_resolve", "grove_read", "grove_write",
    }
    assert set(data["store_scope"]) == {"willow_bot_ci_deposits", "idea_landings"}
    assert set(data["store_write"]) == {"willow_bot_ci_deposits", "idea_landings"}


# ── item 5 / F4: dispatch_send is absent from the settled steward groups ─

def test_dispatch_send_is_not_in_any_settled_steward_group():
    """dispatch_send lives ONLY in steward_dispatch (the open question) —
    never in steward_sweep/steward_read/steward_human_loop/
    steward_store_write/steward_gap_resolve."""
    for group in ("steward_sweep", "steward_read", "steward_human_loop",
                  "steward_store_write", "steward_gap_resolve"):
        assert "dispatch_send" not in gate.PERMISSION_GROUPS[group]


def test_steward_shipped_template_grant_cannot_dispatch(apps_root):
    _write_manifest(apps_root, human_session.STEWARD_APP_ID, _FULL_STEWARD_GRANT)
    assert gate.permitted(human_session.STEWARD_APP_ID, "dispatch_send") is False
