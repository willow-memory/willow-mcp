import io
import json
from pathlib import Path

from willow_mcp import dispatch, gate, registry, server
from willow_mcp import session_start_hook as ssh
from willow_mcp.db import Store
from willow_mcp.paths import mcp_app_dir
from willow_mcp.session_start_hook import handle


ALIASES = {
    "stack": "projects_willow_stack",
    "pm/portfolio": "projects_willow_pm_portfolio",
    "pm/milestones": "projects_willow_pm_milestones",
    "pa/commitments": "projects_willow_pa_commitments",
    "governance/flags": "projects_willow_governance_flags",
    "orient": "projects_willow_orient",
}


def _manifest(tmp_path, monkeypatch, app="willow", scope=None):
    root = tmp_path / "mcp_apps"
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(root))
    path = root / app / "manifest.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "permissions": ["full_access"],
                "store_scope": scope or ["projects_willow_*"],
                "collection_aliases": ALIASES,
            }
        )
    )


def test_manifest_compiler_carries_explicit_aliases():
    reg = registry.load_registry(prefer_home=False)
    row = registry.specialist_row("willow", registry=reg)
    manifest = registry.manifest_from_row(
        row, collection_aliases=reg["collection_aliases"]
    )
    assert manifest["collection_aliases"]["pm/portfolio"] == (
        "projects_willow_pm_portfolio"
    )


def test_aliases_resolve_explicitly_and_canonical_names_remain_available(
    tmp_path, monkeypatch
):
    _manifest(tmp_path, monkeypatch)
    assert gate.resolve_collection_alias("willow", "pm/portfolio") == (
        "projects_willow_pm_portfolio",
        None,
    )
    assert gate.resolve_collection_alias(
        "willow", "projects_willow_pm_portfolio"
    ) == ("projects_willow_pm_portfolio", None)
    assert gate.resolve_collection_alias("willow", "unknown/path")[0] is None


def test_alias_collision_fails_closed(tmp_path, monkeypatch):
    _manifest(tmp_path, monkeypatch)
    path = tmp_path / "mcp_apps" / "willow" / "manifest.json"
    data = json.loads(path.read_text())
    data["collection_aliases"] = {
        "first": "physical",
        "physical": "other",
    }
    path.write_text(json.dumps(data))
    assert gate.collection_aliases("willow") == {}


def test_identity_gate_runs_before_unknown_alias_error(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path / "missing"))
    result = server.store_list(app_id="unknown", collection="unknown/path")
    assert "gate denied" in result["items"][0]["error"]


def test_alias_scope_is_enforced_on_physical_target(tmp_path, monkeypatch):
    _manifest(tmp_path, monkeypatch, scope=["projects_willow_stack"])
    monkeypatch.setattr(server, "_store", Store(tmp_path / "store"))
    result = server.store_list(
        app_id="willow", collection="pm/portfolio"
    )
    assert "projects_willow_pm_portfolio" in result["items"][0]["error"]


def test_project_orientation_reads_every_declared_collection(
    tmp_path, monkeypatch
):
    _manifest(tmp_path, monkeypatch)
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    store = Store(tmp_path / "store")
    for physical in ALIASES.values():
        store.put(physical, {"kind": physical}, record_id="one")
    monkeypatch.setattr(server, "_store", store)
    project = tmp_path / "charter"
    project.mkdir()
    (project / "ORIENT.md").write_text("# Orient\n")

    entered = server.session_enter(
        app_id="willow",
        session_id="fresh",
        project="charter",
        workspace=str(project),
    )
    assert entered["entry_mode"] == "human_orchestrator"
    assert entered["orientation"]["orient"]["exists"] is True
    assert all(
        entered["orientation"]["records"][logical]
        for logical in (
            "stack",
            "pm/portfolio",
            "pm/milestones",
            "pa/commitments",
            "governance/flags",
        )
    )
    assert entered["orientation"]["frank"]["status"] == "not_present"


def test_project_handoffs_do_not_bleed(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    dispatch.session_handoff_write(
        "hanuman", "s1", narrative="alpha only", project="alpha"
    )
    dispatch.session_handoff_write(
        "hanuman", "s2", narrative="beta only", project="beta"
    )
    alpha = dispatch.latest_project_handoff("hanuman", "alpha")
    beta = dispatch.latest_project_handoff("hanuman", "beta")
    assert "alpha only" in alpha["content"]
    assert "beta only" not in alpha["content"]
    assert "beta only" in beta["content"]


def test_specialist_dispatch_session_receives_project_orientation(
    tmp_path, monkeypatch
):
    _manifest(tmp_path, monkeypatch, app="hanuman")
    monkeypatch.setattr(server, "_store", Store(tmp_path / "store"))
    sent = dispatch.dispatch_send(
        "willow", "hanuman", "# Build\n\nDo the work.", summary="build"
    )
    project = tmp_path / "project"
    project.mkdir()
    entered = server.session_enter(
        app_id="hanuman",
        session_id="dispatch-session",
        dispatch_id=sent["dispatch_id"],
        project="project",
        workspace=str(project),
    )
    assert entered["entry_mode"] == "dispatch"
    assert entered["orientation"]["collection_aliases"] == ALIASES
    assert entered["project"]["name"] == "project"


def test_session_start_bridge_invokes_session_enter_without_legacy_hook(
    monkeypatch
):
    seen = {}

    def enter(**kwargs):
        seen.update(kwargs)
        return {"entry_mode": "human", "persona": "voice context"}

    monkeypatch.setattr(server, "session_enter", enter)
    monkeypatch.setenv("WILLOW_APP_ID", "hanuman")
    result = handle({"session_id": "s", "workspace": "/workspace/project"})
    assert seen["workspace"] == "/workspace/project"
    assert "persona" in json.loads(result["additional_context"])


# ── §3.1 dispatch_read grant, pinned so compile-agents cannot erase it ───────

def test_hanuman_manifest_grants_dispatch_read():
    reg = registry.load_registry(prefer_home=False)
    row = registry.specialist_row("hanuman", registry=reg)
    manifest = registry.manifest_from_row(row, collection_aliases=reg["collection_aliases"])
    assert "dispatch_read" in manifest["permissions"], (
        "Hanuman must hold dispatch_read in the SOURCE registry, or the next "
        "compile-agents run erases the live permission repair (Loki C303AA2F §3.1)"
    )


# ── §3.2 explicit physical project scopes, fail-closed (no wildcard) ─────────

def test_orchestrator_scope_is_explicit_projects_not_wildcard():
    reg = registry.load_registry(prefer_home=False)
    scope = reg["orchestrator_seat"]["store_scope"]
    assert "projects_*" not in scope, "the broad projects_* wildcard must be gone"
    project_scopes = [s for s in scope if s.startswith("projects_")]
    assert project_scopes
    assert all(s.startswith("projects_willow_") and "*" not in s for s in project_scopes)
    # every declared alias target is covered by an explicit scope
    assert set(reg["collection_aliases"].values()) <= set(project_scopes)


# ── §3.3 hook: stable interpreter + fail-visible ─────────────────────────────

def test_cursor_hook_uses_a_stable_available_interpreter():
    hooks = Path(__file__).resolve().parents[1] / "src" / "willow_mcp" / "deploy" / "hooks.json"
    cmd = json.loads(hooks.read_text())["hooks"]["sessionStart"][0]["command"]
    assert "willow_mcp.session_start_hook" in cmd
    assert "python3" in cmd or "python" in cmd or "WILLOW_MCP_PYTHON" in cmd


def test_cursor_hook_registers_pre_tool_use_for_agent_shell():
    hooks = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "willow_mcp"
        / "deploy"
        / "hooks.json"
    )
    data = json.loads(hooks.read_text())
    matchers = {h["matcher"] for h in data["hooks"]["preToolUse"]}
    assert "Shell" in matchers
    assert "MCP:.*" in matchers


def test_cursor_hook_registers_session_end():
    hooks = Path(__file__).resolve().parents[1] / "deploy" / "cursor" / "hooks.json"
    data = json.loads(hooks.read_text())
    assert "sessionEnd" in data["hooks"]
    assert "session_stop_hook" in data["hooks"]["sessionEnd"][0]["command"]


def test_session_start_hook_fails_visibly(monkeypatch, capsys):
    monkeypatch.setattr(ssh.sys, "stdin", io.StringIO("this is not json"))
    ssh.main()
    captured = capsys.readouterr()
    assert "session_enter FAILED" in captured.err  # loud on stderr / logs
    payload = json.loads(captured.out)
    assert "FAILED" in payload["additional_context"]  # and in the session context


# ── §3.4 compile merges local policy, reports overrides (never silent) ───────

def test_compile_merges_local_keys_and_reports_overrides(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path / "mcp_apps"))
    reg = {
        "collection_aliases": {},
        "specialists": [{
            "agent_id": "hanuman", "role": "builder",
            "permissions": ["dispatch_read", "dispatch_write"],
            "deny_tools": [], "store_scope": ["hanuman_*"],
        }],
    }
    mpath = mcp_app_dir("hanuman") / "manifest.json"
    mpath.parent.mkdir(parents=True, exist_ok=True)
    mpath.write_text(json.dumps({
        "permissions": ["dispatch_write"],   # stale — must be refreshed
        "local_lease": "operator-added",      # local-only — must survive
    }))

    result = registry.compile_manifests(reg, only_missing=False)

    merged = json.loads(mpath.read_text())
    assert merged["local_lease"] == "operator-added"      # local policy preserved
    assert "dispatch_read" in merged["permissions"]        # registry field refreshed
    assert any("permissions" in o["keys"] for o in result["overridden"]), (
        "a registry field replacing a differing local value must be reported"
    )


def test_compile_creates_missing_manifest_with_no_override(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path / "mcp_apps"))
    reg = {"collection_aliases": {}, "specialists": [{
        "agent_id": "hanuman", "role": "builder",
        "permissions": ["dispatch_read"], "deny_tools": [], "store_scope": ["hanuman_*"],
    }]}
    result = registry.compile_manifests(reg, only_missing=False)
    assert result["overridden"] == []
    assert (mcp_app_dir("hanuman") / "manifest.json").exists()


# ── §3.5 collision-safe project identity ─────────────────────────────────────

def test_project_identity_is_collision_safe_across_workspaces(tmp_path):
    a = tmp_path / "a" / "charter"; a.mkdir(parents=True)
    b = tmp_path / "b" / "charter"; b.mkdir(parents=True)
    na = dispatch.project_context(workspace=str(a))["name"]
    nb = dispatch.project_context(workspace=str(b))["name"]
    assert na != nb                                   # same basename, distinct paths
    assert na.startswith("charter-") and nb.startswith("charter-")


def test_explicit_project_id_wins_over_workspace_derivation(tmp_path):
    ws = tmp_path / "whatever"; ws.mkdir()
    ctx = dispatch.project_context(project="alpha", workspace=str(ws))
    assert ctx["name"] == "alpha"
    assert ctx["derived_from_workspace"] is False


def test_derived_project_name_is_stable_for_one_path(tmp_path):
    ws = tmp_path / "charter"; ws.mkdir()
    first = dispatch.project_context(workspace=str(ws))["name"]
    second = dispatch.project_context(workspace=str(ws))["name"]
    assert first == second and dispatch._PROJECT_RE.fullmatch(first)
