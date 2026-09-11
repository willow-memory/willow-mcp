"""Tests for the diagnostic_summary self-check tool.

The problem-derivation and verdict logic are pure functions, so the headline
case — Postgres reachable but pointed at a database without willow-mcp's tables
(the empty-DB / wrong-WILLOW_PG_DB footgun) — is tested without a live DB.
"""
import json
import os

from willow_mcp import server


# ── verdict logic ────────────────────────────────────────────────────────────

def test_verdict_ok_when_no_problems():
    assert server._derive_verdict([]) == "ok"


def test_verdict_degraded_on_warn_only():
    assert server._derive_verdict([{"severity": "warn"}]) == "degraded"


def test_verdict_broken_on_any_error():
    assert server._derive_verdict([{"severity": "warn"}, {"severity": "error"}]) == "broken"


# ── the empty-DB footgun ─────────────────────────────────────────────────────

def _pg_ok():
    return {"status": "ok", "reachable": True, "dbname": "willow_20", "missing": []}


def _pg_empty():
    return {"status": "warn", "reachable": True, "dbname": "willow",
            "missing": ["knowledge", "tasks", "agents", "routing_decisions"]}


def _store_ok():
    return {"status": "ok", "writable": True, "root": "/x/store", "collections": 0}


def _manifest_ok():
    return {"status": "ok", "app_id": "willow", "apps_root": "/x", "permissions": ["fleet_read"]}


def _manifest_no_app_id():
    return {"status": "warn", "reason": "no_app_id", "app_id": "", "apps_root": "/x",
            "detail": "no app_id supplied — pass the app_id you call willow-mcp with"}


def test_empty_db_is_flagged_as_error():
    problems = server._derive_problems(_store_ok(), _pg_empty(), _manifest_ok(), "stdio")
    pg_problems = [p for p in problems if p["check"] == "postgres"]
    assert len(pg_problems) == 1
    p = pg_problems[0]
    assert p["severity"] == "error"
    assert "WILLOW_PG_DB" in p["fix"]
    assert "willow" in p["detail"]
    assert server._derive_verdict(problems) == "broken"


def test_healthy_db_produces_no_problems():
    problems = server._derive_problems(_store_ok(), _pg_ok(), _manifest_ok(), "stdio")
    assert problems == []
    assert server._derive_verdict(problems) == "ok"


def test_serve_mode_adds_systemd_env_note():
    problems = server._derive_problems(_store_ok(), _pg_empty(), _manifest_ok(), "serve")
    detail = next(p["detail"] for p in problems if p["check"] == "postgres")
    assert "systemd --user" in detail


def test_postgres_unreachable_is_warn_not_error():
    pg = {"status": "fail", "reachable": False}
    problems = server._derive_problems(_store_ok(), pg, _manifest_ok(), "stdio")
    pgp = [p for p in problems if p["check"] == "postgres"][0]
    assert pgp["severity"] == "warn"  # SOIL store still works standalone
    assert server._derive_verdict(problems) == "degraded"


def test_store_not_writable_is_error():
    store = {"status": "fail", "writable": False, "root": "/x/store", "write_error": "permission denied"}
    problems = server._derive_problems(store, _pg_ok(), _manifest_ok(), "stdio")
    assert any(p["check"] == "store" and p["severity"] == "error" for p in problems)


# ── manifest check ───────────────────────────────────────────────────────────

def test_manifest_missing_is_fail(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path))
    check = server._diag_manifest("ghost")
    assert check["status"] == "fail"
    assert "no manifest" in check["detail"]


def test_manifest_group_expands_to_tools(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path))
    app_dir = tmp_path / "demo"
    app_dir.mkdir()
    (app_dir / "manifest.json").write_text(json.dumps({"permissions": ["fleet_read"]}))
    check = server._diag_manifest("demo")
    assert check["status"] == "ok"
    assert "fleet_status" in check["tools_allowed"]
    assert "fleet_health" in check["tools_allowed"]


def test_manifest_empty_permissions_is_warn(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path))
    app_dir = tmp_path / "demo"
    app_dir.mkdir()
    (app_dir / "manifest.json").write_text(json.dumps({"permissions": []}))
    check = server._diag_manifest("demo")
    assert check["status"] == "warn"


# ── B-18: missing app_id is a caller-input warn, not a degraded verdict ───────

def test_diag_manifest_no_app_id_is_caller_input_warn(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path))
    check = server._diag_manifest("")
    assert check["status"] == "warn"
    assert check["reason"] == "no_app_id"


def test_verdict_ok_when_only_caller_input_warn():
    assert server._derive_verdict([{"severity": "warn", "caller_input": True}]) == "ok"


def test_verdict_degraded_when_caller_input_plus_real_warn():
    problems = [{"severity": "warn", "caller_input": True}, {"severity": "warn"}]
    assert server._derive_verdict(problems) == "degraded"


def test_missing_app_id_warns_but_verdict_stays_ok():
    # all subsystems healthy, caller just passed no app_id -> manifest surfaces
    # a caller_input warn, but the overall verdict is still ok.
    problems = server._derive_problems(_store_ok(), _pg_ok(), _manifest_no_app_id(), "stdio")
    mp = [p for p in problems if p["check"] == "manifest"]
    assert len(mp) == 1
    assert mp[0]["severity"] == "warn"
    assert mp[0]["caller_input"] is True
    assert server._derive_verdict(problems) == "ok"


def test_missing_egress_keys_is_warn_problem(monkeypatch):
    monkeypatch.setattr("willow_mcp.egress_setup.resolve_public_key_path", lambda: None)
    problems = server._derive_problems(_store_ok(), _pg_ok(), _manifest_ok(), "stdio")
    egress = [p for p in problems if p["check"] == "egress_keys"]
    assert len(egress) == 1
    assert egress[0]["severity"] == "warn"
    assert "setup-egress" in egress[0]["fix"]
    assert server._derive_verdict(problems) == "degraded"


def test_empty_permissions_warn_still_degrades():
    # a real manifest warn (empty permissions -> every call denied) is NOT
    # caller_input and must still degrade the verdict.
    manifest = {"status": "warn", "app_id": "demo", "apps_root": "/x",
                "detail": "manifest present but permissions empty — every call is denied"}
    problems = server._derive_problems(_store_ok(), _pg_ok(), manifest, "stdio")
    mp = [p for p in problems if p["check"] == "manifest"][0]
    assert mp["severity"] == "warn"
    assert "caller_input" not in mp
    assert server._derive_verdict(problems) == "degraded"


# ── serve-mode redaction ─────────────────────────────────────────────────────

def test_collapse_home_redacts_paths():
    import os
    home = os.path.expanduser("~")
    obj = {"root": f"{home}/.willow/store", "nested": [f"{home}/x"]}
    out = server._collapse_home(obj)
    assert out["root"] == "~/.willow/store"
    assert out["nested"] == ["~/x"]


# ── smoke: the tool returns a well-formed report ─────────────────────────────

def test_diagnostic_summary_smoke():
    fn = getattr(server.diagnostic_summary, "fn", server.diagnostic_summary)
    rep = fn(app_id="")
    assert rep["mode"] == "stdio"
    assert rep["verdict"] in ("ok", "degraded", "broken")
    for key in ("store", "postgres", "schema", "manifest", "identity_bindings", "env"):
        assert key in rep["checks"]
    assert isinstance(rep["problems"], list)


# ── uid_separation check (#231) — informational only, never gates verdict ────

def test_diagnostic_summary_includes_uid_separation_check():
    fn = getattr(server.diagnostic_summary, "fn", server.diagnostic_summary)
    rep = fn(app_id="hanuman")
    assert "uid_separation" in rep["checks"]
    sep = rep["checks"]["uid_separation"]
    assert "separated" in sep and "process" in sep and "targets" in sep


def test_uid_separation_not_separated_never_added_to_problems(monkeypatch):
    """The whole point of B-18: a check that is `False`/unsatisfied on every
    single-uid install today must never become a new `warn`/`error` in
    `problems`, or every existing install's resting state degrades on this
    PR alone. uid_separation is deliberately excluded from _derive_problems;
    assert the exclusion holds even when explicitly False."""
    from willow_mcp import trust_root_setup

    monkeypatch.setattr(
        trust_root_setup,
        "uid_separation_report",
        lambda app_id="": {"separated": False, "process": {"uid": 0, "user": "root"},
                            "targets": [], "same_owner_paths": []},
    )
    fn = getattr(server.diagnostic_summary, "fn", server.diagnostic_summary)
    rep = fn(app_id="hanuman")
    assert rep["checks"]["uid_separation"]["separated"] is False
    checks = {p.get("check") for p in rep["problems"]}
    assert "uid_separation" not in checks


# ── store_db_perms check (#232) — informational only, never gates verdict ────

def test_diagnostic_summary_includes_store_db_perms_check():
    fn = getattr(server.diagnostic_summary, "fn", server.diagnostic_summary)
    rep = fn(app_id="hanuman")
    assert "store_db_perms" in rep["checks"]
    check = rep["checks"]["store_db_perms"]
    assert "files" in check and "exposure" in check and "enforced" in check


def test_store_db_perms_exposure_never_added_to_problems(monkeypatch):
    """Same B-18 discipline as uid_separation: a store `.db` file the mode-bit
    hygiene check finds group/world-readable must never become a new
    `warn`/`error` in `problems` on its own — every unhardened single-uid
    install has exposed store files today, and this check must not degrade
    that install's resting state just by existing."""
    from willow_mcp import trust_root_setup

    monkeypatch.setattr(
        trust_root_setup,
        "store_db_files",
        lambda: ["/x/.willow/store/knowledge/store.db"],
    )
    monkeypatch.setattr(
        trust_root_setup,
        "store_db_exposure",
        lambda: [{"key": "store.db", "path": "/x/.willow/store/knowledge/store.db", "mode": "0o644"}],
    )
    fn = getattr(server.diagnostic_summary, "fn", server.diagnostic_summary)
    rep = fn(app_id="hanuman")
    assert rep["checks"]["store_db_perms"]["exposure"]
    assert rep["checks"]["store_db_perms"]["enforced"] is False
    checks = {p.get("check") for p in rep["problems"]}
    assert "store_db_perms" not in checks


def test_store_db_perms_enforced_false_on_fresh_install_with_no_db_files_yet(monkeypatch):
    """An empty list is not evidence of protection -- `enforced` must read
    False (the honest 'not enforced yet' resting state), not True by the
    vacuous absence of anything to expose."""
    from willow_mcp import trust_root_setup

    monkeypatch.setattr(trust_root_setup, "store_db_files", lambda: [])
    monkeypatch.setattr(trust_root_setup, "store_db_exposure", lambda: [])
    fn = getattr(server.diagnostic_summary, "fn", server.diagnostic_summary)
    rep = fn(app_id="hanuman")
    assert rep["checks"]["store_db_perms"]["enforced"] is False


# ── learned-mapping tree (schema_rings) health ───────────────────────────────

def test_diag_rings_reports_sapling_when_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_MCP_SCHEMA_RINGS", str(tmp_path / "rings.json"))
    r = server._diag_rings()
    assert r["status"] == "ok"
    assert r["pairs"] == 0 and r["columns"] == 0
    assert r["saturation_pct"] == 0.0
    assert set(r) >= {"pairs", "cap", "columns", "confirmations", "saturation_pct"}


def test_diag_rings_counts_grown_rings_and_saturation(tmp_path, monkeypatch):
    rings = tmp_path / "rings.json"
    monkeypatch.setenv("WILLOW_MCP_SCHEMA_RINGS", str(rings))
    monkeypatch.setenv("WILLOW_MCP_SCHEMA_RINGS_MAX", "100")
    # one confirm grows two non-trivial rings (submitter->submitted_by, stat->status)
    server.sp.grow_ring({"submitted_by": {"column": "submitter"},
                         "status": {"column": "stat"}})
    r = server._diag_rings()
    assert r["pairs"] == 2 and r["cap"] == 100
    assert r["confirmations"] == 1
    assert r["saturation_pct"] == 2.0


def test_diagnostic_summary_includes_rings_check(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_MCP_SCHEMA_RINGS", str(tmp_path / "rings.json"))
    report = server.diagnostic_summary(app_id="willow")
    assert "rings" in report["checks"]
    assert report["checks"]["rings"]["backend"] == "schema-rings"


# ── _diag_net_lease's private_key_readable field (#182) ──────────────────────

def test_diag_net_lease_reports_key_not_readable_by_default(tmp_path, monkeypatch):
    """The conftest-wide egress stub (resolve_private_key_path -> None) means a
    clean test environment has nothing to read — the honest default. Pin
    self_writable to [] too (a tmp_path is always writable by the test uid,
    which is its own unrelated reason for 'warn' — see conftest.py) so this
    isolates the private-key field specifically."""
    from willow_mcp import lease
    monkeypatch.setattr(lease, "self_writable_trust_paths", lambda *_: [])
    out = server._diag_net_lease("someapp")
    assert out["private_key_readable"] is False
    assert out["status"] == "ok"


def test_diag_net_lease_reports_key_readable_and_warns(monkeypatch):
    from willow_mcp import lease
    monkeypatch.setattr(lease, "egress_key_readable_by_self", lambda: True)
    out = server._diag_net_lease("someapp")
    assert out["private_key_readable"] is True
    assert out["status"] == "warn"


# ── #332: envelope-registry health surfaces an empty/relocated registry ───────

def _registry_ok():
    return {"status": "ok", "path": "/x/constitutional/pre-approved.json",
            "present": True, "active_grants": 3}


def _registry_empty():
    return {"status": "warn", "path": "/x/constitutional/pre-approved.json",
            "present": True, "active_grants": 0}


def _registry_missing():
    return {"status": "warn", "path": "/x/constitutional/pre-approved.json",
            "present": False, "active_grants": 0}


def test_empty_envelope_registry_is_a_named_degrading_problem():
    problems = server._derive_problems(
        _store_ok(), _pg_ok(), _manifest_ok(), "stdio",
        None, None, None, None, _registry_empty(),
    )
    reg = [p for p in problems if p["check"] == "envelope_registry"]
    assert len(reg) == 1
    assert reg[0]["severity"] == "warn"
    assert "#332" in reg[0]["detail"]
    assert "verb 11" in reg[0]["fix"] or "WILLOW_ENVELOPE_REGISTRY" in reg[0]["fix"]
    # Degrades, never breaks: a fresh install that has not planted grants yet is
    # incomplete, not defective.
    assert server._derive_verdict(problems) == "degraded"


def test_missing_envelope_registry_names_seeding_and_planting():
    problems = server._derive_problems(
        _store_ok(), _pg_ok(), _manifest_ok(), "stdio",
        None, None, None, None, _registry_missing(),
    )
    reg = next(p for p in problems if p["check"] == "envelope_registry")
    assert "not found" in reg["detail"]


def test_healthy_envelope_registry_produces_no_problem():
    problems = server._derive_problems(
        _store_ok(), _pg_ok(), _manifest_ok(), "stdio",
        None, None, None, None, _registry_ok(),
    )
    assert [p for p in problems if p["check"] == "envelope_registry"] == []


def test_envelope_registry_arg_is_optional():
    # Existing callers that do not pass it must be unaffected (no such problem).
    problems = server._derive_problems(_store_ok(), _pg_ok(), _manifest_ok(), "stdio")
    assert [p for p in problems if p["check"] == "envelope_registry"] == []


def test_diag_envelope_registry_counts_only_usable_grants(monkeypatch, tmp_path):
    reg = tmp_path / "pre-approved.json"
    reg.write_text(json.dumps({"active": [{"id": "e1"}, {"id": "e2"}, "garbage", {"no": "id"}]}))
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(reg))
    out = server._diag_envelope_registry()
    assert out == {"status": "ok", "path": str(reg), "present": True, "active_grants": 2}


def test_diag_envelope_registry_warns_on_empty_starter(monkeypatch, tmp_path):
    reg = tmp_path / "pre-approved.json"
    reg.write_text(json.dumps({"active": [], "pre_approved": [], "proposals": []}))
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(reg))
    out = server._diag_envelope_registry()
    assert out["status"] == "warn"
    assert out["active_grants"] == 0
    assert out["present"] is True


def test_diag_envelope_registry_warns_when_absent(monkeypatch, tmp_path):
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(tmp_path / "nope.json"))
    out = server._diag_envelope_registry()
    assert out["status"] == "warn"
    assert out["present"] is False


# ── build_leases check — informational only, never gates verdict ────────────

def test_diagnostic_summary_includes_build_leases_check(tmp_path, monkeypatch):
    """The earn-first surface has to appear alongside net_lease in the
    self-check — same posture as net_lease's own reporting, so `diagnostic_summary`
    stays the one place that reads all of them together."""
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path / "mcp_apps"))
    fn = getattr(server.diagnostic_summary, "fn", server.diagnostic_summary)
    rep = fn(app_id="")
    assert "build_leases" in rep["checks"]
    bl = rep["checks"]["build_leases"]
    assert "roster_size" in bl and bl["roster_size"] > 0
    assert "roster_dry" in bl and "extras" in bl and "tally" in bl
    assert bl["max_ttl_seconds"] == 3 * 60 * 60  # same 3h ceiling as net_lease


def test_build_leases_check_never_enters_problems(tmp_path, monkeypatch):
    """B-18: a check that is empty/dry on every existing install must never
    become a new `warn`/`error` in `problems`, or every install's resting
    state degrades on this PR alone. build_leases is deliberately excluded
    from _derive_problems."""
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path / "mcp_apps"))
    fn = getattr(server.diagnostic_summary, "fn", server.diagnostic_summary)
    rep = fn(app_id="")
    checks = {p.get("check") for p in rep["problems"]}
    assert "build_leases" not in checks


def test_build_leases_check_reflects_a_live_lease(tmp_path, monkeypatch):
    """Grant one lease, confirm it surfaces in the diag output with the
    right issuer, tally, and roster-dry list shrinking by one."""
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path / "mcp_apps"))
    from willow_mcp import build_lease
    build_lease.grant("workflow", 1800, issuer="operator", reason="ship it")

    fn = getattr(server.diagnostic_summary, "fn", server.diagnostic_summary)
    rep = fn(app_id="")
    bl = rep["checks"]["build_leases"]
    assert bl["tally"]["active"] == 1
    assert "workflow" not in bl["roster_dry"]
    assert any(row["tool"] == "workflow" and row["status"] == "active"
               for row in bl["leases"])


def test_diagnostic_summary_is_registered_and_the_probe_helper_is_not():
    """Guard against decorator displacement (regression from #332's own fix):
    _diag_envelope_registry is a PRIVATE helper, not an MCP tool, and
    diagnostic_summary must stay a registered tool. Inserting the helper between
    `@mcp.tool()` and `def diagnostic_summary` once moved the decorator onto the
    helper — the unit suite stayed green because the registered/guarded tool
    counts balanced, and only the live stdio handshake (fleet-seams) caught it.
    This asserts the registry directly so the next such slip fails here."""
    names = {t.name for t in server.mcp._tool_manager.list_tools()}
    assert "diagnostic_summary" in names, "diagnostic_summary must be a registered MCP tool"
    assert "_diag_envelope_registry" not in names, "the private probe helper must not be exposed as a tool"


# ── keyring probe + verdict coverage (gap 37d44bfa1f4c) ──────────────────────
# The five computed sub-checks + a new keyring probe now move the verdict. A
# keyring the seat cannot read blocks session_enter but used to read as `ok`.


def _keyring_broken():
    return {"backend": "willow-keyring", "status": "broken",
            "path": "/x/config/verifiers.json",
            "detail": "the keyring exists but this process cannot read it",
            "fix": "chown it to the uid the seat runs as, then re-run"}


def test_unreadable_keyring_is_a_named_error_and_breaks_verdict():
    # The gap itself: the verdict must consume the keyring sub-check. On the
    # unmodified tree _derive_problems has no severity_checks arg and emits no
    # keyring problem, so this fails there and passes after.
    problems = server._derive_problems(
        _store_ok(), _pg_ok(), _manifest_ok(), "stdio",
        severity_checks={"keyring": _keyring_broken()})
    kp = [p for p in problems if p["check"] == "keyring"]
    assert len(kp) == 1
    assert kp[0]["severity"] == "error"
    assert kp[0]["detail"] and kp[0]["fix"]
    assert server._derive_verdict(problems) == "broken"


def test_diag_keyring_not_enabled_when_unset(monkeypatch):
    monkeypatch.delenv("WILLOW_KEYRING", raising=False)
    from willow_mcp import keyring as _keyring
    monkeypatch.setattr(_keyring, "_injected", None, raising=False)
    check = server._diag_keyring()
    assert check["status"] == "not_enabled"
    assert check["configured"] is False


def test_diag_keyring_refuses_group_readable_secret_keyring(tmp_path, monkeypatch):
    # A keyring holding secret material at a group/world-readable mode is exactly
    # what the loader refuses — tonight's case (owned at a mode session_enter
    # rejects). The probe must call it `broken` with a fix.
    kr = tmp_path / "verifiers.json"
    kr.write_text(json.dumps({"legacy_key": "ab" * 16}))
    os.chmod(kr, 0o644)
    monkeypatch.setenv("WILLOW_KEYRING", str(kr))
    from willow_mcp import keyring as _keyring
    monkeypatch.setattr(_keyring, "_injected", None, raising=False)
    monkeypatch.setattr(_keyring, "_from_env", None, raising=False)
    monkeypatch.setattr(_keyring, "_loaded_from", None, raising=False)
    check = server._diag_keyring()
    assert check["status"] == "broken"
    assert check["configured"] is True
    assert check["fix"]


def test_keyring_broken_drives_diagnostic_summary_off_ok(tmp_path, monkeypatch):
    # End to end: a keyring the loader refuses drives the whole self-check off
    # `ok` with a named keyring problem — the tonight outage, now visible.
    kr = tmp_path / "verifiers.json"
    kr.write_text(json.dumps({"legacy_key": "cd" * 16}))
    os.chmod(kr, 0o644)
    monkeypatch.setenv("WILLOW_KEYRING", str(kr))
    from willow_mcp import keyring as _keyring
    monkeypatch.setattr(_keyring, "_injected", None, raising=False)
    monkeypatch.setattr(_keyring, "_from_env", None, raising=False)
    monkeypatch.setattr(_keyring, "_loaded_from", None, raising=False)
    fn = getattr(server.diagnostic_summary, "fn", server.diagnostic_summary)
    rep = fn(app_id="hanuman")
    assert rep["checks"]["keyring"]["status"] == "broken"
    kp = [p for p in rep["problems"] if p["check"] == "keyring"]
    assert len(kp) == 1 and kp[0]["severity"] == "error"
    assert rep["verdict"] == "broken"


# ── completeness assertion (gap 37d44bfa1f4c) ────────────────────────────────

def test_completeness_assertion_passes_for_the_real_check_set():
    fn = getattr(server.diagnostic_summary, "fn", server.diagnostic_summary)
    rep = fn(app_id="hanuman")
    # If this raised, diagnostic_summary itself would have; assert the guard is
    # actually satisfied by the shipped `checks`.
    server._assert_verdict_considers(set(rep["checks"]))


def test_completeness_assertion_fails_on_unwired_subcheck():
    # Simulate a future probe added to `checks` but wired into none of the three
    # verdict sets — it must raise, not silently never move the verdict.
    names = (set(server._VERDICT_INLINE_SUBCHECKS)
             | set(server._VERDICT_SEVERITY_SUBCHECKS)
             | set(server._VERDICT_INFORMATIONAL_SUBCHECKS))
    names.add("newly_added_probe")
    import pytest
    with pytest.raises(RuntimeError) as ei:
        server._assert_verdict_considers(names)
    assert "newly_added_probe" in str(ei.value)


# ── could-not-run is never counted clean; healthy box stays ok ───────────────

def test_could_not_run_subcheck_degrades_and_is_flagged():
    problems = server._derive_problems(
        _store_ok(), _pg_ok(), _manifest_ok(), "stdio",
        severity_checks={"schema": {"status": "could_not_run",
                                    "error": "postgres unavailable"}})
    sp_probs = [p for p in problems if p["check"] == "schema"]
    assert len(sp_probs) == 1
    assert sp_probs[0]["could_not_run"] is True
    assert server._derive_verdict(problems) == "degraded"


def test_informational_subchecks_at_rest_add_no_false_problem():
    # A healthy box: every severity sub-check ok / at its resting state, keyring
    # not enabled. No problems, verdict ok.
    healthy = {
        "rings": {"status": "ok"},
        "schema": {"status": "ok"},
        "identity_bindings": {"status": "ok"},
        "uid_separation": {"separated": False, "targets": [], "same_owner_paths": []},
        "store_db_perms": {"files": [], "exposure": [], "enforced": False},
        "keyring": {"status": "not_enabled", "configured": False},
    }
    problems = server._derive_problems(
        _store_ok(), _pg_ok(), _manifest_ok(), "stdio",
        severity_checks=healthy)
    assert problems == []
    assert server._derive_verdict(problems) == "ok"


def test_degraded_rings_probe_moves_verdict_via_severity_pipeline():
    problems = server._derive_problems(
        _store_ok(), _pg_ok(), _manifest_ok(), "stdio",
        severity_checks={"rings": {"status": "fail", "error": "rings.json unreadable"}})
    rp = [p for p in problems if p["check"] == "rings"]
    assert len(rp) == 1 and rp[0]["severity"] == "warn"
    assert server._derive_verdict(problems) == "degraded"
