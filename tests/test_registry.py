"""Tests for specialist registry compile pipeline."""

import json

import pytest

from willow_mcp import registry as reg
from willow_mcp import home_init as hi


def test_load_registry_from_bundle():
    data = reg.load_registry(prefer_home=False)
    assert data.get("format") == reg.REGISTRY_FORMAT
    ids = [r["agent_id"] for r in data.get("specialists") or []]
    assert "hanuman" in ids
    assert data.get("orchestrator_seat", {}).get("agent_id") == "willow"
    orch_perms = data["orchestrator_seat"]["permissions"]
    assert "orchestrator" in orch_perms
    assert "commitment_read" in orch_perms
    assert "store_read" in orch_perms
    assert "knowledge_read" in orch_perms


def test_orchestrator_seat_carries_pr12_enabled_operator_grants():
    """PR12 enabled-operator alignment: pin the ratified set that closes the
    envelope-accrual mechanism-vs-manifest gap and formalizes the operator's
    write surface. Any accidental deletion of an entry here demotes Willow
    back to a narrow proxy that can't reach mechanisms the code ships."""
    data = reg.load_registry(prefer_home=False)
    orch_perms = set(data["orchestrator_seat"]["permissions"])

    # Envelope authoring — the bug PR12 primarily closes (mechanism shipped
    # in PRs 5-11, manifest never granted).
    assert {"envelope_read", "envelope_write",
            "envelope_read_discards"} <= orch_perms

    # Operator-scope writes the seat plausibly does directly.
    assert {"knowledge_write", "store_write", "task_queue",
            "commitment_write", "nest_read", "nest_write",
            "human_loop_read", "human_loop_write",
            "code_graph_read", "friction_read"} <= orch_perms

    # Federated MCP — driving downstream servers with the gate in between.
    # Needs BOTH federation_call (tool group) AND mcp_federation
    # (own-line capability that gates fork/exec at server uid) OR the
    # runtime call is denied by the federation gate. The manifest carries
    # both so the operator can actually use the tool.
    assert {"federation_read", "federation_call",
            "mcp_federation"} <= orch_perms

    # What still stays off — pins the deliberate exclusions.
    assert "integration_call" not in orch_perms
    assert "web_net" not in orch_perms
    assert "integration_net" not in orch_perms
    assert "full_access" not in orch_perms
    assert "schema_admin" not in orch_perms


def test_orchestrator_manifest_grants_envelope_tools_after_pr12(home):
    """End-to-end: the ratified permissions actually reach the gate for
    envelope tools. Before PR12 these would return False even though the
    tools existed and the code called them."""
    from willow_mcp.gate import permitted
    hi.ensure_home_layout()
    reg.compile_manifests(reg.load_registry(), only_missing=False)
    for tool in ("envelope_propose", "envelope_ratify", "envelope_reject",
                 "envelope_list", "envelope_pending_read",
                 "envelope_read_discards",
                 "knowledge_ingest", "store_put", "task_submit",
                 "commitment_ingest", "human_required_enqueue",
                 "nest_promote", "federation_call"):
        assert permitted("willow", tool), (
            f"PR12: willow manifest must permit {tool}"
        )


def test_orchestrator_manifest_still_denies_deliberately_off_tools(home):
    """Guardrail: PR12 widened the set but did NOT include integration_call,
    web egress, or schema admin. If any of these become True, we crossed a
    line the design explicitly held."""
    from willow_mcp.gate import permitted
    hi.ensure_home_layout()
    reg.compile_manifests(reg.load_registry(), only_missing=False)
    for tool in ("integration_call",
                 "willow_web_search", "willow_web_fetch",
                 "willow_institutional_search",
                 "schema_confirm_mapping"):
        assert not permitted("willow", tool), (
            f"PR12: willow manifest must NOT permit {tool} — "
            "this is a documented anti-widening"
        )


def test_orchestrator_manifest_supports_session_start_tools(home):
    """session-start open ritual needs tools outside the orchestrator group alone."""
    from willow_mcp.gate import permitted

    hi.ensure_home_layout()
    reg.compile_manifests(reg.load_registry(), only_missing=False)
    for tool in ("commitment_surface", "store_list", "kb_startup_continuity"):
        assert permitted("willow", tool), f"willow manifest must permit {tool}"


def test_manifest_from_row_includes_deny_tools():
    row = {
        "agent_id": "loki",
        "role": "auditor",
        "permissions": ["knowledge_read"],
        "deny_tools": ["task_submit", "store_put"],
        "store_scope": ["loki_*"],
        "human_only": False,
    }
    manifest = reg.manifest_from_row(row)
    assert manifest["deny_tools"] == ["task_submit", "store_put"]
    assert manifest["store_scope"] == ["loki_*"]


def test_compile_manifests_only_missing(home):
    hi.ensure_home_layout()
    first = reg.compile_manifests(reg.load_registry(), only_missing=True)
    assert first["written"] == []
    assert "mcp_apps/hanuman/manifest.json" in first["skipped"]

    second = reg.compile_manifests(reg.load_registry(), only_missing=False)
    assert "mcp_apps/hanuman/manifest.json" in second["written"]

    manifest = json.loads((home / "mcp_apps" / "hanuman" / "manifest.json").read_text())
    assert manifest["permissions"] == [
        "dispatch_read",
        "dispatch_write",
        "task_queue",
        "store_read",
        "knowledge_read",
        "fork_read",
        "fork_write",
        "grove_read",
        "grove_write",
    ]
    assert "kb_promote" in manifest["deny_tools"]


def test_compile_agents_force_overwrites(home, monkeypatch):
    hi.ensure_home_layout()
    path = home / "mcp_apps" / "hanuman" / "manifest.json"
    path.write_text(json.dumps({"permissions": ["full_access"]}) + "\n")

    out = reg.compile_agents_main(force=True)
    assert "mcp_apps/hanuman/manifest.json" in out["written"]
    manifest = json.loads(path.read_text())
    assert "full_access" not in manifest["permissions"]


def _solo_registry(**overrides):
    row = {"agent_id": "kart", "role": "auditor", "permissions": ["store_read"]}
    row.update(overrides)
    return {"format": reg.REGISTRY_FORMAT, "specialists": [row]}


# ── #312: compile_manifests must re-sign under PGP enforcement ─────────────────

def test_compile_manifests_signs_new_manifests_when_pgp_enabled(home, monkeypatch):
    signed: list = []
    monkeypatch.setattr(reg.pgp, "pgp_enabled", lambda: True)
    monkeypatch.setattr(
        reg.pgp, "sign_detached",
        lambda p: (signed.append(p) or (True, str(p) + ".sig")),
    )
    result = reg.compile_manifests(_solo_registry())
    assert result["written"] == ["mcp_apps/kart/manifest.json"]
    assert result["signed"] == ["mcp_apps/kart/manifest.json"]
    assert result["sign_failed"] == []
    assert [p.name for p in signed] == ["manifest.json"]


def test_compile_manifests_does_not_sign_when_pgp_disabled(home, monkeypatch):
    """Unset WILLOW_PGP_FINGERPRINT (the conftest default): unchanged behavior,
    byte-for-byte, from before #312 landed — no gpg invocation at all."""
    called = []
    monkeypatch.setattr(reg.pgp, "sign_detached", lambda p: called.append(p))
    result = reg.compile_manifests(_solo_registry())
    assert result["written"] == ["mcp_apps/kart/manifest.json"]
    assert result["signed"] == []
    assert called == []


def test_compile_manifests_rolls_back_and_raises_on_a_fresh_manifest(home, monkeypatch):
    """The #312 repro's failure leg: signing a manifest this call just created
    fails -- it must not be left on disk unsigned (denied everywhere), and the
    caller must be told loudly, not handed a return value that looks fine."""
    monkeypatch.setattr(reg.pgp, "pgp_enabled", lambda: True)

    def _failing_sign(p):
        (p.parent / f"{p.name}.sig").write_bytes(b"PARTIAL")
        return False, "gpg-agent unreachable"

    monkeypatch.setattr(reg.pgp, "sign_detached", _failing_sign)

    with pytest.raises(reg.ManifestSignError, match="1 manifest"):
        reg.compile_manifests(_solo_registry())

    assert not (home / "mcp_apps" / "kart" / "manifest.json").exists()
    assert not (home / "mcp_apps" / "kart" / "manifest.json.sig").exists()


def test_compile_manifests_rolls_back_to_previous_bytes_on_resign_failure(home, monkeypatch):
    """The observed-impact leg (issue #312 body): a compile that OVERWRITES an
    already-signed manifest and then can't re-sign it must restore the exact
    previous content *and* `.sig`, not leave new content next to a clobbered
    signature."""
    path = home / "mcp_apps" / "kart" / "manifest.json"
    path.parent.mkdir(parents=True)
    before = json.dumps({"app_id": "kart", "permissions": ["knowledge_read"]})
    path.write_text(before)
    sig = path.parent / f"{path.name}.sig"
    sig.write_bytes(b"PRIOR-SIG")
    before_sig = sig.read_bytes()

    def _failing_sign(p):
        (p.parent / f"{p.name}.sig").write_bytes(b"PARTIAL")
        return False, "gpg not found on PATH"

    monkeypatch.setattr(reg.pgp, "pgp_enabled", lambda: True)
    monkeypatch.setattr(reg.pgp, "sign_detached", _failing_sign)

    with pytest.raises(reg.ManifestSignError) as excinfo:
        reg.compile_manifests(_solo_registry(permissions=["store_read"]), only_missing=False)

    assert path.read_text() == before
    assert sig.read_bytes() == before_sig
    failure = excinfo.value.result
    assert failure["sign_failed"] == [
        {"manifest": "mcp_apps/kart/manifest.json", "detail": "gpg not found on PATH"}
    ]
    assert failure["written"] == []


def test_compile_manifests_continues_other_rows_after_one_sign_failure(home, monkeypatch):
    """One unsignable manifest must not strand a sibling manifest that WOULD
    have signed cleanly -- an operator recovering from a partial outage needs
    every fixable row fixed, not just the first one compile happened to hit."""
    row_ok = {"agent_id": "ada", "role": "x", "permissions": ["store_read"]}
    row_bad = {"agent_id": "kart", "role": "x", "permissions": ["store_read"]}
    registry = {"format": reg.REGISTRY_FORMAT, "specialists": [row_ok, row_bad]}

    monkeypatch.setattr(reg.pgp, "pgp_enabled", lambda: True)
    monkeypatch.setattr(
        reg.pgp, "sign_detached",
        lambda p: (False, "boom") if p.parent.name == "kart" else (True, str(p) + ".sig"),
    )

    with pytest.raises(reg.ManifestSignError) as excinfo:
        reg.compile_manifests(registry)

    result = excinfo.value.result
    assert result["signed"] == ["mcp_apps/ada/manifest.json"]
    assert result["sign_failed"] == [
        {"manifest": "mcp_apps/kart/manifest.json", "detail": "boom"}
    ]
    assert (home / "mcp_apps" / "ada" / "manifest.json").exists()
    assert not (home / "mcp_apps" / "kart" / "manifest.json").exists()


def test_compile_manifests_dry_run_never_signs(home, monkeypatch):
    called = []
    monkeypatch.setattr(reg.pgp, "pgp_enabled", lambda: True)
    monkeypatch.setattr(reg.pgp, "sign_detached", lambda p: called.append(p))
    result = reg.compile_manifests(_solo_registry(), dry_run=True)
    assert result["written"] == ["mcp_apps/kart/manifest.json"]
    assert called == []
    assert not (home / "mcp_apps" / "kart" / "manifest.json").exists()


def test_compile_agents_main_folds_meta_into_sign_error_result(home, monkeypatch):
    monkeypatch.setattr(reg, "load_registry", lambda path=None: _solo_registry())
    monkeypatch.setattr(reg.pgp, "pgp_enabled", lambda: True)
    monkeypatch.setattr(reg.pgp, "sign_detached", lambda p: (False, "nope"))

    with pytest.raises(reg.ManifestSignError) as excinfo:
        reg.compile_agents_main(force=True)

    result = excinfo.value.result
    assert result["force"] is True
    assert result["sign_failed"]


def test_compile_cli_main_exits_nonzero_and_prints_result_on_sign_failure(
    home, monkeypatch, capsys,
):
    monkeypatch.setattr(reg, "load_registry", lambda path=None: _solo_registry())
    monkeypatch.setattr(reg.pgp, "pgp_enabled", lambda: True)
    monkeypatch.setattr(reg.pgp, "sign_detached", lambda p: (False, "nope"))
    monkeypatch.setattr("sys.argv", ["willow-mcp-compile"])

    with pytest.raises(SystemExit) as excinfo:
        reg.compile_cli_main()
    assert excinfo.value.code == 1

    out = capsys.readouterr()
    payload = json.loads(out.out)
    assert payload["sign_failed"]
    assert "Error:" in out.err


def test_list_specialists_sorted(home):
    rows = reg.list_specialists()
    assert rows[0]["agent_id"] == "willow"
    assert any(r["agent_id"] == "hanuman" for r in rows)


def test_get_specialist_includes_permissions(home):
    row = reg.get_specialist("loki")
    assert row["agent_id"] == "loki"
    assert "knowledge_read" in row["permissions"]
    assert "task_submit" in row["deny_tools"]


def test_read_persona_text_from_bundle(home):
    text = reg.read_persona_text("jeles")
    assert text and "Jeles" in text
