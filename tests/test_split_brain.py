"""Split-brain surface for trust-critical artifacts (hook spec #4; gaps
006e0144da95, 01cbac265490, feedback_eliminate-split-brains).

Covers the three required behaviors: two divergent resolvable copies are
reported with both paths; a single canonical copy is clean; and the check
never mutates any file it looks at.
"""

import os

from willow_mcp import split_brain, server


def test_two_divergent_copies_reported_with_both_paths(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "constitutional").mkdir(parents=True)
    home_reg = home / "constitutional" / "pre-approved.json"
    home_reg.write_text("{}")

    env_reg = tmp_path / "elsewhere" / "pre-approved.json"
    env_reg.parent.mkdir(parents=True)
    env_reg.write_text("{}")

    monkeypatch.setenv("WILLOW_HOME", str(home))
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(env_reg))
    monkeypatch.delenv("WILLOW_CHARTER_REPO", raising=False)
    monkeypatch.delenv("WILLOW_VAULT_BOX", raising=False)

    report = split_brain._artifact_report(
        "envelope_registry",
        split_brain.envelope_registry_candidates(),
        split_brain._resolved_envelope_registry(),
    )

    assert report["status"] == "warn"
    assert report["divergent"] is True
    reported_paths = {c["path"] for c in report["candidates"] if c["exists"]}
    assert str(home_reg) in reported_paths
    assert str(env_reg) in reported_paths
    # The resolved (in-effect) copy is named, and it is one of the two —
    # never a silent pick that hides which copy is actually live.
    assert report["resolved"] == str(env_reg)
    assert "distinct resolvable copies" in report["detail"]


def test_scan_flags_divergent_artifact_and_leaves_others_clean(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "constitutional").mkdir(parents=True)
    (home / "constitutional" / "pre-approved.json").write_text("{}")

    env_reg = tmp_path / "elsewhere" / "pre-approved.json"
    env_reg.parent.mkdir(parents=True)
    env_reg.write_text("{}")

    # Isolate the implicit ~/.willow default: a real box may genuinely have
    # one, which would make willow_home's own divergence check a property of
    # the machine the suite runs on rather than of this test's fixture.
    monkeypatch.setenv("HOME", str(tmp_path / "fake_home"))
    monkeypatch.setenv("WILLOW_HOME", str(home))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(home / "store"))
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(env_reg))
    monkeypatch.delenv("WILLOW_CHARTER_REPO", raising=False)
    monkeypatch.delenv("WILLOW_VAULT_BOX", raising=False)
    monkeypatch.delenv("WILLOW_KEYRING", raising=False)

    report = split_brain.scan()

    assert report["status"] == "warn"
    assert report["artifacts"]["envelope_registry"]["status"] == "warn"
    # A single canonical copy (or nothing at all) elsewhere stays clean —
    # divergence in one artifact must not bleed a warning into another.
    assert report["artifacts"]["keyring"]["status"] == "ok"
    assert report["artifacts"]["willow_home"]["status"] == "ok"


def test_single_canonical_copy_is_clean_no_report(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "constitutional").mkdir(parents=True)
    reg = home / "constitutional" / "pre-approved.json"
    reg.write_text("{}")

    monkeypatch.setenv("WILLOW_HOME", str(home))
    monkeypatch.delenv("WILLOW_ENVELOPE_REGISTRY", raising=False)
    monkeypatch.delenv("WILLOW_CHARTER_REPO", raising=False)
    monkeypatch.delenv("WILLOW_VAULT_BOX", raising=False)

    report = split_brain._artifact_report(
        "envelope_registry",
        split_brain.envelope_registry_candidates(),
        split_brain._resolved_envelope_registry(),
    )

    assert report["status"] == "ok"
    assert report["divergent"] is False
    assert "detail" not in report
    assert report["resolved"] == str(reg)


def test_scan_all_clean_when_nothing_configured(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "fake_home"))
    monkeypatch.setenv("WILLOW_HOME", str(home))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(home / "store"))
    for var in ("WILLOW_ENVELOPE_REGISTRY", "WILLOW_CHARTER_REPO",
                "WILLOW_VAULT_BOX", "WILLOW_KEYRING"):
        monkeypatch.delenv(var, raising=False)

    report = split_brain.scan()

    assert report["status"] == "ok"
    for artifact in report["artifacts"].values():
        assert artifact["status"] == "ok"
        assert artifact["divergent"] is False


def test_check_never_mutates_any_file(tmp_path, monkeypatch):
    """Read-only guarantee (report, don't repair — feedback_eliminate-split-brains).
    Snapshot every candidate path's existence + mtime before and after a full
    scan(); none may change, and scan() must not create anything new."""
    home = tmp_path / "home"
    (home / "constitutional").mkdir(parents=True)
    home_reg = home / "constitutional" / "pre-approved.json"
    home_reg.write_text("{}")

    vault = tmp_path / "vault"
    vault.mkdir()

    env_reg = tmp_path / "elsewhere" / "pre-approved.json"
    env_reg.parent.mkdir(parents=True)
    env_reg.write_text("{}")

    monkeypatch.setenv("HOME", str(tmp_path / "fake_home"))
    monkeypatch.setenv("WILLOW_HOME", str(home))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(home / "store"))
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(env_reg))
    monkeypatch.setenv("WILLOW_VAULT_BOX", str(vault))
    monkeypatch.delenv("WILLOW_CHARTER_REPO", raising=False)
    monkeypatch.delenv("WILLOW_KEYRING", raising=False)

    def _snapshot(root):
        seen = {}
        for dirpath, _dirs, filenames in os.walk(root):
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                st = os.stat(p)
                seen[p] = (st.st_mtime_ns, st.st_size)
        return seen

    before = {str(tmp_path): _snapshot(tmp_path)}

    report = split_brain.scan()
    assert report["status"] == "warn"  # sanity: the interesting path actually ran

    after = {str(tmp_path): _snapshot(tmp_path)}

    assert before == after, "split_brain.scan() must never create, write, or touch any file"
    # Nothing new appeared under the vault box or WILLOW_HOME either — scan()
    # must not even create the directories it enumerates as candidates.
    assert not (vault / "keyring.json").exists()
    assert not (vault / "constitutional").exists()
    assert not (home / "keyring.json").exists()


def test_diagnostic_summary_wires_split_brain_into_checks_and_verdict(tmp_path, monkeypatch):
    """diagnostic_summary must surface the split-brain check (not just leave it
    reachable as a private helper), and a divergence must move the verdict off
    `ok` — otherwise the outage reads as healthy, same failure mode gap
    37d44bfa1f4c already guards against for the other probes."""
    home = tmp_path / "home"
    (home / "constitutional").mkdir(parents=True)
    (home / "constitutional" / "pre-approved.json").write_text("{}")

    env_reg = tmp_path / "elsewhere" / "pre-approved.json"
    env_reg.parent.mkdir(parents=True)
    env_reg.write_text("{}")

    monkeypatch.setenv("HOME", str(tmp_path / "fake_home"))
    monkeypatch.setenv("WILLOW_HOME", str(home))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(home / "store"))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(home / "mcp_apps"))
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(env_reg))
    monkeypatch.delenv("WILLOW_CHARTER_REPO", raising=False)
    monkeypatch.delenv("WILLOW_VAULT_BOX", raising=False)
    monkeypatch.delenv("WILLOW_KEYRING", raising=False)

    fn = getattr(server.diagnostic_summary, "fn", server.diagnostic_summary)
    rep = fn(app_id="")

    assert "split_brain" in rep["checks"]
    assert rep["checks"]["split_brain"]["status"] == "warn"
    assert any(p["check"] == "split_brain" for p in rep["problems"])
    assert rep["verdict"] != "ok"
