"""Tests for B-32 trust-root hardening operator tooling."""

from __future__ import annotations

import json
import os
import pwd
import stat
from pathlib import Path

import pytest

from willow_mcp import home_init as hi
from willow_mcp import paths
from willow_mcp import trust_root_setup as trs


def test_audit_reports_forgeable_paths_on_default_home(home, monkeypatch):
    # "default home" has to mean a default ENVIRONMENT too. This asserts
    # strict_trust_root is off, and WILLOW_MCP_STRICT_TRUST_ROOT is inherited —
    # so on an install that runs strict mode (this repo's own MCP config does)
    # the test failed while reporting nothing about the code. The sibling test
    # below sets the variable on purpose; this one must clear it on purpose.
    monkeypatch.delenv("WILLOW_MCP_STRICT_TRUST_ROOT", raising=False)
    hi.ensure_home_layout()
    audit = trs.audit_trust_root("hanuman")
    assert audit["strict_trust_root"] is False
    assert audit["hardened"] is False
    keys = {item["key"] for item in audit["forgeable"]}
    assert "lease_root" in keys


def test_audit_hardened_when_strict_and_nothing_forgeable(home, monkeypatch):
    hi.ensure_home_layout()
    monkeypatch.setenv("WILLOW_MCP_STRICT_TRUST_ROOT", "1")
    monkeypatch.setattr(trs.lease, "self_writable_trust_paths", lambda *_: [])
    monkeypatch.setattr(trs.lease, "path_is_self_writable_or_replaceable", lambda *_: False)
    monkeypatch.setattr(trs.lease, "path_is_directly_writable_for_trust", lambda *_: False)
    audit = trs.audit_trust_root("hanuman")
    assert audit["hardened"] is True


def test_merge_strict_env_into_mcp_json(tmp_path):
    mcp_json = tmp_path / ".cursor" / "mcp.json"
    mcp_json.parent.mkdir(parents=True)
    mcp_json.write_text(
        json.dumps({"mcpServers": {"willow-mcp": {"command": "willow-mcp"}}}) + "\n",
        encoding="utf-8",
    )
    assert trs.merge_mcp_env(mcp_json, trs.mcp_env_snippet()) is True
    data = json.loads(mcp_json.read_text(encoding="utf-8"))
    assert data["mcpServers"]["willow-mcp"]["env"]["WILLOW_MCP_STRICT_TRUST_ROOT"] == "1"


def test_harden_dry_run_lists_actions(home, monkeypatch):
    hi.ensure_home_layout()
    monkeypatch.setattr(trs, "resolve_trust_owner", lambda owner: "operator")
    result = trs.harden_trust_root(owner="operator", dry_run=True)
    assert result["filesystem"]["dry_run"] is True
    assert any("chown -R operator:operator" in action for action in result["filesystem"]["actions"])
    # The sweep is tighten-only: its action line names the ceilings it applied
    # and how many paths were above them, even when that number is zero.
    assert any(
        "tighten-only" in action and "files<=644" in action
        for action in result["filesystem"]["actions"]
    )


def test_chmod_tree_legacy_absolute_mode_uses_privileged_find(home, monkeypatch):
    """never_widen=False is the pre-fix absolute sweep, kept for a caller that
    genuinely wants 'exactly this mode'. It still goes through find."""
    hi.ensure_home_layout()
    calls: list[list[str]] = []

    def _capture(argv, *, dry_run):
        calls.append(list(argv))

    monkeypatch.setattr(trs, "_run_privileged", _capture)
    trs._chmod_tree(paths.mcp_apps_root(), dir_mode=0o755, file_mode=0o644, never_widen=False)
    assert any(cmd[:4] == ["find", str(paths.mcp_apps_root()), "-type", "f"] for cmd in calls)
    assert any(cmd[:4] == ["find", str(paths.mcp_apps_root()), "-type", "d"] for cmd in calls)


def test_chmod_tree_never_widens_a_hand_tightened_file(home):
    """The loop this fixes: an operator chmods a file to 0600, the next sweep
    puts it back to 0644. Real chmod on real files — a 0600 file under a 0644
    ceiling must stay 0600 while a 0666 sibling still drops to 0644."""
    hi.ensure_home_layout()
    root = paths.mcp_apps_root()
    tightened = root / "tightened.json"
    loose = root / "loose.json"
    tightened.write_text("{}")
    loose.write_text("{}")
    tightened.chmod(0o600)
    loose.chmod(0o666)

    actions = trs._chmod_tree(root, dir_mode=0o755, file_mode=0o644)

    assert stat.S_IMODE(tightened.stat().st_mode) == 0o600, "sweep widened a hand-tightened file"
    assert stat.S_IMODE(loose.stat().st_mode) == 0o644
    assert any("tighten-only" in a for a in actions)


def test_chmod_tree_never_strips_execute_bits(home):
    """venvs/ lives under $WILLOW_HOME. The absolute sweep stripped +x from
    the venv's bin/ twice (2026-09-01: 38 of 42, workers crash-looped 203/EXEC;
    2026-09-10: 39, `willow-mcp` Permission denied). Execute bits are carved
    out of tighten-only entirely."""
    hi.ensure_home_layout()
    venv_bin = home / "venvs" / "x" / "bin"
    venv_bin.mkdir(parents=True)
    script = venv_bin / "willow-mcp"
    script.write_text("#!/bin/sh\n")
    script.chmod(0o755)
    world_writable_script = venv_bin / "wmc"
    world_writable_script.write_text("#!/bin/sh\n")
    world_writable_script.chmod(0o777)

    trs._chmod_tree(home / "venvs", dir_mode=0o755, file_mode=0o644)

    assert stat.S_IMODE(script.stat().st_mode) == 0o755, "sweep stripped +x"
    # Group/other write is above the ceiling and is cleared; x stays.
    assert stat.S_IMODE(world_writable_script.stat().st_mode) == 0o755


def test_chmod_tree_dry_run_changes_nothing_but_reports_the_count(home, monkeypatch):
    hi.ensure_home_layout()
    root = paths.mcp_apps_root()
    loose = root / "loose.json"
    loose.write_text("{}")
    loose.chmod(0o666)
    calls: list[list[str]] = []
    monkeypatch.setattr(trs, "_run_privileged", lambda argv, *, dry_run: calls.append(list(argv)))

    actions = trs._chmod_tree(root, dir_mode=0o755, file_mode=0o644, dry_run=True)

    assert stat.S_IMODE(loose.stat().st_mode) == 0o666
    assert any("1 change(s)" in a for a in actions)
    assert calls and calls[0][:2] == ["chmod", "644"]


def test_repair_runtime_keeps_a_hand_tightened_runtime_file(home, monkeypatch):
    """At the repair level, not just the helper: a non-secret runtime file the
    operator tightened stays tightened across repair_runtime_permissions()."""
    hi.ensure_home_layout()
    real_user = pwd.getpwuid(os.geteuid()).pw_name
    monkeypatch.setattr(trs, "resolve_runtime_user", lambda _u: real_user)
    runtime_dir = home / "dispatch"
    runtime_dir.mkdir(exist_ok=True)
    tightened = runtime_dir / "hand-tightened.json"
    tightened.write_text("{}")
    tightened.chmod(0o600)

    trs.repair_runtime_permissions(dry_run=False)

    assert stat.S_IMODE(tightened.stat().st_mode) == 0o600


def test_harden_trust_root_tightens_the_keyring_to_owner_only(home, monkeypatch):
    """config/verifiers.json holds private halves; harden-trust-root used to
    leave it at the 0644 the rest of config/ gets, and session_enter then
    refused the world-readable keyring. Now it lands at 0600."""
    hi.ensure_home_layout()
    real_user = pwd.getpwuid(os.geteuid()).pw_name
    monkeypatch.setattr(trs, "resolve_trust_owner", lambda _o: real_user)
    keyring = paths.config_dir() / "verifiers.json"
    keyring.write_text("{}")
    keyring.chmod(0o644)

    trs.apply_trust_root_hardening(real_user, dry_run=False)

    assert stat.S_IMODE(keyring.stat().st_mode) == 0o600


def test_resolve_trust_owner_requires_existing_user(monkeypatch):
    def _missing(_name):
        raise KeyError("missing")

    monkeypatch.setattr(trs.pwd, "getpwnam", _missing)
    with pytest.raises(ValueError, match="does not exist"):
        trs.resolve_trust_owner("nobody-here")


def test_resolve_trust_owner_accepts_existing_user(monkeypatch):
    monkeypatch.setattr(trs.pwd, "getpwnam", lambda name: object())
    assert trs.resolve_trust_owner("operator") == "operator"


def test_trust_root_directories_include_mcp_apps_and_config(home):
    hi.ensure_home_layout()
    roots = {p.name for p in trs.trust_root_directories()}
    assert "mcp_apps" in roots
    assert "config" in roots
    assert paths.willow_home().name not in {p.name for p in trs.trust_root_directories() if p == paths.willow_home()}


def test_trust_root_directories_skip_home_root_when_legacy_policy_files_exist(home):
    hi.ensure_home_layout()
    legacy = paths.consent_legacy_path()
    legacy.parent.mkdir(parents=True, exist_ok=True)
    legacy.write_text('{"consent": {"internet": false, "cloud_llm": false, "lan": false}}\n', encoding="utf-8")
    roots = trs.trust_root_directories()
    assert paths.willow_home() not in roots
    assert legacy in trs.trust_policy_files()


def test_runtime_writable_includes_store_not_config(home):
    hi.ensure_home_layout()
    names = {p.name for p in trs.runtime_writable_directories()}
    assert "store" in names
    assert "config" not in names
    assert "mcp_apps" not in names


def test_repair_runtime_dry_run_targets_store(home, monkeypatch):
    hi.ensure_home_layout()
    monkeypatch.setattr(trs, "resolve_runtime_user", lambda _user: "runtime")
    result = trs.repair_runtime_permissions(dry_run=True)
    assert result["runtime_user"] == "runtime"
    assert any("store" in target for target in result["targets"])
    assert any("chown -R runtime:runtime" in action for action in result["actions"])


# ── secret-file exposure (#181 audit finding) ────────────────────────────────
#
# Found live: repair-runtime-perms' generic runtime-children sweep gave
# vault.key/vault.db/mcp_token.json the SAME world-readable 0644/0755 it
# gives ordinary runtime state -- verified by creating a real vault, running
# repair_runtime_permissions() for real (not dry_run), and watching vault.key
# go from its own 0600 default to 0644. The server (running as the runtime
# user) still needs to read these, so they can't move to the trust owner
# like the egress key did -- same owner, stricter mode: owner-only, always.

def test_repair_runtime_dry_run_plans_owner_only_mode_for_vault_key(home, monkeypatch):
    (home / "vault.key").write_text("fernet-key-placeholder")
    monkeypatch.setattr(trs, "resolve_runtime_user", lambda _user: "runtime")
    result = trs.repair_runtime_permissions(dry_run=True)
    vault_key = str(home / "vault.key")
    assert any(f"chmod 600 {vault_key}" in a for a in result["actions"])
    assert not any(f"chmod 644 {vault_key}" in a for a in result["actions"])


def test_repair_runtime_dry_run_plans_owner_only_mode_for_mcp_token(home, monkeypatch):
    (home / "mcp_token.json").write_text("{}")
    monkeypatch.setattr(trs, "resolve_runtime_user", lambda _user: "runtime")
    result = trs.repair_runtime_permissions(dry_run=True)
    token_path = str(home / "mcp_token.json")
    assert any(f"chmod 600 {token_path}" in a for a in result["actions"])
    assert not any(f"chmod 644 {token_path}" in a for a in result["actions"])


def test_repair_runtime_dry_run_leaves_ordinary_files_world_readable(home, monkeypatch):
    """The fix is scoped to the named secret files -- everything else keeps
    the world-readable mode the gate/runtime state actually needs."""
    hi.ensure_home_layout()
    monkeypatch.setattr(trs, "resolve_runtime_user", lambda _user: "runtime")
    result = trs.repair_runtime_permissions(dry_run=True)
    assert any("files<=644" in a for a in result["actions"])
    assert any("dirs<=755" in a for a in result["actions"])


def test_secret_file_exposure_empty_when_nothing_present(home):
    assert trs.secret_file_exposure() == []


def test_secret_file_exposure_detects_world_readable_vault_key(home):
    key = home / "vault.key"
    key.write_text("fernet-key-placeholder")
    key.chmod(0o644)
    exposure = trs.secret_file_exposure()
    assert {"vault.key"} == {e["key"] for e in exposure}
    assert exposure[0]["mode"] == oct(0o644)


def test_secret_file_exposure_silent_when_properly_protected(home):
    key = home / "vault.key"
    key.write_text("fernet-key-placeholder")
    key.chmod(0o600)
    assert trs.secret_file_exposure() == []


def test_audit_trust_root_not_hardened_when_secret_file_exposed(home, monkeypatch):
    monkeypatch.setattr(trs.lease, "self_writable_trust_paths", lambda *_: [])
    monkeypatch.setattr(trs.lease, "path_is_self_writable_or_replaceable", lambda *_: False)
    monkeypatch.setattr(trs.lease, "path_is_directly_writable_for_trust", lambda *_: False)
    monkeypatch.setenv("WILLOW_MCP_STRICT_TRUST_ROOT", "1")
    (home / "mcp_token.json").write_text("{}")
    (home / "mcp_token.json").chmod(0o644)
    audit = trs.audit_trust_root("hanuman")
    assert audit["hardened"] is False
    assert audit["secret_file_exposure"]


# ── egress key hardening (#182) ──────────────────────────────────────────────
#
# egress_trust_directory() resolves via egress_setup.config_dir(), which
# defaults to ~/.config/willow-mcp/egress — NOT under $WILLOW_HOME, so `home`
# alone does not isolate it. Every test here pins WILLOW_MCP_EGRESS_CONFIG_DIR
# into tmp_path first, or it would chown/chmod the real host directory.

@pytest.fixture
def egress_dir(tmp_path, monkeypatch):
    d = tmp_path / "egress-config"
    monkeypatch.setenv("WILLOW_MCP_EGRESS_CONFIG_DIR", str(d))
    return d


def test_egress_trust_directory_resolves_the_isolated_config_dir(egress_dir):
    assert trs.egress_trust_directory() == egress_dir


def test_egress_trust_directory_is_not_one_of_trust_root_directories(home, egress_dir):
    """The whole point of #182: this directory lives outside $WILLOW_HOME by
    design, so the pre-existing hardening loop never touched it."""
    hi.ensure_home_layout()
    assert egress_dir not in trs.trust_root_directories()


def test_apply_egress_key_hardening_reports_absent_when_never_set_up(egress_dir, monkeypatch):
    monkeypatch.setattr(trs, "resolve_trust_owner", lambda owner: "operator")
    result = trs.apply_egress_key_hardening("operator", dry_run=False)
    assert result["present"] is False
    assert result["actions"] == []


def test_apply_egress_key_hardening_uses_owner_only_mode_not_world_readable(egress_dir, monkeypatch):
    """The critical distinction from apply_trust_root_hardening: 0700/0600, not
    the 0755/0644 policy files use — a readable key needs no forgery at all."""
    egress_dir.mkdir()
    (egress_dir / "private.pem").write_text("-----BEGIN PRIVATE KEY-----\n")
    monkeypatch.setattr(trs, "resolve_trust_owner", lambda owner: "operator")
    result = trs.apply_egress_key_hardening("operator", dry_run=True)
    assert result["present"] is True
    assert any("chown -R operator:operator" in a and str(egress_dir) in a for a in result["actions"])
    assert any("chmod 600" in a for a in result["actions"])
    assert any("chmod 700" in a for a in result["actions"])
    assert not any("chmod 644" in a for a in result["actions"])
    assert not any("chmod 755" in a for a in result["actions"])


def test_harden_trust_root_includes_the_egress_step(home, egress_dir, monkeypatch):
    """ensure_home_layout() already provisions a real keypair into egress_dir
    (home_init.py calls egress_setup.ensure_keypair()) — no need to fake one."""
    hi.ensure_home_layout()
    monkeypatch.setattr(trs, "resolve_trust_owner", lambda owner: "operator")
    result = trs.harden_trust_root(owner="operator", dry_run=True)
    assert "egress" in result["filesystem"]
    assert result["filesystem"]["egress"]["present"] is True
    assert any("chmod 600" in a for a in result["filesystem"]["actions"])


def test_audit_trust_root_reports_the_egress_key_when_self_readable(home, egress_dir, monkeypatch):
    egress_dir.mkdir()
    key = egress_dir / "private.pem"
    key.write_text("-----BEGIN PRIVATE KEY-----\n")
    from willow_mcp import egress_setup
    monkeypatch.setattr(egress_setup, "resolve_private_key_path", lambda: key)
    audit = trs.audit_trust_root("app")
    keys = {f["key"] for f in audit["forgeable"]}
    assert "egress_private_key" in keys


def test_operator_command_hints_mentions_sign_net_task():
    hints = trs.operator_command_hints("operator")
    assert any("sign-net-task" in h for h in hints)


# ── uid-separation legibility report (#231) ──────────────────────────────────
#
# Distinct question from everything above: not "could this process write the
# trust root" (self_writable_trust_paths, the functional truth the verdict is
# built on) but "does the trust root's on-disk OWNER differ from this
# process's own uid" — the plain fact an operator following the
# dedicated-uid-deployment runbook checks first. This container runs single-
# uid, so "genuinely separated" is simulated by monkeypatching path_owner()
# to report a different uid, exactly as instructed for tests that cannot
# create a real second unix user.

def test_process_identity_reports_current_euid():
    me = trs.process_identity()
    assert me["uid"] == os.geteuid()
    assert me["user"]


def test_path_owner_none_for_missing_path(tmp_path):
    assert trs.path_owner(tmp_path / "does-not-exist") is None


def test_path_owner_reports_uid_and_user_for_existing_path(tmp_path):
    f = tmp_path / "present"
    f.write_text("x")
    owner = trs.path_owner(f)
    assert owner["uid"] == os.geteuid()
    assert owner["user"]


def test_uid_separation_false_on_fresh_single_uid_home(home):
    """Every file this test creates is owned by the test's own uid — the
    honest, unhardened resting state. A fresh install with nothing on disk
    yet must also report False, not a false 'separated' from an empty list."""
    hi.ensure_home_layout()
    report = trs.uid_separation_report("hanuman")
    assert report["separated"] is False
    assert report["process"]["uid"] == os.geteuid()
    assert report["same_owner_paths"]  # at least mcp_apps/config exist and match


def test_uid_separation_true_when_every_target_owned_by_another_uid(home, monkeypatch):
    """Simulates the hardened deployment (real chown to a dedicated uid is not
    possible in this single-uid container): every existing trust-root path
    resolves to a different uid than this process."""
    hi.ensure_home_layout()
    other_uid = os.geteuid() + 1

    def _fake_owner(path):
        if not Path(path).expanduser().exists():
            return None
        return {"uid": other_uid, "user": "willow-operator"}

    monkeypatch.setattr(trs, "path_owner", _fake_owner)
    report = trs.uid_separation_report("hanuman")
    assert report["separated"] is True
    assert report["same_owner_paths"] == []
    assert all(t["owned_by_this_process"] is False for t in report["targets"] if t["owner"])


def test_uid_separation_false_when_any_target_still_self_owned(home, monkeypatch):
    """Partial hardening (e.g. repair-runtime-perms restored a secret file to
    the runtime user, which happens to be this process) must not read as
    'separated' — separation is all-or-nothing across the measured surface."""
    hi.ensure_home_layout()
    other_uid = os.geteuid() + 1
    real_owner = trs.path_owner

    def _mixed_owner(path):
        owner = real_owner(path)
        if owner is None:
            return None
        if str(path).endswith("mcp_apps"):
            return owner  # left self-owned, deliberately
        return {"uid": other_uid, "user": "willow-operator"}

    monkeypatch.setattr(trs, "path_owner", _mixed_owner)
    report = trs.uid_separation_report("hanuman")
    assert report["separated"] is False
    assert any(p.endswith("mcp_apps") for p in report["same_owner_paths"])


def test_uid_separation_includes_manifest_only_when_it_exists(home):
    hi.ensure_home_layout()
    no_app = trs.uid_separation_report("")
    assert not any(t["key"] == "manifest" for t in no_app["targets"])

    manifest_dir = paths.mcp_apps_root() / "hanuman"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    (manifest_dir / "manifest.json").write_text("{}")
    with_app = trs.uid_separation_report("hanuman")
    assert any(t["key"] == "manifest" for t in with_app["targets"])


def test_audit_trust_root_includes_uid_separation(home):
    hi.ensure_home_layout()
    audit = trs.audit_trust_root("hanuman")
    assert "uid_separation" in audit
    assert audit["uid_separation"]["process"]["uid"] == os.geteuid()


def test_doctor_cli_reports_uid_separation_not_achieved(home, capsys):
    """Real (unmocked) audit_trust_root on the single-uid test home: the CLI's
    informational line must say so plainly, pointing at the runbook."""
    from willow_mcp import server

    hi.ensure_home_layout()

    class _Args:
        app_id = "hanuman"
        project_root = ""

    server._cmd_doctor(_Args())
    out = capsys.readouterr().out
    assert "uid separation: NOT separated" in out
    assert "dedicated-uid-deployment.md" in out


def test_doctor_cli_confirms_uid_separation_when_simulated_separated(home, monkeypatch, capsys):
    from willow_mcp import server, trust_root_setup

    hi.ensure_home_layout()
    other_uid = os.geteuid() + 1
    monkeypatch.setattr(
        trust_root_setup,
        "path_owner",
        lambda p: {"uid": other_uid, "user": "willow-operator"} if Path(p).expanduser().exists() else None,
    )

    class _Args:
        app_id = "hanuman"
        project_root = ""

    server._cmd_doctor(_Args())
    out = capsys.readouterr().out
    assert "uid separation: OK" in out


def test_harden_trust_root_result_carries_uid_separation_in_after(home, monkeypatch):
    """dry_run=True (as above) rather than a real chown: this sandbox has no
    `operator` unix user to chown to, and running for real is exactly what
    `require_operator_terminal` gates the CLI path on anyway. `after` mirrors
    `before` verbatim on a dry run, so this just asserts audit_trust_root()'s
    new field survives that pass-through."""
    hi.ensure_home_layout()
    monkeypatch.setattr(trs, "resolve_trust_owner", lambda owner: "operator")
    result = trs.harden_trust_root(owner="operator", dry_run=True)
    assert "uid_separation" in result["after"]


def test_doctor_cli_warns_on_secret_file_exposure(home, monkeypatch, capsys):
    """The doctor CLI's own rendering, not just audit_trust_root()'s dict --
    found live (this PR): the print block only fired when audit['forgeable']
    was truthy, so a secret-file-only exposure computed hardened=False but
    printed nothing, silently hiding it from the operator-facing output."""
    from willow_mcp import server

    (home / "mcp_token.json").write_text("{}")
    (home / "mcp_token.json").chmod(0o644)
    monkeypatch.setattr(server, "diagnostic_summary", lambda app_id: {"checks": {}})

    class _Args:
        app_id = "testapp"
        project_root = ""

    server._cmd_doctor(_Args())
    out = capsys.readouterr().out
    assert "secret_files" in out
    assert "mcp_token.json" in out
    assert "repair-runtime-perms" in out


# ── store `.db` OS-level permission hardening (#232) ──────────────────────────
#
# The client-side hook (hooks/pre_tool_use.py's _OWNED_DB_FILE_RE) blocks
# Write/Edit and raw sqlite3 against store.db/vault.db/kart.db/mcp_receipt.db
# -- but it is a tripwire in the agent's own harness, not an OS control.
# vault.db is already covered by B-46's _SECRET_FILE_NAMES; these tests cover
# the other three the same way: store.db (nested per SOIL collection under
# store_root()), kart.db (location follows WILLOW_STORE_ROOT), and
# mcp_receipt.db (now also in _SECRET_FILE_NAMES -- previously only chowned,
# never chmodded, by its own dedicated block; found while implementing #232).
#
# The `home` fixture (conftest.py) always exports WILLOW_STORE_ROOT pointed
# at tmp_path/"store", so kart.db resolves INSIDE store_root() in every test
# below unless a test explicitly unsets it -- exactly the "recommended shape"
# noted in _kart_db_candidate()'s docstring.

def test_store_db_files_empty_on_fresh_home(home):
    hi.ensure_home_layout()
    assert trs.store_db_files() == []


def test_store_db_files_finds_per_collection_store_db(home):
    col_db = paths.store_root() / "knowledge" / "store.db"
    col_db.parent.mkdir(parents=True, exist_ok=True)
    col_db.write_text("sqlite-placeholder")
    assert trs.store_db_files() == [col_db]


def test_store_db_files_finds_kart_db_without_duplicating_it(home):
    kart_db = paths.store_root() / "kart.db"
    kart_db.parent.mkdir(parents=True, exist_ok=True)
    kart_db.write_text("sqlite-placeholder")
    found = trs.store_db_files()
    assert found == [kart_db]  # not double-counted via both the glob and the explicit lookup


def test_store_db_exposure_empty_when_nothing_present(home):
    assert trs.store_db_exposure() == []


def test_store_db_exposure_detects_world_readable_collection_db(home):
    col_db = paths.store_root() / "knowledge" / "store.db"
    col_db.parent.mkdir(parents=True, exist_ok=True)
    col_db.write_text("sqlite-placeholder")
    col_db.chmod(0o644)
    exposure = trs.store_db_exposure()
    assert {"store.db"} == {e["key"] for e in exposure}
    assert exposure[0]["mode"] == oct(0o644)


def test_store_db_exposure_silent_when_properly_protected(home):
    col_db = paths.store_root() / "knowledge" / "store.db"
    col_db.parent.mkdir(parents=True, exist_ok=True)
    col_db.write_text("sqlite-placeholder")
    col_db.chmod(0o600)
    assert trs.store_db_exposure() == []


def test_audit_trust_root_not_hardened_when_store_db_exposed(home, monkeypatch):
    monkeypatch.setattr(trs.lease, "self_writable_trust_paths", lambda *_: [])
    monkeypatch.setattr(trs.lease, "path_is_self_writable_or_replaceable", lambda *_: False)
    monkeypatch.setattr(trs.lease, "path_is_directly_writable_for_trust", lambda *_: False)
    monkeypatch.setenv("WILLOW_MCP_STRICT_TRUST_ROOT", "1")
    col_db = paths.store_root() / "knowledge" / "store.db"
    col_db.parent.mkdir(parents=True, exist_ok=True)
    col_db.write_text("sqlite-placeholder")
    col_db.chmod(0o644)
    audit = trs.audit_trust_root("hanuman")
    assert audit["hardened"] is False
    assert audit["store_db_exposure"]


def test_audit_trust_root_hardened_when_store_db_protected_alongside_everything_else(home, monkeypatch):
    monkeypatch.setattr(trs.lease, "self_writable_trust_paths", lambda *_: [])
    monkeypatch.setattr(trs.lease, "path_is_self_writable_or_replaceable", lambda *_: False)
    monkeypatch.setattr(trs.lease, "path_is_directly_writable_for_trust", lambda *_: False)
    monkeypatch.setenv("WILLOW_MCP_STRICT_TRUST_ROOT", "1")
    col_db = paths.store_root() / "knowledge" / "store.db"
    col_db.parent.mkdir(parents=True, exist_ok=True)
    col_db.write_text("sqlite-placeholder")
    col_db.chmod(0o600)
    audit = trs.audit_trust_root("hanuman")
    assert audit["store_db_exposure"] == []
    assert audit["hardened"] is True


def test_repair_runtime_dry_run_plans_owner_only_mode_for_store_root(home, monkeypatch):
    """store_root() itself -- not just a named file -- gets the secret-file
    treatment: owner-only 0700/0600 recursively, same class of fix as B-46's
    vault.key, applied to the whole SOIL store tree."""
    hi.ensure_home_layout()
    monkeypatch.setattr(trs, "resolve_runtime_user", lambda _user: "runtime")
    result = trs.repair_runtime_permissions(dry_run=True)
    store_root = str(paths.store_root())
    assert any(
        f"tighten-only files<=600 dirs<=700 {store_root}" in a for a in result["actions"]
    )
    assert any(
        f"chmod 700 {store_root}" in a for a in result["actions"]
    )
    assert not any(
        f"files<=644 dirs<=755 {store_root}" in a for a in result["actions"]
    )


def test_repair_runtime_dry_run_hardens_mcp_receipt_db(home, monkeypatch):
    (home / "mcp_receipt.db").write_text("sqlite-placeholder")
    monkeypatch.setattr(trs, "resolve_runtime_user", lambda _user: "runtime")
    result = trs.repair_runtime_permissions(dry_run=True)
    receipt = str(home / "mcp_receipt.db")
    assert any(f"chmod 600 {receipt}" in a for a in result["actions"])
    assert not any(f"chmod 644 {receipt}" in a for a in result["actions"])


def test_kart_db_candidate_falls_back_outside_willow_home_when_store_root_unset(home, monkeypatch):
    """When WILLOW_STORE_ROOT is unset, task_queue.py's kart.db fallback
    lands under raw ~/.willow -- NOT paths.willow_home(), which also honors
    WILLOW_HOME -- so it can end up outside this install's home entirely.
    Pure path computation, no filesystem touched: asserts the documented
    divergence exists rather than asserting on the real host's home dir."""
    monkeypatch.delenv("WILLOW_STORE_ROOT", raising=False)
    expected = str(Path.home() / ".willow" / "kart.db")
    assert str(trs._kart_db_candidate()) == expected


def test_repair_runtime_dry_run_hardens_kart_db_wherever_it_resolves(home, monkeypatch):
    """kart.db must be named and hardened even when it lands outside
    store_root() (the WILLOW_STORE_ROOT-unset case) -- not silently skipped
    because it isn't nested under the store sweep. _kart_db_candidate() is
    monkeypatched to a safe tmp location standing in for that "outside
    store_root" case, rather than touching the real host's ~/.willow."""
    hi.ensure_home_layout()
    outside_root = home.parent / "outside-store-root"
    outside_root.mkdir()
    kart_db = outside_root / "kart.db"
    kart_db.write_text("sqlite-placeholder")
    monkeypatch.setattr(trs, "_kart_db_candidate", lambda: kart_db)
    monkeypatch.setattr(trs, "resolve_runtime_user", lambda _user: "runtime")
    result = trs.repair_runtime_permissions(dry_run=True)
    expected = str(kart_db)
    assert any(f"chown runtime:runtime {expected}" in a for a in result["actions"])
    assert any(f"chmod 600 {expected}" in a for a in result["actions"])


def test_repair_runtime_real_run_tightens_store_db_files_to_owner_only_mode(home, monkeypatch):
    """Real chmod, not a dry-run action-string assertion -- the same
    verification method B-46 used for vault.key: create real files, run
    repair_runtime_permissions() for REAL (not dry_run), then stat the
    actual mode bits on disk afterward. Ownership is monkeypatched to the
    CURRENT real unix user (this sandbox has no second account to chown to
    -- see docs/deploy/dedicated-uid-deployment.md), so the chown half is
    simulated, but the chmod calls run through the real `chmod`/`find`
    subprocess -- this proves the MODE half of #232 actually lands on disk,
    independent of the (untestable here) uid-separation half."""
    hi.ensure_home_layout()
    real_user = pwd.getpwuid(os.geteuid()).pw_name
    monkeypatch.setattr(trs, "resolve_runtime_user", lambda _user: real_user)

    col_db = paths.store_root() / "knowledge" / "store.db"
    col_db.parent.mkdir(parents=True, exist_ok=True)
    col_db.write_text("sqlite-placeholder")
    col_db.chmod(0o644)

    receipt = home / "mcp_receipt.db"
    receipt.write_text("sqlite-placeholder")
    receipt.chmod(0o644)

    kart_db = paths.store_root() / "kart.db"
    kart_db.write_text("sqlite-placeholder")
    kart_db.chmod(0o644)

    trs.repair_runtime_permissions(dry_run=False)

    for f in (col_db, receipt, kart_db):
        mode = stat.S_IMODE(f.stat().st_mode)
        assert mode == 0o600, f"{f} left at {oct(mode)}, expected owner-only 0600"
    dir_mode = stat.S_IMODE(paths.store_root().stat().st_mode)
    assert dir_mode == 0o700, f"store_root left at {oct(dir_mode)}, expected owner-only 0700"
    # And the exposure/audit surfaces agree with what's now on disk.
    assert trs.store_db_exposure() == []


def test_doctor_cli_warns_on_store_db_exposure(home, monkeypatch, capsys):
    from willow_mcp import server

    col_db = paths.store_root() / "knowledge" / "store.db"
    col_db.parent.mkdir(parents=True, exist_ok=True)
    col_db.write_text("sqlite-placeholder")
    col_db.chmod(0o644)
    monkeypatch.setattr(server, "diagnostic_summary", lambda app_id: {"checks": {}})

    class _Args:
        app_id = "testapp"
        project_root = ""

    server._cmd_doctor(_Args())
    out = capsys.readouterr().out
    assert "store_db" in out
    assert "store.db" in out
    assert "repair-runtime-perms" in out
