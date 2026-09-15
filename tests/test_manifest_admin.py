"""Tests for manifest_admin.py — the local-CLI-only permission toggle backing
`willow-mcp allow-permission` / `deny-permission`."""
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from willow_mcp import manifest_admin


@pytest.fixture
def apps_root(tmp_path, monkeypatch):
    root = tmp_path / "mcp_apps"
    root.mkdir()
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(root))
    return root


def test_set_permission_creates_manifest_when_absent(apps_root):
    manifest = manifest_admin.set_permission("newapp", "store_read", True)
    assert manifest["permissions"] == ["store_read"]
    on_disk = json.loads((apps_root / "newapp" / "manifest.json").read_text())
    assert on_disk["permissions"] == ["store_read"]


def test_set_permission_is_additive_and_dedupes(apps_root):
    manifest_admin.set_permission("app", "store_read", True)
    manifest = manifest_admin.set_permission("app", "store_read", True)
    assert manifest["permissions"] == ["store_read"]  # no duplicate


def test_set_permission_revokes(apps_root):
    manifest_admin.set_permission("app", "store_read", True)
    manifest_admin.set_permission("app", "task_net", True)
    manifest = manifest_admin.set_permission("app", "store_read", False)
    assert manifest["permissions"] == ["task_net"]


def test_set_permission_resigns_when_pgp_enforced(apps_root, monkeypatch):
    """Rewriting a manifest invalidates its detached signature, and an unsigned
    manifest is denied everywhere — so the edit path must re-sign, or the
    operator's own supported command silently revokes the app's whole gate."""
    signed: list = []
    monkeypatch.setattr(
        manifest_admin.pgp, "expected_fingerprint", lambda: "A" * 40
    )
    monkeypatch.setattr(
        manifest_admin.pgp, "verify_detached", lambda *a, **kw: (True, "ok")
    )

    def _sign(path):
        manifest_admin.pgp.detached_sig_path(path).write_bytes(b"SIGNED")
        signed.append(path)
        return True, str(path) + ".sig"

    monkeypatch.setattr(
        manifest_admin.pgp, "sign_detached", _sign,
    )
    manifest_admin.set_permission("app", "store_read", True)
    assert [p.name for p in signed] == ["manifest.json"]


def test_set_permission_rolls_back_when_resigning_fails(apps_root, monkeypatch):
    """A half-applied change that leaves an unsigned manifest is worse than no
    change: the app loses every tool it already had. Restore content *and*
    `.sig`, then raise — gpg may have clobbered the prior signature file."""
    manifest_admin.set_permission("app", "store_read", True)
    path = apps_root / "app" / "manifest.json"
    sig = path.parent / f"{path.name}.sig"
    # Plant a prior signature so rollback must restore it, not just content.
    sig.write_bytes(b"PRIOR-SIG")
    before = path.read_text()
    before_sig = sig.read_bytes()

    def _failing_sign(p):
        # Signing happens in staging, before the protected pair is touched.
        (p.parent / f"{p.name}.sig").write_bytes(b"PARTIAL")
        return False, "gpg not found on PATH"

    monkeypatch.setattr(
        manifest_admin.pgp, "expected_fingerprint", lambda: "A" * 40
    )
    monkeypatch.setattr(
        manifest_admin.pgp, "verify_detached", lambda *a, **kw: (True, "ok")
    )
    monkeypatch.setattr(manifest_admin.pgp, "sign_detached", _failing_sign)
    with pytest.raises(RuntimeError, match="refused before mutation"):
        manifest_admin.set_permission("app", "task_net", True)

    assert path.read_text() == before
    assert sig.read_bytes() == before_sig


def test_set_permission_rollback_removes_a_manifest_it_created(apps_root, monkeypatch):
    """First-permission case: there is no previous content to restore, so the
    file the failed call materialized must be removed, not left unsigned —
    including any partial `.sig` gpg may have written."""
    monkeypatch.setattr(
        manifest_admin.pgp, "expected_fingerprint", lambda: "A" * 40
    )

    def _failing_sign(p):
        (p.parent / f"{p.name}.sig").write_bytes(b"PARTIAL")
        return False, "gpg-agent unreachable"

    monkeypatch.setattr(manifest_admin.pgp, "sign_detached", _failing_sign)
    with pytest.raises(RuntimeError, match="refused before mutation"):
        manifest_admin.set_permission("fresh", "store_read", True)

    assert not (apps_root / "fresh" / "manifest.json").exists()
    assert not (apps_root / "fresh" / "manifest.json.sig").exists()


def test_set_permission_revoke_on_absent_manifest_writes_nothing(apps_root):
    """A revoke that changes nothing must not materialize a manifest: an empty
    manifest reads as `store_scope` unrestricted, while no manifest at all
    reads as deny-all (gate.py) — so this no-op must not silently widen access."""
    manifest = manifest_admin.set_permission("ghost", "store_read", False)
    assert manifest["permissions"] == []
    assert not (apps_root / "ghost" / "manifest.json").exists()


def test_set_permission_rejects_unknown_name(apps_root):
    with pytest.raises(ValueError, match="unknown permission"):
        manifest_admin.set_permission("app", "not_a_real_group", True)


def test_set_permission_preserves_other_manifest_fields(apps_root):
    app_dir = apps_root / "app"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(
        json.dumps({"permissions": ["store_read"], "store_scope": ["app_*"]})
    )
    manifest = manifest_admin.set_permission("app", "task_net", True)
    assert manifest["store_scope"] == ["app_*"]
    assert set(manifest["permissions"]) == {"store_read", "task_net"}


def test_set_permission_rejects_invalid_app_id(apps_root):
    with pytest.raises(ValueError):
        manifest_admin.set_permission("../escape", "store_read", True)


def test_set_permission_is_idempotent_under_pgp_enforcement(apps_root, monkeypatch):
    """Re-granting a permission the app already has must stay a no-op.

    `allow-permission` is the operator's supported edit path and runbooks re-run
    it defensively. Before the guard covered the `existed and not changed` case,
    a re-grant fell through to rewrite-and-re-sign: identical content, the valid
    signature it already had discarded, gpg invoked — and on a host where signing
    fails (no agent, key on another machine) the call *raised* for a change that
    changed nothing. Rollback kept the file correct, so the damage was the
    exception, not the data; an idempotent command that throws on the second run
    is still broken.
    """
    manifest_admin.set_permission("app", "store_read", True)
    path = apps_root / "app" / "manifest.json"
    before = path.read_text()

    calls: list = []
    monkeypatch.setattr(
        manifest_admin.pgp, "expected_fingerprint", lambda: "A" * 40
    )
    monkeypatch.setattr(
        manifest_admin.pgp, "sign_detached",
        lambda p: (calls.append(p) or (False, "gpg-agent unreachable")),
    )

    manifest_admin.set_permission("app", "store_read", True)   # must not raise
    assert calls == [], "a no-op re-grant must not reach the signer"
    assert path.read_text() == before

    # A revoke of something not held is the same no-op, from the other side.
    manifest_admin.set_permission("app", "task_net", False)
    assert calls == []
    assert path.read_text() == before


def test_signed_manifest_refuses_when_sudo_lost_fingerprint(apps_root):
    """An existing signed trust artifact is proof that unsigned mode is not an
    acceptable fallback.  Environment loss must refuse before either sibling
    changes."""
    manifest_admin.set_permission("app", "store_read", True)
    path = apps_root / "app" / "manifest.json"
    sig = manifest_admin.pgp.detached_sig_path(path)
    sig.write_bytes(b"PRIOR-SIG")
    before = path.read_bytes()

    with pytest.raises(RuntimeError, match="accidental side effect of sudo"):
        manifest_admin.set_permission("app", "task_net", True)

    assert path.read_bytes() == before
    assert sig.read_bytes() == b"PRIOR-SIG"


def test_permissionerror_tmp_topology_routes_only_presigned_pair(
    apps_root, monkeypatch
):
    """The deployed failure is EACCES creating manifest.json.tmp-* under the
    trust-owner directory.  Sign and verify first, then hand the immutable
    candidate to the privileged publisher; never mutate the live pair."""
    monkeypatch.setattr(
        manifest_admin.pgp, "expected_fingerprint", lambda: "A" * 40
    )
    monkeypatch.setattr(
        manifest_admin.pgp, "verify_detached", lambda *a, **kw: (True, "ok")
    )

    def _sign(path):
        manifest_admin.pgp.detached_sig_path(path).write_bytes(b"NEW-SIG")
        return True, "signed"

    monkeypatch.setattr(manifest_admin.pgp, "sign_detached", _sign)
    denied = PermissionError(
        13, "Permission denied", str(apps_root / "app" / "manifest.json.tmp-123")
    )
    monkeypatch.setattr(
        manifest_admin, "publish_signed_pair",
        lambda *a, **kw: (_ for _ in ()).throw(denied),
    )
    monkeypatch.setattr(
        manifest_admin.pgp,
        "export_public_key",
        lambda fingerprint: (b"PUBLIC-KEY", "ok"),
    )
    published = []

    manifest = manifest_admin.set_permission(
        "app",
        "store_read",
        True,
        privileged_publisher=lambda path, body, sig, key, fp, previous, perm, granted: published.append(
            (path, body, sig, key, fp, previous, perm, granted)
        ),
    )

    assert manifest["permissions"] == ["store_read"]
    assert len(published) == 1
    (
        path,
        body,
        signature,
        public_key,
        fingerprint,
        previous,
        permission,
        granted,
    ) = published[0]
    assert path == apps_root / "app" / "manifest.json"
    assert json.loads(body)["permissions"] == ["store_read"]
    assert signature == b"NEW-SIG"
    assert public_key == b"PUBLIC-KEY"
    assert fingerprint == "A" * 40
    assert previous == "absent"
    assert permission == "store_read"
    assert granted is True
    assert not path.exists()


def test_publish_signed_pair_rolls_back_both_bytes_on_second_rename_failure(
    apps_root, monkeypatch
):
    app_dir = apps_root / "app"
    app_dir.mkdir()
    path = app_dir / "manifest.json"
    sig = manifest_admin.pgp.detached_sig_path(path)
    path.write_bytes(b'{"permissions": ["store_read"]}')
    sig.write_bytes(b"PRIOR-SIG")
    previous_digest = manifest_admin._content_digest(path.read_bytes())
    monkeypatch.setattr(
        manifest_admin.pgp, "verify_detached", lambda *a, **kw: (True, "ok")
    )
    real_replace = manifest_admin.os.replace

    def _replace(src, dst):
        if Path(dst) == path and ".candidate-" in Path(src).name:
            raise PermissionError(13, "Permission denied", str(dst))
        return real_replace(src, dst)

    monkeypatch.setattr(manifest_admin.os, "replace", _replace)
    with pytest.raises(PermissionError):
        manifest_admin.publish_signed_pair(
            path,
            json.dumps(
                {"permissions": ["store_read", "task_net"]}, indent=2
            ).encode(),
            b"NEW-SIG",
            "A" * 40,
            previous_digest,
            "task_net",
            True,
        )

    assert path.read_bytes() == b'{"permissions": ["store_read"]}'
    assert sig.read_bytes() == b"PRIOR-SIG"


def test_publish_via_trust_owner_staging_dir_is_not_world_listable(
    apps_root, monkeypatch
):
    """Pre-sudo staging must not be 0o755; trust owner reaches files by path."""
    app_dir = apps_root / "app"
    app_dir.mkdir()
    path = app_dir / "manifest.json"
    monkeypatch.setattr(manifest_admin.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        manifest_admin.pwd,
        "getpwuid",
        lambda uid: SimpleNamespace(
            pw_uid=994, pw_name="willow-operator", pw_gid=os.getgid()
        ),
    )
    modes: list[int] = []
    real_chmod = manifest_admin.os.chmod

    def _chmod(p, mode):
        modes.append(mode)
        return real_chmod(p, mode)

    monkeypatch.setattr(manifest_admin.os, "chmod", _chmod)
    monkeypatch.setattr(
        manifest_admin.subprocess,
        "run",
        lambda argv, check: SimpleNamespace(returncode=0),
    )
    monkeypatch.setattr(
        manifest_admin, "_uid_can_execute_path", lambda _path, _uid: True
    )

    manifest_admin.publish_via_trust_owner(
        path,
        b'{"permissions": ["store_read"]}',
        b"SIGNED",
        b"PUBLIC-KEY",
        "B" * 40,
        "absent",
        "store_read",
        True,
    )

    assert 0o711 in modes


def test_cmd_publish_permission_uses_sudo_bridge_terminal_gate(
    apps_root, monkeypatch, tmp_path
):
    """_publish-permission must not call require_operator_terminal on trust uid."""
    from willow_mcp import human_session, server

    staged_manifest = tmp_path / "manifest.json"
    staged_sig = manifest_admin.pgp.detached_sig_path(staged_manifest)
    staged_key = tmp_path / "operator-public-key.asc"
    staged_manifest.write_bytes(b'{"permissions": ["store_read"]}')
    staged_sig.write_bytes(b"SIG")
    staged_key.write_bytes(b"KEY")

    calls: list[str] = []

    def _bridge():
        calls.append("bridge")

    def _human():
        calls.append("human")
        raise PermissionError("would block trust-owner sudo")

    monkeypatch.setattr(
        human_session, "require_trust_owner_publication_terminal", _bridge
    )
    monkeypatch.setattr(human_session, "require_operator_terminal", _human)
    published = []
    monkeypatch.setattr(
        manifest_admin,
        "publish_staged_permission",
        lambda **kw: published.append(kw),
    )

    args = SimpleNamespace(
        apps_root=str(apps_root),
        app_id="app",
        manifest=str(staged_manifest),
        signature=str(staged_sig),
        public_key=str(staged_key),
        fingerprint="C" * 40,
        previous_digest="absent",
        permission="store_read",
        action="grant",
    )
    server._cmd_publish_permission(args)

    assert calls == ["bridge"]
    assert published


def test_privilege_bridge_uses_absolute_python_and_explicit_fingerprint(
    apps_root, monkeypatch
):
    """sudo may discard PATH, HOME and WILLOW_PGP_FINGERPRINT.  The bridge
    resolves Python before sudo and passes public verification inputs as
    arguments; it never asks the trust-owner identity to sign."""
    app_dir = apps_root / "app"
    app_dir.mkdir()
    path = app_dir / "manifest.json"
    monkeypatch.setattr(manifest_admin.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        manifest_admin.pwd,
        "getpwuid",
        lambda uid: SimpleNamespace(
            pw_uid=994, pw_name="willow-operator", pw_gid=os.getgid()
        ),
    )
    calls = []
    monkeypatch.setattr(
        manifest_admin.subprocess,
        "run",
        lambda argv, check: (calls.append(argv) or SimpleNamespace(returncode=0)),
    )
    monkeypatch.setattr(
        manifest_admin, "_uid_can_execute_path", lambda _path, _uid: True
    )

    manifest_admin.publish_via_trust_owner(
        path,
        b'{"permissions": ["store_read"]}',
        b"SIGNED",
        b"PUBLIC-KEY",
        "B" * 40,
        "absent",
        "store_read",
        True,
    )

    command = calls[0]
    assert command[:4] == ["sudo", "-u", "willow-operator", "--"]
    assert Path(command[4]).is_absolute()
    assert command[5:8] == ["-m", "willow_mcp", "_publish-permission"]
    assert command[command.index("--fingerprint") + 1] == "B" * 40
    assert "gpg" not in command
    assert not any(arg.startswith("WILLOW_PGP_FINGERPRINT=") for arg in command)


def test_cli_python_for_trust_owner_keeps_venv_symlink(tmp_path, monkeypatch):
    """Resolved system python must not replace the venv entrypoint."""
    real = tmp_path / "usr" / "bin" / "python3.14"
    real.parent.mkdir(parents=True)
    real.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    os.chmod(real, 0o755)

    venv_bin = tmp_path / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python3").symlink_to(real)
    link = venv_bin / "python"
    link.symlink_to("python3")

    monkeypatch.setattr(manifest_admin.sys, "executable", str(link))
    monkeypatch.delenv("WILLOW_MCP_PYTHON", raising=False)

    chosen = manifest_admin._cli_python_for_trust_owner()
    assert str(chosen) == os.path.abspath(str(link))
    assert str(chosen) != str(Path(link).resolve())


def test_resolved_system_python_cannot_import_willow_mcp(tmp_path):
    """Live-shape check: venv entrypoint path is not the resolved base binary."""
    real = Path(sys.executable).resolve()
    venv_python = tmp_path / "venv" / "bin" / "python"
    venv_python.parent.mkdir(parents=True)
    venv_python.symlink_to(real)

    entry = os.path.abspath(str(venv_python))
    assert entry != str(real)
    assert Path(entry).resolve() == real


def test_publish_via_trust_owner_uses_venv_symlink_not_resolved_base(
    apps_root, monkeypatch, tmp_path
):
    real = Path(sys.executable).resolve()
    venv_bin = tmp_path / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    venv_python = venv_bin / "python"
    venv_python.symlink_to(real)

    monkeypatch.setattr(manifest_admin.sys, "executable", str(venv_python))
    monkeypatch.delenv("WILLOW_MCP_PYTHON", raising=False)

    app_dir = apps_root / "app"
    app_dir.mkdir()
    path = app_dir / "manifest.json"
    monkeypatch.setattr(manifest_admin.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        manifest_admin.pwd,
        "getpwuid",
        lambda uid: SimpleNamespace(
            pw_uid=994, pw_name="willow-operator", pw_gid=os.getgid()
        ),
    )
    calls: list[list[str]] = []

    real_run = subprocess.run

    def _run(argv, check=False, **kwargs):
        if isinstance(argv, list) and argv and argv[0] == "sudo":
            calls.append(argv)
            return SimpleNamespace(returncode=0)
        return real_run(argv, check=check, **kwargs)

    monkeypatch.setattr(manifest_admin.subprocess, "run", _run)
    monkeypatch.setattr(manifest_admin, "_require_python_imports_willow_mcp", lambda _p: None)
    monkeypatch.setattr(
        manifest_admin,
        "_uid_can_execute_path",
        lambda _path, _uid: True,
    )

    manifest_admin.publish_via_trust_owner(
        path,
        b'{"permissions": ["store_read"]}',
        b"SIGNED",
        b"PUBLIC-KEY",
        "B" * 40,
        "absent",
        "store_read",
        True,
    )

    sudo_cmd = calls[0]
    assert sudo_cmd[4] == os.path.abspath(str(venv_python))
    assert sudo_cmd[4] != str(real)


def test_publish_via_trust_owner_refuses_when_trust_owner_cannot_execute(
    apps_root, monkeypatch,
):
    app_dir = apps_root / "app"
    app_dir.mkdir()
    path = app_dir / "manifest.json"
    monkeypatch.setattr(manifest_admin.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        manifest_admin.pwd,
        "getpwuid",
        lambda uid: SimpleNamespace(
            pw_uid=994, pw_name="willow-operator", pw_gid=os.getgid()
        ),
    )
    monkeypatch.setattr(
        manifest_admin,
        "_uid_can_execute_path",
        lambda _path, _uid: False,
    )

    real_run = subprocess.run

    def _no_sudo(argv, check=False, **kwargs):
        if isinstance(argv, list) and argv and argv[0] == "sudo":
            pytest.fail("sudo should not run")
        return real_run(argv, check=check, **kwargs)

    monkeypatch.setattr(manifest_admin.subprocess, "run", _no_sudo)

    with pytest.raises(PermissionError, match="cannot execute"):
        manifest_admin.publish_via_trust_owner(
            path,
            b'{"permissions": ["store_read"]}',
            b"SIGNED",
            b"PUBLIC-KEY",
            "B" * 40,
            "absent",
            "store_read",
            True,
        )


def test_publisher_rejects_signed_replay_beyond_requested_permission(
    apps_root, monkeypatch
):
    app_dir = apps_root / "app"
    app_dir.mkdir()
    path = app_dir / "manifest.json"
    sig = manifest_admin.pgp.detached_sig_path(path)
    path.write_text(json.dumps({"permissions": ["store_read"]}, indent=2))
    sig.write_bytes(b"PRIOR")
    before = path.read_bytes()
    monkeypatch.setattr(
        manifest_admin.pgp, "verify_detached", lambda *a, **kw: (True, "ok")
    )

    replay = json.dumps(
        {"permissions": ["store_read", "task_net", "full_access"]}, indent=2
    ).encode()
    with pytest.raises(RuntimeError, match="exact requested one-permission"):
        manifest_admin.publish_signed_pair(
            path,
            replay,
            b"VALID-OLD-SIGNATURE",
            "A" * 40,
            manifest_admin._content_digest(before),
            "task_net",
            True,
        )

    assert path.read_bytes() == before
    assert sig.read_bytes() == b"PRIOR"
