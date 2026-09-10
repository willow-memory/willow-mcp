"""CLI smoke tests for egress onboarding commands."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _run(*args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    import os

    merged = {**os.environ, **(env or {})}
    return subprocess.run(
        [sys.executable, "-m", "willow_mcp", *args],
        capture_output=True,
        text=True,
        env=merged,
        check=False,
    )


def test_setup_egress_creates_manifest(tmp_path, monkeypatch):
    cfg = tmp_path / "egress"
    willow_home = tmp_path / "willow"
    willow_home.mkdir()
    monkeypatch.setenv("WILLOW_MCP_EGRESS_CONFIG_DIR", str(cfg))
    monkeypatch.setenv("WILLOW_HOME", str(willow_home))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(willow_home))

    out = _run("setup-egress")
    assert out.returncode == 0, out.stderr
    payload = json.loads(out.stdout.split("\n\n")[0])
    assert payload["action"] == "created"
    assert Path(payload["private_key"]).is_file()
    assert Path(payload["public_key"]).is_file()
    assert (cfg / "manifest.json").is_file()


def _willow_home(tmp_path, monkeypatch):
    willow_home = tmp_path / "willow"
    willow_home.mkdir()
    monkeypatch.setenv("WILLOW_HOME", str(willow_home))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(willow_home / "mcp_apps"))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(willow_home / "store"))
    monkeypatch.delenv("WILLOW_MCP_STRICT_TRUST_ROOT", raising=False)
    monkeypatch.delenv("WILLOW_IN_KART", raising=False)
    return willow_home


# ── dev-net: one command for the three legitimate open-web grants (#287) ─────

def test_dev_net_grants_all_three_keys_when_consent_already_on(tmp_path, monkeypatch):
    willow_home = _willow_home(tmp_path, monkeypatch)
    apps = willow_home / "mcp_apps" / "devapp"
    apps.mkdir(parents=True)
    (apps / "manifest.json").write_text(json.dumps({"permissions": ["web_read"]}))
    # Consent already granted — dev-net must not need a TTY for this run.
    (willow_home / "config").mkdir(parents=True)
    (willow_home / "config" / "settings.global.json").write_text(
        json.dumps({"consent": {"internet": True, "cloud_llm": False}})
    )

    out = _run("dev-net", "devapp", "--ttl", "30m", "--issuer", "ci", "--reason", "test")
    assert out.returncode == 0, out.stderr

    manifest = json.loads((apps / "manifest.json").read_text())
    assert "web_net" in manifest["permissions"]

    lease_file = willow_home / "mcp_apps" / "_net_leases" / "devapp.json"
    assert lease_file.is_file()
    lease_record = json.loads(lease_file.read_text())
    assert lease_record["app_id"] == "devapp"
    assert lease_record["issuer"] == "ci"

    # The trailing block of stdout is the egress_status JSON dump.
    json_start = out.stdout.index("{")
    status = json.loads(out.stdout[json_start:])
    assert status["app_id"] == "devapp"
    assert status["egress_permitted"] is True
    assert status["keys"]["manifest_permission"]["granted"] is True
    assert status["keys"]["operator_consent"]["granted"] is True
    assert status["keys"]["egress_lease"]["granted"] is True


def test_dev_net_refuses_without_tty_when_consent_still_needs_changing(tmp_path, monkeypatch):
    willow_home = _willow_home(tmp_path, monkeypatch)
    apps = willow_home / "mcp_apps" / "devapp"
    apps.mkdir(parents=True)
    (apps / "manifest.json").write_text(json.dumps({"permissions": ["web_read"]}))
    # No consent file at all — consent.internet_permitted() reads False, so
    # dev-net must attempt the mutation, which requires an operator terminal.
    # subprocess.run's stdin is never a real tty, so this must fail closed.

    out = _run("dev-net", "devapp", "--ttl", "30m")
    assert out.returncode != 0
    assert "consent" in out.stderr.lower()
    # The manifest permission grant may have landed (it needs no TTY), but no
    # lease should exist — the sequence must not silently skip the consent
    # failure and grant a lease anyway.
    lease_file = willow_home / "mcp_apps" / "_net_leases" / "devapp.json"
    assert not lease_file.is_file()


def test_dev_net_refuses_when_strict_trust_root_is_set_without_force(tmp_path, monkeypatch):
    willow_home = _willow_home(tmp_path, monkeypatch)
    monkeypatch.setenv("WILLOW_MCP_STRICT_TRUST_ROOT", "1")

    out = _run(
        "dev-net", "devapp", "--ttl", "30m",
        env={"WILLOW_MCP_STRICT_TRUST_ROOT": "1"},
    )
    assert out.returncode != 0
    assert "STRICT_TRUST_ROOT" in out.stderr or "strict" in out.stderr.lower()
    lease_file = willow_home / "mcp_apps" / "_net_leases" / "devapp.json"
    assert not lease_file.is_file()


def test_dev_net_cannot_run_inside_kart(tmp_path, monkeypatch):
    _willow_home(tmp_path, monkeypatch)
    out = _run("dev-net", "devapp", "--ttl", "30m", env={"WILLOW_IN_KART": "1"})
    assert out.returncode != 0
    assert "Kart" in out.stderr


def test_setup_egress_merges_mcp_json(tmp_path, monkeypatch):
    cfg = tmp_path / "egress"
    willow_home = tmp_path / "willow"
    willow_home.mkdir()
    project = tmp_path / "proj"
    mcp_json = project / ".cursor" / "mcp.json"
    mcp_json.parent.mkdir(parents=True)
    mcp_json.write_text(
        json.dumps({"mcpServers": {"willow-mcp": {"command": "willow-mcp"}}}) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("WILLOW_MCP_EGRESS_CONFIG_DIR", str(cfg))
    monkeypatch.setenv("WILLOW_HOME", str(willow_home))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(willow_home))

    out = _run("setup-egress", "--project-root", str(project))
    assert out.returncode == 0, out.stderr
    data = json.loads(mcp_json.read_text(encoding="utf-8"))
    assert "WILLOW_MCP_EGRESS_PUBLIC_KEY" in data["mcpServers"]["willow-mcp"]["env"]


# ── the signing subcommand is terminal, like every one around it ─────────────

def test_sign_net_task_does_not_fall_through_into_the_server(monkeypatch):
    """`sign-net-task` must return, not boot the stdio server after signing.

    Its dispatch branch was the only one in `_main` without a `return`, so the
    envelope printed and then the process started serving stdio. To an operator
    at a terminal that is indistinguishable from a hang, and the envelope they
    came for has already scrolled past — measured live 2026-09-09, twice, before
    the cause was read out of the source.
    """
    from willow_mcp import server

    signed = []
    monkeypatch.setattr(server, "_cmd_sign_net_task", lambda args: signed.append(args.app_id))

    def _served(*_args, **_kwargs):
        raise AssertionError("_main fell through into the server after signing")

    monkeypatch.setattr(server.mcp, "run", _served)
    monkeypatch.setattr(
        server.sys,
        "argv",
        ["willow-mcp", "sign-net-task", "--task", "# allow_net\ntrue", "willow"],
    )

    server._main()

    assert signed == ["willow"]
