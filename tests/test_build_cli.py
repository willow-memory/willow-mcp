"""CLI smoke tests for grant-build / revoke-build / build-status / earn-check.

The rule these implement: a tool tagged EARN-FIRST leaves that tier only when
an operator holds an active build lease for it. The CLI is local-only and
never mintable from an MCP tool — same posture as `grant-net`.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys


def _run(*args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    merged = {**os.environ, **(env or {})}
    return subprocess.run(
        [sys.executable, "-m", "willow_mcp", *args],
        capture_output=True,
        text=True,
        env=merged,
        check=False,
    )


def _home(tmp_path, monkeypatch):
    willow_home = tmp_path / "willow"
    willow_home.mkdir()
    monkeypatch.setenv("WILLOW_HOME", str(willow_home))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(willow_home / "mcp_apps"))
    monkeypatch.delenv("WILLOW_MCP_STRICT_TRUST_ROOT", raising=False)
    return willow_home


# ── grant / revoke / status roundtrip ────────────────────────────────────────

def test_grant_build_writes_a_lease_file(tmp_path, monkeypatch):
    home = _home(tmp_path, monkeypatch)
    out = _run(
        "grant-build", "workflow",
        "--ttl", "30m", "--issuer", "sean",
        "--reason", "ship the multi-phase engine",
    )
    assert out.returncode == 0, out.stderr
    assert "expires" in out.stdout
    assert "sean" in out.stdout

    lease_file = home / "mcp_apps" / "_build_leases" / "workflow.json"
    assert lease_file.is_file()
    record = json.loads(lease_file.read_text())
    assert record["tool"] == "workflow"
    assert record["issuer"] == "sean"
    assert "multi-phase" in record["reason"]
    assert 0 < record["ttl_seconds"] <= 1800


def test_grant_build_refuses_ttl_over_ceiling(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    out = _run("grant-build", "workflow", "--ttl", "4h", "--issuer", "sean")
    assert out.returncode != 0
    assert "ceiling" in out.stderr


def test_grant_build_notes_missing_reason(tmp_path, monkeypatch):
    """No --reason still writes a lease, but the CLI flags it — the rule this
    seal opens is 'operator asks AND agrees,' and the reason is where the
    agreement lives."""
    _home(tmp_path, monkeypatch)
    out = _run("grant-build", "workflow", "--ttl", "10m", "--issuer", "sean")
    assert out.returncode == 0, out.stderr
    assert "NOTE" in out.stderr
    assert "reason" in out.stderr


def test_revoke_build_removes_the_lease(tmp_path, monkeypatch):
    home = _home(tmp_path, monkeypatch)
    _run("grant-build", "workflow", "--ttl", "10m", "--issuer", "sean")
    lease_file = home / "mcp_apps" / "_build_leases" / "workflow.json"
    assert lease_file.is_file()

    out = _run("revoke-build", "workflow")
    assert out.returncode == 0, out.stderr
    assert "revoked" in out.stdout
    assert not lease_file.exists()


def test_revoke_build_is_idempotent(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    out = _run("revoke-build", "workflow")
    assert out.returncode == 0, out.stderr
    assert "was not present" in out.stdout


def test_build_status_lists_leases(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    _run("grant-build", "workflow", "--ttl", "10m", "--issuer", "sean")
    _run("grant-build", "intake", "--ttl", "10m", "--issuer", "sean")

    out = _run("build-status")
    assert out.returncode == 0, out.stderr
    assert "workflow" in out.stdout
    assert "intake" in out.stdout
    assert "active" in out.stdout


def test_build_status_empty_message(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    out = _run("build-status")
    assert out.returncode == 0, out.stderr
    assert "No build leases" in out.stdout
    assert "grant-build" in out.stdout  # tells the user how to earn one


def test_build_status_json_matches_read_only_convention(tmp_path, monkeypatch):
    """`--json` mirrors the convention `net-status` / `earn-check` /
    `gates --json` already use — machine output for status readers."""
    _home(tmp_path, monkeypatch)
    _run("grant-build", "workflow", "--ttl", "30m", "--issuer", "sean",
         "--reason", "ship it")

    out = _run("build-status", "--json")
    assert out.returncode == 0, out.stderr
    payload = json.loads(out.stdout)
    assert "leases" in payload
    active = [r for r in payload["leases"] if r["status"] == "active"]
    assert len(active) == 1
    assert active[0]["tool"] == "workflow"
    assert active[0]["issuer"] == "sean"


def test_build_status_json_empty_is_still_valid_json(tmp_path, monkeypatch):
    """Zero leases must emit `{"leases": []}`, not the human message —
    a caller parsing the stream cannot handle a prose fallback."""
    _home(tmp_path, monkeypatch)
    out = _run("build-status", "--json")
    assert out.returncode == 0, out.stderr
    payload = json.loads(out.stdout)
    assert payload == {"leases": []}


def test_build_status_json_scoped_to_one_tool(tmp_path, monkeypatch):
    """The positional `tool` arg still narrows the machine output."""
    _home(tmp_path, monkeypatch)
    _run("grant-build", "workflow", "--ttl", "30m", "--issuer", "sean")
    _run("grant-build", "intake", "--ttl", "30m", "--issuer", "sean")

    out = _run("build-status", "workflow", "--json")
    assert out.returncode == 0, out.stderr
    payload = json.loads(out.stdout)
    assert {row["tool"] for row in payload["leases"]} == {"workflow"}


# ── earn-check: the status readout that replaces re-litigation ───────────────

def test_earn_check_reports_dry_when_nothing_is_leased(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    out = _run("earn-check", "--json")
    assert out.returncode == 0, out.stderr
    payload = json.loads(out.stdout)
    assert payload["roster"]
    assert all(row["state"] == "dry" for row in payload["roster"])
    tally = {row["state"] for row in payload["roster"]}
    assert tally == {"dry"}


def test_earn_check_flips_a_family_to_ready(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    _run("grant-build", "workflow", "--ttl", "30m", "--issuer", "sean",
         "--reason", "ship multi-phase")

    out = _run("earn-check", "--json")
    assert out.returncode == 0, out.stderr
    payload = json.loads(out.stdout)
    row = next(r for r in payload["roster"] if r["family"] == "workflow")
    assert row["state"] == "ready"
    assert row["issuer"] == "sean"
    assert row["remaining_seconds"] and row["remaining_seconds"] > 0

    # The other roster rows stay dry.
    dry = [r for r in payload["roster"] if r["family"] != "workflow"]
    assert dry and all(r["state"] == "dry" for r in dry)


def test_earn_check_human_output_shows_the_tally(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    _run("grant-build", "workflow", "--ttl", "30m", "--issuer", "sean",
         "--reason", "ship it")

    out = _run("earn-check")
    assert out.returncode == 0, out.stderr
    assert "earn-first roster" in out.stdout
    assert "ready:1" in out.stdout
    assert "workflow" in out.stdout


def test_earn_check_surfaces_leases_outside_the_roster(tmp_path, monkeypatch):
    """A build lease for a family not yet in the doc must still be visible —
    silent invisibility is exactly what a status readout must not do."""
    _home(tmp_path, monkeypatch)
    _run("grant-build", "brand-new-family", "--ttl", "10m", "--issuer", "sean",
         "--reason", "one-off")

    out = _run("earn-check", "--json")
    payload = json.loads(out.stdout)
    extras = {row["family"] for row in payload["extras"]}
    assert "brand-new-family" in extras


# ── the roster does not leak into gate.list_app_ids ──────────────────────────

def test_build_leases_dir_is_skipped_by_list_app_ids(tmp_path, monkeypatch):
    """`_build_leases/` sits under mcp_apps/ for the sandbox mount, but it is
    not an app — it must not appear in the app listing gate uses."""
    home = _home(tmp_path, monkeypatch)
    # Create one real app and one build-lease.
    (home / "mcp_apps" / "realapp").mkdir(parents=True)
    (home / "mcp_apps" / "realapp" / "manifest.json").write_text(
        json.dumps({"permissions": []})
    )
    _run("grant-build", "workflow", "--ttl", "10m", "--issuer", "sean")

    from willow_mcp import gates_panel  # imported here so env is applied first
    apps = gates_panel.list_app_ids()
    assert "realapp" in apps
    assert "_build_leases" not in apps
    assert "_net_leases" not in apps
