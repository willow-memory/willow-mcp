import subprocess
from pathlib import Path

import pytest

from willow_mcp import worker_service as ws


@pytest.fixture
def config(tmp_path):
    return ws.WorkerServiceConfig(
        python=Path("/opt/willow-mcp/bin/python"),
        workdir=tmp_path / "checkout",
        willow_home=tmp_path / "home",
        store_root=tmp_path / "store",
        pg_db="willow_mcp_prod",
        pg_user="willow_role",
        app_id="worker-host",
        heartbeat_root=tmp_path / "heartbeats",
        sandbox_config=tmp_path / "home" / "kart-sandbox.json",
    )


@pytest.mark.parametrize("lane", ws.LANES)
def test_clean_install_renders_standalone_worker_units(config, lane):
    unit = ws.render_unit(lane, config)
    assert "[Service]" in unit
    assert f"--lane {lane}" in unit
    assert "--require-postgres" in unit
    assert "WILLOW_HOME=" in unit
    assert "WILLOW_STORE_ROOT=" in unit
    assert "WILLOW_PG_DB=willow_mcp_prod" in unit
    assert "WILLOW_PG_USER=willow_role" in unit
    assert "WILLOW_APP_ID=worker-host" in unit
    assert "WILLOW_WORKER_LANE=" in unit
    assert "WILLOW_WORKER_HEARTBEAT_ROOT=" in unit
    # The seam that the 2026-07-20 units were missing. Rendered units carried no
    # KART_SANDBOX_CONFIG and no EnvironmentFile, so kartikeya silently used its
    # vendored policy and both lanes failed every task for 28 hours.
    assert f'Environment="KART_SANDBOX_CONFIG={config.sandbox_config}"' in unit
    # ...as a literal Environment=, never through an EnvironmentFile: that file
    # is read at exec time, so editing it cannot reach a running worker. The one
    # EnvironmentFile a worker carries is the optional inference-only env.kart
    # (Nestor pair b1e88cda), never the full $WILLOW_HOME/env, which holds the Nestor
    # seal key.
    env_files = [
        line for line in unit.splitlines() if line.startswith("EnvironmentFile=")
    ]
    assert env_files == [f"EnvironmentFile=-{config.willow_home}/env.kart"]
    assert "willow-2.0" not in unit
    assert "@" not in unit


def test_install_writes_both_lanes_without_starting_services(
    config, tmp_path
):
    result = ws.install_services(config, destination=tmp_path, reload=False)
    assert len(result["installed"]) == 2
    assert result["started"] == []
    assert result["enabled"] == []
    assert (tmp_path / ws.unit_name("fast")).is_file()
    assert (tmp_path / ws.unit_name("batch")).is_file()


def test_default_config_carries_pg_user_from_env(monkeypatch):
    monkeypatch.setenv("WILLOW_PG_USER", "willow_role")
    assert ws.default_config().pg_user == "willow_role"


def test_default_config_pg_user_falls_back_to_os_user(monkeypatch):
    monkeypatch.delenv("WILLOW_PG_USER", raising=False)
    monkeypatch.setenv("USER", "deploybot")
    assert ws.default_config().pg_user == "deploybot"


def test_default_config_pg_user_never_empty(monkeypatch):
    # An empty Environment value would fail _safe at render; the unit must always
    # name a concrete role.
    monkeypatch.delenv("WILLOW_PG_USER", raising=False)
    monkeypatch.delenv("USER", raising=False)
    assert ws.default_config().pg_user == "willow"


def test_repository_and_packaged_worker_templates_match():
    repository = Path(__file__).resolve().parents[1] / "deploy" / ws.template_path().name
    assert repository.read_text() == ws.template_path().read_text()


def _runner(states, calls):
    def run(*args):
        calls.append(args)
        if args[0] == "is-active":
            state = states.get(args[1], "inactive")
            return subprocess.CompletedProcess(
                args, 0 if state == "active" else 3, stdout=state + "\n", stderr=""
            )
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    return run


def test_status_distinguishes_installed_active_and_inactive(
    config, tmp_path
):
    ws.install_services(config, destination=tmp_path, reload=False)
    calls = []
    runner = _runner({ws.unit_name("fast"): "active"}, calls)
    result = ws.service_status(destination=tmp_path, runner=runner)
    by_lane = {service["lane"]: service for service in result["services"]}
    assert by_lane["fast"]["active"] is True
    assert by_lane["batch"]["active"] is False
    assert all(service["installed"] for service in by_lane.values())


def test_uninstall_refuses_to_stop_an_active_service(
    config, tmp_path
):
    ws.install_services(config, destination=tmp_path, reload=False)
    runner = _runner({ws.unit_name("batch"): "active"}, [])
    with pytest.raises(RuntimeError, match="stop them explicitly"):
        ws.uninstall_services(
            destination=tmp_path, reload=False, runner=runner
        )
    assert (tmp_path / ws.unit_name("batch")).exists()


def test_uninstall_removes_inactive_units_without_stop_calls(
    config, tmp_path
):
    ws.install_services(config, destination=tmp_path, reload=False)
    calls = []
    runner = _runner({}, calls)
    result = ws.uninstall_services(
        destination=tmp_path, reload=True, runner=runner
    )
    assert len(result["removed"]) == 2
    assert result["stopped"] == []
    assert all(call[0] != "stop" for call in calls)
    assert ("daemon-reload",) in calls
