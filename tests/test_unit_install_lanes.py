"""unit.install for the worker lane family, and the downgrade guard.

The worker template is shared by both lanes, so it declares
`willow-mcp-worker-@LANE@.service`. Verb 17 installs
`willow-mcp-worker-fast.service` / `-batch.service` from it, with the lane read
from the unit name and the rest filled by worker_service.default_config(), the
keyboard installer's own resolver.

A reinstall must never weaken the unit it replaces. On 2026-09-29 the live
worker units carried WILLOW_MCP_STRICT_TRUST_ROOT=1 and WILLOW_ROOT, hand-added,
and the template carried neither, so any reinstall would have dropped both.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.test_unit_install import (
    REPO,
    TEMPLATE,
    _charter,
    _citations,
    _Fake,
    _FakeGovernancePg,
    _install,
)
from willow_mcp import unit_install_executor as uix
from willow_mcp import worker_service as ws

_REPO_ROOT = Path(__file__).resolve().parent.parent
WORKER_TEMPLATE = (_REPO_ROOT / "deploy" / "willow-mcp-worker.service.template").read_text(encoding="utf-8")
WSRC = f"{REPO}@deploy/willow-mcp-worker.service.template"
FAST = "willow-mcp-worker-fast.service"


@pytest.fixture
def worker_root(tmp_path):
    clone = tmp_path / "wgh" / "willow-memory" / "willow-mcp"
    (clone / ".git").mkdir(parents=True)
    (clone / "deploy").mkdir()
    (clone / "deploy" / "willow-mcp-worker.service.template").write_text(WORKER_TEMPLATE, encoding="utf-8")
    return tmp_path / "wgh"


@pytest.fixture
def github_root(tmp_path):
    """The nestor-ui clone test_unit_install uses, defined here rather than
    imported: an imported fixture shadows the test argument (F811)."""
    clone = tmp_path / "gh" / "willow-memory" / "willow-mcp"
    (clone / ".git").mkdir(parents=True)
    (clone / "deploy").mkdir()
    (clone / "deploy" / "nestor-ui.service.template").write_text(TEMPLATE, encoding="utf-8")
    return tmp_path / "gh"


@pytest.fixture
def dest(tmp_path):
    d = tmp_path / "systemd-user"
    d.mkdir()
    return d


def _live_unit(strict: str = "1", *, willow_root: bool = True) -> str:
    """The shape of the hand-maintained live worker unit (settings only)."""
    lines = [
        "[Service]",
        'Environment="WILLOW_HOME=/srv/wh"',
        f'Environment="WILLOW_MCP_STRICT_TRUST_ROOT={strict}"',
    ]
    if willow_root:
        lines.append('Environment="WILLOW_ROOT=/srv/wd"')
    lines += ['Environment="WILLOW_APP_ID=willow"', "ExecStart=/srv/venv/bin/willow-mcp worker --lane fast"]
    return "\n".join(lines) + "\n"


def _worker_install(pg, fake, root, dest, unit=FAST, **kw):
    kw.setdefault("values", None)  # real render_values + lane_values
    return _install(pg, fake, root, dest, unit=unit, source=WSRC, **kw)


# ── the name ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("unit,expected", [
    ("willow-mcp-worker-fast.service", (True, "fast")),
    ("willow-mcp-worker-batch.service", (True, "batch")),
    ("willow-mcp-worker-slow.service", (False, "")),
    ("willow-mcp-worker-.service", (False, "")),
    ("other-fast.service", (False, "")),
])
def test_lane_family_matches_only_admitted_lanes(unit, expected):
    assert uix.match_declared("willow-mcp-worker-@LANE@.service", unit) == expected


def test_plain_declared_name_is_unchanged():
    assert uix.match_declared("nestor-ui.service", "nestor-ui.service") == (True, "")
    assert uix.match_declared("nestor-ui.service", "other.service") == (False, "")


def test_unregistered_lane_family_never_matches():
    assert uix.match_declared("rogue-@LANE@.service", "rogue-fast.service") == (False, "")


def test_template_declares_the_worker_family():
    path = _REPO_ROOT / "deploy" / "willow-mcp-worker.service.template"
    assert uix.declared_unit_name(WORKER_TEMPLATE, path) == "willow-mcp-worker-@LANE@.service"


# ── the install ──────────────────────────────────────────────────────────────

def test_worker_lane_installs_with_lane_and_work_root(home, tmp_path, monkeypatch, worker_root, dest):
    monkeypatch.delenv("WILLOW_MCP_STRICT_TRUST_ROOT", raising=False)
    _charter(tmp_path, monkeypatch, units=(FAST,), sources=(WSRC,))
    out = _worker_install(_FakeGovernancePg(), _Fake(), worker_root, dest)
    assert out["ok"] and out["installed"], out
    body = (dest / FAST).read_text(encoding="utf-8")
    clone = worker_root / "willow-memory" / "willow-mcp"
    assert 'Environment="WILLOW_WORKER_LANE=fast"' in body
    assert f'Environment="WILLOW_ROOT={clone}"' in body
    assert f"WorkingDirectory={clone}" in body
    assert "EnvironmentFile=-" in body and body.split("EnvironmentFile=-", 1)[1].split("\n", 1)[0].endswith("/env.kart")
    # A fresh box, non-strict installer: strict is written off, explicitly.
    assert 'Environment="WILLOW_MCP_STRICT_TRUST_ROOT=0"' in body
    assert "@" not in body


def test_unknown_lane_is_ENAME_before_any_citation(home, tmp_path, monkeypatch, worker_root, dest):
    _charter(tmp_path, monkeypatch, units=("willow-mcp-worker-slow.service",), sources=(WSRC,))
    pg = _FakeGovernancePg()
    out = _worker_install(pg, _Fake(), worker_root, dest, unit="willow-mcp-worker-slow.service")
    assert out["error"] == "ENAME"
    assert _citations(pg) == []
    assert not (dest / "willow-mcp-worker-slow.service").exists()


def test_strict_is_carried_forward_from_the_replaced_unit(home, tmp_path, monkeypatch, worker_root, dest):
    # The desk broker runs non-strict; the worker it replaces is strict.
    monkeypatch.delenv("WILLOW_MCP_STRICT_TRUST_ROOT", raising=False)
    (dest / FAST).write_text(_live_unit("1"), encoding="utf-8")
    _charter(tmp_path, monkeypatch, units=(FAST,), sources=(WSRC,))
    out = _worker_install(_FakeGovernancePg(), _Fake(), worker_root, dest)
    assert out["ok"], out
    assert 'Environment="WILLOW_MCP_STRICT_TRUST_ROOT=1"' in (dest / FAST).read_text(encoding="utf-8")


def test_strict_from_a_strict_installer(home, tmp_path, monkeypatch, worker_root, dest):
    monkeypatch.setenv("WILLOW_MCP_STRICT_TRUST_ROOT", "1")
    _charter(tmp_path, monkeypatch, units=(FAST,), sources=(WSRC,))
    out = _worker_install(_FakeGovernancePg(), _Fake(), worker_root, dest)
    assert out["ok"], out
    assert 'Environment="WILLOW_MCP_STRICT_TRUST_ROOT=1"' in (dest / FAST).read_text(encoding="utf-8")


# ── the downgrade guard ──────────────────────────────────────────────────────

def test_turning_strict_off_is_EDOWNGRADE_and_touches_nothing(home, tmp_path, monkeypatch, worker_root, dest):
    before = _live_unit("1")
    (dest / FAST).write_text(before, encoding="utf-8")
    _charter(tmp_path, monkeypatch, units=(FAST,), sources=(WSRC,))
    pg = _FakeGovernancePg()
    values = {
        "PYTHON": "/v/bin/python", "WILLOW_HOME": "/srv/wh", "WILLOW_STORE_ROOT": "/srv/store",
        "WORKDIR": "/srv/wd", "WILLOW_PG_DB": "w", "WILLOW_PG_USER": "w", "APP_ID": "willow",
        "HEARTBEAT_ROOT": "/srv/hb", "KART_SANDBOX_CONFIG": "/srv/k.json",
        "STRICT_TRUST_ROOT": "0",
    }
    out = _worker_install(pg, _Fake(), worker_root, dest, values=values)
    assert out["error"] == "EDOWNGRADE", out
    assert "WILLOW_MCP_STRICT_TRUST_ROOT would turn off" in out["downgrades"]
    assert (dest / FAST).read_text(encoding="utf-8") == before
    assert _citations(pg) == []


def test_dropping_willow_root_is_EDOWNGRADE(home, tmp_path, monkeypatch, github_root, dest):
    # nestor-ui's template carries no WILLOW_ROOT; installing it over a unit
    # that has one would drop it. The guard is generic, not worker-only.
    before = 'Environment="WILLOW_ROOT=/srv/wd"\n'
    (dest / "nestor-ui.service").write_text(before, encoding="utf-8")
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    out = _install(pg, _Fake(), github_root, dest)
    assert out["error"] == "EDOWNGRADE", out
    assert (dest / "nestor-ui.service").read_text(encoding="utf-8") == before
    assert _citations(pg) == []


@pytest.mark.parametrize("existing,rendered,expected", [
    ("", 'Environment="WILLOW_MCP_STRICT_TRUST_ROOT=0"', []),
    (_live_unit("1"), _live_unit("1"), []),
    (_live_unit("0"), _live_unit("0"), []),
    (_live_unit("1"), _live_unit("0"), ["WILLOW_MCP_STRICT_TRUST_ROOT would turn off"]),
    (_live_unit("1"), _live_unit("1", willow_root=False), ["WILLOW_ROOT would be dropped"]),
])
def test_posture_downgrades(existing, rendered, expected):
    assert uix.posture_downgrades(existing, rendered) == expected


# ── the live settings survive the template ───────────────────────────────────

def test_every_live_worker_setting_survives_the_template(tmp_path):
    """Render the repo template with the live box's values and require every
    setting today's hand-maintained unit carries. This is the drift that
    would have silently stripped strict trust root and the work root."""
    config = ws.WorkerServiceConfig(
        python=Path("/srv/venv/bin/python"), workdir=Path("/srv/wd"),
        willow_home=Path("/srv/wh"), store_root=Path("/srv/wh/store"),
        pg_db="willow_20", pg_user="op", app_id="willow",
        heartbeat_root=Path("/srv/wh/worker_heartbeat"),
        sandbox_config=Path("/srv/wh/kart-sandbox.json"), strict_trust_root="1",
    )
    rendered = uix._env_lines(ws.render_unit("fast", config))
    live = {
        "WILLOW_HOME": "/srv/wh",
        "WILLOW_MCP_STRICT_TRUST_ROOT": "1",
        "WILLOW_ROOT": "/srv/wd",
        "WILLOW_STORE_ROOT": "/srv/wh/store",
        "WILLOW_PG_DB": "willow_20",
        "WILLOW_PG_USER": "op",
        "WILLOW_APP_ID": "willow",
        "WILLOW_WORKER_LANE": "fast",
        "WILLOW_WORKER_HEARTBEAT_ROOT": "/srv/wh/worker_heartbeat",
    }
    missing = {k: v for k, v in live.items() if rendered.get(k) != v}
    assert missing == {}, f"the template would drop or change live settings: {missing}"
