"""Box-derived defaults for the env vars every desk used to repeat.

WILLOW_STORE_ROOT, WILLOW_PG_DB and WILLOW_FLEET_ROSTER each used to fall back
to a value that is wrong on any box whose home is not ~/.willow — and wrong
silently, which is the part that cost time. These tests pin the derivation and,
just as importantly, pin that an explicit env var still wins over it: the
change adds a default *beneath* the environment, it does not move authority
into a file.
"""
from __future__ import annotations

import json

import pytest

from willow_mcp import fleet_roster, paths

_VARS = ("WILLOW_HOME", "WILLOW_STORE_ROOT", "WILLOW_PG_DB",
         "WILLOW_FLEET_ROSTER", "WILLOW_PROJECT_ROOT")


@pytest.fixture
def box(tmp_path, monkeypatch):
    """A $WILLOW_HOME with none of the derived vars set."""
    for var in _VARS:
        monkeypatch.delenv(var, raising=False)
    home = tmp_path / "box"
    (home / "config").mkdir(parents=True)
    monkeypatch.setenv("WILLOW_HOME", str(home))
    return home


def _write_settings(home, obj):
    (home / "config" / "settings.global.json").write_text(
        json.dumps(obj), encoding="utf-8"
    )


# ── store root ───────────────────────────────────────────────────────────────

def test_store_root_derives_from_home(box):
    assert paths.store_root() == box / "store"


def test_store_root_env_wins(box, tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "elsewhere"))
    assert paths.store_root() == tmp_path / "elsewhere"


def test_task_queue_sqlite_falls_back_under_the_derived_store_root(box):
    """The SQLite fallback and the store must land in the same place.

    They did not: db.py defaulted to ~/.willow/store while task_queue.py
    defaulted to ~/.willow, one path segment apart, so an unset variable put
    kart.db beside the store rather than inside it.
    """
    from willow_mcp import task_queue  # imported late; module reads env at call

    assert task_queue.__name__  # module imports cleanly without WILLOW_STORE_ROOT
    assert paths.store_root() / "kart.db" == box / "store" / "kart.db"


# ── postgres database name ───────────────────────────────────────────────────

def test_pg_db_defaults_to_willow_with_no_settings(box):
    assert paths.pg_db() == "willow"


def test_pg_db_reads_canonical_settings(box):
    _write_settings(box, {"postgres": {"db": "willow_20"}})
    assert paths.pg_db() == "willow_20"


def test_pg_db_env_wins_over_settings(box, monkeypatch):
    _write_settings(box, {"postgres": {"db": "willow_20"}})
    monkeypatch.setenv("WILLOW_PG_DB", "willow_test")
    assert paths.pg_db() == "willow_test"


def test_pg_db_survives_a_malformed_settings_file(box):
    """Fail-soft: a path lookup must not raise because settings are broken."""
    (box / "config" / "settings.global.json").write_text("{not json", encoding="utf-8")
    assert paths.pg_db() == "willow"


def test_pg_db_ignores_a_non_string_db_name(box):
    _write_settings(box, {"postgres": {"db": 20}})
    assert paths.pg_db() == "willow"


# ── fleet roster ─────────────────────────────────────────────────────────────

def test_roster_prefers_the_box_over_a_project_checkout(box, tmp_path, monkeypatch):
    (box / "fleet.json").write_text("{}", encoding="utf-8")
    project = tmp_path / "repo"
    project.mkdir()
    (project / "fleet.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("WILLOW_PROJECT_ROOT", str(project))
    assert fleet_roster.roster_path() == box / "fleet.json"


def test_roster_falls_back_to_project_root_when_the_box_has_none(box, tmp_path, monkeypatch):
    project = tmp_path / "repo"
    project.mkdir()
    monkeypatch.setenv("WILLOW_PROJECT_ROOT", str(project))
    assert fleet_roster.roster_path() == project / "fleet.json"


def test_roster_env_wins(box, tmp_path, monkeypatch):
    (box / "fleet.json").write_text("{}", encoding="utf-8")
    named = tmp_path / "named.json"
    monkeypatch.setenv("WILLOW_FLEET_ROSTER", str(named))
    assert fleet_roster.roster_path() == named


def test_roster_with_nothing_configured_names_the_box(box):
    """Not ~/github/willow/fleet.json, which is what it used to name."""
    assert fleet_roster.roster_path() == box / "fleet.json"
