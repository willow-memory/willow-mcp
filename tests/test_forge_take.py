"""forge-play is a fleet dependency now: the three modules that used to be
vendored FROM here are imported from the Forge, and this file is what would
notice if the Forge dropped or reshaped the surface willow-mcp holds.

The instrument that replaces a tight version cap (docs/design/fleet-versioning.md,
Rule 1), in the shape of `test_the_installed_jeles_still_has_the_surface_we_use`:
runs against whatever forge-play is really installed, pins exactly the names
server.py / friction.py call and no more, and proves the seam modules are
re-exports (the same objects), not copies that could drift again.
"""
from __future__ import annotations

import inspect

import pytest

forge_human_loop = pytest.importorskip("forge.human_loop", reason="forge-play is a declared runtime dependency")
forge_friction_floor = pytest.importorskip("forge.friction_floor")
forge_model_egress = pytest.importorskip("forge.model_egress")

from willow_mcp import friction_floor, human_loop, model_egress  # noqa: E402


# ── the seam modules re-export, they do not copy ─────────────────────────────

@pytest.mark.parametrize("name", [
    "enqueue", "resolve", "list_queue", "queue_stats",
    "create_attestation", "list_attestations", "has_attestation", "HumanLoopError",
    "QUEUE_OPEN", "QUEUE_KINDS", "PRIORITIES",
])
def test_human_loop_names_are_the_forges(name):
    assert getattr(human_loop, name) is getattr(forge_human_loop, name), (
        f"willow_mcp.human_loop.{name} is a copy, not the Forge's — the seam drifted")


@pytest.mark.parametrize("name", ["FrictionFloor", "Turn", "Flag", "friction_score", "escalation_score", "stance_friction"])
def test_friction_floor_names_are_the_forges(name):
    assert getattr(friction_floor, name) is getattr(forge_friction_floor, name)


@pytest.mark.parametrize("name", ["model_host", "is_local_host", "MODEL_HOST_ENV", "DEFAULT_MODEL_HOST"])
def test_model_egress_detection_half_is_the_forges(name):
    assert getattr(model_egress, name) is getattr(forge_model_egress, name)


def test_denial_stays_here_because_it_reads_this_repos_consent_store():
    """The Forge holds the DETECTION half of model_egress on purpose and gates
    egress on the build's manifest instead; `denial()` reads willow-mcp's
    `consent.cloud_llm` and is not the Forge's to own."""
    assert callable(model_egress.denial)
    assert not hasattr(forge_model_egress, "denial"), (
        "the Forge grew a denial(); decide which consent store wins before re-exporting it")
    assert inspect.signature(model_egress.denial).parameters.get("tool_name") is not None


# ── the calls server.py / friction.py actually make ──────────────────────────

def test_enqueue_still_takes_what_server_passes():
    p = inspect.signature(forge_human_loop.enqueue).parameters
    assert list(p)[0] == "store"
    for name in ("kind", "title", "source_agent"):
        assert name in p and p[name].kind is inspect.Parameter.KEYWORD_ONLY, name


def test_resolve_and_attest_still_take_what_server_passes():
    p = inspect.signature(forge_human_loop.resolve).parameters
    assert list(p)[:2] == ["store", "item_id"] and p["resolved_by"].kind is inspect.Parameter.KEYWORD_ONLY
    q = inspect.signature(forge_human_loop.create_attestation).parameters
    for name in ("subject_id", "attested_by", "by_human"):
        assert name in q and q[name].kind is inspect.Parameter.KEYWORD_ONLY, name


def test_friction_floor_still_scans_turns():
    assert list(inspect.signature(forge_friction_floor.FrictionFloor.scan).parameters) == ["self", "turns"]
    assert {"role", "text"} <= set(inspect.signature(forge_friction_floor.Turn).parameters)
    assert list(inspect.signature(forge_friction_floor.friction_score).parameters) == ["agent_text", "user_context"]


def test_is_local_host_is_still_fail_closed():
    """The property D7 turns on: only all-loopback is local. An unparseable URL
    reads as OFF the machine."""
    assert forge_model_egress.is_local_host("http://localhost:11434") is True
    assert forge_model_egress.is_local_host("http://127.0.0.1:11434") is True
    assert forge_model_egress.is_local_host("not a url") is False
    assert forge_model_egress.is_local_host("http://example.invalid:11434") is False


def test_the_arrow_points_one_way():
    """Willow depends on the Forge. The Forge must never import willow_mcp —
    the reverse is a cycle, and the Forge's own suite asserts it too."""
    import forge
    import pathlib
    root = pathlib.Path(forge.__file__).parent
    offenders = [p.name for p in root.glob("*.py")
                 if any(line.lstrip().startswith(("import willow_mcp", "from willow_mcp"))
                        for line in p.read_text(encoding="utf-8").splitlines())]
    assert not offenders, offenders
