"""Tests for AS-8 exposure membrane (exposure.json + slice resolution)."""

import json

import pytest

from willow_mcp import dispatch as ds
from willow_mcp import exposure as exp
from willow_mcp import home_init as hi
from willow_mcp import paths
from willow_mcp import server


def _write_ratified_seed(home, agent_id: str, **overrides):
    seeds = home / "seeds"
    seeds.mkdir(parents=True, exist_ok=True)
    data = {
        "format": "agent_seed_v1",
        "identity": {"agent_id": agent_id, "kind": "specialist", "display_name": agent_id.title()},
        "seed": {
            "instruction": "One bite.",
            "ratification": {
                "status": "ratified",
                "ratifier_agent_id": "sean",
                "ratified_at": "2026-07-09T00:00:00Z",
            },
        },
        "persona": {
            "register": "formal",
            "voice_rules": ["short"],
            "character": "builder",
            "cast": "secret cast",
        },
        "context": {
            "active_work": "PR stack",
            "session_pattern": "one bite",
            "correction_pattern": "ask first",
            "personal_note": "private",
        },
        "gaps": [],
    }
    data.update(overrides)
    (seeds / f"{agent_id}.json").write_text(json.dumps(data) + "\n")


@pytest.fixture
def reader_app(home):
    app_dir = home / "mcp_apps" / "reader"
    app_dir.mkdir(parents=True)
    (app_dir / "manifest.json").write_text(
        json.dumps({"permissions": ["dispatch_read"]})
    )
    return "reader"


def test_default_exposure_config_shape():
    cfg = exp.default_exposure_config()
    assert cfg["format"] == exp.EXPOSURE_FORMAT
    assert cfg["defaults"]["session_enter"] == "work_context"
    assert cfg["agents"]["sean"]["deny_presets"]


def test_home_init_writes_exposure_json(home):
    hi.ensure_home_layout()
    path = paths.exposure_config_path()
    assert path.is_file()
    data = json.loads(path.read_text())
    assert data["format"] == exp.EXPOSURE_FORMAT


def test_resolve_preset_global_default(home):
    hi.ensure_home_layout()
    preset, source = exp.resolve_preset("hanuman", "grove")
    assert preset == "voice_only"
    assert source == "defaults.grove"


def test_resolve_preset_per_agent_override(home):
    hi.ensure_home_layout()
    preset, source = exp.resolve_preset("sean", "kb_ingest")
    assert preset == "voice_only"
    assert "sean" in source


def test_apply_slice_voice_only_excludes_cast():
    data = {
        "persona": {"register": "calm", "voice_rules": ["a"], "cast": "secret"},
        "context": {"active_work": "hidden"},
    }
    body = exp.apply_slice(data, "voice_only")
    assert body == {"persona": {"register": "calm", "voice_rules": ["a"]}}


def test_apply_slice_full_alias():
    data = {"format": "agent_seed_v1", "persona": {"register": "x"}}
    body = exp.apply_slice(data, "full")
    assert body["format"] == "agent_seed_v1"


def test_build_exposure_slice_session_enter(home, monkeypatch):
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    hi.ensure_home_layout()
    _write_ratified_seed(home, "hanuman")
    out = exp.build_exposure_slice("hanuman", destination="session_enter")
    assert out["ok"] is True
    assert out["preset"] == "work_context"
    assert "active_work" in out["body"].get("context", {})
    assert "cast" not in out["body"].get("persona", {})


def test_build_exposure_slice_custom_fields(home, monkeypatch):
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    _write_ratified_seed(home, "loki")
    out = exp.build_exposure_slice(
        "loki",
        fields=["persona.register", "context.active_work"],
    )
    assert out["ok"] is True
    assert out["preset"] == "custom"
    assert out["body"]["persona"]["register"] == "formal"
    assert out["body"]["context"]["active_work"] == "PR stack"


def test_preset_denied_operator_full_seed(home, monkeypatch):
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    hi.ensure_home_layout()
    _write_ratified_seed(
        home,
        "sean",
        identity={"agent_id": "sean", "kind": "operator"},
    )
    out = exp.build_exposure_slice("sean", preset="full_seed")
    assert out["ok"] is False
    assert out["error"] == "preset_denied"


def test_session_enter_includes_exposure(home, monkeypatch):
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    hi.ensure_home_layout()
    _write_ratified_seed(home, "jeles")
    out = ds.session_enter("jeles", "sess-exp")
    exposure = out.get("agent_seed_exposure")
    assert exposure is not None
    assert exposure["preset"] == "work_context"
    assert "body" in exposure


def test_exposure_config_get_tool(reader_app, home):
    hi.ensure_home_layout()
    out = server.exposure_config_get(reader_app)
    assert out["format"] == exp.EXPOSURE_FORMAT
    assert out["exists"] is True
    assert "defaults" in out["config"]


def test_exposure_slice_tool(reader_app, home, monkeypatch):
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    _write_ratified_seed(home, "ada")
    out = server.exposure_slice(reader_app, "ada", destination="grove")
    assert out["ok"] is True
    assert out["preset"] == "voice_only"


# ── Federation exposure tier (sealed ae23d366 clause 3) ──────────────────────


def test_default_exposure_config_carries_federation_call_destination():
    cfg = exp.default_exposure_config()
    assert cfg["defaults"]["federation_call"] == "public"


def test_resolve_exposure_tier_defaults_to_public_when_unconfigured(home):
    """REWORK (Loki 8AA7CBE7, HIGH): fail-closed means an unconfigured
    caller sees the LEAST by default -- "public" -- not "internal", the
    most sensitive bucket."""
    hi.ensure_home_layout()
    assert exp.resolve_exposure_tier("reader") == "public"


def test_resolve_exposure_tier_honors_a_per_agent_override(home):
    hi.ensure_home_layout()
    cfg = exp.load_exposure_config()
    cfg["agents"]["reader"] = {"defaults": {"federation_call": "serve"}}
    paths.exposure_config_path().write_text(json.dumps(cfg), encoding="utf-8")
    assert exp.resolve_exposure_tier("reader") == "serve"


def test_resolve_exposure_tier_honors_an_internal_override_over_stdio(home):
    hi.ensure_home_layout()
    cfg = exp.load_exposure_config()
    cfg["agents"]["reader"] = {"defaults": {"federation_call": "internal"}}
    paths.exposure_config_path().write_text(json.dumps(cfg), encoding="utf-8")
    assert exp.resolve_exposure_tier("reader", serve_mode=False) == "internal"


def test_resolve_exposure_tier_caps_at_serve_over_the_serve_transport_even_with_an_internal_override(home):
    """Loki 8AA7CBE7, finding 3: the transport is the stronger signal for
    "is this call remote". A caller configured for "internal" still never
    resolves above "serve" when the call arrived over a serve/OAuth
    process — the effective tier is the minimum of the two."""
    hi.ensure_home_layout()
    cfg = exp.load_exposure_config()
    cfg["agents"]["reader"] = {"defaults": {"federation_call": "internal"}}
    paths.exposure_config_path().write_text(json.dumps(cfg), encoding="utf-8")
    assert exp.resolve_exposure_tier("reader", serve_mode=True) == "serve"


def test_resolve_exposure_tier_falls_back_to_public_on_an_unrecognized_value(home):
    """An on-disk exposure.json written before this destination existed
    resolves federation_call through the "*" wildcard ("voice_only", a
    seed preset, not a visibility tier) — that must never widen what a
    caller sees. Falls back to the narrowest tier ("public") instead of
    passing an invalid value through."""
    hi.ensure_home_layout()
    cfg = exp.load_exposure_config()
    del cfg["defaults"]["federation_call"]
    paths.exposure_config_path().write_text(json.dumps(cfg), encoding="utf-8")
    assert exp.resolve_exposure_tier("reader") == "public"


def test_transport_ceiling_stdio_is_internal_serve_mode_is_serve():
    assert exp.transport_ceiling(False) == "internal"
    assert exp.transport_ceiling(True) == "serve"


def test_visible_to_internal_caller_sees_every_tier():
    """Ceiling model (Loki 8AA7CBE7, HIGH): "drops rows above the caller's
    tier" means internal, the widest tier, sees everything."""
    assert exp.visible_to("internal", "internal") is True
    assert exp.visible_to("internal", "serve") is True
    assert exp.visible_to("internal", "public") is True


def test_visible_to_serve_caller_sees_serve_and_public_not_internal():
    assert exp.visible_to("serve", "serve") is True
    assert exp.visible_to("serve", "public") is True
    assert exp.visible_to("serve", "internal") is False


def test_visible_to_public_caller_sees_public_only():
    assert exp.visible_to("public", "public") is True
    assert exp.visible_to("public", "serve") is False
    assert exp.visible_to("public", "internal") is False


def test_visible_to_missing_visibility_is_treated_as_internal():
    """An unmarked row gets the least benefit of the doubt: it takes an
    internal caller to see it, same as an explicit visibility:internal row."""
    assert exp.visible_to("internal", None) is True
    assert exp.visible_to("internal", "") is True
    assert exp.visible_to("serve", None) is False
    assert exp.visible_to("public", None) is False


def test_visible_to_unrecognized_caller_tier_falls_back_to_public():
    assert exp.visible_to("bogus-tier", "public") is True
    assert exp.visible_to("bogus-tier", "serve") is False
    assert exp.visible_to("bogus-tier", "internal") is False
