"""AS-8: exposure membrane — standing defaults + per-destination slice resolution.

Config: $WILLOW_HOME/config/exposure.json (exposure_v1).
See docs/design/agent-seed.md §5.
"""

from __future__ import annotations

import json
from typing import Any

from .paths import exposure_config_path, willow_home
from .seed_loader import load_seed_document, seed_path

EXPOSURE_FORMAT = "exposure_v1"

# Preset → dotted field paths (checkbox IDs for future UI picker).
PRESET_FIELDS: dict[str, tuple[str, ...]] = {
    # The narrowest destination — exposes NOTHING. Registered for egress sinks
    # like Sentry telemetry, where the correct answer is "leak nothing at all"
    # (see observability.py). apply_field_paths([]) yields an empty body.
    "telemetry": (),
    "voice_only": ("persona.register", "persona.voice_rules"),
    "work_context": (
        "persona.register",
        "persona.voice_rules",
        "context.active_work",
        "context.session_pattern",
        "context.correction_pattern",
    ),
    "full_seed": (
        "persona.register",
        "persona.voice_rules",
        "persona.character",
        "persona.pillars",
        "persona.cast",
        "context.active_work",
        "context.session_pattern",
        "context.correction_pattern",
        "context.cognitive_style",
        "context.personal_note",
        "seed.instruction",
    ),
}

SLICE_PRESETS = frozenset({"voice_only", "work_context", "full", "full_seed", "custom"})
_FULL_PRESETS = frozenset({"full", "full_seed"})
_OPERATOR_KIND = "operator"


def default_exposure_config() -> dict[str, Any]:
    return {
        "format": EXPOSURE_FORMAT,
        "defaults": {
            "session_enter": "work_context",
            "kb_ingest": "work_context",
            "agent_seed_mirror": "work_context",
            "grove": "voice_only",
            "cloud_llm": "voice_only",
            "sentry": "telemetry",
            "dispatch": "work_context",
            # Sealed ae23d366 clause 3: federation_call's own destination —
            # a VISIBILITY TIER name (see _VISIBILITY_TIERS below), not a
            # seed-field preset. REWORK (Loki 24242675, finding 2): this
            # entry is NOT consulted when an app_id has no per-agent
            # override — resolve_exposure_tier() uses the transport
            # ceiling for that case instead (see its docstring), so an
            # unconfigured fleet seat still sees its own corpus rather
            # than nothing. "public" here is only the fallback for an
            # explicit per-agent override whose VALUE is unrecognized
            # (e.g. a pre-existing exposure.json entry written before this
            # destination existed) — the narrowest tier, so a garbled
            # override can never widen what a caller sees.
            "federation_call": "public",
            "*": "voice_only",
        },
        "agents": {
            "sean": {
                "defaults": {"kb_ingest": "voice_only", "cloud_llm": "voice_only"},
                "deny_presets": ["full_seed", "full"],
            }
        },
    }


# ── Federation exposure tier (sealed ae23d366 clause 3) ─────────────────────
#
# Reuses resolve_preset()'s existing per-agent/per-destination default
# lookup (same exposure.json shape, same reader) for a DIFFERENT axis: not
# "which seed fields does this destination see" but "which visibility tier
# of a federated corpus row does this caller see". The destination key is
# FEDERATION_DESTINATION ("federation_call"); the "preset" values for that
# one destination are visibility tier names instead of seed presets.
#
# REWORK (Loki audit 8AA7CBE7, both HIGH findings): the first build here
# invented a two-bucket audience-match model and got the fail-closed default
# backwards. The seal's own verb is "drops rows ABOVE the caller's exposure
# tier" — a CEILING, a linear order, exactly the shape this module already
# uses for seed-field presets (telemetry < voice_only < work_context <
# full_seed, emptiest-first, emptiest as the fail-closed default). The
# analogous order here is:
#
#     public  <  serve  <  internal        (ascending sensitivity)
#
# A caller at tier T sees every row whose visibility rank is <= rank(T):
# an "internal" caller sees internal + serve + public rows (everything); a
# "serve" caller sees serve + public; a "public" caller sees public only.
#
# REWORK 2 (Loki 24242675, finding 2): "fail closed" is about a REMOTE
# caller never reaching "internal" by accident — it does NOT mean an
# unconfigured caller's default is "public". The first rework of this
# module made that mistake too: with no per-agent override on disk, EVERY
# fleet seat (including a plain stdio desk asking about its own corpus)
# resolved to "public" and saw nothing until an operator hand-wrote a
# per-agent override for it. The seal describes a ceiling per caller, not
# a floor that is the same for everyone. See `resolve_exposure_tier`: when
# no per-agent override exists, the caller's tier IS this process's
# transport ceiling (`transport_ceiling`) — stdio (a trusted local
# process, already inside this box) defaults to "internal"; serve/OAuth
# (possibly answering a remote session) defaults to "serve". Fail-closed
# still holds where it matters: a serve/OAuth process can never resolve
# above "serve" no matter what its app_id's own override says (see the
# min() in `resolve_exposure_tier`).
FEDERATION_DESTINATION = "federation_call"

#: The visibility tiers, ascending by sensitivity — index is the rank used
#: by `visible_to`/`resolve_exposure_tier`. A row's `visibility` field, or a
#: caller's resolved federation_call preset, that is not one of these three
#: is treated at its respective fail-closed end (see the two distinct
#: fallbacks below — a caller falls closed NARROW, a row falls closed WIDE).
_VISIBILITY_TIERS: tuple[str, ...] = ("public", "serve", "internal")
_TIER_RANK: dict[str, int] = {name: i for i, name in enumerate(_VISIBILITY_TIERS)}

#: Fail-closed default for a CALLER whose tier cannot be resolved (no
#: per-agent override on disk, or a value this module does not recognize —
#: e.g. an on-disk exposure.json written before this destination existed,
#: where the "*" wildcard default such as "voice_only" would otherwise
#: resolve here and mean nothing as a visibility tier). The narrowest tier:
#: an unresolvable caller sees the least, never the most.
DEFAULT_VISIBILITY_TIER = "public"

#: Fail-closed default for a ROW whose `visibility` field is absent or
#: unrecognized: the WIDEST (most sensitive) tier, so an unmarked row gets
#: the least benefit of the doubt, not the most — it takes an "internal"
#: caller to see it, same as an explicitly `visibility: "internal"` row.
_UNMARKED_ROW_VISIBILITY = "internal"


def transport_ceiling(serve_mode: bool) -> str:
    """The maximum visibility tier this PROCESS's transport permits,
    regardless of what the caller's own exposure.json says. A stdio process
    (Kart, a local desk/specialist session) speaks for a trusted fleet
    member already running inside this box — its ceiling is "internal", no
    extra restriction from the transport. An HTTP+OAuth serve-mode process
    (`server._serve_mode()`) may be answering a bound-but-remote session —
    grove serve, a claude.ai client — so its ceiling caps at "serve" even
    for a caller configured (or defaulted) to "internal"; the transport is
    the stronger signal for "is this call remote" (Loki 8AA7CBE7, finding
    3), and the effective tier is always the minimum of the two."""
    return "serve" if serve_mode else "internal"


def _configured_tier(app_id: str) -> str | None:
    """The app_id's own EXPLICIT per-agent `federation_call` override, if
    one is recorded in exposure.json — normalized, but not yet validated
    against `_VISIBILITY_TIERS` (the caller decides what an unrecognized
    value means). Returns `None` when no per-agent override exists at all
    — this is deliberately NOT the same as reading the global
    `defaults.federation_call` floor (Loki 24242675, finding 2): see
    `resolve_exposure_tier` for why "unconfigured" and "public" are not
    the same thing."""
    cfg = load_exposure_config()
    agent_key = (app_id or "").strip().lower()
    agents = cfg.get("agents") or {}
    agent_cfg = agents.get(agent_key) if isinstance(agents, dict) else None
    if isinstance(agent_cfg, dict):
        per_agent = agent_cfg.get("defaults") or {}
        if isinstance(per_agent, dict) and FEDERATION_DESTINATION in per_agent:
            return _normalize_preset(str(per_agent[FEDERATION_DESTINATION]))
    return None


def resolve_exposure_tier(app_id: str, *, serve_mode: bool = False) -> str:
    """The caller's exposure tier for federation_call row filtering.

    REWORK (Loki 24242675, finding 2): when `app_id` has no EXPLICIT
    per-agent override on disk, its tier IS this process's transport
    ceiling (`transport_ceiling`) — not `DEFAULT_VISIBILITY_TIER`
    ("public"). An unconfigured stdio desk asking about its own corpus
    must see it; falling back to "public" for every unconfigured caller
    blinded the whole fleet to its own federated rows until an operator
    hand-wrote a per-agent override for each seat, which is not what a
    ceiling-per-caller model means. When `app_id` DOES carry an explicit
    override, that value applies (fail-closed to `DEFAULT_VISIBILITY_TIER`
    if unrecognized), but is still capped at the transport ceiling — an
    "internal" override can never lift a serve/OAuth process above
    "serve" (Loki 8AA7CBE7, finding 3).

    `serve_mode` defaults to False (stdio) for callers — like exposure.py's
    own unit tests — that have no transport of their own to report; a
    caller that does (server.federation_call) must pass its own
    `_serve_mode()`."""
    ceiling = transport_ceiling(serve_mode)
    configured = _configured_tier(app_id)
    if configured is None:
        return ceiling
    app_tier = configured if configured in _VISIBILITY_TIERS else DEFAULT_VISIBILITY_TIER
    return app_tier if _TIER_RANK[app_tier] <= _TIER_RANK[ceiling] else ceiling


def row_tier(row_visibility: str | None) -> str:
    """Normalize a row's `visibility` field to one of `_VISIBILITY_TIERS`,
    falling back to `_UNMARKED_ROW_VISIBILITY` ("internal") when absent or
    unrecognized — the same rule `visible_to` applies, exposed here for a
    caller (mcp_federation_client's withheld-row marker, Loki 24242675
    finding 4) that needs to NAME which tier a withheld row required, not
    just whether it cleared."""
    return row_visibility if row_visibility in _VISIBILITY_TIERS else _UNMARKED_ROW_VISIBILITY


def visible_to(caller_tier: str, row_visibility: str | None) -> bool:
    """True when a row carrying `row_visibility` may be returned to a
    caller at `caller_tier` — a ceiling: the row's rank must be at or below
    the caller's own rank. An unrecognized `caller_tier` falls closed to
    DEFAULT_VISIBILITY_TIER ("public", the narrowest); an absent/
    unrecognized `row_visibility` falls closed to `_UNMARKED_ROW_VISIBILITY`
    ("internal", the widest — least benefit of the doubt for an unmarked
    row, not the most)."""
    tier = caller_tier if caller_tier in _VISIBILITY_TIERS else DEFAULT_VISIBILITY_TIER
    vis = row_tier(row_visibility)
    return _TIER_RANK[vis] <= _TIER_RANK[tier]


def load_exposure_config() -> dict[str, Any]:
    path = exposure_config_path()
    if not path.is_file():
        return default_exposure_config()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default_exposure_config()
    if not isinstance(data, dict):
        return default_exposure_config()
    if data.get("format") != EXPOSURE_FORMAT:
        data = {**default_exposure_config(), **data, "format": EXPOSURE_FORMAT}
    return data


def _normalize_preset(name: str) -> str:
    key = (name or "").strip().lower()
    if key == "full":
        return "full_seed"
    return key


def _get_nested(data: dict[str, Any], path: str) -> Any:
    cur: Any = data
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _set_nested(body: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    cur = body
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = value


def apply_field_paths(data: dict[str, Any], paths: list[str]) -> dict[str, Any]:
    body: dict[str, Any] = {}
    for path in paths:
        val = _get_nested(data, path)
        if val is not None and val != "" and val != [] and val != {}:
            _set_nested(body, path, val)
    return body


def apply_slice(data: dict[str, Any], slice_name: str) -> dict[str, Any]:
    """Apply a named exposure preset to seed JSON (backward-compatible with AS-5/6)."""
    preset = _normalize_preset(slice_name)
    if preset in _FULL_PRESETS:
        return dict(data)
    fields = PRESET_FIELDS.get(preset)
    if fields is None:
        raise ValueError(f"unsupported slice: {slice_name!r}")
    return apply_field_paths(data, list(fields))


def resolve_preset(agent_id: str, destination: str) -> tuple[str, str]:
    """Return (preset, source) where source is config path key used."""
    cfg = load_exposure_config()
    dest = (destination or "*").strip() or "*"
    agent_key = (agent_id or "").strip().lower()
    agents = cfg.get("agents") or {}
    agent_cfg = agents.get(agent_key) if isinstance(agents, dict) else None
    if isinstance(agent_cfg, dict):
        per_agent = agent_cfg.get("defaults") or {}
        if isinstance(per_agent, dict) and dest in per_agent:
            return _normalize_preset(str(per_agent[dest])), f"agents.{agent_key}.defaults.{dest}"
    defaults = cfg.get("defaults") or {}
    if isinstance(defaults, dict) and dest in defaults:
        return _normalize_preset(str(defaults[dest])), f"defaults.{dest}"
    if isinstance(defaults, dict) and "*" in defaults:
        return _normalize_preset(str(defaults["*"])), "defaults.*"
    return "voice_only", "builtin"


def preset_denied(agent_id: str, preset: str) -> str | None:
    cfg = load_exposure_config()
    agent_key = (agent_id or "").strip().lower()
    agents = cfg.get("agents") or {}
    agent_cfg = agents.get(agent_key) if isinstance(agents, dict) else None
    norm = _normalize_preset(preset)
    if isinstance(agent_cfg, dict):
        denied = { _normalize_preset(str(x)) for x in (agent_cfg.get("deny_presets") or []) }
        if norm in denied:
            return f"preset {norm!r} denied for agent {agent_key}"
    data, _ = load_seed_document(agent_id)
    if data and norm in _FULL_PRESETS:
        kind = str((data.get("identity") or {}).get("kind") or "").lower()
        if kind == _OPERATOR_KIND:
            return "full_seed denied for operator kind"
    return None


def build_exposure_slice(
    agent_id: str,
    *,
    destination: str = "session_enter",
    preset: str = "",
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Resolve and apply exposure slice for outbound/session use."""
    key = (agent_id or "").strip()
    if seed_path(key) is None:
        return {"ok": False, "error": "invalid_agent_id", "agent_id": key}

    data, err = load_seed_document(key)
    if err or data is None:
        return {"ok": False, "error": err or "unreadable", "agent_id": key}

    if fields:
        chosen_preset = "custom"
        source = "fields_argument"
        field_list = [str(f).strip() for f in fields if str(f).strip()]
        body = apply_field_paths(data, field_list)
    else:
        chosen_preset, source = resolve_preset(key, destination) if not preset else (_normalize_preset(preset), "preset_argument")
        deny = preset_denied(key, chosen_preset)
        if deny:
            return {"ok": False, "error": "preset_denied", "reason": deny, "agent_id": key, "preset": chosen_preset}
        if chosen_preset == "custom":
            return {"ok": False, "error": "custom_requires_fields", "agent_id": key}
        if chosen_preset in _FULL_PRESETS:
            body = dict(data)
            field_list = list(PRESET_FIELDS["full_seed"])
        else:
            field_list = list(PRESET_FIELDS.get(chosen_preset, PRESET_FIELDS["voice_only"]))
            body = apply_field_paths(data, field_list)

    rel_cfg = str(exposure_config_path().relative_to(willow_home())) if exposure_config_path().is_file() else None
    return {
        "ok": True,
        "agent_id": key,
        "destination": destination,
        "preset": chosen_preset,
        "resolved_from": source,
        "config_path": rel_cfg,
        "fields": field_list,
        "body": body,
    }
