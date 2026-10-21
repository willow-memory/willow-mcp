"""AS-5: mirror canonical home seeds into SOIL store collection.

Design collection name: agents/seeds — standalone store uses flat
`willow_agents_seeds` (matches orchestrator store_scope `willow_*`).
Slice presets resolved via exposure.py (AS-8) when slice is omitted.
"""

from __future__ import annotations

from typing import Any

from . import onescript_reach
from .exposure import (
    SLICE_PRESETS,
    apply_slice,
    preset_denied,
    resolve_preset,
)
from .seed_loader import SEED_FORMAT, load_agent_seed, load_seed_document, seed_trusted

# Flat SOIL collection mirroring docs/design/agent-seed.md § agents/seeds
MIRROR_COLLECTION = "willow_agents_seeds"
MIRROR_DESTINATION = "agent_seed_mirror"

_MIRROR_PRESETS = frozenset(p for p in SLICE_PRESETS if p != "custom")


def _utc_now() -> str:
    """In the one script's ``seconds_z`` format, from its one clock (flatten-2 F8:
    "Using the onescript at every path."). ``$ONESCRIPT_NOW`` pins it. With no one
    script reachable this raises ``onescript_reach.Unreachable``, with why."""
    return onescript_reach.module("clock").seconds_z()


def _effective_slice(agent_id: str, slice_name: str) -> str:
    if (slice_name or "").strip():
        return slice_name.strip()
    preset, _ = resolve_preset(agent_id, MIRROR_DESTINATION)
    return "full" if preset == "full_seed" else preset


def build_mirror_record(agent_id: str, *, slice_name: str = "") -> dict[str, Any]:
    """Build mirror payload from home canonical seed (does not write store)."""
    key = (agent_id or "").strip()
    slice_key = _effective_slice(key, slice_name)
    if slice_key not in _MIRROR_PRESETS:
        return {
            "ok": False,
            "error": f"unsupported slice: {slice_key}",
            "allowed": sorted(_MIRROR_PRESETS),
        }

    deny = preset_denied(key, slice_key)
    if deny:
        return {"ok": False, "error": "preset_denied", "reason": deny, "agent_id": key}

    loaded = load_agent_seed(key)
    if not loaded.get("present"):
        return {"ok": False, "error": loaded.get("reason", "no_seed"), "agent_id": key}

    status = str(loaded.get("ratification_status") or "pending")
    if status != "ratified":
        return {
            "ok": False,
            "error": "seed_not_ratified",
            "agent_id": key,
            "ratification_status": status,
            "advisory": loaded.get("advisory"),
        }

    if not seed_trusted(loaded):
        return {
            "ok": False,
            "error": "seed_signature_invalid",
            "agent_id": key,
            "verify": loaded.get("verify"),
        }

    data, err = load_seed_document(key)
    if err or data is None:
        return {"ok": False, "error": err or "unreadable", "agent_id": key}

    rel = f"seeds/{key}.json"
    record: dict[str, Any] = {
        "format": SEED_FORMAT,
        "agent_id": key,
        "_mirror_of": rel,
        "_slice": slice_key,
        "_mirrored_at": _utc_now(),
        "ratification": (data.get("seed") or {}).get("ratification") or {},
        "body": apply_slice(data, slice_key),
    }
    if loaded.get("verify") is not None:
        record["verify"] = loaded["verify"]
    return {"ok": True, "agent_id": key, "collection": MIRROR_COLLECTION, "record": record}


def mirror_seed_to_store(store: Any, agent_id: str, *, slice_name: str = "") -> dict[str, Any]:
    """Write mirror record to SOIL; record_id = {agent_id} or {agent_id}__{slice}."""
    built = build_mirror_record(agent_id, slice_name=slice_name)
    if not built.get("ok"):
        return built

    key = built["agent_id"]
    record = built["record"]
    slice_key = record["_slice"]
    rid = key if slice_key in {"full", "full_seed"} else f"{key}__{slice_key}"
    stored_id, action = store.put(MIRROR_COLLECTION, record, record_id=rid)
    return {
        "ok": True,
        "agent_id": key,
        "collection": MIRROR_COLLECTION,
        "record_id": stored_id,
        "action": action,
        "slice": slice_key,
        "_mirror_of": record["_mirror_of"],
    }
