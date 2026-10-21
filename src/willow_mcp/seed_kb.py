"""AS-6: promote ratified agent_seed slices to Postgres KB (source_type: agent_seed).

See docs/design/agent-seed.md § KB atom (slice promotion).
Slice defaults resolved via exposure.py (AS-8) when slice is omitted.
"""

from __future__ import annotations

from typing import Any

from psycopg2.extras import Json

from . import onescript_reach
from .exposure import SLICE_PRESETS, apply_slice, preset_denied, resolve_preset
from .seed_loader import SEED_FORMAT, load_agent_seed, load_seed_document, seed_trusted

SOURCE_TYPE = "agent_seed"
KB_DESTINATION = "kb_ingest"
DEFAULT_SLICE = "work_context"
_FORBIDDEN_KINDS_FOR_FULL = frozenset({"operator"})
_KB_PRESETS = frozenset(p for p in SLICE_PRESETS if p != "custom")


def _utc_now() -> str:
    """In the one script's ``seconds_z`` format, from its one clock (flatten-2 F8:
    "Using the onescript at every path."). ``$ONESCRIPT_NOW`` pins it. With no one
    script reachable this raises ``onescript_reach.Unreachable``, with why."""
    return onescript_reach.module("clock").seconds_z()


def _effective_slice(agent_id: str, slice_name: str) -> str:
    if (slice_name or "").strip():
        return slice_name.strip()
    preset, _ = resolve_preset(agent_id, KB_DESTINATION)
    return "full" if preset == "full_seed" else preset


def _forbidden_body_reason(body: dict[str, Any]) -> str | None:
    persona = body.get("persona") or {}
    context = body.get("context") or {}
    if persona.get("cast"):
        return "persona.cast is not eligible for KB promotion"
    if context.get("personal_note"):
        return "context.personal_note is not eligible for KB promotion"
    return None


def build_kb_atom(
    agent_id: str,
    *,
    slice_name: str = "",
    sensitivity: str = "sensitive",
    tier: str = "canonical",
) -> dict[str, Any]:
    """Validate seed and build KB payload (does not write Postgres)."""
    key = (agent_id or "").strip()
    slice_key = _effective_slice(key, slice_name)
    if slice_key not in _KB_PRESETS:
        return {
            "ok": False,
            "error": f"unsupported slice: {slice_key}",
            "allowed": sorted(_KB_PRESETS),
        }

    deny = preset_denied(key, slice_key)
    if deny:
        return {"ok": False, "error": "preset_denied", "reason": deny, "agent_id": key}

    loaded = load_agent_seed(key)
    if not loaded.get("present"):
        return {"ok": False, "error": loaded.get("reason", "no_seed"), "agent_id": key}

    if str(loaded.get("ratification_status") or "").lower() != "ratified":
        return {
            "ok": False,
            "error": "seed_not_ratified",
            "agent_id": key,
            "ratification_status": loaded.get("ratification_status"),
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

    identity = data.get("identity") or {}
    kind = str(identity.get("kind") or "").lower()
    if slice_key in {"full", "full_seed"} and kind in _FORBIDDEN_KINDS_FOR_FULL:
        return {
            "ok": False,
            "error": "full_slice_denied_for_operator",
            "agent_id": key,
            "kind": kind,
        }

    body = apply_slice(data, slice_key)
    forbidden = _forbidden_body_reason(body)
    if forbidden:
        return {"ok": False, "error": "forbidden_body_field", "reason": forbidden, "agent_id": key}

    if slice_key in {"full", "full_seed"}:
        forbidden = _forbidden_body_reason(data)
        if forbidden:
            return {"ok": False, "error": "forbidden_body_field", "reason": forbidden, "agent_id": key}

    rat = (data.get("seed") or {}).get("ratification") or {}
    display = str(identity.get("display_name") or key).strip() or key
    source_id = f"seeds/{key}.json"
    title = f"Agent seed — {display} ({slice_key} slice)"
    summary = f"Ratified {slice_key} excerpt from {source_id}"

    content: dict[str, Any] = {
        "kind": SEED_FORMAT,
        "title": title,
        "summary": summary,
        "tier": tier,
        "sensitivity": sensitivity,
        "agent_id": key,
        "slice": slice_key,
        "source_id": source_id,
        "body": body,
        "ratification": rat,
        "promoted_at": _utc_now(),
    }
    if loaded.get("verify") is not None:
        content["verify"] = loaded["verify"]

    tags = ["agent_seed", key, slice_key, tier]
    if sensitivity:
        tags.append(f"sensitivity:{sensitivity}")

    return {
        "ok": True,
        "agent_id": key,
        "slice": slice_key,
        "source_type": SOURCE_TYPE,
        "source_id": source_id,
        "title": title,
        "summary": summary,
        "domain": "agent_seed",
        "content": content,
        "tags": tags,
    }


def _write_param(field_mapping: dict, value: Any) -> Any:
    if field_mapping.get("data_type") in ("jsonb", "json"):
        return Json(value)
    return value


def _find_existing_atom_id(
    pg: Any,
    fields: dict[str, Any],
    agent_id: str,
    slice_name: str,
) -> str | None:
    id_col = fields["id"]["column"]
    content_col = fields["content"]["column"]
    if not id_col or not content_col:
        return None
    source_col = fields["source"]["column"]
    params: list[Any]
    if source_col:
        sql = (
            f'SELECT "{id_col}" FROM knowledge WHERE "{source_col}" = %s '  # nosec B608 - id_col/content_col/source_col come from the caller's confirmed schema_profile field mapping, not request input; all values are bound params
            f'AND "{content_col}"->>\'agent_id\' = %s AND "{content_col}"->>\'slice\' = %s '
            f"LIMIT 1"
        )
        params = [SOURCE_TYPE, agent_id, slice_name]
    else:
        sql = (
            f'SELECT "{id_col}" FROM knowledge WHERE "{content_col}"->>\'kind\' = %s '  # nosec B608 - id_col/content_col come from the caller's confirmed schema_profile field mapping, not request input; all values are bound params
            f'AND "{content_col}"->>\'agent_id\' = %s AND "{content_col}"->>\'slice\' = %s '
            f"LIMIT 1"
        )
        params = [SEED_FORMAT, agent_id, slice_name]
    cur = pg.cursor()
    cur.execute(sql, params)
    row = cur.fetchone()
    cur.close()
    return str(row[0]) if row else None


def promote_seed_to_kb(
    pg: Any,
    fields: dict[str, Any],
    *,
    agent_id: str,
    slice_name: str = "",
    sensitivity: str = "sensitive",
    tier: str = "canonical",
    supersede: bool = True,
    new_id: str,
) -> dict[str, Any]:
    """Insert or update KB row for a ratified seed slice."""
    built = build_kb_atom(
        agent_id,
        slice_name=slice_name,
        sensitivity=sensitivity,
        tier=tier,
    )
    if not built.get("ok"):
        return built

    slice_key = built["slice"]
    if fields["id"]["column"] is None or fields["content"]["column"] is None:
        return {"ok": False, "error": "schema_unusable: knowledge table missing id or content"}

    existing_id = _find_existing_atom_id(pg, fields, built["agent_id"], slice_key) if supersede else None
    atom_id = existing_id or new_id
    action = "updated" if existing_id else "created"

    values: dict[str, Any] = {"id": atom_id, "content": built["content"]}
    if fields["domain"]["column"]:
        values["domain"] = built["domain"]
    if fields["source"]["column"]:
        values["source"] = built["source_type"]
    if fields["tags"]["column"]:
        values["tags"] = built["tags"]

    if existing_id:
        set_parts = [f'"{fields[f]["column"]}" = %s' for f in values if f != "id"]
        params = [_write_param(fields[f], values[f]) for f in values if f != "id"]
        params.append(atom_id)
        sql = f'UPDATE knowledge SET {", ".join(set_parts)} WHERE "{fields["id"]["column"]}" = %s'  # nosec B608 - set_parts/fields["id"] come from the caller's confirmed schema_profile field mapping, not request input; all values are bound params
        cur = pg.cursor()
        cur.execute(sql, params)
        cur.close()
    else:
        cols = ", ".join(f'"{fields[f]["column"]}"' for f in values)
        placeholders = ", ".join(["%s"] * len(values))
        params = [_write_param(fields[f], v) for f, v in values.items()]
        cur = pg.cursor()
        cur.execute(
            f"INSERT INTO knowledge ({cols}) VALUES ({placeholders})",  # nosec B608 - cols come from the caller's confirmed schema_profile field mapping, not request input; placeholders is a fixed "%s" repeat; all values are bound params
            params,
        )
        cur.close()

    return {
        "ok": True,
        "action": action,
        "id": atom_id,
        "agent_id": built["agent_id"],
        "slice": slice_key,
        "source_type": SOURCE_TYPE,
        "source_id": built["source_id"],
        "title": built["title"],
        "summary": built["summary"],
    }
