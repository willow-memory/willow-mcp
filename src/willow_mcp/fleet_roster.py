"""Canonical charter fleet roster reconciliation without silent deletion."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

# Schema guard (Loki R1, audit of 456849a..2ef4419). The roster is read on the
# own-euid shape (governance=False: broker-writable, unsigned), so it must never
# carry anything that confers trust or capability. The allowlist is exactly what
# the consumers read: status()/sync() use data["agents"], and per row only
# "role" and "trust" (the agents-table columns; "trust" is a display label, not
# an authority). Everything else is dropped; keys that look like authority are
# refused outright. If the roster ever needs such a field, flip the read below to
# governance=True (trust-owner-owned + signed) instead of widening this list.
_TOP_KEYS = frozenset({"agents"})
_ROW_KEYS = frozenset({"role", "trust"})
_FORBIDDEN_KEY = re.compile(
    r"capabilit|permission|grant|manifest|trust|fingerprint|fpr|syscall|envelope"
    r"|privilege|authori|allow|scope|signature|\bsudo\b|\badmin\b",
    re.IGNORECASE,
)


def _forbidden_keys(node: object, path: str = "") -> list[str]:
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}/{key}"
            if _FORBIDDEN_KEY.search(str(key)):
                found.append(here)
            found.extend(_forbidden_keys(value, here))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            found.extend(_forbidden_keys(value, f"{path}[{i}]"))
    return found


def _guard_schema(data: dict) -> dict:
    """Refuse authority-bearing keys; strip every other key outside the allowlist."""
    agents = data.get("agents")
    # The one allowed trust-ish key per row ("trust" under agents/<name>) is
    # removed from the scan; anything else matching the pattern is a refusal.
    scan = {k: v for k, v in data.items() if k != "agents"}
    if isinstance(agents, dict):
        scan["agents"] = {
            name: ({k: v for k, v in row.items() if k not in _ROW_KEYS} if isinstance(row, dict) else row)
            for name, row in agents.items()
        }
    bad = _forbidden_keys(scan)
    if bad:
        raise ValueError(
            "fleet.json carries authority-bearing field(s) the roster may not hold: "
            + ", ".join(sorted(bad))
        )
    clean = {k: v for k, v in data.items() if k in _TOP_KEYS}
    if isinstance(agents, dict):
        clean["agents"] = {
            name: ({k: v for k, v in row.items() if k in _ROW_KEYS} if isinstance(row, dict) else row)
            for name, row in agents.items()
        }
    return clean


def roster_path() -> Path:
    from .paths import fleet_roster_path

    return fleet_roster_path()


def load_roster() -> dict:
    # Authenticate the roster's trust root before reconciling from it (§4.6).
    from .paths import trusted_read

    # Not a governance input in the D4 sense: the roster lives at
    # $WILLOW_HOME/fleet.json, broker-owned. Kept on the own-euid shape; if the
    # roster ever needs a trust/capability field, flip this to governance=True.
    trusted_read(roster_path(), governance=False)
    data = json.loads(roster_path().read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("fleet.json must be an object")
    data = _guard_schema(data)
    agents = data.get("agents")
    if not isinstance(agents, dict):
        raise ValueError("fleet.json agents must be an object")
    for name, row in agents.items():
        if (
            not isinstance(name, str)
            or not isinstance(row, dict)
            or not isinstance(row.get("trust"), str)
            or not isinstance(row.get("role"), str)
        ):
            raise ValueError(f"malformed fleet roster row: {name!r}")
    return data


def _id(name: str) -> str:
    return hashlib.sha256(f"willow-fleet:{name}".encode()).hexdigest()[:8].upper()


def _roster_digest() -> str:
    """SHA-256 of the on-disk roster bytes — the source pin for §4.7's recheck."""
    return hashlib.sha256(roster_path().read_bytes()).hexdigest()


def db_rows(pg) -> list[dict]:
    cur = pg.cursor()
    cur.execute(
        "SELECT id, name, role, trust, folder_root, created_at, valid_at, "
        "invalid_at, updated_at FROM agents ORDER BY name"
    )
    rows = [
        dict(
            zip(
                (
                    "id", "name", "role", "trust", "folder_root", "created_at",
                    "valid_at", "invalid_at", "updated_at",
                ),
                row,
            )
        )
        for row in cur.fetchall()
    ]
    cur.close()
    return rows


def status(pg) -> dict:
    canonical = load_roster()["agents"]
    existing = {row["name"]: row for row in db_rows(pg)}
    missing = sorted(
        name
        for name in canonical
        if name not in existing or existing[name]["invalid_at"] is not None
    )
    contested = sorted(
        name
        for name, row in existing.items()
        if name not in canonical and row["invalid_at"] is None
    )
    archived = sorted(
        name
        for name, row in existing.items()
        if name not in canonical and row["invalid_at"] is not None
    )
    mismatched = []
    agents = []
    for name, expected in sorted(canonical.items()):
        current = existing.get(name)
        if current and (
            current["role"] != expected["role"]
            or current["trust"] != expected["trust"]
        ):
            mismatched.append(name)
        agents.append(
            {
                "id": current["id"] if current else _id(name),
                "name": name,
                "role": expected["role"],
                "trust": expected["trust"],
                "since": str(current["created_at"]) if current else None,
                "db_state": (
                    "missing"
                    if not current
                    else "archived"
                    if current["invalid_at"] is not None
                    else "present"
                ),
            }
        )
    return {
        "agents": agents,
        "count": len(agents),
        "source": str(roster_path()),
        "drift": {
            "missing": missing,
            "mismatched": mismatched,
            "contested": contested,
            "archived": archived,
        },
    }


def sync(pg) -> dict:
    # Non-forgeable operator boundary (§4.3) replaces the bare isatty() gate.
    from .human_session import require_operator_terminal

    require_operator_terminal()
    # Source-digest recheck (§4.7): pin the roster we reconciled from and refuse
    # to write if the file changed under us between read and write (TOCTOU).
    source_digest = _roster_digest()
    snapshot = status(pg)
    canonical = load_roster()["agents"]
    existing = {row["name"]: row for row in db_rows(pg)}
    if _roster_digest() != source_digest:
        raise RuntimeError("fleet roster changed during sync; aborted before writing")
    cur = pg.cursor()
    written = []
    for name, expected in canonical.items():
        current = existing.get(name)
        if (
            current
            and current["role"] == expected["role"]
            and current["trust"] == expected["trust"]
            and current["invalid_at"] is None
        ):
            continue
        if current:
            cur.execute(
                "UPDATE agents SET role=%s, trust=%s, invalid_at=NULL, "
                "valid_at=COALESCE(valid_at, now()), updated_at=now() WHERE name=%s",
                (expected["role"], expected["trust"], name),
            )
        else:
            cur.execute(
                "INSERT INTO agents "
                "(id, name, role, trust, created_at, valid_at, updated_at) "
                "VALUES (%s, %s, %s, %s, now(), now(), now())",
                (_id(name), name, expected["role"], expected["trust"]),
            )
        written.append(name)
    cur.close()
    pg.commit()
    return {
        "written": sorted(written),
        "contested_preserved": snapshot["drift"]["contested"],
        "deleted": [],
        "status": status(pg),
    }
