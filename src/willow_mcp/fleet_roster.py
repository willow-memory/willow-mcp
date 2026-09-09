"""Canonical charter fleet roster reconciliation without silent deletion."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def roster_path() -> Path:
    from .paths import fleet_roster_path

    return fleet_roster_path()


def load_roster() -> dict:
    # Authenticate the roster's trust root before reconciling from it (§4.6).
    from .paths import trusted_read

    trusted_read(roster_path())
    data = json.loads(roster_path().read_text(encoding="utf-8"))
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
