"""Sandbox-only schema auto-confirmation — the dev-bootstrap seam.

Confirming a schema mapping is normally a human act with rendered-sample
evidence (B-10/B-11; skills/schema-confirm.md): on an ADOPTED database a
name match is an assertion, not evidence. The contributor sandbox is the
one context where that evidence bar is vacuous — the bootstrap applies the
repo's own DDL to a database it just created, so the mapper and the schema
share a single source of truth and the tables are empty. Requiring a human
to confirm that mapping verifies nothing, stalls every cold session at
``unconfirmed_schema``, and in practice teaches agents to flip the artifact
by hand — the exact self-service the gate's spirit forbids.

So the bootstrap confirms automatically, behind three guards that must ALL
hold per (database, table, app):

  1. **No human-authored mapping artifact** for this database fingerprint —
     an operator's confirmed mapping, or one they deliberately marked and
     left unconfirmed, is never touched. The one artifact this guard lets
     through is a *pristine placeholder*: the unconfirmed mapping
     ``schema_profile.resolve()`` scatters as a discovery side effect, with
     no sign a human touched it. Those are safe to re-derive, and treating
     them as sacrosanct is what stranded a warm container — a prior run's
     placeholder made every later run decline forever (see
     ``_is_pristine_placeholder``).
  2. **Every canonical field resolved tier="exact" at confidence 1.0** —
     a single alias or fuzzy match means this is an adopted schema, and
     adopted schemas take the human path.
  3. **The live table's column set exactly equals the repo DDL's column
     set** — a pre-existing table with extra, missing, or renamed columns
     falls through to the human path. (A pre-existing table that is
     column-identical to the repo DDL is byte-equivalent to what the
     bootstrap would have created, so the same argument covers it.)

Every decision — confirmed or declined — is reported with the guard that
decided it, and an auto-confirmed artifact records
``confirmed_by="sandbox-bootstrap"`` so an auditor can tell it from a human
confirmation at a glance.
"""
from __future__ import annotations

import re
from pathlib import Path

# Keywords that start a table-level constraint line inside CREATE TABLE — not
# column definitions.
_CONSTRAINT_KEYWORDS = frozenset(
    {"primary", "unique", "check", "constraint", "foreign", "exclude", "like"}
)

_CREATE_RE_TEMPLATE = r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?{table}\s*\((.*?)\)\s*;"


def _ddl_columns(ddl_path: Path, table: str) -> set[str] | None:
    """Column names of ``table``'s CREATE TABLE in a repo DDL file, or None
    when the file or statement can't be read — None always declines guard 3."""
    try:
        text = ddl_path.read_text(encoding="utf-8")
    except OSError:
        return None
    m = re.search(
        _CREATE_RE_TEMPLATE.format(table=re.escape(table)),
        text,
        re.IGNORECASE | re.DOTALL,
    )
    if not m:
        return None
    cols: set[str] = set()
    depth = 0
    for raw_line in m.group(1).splitlines():
        line = raw_line.split("--", 1)[0].strip()
        if not line:
            continue
        # Only lines at paren depth 0 begin a column/constraint definition;
        # continuation lines inside a CHECK(...) etc. are skipped via depth.
        if depth == 0:
            first = re.match(r'^"?([A-Za-z_][A-Za-z0-9_]*)"?', line)
            if first and first.group(1).lower() not in _CONSTRAINT_KEYWORDS:
                cols.add(first.group(1))
        depth += line.count("(") - line.count(")")
        depth = max(depth, 0)
    return cols or None


def _all_exact(mapping: dict, ddl_cols: set[str] | None = None) -> bool:
    fields = mapping.get("fields") or {}
    if not fields:
        return False
    for name, f in fields.items():
        # Canonical fields the repo DDL does not carry yet (e.g. db_authorization
        # before the reviewed migration lands) resolve as unmapped — that is not
        # evidence of an adopted schema, so bootstrap may ignore them.
        if (
            ddl_cols is not None
            and f.get("tier") == "unmapped"
            and name not in ddl_cols
        ):
            continue
        if f.get("tier") != "exact" or f.get("confidence") != 1.0:
            return False
    return True


# The exact key set schema_profile.resolve() writes for a discovery placeholder
# (plus the schema_drift flag it may add on a confirmed→unconfirmed downgrade).
# An artifact carrying any key beyond these bears a human fingerprint.
_PLACEHOLDER_KEYS = frozenset(
    {"schema_version", "database", "table", "discovered_at", "confirmed",
     "fields", "schema_drift",
     # resolve() has stamped manifest_sha256 on every placeholder since the
     # grant-tracking change; without it here guard 1 read every placeholder
     # as human-authored and declined forever (the exact strand this guard's
     # docstring describes). extend_refused is resolve()'s own note that a
     # sibling did not match — machine-written, not a person's fingerprint.
     "manifest_sha256", "extend_refused"}
)


def _is_pristine_placeholder(artifact: dict) -> bool:
    """True when ``artifact`` is exactly the unconfirmed mapping
    ``schema_profile.resolve()`` persists as a side effect, with no sign a human
    touched it — the one existing artifact guard 1 will re-derive.

    ``resolve()`` writes an UNCONFIRMED placeholder every time it runs against a
    table that has no artifact yet, so a warm container accumulates them; guard 1
    treating one as a human's confirmed choice is what stranded the sandbox
    worker on ``unconfirmed_schema``. A confirmed mapping, a human override tier,
    or any extra key (an operator note, a hand-added field) all mean a person
    acted — those stay protected. Anything unrecognizable fails safe toward
    preservation (returns False)."""
    if not isinstance(artifact, dict) or artifact.get("confirmed"):
        return False
    if set(artifact) - _PLACEHOLDER_KEYS:
        return False
    fields = artifact.get("fields")
    if not isinstance(fields, dict):
        return False
    return all(
        isinstance(f, dict) and f.get("tier") != "confirmed_override"
        for f in fields.values()
    )


def auto_confirm(schema_dir: Path, app_ids: list[str]) -> list[dict]:
    """Apply the three guards and confirm what passes. Returns one decision
    dict per (table, app): {table, app_id, confirmed, reason}."""
    from . import db
    from . import schema_profile as sp
    from .server import _CONFIRMABLE_TABLES

    results: list[dict] = []
    pg = db.get_pg()
    if pg is None:
        return [{"table": "*", "app_id": "*", "confirmed": False,
                 "reason": "postgres unavailable"}]
    fingerprint = sp.db_fingerprint(pg)

    for table, canonical_fields in _CONFIRMABLE_TABLES.items():
        ddl_cols = _ddl_columns(schema_dir / f"{table}.postgres.sql", table)
        live_cols = {c.name for c in sp.introspect(pg, table)}
        for app_id in app_ids:
            decision = {"table": table, "app_id": app_id, "confirmed": False}
            # Guard 1 — never touch an artifact a human confirmed or marked. A
            # pristine placeholder (resolve()'s untouched discovery side effect)
            # is the one exception: safe to re-derive, and locking on it is what
            # stranded a warm container's worker (a prior run's placeholder made
            # every later run decline forever).
            existing = sp.load_mapping(app_id, fingerprint, table)
            if existing is not None and not _is_pristine_placeholder(existing):
                decision["reason"] = "guard 1: human-authored or confirmed mapping exists"
                results.append(decision)
                continue
            if not live_cols:
                decision["reason"] = "table not present"
                results.append(decision)
                continue
            mapping = sp.resolve(pg, app_id, table, list(canonical_fields))
            if "error" in mapping:
                decision["reason"] = f"resolve error: {mapping['error']}"
                results.append(decision)
                continue
            # Guard 2 — one non-exact field means adopted schema, human path.
            if not _all_exact(mapping, ddl_cols):
                decision["reason"] = "guard 2: not every field is exact@1.0"
                results.append(decision)
                continue
            # Guard 3 — live columns must equal the repo DDL's columns.
            if ddl_cols is None or live_cols != ddl_cols:
                decision["reason"] = "guard 3: live table differs from repo DDL"
                results.append(decision)
                continue
            mapping["confirmed"] = True
            mapping["confirmed_by"] = "sandbox-bootstrap"
            sp.save_mapping(app_id, fingerprint, table, mapping)
            decision["confirmed"] = True
            decision["reason"] = "all guards passed (repo-authored schema)"
            results.append(decision)
    return results


def _seeded_app_ids() -> list[str]:
    from . import paths

    root = paths.mcp_apps_root()
    if not root.is_dir():
        return []
    return sorted(
        p.name for p in root.iterdir()
        if p.is_dir() and not p.name.startswith("_")
    )


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent.parent
    schema_dir = repo_root / "docs" / "schema"
    apps = _seeded_app_ids()
    if not apps:
        print("sandbox_confirm: no app manifests found — nothing to confirm")
        return 0
    confirmed = declined = 0
    for d in auto_confirm(schema_dir, apps):
        if d["confirmed"]:
            confirmed += 1
            print(f"sandbox_confirm: CONFIRMED {d['table']} for {d['app_id']} "
                  f"({d['reason']})")
        else:
            declined += 1
            # Guard-1 declines are the steady state on a warm container —
            # only surface the interesting ones.
            if not d["reason"].startswith("guard 1"):
                print(f"sandbox_confirm: declined {d['table']} for "
                      f"{d['app_id']} — {d['reason']}")
    print(f"sandbox_confirm: {confirmed} confirmed, {declined} declined")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
