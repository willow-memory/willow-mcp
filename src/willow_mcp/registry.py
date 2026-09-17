"""Specialist registry loader and manifest compiler.

Source of truth: bundle/config/specialists.json (shipped) or
$WILLOW_HOME/config/specialists.json (operator overlay after init).

See docs/design/specialist-registry.md and permissions-matrix.md.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from . import pgp
from .paths import bundle_dir, mcp_app_dir, personas_dir, specialists_config_path, willow_home

REGISTRY_FORMAT = "specialist_registry_v1"


class ManifestSignError(RuntimeError):
    """Raised by `compile_manifests` when PGP is enforced and one or more
    written manifests could not be (re-)signed. `result` carries the same
    dict a successful call would have returned (`written`/`skipped`/
    `overridden`/`signed`/`sign_failed`), so a caller that catches this can
    still report exactly what happened rather than only an error string —
    see issue #312 item 2 ("report it")."""

    def __init__(self, message: str, *, result: dict[str, Any]) -> None:
        super().__init__(message)
        self.result = result


def registry_path(prefer_home: bool = True) -> Path:
    """Resolve registry JSON: home overlay when present, else bundle seed."""
    home_path = specialists_config_path()
    if prefer_home and home_path.is_file():
        return home_path
    bundle_path = bundle_dir() / "config" / "specialists.json"
    if bundle_path.is_file():
        return bundle_path
    return home_path


def load_registry(*, path: Path | None = None, prefer_home: bool = True) -> dict[str, Any]:
    src = path or registry_path(prefer_home=prefer_home)
    if not src.is_file():
        return {"format": REGISTRY_FORMAT, "specialists": []}
    data = json.loads(src.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"registry must be a JSON object: {src}")
    return data


def iter_registry_rows(registry: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for row in registry.get("specialists") or []:
        if isinstance(row, dict):
            yield row
    orch = registry.get("orchestrator_seat")
    if isinstance(orch, dict):
        yield orch


def manifest_from_row(
    row: dict[str, Any],
    *,
    collection_aliases: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build an mcp_apps manifest dict from a registry row."""
    agent_id = row.get("agent_id")
    if not agent_id:
        raise ValueError("registry row missing agent_id")

    manifest: dict[str, Any] = {
        "app_id": agent_id,
        "human_only": bool(row.get("human_only", False)),
        "role": row.get("role", ""),
        "permissions": list(row.get("permissions") or []),
        "deny_tools": list(row.get("deny_tools") or []),
    }
    store_scope = row.get("store_scope")
    if store_scope is not None:
        manifest["store_scope"] = list(store_scope)
    aliases = dict(collection_aliases or {})
    aliases.update(row.get("collection_aliases") or {})
    if aliases:
        # Gap 982594e01ab3: registry-level aliases often name projects_willow_*;
        # a specialist with store_scope like jeles_* must not inherit those as
        # reachable logical names. Filter against the row's own scope at compile
        # time so the written manifest matches what gate.collection_aliases
        # will serve.
        from .db import collection_in_scope

        scope = manifest.get("store_scope")
        if scope is not None:
            aliases = {
                logical: physical
                for logical, physical in aliases.items()
                if isinstance(logical, str)
                and isinstance(physical, str)
                and collection_in_scope(physical, scope)
            }
        if aliases:
            manifest["collection_aliases"] = aliases
    return manifest


def _read_manifest_json(path: Path) -> dict[str, Any]:
    """Best-effort read of an existing manifest; {} on absence or corruption."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def compile_manifests(
    registry: dict[str, Any] | None = None,
    *,
    only_missing: bool = False,
    dry_run: bool = False,
) -> dict[str, list[str]]:
    """Write manifests under $WILLOW_HOME/mcp_apps from registry rows.

    Overwriting an existing manifest MERGES rather than clobbers (Loki C303AA2F
    §3.4): registry-owned fields are authoritative, but operator-added local keys
    are preserved. Any registry field that replaces a differing local value is
    reported in ``overridden`` so the override is visible, never silent.

    Signing (issue #312): under PGP enforcement (``pgp.pgp_enabled()``) every
    manifest this writes has its old detached signature invalidated by the
    write, exactly like `manifest_admin.set_permission` — a rewritten manifest
    with no fresh `.sig` is denied everywhere (`gate._load_manifest`), and
    that denial is indistinguishable from "no manifest at all" by design, so
    an un-re-signed compile is a *silent* fleet-wide lockout. Each write is
    followed by `pgp.sign_detached`; a failure rolls that one manifest *and* its
    detached `.sig` back to their previous bytes (or removes both, if this call
    created the file) rather than leaving written-but-unsigned content on disk —
    `gpg --detach-sign --yes -o` can clobber an existing `.sig` even when the
    sign later fails, so restoring content alone is not enough. Rolled-back
    manifests are reported in ``sign_failed`` and dropped from ``written`` (they
    were not durably written); manifests that signed cleanly land in ``signed``.
    Compilation continues across rows so one bad manifest doesn't strand the
    others un-re-signed too, but if anything failed to sign the whole call
    raises `ManifestSignError` (carrying the full result dict) once every row
    has been attempted — fail loud, per PR #294's precedent, never silent.
    """
    reg = registry if registry is not None else load_registry()
    written: list[str] = []
    skipped: list[str] = []
    overridden: list[dict[str, Any]] = []
    signed: list[str] = []
    sign_failed: list[dict[str, str]] = []

    for row in iter_registry_rows(reg):
        agent_id = str(row.get("agent_id", "")).strip()
        if not agent_id:
            continue
        manifest_path = mcp_app_dir(agent_id) / "manifest.json"
        rel = str(manifest_path.relative_to(willow_home()))

        if only_missing and manifest_path.exists():
            skipped.append(rel)
            continue

        manifest = manifest_from_row(
            row,
            collection_aliases=reg.get("collection_aliases") or {},
        )
        existed_before = manifest_path.exists()
        if existed_before:
            existing = _read_manifest_json(manifest_path)
            if existing:
                changed = sorted(
                    key for key, value in manifest.items()
                    if key in existing and existing[key] != value
                )
                if changed:
                    overridden.append({"manifest": rel, "keys": changed})
                merged = dict(existing)   # keep operator-added local-only keys
                merged.update(manifest)   # registry-owned fields win
                manifest = merged
        if dry_run:
            written.append(rel)
            continue

        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        previous_bytes = manifest_path.read_text(encoding="utf-8") if existed_before else None
        previous_sig = pgp.read_detached_sig_bytes(manifest_path) if existed_before else None
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        written.append(rel)

        if pgp.pgp_enabled():
            ok, detail = pgp.sign_detached(manifest_path)
            if ok:
                signed.append(rel)
            else:
                pgp.restore_signed_content(manifest_path, previous_bytes, previous_sig)
                written.remove(rel)
                sign_failed.append({"manifest": rel, "detail": detail})

    result = {
        "written": written,
        "skipped": skipped,
        "overridden": overridden,
        "signed": signed,
        "sign_failed": sign_failed,
    }
    if sign_failed:
        raise ManifestSignError(
            f"{len(sign_failed)} manifest(s) could not be (re-)signed and were "
            f"rolled back to their previous content+signature (never left "
            f"unsigned on disk): "
            f"{[f['manifest'] for f in sign_failed]}. Sign from a host terminal with "
            f"a reachable gpg-agent (`willow-mcp sign-manifest <app_id>`), or unset "
            f"WILLOW_PGP_FINGERPRINT to run without enforcement, then re-run compile.",
            result=result,
        )
    return result


def compile_agents_main(
    *,
    force: bool = False,
    dry_run: bool = False,
    registry_file: Path | None = None,
) -> dict[str, Any]:
    reg = load_registry(path=registry_file) if registry_file else load_registry()
    meta = {
        "registry": str(registry_file or registry_path()),
        "dry_run": dry_run,
        "force": force,
    }
    try:
        result = compile_manifests(reg, only_missing=not force, dry_run=dry_run)
    except ManifestSignError as e:
        # Re-raise with the meta keys folded into `.result` so a caller that
        # catches this (a CLI wrapper) can print one JSON blob instead of
        # having to reassemble it from the bare compile_manifests() result.
        raise ManifestSignError(str(e), result={**meta, **e.result}) from e
    return {**meta, **result}


def compile_cli_main() -> None:
    """Console entry for `willow-mcp-compile` (avoids fleet `willow-mcp` shim)."""
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(
        prog="willow-mcp-compile",
        description="Compile mcp_apps manifests from specialists registry",
    )
    parser.add_argument("--force", action="store_true", help="overwrite existing manifests")
    parser.add_argument("--dry-run", action="store_true", help="report paths only")
    parser.add_argument("--registry", default="", help="path to specialists.json")
    args = parser.parse_args()
    reg = Path(args.registry).expanduser() if args.registry else None
    try:
        result = compile_agents_main(force=args.force, dry_run=args.dry_run, registry_file=reg)
    except ManifestSignError as e:
        print(json.dumps(e.result, indent=2))
        print(f"Error: {e}", file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps(result, indent=2))


# ── Specialist lookup + persona (S-R5 / S-R6) ───────────────────────────────

_PUBLIC_LIST_FIELDS = (
    "agent_id",
    "function",
    "display_name",
    "role",
    "roles",
    "job",
    "not_job",
    "persona_path",
    "entry_mode",
    "receive_dispatch",
    "human_only",
    "sort_order",
)


def specialist_row(agent_id: str, *, registry: dict[str, Any] | None = None) -> dict[str, Any] | None:
    key = (agent_id or "").strip().lower()
    if not key:
        return None
    for row in iter_registry_rows(registry or load_registry()):
        if str(row.get("agent_id", "")).lower() == key:
            return dict(row)
    return None


def _row_for_public(row: dict[str, Any], *, include_permissions: bool = False) -> dict[str, Any]:
    out = {k: row[k] for k in _PUBLIC_LIST_FIELDS if k in row}
    if include_permissions:
        out["permissions"] = list(row.get("permissions") or [])
        out["deny_tools"] = list(row.get("deny_tools") or [])
        scope = row.get("store_scope")
        if scope is not None:
            out["store_scope"] = list(scope)
    return out


def list_specialists(*, include_permissions: bool = False) -> list[dict[str, Any]]:
    rows = list(iter_registry_rows(load_registry()))
    rows.sort(key=lambda r: (int(r.get("sort_order") or 0), str(r.get("agent_id") or "")))
    return [_row_for_public(r, include_permissions=include_permissions) for r in rows]


def get_specialist(agent_id: str, *, include_permissions: bool = True) -> dict[str, Any] | None:
    row = specialist_row(agent_id)
    if not row:
        return None
    out = _row_for_public(row, include_permissions=include_permissions)
    out["namespace"] = row.get("namespace", "")
    out["grove_sender"] = row.get("grove_sender", row.get("agent_id", ""))
    out["model_hint"] = row.get("model_hint", "")
    return out


def resolve_persona_path(agent_id: str) -> Path | None:
    """Resolve persona .md on disk: $WILLOW_HOME/personas/ then bundle."""
    row = specialist_row(agent_id)
    if not row:
        return None
    rel = (row.get("persona_path") or "").strip()
    if not rel:
        return None
    rel_path = Path(rel)
    candidates = [
        personas_dir() / rel_path.name,
        personas_dir() / rel_path,
        bundle_dir() / rel_path,
    ]
    if rel_path.parts and rel_path.parts[0] == "personas":
        candidates.append(personas_dir() / Path(*rel_path.parts[1:]))
    for path in candidates:
        if path.is_file():
            return path
    return None


def read_persona_text(agent_id: str) -> str | None:
    path = resolve_persona_path(agent_id)
    if not path:
        return None
    return path.read_text(encoding="utf-8")


def persona_context(agent_id: str) -> dict[str, Any]:
    """Session-enter payload: registry row + loaded persona voice."""
    row = specialist_row(agent_id)
    if not row:
        return {}
    path = resolve_persona_path(agent_id)
    return {
        "display_name": row.get("display_name", ""),
        "role": row.get("role", ""),
        "function": row.get("function", ""),
        "job": row.get("job", ""),
        "not_job": row.get("not_job", ""),
        "persona_path": row.get("persona_path", ""),
        "persona_file": str(path) if path else None,
        "persona": read_persona_text(agent_id) or "",
    }
