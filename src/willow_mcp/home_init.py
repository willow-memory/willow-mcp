"""Scaffold $WILLOW_HOME for the standalone willow-mcp product.

Idempotent: creates directories, writes default config only when missing,
copies bundled seeds (templates, skills, hooks) without overwriting operator files.

See docs/design/product-layout.md (LOCKED).
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

from .paths import (
    LAYOUT_VERSION,
    agent_roster_path,
    all_layout_dirs,
    bundle_dir,
    envelope_registry_path,
    exposure_config_path,
    layout_version_path,
    persona_envelopes_path,
    personas_dir,
    rotation_path,
    seeds_dir,
    settings_global_path,
    syscall_table_path,
    willow_home,
)
from .exposure import default_exposure_config
from .registry import ManifestSignError, compile_manifests, load_registry

_DEFAULT_ROSTER: dict[str, Any] = {
    "format": "agent_roster_v1",
    "agents": [
        {"id": "willow", "role": "orchestrator", "default_app_id": "willow"},
        {"id": "hanuman", "role": "builder", "default_app_id": "hanuman"},
        {"id": "loki", "role": "auditor", "default_app_id": "loki"},
        {"id": "jeles", "role": "librarian", "default_app_id": "jeles"},
        {"id": "ada", "role": "operator", "default_app_id": "ada"},
    ],
}

_DEFAULT_ENVELOPES: dict[str, Any] = {
    "format": "persona_envelopes_v1",
    "note": "Tool ACL per role — not charter pre-approved.json authority grants.",
    "roles": {
        "orchestrator": {"allow_groups": ["orchestrator", "full_access"]},
        "builder": {"allow_groups": ["dispatch_write", "task_queue", "store_read", "knowledge_read"]},
        "auditor": {"allow_groups": ["dispatch_read", "dispatch_write", "knowledge_read"]},
        # gap_read/gap_write, and not the softer read-only line, because the
        # librarian is the seat that *discovers* what the fleet cannot answer.
        # `jeles` — a declared dependency of this package — forwards every
        # corpus miss into the shared backlog via gap_log, so a librarian
        # without gap_write makes a shipped seam fail closed and silently.
        # gap_promote (landing a gap as trusted knowledge) and gap_purge
        # (clearing a whole fleet-shared topic) stay off this line.
        "librarian": {"allow_groups": [
            "dispatch_read", "dispatch_write", "knowledge_read",
            "gap_read", "gap_write", "grove_read", "grove_write",
        ]},
        "operator": {"allow_groups": ["dispatch_read", "fleet_read", "knowledge_read"]},
    },
}

_DEFAULT_SETTINGS: dict[str, Any] = {
    "consent": {
        "internet": False,
        "cloud_llm": False,
    },
}

_DEFAULT_ROTATION: dict[str, Any] = {
    "format": "rotation_v1",
    "providers": {},
}

_GOVERNANCE_FILE_MODE = 0o600


def _harden_governance_file(path: Path) -> None:
    """trusted_read() refuses group/other-writable governance inputs."""
    os.chmod(path, _GOVERNANCE_FILE_MODE)


def _write_json_if_missing(path: Path, data: dict) -> bool:
    if path.exists():
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    if path.parent.name == "constitutional" or path.name in {
        "pre-approved.json", "syscall-table.json", "review_queue.json",
        "frank_head_anchor.json",
    }:
        _harden_governance_file(path)
    return True


def _copy_bundle_tree(subdir: str, dest: Path) -> list[str]:
    """Copy files from package bundle/{subdir}/ to dest. Returns copied paths."""
    src_root = bundle_dir() / subdir
    if not src_root.is_dir():
        return []
    copied: list[str] = []
    dest.mkdir(parents=True, exist_ok=True)
    for src in src_root.rglob("*"):
        if not src.is_file():
            continue
        rel = src.relative_to(src_root)
        target = dest / rel
        if target.exists():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)
        copied.append(str(target.relative_to(willow_home())))
    return copied


def _copy_bundle_file_if_missing(src: Path, dest: Path) -> bool:
    if not src.is_file() or dest.exists():
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    _harden_governance_file(dest)
    return True


def _materialize_registry() -> dict[str, list[str]]:
    """Copy specialists registry, personas, seed template, and per-agent manifests."""
    from .paths import specialists_config_path

    created: list[str] = []
    bundle_registry = load_registry(prefer_home=False)
    if bundle_registry and _write_json_if_missing(specialists_config_path(), bundle_registry):
        created.append(str(specialists_config_path().relative_to(willow_home())))

    personas_copied = _copy_bundle_tree("personas", personas_dir())
    seeds_copied: list[str] = []
    seed_tpl = bundle_dir() / "seeds" / "agent-seed-template.json"
    seed_dest = seeds_dir() / "agent-seed-template.json"
    if _copy_bundle_file_if_missing(seed_tpl, seed_dest):
        seeds_copied.append(str(seed_dest.relative_to(willow_home())))

    # ensure_home_layout() is documented "safe to call repeatedly" -- a raised
    # ManifestSignError (issue #312) would abort the whole layout pass on a
    # partial state (dirs already made, config already written) rather than
    # leave the install idempotently retriable. Catch it here instead: the
    # underlying rollback in compile_manifests already happened (no manifest
    # is left written-but-unsigned), and `manifests_sign_failed` below makes
    # the failure visible in ensure_home_layout()'s own return value so it is
    # never silent, just non-fatal to onboarding.
    try:
        compile_result = compile_manifests(load_registry(), only_missing=True)
    except ManifestSignError as e:
        compile_result = e.result

    return {
        "registry_config_created": created,
        "personas_copied": personas_copied,
        "seeds_copied": seeds_copied,
        "manifests_created": compile_result.get("written") or [],
        "manifests_sign_failed": compile_result.get("sign_failed") or [],
    }


def ensure_home_layout(home: Path | None = None) -> dict[str, Any]:
    """Create the locked product tree under $WILLOW_HOME. Safe to call repeatedly."""
    if home is not None:
        import os

        os.environ["WILLOW_HOME"] = str(home)

    created_dirs: list[str] = []
    for d in all_layout_dirs():
        if not d.exists():
            d.mkdir(parents=True, exist_ok=True)
            created_dirs.append(str(d.relative_to(willow_home())))

    config_created: list[str] = []
    if _write_json_if_missing(settings_global_path(), _DEFAULT_SETTINGS):
        config_created.append(str(settings_global_path().relative_to(willow_home())))
    if _write_json_if_missing(agent_roster_path(), _DEFAULT_ROSTER):
        config_created.append(str(agent_roster_path().relative_to(willow_home())))
    if _write_json_if_missing(persona_envelopes_path(), _DEFAULT_ENVELOPES):
        config_created.append(str(persona_envelopes_path().relative_to(willow_home())))
    if _write_json_if_missing(rotation_path(), _DEFAULT_ROTATION):
        config_created.append(str(rotation_path().relative_to(willow_home())))
    if _write_json_if_missing(exposure_config_path(), default_exposure_config()):
        config_created.append(str(exposure_config_path().relative_to(willow_home())))

    review_q = willow_home() / "constitutional" / "review_queue.json"
    if _write_json_if_missing(review_q, {"format": "review_queue_v1", "items": []}):
        config_created.append(str(review_q.relative_to(willow_home())))

    # The Article III.2 envelope registry and its companion syscall table.
    # Copied (not inlined like _DEFAULT_ROSTER etc.) because they're real
    # bundled JSON documents, not small Python dict literals. The registry
    # seed is an empty-but-valid starter shape — this is operator-instance
    # data (real grants an operator ratifies), never shipped with real
    # content. The syscall table seed IS real content: it's generic verb
    # mechanism data, not a secret, so there's nothing to start empty.
    constitutional_seeded: list[str] = []
    if _copy_bundle_file_if_missing(bundle_dir() / "constitutional" / "pre-approved.json", envelope_registry_path()):
        constitutional_seeded.append(str(envelope_registry_path().relative_to(willow_home())))
    if _copy_bundle_file_if_missing(bundle_dir() / "constitutional" / "syscall-table.json", syscall_table_path()):
        constitutional_seeded.append(str(syscall_table_path().relative_to(willow_home())))

    registry_result = _materialize_registry()

    egress_result: dict[str, Any] = {"action": "skipped"}
    try:
        from . import egress_setup

        egress_result = egress_setup.ensure_keypair()
    except ValueError as exc:
        egress_result = {"action": "error", "error": str(exc)}

    # orchestrator manifest may also be created by registry pass; dedupe in output
    for path in registry_result.get("registry_config_created") or []:
        if path not in config_created:
            config_created.append(path)

    seeds: dict[str, list[str]] = {
        "templates": _copy_bundle_tree("templates", willow_home() / "templates"),
        "skills": _copy_bundle_tree("skills", willow_home() / "skills"),
        "hooks": _copy_bundle_tree("hooks", willow_home() / "hooks"),
        "constitutional": constitutional_seeded,
    }

    layout_version_path().write_text(f"{LAYOUT_VERSION}\n", encoding="utf-8")

    return {
        "home": str(willow_home()),
        "layout_version": LAYOUT_VERSION,
        "dirs_created": created_dirs,
        "config_created": config_created,
        "seeds_copied": seeds,
        "registry": registry_result,
        "egress": egress_result,
    }


def main() -> None:
    result = ensure_home_layout()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
