"""Canonical $WILLOW_HOME path API for the willow-mcp standalone product.

All runtime filesystem layout is defined in docs/design/product-layout.md (LOCKED).
Import from here — do not scatter path joins across the codebase.
"""

from __future__ import annotations

import os
import stat
import re
from pathlib import Path

LAYOUT_VERSION = 1


def trusted_read(path: Path) -> None:
    """Fail-closed authentication of a policy/source file before it is trusted.

    Loki B5FB7E2B §4.6: an envelope registry, syscall table, or fleet roster the
    agent (or anyone but the operator) can replace must not be believed. Refuses
    a symlinked path or parent, foreign ownership, or a group/other-writable file
    or parent — the same trust-root shape ``consent_admin`` already enforces on
    the write side, now applied to reads of governance inputs.
    """
    if path.is_symlink() or path.parent.is_symlink():
        raise PermissionError(f"symlinked source path refused: {path}")
    euid = os.geteuid()
    for target in (path.parent, path):
        if not target.exists():
            raise PermissionError(f"source path missing: {target}")
        info = target.stat()
        if info.st_uid != euid or stat.S_IMODE(info.st_mode) & 0o022:
            raise PermissionError(
                f"untrusted ownership or permissions on source path: {target}"
            )

_DISPATCH_ID_RE = re.compile(r"^[A-Z0-9]{8}$")
_APP_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")
_PROJECT_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,128}$")
_PACKAGE_NAME_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


def willow_home() -> Path:
    return Path(os.environ.get("WILLOW_HOME", Path.home() / ".willow"))


def layout_version_path() -> Path:
    return willow_home() / ".layout-version"


# ── severance: the fleet this install claims NOT to be ────────────────────────
#
# Every path above is willow_home()/<subdir>, so "no resolved path lies under
# WILLOW_HOME" is a tautological failure, not an assertion — a correctly severed
# install has all of its paths under its own home. The checkable property is
# that none of them lies under the *fleet's* home, and that the fleet's database
# is not this install's database. willow-mcp has no way to know either unless the
# operator names them.
#
# Both are env-only and neither defaults. In particular fleet_home() must NOT
# fall back to ~/.willow: on a fleet host that is a symlink into the fleet's own
# tree, so an unconfigured install would declare itself severed from the very
# directory it is standing in.
#
# Unset means "no severance claimed" — a single-trust-domain install is complete
# without one, and asserting otherwise would make `degraded` the resting verdict
# for most installs (B-18). Set-but-unreadable fails closed (B-25).

def fleet_home() -> Path | None:
    raw = os.environ.get("WILLOW_MCP_FLEET_HOME", "").strip()
    return Path(raw) if raw else None


def fleet_pg_db() -> str:
    return os.environ.get("WILLOW_MCP_FLEET_PG_DB", "").strip()


def severance_asserted() -> bool:
    return fleet_home() is not None or bool(fleet_pg_db())


# ── config/ ───────────────────────────────────────────────────────────────────

def config_dir() -> Path:
    return willow_home() / "config"


def settings_global_path() -> Path:
    """Canonical settings; legacy root copy may still exist — see consent.py."""
    return config_dir() / "settings.global.json"


def settings_global_legacy_path() -> Path:
    return willow_home() / "settings.global.json"


def consent_path() -> Path:
    return config_dir() / "consent.json"


def consent_legacy_path() -> Path:
    return willow_home() / "consent.json"


def agent_roster_path() -> Path:
    return config_dir() / "agent_roster.json"


def persona_envelopes_path() -> Path:
    return config_dir() / "persona_envelopes.json"


def rotation_path() -> Path:
    return config_dir() / "rotation.json"


def exposure_config_path() -> Path:
    return config_dir() / "exposure.json"


def subject_consent_store() -> Path:
    """Directory the guardian-consent core reads and writes.

    A directory, not a file: it holds the append-only consent chain
    (`consent.jsonl`) and the per-subject disclosure chains
    (`disclosures/<hash>.jsonl`). Kept OUTSIDE config/ — config/ is
    operator-authored policy files; this is a machine-appended, hash-chained
    ledger the operator CLI mutates, never hand-edits.
    """
    return willow_home() / "subject_consent"


# ── dispatch / sessions / handoffs ────────────────────────────────────────────

def dispatch_root() -> Path:
    return willow_home() / "dispatch"


def dispatch_dir(dispatch_id: str) -> Path:
    if not _DISPATCH_ID_RE.match(dispatch_id or ""):
        raise ValueError(f"invalid dispatch_id: {dispatch_id!r}")
    return dispatch_root() / dispatch_id


def sessions_dir() -> Path:
    return willow_home() / "sessions"


def session_path(app_id: str, session_id: str) -> Path:
    if not _APP_ID_RE.match(app_id or ""):
        raise ValueError(f"invalid app_id: {app_id!r}")
    safe_sid = re.sub(r"[^a-zA-Z0-9_\-]", "_", session_id or "")[:64]
    return sessions_dir() / f"{app_id}-{safe_sid}.json"


def attribution_ledger_path() -> Path:
    """PR4 of the identity-in-session plan: append-only hash chain of session
    attestations. One file per willow-mcp instance, at a fixed name under
    sessions_dir() so a caller does not have to know an app_id or session_id
    to check the tip. See src/willow_mcp/attribution_ledger.py."""
    return sessions_dir() / "attribution_ledger.jsonl"


def session_attestation_path(app_id: str, session_id: str) -> Path:
    """Path to the immutable identity attestation for an orchestrator session
    (#313). `session_path()` holds mutable operational state (status,
    dispatch_id, updated_at) that the server rewrites on every session_bind
    call (session_enter, dispatch_accept, session_handoff_write, agent_clear,
    ...) -- a detached signature over that file self-invalidates on the very
    next ordinary write. This sibling file holds only the stable
    {app_id, session_id} identity tuple attest-session actually needs to
    vouch for, and is written once, atomically with its .sig, by attest-session
    -- normal session writes never touch it."""
    if not _APP_ID_RE.match(app_id or ""):
        raise ValueError(f"invalid app_id: {app_id!r}")
    safe_sid = re.sub(r"[^a-zA-Z0-9_\-]", "_", session_id or "")[:64]
    return sessions_dir() / f"{app_id}-{safe_sid}.attest.json"


def handoffs_dir(app_id: str = "") -> Path:
    base = willow_home() / "handoffs"
    if not app_id:
        return base
    if not _APP_ID_RE.match(app_id):
        raise ValueError(f"invalid app_id: {app_id!r}")
    return base / app_id


# ── projects / knowledge ──────────────────────────────────────────────────────

def projects_dir() -> Path:
    return willow_home() / "projects"


def project_path(project_id: str) -> Path:
    if not _PROJECT_ID_RE.match(project_id or ""):
        raise ValueError(f"invalid project_id: {project_id!r}")
    return projects_dir() / f"{project_id}.json"


def knowledge_dir() -> Path:
    return willow_home() / "knowledge"


def knowledge_atom_path(atom_id: str) -> Path:
    safe = re.sub(r"[^a-zA-Z0-9_\-]", "_", atom_id or "")[:128]
    if not safe:
        raise ValueError("invalid atom_id")
    return knowledge_dir() / f"{safe}.json"


# ── templates / skills / hooks / packages ───────────────────────────────────

def templates_dir() -> Path:
    return willow_home() / "templates"


def skills_dir() -> Path:
    return willow_home() / "skills"


def hooks_dir() -> Path:
    return willow_home() / "hooks"


def personas_dir() -> Path:
    return willow_home() / "personas"


def seeds_dir() -> Path:
    return willow_home() / "seeds"


def specialists_config_path() -> Path:
    return config_dir() / "specialists.json"


def packages_dir() -> Path:
    return willow_home() / "packages"


def package_dir(package_name: str) -> Path:
    if not _PACKAGE_NAME_RE.match(package_name or ""):
        raise ValueError(f"invalid package_name: {package_name!r}")
    return packages_dir() / package_name


# ── mcp_apps / store ──────────────────────────────────────────────────────────

def mcp_apps_root() -> Path:
    override = os.environ.get("WILLOW_MCP_APPS_ROOT", "").strip()
    if override:
        return Path(override)
    return willow_home() / "mcp_apps"


def mcp_app_dir(app_id: str) -> Path:
    if not _APP_ID_RE.match(app_id or ""):
        raise ValueError(f"invalid app_id: {app_id!r}")
    return mcp_apps_root() / app_id


def store_root() -> Path:
    override = os.environ.get("WILLOW_STORE_ROOT", "").strip()
    if override:
        return Path(override)
    return willow_home() / "store"


def schema_maps_dir(app_id: str) -> Path:
    """Per-app schema mapping artifacts (B-50, issue #238) -- a top-level
    runtime-writable root, deliberately NOT under mcp_apps/<app_id>/.

    Was originally documented and shipped under mcp_apps/<app_id>/
    schema_maps/ (docs/design/schema-adaptation.md's original §3.2), but that
    conflicts with mcp_apps/ being the trust-root-hardened, operator-owned
    directory #183/#186 depend on: on a uid-separated install, the runtime
    process legitimately writing schema maps can never create a subdirectory
    under an operator-owned, 0755 mcp_apps/<app_id>/ -- the parent directory's
    own permissions block it regardless of what's excluded from any chown
    sweep. Relocated here (a sibling of store_root()/dispatch_root(), same
    "runtime state, not policy" class) so the conflict can't happen at all.
    """
    if not _APP_ID_RE.match(app_id or ""):
        raise ValueError(f"invalid app_id: {app_id!r}")
    return willow_home() / "schema_maps" / app_id


# ── ledgers / resources / constitutional / logs ───────────────────────────────

def ledgers_dir() -> Path:
    return willow_home() / "ledgers"


def ledger_entry_path(entry_hash: str) -> Path:
    safe = re.sub(r"[^a-fA-F0-9]", "", entry_hash or "")[:64]
    if not safe:
        raise ValueError("invalid entry_hash")
    return ledgers_dir() / "entries" / f"{safe}.json"


def resources_dir() -> Path:
    return willow_home() / "resources"


def constitutional_dir() -> Path:
    return willow_home() / "constitutional"


def review_queue_path() -> Path:
    return constitutional_dir() / "review_queue.json"


def frank_head_anchor_path() -> Path:
    """The FRANK governance chain's externally-held head anchor (#280).

    Lives beside the other governance inputs `trusted_read()` already
    authenticates (pre-approved.json, syscall-table.json) — same directory,
    same ownership/permission contract. The whole point of this file is that
    it sits OUTSIDE Postgres: whoever can write `frank_ledger` rows (the
    database operator/credential) need not also be able to write here, so a
    ``rechain()``-laundered relink that is internally consistent in the
    database still disagrees with what this file remembers. See
    `frank_head_anchor.py` and `governance_ledger.py`'s module docstring."""
    return constitutional_dir() / "frank_head_anchor.json"


def envelope_registry_path() -> Path:
    """Default location of the Article III.2 pre-approved envelope registry.

    Previously this lived in a sibling ``willow`` charter repo
    (``~/github/willow/envelopes/pre-approved.json``) — a hard dependency on a
    second repo existing at all. It is operator-instance data (real grants,
    real paths, real dates), not shippable package content, so it belongs
    under $WILLOW_HOME next to `review_queue_path()`, not inside the
    installed package tree. `envelopes.py`'s `registry_path()` still honors
    `WILLOW_ENVELOPE_REGISTRY` first; this is only the default when that is
    unset.
    """
    return constitutional_dir() / "pre-approved.json"


def syscall_table_path() -> Path:
    """Default location of the envelope syscall table — see `envelope_registry_path()`.

    Unlike the registry, this table's *content* is generic mechanism data
    (verb definitions), not operator secrets, so willow-mcp ships a real
    starting copy under bundle/constitutional/ rather than an empty shape.
    """
    return constitutional_dir() / "syscall-table.json"


def logs_dir() -> Path:
    return willow_home() / "logs"


def log_path_for_date(date_str: str) -> Path:
    # YYYY-MM-DD
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", date_str or ""):
        raise ValueError(f"invalid date: {date_str!r}")
    return logs_dir() / f"{date_str}.log"


# ── internal (product runtime; not operator-facing tree docs) ─────────────────

def worker_heartbeat_dir() -> Path:
    return willow_home() / "worker_heartbeat"


def vault_db_path() -> Path:
    return willow_home() / "vault.db"


def mcp_token_path() -> Path:
    return willow_home() / "mcp_token.json"


def identity_bindings_dir() -> Path:
    return mcp_apps_root() / "_identity_bindings"


def net_leases_dir() -> Path:
    return mcp_apps_root() / "_net_leases"


def build_leases_dir() -> Path:
    return mcp_apps_root() / "_build_leases"


def bundle_dir() -> Path:
    """Shipped seeds inside the installed package."""
    return Path(__file__).resolve().parent / "bundle"


def all_layout_dirs() -> list[Path]:
    """Directories created by willow-mcp-init (scaffold only)."""
    home = willow_home()
    return [
        home / "config",
        home / "dispatch",
        home / "handoffs",
        home / "sessions",
        home / "projects",
        home / "knowledge",
        home / "templates",
        home / "skills",
        home / "hooks",
        home / "personas",
        home / "seeds",
        home / "packages",
        home / "mcp_apps",
        home / "store",
        home / "ledgers" / "entries",
        home / "resources",
        home / "constitutional",
        home / "logs",
        home / "worker_heartbeat",
    ]


def new_dispatch_id() -> str:
    import uuid

    return uuid.uuid4().hex[:8].upper()
