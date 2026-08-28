"""willow_mcp/manifest_admin.py — local-CLI-only manifest permission toggles.

Companion to `lease.py`/`identity_binding.py`'s sudo invariant: an app's own
`manifest.json` is the file that grants it tool access, so writing it must
never be reachable from an MCP tool call — an agent could otherwise grant
itself whatever it was just denied. `set_permission()` backs the
`willow-mcp allow-permission` / `deny-permission` CLI subcommands
(stdio-only, operator-run), the same boundary as `grant-net` and
`confirm-binding`. **Do not wire this into an `@mcp.tool()`.**

This does not replace hand-editing `manifest.json` or regenerating it from
`specialists.json` via `willow-mcp compile-agents` — it just gives an
operator a one-line way to flip a single permission group without opening
an editor.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from . import pgp
from .gate import (
    CAPABILITY_PERMISSIONS,
    FEDERATED_PERMISSION_PREFIX,
    PERMISSION_GROUPS,
    _apps_root,
    _validate_app_id,
)

#: Same typo-guard reasoning as `gate.store_scope`'s malformed-field check
#: (B-25): an operator toggling a misspelled permission name would otherwise
#: believe they granted or revoked something, and nothing would happen.
#:
#: Derived from `gate` rather than restated here. The restatement is what broke:
#: this line used to name three of the six capability permissions, so `task_db`,
#: `mcp_federation` and `grove_relay` were enforced by `permitted()` and
#: ungrantable by any operator command. A typo guard that refuses correctly
#: spelled names is not a stricter guard, it is a broken one.
KNOWN_PERMISSIONS = frozenset(PERMISSION_GROUPS) | CAPABILITY_PERMISSIONS


def validate_permission(perm: str) -> str:
    """Return `perm` if an operator may grant it, else raise `ValueError`.

    Two shapes are legal, and they are checked differently on purpose:

    * a name in `KNOWN_PERMISSIONS` — a fixed set, checked by membership;
    * a federated per-tool grant `mcp:<server_id>:<tool>` — checked against the
      ratification registry, because these names *cannot* be enumerated ahead
      of time. A `server_id` is a digest of a server's launch identity
      (`mcp_federation._stable_id`) and does not exist until an operator has
      ratified that server, so there is no moment at which a static list could
      contain it.

    Requiring ratification here is the typo guard for the federated half, and
    it is also the only place the two halves of `federation_egress`'s check can
    be kept from drifting apart: a grant naming an unratified server would sit
    in a manifest looking effective and deny at every call, which is the silent
    shape this module exists to refuse.
    """
    if perm in KNOWN_PERMISSIONS:
        return perm
    if not perm.startswith(FEDERATED_PERMISSION_PREFIX):
        raise ValueError(
            f"unknown permission {perm!r} — expected one of "
            f"{sorted(KNOWN_PERMISSIONS)}, or a federated grant "
            f"'mcp:<server_id>:<tool>'"
        )

    from . import mcp_federation

    parts = perm.split(":")
    if len(parts) != 3 or not parts[1] or not parts[2]:
        raise ValueError(
            f"malformed federated permission {perm!r} — expected exactly "
            f"'mcp:<server_id>:<tool>' with both parts non-empty"
        )
    server_id = parts[1]
    if not mcp_federation.is_ratified(server_id):
        ratified = [
            f"{e.get('name', '?')} ({e.get('server_id', '?')})"
            for e in mcp_federation.list_ratified()
        ]
        raise ValueError(
            f"no ratified server {server_id!r} — a per-tool grant names the "
            f"server it applies to, and that server must be ratified first "
            f"(`willow-mcp federation ratify`). Ratified now: "
            f"{ratified or 'none'}"
        )
    return perm


def manifest_path(app_id: str) -> Path:
    return _apps_root() / _validate_app_id(app_id) / "manifest.json"


def _write_json_atomic(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    tmp.write_text(json.dumps(record, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def read_manifest(app_id: str) -> dict:
    """This app's manifest, or `{"permissions": []}` if none exists yet."""
    path = manifest_path(app_id)
    if not path.is_file():
        return {"permissions": []}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} top level is not an object")
    data.setdefault("permissions", [])
    return data


def set_permission(app_id: str, perm: str, granted: bool) -> dict:
    """Add or remove `perm` from an app's manifest `permissions` list.

    Creates the manifest if this is its first permission. Raises on an
    unknown permission name rather than silently writing (and matching)
    nothing.

    Revoking from an app with no manifest is a deliberate no-op that writes
    nothing: `gate.store_scope` treats "no manifest" as deny-all but a
    manifest with an empty `permissions` list and no `store_scope` field as
    *unrestricted* — materializing an empty manifest here would turn a
    no-op revoke into a store-access grant nobody asked for.
    """
    validate_permission(perm)
    existed = manifest_path(app_id).is_file()
    manifest = read_manifest(app_id)
    perms = list(manifest.get("permissions") or [])
    changed = False
    if granted:
        if perm not in perms:
            perms.append(perm)
            changed = True
    elif perm in perms:
        perms = [p for p in perms if p != perm]
        changed = True

    # Nothing to write, whether or not the file is there. The `not existed` half
    # is the documented one above; the `existed` half matters under PGP
    # enforcement, where falling through would rewrite identical content, discard
    # the valid signature that content already has, and re-sign — turning
    # `allow-permission` from an idempotent command into one that invokes gpg and
    # *raises* on a re-grant that changes nothing.
    if not changed:
        return manifest

    manifest["permissions"] = perms
    path = manifest_path(_validate_app_id(app_id))
    previous = path.read_text(encoding="utf-8") if existed else None
    previous_sig = pgp.read_detached_sig_bytes(path) if existed else None
    _write_json_atomic(path, manifest)

    # Under PGP enforcement the manifest's authority comes from its detached
    # signature, and rewriting the file invalidates it. Writing and walking away
    # would silently revoke the app's entire gate -- the operator's own supported
    # edit path taking the fleet down, with nothing said. Re-sign, or put the
    # content *and* `.sig` back exactly as they were and refuse: a half-applied
    # permission change that leaves an unsigned (or wrong-signed) manifest is
    # strictly worse than no change at all. `gpg --detach-sign --yes -o` can
    # clobber the prior `.sig` even when the sign later fails, so content-only
    # rollback is not enough.
    if pgp.pgp_enabled():
        ok, detail = pgp.sign_detached(path)
        if not ok:
            pgp.restore_signed_content(path, previous, previous_sig)
            raise RuntimeError(
                f"permission change rolled back: manifest for {app_id!r} could not be "
                f"re-signed and an unsigned manifest is denied everywhere ({detail}). "
                f"Sign from a host terminal with a reachable gpg-agent, or unset "
                f"WILLOW_PGP_FINGERPRINT to run without enforcement."
            )
    return manifest
