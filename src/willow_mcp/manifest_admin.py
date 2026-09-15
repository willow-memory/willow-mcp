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
import hashlib
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import tempfile
from typing import Callable

_REAL_SUBPROCESS_RUN = subprocess.run

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
    try:
        tmp.write_text(json.dumps(record, indent=2), encoding="utf-8")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


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


_ABSENT_DIGEST = "absent"
PrivilegedPublisher = Callable[
    [Path, bytes, bytes, bytes, str, str, str, bool],
    None,
]


def _content_digest(content: bytes | None) -> str:
    return _ABSENT_DIGEST if content is None else hashlib.sha256(content).hexdigest()


def _cli_python_for_trust_owner() -> Path:
    """Absolute CLI interpreter path for the trust-owner sudo helper.

    sudo may discard PATH; the bridge must pass an absolute executable. A venv's
    ``bin/python`` is usually a symlink chain to the system interpreter — resolving
    that chain hands back a base Python that cannot import ``willow_mcp``. The
    venv is identified by the path you invoke, not the binary behind it.
    """
    raw = os.environ.get("WILLOW_MCP_PYTHON", "").strip() or sys.executable
    path = Path(raw)
    if not path.is_absolute():
        path = Path(os.path.abspath(str(path)))
    if not path.is_file():
        raise RuntimeError(
            "permission change refused before mutation: CLI python "
            f"{path} is not a readable file"
        )
    return path


def _mode_allows(uid: int, gid: int, st: os.stat_result, access: int) -> bool:
    mode = stat.S_IMODE(st.st_mode)
    perm = {os.R_OK: 4, os.W_OK: 2, os.X_OK: 1}[access]
    if uid == st.st_uid:
        return bool((mode >> 6) & perm)
    pw = pwd.getpwuid(uid)
    group_ids = set(os.getgrouplist(pw.pw_name, pw.pw_gid))
    if st.st_gid in group_ids:
        return bool((mode >> 3) & perm)
    return bool(mode & perm)


def _uid_can_execute_path(path: Path, uid: int) -> bool:
    """Whether ``uid`` may traverse ``path`` and execute the final component."""
    if not path.is_absolute():
        return False
    pw = pwd.getpwuid(uid)
    parts: list[Path] = []
    cursor = path
    while True:
        parts.append(cursor)
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    parts.reverse()
    for idx, component in enumerate(parts):
        try:
            st = component.lstat()
        except OSError:
            return False
        is_last = idx == len(parts) - 1
        if is_last:
            if not (stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)):
                return False
        elif not stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode):
            return False
        if not _mode_allows(uid, pw.pw_gid, st, os.X_OK):
            return False
    return True


def _require_trust_owner_can_invoke_python(python: Path, owner_uid: int) -> None:
    if not _uid_can_execute_path(python, owner_uid):
        owner = pwd.getpwuid(owner_uid).pw_name
        raise PermissionError(
            "permission change refused before mutation: trust owner "
            f"{owner!r} cannot execute {python}"
        )


def _require_python_imports_willow_mcp(python: Path) -> None:
    probe = _REAL_SUBPROCESS_RUN(
        [str(python), "-c", "import willow_mcp"],
        check=False,
        capture_output=True,
        timeout=60,
    )
    if probe.returncode != 0:
        detail = (probe.stderr or probe.stdout or b"").decode("utf-8", "replace").strip()
        raise RuntimeError(
            "permission change refused before mutation: "
            f"{python} cannot import willow_mcp ({detail or 'nonzero exit'})"
        )


def _replace_bytes(path: Path, content: bytes | None, token: str) -> None:
    """Atomically restore one sibling while the signed-pair lock is held."""
    if content is None:
        path.unlink(missing_ok=True)
        return
    tmp = path.parent / f".{path.name}.restore-{token}"
    try:
        tmp.write_bytes(content)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def publish_signed_pair(
    path: Path,
    manifest_bytes: bytes,
    signature_bytes: bytes,
    fingerprint: str,
    previous_digest: str,
    permission: str,
    granted: bool,
    public_key: bytes | None = None,
) -> None:
    """Verify and publish a manifest/signature generation as one logical pair.

    The two renames happen under the exclusive side of ``signed_pair_lock``;
    gate readers hold the shared side.  Any failure after the first rename
    restores both prior siblings byte-for-byte before releasing the lock.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    token = f"{os.getpid()}-{os.urandom(6).hex()}"
    candidate = path.parent / f".{path.name}.candidate-{token}"
    candidate_sig = pgp.detached_sig_path(candidate)
    live_sig = pgp.detached_sig_path(path)

    with pgp.signed_pair_lock(path, exclusive=True):
        current = path.read_bytes() if path.is_file() else None
        if _content_digest(current) != previous_digest:
            raise RuntimeError(
                "manifest changed while the permission update was being signed; "
                "nothing was published — re-run the command against the current manifest"
            )
        current_manifest = (
            json.loads(current.decode("utf-8"))
            if current is not None
            else {"permissions": []}
        )
        expected_perms = list(current_manifest.get("permissions") or [])
        if granted and permission not in expected_perms:
            expected_perms.append(permission)
        elif not granted and permission in expected_perms:
            expected_perms = [p for p in expected_perms if p != permission]
        current_manifest["permissions"] = expected_perms
        expected_bytes = json.dumps(current_manifest, indent=2).encode("utf-8")
        if manifest_bytes != expected_bytes:
            raise RuntimeError(
                "signed candidate is not the exact requested one-permission change "
                "from the current manifest; nothing was published"
            )
        previous_sig = live_sig.read_bytes() if live_sig.is_file() else None
        published = False
        try:
            candidate.write_bytes(manifest_bytes)
            candidate_sig.write_bytes(signature_bytes)
            os.chmod(candidate, 0o644)
            os.chmod(candidate_sig, 0o644)
            ok, detail = pgp.verify_detached(
                candidate,
                fingerprint=fingerprint,
                public_key=public_key,
            )
            if not ok:
                raise RuntimeError(
                    f"signed manifest candidate failed verification; nothing was "
                    f"published ({detail})"
                )

            # Signature first is fail-closed even for a non-cooperating reader;
            # cooperating gate readers cannot enter between these renames.
            os.replace(candidate_sig, live_sig)
            published = True
            os.replace(candidate, path)
        except Exception:
            if published:
                _replace_bytes(path, current, token)
                _replace_bytes(live_sig, previous_sig, token)
            raise
        finally:
            candidate.unlink(missing_ok=True)
            candidate_sig.unlink(missing_ok=True)


def _signed_candidate(
    manifest: dict,
    fingerprint: str,
    publish: Callable[[bytes, bytes], None],
) -> None:
    """Sign outside the protected trust root, verify, then call ``publish``."""
    manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
    with tempfile.TemporaryDirectory(prefix="willow-manifest-") as raw_dir:
        stage_dir = Path(raw_dir)
        # The trust-owner uid must be able to read the staged public policy and
        # signature after sudo changes identity.  Neither file contains a key.
        os.chmod(stage_dir, 0o755)
        candidate = stage_dir / "manifest.json"
        candidate.write_bytes(manifest_bytes)
        os.chmod(candidate, 0o644)
        ok, detail = pgp.sign_detached(candidate)
        if not ok:
            raise RuntimeError(
                f"permission change refused before mutation: manifest candidate "
                f"could not be signed ({detail})"
            )
        signature = pgp.detached_sig_path(candidate)
        os.chmod(signature, 0o644)
        ok, detail = pgp.verify_detached(candidate, fingerprint=fingerprint)
        if not ok:
            raise RuntimeError(
                f"permission change refused before mutation: signed candidate "
                f"did not verify against WILLOW_PGP_FINGERPRINT ({detail})"
            )
        publish(manifest_bytes, signature.read_bytes())


def publish_via_trust_owner(
    path: Path,
    manifest_bytes: bytes,
    signature_bytes: bytes,
    public_key: bytes,
    fingerprint: str,
    previous_digest: str,
    permission: str,
    granted: bool,
) -> None:
    """Ask sudo to run only the verified publication step as the path owner.

    Signing has already happened as the invoking human, with that human's
    gpg-agent and key context.  The trust-owner process receives no signing
    environment and cannot silently disable enforcement: the expected
    fingerprint and already-signed public files are explicit arguments.
    """
    ownership_anchor = path.parent if path.parent.exists() else path.parent.parent
    owner_info = pwd.getpwuid(ownership_anchor.stat().st_uid)
    if owner_info.pw_uid == os.geteuid():
        raise PermissionError(
            f"cannot publish under {path.parent}: it is owned by the current uid "
            "but is not writable; fix its ACL/mode instead of changing identity"
        )

    with tempfile.TemporaryDirectory(prefix="willow-publish-") as raw_dir:
        stage_dir = Path(raw_dir)
        # Traverse-only for other uids: sudo passes explicit paths; listing denied.
        os.chmod(stage_dir, 0o711)
        staged_manifest = stage_dir / "manifest.json"
        staged_sig = pgp.detached_sig_path(staged_manifest)
        staged_public_key = stage_dir / "operator-public-key.asc"
        staged_manifest.write_bytes(manifest_bytes)
        staged_sig.write_bytes(signature_bytes)
        staged_public_key.write_bytes(public_key)
        os.chmod(staged_manifest, 0o644)
        os.chmod(staged_sig, 0o644)
        os.chmod(staged_public_key, 0o644)

        python = _cli_python_for_trust_owner()
        _require_python_imports_willow_mcp(python)
        _require_trust_owner_can_invoke_python(python, owner_info.pw_uid)

        command = [
            "sudo",
            "-u",
            owner_info.pw_name,
            "--",
            str(python),
            "-m",
            "willow_mcp",
            "_publish-permission",
            "--apps-root",
            str(path.parent.parent),
            "--manifest",
            str(staged_manifest),
            "--signature",
            str(staged_sig),
            "--public-key",
            str(staged_public_key),
            "--fingerprint",
            fingerprint,
            "--previous-digest",
            previous_digest,
            "--permission",
            permission,
            "--action",
            "grant" if granted else "revoke",
            path.parent.name,
        ]
        result = subprocess.run(command, check=False)
        if result.returncode != 0:
            raise PermissionError(
                "trust-owner publication failed; the prior manifest and signature "
                "were preserved. Run from an interactive operator terminal with "
                f"sudo authority for {owner_info.pw_name!r}"
            )


def publish_staged_permission(
    *,
    apps_root: Path,
    app_id: str,
    staged_manifest: Path,
    staged_signature: Path,
    staged_public_key: Path,
    fingerprint: str,
    previous_digest: str,
    permission: str,
    granted: bool,
) -> None:
    """Trust-owner half of a staged signed permission update."""
    app_id = _validate_app_id(app_id)
    apps_root = apps_root.expanduser().resolve()
    ownership_anchor = apps_root / app_id
    if not ownership_anchor.exists():
        ownership_anchor = apps_root
    if ownership_anchor.stat().st_uid != os.geteuid():
        raise PermissionError(
            f"publication uid {os.geteuid()} does not own hardened trust path "
            f"{ownership_anchor}"
        )
    manifest_bytes = staged_manifest.read_bytes()
    signature_bytes = staged_signature.read_bytes()
    public_key = staged_public_key.read_bytes()
    publish_signed_pair(
        apps_root / app_id / "manifest.json",
        manifest_bytes,
        signature_bytes,
        fingerprint,
        previous_digest,
        permission,
        granted,
        public_key,
    )


def set_permission(
    app_id: str,
    perm: str,
    granted: bool,
    *,
    privileged_publisher: PrivilegedPublisher | None = None,
) -> dict:
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
    previous = path.read_bytes() if existed else None
    previous_digest = _content_digest(previous)
    existing_sig = pgp.read_detached_sig_bytes(path) if existed else None

    fingerprint = pgp.expected_fingerprint()
    if existing_sig is not None and not fingerprint:
        raise RuntimeError(
            "permission change refused before mutation: this manifest already has "
            "a detached signature but WILLOW_PGP_FINGERPRINT is unset or malformed. "
            "Restore the operator fingerprint in this shell; disabling enforcement "
            "must never be an accidental side effect of sudo environment loss"
        )

    if fingerprint:
        if existed:
            ok, detail = pgp.verify_detached(path, fingerprint=fingerprint)
            if not ok:
                raise RuntimeError(
                    f"permission change refused before mutation: the current manifest "
                    f"signature is not valid for WILLOW_PGP_FINGERPRINT ({detail})"
                )

        def _publish(manifest_bytes: bytes, signature_bytes: bytes) -> None:
            try:
                publish_signed_pair(
                    path,
                    manifest_bytes,
                    signature_bytes,
                    fingerprint,
                    previous_digest,
                    perm,
                    granted,
                )
            except PermissionError:
                if privileged_publisher is None:
                    raise
                public_key, detail = pgp.export_public_key(fingerprint)
                if public_key is None:
                    raise RuntimeError(
                        "permission change refused before privileged publication: "
                        f"the signer public key could not be exported ({detail})"
                    )
                privileged_publisher(
                    path,
                    manifest_bytes,
                    signature_bytes,
                    public_key,
                    fingerprint,
                    previous_digest,
                    perm,
                    granted,
                )

        _signed_candidate(manifest, fingerprint, _publish)
    else:
        # Unsigned local/dev mode remains supported, but it never gets a sudo
        # bridge: a hardened trust root must not be mutated through a path that
        # only "works" because the fingerprint disappeared from the environment.
        _write_json_atomic(path, manifest)
    return manifest
