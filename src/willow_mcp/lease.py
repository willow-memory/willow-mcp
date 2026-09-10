"""Time-boxed egress leases — the third key of the egress gate (B-32).

The sudo invariant (FRANK `90e52ab7`): *a model may REQUEST egress, never
CONFIRM it — request and confirm are separate authorities.* A standing boolean
in a file the requester can write does not separate them. It only looks like it
does.

Before this module, `allow_net=True` needed two keys:

    task_net           manifest capability     "this app may ever ask"
    consent.internet   operator switch         "egress is permitted right now"

Both are booleans, both live in files the host-side agent can write with
ordinary file tools, and neither expires. B-14 made `$WILLOW_HOME/mcp_apps`
`bound_ro` *inside the Kart sandbox* precisely so an untrusted runtime could not
rewrite the ACL that gates it — but the agent driving the session is not inside
that sandbox. It closed the sandbox door and left the host door open.

A lease is the third key, and the one with a clock on it:

    lease              operator grant          "egress, for THIS app, until T"

It is deliberately **not mintable from any MCP tool**, exactly as
`confirm_binding` is not (L-AUTH-02, `identity_binding.py`). It is issued by the
local `willow-mcp grant-net` CLI, run by the operator on the host that owns
`$WILLOW_HOME`, and it dies on its own. Leases live beside `_identity_bindings/`
under `mcp_apps/` so they inherit B-14's `bound_ro` sandbox mount: a sandboxed
task cannot mint one even if it can write the rest of `$WILLOW_HOME`.

**Read fail-closed, in the spirit of `consent.py`.** Anything that is not a
well-formed, unexpired, positively-matching lease is *no lease*:

* absent file                    → no lease
* unparseable file               → no lease (and an ERROR log)
* naive timestamp (no timezone)  → no lease. A deadline without a zone is not a
                                   deadline; it is a wish.
* `expires_at` in the past       → no lease
* `ttl_seconds` above MAX_TTL    → no lease. A lease that outlives the ceiling
                                   was not issued under this policy.
* record's `app_id` != the caller's → no lease. **A name is not an identity:**
                                   the filename is where we looked, not what the
                                   record claims. A `willow.json` whose body says
                                   `"app_id": "other"` grants `willow` nothing.

**What this fixes, and what it does not.** A lease expires, so a self-granted
lease decays instead of persisting forever, and every grant is a dated, attributed
record rather than a silent word in a permissions list. That is a real narrowing.
It is *not* the structural fix. As long as the server's euid can write the lease
directory, an agent running as that euid can still mint one — it must now forge a
*third* artifact, with a clock, under audit, but the OS is not stopping it. The
only thing that stops it is ownership: see `self_writable_trust_paths()` and
`WILLOW_MCP_STRICT_TRUST_ROOT`, which turn "nothing enforces this" into a named,
checkable deployment property. Until the lease root is owned by a uid the agent
does not run as, this module is a mitigation, not a fix. It says so in
`diagnostic_summary` rather than letting the layering imply otherwise.
"""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

# The gate owns the canonical app_id shape; re-deriving it here would let the two
# drift apart, and a lease keyed on an app_id the gate would reject is a lease
# for nobody.
from .gate import _validate_app_id

logger = logging.getLogger("willow_mcp.lease")

#: FRANK `cc553729` scopes an egress lease to a turn, a session, or at most 3
#: hours. The ceiling is enforced on both write (grant refuses) and read (a
#: record claiming more is malformed) — a file edited past the ceiling after it
#: was issued must not be honored just because it was well-formed once.
MAX_TTL_SECONDS = 3 * 60 * 60

_TTL_RE = re.compile(r"^(\d+)\s*([smh]?)$", re.IGNORECASE)
_TTL_UNITS = {"s": 1, "m": 60, "h": 3600, "": 1}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _leases_root(create: bool = False) -> Path:
    """The lease directory. `create` only for the one caller that issues leases.

    Readers must never mkdir here. The hardened deployment this module argues for
    is a lease root the server's uid *cannot* write — and on that host a reader
    that tries to create the directory raises `OSError(EROFS)` instead of simply
    denying. A read path that mutates the trust root, and dies when it cannot, has
    the failure mode exactly backwards.
    """
    home = Path(os.environ.get("WILLOW_HOME", Path.home() / ".willow"))
    root = Path(os.environ.get("WILLOW_MCP_APPS_ROOT", home / "mcp_apps")) / "_net_leases"
    if create:
        root.mkdir(parents=True, exist_ok=True)
    return root


def lease_path(app_id: str, create_root: bool = False) -> Path:
    """Path to this app's lease. Raises on an app_id the gate would reject."""
    return _leases_root(create=create_root) / f"{_validate_app_id(app_id)}.json"


def _nearest_existing(path: Path) -> Optional[Path]:
    """The closest ancestor that exists — the directory whose writability decides
    whether this process could create `path`."""
    for candidate in [path, *path.parents]:
        if candidate.exists():
            return candidate
    return None


def path_is_self_writable_or_replaceable(path: Path) -> bool:
    """Whether this process can alter ``path`` or replace it through an ancestor.

    Checking only the leaf is insufficient: a read-only file in a writable
    directory can be unlinked and replaced, and a protected directory beneath a
    writable parent can be renamed wholesale.  Walk to the filesystem root so
    strict trust mode describes the complete pathname authority.
    """
    try:
        target = path.expanduser().resolve(strict=False)
    except OSError:
        target = path.expanduser().absolute()
    existing = _nearest_existing(target)
    if existing is None:
        return True
    for candidate in (existing, *existing.parents):
        try:
            if os.access(candidate, os.W_OK):
                return True
        except OSError:
            return True
    return False


def path_is_directly_writable_for_trust(path: Path) -> bool:
    """Whether this process can write ``path`` or create/replace it in its parent.

    Unlike ``path_is_self_writable_or_replaceable``, does **not** walk ancestors
    above the immediate parent. A trust root owned by another uid inside a
    writable ``$WILLOW_HOME`` is not forgeable merely because the home directory
  is writable — B-32 hardening is the file's own uid/mode, not rename-the-whole-
    subtree via a distant parent.
    """
    try:
        target = path.expanduser().resolve(strict=False)
    except OSError:
        target = path.expanduser().absolute()
    if target.exists():
        try:
            if os.access(target, os.W_OK):
                return True
        except OSError:
            return True
    parent = target.parent
    if not parent.exists():
        nearest = _nearest_existing(target)
        parent = nearest if nearest is not None else parent
    if parent.exists():
        try:
            if os.access(parent, os.W_OK):
                return True
        except OSError:
            return True
    return False


def parse_ttl(value: str) -> int:
    """`90s` / `30m` / `2h` / bare seconds -> int seconds. Raises on anything else."""
    m = _TTL_RE.match(str(value).strip())
    if not m:
        raise ValueError(f"unparseable ttl {value!r} — use e.g. 900s, 30m, 2h")
    seconds = int(m.group(1)) * _TTL_UNITS[m.group(2).lower()]
    if seconds <= 0:
        raise ValueError("ttl must be positive")
    if seconds > MAX_TTL_SECONDS:
        raise ValueError(
            f"ttl {value!r} ({seconds}s) exceeds the {MAX_TTL_SECONDS}s ceiling "
            "— an egress lease is scoped to a turn, a session, or at most 3 hours"
        )
    return seconds


#: A lease is a public grant, not a secret: the process it authorizes must be
#: able to read it, and it carries nothing (app_id, deadline, issuer, reason)
#: that reading could forge. Owner-write, world-read — the same class the
#: manifests beside it are in after harden-trust-root.
_LEASE_FILE_MODE = 0o644


def _make_lease_readable(path: Path) -> None:
    """Leave the lease world-readable and, when issued as root, owned by the
    trust owner rather than root.

    Measured 2026-09-10 (gap d90246688413): `sudo … willow-mcp grant-net`
    printed success and the seat then read "Permission denied" on the file it
    had just been granted — root's umask produced a root-owned 0600 lease
    inside the 994-owned lease root, so the grant was correct on disk and
    invisible to the process it authorized. The previous night's root-issued
    lease happened to land readable; the mode was never stable. This makes it
    stable. Best-effort: a chown that fails (no such trust owner) is not a
    failed grant, and is logged rather than raised.
    """
    try:
        os.chmod(path, _LEASE_FILE_MODE)
    except OSError as e:
        logger.warning("lease: could not set mode on %s (%s)", path, e)
    if os.geteuid() != 0:
        return
    try:
        import pwd

        from .trust_root_setup import default_trust_owner

        owner = pwd.getpwnam(default_trust_owner())
        os.chown(path, owner.pw_uid, owner.pw_gid)
    except (KeyError, OSError, ImportError) as e:
        logger.warning("lease: issued as root; could not chown %s to the trust owner (%s)", path, e)


def _write_json_atomic(path: Path, record: dict) -> None:
    """Temp file + atomic rename: a crash mid-write must never leave a lease that
    parses as JSON with a truncated `expires_at`."""
    tmp = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    tmp.write_text(json.dumps(record, indent=2), encoding="utf-8")
    os.replace(tmp, path)
    _make_lease_readable(path)


def _parse_deadline(raw: object) -> Optional[datetime]:
    """ISO-8601 with an explicit offset, or None. A naive timestamp is refused:
    without a zone we would have to guess, and guessing extends the lease."""
    if not isinstance(raw, str) or not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt.astimezone(timezone.utc)


def read_lease(app_id: str) -> dict:
    """Resolve this app's lease. Never raises; never returns a lease it is unsure of.

    `status` is one of:
      `none`      no lease file
      `active`    well-formed, matching, unexpired
      `expired`   well-formed and matching, but its deadline has passed
      `unreadable` the file (or its directory) exists and this process is
                  refused by the OS — a mode/owner problem, NOT a bad lease;
                  the fix is chmod/chown, never a re-grant
      `malformed` unparseable, or claiming more than MAX_TTL_SECONDS
      `mismatch`  the record names a different app_id than the file it lives in
    Only `active` authorizes anything.
    """
    check: dict = {"app_id": app_id, "status": "none", "path": None,
                   "expires_at": None, "remaining_seconds": None}
    try:
        path = lease_path(app_id)
    except PermissionError as e:
        logger.error("lease: cannot reach the lease root for %r (%s) — denying egress", app_id, e)
        return {**check, "status": "unreadable", "error": f"permission denied: {e}"}
    except (ValueError, OSError) as e:
        logger.warning("lease: %s — no lease", e)
        return {**check, "status": "malformed", "error": str(e)}

    check["path"] = str(path)
    try:
        if not path.is_file():
            return check
    except PermissionError as e:
        logger.error("lease: cannot stat %s (%s) — denying egress", path, e)
        return {**check, "status": "unreadable", "error": f"permission denied: {e}"}
    except OSError as e:  # unreadable directory, etc. — not a lease
        logger.error("lease: cannot stat %s (%s) — denying egress", path, e)
        return {**check, "status": "malformed", "error": f"unreadable: {e}"}

    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except PermissionError as e:
        # The lease is there and correct for all we know; THIS process may not
        # open it. Reporting that as "malformed" sent the operator to re-issue
        # a lease that was fine (2026-09-10) — name the actual fault.
        logger.error("lease: %s exists but is not readable by uid %s (%s) — denying egress",
                     path, os.geteuid(), e)
        return {**check, "status": "unreadable", "error": f"permission denied: {str(e)[:120]}"}
    except Exception as e:
        logger.error("lease: %s is unparseable (%s) — denying egress", path, e)
        return {**check, "status": "malformed", "error": f"unparseable: {str(e)[:120]}"}
    if not isinstance(record, dict):
        logger.error("lease: %s top level is not an object — denying egress", path)
        return {**check, "status": "malformed", "error": "top level is not an object"}

    # A name is not an identity. The filename says where we looked; the record
    # says what it claims to be. Only the claim counts.
    claimed = record.get("app_id")
    if claimed != app_id:
        logger.error(
            "lease: %s claims app_id %r but sits at %r — denying egress",
            path, claimed, app_id,
        )
        return {**check, "status": "mismatch", "error": f"record claims app_id {claimed!r}",
                "issuer": record.get("issuer")}

    ttl = record.get("ttl_seconds")
    if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0 or ttl > MAX_TTL_SECONDS:
        logger.error("lease: %s has ttl_seconds=%r (ceiling %d) — denying egress",
                     path, ttl, MAX_TTL_SECONDS)
        return {**check, "status": "malformed",
                "error": f"ttl_seconds={ttl!r} outside 1..{MAX_TTL_SECONDS}"}

    deadline = _parse_deadline(record.get("expires_at"))
    if deadline is None:
        logger.error("lease: %s has no timezone-aware expires_at — denying egress", path)
        return {**check, "status": "malformed",
                "error": "expires_at missing, unparseable, or without a timezone"}

    remaining = (deadline - _now()).total_seconds()
    check.update(expires_at=deadline.isoformat(),
                 remaining_seconds=int(remaining),
                 issuer=record.get("issuer"),
                 reason=record.get("reason"),
                 granted_at=record.get("granted_at"))
    check["status"] = "active" if remaining > 0 else "expired"
    return check


def active(app_id: str) -> bool:
    """True only for a lease we positively read as well-formed and unexpired."""
    return read_lease(app_id)["status"] == "active"


def grant(app_id: str, ttl_seconds: int, issuer: str, reason: str = "") -> dict:
    """Issue a lease. **Operator-only — never call this from an MCP tool.**

    Overwrites any existing lease: re-granting is how an operator extends, and a
    shorter re-grant must be able to shorten. Raises on a ttl above the ceiling.
    """
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
        raise ValueError(f"ttl_seconds must be a positive int, got {ttl_seconds!r}")
    if ttl_seconds > MAX_TTL_SECONDS:
        raise ValueError(f"ttl_seconds {ttl_seconds} exceeds the {MAX_TTL_SECONDS}s ceiling")
    if not issuer:
        raise ValueError("issuer is required — an unattributed grant is not a grant")
    now = _now()
    record = {
        "app_id": _validate_app_id(app_id),
        "granted_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat(),
        "ttl_seconds": ttl_seconds,
        "issuer": issuer,
        "reason": reason,
    }
    _write_json_atomic(lease_path(app_id, create_root=True), record)
    logger.warning("lease: granted egress to %r for %ds by %r (%s)",
                   app_id, ttl_seconds, issuer, reason or "no reason given")
    return record


def revoke(app_id: str) -> bool:
    """Delete this app's lease. True if one was there. **Operator-only.**"""
    path = lease_path(app_id)
    if not path.is_file():
        return False
    path.unlink()
    logger.warning("lease: revoked egress lease for %r", app_id)
    return True


def list_leases() -> list[dict]:
    """Every lease on disk, resolved. Expired and malformed ones are included —
    `net-status` exists to show exactly those."""
    root = _leases_root()
    if not root.is_dir():
        return []
    return [read_lease(path.stem) for path in sorted(root.glob("*.json"))]


def self_writable_trust_paths(app_id: str = "") -> list[dict]:
    """Trust-root paths this process could rewrite — i.e. the keys it could forge.

    This is the honest measure of B-32. `os.access(..., W_OK)` answers for the
    *effective* uid, so it answers the only question that matters: could the
    process reading this policy also have written it? A confirm authority inside
    the actor's write reach is not an authority. Running as root makes everything
    writable, which is correctly reported as no separation at all.

    Returns [] when the trust root is genuinely out of reach — the deployment
    B-32 asks for.
    """
    found: list[dict] = []
    lease_root = _leases_root()
    # A lease root that does not exist yet is still forgeable if this process could
    # *create* it — so the question is really about the nearest ancestor that does
    # exist. Reporting "not writable" for an absent directory would be a lie that
    # reads as hardening.
    if path_is_directly_writable_for_trust(lease_root):
        found.append({"key": "lease_root", "path": str(lease_root)})

    if app_id:
        home = Path(os.environ.get("WILLOW_HOME", Path.home() / ".willow"))
        root = Path(os.environ.get("WILLOW_MCP_APPS_ROOT", home / "mcp_apps"))
        manifest = root / app_id / "manifest.json"
        # A manifest that does not exist grants nothing, so it is not a key that
        # could be forged into one — the gate denies an unmanifested app outright.
        if manifest.exists() and path_is_directly_writable_for_trust(manifest):
            found.append({"key": "manifest", "path": str(manifest)})
    return found


def path_is_self_readable(path: Path) -> bool:
    """Whether this process can read ``path`` directly (leaf only, no ancestor
    walk — unlike a write, a read exposure isn't compounded by a writable
    parent: renaming the file doesn't reveal its contents to a process that
    couldn't already read it).

    A distinct question from write-forgery. `self_writable_trust_paths()`
    above answers "could this process have authored the policy" — for most
    trust-root files (manifests, leases) that's the actual threat: an agent
    rewrites its own grant. The egress signing key is different: a process
    that can merely *read* it needs no forgery at all — it can sign with
    the real authority (#182). Reports False for a path that doesn't exist
    yet: nothing to steal is not the same as a stolen key.
    """
    try:
        target = path.expanduser().resolve(strict=False)
    except OSError:
        target = path.expanduser().absolute()
    if not target.is_file():
        return False
    try:
        return os.access(target, os.R_OK)
    except OSError:
        return True  # unverifiable ⇒ cannot claim protection


def egress_key_readable_by_self() -> bool:
    """Whether this process can read the configured egress private signing
    key (#182). Deferred import: lease.py has no module-level dependency on
    egress_setup today, and this keeps it that way."""
    from . import egress_setup
    key_path = egress_setup.resolve_private_key_path()
    if key_path is None:
        return False
    return path_is_self_readable(key_path)


def strict_trust_root() -> bool:
    """Opt-in: refuse egress when this process can write the keys that authorize it.

    Off by default, and that default is a statement about deployments, not about
    policy. On a single-uid host — which is every willow install today — the
    server and the agent share an euid, so strict mode denies egress until the
    operator separates them (`chown` the lease root to a uid the agent does not
    run as). Turning it on before that separation exists would break every
    install; leaving it silent would let the lease *look* like a control it is
    not. So: default off, reported always (see `diagnostic_summary`).

    This is not the B-31 inversion. There, an *unreadable policy* resolved to
    permitted. Here the policy is read perfectly well; what is absent is the OS
    enforcing who may have authored it.
    """
    return os.environ.get("WILLOW_MCP_STRICT_TRUST_ROOT", "").strip().lower() in ("1", "true", "yes")
