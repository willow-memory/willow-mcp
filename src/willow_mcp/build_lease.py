"""Time-boxed build leases — the earn-first key.

Companion to `lease.py`. Same shape, different subject. Where `lease.py`
authorizes a *runtime* action (open-web egress by an app_id, for a bounded
window), this authorizes a *build* action (ship an earn-first tool by name,
for a bounded window).

The rule this enforces (2026-08-26 seat decision, sealed elsewhere): a tool
tagged EARN-FIRST leaves that tier only when a human asks for it AND agrees
to what gate the ask opens, recorded as a lease with a 3h ceiling. When the
lease expires the tool falls back to earn-first — further work needs a fresh
ask under the same terms.

**Same failure-mode discipline as `lease.py`:** anything that is not a
well-formed, unexpired, positively-matching lease is *no lease* — absent,
unparseable, over-ceiling, or naming a different tool than the file it sits
in. The record's `tool` claim is what counts; the filename is where we
looked.

**Same mint-boundary as `lease.py`:** issued only by the local
`willow-mcp grant-build` CLI, never by an MCP tool — request and confirm are
separate authorities. Lives beside `_net_leases/` under `mcp_apps/`, so it
inherits B-14's `bound_ro` sandbox mount: a Kart task cannot mint one even
if it can write elsewhere in `$WILLOW_HOME`.

This module does not itself enforce the seal against a build attempt — that
belongs to whatever ships the tool. What lives here is the artifact, its
lifecycle, and the fail-closed reader that whatever ships an earn-first tool
consults to decide whether the ask is live.
"""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("willow_mcp.build_lease")

#: FRANK `cc553729` — the same 3h ceiling as `lease.py`. A build authorization
#: is scoped to a turn, a session, or at most 3 hours. Enforced on both write
#: (grant refuses) and read (a record claiming more is malformed) — a file
#: edited past the ceiling after issue must not be honored just because it was
#: well-formed once.
MAX_TTL_SECONDS = 3 * 60 * 60

#: A tool name has the same charset as an app_id — no path chars, no shell
#: metacharacters, no leading dot. Kept as its own regex rather than importing
#: `gate._APP_ID_RE` so a future divergence (a tool namespace convention that
#: adds `:` or `.`, say) does not silently widen egress-lease identity too.
_TOOL_NAME_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")

_TTL_RE = re.compile(r"^(\d+)\s*([smh]?)$", re.IGNORECASE)
_TTL_UNITS = {"s": 1, "m": 60, "h": 3600, "": 1}


def _validate_tool_name(tool: str) -> str:
    if not tool or not _TOOL_NAME_RE.match(tool):
        raise ValueError(f"Invalid tool name: {tool!r}")
    return tool


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _leases_root(create: bool = False) -> Path:
    """The build-lease directory. `create` only for the one caller that issues
    leases. Readers must never mkdir here — a read path that mutates the trust
    root has the failure mode backwards."""
    home = Path(os.environ.get("WILLOW_HOME", Path.home() / ".willow"))
    root = Path(os.environ.get("WILLOW_MCP_APPS_ROOT", home / "mcp_apps")) / "_build_leases"
    if create:
        root.mkdir(parents=True, exist_ok=True)
    return root


def lease_path(tool: str, create_root: bool = False) -> Path:
    """Path to this tool's build lease. Raises on a name that would not
    validate as a tool identifier."""
    return _leases_root(create=create_root) / f"{_validate_tool_name(tool)}.json"


def parse_ttl(value: str) -> int:
    """`90s` / `30m` / `2h` / bare seconds -> int seconds. Raises on anything
    else, or on a value over the 3h ceiling."""
    m = _TTL_RE.match(str(value).strip())
    if not m:
        raise ValueError(f"unparseable ttl {value!r} — use e.g. 900s, 30m, 2h")
    seconds = int(m.group(1)) * _TTL_UNITS[m.group(2).lower()]
    if seconds <= 0:
        raise ValueError("ttl must be positive")
    if seconds > MAX_TTL_SECONDS:
        raise ValueError(
            f"ttl {value!r} ({seconds}s) exceeds the {MAX_TTL_SECONDS}s ceiling "
            "— a build lease is scoped to a turn, a session, or at most 3 hours"
        )
    return seconds


def _write_json_atomic(path: Path, record: dict) -> None:
    tmp = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    tmp.write_text(json.dumps(record, indent=2), encoding="utf-8")
    os.replace(tmp, path)


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


def read_lease(tool: str) -> dict:
    """Resolve this tool's build lease. Never raises; never returns a lease it
    is unsure of.

    `status` is one of:
      `none`       no lease file
      `active`     well-formed, matching, unexpired
      `expired`    well-formed and matching, but its deadline has passed
      `malformed`  unreadable, unparseable, or claiming more than MAX_TTL_SECONDS
      `mismatch`   the record names a different tool than the file it lives in
    Only `active` authorizes anything.
    """
    check: dict = {"tool": tool, "status": "none", "path": None,
                   "expires_at": None, "remaining_seconds": None}
    try:
        path = lease_path(tool)
    except (ValueError, OSError) as e:
        logger.warning("build_lease: %s — no lease", e)
        return {**check, "status": "malformed", "error": str(e)}

    check["path"] = str(path)
    try:
        if not path.is_file():
            return check
    except OSError as e:
        logger.error("build_lease: cannot stat %s (%s) — denying build", path, e)
        return {**check, "status": "malformed", "error": f"unreadable: {e}"}

    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.error("build_lease: %s is unparseable (%s) — denying build", path, e)
        return {**check, "status": "malformed", "error": f"unparseable: {str(e)[:120]}"}
    if not isinstance(record, dict):
        logger.error("build_lease: %s top level is not an object — denying build", path)
        return {**check, "status": "malformed", "error": "top level is not an object"}

    # A name is not an identity. Filename says where we looked; record says
    # what it claims. Only the claim counts.
    claimed = record.get("tool")
    if claimed != tool:
        logger.error(
            "build_lease: %s claims tool %r but sits at %r — denying build",
            path, claimed, tool,
        )
        return {**check, "status": "mismatch", "error": f"record claims tool {claimed!r}",
                "issuer": record.get("issuer")}

    ttl = record.get("ttl_seconds")
    if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0 or ttl > MAX_TTL_SECONDS:
        logger.error("build_lease: %s has ttl_seconds=%r (ceiling %d) — denying build",
                     path, ttl, MAX_TTL_SECONDS)
        return {**check, "status": "malformed",
                "error": f"ttl_seconds={ttl!r} outside 1..{MAX_TTL_SECONDS}"}

    deadline = _parse_deadline(record.get("expires_at"))
    if deadline is None:
        logger.error("build_lease: %s has no timezone-aware expires_at — denying build", path)
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


def active(tool: str) -> bool:
    """True only for a lease we positively read as well-formed and unexpired."""
    return read_lease(tool)["status"] == "active"


def grant(tool: str, ttl_seconds: int, issuer: str, reason: str = "") -> dict:
    """Issue a build lease. **Operator-only — never call this from an MCP tool.**

    Overwrites any existing lease: re-granting is how an operator extends, and
    a shorter re-grant must be able to shorten. Raises on a ttl above the 3h
    ceiling, an empty issuer, or a tool name that would not validate.

    `reason` is required in spirit and free in shape — the point is that the
    operator agreed, on the record, to what building this tool opens. An empty
    reason lands (a re-grant to extend an in-flight session shouldn't be
    blocked on rewording), but the CLI prompts for one every time.
    """
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
        raise ValueError(f"ttl_seconds must be a positive int, got {ttl_seconds!r}")
    if ttl_seconds > MAX_TTL_SECONDS:
        raise ValueError(f"ttl_seconds {ttl_seconds} exceeds the {MAX_TTL_SECONDS}s ceiling")
    if not issuer:
        raise ValueError("issuer is required — an unattributed grant is not a grant")
    now = _now()
    record = {
        "tool": _validate_tool_name(tool),
        "granted_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat(),
        "ttl_seconds": ttl_seconds,
        "issuer": issuer,
        "reason": reason,
    }
    _write_json_atomic(lease_path(tool, create_root=True), record)
    logger.warning("build_lease: granted build authority for %r for %ds by %r (%s)",
                   tool, ttl_seconds, issuer, reason or "no reason given")
    return record


def revoke(tool: str) -> bool:
    """Delete this tool's build lease. True if one was there. **Operator-only.**"""
    path = lease_path(tool)
    if not path.is_file():
        return False
    path.unlink()
    logger.warning("build_lease: revoked build lease for %r", tool)
    return True


def list_leases() -> list[dict]:
    """Every build lease on disk, resolved. Expired and malformed rows are
    included — `build-status` and `earn-check` exist to show exactly those."""
    root = _leases_root()
    if not root.is_dir():
        return []
    return [read_lease(path.stem) for path in sorted(root.glob("*.json"))]
