"""Dispatch packet I/O — meta.json, assignment.md, status.json under $WILLOW_HOME/dispatch/."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .db import encode_cursor, decode_cursor

from .paths import (
    dispatch_dir,
    dispatch_root,
    handoffs_dir,
    new_dispatch_id,
    session_path,
    sessions_dir,
)
from . import dispatch_signing
from .human_session import is_orchestrator_app
from .registry import persona_context
from .seed_loader import seed_context
from .roles import VALID_STATUSES

_AGENT_DOC = "docs/AGENTS.md"
_PROJECT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")

# Dispatch closeout: tool name reflects the MCP call signature generation; on-disk
# handoff.json format stays handoff_v1 (BC504427 — intentional, not a mismatch).
DISPATCH_CLOSEOUT = {"tool": "handoff_write_v4", "format": "handoff_v1"}

logger = logging.getLogger("willow_mcp.dispatch")


def closeout_from_meta(meta: dict) -> dict:
    """Resolve closeout tool + on-disk format from packet meta (new or legacy)."""
    closeout = meta.get("closeout")
    if isinstance(closeout, dict) and closeout.get("tool"):
        return {
            "tool": str(closeout["tool"]),
            "format": str(closeout.get("format") or "handoff_v1"),
        }
    if meta.get("reply_contract") == "handoff_v4":
        return dict(DISPATCH_CLOSEOUT)
    return dict(DISPATCH_CLOSEOUT)


# ── best-effort Postgres mirror (fleet visibility) ─────────────────────────────
# Dispatch packets are filesystem-canonical (a standalone install has no
# Postgres). But the fleet reads the *other* willow-mcp state — store, knowledge,
# tasks, agents — from a shared Postgres; dispatch is the one subsystem it can't
# see. When an operator runs willow-mcp as a fleet host (WILLOW_MCP_DISPATCH_MIRROR
# truthy) *and* a host DB is reachable, mirror each packet's routing/status into a
# `dispatch_tasks` table so the fleet sees dispatches too. This is NEVER load-
# bearing: the filesystem packet is the source of truth, the mirror is opt-in and
# off by default, and every failure here is swallowed — a broken or absent DB must
# not affect a dispatch that already wrote to disk. See docs/schema/
# dispatch_tasks.postgres.sql.

_DISPATCH_TASKS_DDL = """
CREATE TABLE IF NOT EXISTS dispatch_tasks (
    dispatch_id text PRIMARY KEY,
    from_app    text        NOT NULL DEFAULT '',
    to_app      text        NOT NULL DEFAULT '',
    role        text        NOT NULL DEFAULT '',
    phase       text        NOT NULL DEFAULT '',
    priority    text        NOT NULL DEFAULT 'normal',
    reply_to    text        NOT NULL DEFAULT '',
    summary     text        NOT NULL DEFAULT '',
    status      text        NOT NULL DEFAULT 'pending',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
"""


def dispatch_mirror_enabled() -> bool:
    """True when the operator has opted this install into mirroring dispatch
    packets to a shared Postgres (fleet-host duty). Off by default — a standalone
    install stays filesystem-only and never reaches for a DB."""
    return bool(os.environ.get("WILLOW_MCP_DISPATCH_MIRROR", "").strip())


def _pg_mirror_upsert(meta: dict) -> None:
    """Best-effort: mirror a packet's routing + status into `dispatch_tasks`.
    Silent no-op when mirroring is off or no host DB is reachable; never raises —
    the filesystem packet has already been written and is canonical."""
    if not dispatch_mirror_enabled():
        return
    try:
        from . import db
        conn = db.get_pg()
        if conn is None:
            return
        cur = conn.cursor()
        cur.execute(_DISPATCH_TASKS_DDL)
        cur.execute(
            "INSERT INTO dispatch_tasks (dispatch_id, from_app, to_app, role, "
            "phase, priority, reply_to, summary, status, created_at, updated_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, now(), now()) "
            "ON CONFLICT (dispatch_id) DO UPDATE SET "
            "status = EXCLUDED.status, summary = EXCLUDED.summary, updated_at = now()",
            (
                meta.get("dispatch_id", ""), meta.get("from_app", ""),
                meta.get("to_app", ""), meta.get("role", ""), meta.get("phase", ""),
                meta.get("priority", "normal"), meta.get("reply_to", ""),
                meta.get("summary", ""), meta.get("status", "pending"),
            ),
        )
        cur.close()
    except Exception:  # best-effort: a DB fault must never break a written packet
        logger.debug("dispatch: PG mirror upsert skipped", exc_info=True)


def _pg_mirror_status(dispatch_id: str, status: str) -> None:
    """Best-effort: reflect a status transition into `dispatch_tasks`. A row that
    doesn't exist (mirror enabled after the packet was created) is a no-op UPDATE,
    which is acceptable — the next transition or a re-send upserts it."""
    if not dispatch_mirror_enabled():
        return
    try:
        from . import db
        conn = db.get_pg()
        if conn is None:
            return
        cur = conn.cursor()
        cur.execute(_DISPATCH_TASKS_DDL)
        cur.execute(
            "UPDATE dispatch_tasks SET status = %s, updated_at = now() "
            "WHERE dispatch_id = %s",
            (status, (dispatch_id or "").upper()),
        )
        cur.close()
    except Exception:
        logger.debug("dispatch: PG mirror status skipped", exc_info=True)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _read_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def project_context(project: str = "", workspace: str = "") -> dict:
    root_value = (
        workspace
        or os.environ.get("WILLOW_PROJECT_ROOT", "")
    ).strip()
    root = Path(root_value).expanduser().resolve() if root_value else None
    name = (project or os.environ.get("WILLOW_HANDOFF_PROJECT", "")).strip()
    derived = False
    if not name and root:
        # Collision-safe derivation (Loki C303AA2F §3.5): the bare basename
        # collides — /a/charter and /b/charter would share one project state.
        # Disambiguate a human-readable prefix with a short digest of the
        # *canonical* (resolved) path so distinct workspaces never merge. An
        # explicit project id always wins over this and is used verbatim.
        digest = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:8]
        prefix = re.sub(r"[^A-Za-z0-9_.-]", "-", root.name).strip("-") or "project"
        name = f"{prefix}-{digest}"
        derived = True
    if name and not _PROJECT_RE.fullmatch(name):
        return {"error": "invalid_project", "project": name}
    return {
        "name": name or None,
        "root": str(root) if root else None,
        "workspace": str(root) if root else (workspace or None),
        "derived_from_workspace": derived,
    }


def dispatch_send(
    from_app: str,
    to_app: str,
    assignment_md: str,
    *,
    role: str = "",
    reply_to: str = "willow",
    summary: str = "",
    phase: str = "operate",
    priority: str = "normal",
    context_refs: Optional[list[str]] = None,
    dispatch_id: str = "",
) -> dict:
    """Create dispatch/{id}/ with meta, assignment, and status pending."""
    if not (assignment_md or "").strip():
        return {"error": "assignment_required"}
    did = (dispatch_id or new_dispatch_id()).upper()
    # B-52/#241: refuse to write into a redirected dispatch/ tree -- if the
    # root itself is a symlink, mkdir would happily create the new packet
    # wherever that symlink points instead of under dispatch/.
    if dispatch_root().is_symlink():
        return {"error": "dispatch_root_symlinked"}
    root = dispatch_dir(did)
    if root.exists() or root.is_symlink():
        return {"error": "dispatch_exists", "dispatch_id": did}

    role = (role or to_app).lower()
    rel_assignment = f"dispatch/{did}/assignment.md"
    assignment_text = assignment_md.strip() + "\n"
    meta = {
        "format": "startup_packet_meta_v1",
        "version": 1,
        "dispatch_id": did,
        "from_app": from_app,
        "to_app": to_app,
        "role": role,
        "phase": phase,
        "reply_to": reply_to,
        "priority": priority,
        "closeout": dict(DISPATCH_CLOSEOUT),
        "assignment_path": rel_assignment,
        # B-55/#243: recorded at send time so dispatch_read can detect the
        # assignment being edited on disk between send and read/accept --
        # dispatch/ is operator-writable (B-52/#241's own residual), so
        # nothing else stops that edit; this at least makes it detectable
        # rather than silently trusted.
        "assignment_sha256": hashlib.sha256(assignment_text.encode("utf-8")).hexdigest(),
        "context_refs": list(context_refs or []),
        "summary": (summary or "").strip() or _first_line(assignment_md),
        "created_at": _utc_now(),
        "status": "pending",
    }
    # B-52/#241: sign every field above (HMAC-SHA256, runtime-held key --
    # dispatch_signing.py) so dispatch_read/dispatch_list can tell a packet
    # this call actually wrote from one hand-planted directly under the
    # operator-writable dispatch/ tree. Computed last, over the fully
    # populated dict, so it covers every field including assignment_sha256.
    meta["signature"] = dispatch_signing.sign_meta(meta)
    status = {
        "status": "pending",
        "updated_at": meta["created_at"],
        "handoff_path": None,
        "verified_at": None,
        "cleared_at": None,
    }

    root.mkdir(parents=True, exist_ok=False)
    _write_json(root / "meta.json", meta)
    (root / "assignment.md").write_text(assignment_text, encoding="utf-8")
    _write_json(root / "status.json", status)
    _pg_mirror_upsert(meta)  # best-effort fleet mirror; filesystem is canonical

    return {
        "dispatch_id": did,
        "to_app": to_app,
        "from_app": from_app,
        "status": "pending",
        "assignment_path": str(root / "assignment.md"),
        "summary": meta["summary"],
    }


def _first_line(md: str) -> str:
    for line in md.splitlines():
        s = line.strip().lstrip("#").strip()
        if s:
            return s[:200]
    return "dispatch assignment"


_REQUIRED_META_FIELDS = ("dispatch_id", "from_app", "to_app")

# B-52/#241 (continued): every filename dispatch_send/handoff_write_v4 ever
# create *as a real file* under a packet directory. dispatch/ is operator-
# writable, so _meta_is_well_formed alone doesn't stop a same-uid attacker
# from leaving the meta well-formed but swapping one of these names for a
# symlink into a file elsewhere on disk (another app's data, a secret, an
# arbitrary path) -- dispatch_read/handoff_read would then hand that file's
# *content* back as if it were packet content, to whichever caller is a
# party to the packet. That caller (a specialist agent) is frequently a
# different principal from the local filesystem uid, reached only through
# MCP -- it has no independent way to notice the substitution. Refusing a
# symlinked packet dir or member file closes that disclosure path; it does
# not (and cannot, same-uid) stop the packet from being forged in the first
# place -- see _meta_is_well_formed's own docstring for that residual.
PACKET_FILE_NAMES = ("meta.json", "assignment.md", "status.json", "handoff.json", "closeout.md")


def packet_symlink_refused(root: Path) -> bool:
    """True if `root` (a packet directory) or any canonical packet file inside
    it is a symlink. Same is_symlink() doctrine as paths.trusted_read() /
    consent_admin._trusted(); see PACKET_FILE_NAMES above for why."""
    if root.is_symlink():
        return True
    return any((root / name).is_symlink() for name in PACKET_FILE_NAMES)


def _meta_is_well_formed(meta: dict) -> bool:
    """A packet dispatch_send actually wrote always carries the
    startup_packet_meta_v1 format marker and dispatch_id/from_app/to_app
    (B-52, issue #241). A packet mkdir'd directly under the operator-
    writable dispatch/ tree, bypassing dispatch_send entirely, is unlikely
    to replicate this exactly unless deliberately spoofed. Not
    cryptographic -- full closure needs the same uid separation as #231 --
    but it does refuse the trivial "mkdir + bare {}" case the red-team
    demonstrated, at zero cost to any packet dispatch_send actually wrote."""
    if meta.get("format") != "startup_packet_meta_v1":
        return False
    return all((meta.get(f) or "").strip() for f in _REQUIRED_META_FIELDS)


def dispatch_read(dispatch_id: str) -> dict:
    root = dispatch_dir(dispatch_id)
    # B-52/#241: refuse before ever opening a file -- a symlinked packet dir
    # or member file could otherwise redirect this read to content outside
    # dispatch/ entirely. Checked ahead of existence/well-formedness so a
    # symlink can never even reach _read_json.
    if packet_symlink_refused(root):
        return {"error": "symlinked_packet", "dispatch_id": dispatch_id}
    meta = _read_json(root / "meta.json")
    if not meta:
        return {"error": "not_found", "dispatch_id": dispatch_id}
    if not _meta_is_well_formed(meta):
        return {"error": "malformed_packet", "dispatch_id": dispatch_id}
    # B-52/#241: a well-formed meta.json can still be a hand-planted forgery
    # -- verify the HMAC before trusting anything else in it. A present-but-
    # wrong signature is tamper evidence and always refused; a MISSING
    # signature (legacy_unsigned -- packets written before signing existed)
    # is refused only under strict mode, otherwise let through flagged.
    sig_status = dispatch_signing.signature_status(meta)
    if sig_status == dispatch_signing.SIG_INVALID:
        return {"error": "invalid_signature", "dispatch_id": dispatch_id}
    if sig_status == dispatch_signing.SIG_LEGACY_UNSIGNED and dispatch_signing.strict_mode():
        return {"error": "unsigned_packet_strict_mode", "dispatch_id": dispatch_id}
    status = _read_json(root / "status.json") or {}
    assignment_path = root / "assignment.md"
    assignment = ""
    if assignment_path.exists():
        assignment = assignment_path.read_text(encoding="utf-8")
    # B-55/#243: the assignment on disk must still match what dispatch_send
    # actually wrote -- dispatch/ is operator-writable, so nothing else
    # stops an in-place edit between send and read/accept.
    expected_hash = meta.get("assignment_sha256")
    if expected_hash:
        actual_hash = hashlib.sha256(assignment.encode("utf-8")).hexdigest()
        if actual_hash != expected_hash:
            return {"error": "assignment_tampered", "dispatch_id": dispatch_id}
    return {
        "dispatch_id": dispatch_id,
        "meta": meta,
        "status": status,
        "assignment": assignment,
        "signature_status": sig_status,
    }


def is_dispatch_party(app_id: str, meta: dict) -> bool:
    """Whether app_id is from_app, to_app, or reply_to on this packet's own
    meta.json -- the three identities a dispatch names as involved (B-54,
    issue #242). Read-side check, deliberately broader than dispatch_accept's
    to_app-only write check above: the sender should be able to read status
    on its own dispatch, and reply_to is who verifies the handoff -- neither
    of those is "accepting" the packet, but both are legitimately a party
    to it. Server.py's dispatch_read/handoff_read wrappers use this to deny
    a caller who has dispatch_read permission but no relationship to this
    specific packet (previously: any dispatch_read holder could read any
    dispatch_id's full assignment/handoff content)."""
    who = (app_id or "").strip().lower()
    if not who:
        return False
    return who in {
        (meta.get("from_app") or "").strip().lower(),
        (meta.get("to_app") or "").strip().lower(),
        (meta.get("reply_to") or "").strip().lower(),
    }


def dispatch_list(
    *,
    to_app: str = "",
    from_app: str = "",
    status: str = "",
    limit: int = 20,
    cursor: Optional[str] = None,
) -> dict:
    disp_root = dispatch_root()
    # B-52/#241: fail closed if the dispatch root itself has been replaced by
    # a symlink (e.g. to redirect future dispatch_send writes elsewhere) --
    # same is_dir()-follows-symlinks trap as any individual packet dir.
    if disp_root.is_symlink() or not disp_root.is_dir():
        return {"dispatches": [], "total": 0, "unverified": [], "unverified_total": 0,
                "next_cursor": None}

    # Decode cursor — it encodes the mtime and dispatch_id of the last packet
    # returned, so we can resume after it in the mtime-descending walk.
    after_mtime: Optional[float] = None
    after_dispatch_id = ""
    if cursor:
        decoded = decode_cursor(cursor)
        parts = decoded.split("\x00", 1)
        if len(parts) == 2:
            after_mtime = float(parts[0])
            after_dispatch_id = parts[1]
        else:
            after_mtime = float(parts[0])

    rows: list[dict] = []
    # B-52/#241: packets that fail signature verification are NOT normal
    # entries -- collected here instead, each carrying `unverified: true` and
    # a `signature_status` reason, so tampering is surfaced rather than
    # silently dropped (a caller who only reads `dispatches` never sees a
    # forged/legacy packet mixed in with trusted ones).
    unverified: list[dict] = []
    for child in sorted(disp_root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        # child.is_dir() follows a symlink, so check is_symlink() first --
        # a symlinked entry is refused outright, not silently followed.
        if child.is_symlink() or not child.is_dir():
            continue
        if packet_symlink_refused(child):
            continue

        # Skip entries before the cursor position (mtime descending order)
        if after_mtime is not None:
            child_mtime = child.stat().st_mtime
            if (child_mtime > after_mtime or
                    (child_mtime == after_mtime and child.name >= after_dispatch_id)):
                continue

        meta = _read_json(child / "meta.json")
        st = _read_json(child / "status.json") or {}
        if not meta or not _meta_is_well_formed(meta):
            continue
        if to_app and meta.get("to_app", "").lower() != to_app.lower():
            continue
        if from_app and meta.get("from_app", "").lower() != from_app.lower():
            continue
        cur_status = st.get("status") or meta.get("status") or "pending"
        if status and cur_status != status:
            continue
        sig_status = dispatch_signing.signature_status(meta)
        if sig_status == dispatch_signing.SIG_LEGACY_UNSIGNED and dispatch_signing.strict_mode():
            continue  # strict mode: hard-reject, not even surfaced as unverified
        row = {
            "dispatch_id": meta.get("dispatch_id", child.name),
            "from_app": meta.get("from_app"),
            "to_app": meta.get("to_app"),
            "role": meta.get("role"),
            "summary": meta.get("summary", ""),
            "status": cur_status,
            "created_at": meta.get("created_at"),
            "reply_to": meta.get("reply_to"),
            "_mtime": child.stat().st_mtime,
        }
        if sig_status == dispatch_signing.SIG_VALID:
            rows.append(row)
            if len(rows) > limit:
                break
        else:
            row["unverified"] = True
            row["signature_status"] = sig_status
            unverified.append(row)

    has_more = len(rows) > limit
    rows = rows[:limit]

    # Build cursor from the last verified row and strip internal _mtime
    next_cursor = None
    if has_more and rows:
        last = rows[-1]
        next_cursor = encode_cursor(
            f"{last['_mtime']}\x00{last['dispatch_id']}"
        )
    for row in rows:
        row.pop("_mtime", None)

    return {
        "dispatches": rows,
        "total": len(rows),
        "unverified": unverified,
        "unverified_total": len(unverified),
        "next_cursor": next_cursor,
    }


def dispatch_set_status(dispatch_id: str, status: str, **extra: Any) -> dict:
    if status not in VALID_STATUSES:
        return {"error": "invalid_status", "status": status}
    root = dispatch_dir(dispatch_id)
    # B-52/#241: every current caller already routes through dispatch_read
    # first, which refuses a symlinked packet before ever reaching here --
    # but this writes through status.json/meta.json (_write_json follows a
    # symlink to whatever it points at), so guard independently rather than
    # relying on call-order elsewhere never changing.
    if packet_symlink_refused(root):
        return {"error": "symlinked_packet", "dispatch_id": dispatch_id}
    path = root / "status.json"
    data = _read_json(path)
    if data is None:
        return {"error": "not_found", "dispatch_id": dispatch_id}
    data["status"] = status
    data["updated_at"] = _utc_now()
    for key, val in extra.items():
        if val is not None:
            data[key] = val
    _write_json(path, data)
    meta_path = root / "meta.json"
    meta = _read_json(meta_path)
    if meta:
        meta["status"] = status
        # B-52/#241: this is a legitimate mutation of meta.json (only reached
        # through dispatch_accept/handoff_write_v4/agent_clear -- never a raw
        # write), so re-sign rather than let a lifecycle transition
        # self-invalidate the packet's own signature. Any OTHER edit to
        # meta.json -- one that didn't go through this function -- still
        # invalidates it, which is exactly the tamper evidence this exists
        # to catch. A legacy packet with no prior signature is signed for
        # the first time here, same as dispatch_send would have.
        meta["signature"] = dispatch_signing.sign_meta(meta)
        _write_json(meta_path, meta)
    _pg_mirror_status(dispatch_id, status)  # best-effort fleet mirror
    return {"dispatch_id": dispatch_id, "status": status}


def dispatch_accept(dispatch_id: str, app_id: str, session_id: str = "") -> dict:
    """Specialist takes packet: pending → working."""
    pkt = dispatch_read(dispatch_id)
    if pkt.get("error"):
        return pkt
    if pkt["meta"].get("to_app", "").lower() != app_id.lower():
        return {"error": "wrong_recipient", "expected": pkt["meta"].get("to_app")}
    cur = pkt.get("status", {}).get("status", "pending")
    if cur not in ("pending", "cleared"):
        return {"error": "invalid_transition", "from": cur, "to": "working"}
    dispatch_set_status(dispatch_id, "working")
    if session_id:
        session_bind(app_id, session_id, dispatch_id, "working")
    return dispatch_read(dispatch_id)


def session_bind(
    app_id: str,
    session_id: str,
    dispatch_id: str,
    status: str,
    verifier: str = "",
) -> dict:
    """Write the thin session-state file. When ``verifier`` is non-empty, it
    is preserved across subsequent binds (a later ``status`` change never
    overwrites a bound verifier with empty); when empty, whatever was on
    disk stays. Identity-in-session PR2: the session record now names the
    operator who attested it. See ``docs/design/identity-in-session.md`` when
    it lands (PR4)."""
    sessions_dir().mkdir(parents=True, exist_ok=True)
    path = session_path(app_id, session_id)
    prior = _read_json(path)
    prior_verifier = (prior or {}).get("verifier", "")
    data = {
        "app_id": app_id,
        "session_id": session_id,
        "status": status,
        "dispatch_id": dispatch_id,
        "verifier": verifier or prior_verifier,
        "updated_at": _utc_now(),
    }
    _write_json(path, data)
    return data


def session_read(app_id: str, session_id: str) -> dict:
    data = _read_json(session_path(app_id, session_id))
    if not data:
        return {"error": "not_found"}
    return data


def _pending_for_app(app_id: str) -> dict | None:
    rows = dispatch_list(to_app=app_id, status="pending", limit=1)
    dispatches = rows.get("dispatches") or []
    return dispatches[0] if dispatches else None


def _resolve_session_sig(
    app_id: str,
    session_id: str,
    verifier: str,
    attested_at: str,
    seal_sig: str,
) -> None:
    """PR2 of the identity-in-session plan: refuse before session_bind writes.

    Short-circuits when the keyring is not enabled (legacy PGP-fingerprint
    path continues untouched). When the keyring IS enabled:

    * ``verifier`` and ``seal_sig`` both empty → downgrade to unattested;
      matches ``by_human_attested``'s existing downgrade-not-denial policy.
    * one supplied without the other → refuse; a signature without a
      named verifier is a claim about nobody, and a verifier claim without a
      signature is an attribution attempt that must not silently succeed.
    * both supplied but the sig does not verify → refuse. Mirrors
      ``nestor/memory.py::_resolve_seal_sig``: refusal comes BEFORE any
      write, and the store never sees an unverified attempt.

    Raises :class:`session_signing.InvalidSessionSignatureError` in the
    refusal paths.
    """
    from . import session_signing

    if not session_signing.signing_enabled():
        return  # keyring not enabled → legacy path
    if not verifier and not seal_sig:
        return  # no attempt → downgrade to unattested (session_bind writes verifier="")
    if not verifier:
        raise session_signing.InvalidSessionSignatureError(
            "seal_sig supplied without verifier — a signature must name the "
            "operator it attests for"
        )
    if not seal_sig:
        raise session_signing.InvalidSessionSignatureError(
            f"verifier {verifier!r} supplied without seal_sig — a signature "
            "over the frozen wire message is required when the keyring is "
            "enabled"
        )
    if not attested_at:
        raise session_signing.InvalidSessionSignatureError(
            "attested_at is empty — the timestamp is part of the signed "
            "payload and must be supplied by the client-side signer"
        )
    if not session_signing.session_is_valid(
        app_id, session_id, verifier, attested_at, seal_sig
    ):
        raise session_signing.InvalidSessionSignatureError(
            f"session attestation for {verifier!r} does not verify — the "
            "signature does not match the frozen wire bytes for this "
            "verifier's key on this instance"
        )


def session_enter(
    app_id: str,
    session_id: str,
    dispatch_id: str = "",
    project: str = "",
    workspace: str = "",
    verifier: str = "",
    attested_at: str = "",
    seal_sig: str = "",
) -> dict:
    """Resolve session entry mode: human prompt vs dispatch id path.

    Orchestrator (willow) is human-only — never dispatch entry. See
    human-orchestrator.md.

    Identity-in-session PR2: three new optional parameters route through the
    willow branch. ``verifier`` names the operator attesting; ``attested_at``
    is the RFC3339 timestamp in the signed payload; ``seal_sig`` is the
    hex-encoded signature over the frozen wire message the client-side
    signer produced. When the keyring is not enabled all three are ignored,
    preserving the pre-PR2 behavior verbatim. Specialist sessions ignore
    the params too — attribution-to-specialist propagation is a separate
    concern, out of scope for PR2.
    """
    project_info = project_context(project, workspace)
    if project_info.get("error"):
        return project_info

    # ── Orchestrator seat: human operator only; no agent, no packet boot ──
    if is_orchestrator_app(app_id):
        did = (dispatch_id or "").strip().upper()
        if did:
            return {
                "entry_mode": "human_orchestrator",
                "app_id": app_id,
                "session_id": session_id,
                "error": "orchestrator_human_only",
                "message": (
                    "Willow is human-only. dispatch_id is not accepted. "
                    "Agents cannot run the orchestrator seat."
                ),
            }
        # Refuse before session_bind writes anything. When the keyring is not
        # enabled this is a no-op and the legacy behavior stands.
        _resolve_session_sig(app_id, session_id, verifier, attested_at, seal_sig)
        # The verifier field means SOMEONE ATTESTED this session with proof.
        # When the keyring is disabled there is no proof mechanism, so a
        # verifier claim is metadata without backing — never written. This
        # preserves the invariant: a non-empty verifier on the session record
        # is always the name of someone whose signature verified at some
        # point (past-tense; a later revocation may retire the trust).
        from . import session_signing as _session_signing
        stored_verifier = verifier if _session_signing.signing_enabled() else ""
        session_bind(app_id, session_id, "", "idle", verifier=stored_verifier)
        return {
            "entry_mode": "human_orchestrator",
            "app_id": app_id,
            "session_id": session_id,
            "dispatch_id": None,
            "agent_doc": _AGENT_DOC,
            "agent_doc_section": "orchestrator",
            "closeout_tools": ["session_handoff_write"],
            "project": project_info,
            "message": (
                "Human orchestrator entry. Desk: dispatch_list. "
                "Assign with dispatch_send (human host only). "
                "Never dispatch entry for willow."
            ),
            **persona_context(app_id),
            **seed_context(app_id),
        }

    did = (dispatch_id or "").strip().upper()

    if not did:
        existing = session_read(app_id, session_id)
        if not existing.get("error") and existing.get("dispatch_id"):
            did = str(existing["dispatch_id"]).upper()

    if not did:
        pending = _pending_for_app(app_id)
        if pending:
            did = pending["dispatch_id"]

    if not did:
        session_bind(app_id, session_id, "", "idle")
        return {
            "entry_mode": "human",
            "app_id": app_id,
            "session_id": session_id,
            "dispatch_id": None,
            "agent_doc": _AGENT_DOC,
            "agent_doc_section": "specialist",
            "closeout_tools": ["context_save", "session_handoff_write"],
            "project": project_info,
            "message": "Human entry — no dispatch_id. Use human-facing agent and output.",
            **persona_context(app_id),
            **seed_context(app_id),
        }

    pkt = dispatch_read(did)
    if pkt.get("error"):
        return {"entry_mode": "dispatch", "error": pkt["error"], "dispatch_id": did}

    if pkt["meta"].get("to_app", "").lower() != app_id.lower():
        return {
            "entry_mode": "dispatch",
            "error": "wrong_recipient",
            "dispatch_id": did,
            "expected": pkt["meta"].get("to_app"),
        }

    cur = pkt.get("status", {}).get("status", "pending")
    if cur == "pending":
        pkt = dispatch_accept(did, app_id, session_id)
    elif session_id:
        session_bind(app_id, session_id, did, cur)

    closeout = closeout_from_meta(pkt.get("meta", {}))
    return {
        "entry_mode": "dispatch",
        "app_id": app_id,
        "session_id": session_id,
        "dispatch_id": did,
        "agent_doc": _AGENT_DOC,
        "agent_doc_section": "specialist",
        "role": pkt.get("meta", {}).get("role"),
        "assignment": pkt.get("assignment", ""),
        "summary": pkt.get("meta", {}).get("summary", ""),
        "closeout": closeout,
        "closeout_tools": [closeout["tool"]],
        "project": project_info,
        "status": pkt.get("status", {}).get("status"),
        **persona_context(app_id),
        **seed_context(app_id),
    }


def session_handoff_write(
    app_id: str,
    session_id: str,
    *,
    narrative: str,
    summary: str = "",
    findings: Optional[list[dict]] = None,
    next_bite: str = "",
    project: str = "",
    workspace: str = "",
) -> dict:
    """Project-scoped v3 human-entry closeout — no dispatch_id required."""
    project_info = project_context(project, workspace)
    if project_info.get("error"):
        return project_info
    sessions_dir().mkdir(parents=True, exist_ok=True)
    handoffs = handoffs_dir(app_id)
    project_name = project_info.get("name")
    if project_name:
        handoffs = handoffs / project_name
    handoffs.mkdir(parents=True, exist_ok=True)
    stamp = _utc_now()[:10]
    hid = new_dispatch_id()[:8].lower()
    path = handoffs / f"session_handoff-{stamp}-{hid}_{app_id}.md"
    lines = [
        f"# Session handoff — {app_id}",
        "",
        "**Format:** session_handoff_v3",
        "**Entry mode:** human",
        f"**Session:** {session_id}",
        f"**Project:** {project_name or ''}",
        f"**Workspace:** {project_info.get('workspace') or ''}",
        f"**Written:** {_utc_now()}",
        "",
        "## Summary",
        "",
        summary or narrative[:500],
        "",
        "## Narrative",
        "",
        narrative,
        "",
    ]
    if findings:
        lines.extend(["## Findings", ""])
        for f in findings:
            if isinstance(f, str):
                lines.append(f"- {f}")
                continue
            if not isinstance(f, dict):
                continue
            lines.append(f"- **{f.get('id', 'finding')}** ({f.get('severity', '')}): {f.get('text', '')}")
        lines.append("")
    if next_bite:
        lines.extend(["## Next bite", "", next_bite, ""])
    body = "\n".join(lines)
    path.write_text(body, encoding="utf-8")
    session_bind(app_id, session_id, "", "idle")
    return {
        "entry_mode": "human",
        "format": "session_handoff_v3",
        "project": project_info,
        "handoff_path": str(path),
        "continuity_key": f"handoff/{stamp}-{hid}",
    }


def latest_project_handoff(app_id: str, project: str) -> dict | None:
    if not project or not _PROJECT_RE.fullmatch(project):
        return None
    root = handoffs_dir(app_id) / project
    if not root.is_dir():
        return None
    paths = sorted(
        root.glob("session_handoff-*.md"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not paths:
        return None
    path = paths[0]
    return {"path": str(path), "content": path.read_text(encoding="utf-8")}


def agent_clear(target_app: str, dispatch_id: str, session_id: str = "") -> dict:
    """Orchestrator clears specialist after verify: → cleared."""
    pkt = dispatch_read(dispatch_id)
    if pkt.get("error"):
        return pkt
    st = pkt.get("status", {}).get("status")
    if st not in ("complete", "verified"):
        return {"error": "not_ready_for_clear", "status": st}
    dispatch_set_status(
        dispatch_id,
        "cleared",
        cleared_at=_utc_now(),
    )
    if session_id:
        session_bind(target_app, session_id, "", "idle")
    return {"dispatch_id": dispatch_id, "target_app": target_app, "status": "cleared"}
