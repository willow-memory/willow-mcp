"""Dispatch packet I/O — meta.json, assignment.md, status.json under $WILLOW_HOME/dispatch/."""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import logging
import os
import re
import uuid
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


def _post_dispatch_wake(meta: dict) -> None:
    """Best-effort: wake the target seat's Grove bus listener for a fresh
    dispatch. Same posture as `_pg_mirror_upsert` right above it — a bus
    failure (ratatosk missing, gate denial, Postgres down, anything else) is
    logged and swallowed here, never raised, so a dead or unconfigured Grove
    bus can never break a dispatch that has already written its packet to
    disk. See `grove_tools.post_wake_envelope` for the envelope shape and why
    `BusListener.validate_envelope` accepts it."""
    try:
        from . import grove_tools
        result = grove_tools.post_wake_envelope(
            meta.get("from_app", ""),
            meta.get("to_app", ""),
            dispatch_id=meta.get("dispatch_id", ""),
            summary=meta.get("summary", ""),
            reply_to=meta.get("reply_to", ""),
        )
        if not result.get("posted"):
            logger.debug("dispatch: wake not posted: %s", result.get("reason"))
    except Exception:  # best-effort: a wake fault must never break a written packet
        logger.debug("dispatch: wake post skipped", exc_info=True)


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
    """Atomic write (bite 1, dispatch 9BA76253, LOW-5): a plain truncate-then-
    write left a reader able to observe a partially-written status.json or
    meta.json mid-write. Write to a per-call temp file in the same directory,
    then os.replace it into place -- atomic on POSIX, so a reader always sees
    either the old content or the new, never a partial one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


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
    from_verifier: str = "",
    from_session: str = "",
    gaps_project: str = "",
    gaps_paths: Optional[list[str]] = None,
    runner: str = "seat",
) -> dict:
    """Create dispatch/{id}/ with meta, assignment, and status pending.

    ``from_verifier`` and ``from_session`` name the human operator whose
    orchestrator session generated this dispatch (envelope-accrual PR9,
    Kart-boundary silence follow-up). They travel inside the signed
    meta.json so the specialist can carry the orchestrator's attribution
    forward — when the specialist hits ENOGRANTS on a verb, the
    auto-propose queue entry can be attributed back to the operator, not
    dropped as unattributed. Both empty (legacy call site, unattributed
    orchestrator, or specialist-to-specialist chain) keeps the pre-PR9
    behavior: no attribution rides the packet, the specialist's own gate
    misses stay silent.

    ``gaps_project`` and ``gaps_paths`` (Loki 28B97C69 H1b) record the
    project and paths server.dispatch_send's own gaps_touching computation
    used AT SEND TIME. They ride the signed packet so session_enter can
    recompute the recipient's gaps_touching block from what the packet
    itself names, never from the specialist's own entering workspace --
    a packet about `ratatosk` entered from `willows-grove` must not lose
    its tier-3 match just because the specialist opened a different repo."""
    if not (assignment_md or "").strip():
        return {"error": "assignment_required"}
    if (from_app or "").strip().lower() == (to_app or "").strip().lower():
        # Loki 40A353F2 A1: a self-addressed packet is the shape a seat uses
        # to mint its own citation (send to self citing X, accept, read X).
        # Refused regardless of envelope — there is no legitimate self-send.
        return {"error": "EINVAL", "message": "a packet cannot be sent to its sender",
                "from_app": from_app, "to_app": to_app}
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
    # N1 (dispatch 1AD03A64): listener opt-in. "seat" (default) or
    # "ratatosk" -- the only two runners this fleet has today. Stored on
    # the signed meta so dispatch_accept/session_enter can refuse a
    # mismatched acceptor (ERUNNER) without trusting the caller's own
    # claim about what it is.
    runner_norm = (runner or "seat").strip().lower()
    if runner_norm not in ("seat", "ratatosk"):
        return {"error": "EINVAL",
                "message": f"runner must be 'seat' or 'ratatosk', got {runner!r}"}
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
        # Envelope-accrual PR9: the operator's identity rides the packet so
        # the specialist can attribute its own auto-proposed envelopes back
        # to the human who dispatched it. Empty when the orchestrator's own
        # session is unattributed, or on a specialist-to-specialist chain
        # where no operator is directly upstream (also empty on legacy
        # in-repo callers that don't pass these). Covered by the HMAC
        # signature below like every other field — tampering with either
        # field invalidates the packet, so a hand-planted meta.json can't
        # forge an operator attribution.
        "from_verifier": (from_verifier or "").strip(),
        "from_session": (from_session or "").strip(),
        # Loki 28B97C69 H1b: the send-time project/paths for gaps_touching,
        # so session_enter reads the packet's own project rather than the
        # specialist's entering workspace.
        "gaps_project": (gaps_project or "").strip(),
        "gaps_paths": list(gaps_paths or []),
        "runner": runner_norm,
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
    _post_dispatch_wake(meta)  # best-effort Grove wake; filesystem is canonical

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
PACKET_FILE_NAMES = ("meta.json", "assignment.md", "status.json", "handoff.json", "closeout.md", "refused", ".handoff.lock", "history")


def packet_symlink_refused(root: Path) -> bool:
    """True if `root` (a packet directory) or any canonical packet file inside
    it is a symlink. Same is_symlink() doctrine as paths.trusted_read() /
    consent_admin._trusted(); see PACKET_FILE_NAMES above for why."""
    if root.is_symlink():
        return True
    return any((root / name).is_symlink() for name in PACKET_FILE_NAMES)


@contextlib.contextmanager
def packet_lock(root: Path):
    """Cross-process exclusive claim on one packet directory (bite 1,
    dispatch 9BA76253 rework of 2E590F1B/262F89A1 F1/F2): `fcntl.flock` on a
    lockfile inside the packet dir. Blocks until acquired. Holds ACROSS
    separate OS processes, not just threads inside one interpreter -- this
    is load-bearing because the ratatosk listener runs its own willow-mcp
    child process, a real second `python` racing the actual specialist for
    the same packet, not a second thread in the same one.

    Takes the resolved packet directory rather than a dispatch_id so each
    caller resolves it through ITS OWN module-local `dispatch_dir` (this
    module's, or handoff.py's) -- a test that patches one module's
    `dispatch_dir` (a common fixture shape in this repo) then gets a lock
    path consistent with the directory that module actually reads and
    writes, instead of silently falling through to this module's real,
    unpatched one.

    Every caller that mutates a packet's accept/complete transition must
    re-read the packet's status AFTER entering this context, never rely on
    a read taken before it -- otherwise two callers can both observe
    'working' before either acquires the lock and both believe they are the
    first writer once they get it."""
    root.mkdir(parents=True, exist_ok=True)
    lock_path = root / ".handoff.lock"
    # N7 (dispatch 1AD03A64): O_NOFOLLOW so a symlink planted at .handoff.lock
    # (dispatch/ is operator-writable) cannot redirect this open to a file
    # outside the packet dir -- same disclosure shape PACKET_FILE_NAMES exists
    # to close for the other packet files, now closed for the lockfile too.
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    fh = os.fdopen(fd, "r+")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        finally:
            fh.close()


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


# ── cited-packet read (gaps fe3ae204a964 / e40691d86df6) ─────────────────────
#
# An audit packet cites the builder's dispatch_id in its context_refs; a
# rework packet cites the audit's. Under B-54 (#242) the auditor was
# `not_party_to_dispatch` on the very packet it was assigned to audit and read
# handoff.json off disk instead — the disclosure rule held and the audit
# trail lost the read. A citation is a relationship the orchestrator wrote
# into the citing packet's signed meta, so it is grounds for a READ of the
# cited packet: `dispatch_read` / `handoff_read` succeed for caller C when C
# is the to_app of a packet P that cites X and P is working or complete.
# Read only — never accept, handoff, or clear through a citation. Depth one —
# a citation of a citation grants nothing. Anything a citation allows is
# receipted with `via: P` so the trail says how the read was allowed.
#
# Who may vouch (Loki 40A353F2, A1): `dispatch_send` is filesystem-backed and
# eight specialist manifests hold it, so a seat can write a packet to itself
# citing any id and accept it — a citation a specialist authored for its own
# reader is not a relationship, it is a request. A citing packet grants a
# read only when its `from_app` is the orchestrator or is itself a party to
# the cited packet: the vouching identity must already be entitled to what it
# is vouching for. A packet cannot be sent to its sender at all
# (`dispatch_send` refuses EINVAL), which closes the trivial shape outright.

# A context_ref cites a packet only when the entry IS the id (``67E344A9``) or
# ``dispatch:<id>`` — nothing else. Prose extraction was dropped (Loki
# 40A353F2, A2): "see dispatch DEADBEEF-ish notes" minted DEADBEEF.
_CITATION_ID_RE = re.compile(r"^(?:dispatch:)?([0-9A-Fa-f]{8})$")
CITATION_READ_STATUSES = frozenset({"working", "complete", "verified"})


def citation_set(meta: dict) -> set[str]:
    """The dispatch ids a packet's ``context_refs`` name: entries that are
    exactly a bare id (``67E344A9``) or ``dispatch:67E344A9``. Any other
    entry — prose, a longer token, an id with a suffix — contributes
    nothing; a citation is a deliberate entry, not a mention."""
    out: set[str] = set()
    for ref in meta.get("context_refs") or []:
        if not isinstance(ref, str):
            continue
        m = _CITATION_ID_RE.match(ref.strip())
        if m:
            out.add(m.group(1).upper())
    return out


def citation_may_vouch(citing_meta: dict, cited_meta: dict) -> bool:
    """Whether the author of the citing packet is entitled to vouch for a
    read of the cited one: the orchestrator always is; any other sender only
    when it is itself a party (from_app / to_app / reply_to) to the cited
    packet. A specialist that is a stranger to the cited packet cannot open
    it to its own reader by writing a packet that cites it."""
    sender = (citing_meta.get("from_app") or "").strip().lower()
    if not sender:
        return False
    if is_orchestrator_app(sender):
        return True
    return is_dispatch_party(sender, cited_meta)


def citation_read_access(app_id: str, target_dispatch_id: str) -> dict | None:
    """Return ``{"via": <citing packet id>, "via_status": ..., "via_from":
    ...}`` when ``app_id`` may read the packet ``target_dispatch_id``
    through a citation, else ``None``.

    Grounds: a packet P with ``to_app == app_id``, status in
    :data:`CITATION_READ_STATUSES`, ``target_dispatch_id`` in P's citation
    set, and P's ``from_app`` entitled to vouch (:func:`citation_may_vouch`:
    the orchestrator, or a party to the cited packet). P must itself verify
    (signature, no symlink) — a forged citing packet grants nothing. Only
    P's own context_refs are consulted: what P cites is readable, what P's
    citations cite is not. The cited packet must exist and verify too — a
    citation of nothing grants nothing.
    """
    who = (app_id or "").strip().lower()
    target = (target_dispatch_id or "").strip().upper()
    if not who or not target:
        return None
    disp_root = dispatch_root()
    if disp_root.is_symlink() or not disp_root.is_dir():
        return None
    cited_dir = disp_root / target
    if cited_dir.is_symlink() or not cited_dir.is_dir() or packet_symlink_refused(cited_dir):
        return None
    cited_meta = _read_json(cited_dir / "meta.json")
    if not cited_meta or not _meta_is_well_formed(cited_meta):
        return None
    for child in sorted(disp_root.iterdir(), key=lambda p: p.name):
        if child.is_symlink() or not child.is_dir() or packet_symlink_refused(child):
            continue
        if child.name.upper() == target:
            continue
        meta = _read_json(child / "meta.json")
        if not meta or not _meta_is_well_formed(meta):
            continue
        if (meta.get("to_app") or "").strip().lower() != who:
            continue
        if target not in citation_set(meta):
            continue
        if not citation_may_vouch(meta, cited_meta):
            continue
        if dispatch_signing.signature_status(meta) != dispatch_signing.SIG_VALID:
            continue
        st = _read_json(child / "status.json") or {}
        cur = st.get("status") or meta.get("status") or "pending"
        if cur not in CITATION_READ_STATUSES:
            continue
        return {
            "via": str(meta.get("dispatch_id") or child.name).upper(),
            "via_status": cur,
            "via_from": (meta.get("from_app") or "").strip().lower(),
        }
    return None


NOT_PARTY_HINT = (
    "not a party to this packet; a working or complete packet addressed to you "
    "that lists this id in its context_refs grants read only — and only when "
    "that packet was sent by the orchestrator or by a party to this one"
)


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


def dispatch_set_status(
    dispatch_id: str, status: str, *, already_locked: bool = False, **extra: Any,
) -> dict:
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
    # N5 (dispatch 1AD03A64, Loki 10A39E21 N5): dispatch_withdraw/
    # agent_clear/verify_handoff used to read-modify-write status.json
    # OUTSIDE packet_lock -- a concurrent accept or close could lose an
    # update against them. `already_locked=True` is passed ONLY by callers
    # that already hold packet_lock for this same dispatch_id
    # (dispatch_accept, handoff_write_v4) -- taking it again here, even in
    # the same process, would deadlock (flock is per open-file-description,
    # not per-process). Every other caller gets the lock taken right here.
    if already_locked:
        return _dispatch_set_status_locked(dispatch_id, root, status, extra)
    with packet_lock(root):
        return _dispatch_set_status_locked(dispatch_id, root, status, extra)


def _dispatch_set_status_locked(dispatch_id: str, root: Path, status: str, extra: dict) -> dict:
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
        meta["signature"] = dispatch_signing.sign_meta(meta)
        _write_json(meta_path, meta)
    _pg_mirror_status(dispatch_id, status)  # best-effort fleet mirror
    return {"dispatch_id": dispatch_id, "status": status}


def _archive_prior_handoff(dispatch_id: str) -> None:
    """F3 (dispatch 1AD03A64): move a cleared packet's prior handoff.json
    and closeout.md to history/<utc-ts>/ before a re-accept starts a fresh
    cycle. Caller must already hold packet_lock. A missing handoff.json
    (never actually completed, or already archived) is a silent no-op."""
    root = dispatch_dir(dispatch_id)
    handoff_path = root / "handoff.json"
    if not handoff_path.exists():
        return
    ts = _utc_now().replace(":", "").replace("-", "")
    # F3B (Loki ADC80409): _utc_now() has one-second granularity; exist_ok
    # plus os.replace let three re-accepts in the same wall-clock second
    # overwrite each other's archive. A random token makes the directory
    # name unique regardless of timing, same discipline as the sidecar
    # filenames in _write_refused_sidecar.
    token = uuid.uuid4().hex[:8]
    hist_dir = root / "history" / f"{ts}-{token}"
    hist_dir.mkdir(parents=True, exist_ok=False)
    import os as _os
    _os.replace(handoff_path, hist_dir / "handoff.json")
    closeout_path = root / "closeout.md"
    if closeout_path.exists():
        _os.replace(closeout_path, hist_dir / "closeout.md")


def dispatch_accept(dispatch_id: str, app_id: str, session_id: str = "", runner: str = "seat") -> dict:
    """Specialist takes packet: pending → working.

    Bite 1 (dispatch 9BA76253, rework of 2E590F1B/262F89A1 F2): the accept
    that actually flips pending/cleared → working is the ONLY event that
    records ``accepted_session_id`` on the packet's status -- under the
    same cross-process ``packet_lock`` handoff_write_v4 re-reads status
    under, so a claim here can't race a concurrent accept attempt from a
    second process. ``handoff_write_v4`` later refuses a write whose
    ``session_id`` doesn't match this recorded value (ESESSION) -- this is
    what stops a re-entering session (e.g. the ratatosk listener's own
    child process) from ever being treated as the accepting one. Always
    written (even as ``""``) so a fresh accept on a recurring/cleared
    packet overwrites whatever stale value a prior cycle left, rather than
    leaving a previous session's id bound to a new acceptance.

    When the packet carries ``from_verifier`` (envelope-accrual PR9),
    that operator identity is bound onto the specialist's session record
    and added to the in-process attribution cache. That's what lets the
    specialist's own auto-propose from ``_enveloped_verb_gate`` succeed —
    ``envelope_authoring.propose`` requires an attributed session, and
    the specialist has no keyring identity of its own; the orchestrator's
    identity travels through the dispatch packet to serve as the
    proposer of record."""
    pkt = dispatch_read(dispatch_id)
    if pkt.get("error"):
        return pkt
    if pkt["meta"].get("to_app", "").lower() != app_id.lower():
        return {"error": "wrong_recipient", "expected": pkt["meta"].get("to_app")}
    # N1 (dispatch 1AD03A64): listener opt-in. A packet's runner is fixed at
    # dispatch_send time; a caller whose own runner doesn't match is refused
    # here, before the lock -- no bind, no status change, so a listener
    # racing a real seat for a seat-only packet can never win the accept.
    pkt_runner = (pkt["meta"].get("runner") or "seat").strip().lower()
    caller_runner = (runner or "seat").strip().lower()
    if pkt_runner != caller_runner:
        return {
            "error": "ERUNNER",
            "dispatch_id": dispatch_id,
            "expected": pkt_runner,
            "got": caller_runner,
            "message": (
                f"packet {dispatch_id!r} is runner={pkt_runner!r}; caller "
                f"passed runner={caller_runner!r} -- refused, no bind, no "
                f"status change"
            ),
        }
    with packet_lock(dispatch_dir(dispatch_id)):
        # Re-read status UNDER the lock -- a read taken before acquiring it
        # can be stale by the time this caller wins the lock.
        pkt = dispatch_read(dispatch_id)
        if pkt.get("error"):
            return pkt
        cur = pkt.get("status", {}).get("status", "pending")
        # F3 (dispatch 1AD03A64), operator ruling recorded as SOIL
        # listener-opt-in-and-reaccept-archive-2026-09-28 ("Archive the old
        # one"): re-accepting a CLEARED packet (a recurring dispatch) is
        # allowed, but its prior handoff.json/closeout.md are archived
        # under history/ FIRST, atomically, under this same lock -- so the
        # new run always writes fresh and _create_handoff_exclusive never
        # loses a race against a stale verdict left by the previous cycle.
        if cur not in ("pending", "cleared"):
            return {"error": "invalid_transition", "from": cur, "to": "working"}
        if cur == "cleared":
            _archive_prior_handoff(dispatch_id)
        dispatch_set_status(
            dispatch_id, "working", accepted_session_id=session_id,
            already_locked=True,
        )
        # G3 (Loki 6FC22847): session_bind used to run AFTER this lock was
        # released -- a withdraw winning the very next acquisition of this
        # same lock in that window saw status "working" with
        # accepted_session_id already recorded but no session record yet
        # on disk, so _sessions_bound_to (which reads session files, not
        # status.json) found nothing bound. Binding here, still under the
        # same lock as the status write, closes that window: by the time
        # any other caller can acquire this lock, both the packet's
        # accepted_session_id and the session record agree.
        if session_id:
            from_verifier = str(pkt["meta"].get("from_verifier") or "").strip()
            session_bind(
                app_id, session_id, dispatch_id, "working",
                verifier=from_verifier,
            )
            if from_verifier:
                # Adds this specialist session to the attribution cache so
                # its own gate misses (via _auto_propose_on_gate_miss)
                # succeed rather than short-circuiting on
                # is_session_attributed=False. Lazy import: human_session
                # pulls keyring, and dispatch.py is imported early enough
                # that a top-level import loops.
                from . import human_session as _hs
                _hs._remember_attributed(session_id)
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
    runner: str = "seat",
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
        # NB: attribution cache warming happens in orchestrator_write_denial
        # after it verifies the sidecar (PR4 lazy-cache shape). PR8's
        # auto-sign path in session_start_hook writes the sidecar to disk
        # BEFORE calling session_enter, so the first orchestrator write
        # will find the sidecar there and populate the cache exactly the
        # way a manually sign-session'd flow would. Warming the cache
        # here without a sidecar on disk would break the invariant that
        # session-is-attributed IFF sidecar+sig verify (a subsequent
        # process restart would find the cache empty and the sidecar
        # missing, refusing the operator).
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
        # Gap 22c8c1aab079: a bare entry used to be handed the oldest pending
        # packet for this app_id, whatever the seat had come to do — an
        # unrelated packet was auto-claimed by whoever entered next. A
        # packet is bound only when the caller names it (dispatch_id); a
        # bare entry is told what is pending and enters unassigned.
        pending_ids = [
            row["dispatch_id"]
            for row in (dispatch_list(to_app=app_id, status="pending", limit=20)
                        .get("dispatches") or [])
        ]
        session_bind(app_id, session_id, "", "idle")
        return {
            "entry_mode": "human",
            "app_id": app_id,
            "session_id": session_id,
            "dispatch_id": None,
            "pending_dispatches": pending_ids,
            "agent_doc": _AGENT_DOC,
            "agent_doc_section": "specialist",
            "closeout_tools": ["context_save", "session_handoff_write"],
            "project": project_info,
            "message": (
                "Human entry — no dispatch_id. Use human-facing agent and output."
                + (f" {len(pending_ids)} packet(s) pending for {app_id}: "
                   f"{', '.join(pending_ids)} — none is bound; re-enter with "
                   "dispatch_id=<id> to work one."
                   if pending_ids else "")
            ),
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
    if cur == "withdrawn":
        return {
            "entry_mode": "dispatch",
            "error": "invalid_transition",
            "from": cur,
            "to": "working",
            "dispatch_id": did,
            "message": "packet was withdrawn by the orchestrator; it cannot be entered",
        }

    # G2 (Loki 6FC22847): an empty/missing session_id used to reach the
    # re-entry branch below (`elif session_id:` was simply skipped) and
    # fall all the way through to the result -- full assignment,
    # held_by_other_session left False, and the bearer accepted_session_id
    # handed back -- without EITHER the runner check or the
    # held-by-another-session check ever running. Refuse before any of
    # that: a dispatch entry always names the session entering it.
    if not (session_id or "").strip():
        return {
            "entry_mode": "dispatch",
            "error": "EINVAL",
            "dispatch_id": did,
            "message": "session_id is required to enter a dispatch packet",
        }

    # N1B / G2 (Loki 6FC22847): the runner check now runs before ANY status
    # branch -- it used to sit only inside the re-entry branch (reachable
    # solely when session_id was truthy), so a runner mismatch on a fresh
    # accept relied entirely on dispatch_accept's own later, redundant
    # check. Checking here first makes it uniform for the pending-accept
    # and re-entry paths alike; it can run unconditionally now that
    # session_id is guaranteed non-empty above.
    pkt_runner = (pkt["meta"].get("runner") or "seat").strip().lower()
    caller_runner = (runner or "seat").strip().lower()
    if pkt_runner != caller_runner:
        return {
            "entry_mode": "dispatch",
            "error": "ERUNNER",
            "dispatch_id": did,
            "expected": pkt_runner,
            "got": caller_runner,
            "message": (
                f"packet {did!r} is runner={pkt_runner!r}; caller "
                f"passed runner={caller_runner!r} -- refused, no bind, "
                f"no status change"
            ),
        }

    held_by_other_session = False
    if cur == "pending":
        accept_result = dispatch_accept(did, app_id, session_id, runner=runner)
        if accept_result.get("error"):
            # The runner check just above already excludes ERUNNER here --
            # any error reaching this point is the N4 (Loki 10A39E21 N4)
            # concurrent-accept race: re-read rather than let `pkt` become
            # the bare error dict and fall through below as a
            # success-shaped, empty entry.
            pkt = dispatch_read(did)
            if pkt.get("error"):
                return {"entry_mode": "dispatch", "error": pkt["error"], "dispatch_id": did}
            cur = pkt.get("status", {}).get("status", "pending")
            accepted_session_id = str(pkt.get("status", {}).get("accepted_session_id") or "")
            if accepted_session_id and accepted_session_id != session_id:
                held_by_other_session = True
            elif accepted_session_id != session_id:
                # Lost the race and it isn't even bound to us -- surface
                # the real error rather than pretending success.
                return {
                    "entry_mode": "dispatch",
                    "error": accept_result["error"],
                    "dispatch_id": did,
                    "status": cur,
                }
        else:
            pkt = accept_result
    else:
        # Re-entry into an already-accepted (or since-cleared) packet.
        # session_id is guaranteed non-empty above. Bite 1 (dispatch
        # 9BA76253, rework of 2E590F1B/262F89A1 F2): a re-entry is only
        # ever a continuation of the SAME accepting session -- not a
        # chance for a second session (the ratatosk listener's own child
        # process is the motivating case) to silently pick up
        # attribution/binding for a packet it never actually accepted.
        # `accepted_session_id` is recorded ONLY by dispatch_accept (see
        # its docstring); when it is present and names a DIFFERENT session
        # than this one, this call does not bind -- no session_bind, no
        # attribution lift -- and the caller is told the packet is held by
        # another session. An empty/absent `accepted_session_id` (a legacy
        # packet accepted before this field existed, or one accepted with
        # no session_id at all) has nothing recorded to protect, so
        # re-entry there keeps the pre-existing permissive behavior.
        accepted_session_id = str(pkt.get("status", {}).get("accepted_session_id") or "")
        if accepted_session_id and accepted_session_id != session_id:
            held_by_other_session = True
        else:
            from_verifier = str(pkt["meta"].get("from_verifier") or "").strip()
            session_bind(app_id, session_id, did, cur, verifier=from_verifier)
            if from_verifier:
                from . import human_session as _hs
                _hs._remember_attributed(session_id)

    closeout = closeout_from_meta(pkt.get("meta", {}))
    result = {
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
        # Loki 28B97C69 H1b: the packet's OWN gaps project/paths, recorded
        # at send time -- server.session_enter reads these (falling back
        # to the entering workspace's project / a fresh extraction from
        # `assignment` for a packet sent before this shipped) rather than
        # the specialist's entering workspace, which may be a different
        # repo entirely from the one the assignment is about.
        "gaps_project": pkt.get("meta", {}).get("gaps_project", ""),
        "gaps_paths": pkt.get("meta", {}).get("gaps_paths", []),
        "status": pkt.get("status", {}).get("status"),
        # Bite 1 (dispatch 9BA76253): surfaced so a re-entering caller can
        # tell "you are not the accepting session" apart from an ordinary
        # continuation -- see the else branch above.
        "held_by_other_session": held_by_other_session,
        **persona_context(app_id),
        **seed_context(app_id),
    }
    # G1 (Loki 6FC22847): accepted_session_id is a bearer value -- never
    # return it from session_enter to anyone, including the holder. The
    # holder already knows its own session_id; there is no legitimate
    # reader of this field here (dispatch_read/dispatch_list withhold it
    # too -- see server.py's dispatch_read wrapper and dispatch_list's row
    # shape above).
    return result


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
    root = dispatch_dir(dispatch_id)
    # N5C (Loki ADC80409): same stale-read-before-lock hazard as withdraw
    # (N5B) -- re-read status under packet_lock so a concurrent write
    # (e.g. the packet going to "failed") can't be clobbered by a clear
    # decided against a status read before this caller won the lock.
    with packet_lock(root):
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
            already_locked=True,
        )
    if session_id:
        session_bind(target_app, session_id, "", "idle")
    return {"dispatch_id": dispatch_id, "target_app": target_app, "status": "cleared"}


def _sessions_bound_to(app_id: str, dispatch_id: str) -> list[dict]:
    """Session records of ``app_id`` whose ``dispatch_id`` is this packet and
    whose status is still ``working`` — the only liveness signal the session
    layer holds. A record is a file the seat wrote at bind time; nothing
    here can tell a live seat from one that died without closing, which is
    exactly why a working packet with such a record is refused rather than
    withdrawn from under it."""
    root = sessions_dir()
    if not root.is_dir():
        return []
    want = (dispatch_id or "").upper()
    prefix = f"{app_id}-"
    out: list[dict] = []
    for path in sorted(root.glob(f"{prefix}*.json")):
        if path.is_symlink() or path.name.endswith(".attest.json"):
            continue
        rec = _read_json(path)
        if not rec:
            continue
        if str(rec.get("dispatch_id") or "").upper() != want:
            continue
        if rec.get("status") == "working":
            out.append(rec)
    return out


def dispatch_withdraw(
    dispatch_id: str, reason: str, *, by_app: str, force: bool = False,
) -> dict:
    """Orchestrator retires a packet: pending → withdrawn (gap afa515539c0a).

    ``working`` → ``withdrawn`` only when no session record of the assignee
    is still bound to the packet as ``working``; when one is, the packet is
    refused ``EBUSY`` naming the session ids and the reconcile path
    (``session_reconcile`` on each, which moves the record off working) —
    liveness beyond the session record cannot be known here, and withdrawing
    a packet a seat is working would strand its handoff. ``dispatch_accept``
    binds a session, so an accepted packet whose seat died stays EBUSY until
    someone reconciles it; ``force=True`` is the orchestrator's way past that
    (Loki 40A353F2, B1): the withdrawal proceeds, the bound session ids are
    recorded on status.json as ``forced_over_sessions`` and returned, and
    the server wrapper puts them in the FRANK event. ``force`` is honoured
    only for an orchestrator ``by_app``; anyone else gets EBUSY as before.

    ``withdrawn`` is terminal: ``dispatch_accept``, ``session_enter(
    dispatch_id=...)`` and ``handoff_write_v4`` all refuse
    ``invalid_transition``; ``dispatch_list(status="pending")`` never
    returns it. The reason is recorded on status.json; the FRANK
    ``dispatch_withdraw`` event is the server wrapper's (it holds the
    ledger).
    """
    if not (reason or "").strip():
        return {"error": "reason_required", "dispatch_id": dispatch_id}
    pkt = dispatch_read(dispatch_id)
    if pkt.get("error"):
        return pkt
    did = pkt["meta"].get("dispatch_id") or dispatch_id.upper()
    root = dispatch_dir(did)
    # N5B (Loki ADC80409): the decision (read status, check EBUSY) used to
    # be made BEFORE acquiring packet_lock -- a concurrent dispatch_accept
    # or handoff_write_v4 could land between this read and the write below,
    # so withdraw's own "pending"/EBUSY read went stale and it overwrote a
    # packet that had since become working and session-bound. Re-read
    # under the lock, same discipline dispatch_accept/handoff_write_v4 use.
    with packet_lock(root):
        pkt = dispatch_read(did)
        if pkt.get("error"):
            return pkt
        cur = pkt.get("status", {}).get("status", "pending")
        if cur == "withdrawn":
            return {"error": "already", "dispatch_id": did, "status": cur}
        forced_over: list[str] = []
        if cur == "working":
            bound = _sessions_bound_to(pkt["meta"].get("to_app", ""), did)
            session_ids = [str(r.get("session_id")) for r in bound]
            # G3 (Loki 6FC22847): accepted_session_id on status.json is now
            # written inside the SAME lock dispatch_accept holds for the
            # session_bind that follows it (see dispatch_accept) -- but a
            # packet's on-disk accepted_session_id can still be the only
            # record of a claim in flight the instant this withdraw wins
            # the lock. Treat a non-empty accepted_session_id as bound even
            # when no session record backs it yet: EBUSY, not a torn
            # "withdrawn packet with a session still coming".
            accepted_session_id = str(pkt.get("status", {}).get("accepted_session_id") or "")
            if accepted_session_id and accepted_session_id not in session_ids:
                # A session record's ABSENCE (not_found) is the narrow
                # accept-race window this exists for -- nothing on disk yet
                # to disprove the claim, so treat it as bound. A session
                # record that DOES exist but is no longer "working" (e.g.
                # "idle", written by session_bind when a seat legitimately
                # releases the packet after a human closeout) means the
                # claim was explicitly released -- this stale
                # accepted_session_id must not resurrect it as bound
                # forever; _sessions_bound_to above already covers the
                # still-working case.
                rec = session_read(pkt["meta"].get("to_app", ""), accepted_session_id)
                if rec.get("error"):
                    session_ids.append(accepted_session_id)
            if session_ids:
                if force and is_orchestrator_app(by_app):
                    forced_over = session_ids
                else:
                    to_app = pkt["meta"].get("to_app")
                    return {
                        "error": "EBUSY",
                        "dispatch_id": did,
                        "status": cur,
                        "sessions": session_ids,
                        "reconcile": [
                            {"tool": "session_reconcile", "app_id": to_app, "session_id": s}
                            for s in session_ids
                        ],
                        "message": (
                            f"{to_app} session(s) {', '.join(session_ids)} still bound "
                            "to this packet as working; liveness beyond the session "
                            "record cannot be known here. Wait for the handoff, "
                            f"reconcile the session(s) (session_reconcile(app_id={to_app!r}, "
                            "session_id=<id>, ...)), or — orchestrator only, for a seat "
                            "that is gone — withdraw with force=True; the forced-over "
                            "sessions are recorded on the packet and in FRANK."
                        ),
                    }
        elif cur != "pending":
            return {"error": "invalid_transition", "from": cur, "to": "withdrawn",
                    "dispatch_id": did}
        extra: dict[str, Any] = {}
        if forced_over:
            extra["forced_over_sessions"] = forced_over
        dispatch_set_status(
            did, "withdrawn",
            withdrawn_at=_utc_now(),
            withdrawn_by=by_app,
            withdraw_reason=reason.strip(),
            already_locked=True,
            **extra,
        )
        out = {"dispatch_id": did, "previous": cur, "status": "withdrawn",
               "to_app": pkt["meta"].get("to_app"), "reason": reason.strip()}
        if forced_over:
            out["forced_over_sessions"] = forced_over
        return out
