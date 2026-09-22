"""willow_mcp.envelope_authoring — propose / ratify / reject / list.

PR5 of the envelope accrual plan. Fills the write-hole in
:mod:`willow_mcp.envelopes`: the registry gate has always been fully shipped
(``EnvelopeAuthority.check``, ``_enveloped_verb_gate``, ``authorize_and_cite``
+ FRANK citations), but until now the ONLY way to add or mutate an entry in
``$WILLOW_HOME/constitutional/pre-approved.json`` was to hand-edit the JSON.
This module makes the ``proposals[]`` slot the constitutional file already
declares (``syscall-table.json:233``: "Agents MAY draft proposals into
``pre-approved.json#proposals``; a proposal has no force until root moves it
to active") an actual runtime surface.

Three primitives, ported straight from Nestor §5.8:

* **propose** = ``memory.add_pair(status="draft")``. An agent writes to
  ``proposals[]`` with no force. Refuses when the calling session isn't
  keyring-attributed — the provenance rail per the plan's Q&A.
* **ratify** = ``memory.seal(...)``. The operator moves a proposal into
  ``active[]``; only the human key can do this (``require_operator_terminal``
  + keyring verifier check).
* **reject** = ``memory.reject_pair(reopen_when=...)``. The "no" is recorded
  with never / not-yet, mirroring the fleet's existing rejection discipline.

Every authoring act appends a FRANK ledger event
(``envelope_proposed`` / ``envelope_ratified`` / ``envelope_rejected``) so
"shapes the operator has said yes to" becomes a queryable ledger walk in
later PRs. Existing ``envelope_citation`` events (uses) are unchanged.

**issued_by="root" preserved.** ``ratify`` writes ``"root"`` when the
operator's verifier passes the keyring check — "root" in willow means "the
human at the terminal with a keyring-registered key," same discipline PR1-4
established for the session-record ``verifier`` field.

**Server verifies, never signs.** Ratify + reject take the operator's
``verifier`` as an arg; the caller (CLI subcommand or MCP tool wrapper) is
responsible for producing it from the local keyring context. This module
does not read the operator's private key material; it only checks that the
supplied verifier exists in the keyring and is not compromised.

**Trusted-read discipline preserved.** Reads go through
:func:`envelopes._load` (which routes through ``paths.trusted_read``); writes
use an atomic rename with prior-content rollback on failure, mirroring the
discipline :func:`sign_session_cli.cmd_sign_session` uses for its sidecar +
sig write.
"""
from __future__ import annotations

import json
import os
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from . import envelopes as _envelopes
from . import human_session as _human_session
from . import keyring as _keyring


# Event types written to the FRANK governance ledger (PR5). Frozen strings —
# every reader that matches them is a wire contract.
FRANK_EVENT_PROPOSED = "envelope_proposed"
FRANK_EVENT_RATIFIED = "envelope_ratified"
FRANK_EVENT_REJECTED = "envelope_rejected"
FRANK_EVENT_REVOKED = "envelope_revoked"


class EnvelopeAuthoringError(Exception):
    """Base class for authoring refusals."""


class UnattributedSessionError(EnvelopeAuthoringError):
    """The calling session is not in the keyring attribution cache. Only
    attributed sessions may propose envelopes — the provenance rail from
    the plan's Q&A: a proposal must always be attributable to the human
    whose work generated the need."""


class UnknownVerbError(EnvelopeAuthoringError):
    """The proposed verb is not in the syscall table."""


class InvalidBoundsSignatureError(EnvelopeAuthoringError):
    """The proposed bounds' keys do not exactly match the verb's declared
    bounds signature. A bounds object that misses a key or carries an extra
    one makes the envelope void, not loosely interpretable (schema §
    envelope_schema.fields.bounds)."""


class ProposalNotFoundError(EnvelopeAuthoringError):
    """No pending proposal with the given id."""


class EnvelopeNotFoundError(EnvelopeAuthoringError):
    """No ACTIVE envelope carries the named id."""


class EnvelopeIdCollisionError(EnvelopeAuthoringError):
    """A generated envelope id collided with an existing entry — retry
    should succeed (uuid4 collision is not a scenario worth solving
    beyond loud refusal)."""


class OperatorVerifierRequired(EnvelopeAuthoringError):
    """Ratify/reject requires an operator verifier known to the keyring
    and not compromised. Same shape ``session_signing.session_is_valid``
    downgrades on: unknown / compromised → refuse."""


class RegistryMismatchError(EnvelopeAuthoringError):
    """``EREGISTRY`` (gap 4c7512c57a7e): the registry this process resolves
    is not the one ``$WILLOW_HOME`` names. An operator act that lands in a
    registry the desk does not read reports "ratified" and changes nothing
    the desk can see — the proposal stays ``proposed`` on the broker and the
    seat ratifies again on the operator's word. Refused before any write;
    ``detail`` names both paths and the env that steered the resolve."""

    def __init__(self, message: str, detail: dict):
        super().__init__(message)
        self.detail = detail


# ---------------------------------------------------------------------------
# Registry identity — which file is in effect, and is it the home's own
# ---------------------------------------------------------------------------


def registry_identity(path: Optional[Path] = None) -> dict:
    """``{path, fingerprint, exists, mtime, active, proposals}`` for the
    registry in effect (or ``path``). ``fingerprint`` is the sha256 of the
    ACTIVE register's own file bytes, 16 hex — enough for two readers to
    agree they are looking at the same file, which is the question the desk
    asks when an operator says "ratified" and the queue has not moved.
    Read-only; counts come from a plain ``json.loads`` so a registry the
    trusted-read gate would refuse still gets a fingerprint (the gate's own
    refusal is unchanged elsewhere).

    ``proposals`` (pair 31f5d3af: proposals[] now lives in the broker-owned
    sidecar, :func:`_proposals_path`, never the active register itself) is
    read from that sidecar — a missing sidecar (no proposal ever queued
    yet) counts as zero, not unreadable; only the ACTIVE file's own
    fingerprint/exists/mtime speak to whether the identity check as a whole
    succeeded, since that is the file whose trust root actually matters
    here."""
    import hashlib
    p = path if path is not None else _envelopes.registry_path()
    out: dict[str, Any] = {"path": str(p), "fingerprint": None, "exists": False,
                           "mtime": None, "active": None, "proposals": None}
    try:
        raw = p.read_bytes()
    except OSError:
        return out
    out["exists"] = True
    out["fingerprint"] = hashlib.sha256(raw).hexdigest()[:16]
    try:
        out["mtime"] = (
            datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc)
            .replace(microsecond=0).isoformat().replace("+00:00", "Z")
        )
    except OSError:
        pass
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return out
    if isinstance(doc, dict):
        out["active"] = len(doc.get("active") or [])
        # Legacy pre-split file (never migrated) may still carry proposals
        # inline — read it if present, else fall through to the sidecar.
        out["proposals"] = len(doc.get("proposals") or [])
    prop_path = p.with_name("proposals.json")
    try:
        prop_raw = prop_path.read_bytes()
        prop_doc = json.loads(prop_raw.decode("utf-8"))
        if isinstance(prop_doc, dict):
            out["proposals"] = len(prop_doc.get("proposals") or [])
    except (OSError, ValueError, UnicodeDecodeError):
        pass
    return out


def _same_file(a: Path, b: Path) -> bool:
    try:
        return os.path.realpath(a) == os.path.realpath(b)
    except OSError:
        return False


def registry_mismatch() -> Optional[dict]:
    """``None`` when the registry in effect is ``$WILLOW_HOME/constitutional/
    pre-approved.json``; otherwise the ``EREGISTRY`` detail: ``resolved``,
    ``expected``, ``steered_by`` (the env var that moved the resolve — or
    the absence of ``WILLOW_HOME``, which lands the implicit ``~/.willow``
    default), and a ``message`` that names all three.

    The home's own registry is the one every reader on the box — the desk,
    the serve broker, ``home_init``'s seed — reads by default. A ratify
    that goes anywhere else is an act the desk cannot see."""
    from . import paths as _paths
    resolved = _envelopes.registry_path()
    home_env = (os.environ.get("WILLOW_HOME") or "").strip()
    try:
        expected: Optional[Path] = _paths.willow_home() / "constitutional" / "pre-approved.json"
    except _paths.RetiredHomeError as exc:
        return {
            "error": "EREGISTRY",
            "resolved": str(resolved),
            "expected": None,
            "steered_by": "WILLOW_HOME unset (implicit ~/.willow default, retired)",
            "message": (
                f"EREGISTRY: registry resolved to {resolved} with WILLOW_HOME unset; "
                f"the implicit home is retired ({exc}). Set WILLOW_HOME to the live "
                "home before ratifying."
            ),
        }
    if expected is not None and _same_file(resolved, expected):
        return None
    if (os.environ.get("WILLOW_ENVELOPE_REGISTRY") or "").strip():
        steered_by = "WILLOW_ENVELOPE_REGISTRY"
    elif (os.environ.get("WILLOW_CHARTER_REPO") or "").strip():
        steered_by = "WILLOW_CHARTER_REPO"
    elif not home_env:
        steered_by = "WILLOW_HOME unset (implicit ~/.willow default)"
    else:
        steered_by = "unknown"
    return {
        "error": "EREGISTRY",
        "resolved": str(resolved),
        "expected": str(expected),
        "steered_by": steered_by,
        "message": (
            f"EREGISTRY: this process resolves the envelope registry to {resolved} "
            f"(steered by {steered_by}), but $WILLOW_HOME names {expected}. An "
            "operator act written to the former is invisible to every reader of "
            "the latter — refused before any write. Unset the steering env or "
            "point WILLOW_HOME at the home whose registry you mean."
        ),
    }


def _refuse_registry_mismatch(act: str) -> None:
    detail = registry_mismatch()
    if detail is not None:
        raise RegistryMismatchError(f"{act} refused — {detail['message']}", detail)


# ---------------------------------------------------------------------------
# Registry read/write helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _proposals_path() -> Path:
    """Sealed pair 31f5d3af (2026-09-22): the active register
    (``pre-approved.json``) and the proposal queue are two different trust
    boundaries, not one file with two views. ``proposals[]``/``archived[]``
    live in this sibling file instead — broker-owned (0600, the same uid
    that has always run the broker), never signed, never requiring
    trust-owner ownership. The broker writes it directly, exactly as it
    always wrote the combined file before this split."""
    return _envelopes.registry_path().with_name("proposals.json")


def _load_registry() -> dict:
    """Read the current registry as a MERGED VIEW: ``active`` from the
    (now possibly trust-owner-owned, signed) active register
    (:func:`envelopes.registry_path`); ``proposals``/``archived`` from the
    broker-owned sidecar (:func:`_proposals_path`, pair 31f5d3af). Every
    reader below (propose/ratify/reject/list_*) keeps operating on the one
    shape it always has; only this function and :func:`_save_registry`
    know the file is actually split in two. Both routed through
    :func:`envelopes._load`, which itself routes through
    ``paths.trusted_read`` — a writable/symlinked/unsigned-when-required
    source is a forged-envelope vector and the read refuses it."""
    active_doc = _envelopes._load(_envelopes.registry_path())
    proposals_path = _proposals_path()
    proposals_doc = _envelopes._load(proposals_path) if proposals_path.is_file() else {}
    return {
        "active": active_doc.get("active") or [],
        "proposals": proposals_doc.get("proposals") or [],
        "archived": proposals_doc.get("archived") or [],
    }


def _maybe_sign(path: Path) -> None:
    """Re-sign ``path`` under ``WILLOW_PGP_FINGERPRINT`` when PGP is
    enforced — the active register's own trust shape after pair 31f5d3af:
    ``trusted_read``'s trust-owner branch refuses a trust-owner-owned file
    whose detached signature does not verify, so a write that lands
    unsigned (or signed under the wrong key) is unreadable to every OTHER
    process on the box even though it wrote successfully here. Never
    called for the broker-owned proposals sidecar, which stays on the
    euid-ownership trust rail exactly as the whole registry did before
    this split."""
    from . import pgp

    if not pgp.pgp_enabled():
        return
    ok, detail = pgp.sign_detached(path)
    if not ok:
        raise EnvelopeAuthoringError(
            f"{path} was written but could not be re-signed under "
            f"WILLOW_PGP_FINGERPRINT ({detail}) — the write already landed; "
            "every other reader will refuse it as unsigned until this is fixed"
        )


def _save_registry(registry: dict) -> None:
    """Split write, the counterpart to :func:`_load_registry`'s merged
    read: ``active`` to the (signed) active register, ``proposals``/
    ``archived`` to the broker-owned sidecar. Two atomic writes, not one —
    a crash between them is a legitimate half-state under the sealed
    shape, the same way a crash between two independently-owned files
    always is; there is no single-file transaction to preserve here
    anymore. Every call site that used to hand the whole merged dict to
    ``_atomic_write(envelopes.registry_path(), registry)`` now calls this
    instead."""
    _atomic_write(_envelopes.registry_path(), {"active": registry.get("active") or []})
    _maybe_sign(_envelopes.registry_path())
    _atomic_write(_proposals_path(), {
        "proposals": registry.get("proposals") or [],
        "archived": registry.get("archived") or [],
    })


def _load_syscall_table() -> dict[int, dict]:
    """Verbs by id."""
    table = _envelopes._load(_envelopes.syscall_path())
    return {
        int(row["id"]): row
        for row in table.get("verbs") or []
        if isinstance(row, dict) and isinstance(row.get("id"), int)
    }


def _atomic_write(path: Path, doc: dict) -> None:
    """Write ``doc`` atomically. Mirrors ``sign_session_cli``'s discipline:
    write to a tmp file, replace atomically, so a mid-flight failure never
    leaves the registry half-written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    # paths.trusted_read fail-closed refuses a group/other-writable source
    # (mode & 0o022) — the umask-derived mode open() leaves on tmp (typically
    # 664) trips that on the very next read. Strip those bits before the
    # atomic rename so a fresh write never re-triggers the guard it's meant
    # to satisfy.
    os.chmod(tmp, stat.S_IMODE(os.stat(tmp).st_mode) & ~0o022)
    os.replace(tmp, path)


def _find_verb(verb: str, verbs_by_id: dict[int, dict]) -> tuple[int, dict]:
    for vid, row in verbs_by_id.items():
        if row.get("verb") == verb:
            return vid, row
    raise UnknownVerbError(
        f"verb {verb!r} is not in the syscall table (verbs known: "
        f"{sorted(row.get('verb', '?') for row in verbs_by_id.values())})"
    )


def _validate_bounds_signature(verb: str, bounds: dict, verbs_by_id: dict[int, dict]) -> int:
    """Return the verb_id when bounds match the verb's declared signature;
    raise :class:`InvalidBoundsSignatureError` otherwise. Same equality shape
    :meth:`envelopes.EnvelopeAuthority.check` enforces post-ratification —
    catching the mismatch at propose-time so the operator never sees an
    envelope in the queue that will refuse the moment they ratify it."""
    verb_id, spec = _find_verb(verb, verbs_by_id)
    expected = set((spec.get("bounds") or {}).keys())
    # Registry v1.1 hoists metering fields from older verb rows.
    expected -= {"max_count", "expires_at"}
    got = set(bounds.keys())
    if expected != got:
        raise InvalidBoundsSignatureError(
            f"bounds signature mismatch for verb {verb!r}: "
            f"expected keys {sorted(expected)}, got {sorted(got)}. "
            "A bounds object that misses a key or carries an extra one makes "
            "the envelope void, not loosely interpretable."
        )
    return verb_id


def _keyring_verifier_active(verifier: str) -> bool:
    """True iff ``verifier`` is registered in the keyring and not
    compromised. Empty or unknown → False. Same downgrade shape
    :func:`session_signing.session_is_valid` uses: caller gets a bool, the
    refusal decision is upstream."""
    if not verifier:
        return False
    ring = _keyring.get_keyring()
    if ring is None:
        return False
    return ring.verifying_entry(verifier) is not None


# ---------------------------------------------------------------------------
# The five primitives
# ---------------------------------------------------------------------------


def propose(
    *,
    verb: str,
    grantee: str,
    bounds: dict,
    reason: str,
    verifier: str,
    session_id: str,
    expires_at: Optional[str] = None,
    max_count: Optional[int] = None,
    precedent_ids: Optional[Iterable[str]] = None,
    ledger: Optional[Any] = None,
    orchestrator_session_id: Optional[str] = None,
    proposer_app_id: str = "",
) -> dict:
    """Write an envelope proposal into ``pre-approved.json#proposals[]``.

    Attribution-gated: refuses when the calling session is not in
    :data:`human_session._attributed_sessions`. That's the provenance rail
    from the plan — every proposal is tied to the human whose work generated
    the need. Unattributed callers cannot cause a proposal to appear.

    Returns the proposal row as it was written (includes generated ``id``
    and ``proposed_at``). Appends an ``envelope_proposed`` event to the
    FRANK ledger when one is available; ledger-write failure is reported in
    the returned dict but does not roll back the sidecar write (mirrors the
    discipline sign-session uses for its ledger append).

    Deliberately NOT guarded by ``EREGISTRY`` (:func:`registry_mismatch`):
    a proposal has no force wherever it lands, and a specialist's
    auto-propose on a gate miss must be able to queue into whatever registry
    its process resolves — a steered resolve costs nothing here. The guard
    sits on the operator acts (ratify / reject / revoke), where a write to
    the wrong file is a "ratified" the desk cannot see (gap 4c7512c57a7e).
    """
    if _keyring.enabled():
        # Attribution rail is active. Every gate below is inside the
        # keyring-enabled branch — a deployment with no keyring stays on
        # the pre-PR5 shape (which is "hand-edit the JSON," so propose()
        # is not a path they use).
        if not verifier:
            raise UnattributedSessionError(
                "envelope_propose requires a verifier — the human whose "
                "session this proposal is attributed to. Attributed "
                "sessions carry a verifier on their session record; an "
                "unattested willow session cannot propose."
            )
        if not _keyring_verifier_active(verifier):
            raise UnattributedSessionError(
                f"verifier {verifier!r} is unknown to the keyring or has "
                "been revoked as compromised. Propose refuses rather than "
                "letting an untrusted claim into the queue."
            )
        if not session_id or not _human_session.is_session_attributed(session_id):
            raise UnattributedSessionError(
                f"session {session_id!r} is not in the attribution cache. "
                "The proposal must come from a session that carried a "
                "valid signature at session_enter time — see "
                "docs/design/identity-in-session.md (PR4) for the cache "
                "lifecycle."
            )

    verbs_by_id = _load_syscall_table()
    verb_id = _validate_bounds_signature(verb, bounds, verbs_by_id)

    registry = _load_registry()
    proposals = list(registry.get("proposals") or [])
    active = list(registry.get("active") or [])

    proposal_id = f"env-{verb}-{uuid.uuid4().hex[:12]}"
    if any(row.get("id") == proposal_id for row in proposals + active):
        raise EnvelopeIdCollisionError(
            f"generated id {proposal_id!r} already exists — retry"
        )

    # PR7: precedent recall. If the caller didn't supply precedent_ids
    # explicitly, ask envelope_shapes for the top matches against
    # currently-active envelopes for this (verb, grantee, bounds) shape.
    # An import-guarded call — if envelope_shapes ever needs an optional
    # dep this module doesn't want to pull in, propose still works.
    resolved_precedents: list[str]
    if precedent_ids is None:
        try:
            from . import envelope_shapes as _es
            resolved_precedents = _es.top_precedent_ids(
                verb, grantee, bounds
            )
        except Exception:
            # Precedent recall failing must never block propose — the
            # operator can still ratify from scratch. Log to no-op and
            # move on.
            resolved_precedents = []
    else:
        resolved_precedents = list(precedent_ids)

    row = {
        "id": proposal_id,
        "verb_id": verb_id,
        "verb": verb,
        "grantee": grantee,
        "bounds": bounds,
        "issued_by": "",  # unset until ratify — "root" is a keyring-verified act
        "issued_at": "",
        "ratified_via": "",
        "expires_at": expires_at,
        "max_count": max_count,
        "use_count_source": "frank",
        "status": "proposed",
        "notes": reason,
        # Fields added by PR5 for the accrual loop
        "proposed_at": _now_iso(),
        "proposed_by": {
            "verifier": verifier,
            "session_id": session_id,
            "orchestrator_session_id": orchestrator_session_id or session_id,
            "proposer_app_id": proposer_app_id,
        },
        "precedent_ids": resolved_precedents,
    }
    proposals.append(row)
    registry["proposals"] = proposals
    _save_registry(registry)

    ledger_record_id = None
    ledger_error = None
    if ledger is not None:
        try:
            ledger_record_id = ledger.append(
                proposer_app_id or "willow",
                FRANK_EVENT_PROPOSED,
                {
                    "envelope_id": proposal_id,
                    "verb": verb,
                    "verb_id": verb_id,
                    "grantee": grantee,
                    "bounds_digest": _bounds_digest(bounds),
                    "verifier": verifier,
                    "orchestrator_session_id": orchestrator_session_id or session_id,
                    "proposer_app_id": proposer_app_id,
                    "precedent_ids": row["precedent_ids"],
                    "proposed_at": row["proposed_at"],
                },
            )
        except Exception as exc:  # pragma: no cover — ledger is optional
            ledger_error = str(exc)

    result = dict(row)
    result["_ledger_record_id"] = ledger_record_id
    if ledger_error:
        result["_ledger_error"] = ledger_error
    return result


def ratify(
    proposal_id: str,
    *,
    verifier: str,
    ledger: Optional[Any] = None,
) -> dict:
    """Move a proposal from ``proposals[]`` to ``active[]``. The operator's
    keyring-verified act. ``issued_by`` is stamped as ``"root"`` per schema
    (invariant preserved from the pre-PR5 shape).

    The caller (CLI subcommand or MCP tool) is responsible for wrapping this
    in :func:`human_session.require_operator_terminal` — this module does not
    reach for the tty; a lone unit test that constructs a valid verifier +
    keyring is a legitimate caller.

    Returns the ratified envelope row. Appends ``envelope_ratified`` to the
    FRANK ledger when one is available.
    """
    if not _keyring_verifier_active(verifier):
        raise OperatorVerifierRequired(
            f"ratify requires an operator verifier known to the keyring "
            f"and not compromised; got {verifier!r}."
        )
    _refuse_registry_mismatch("ratify")

    registry = _load_registry()
    proposals = list(registry.get("proposals") or [])
    active = list(registry.get("active") or [])
    matches = [row for row in proposals if row.get("id") == proposal_id]
    if not matches:
        raise ProposalNotFoundError(
            f"no pending proposal with id {proposal_id!r}"
        )
    proposal = matches[0]
    proposals = [row for row in proposals if row.get("id") != proposal_id]

    ratified_at = _now_iso()
    ratified: dict = {
        **{k: v for k, v in proposal.items() if not k.startswith("_")},
        "issued_by": "root",
        "issued_at": ratified_at,
        "status": "active",
    }

    ledger_record_id = None
    ledger_error = None
    if ledger is not None:
        try:
            ledger_record_id = ledger.append(
                "willow",
                FRANK_EVENT_RATIFIED,
                {
                    "envelope_id": proposal_id,
                    "verb": proposal["verb"],
                    "verb_id": proposal["verb_id"],
                    "grantee": proposal["grantee"],
                    "bounds_digest": _bounds_digest(proposal["bounds"]),
                    "verifier": verifier,
                    "ratified_at": ratified_at,
                },
            )
        except Exception as exc:  # pragma: no cover — ledger is optional
            ledger_error = str(exc)

    ratified["ratified_via"] = (
        f"frank ledger entry {ledger_record_id}" if ledger_record_id
        else f"keyring verifier {verifier}"
    )
    active.append(ratified)
    registry["proposals"] = proposals
    registry["active"] = active
    _save_registry(registry)

    result = dict(ratified)
    result["_ledger_record_id"] = ledger_record_id
    if ledger_error:
        result["_ledger_error"] = ledger_error
    return result


def reject(
    proposal_id: str,
    *,
    reason: str,
    verifier: str,
    reopen_when: str = "",
    ledger: Optional[Any] = None,
) -> dict:
    """Record a "no" on a proposal. Same keyring guard as :func:`ratify`.

    ``reopen_when`` distinguishes NEVER (empty) from NOT YET (non-empty),
    mirroring :func:`nestor.memory.reject_match`'s policy. A reader that
    surfaces rejections should show non-empty ``reopen_when`` as a condition
    to re-check, not a closed door.

    PR11 (envelope-accrual, archived state): the rejected row does not
    vanish — it moves to the registry's ``archived[]`` list with
    ``status="rejected"``, its bounds intact, and the ``reason`` /
    ``reopen_when`` / ``verifier`` fields preserved. This is what lets
    :func:`envelope_shapes.similar_precedents` count "the operator's
    no with a reopen condition" as a precedent alongside their yeses —
    the same signal Nestor's ``reject_match`` surfaces. Registry growth
    is a real long-run cost; compaction is left for a later PR when
    the archived list actually gets large enough to matter.

    Returns ``{proposal_id, verifier, rejected_at, reason, reopen_when}`` and
    appends ``envelope_rejected`` to the FRANK ledger when one is available.
    """
    if not _keyring_verifier_active(verifier):
        raise OperatorVerifierRequired(
            f"reject requires an operator verifier known to the keyring "
            f"and not compromised; got {verifier!r}."
        )
    _refuse_registry_mismatch("reject")

    registry = _load_registry()
    proposals = list(registry.get("proposals") or [])
    matches = [row for row in proposals if row.get("id") == proposal_id]
    if not matches:
        raise ProposalNotFoundError(
            f"no pending proposal with id {proposal_id!r}"
        )
    proposal = matches[0]
    proposals = [row for row in proposals if row.get("id") != proposal_id]

    rejected_at = _now_iso()
    # PR11: archive the rejected row instead of dropping. Bounds + polarity
    # + reopen_when carry into the precedent walk. The operator's decision
    # (yes AND no) is what accrues, not just the ratified subset.
    archived = list(registry.get("archived") or [])
    archived.append({
        **{k: v for k, v in proposal.items() if not k.startswith("_")},
        "status": "rejected",
        "archived_at": rejected_at,
        "rejected_at": rejected_at,
        "reject_reason": reason,
        "reopen_when": reopen_when,
        "rejected_by": verifier,
    })
    registry["proposals"] = proposals
    registry["archived"] = archived
    _save_registry(registry)

    ledger_record_id = None
    ledger_error = None
    if ledger is not None:
        try:
            ledger_record_id = ledger.append(
                "willow",
                FRANK_EVENT_REJECTED,
                {
                    "proposal_id": proposal_id,
                    "verb": proposal["verb"],
                    "grantee": proposal["grantee"],
                    "bounds_digest": _bounds_digest(proposal["bounds"]),
                    "verifier": verifier,
                    "reason": reason,
                    "reopen_when": reopen_when,
                    "rejected_at": rejected_at,
                },
            )
        except Exception as exc:  # pragma: no cover — ledger is optional
            ledger_error = str(exc)

    result = {
        "proposal_id": proposal_id,
        "verifier": verifier,
        "reason": reason,
        "reopen_when": reopen_when,
        "rejected_at": rejected_at,
        "_ledger_record_id": ledger_record_id,
    }
    if ledger_error:
        result["_ledger_error"] = ledger_error
    return result


def list_active(
    *, grantee: Optional[str] = None, verb: Optional[str] = None
) -> list[dict]:
    """Currently active envelopes, filterable by grantee and/or verb.
    Read-only.

    "Active" means what the GATE means by it: a row in ``active[]`` that is
    not revoked and whose ``status`` is ``"active"`` — the same predicate
    ``envelopes.usable_active_grants`` applies. Membership of ``active[]``
    alone is not enough. A revoked envelope stays in that list on purpose
    (the register keeps the history of what was granted and withdrawn), and
    listing it here reported grants as in force that the gate would refuse —
    the surface an operator reads disagreeing with the surface that enforces.
    Use :func:`list_revoked` to see what was withdrawn."""
    registry = _load_registry()
    rows = [row for row in (registry.get("active") or []) if not _is_revoked(row)]
    if grantee is not None:
        rows = [row for row in rows if _grantee_matches(row.get("grantee"), grantee)]
    if verb is not None:
        rows = [row for row in rows if row.get("verb") == verb]
    return list(rows)


def _is_revoked(row: dict) -> bool:
    """The gate's own predicate (``envelopes.py`` line ~198), one place."""
    return bool(row.get("revoked")) or row.get("status") == "revoked"


def list_revoked(
    *, grantee: Optional[str] = None, verb: Optional[str] = None
) -> list[dict]:
    """Envelopes that were granted and later withdrawn. Read-only.

    These rows stay in ``active[]`` rather than moving to ``archived[]``: an
    envelope that was in force and was withdrawn is a different fact from a
    proposal that was never granted, and the register should be able to say
    which happened."""
    registry = _load_registry()
    rows = [row for row in (registry.get("active") or []) if _is_revoked(row)]
    if grantee is not None:
        rows = [row for row in rows if _grantee_matches(row.get("grantee"), grantee)]
    if verb is not None:
        rows = [row for row in rows if row.get("verb") == verb]
    return list(rows)


def revoke(
    envelope_id: str,
    *,
    verifier: str,
    reason: str,
    ledger=None,
) -> dict:
    """Withdraw an ACTIVE envelope. Operator act, CLI only.

    Until this existed, revocation was a state the system could read and not
    produce: the gate honours ``revoked``/``status == "revoked"``
    (``envelopes.py``), no code path ever set either, and ``envelope reject``
    acts on pending PROPOSALS. Withdrawing a live grant therefore meant
    hand-editing ``constitutional/pre-approved.json`` — the trust root — which
    is the act the envelope programme exists to keep hands off.

    The row is marked in place and KEPT, never deleted: the register's value
    is that it records what was granted AND what was taken back, and a
    disappeared grant cannot be audited. ``bounds`` and ``ratified_via``
    survive intact so the row still scores as a precedent.

    Deliberately NOT an MCP tool, for the same reason ``frank-anchor`` is
    CLI-only: an agent must not be able to withdraw the grants that bound it,
    nor a peer's. Narrowing authority is safer than widening it, but a seat
    that can revoke can also deny — it could strip another agent's dispatch
    grant and stall the fleet. Revocation is an operator act, and the
    keyring check below is what makes "operator" mean something.

    Returns ``{envelope_id, verifier, revoked_at, reason}`` and appends
    ``envelope_revoked`` to FRANK when a ledger is available.
    """
    if not _keyring_verifier_active(verifier):
        raise OperatorVerifierRequired(
            f"revoke requires an operator verifier known to the keyring "
            f"and not compromised; got {verifier!r}."
        )
    if not (reason or "").strip():
        # A withdrawn grant with no stated reason is the thing a later reader
        # cannot act on: they can see the authority is gone and not whether
        # it was redundant, mistaken, or abused.
        raise EnvelopeAuthoringError("revoke requires a reason")
    _refuse_registry_mismatch("revoke")

    registry = _load_registry()
    rows = registry.get("active") or []
    matches = [row for row in rows if row.get("id") == envelope_id]
    if not matches:
        raise EnvelopeNotFoundError(f"no envelope with id {envelope_id!r}")
    row = matches[0]
    if _is_revoked(row):
        raise EnvelopeAuthoringError(
            f"envelope {envelope_id!r} is already revoked "
            f"(at {row.get('revoked_at') or 'unknown time'})")

    revoked_at = _now_iso()
    row["status"] = "revoked"
    row["revoked"] = True
    row["revoked_at"] = revoked_at
    row["revoked_by"] = verifier
    row["revoked_reason"] = reason
    _save_registry(registry)

    ledger_record_id = None
    ledger_error = None
    if ledger is not None:
        try:
            ledger_record_id = ledger.append(
                "willow",
                FRANK_EVENT_REVOKED,
                {
                    "envelope_id": envelope_id,
                    "verb": row.get("verb"),
                    "grantee": row.get("grantee"),
                    "bounds_digest": _bounds_digest(row.get("bounds") or {}),
                    "ratified_via": row.get("ratified_via"),
                    "revoked_by": verifier,
                    "revoked_at": revoked_at,
                    "reason": reason,
                },
            )
        except Exception as exc:                      # ledger down != act undone
            ledger_error = str(exc)
    return {
        "envelope_id": envelope_id,
        "verifier": verifier,
        "revoked_at": revoked_at,
        "reason": reason,
        "ledger_record_id": ledger_record_id,
        "ledger_error": ledger_error,
    }


def list_archived(
    *,
    grantee: Optional[str] = None,
    verb: Optional[str] = None,
    status: Optional[str] = None,
) -> list[dict]:
    """Envelope rows the operator has archived — today, rejected
    proposals moved by :func:`reject` (PR11). Filterable by grantee,
    verb, and status. Read-only.

    Bounds and reopen_when carry through so a caller can score archived
    rows as precedents (see :func:`envelope_shapes.similar_precedents`
    with ``include_archived=True``). The ``status`` filter is opt-in —
    absent, all archived rows come back regardless of why they were
    archived (rejected today; superseded / revoked in future PRs)."""
    registry = _load_registry()
    rows = list(registry.get("archived") or [])
    if grantee is not None:
        rows = [row for row in rows if _grantee_matches(row.get("grantee"), grantee)]
    if verb is not None:
        rows = [row for row in rows if row.get("verb") == verb]
    if status is not None:
        rows = [row for row in rows if row.get("status") == status]
    return rows


def list_pending(
    *,
    oldest_first: bool = True,
    limit: int = 50,
    include_precedents: bool = True,
) -> list[dict]:
    """Proposals awaiting ratification. Operator's queue view.

    Sorted by ``proposed_at`` (oldest first by default so the operator sees
    the longest-waiting proposals at the top). Bounded by ``limit`` — the
    queue can grow; a paginated read is safer than an unbounded one.

    When ``include_precedents`` is True (the default; PR10), each row gets
    a ``precedents_expanded`` field: for every id in ``precedent_ids``
    that still resolves to a currently-active envelope, the full envelope
    row is inlined so the operator can see WHAT they'd be reaffirming
    without a second lookup. IDs that no longer resolve (envelope was
    revoked, registry was edited by hand) are silently dropped from the
    expansion — the id itself stays in ``precedent_ids`` as tamper
    evidence but the operator's ratify surface reflects only what's
    actually still on record. Empty list on a row with no precedents.
    """
    registry = _load_registry()
    rows = list(registry.get("proposals") or [])
    rows.sort(key=lambda r: r.get("proposed_at") or "", reverse=not oldest_first)
    rows = rows[: max(0, int(limit))]
    if not include_precedents:
        return rows
    # Build one lookup so N pending × M precedents is O(N+M+A) rather than
    # O(N × M × A). Active + archived are small in practice; still worth
    # the loop. Active wins ties (an id present in both — shouldn't happen,
    # but active is the current state, so it's the truth if it does).
    active_by_id = {
        row.get("id"): row for row in (registry.get("active") or [])
        if row.get("id")
    }
    archived_by_id = {
        row.get("id"): row for row in (registry.get("archived") or [])
        if row.get("id") and row.get("id") not in active_by_id
    }
    enriched = []
    for row in rows:
        row = dict(row)
        expanded = []
        for pid in row.get("precedent_ids") or []:
            hit = active_by_id.get(pid)
            if hit is not None:
                expanded.append({**hit, "precedent_status": "active"})
                continue
            hit = archived_by_id.get(pid)
            if hit is not None:
                # PR11: an archived precedent — most often the operator's
                # "no with reopen_when" from a prior session. Same shape,
                # different polarity. The `precedent_status` field is
                # what tells the ratify surface how to render it.
                expanded.append({
                    **hit,
                    "precedent_status": hit.get("status") or "archived",
                })
        row["precedents_expanded"] = expanded
        enriched.append(row)
    return enriched


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _grantee_matches(row_grantee, query: str) -> bool:
    """Loose match: the registry row's grantee can be a string or a list of
    strings; the caller's query is a plain string. Returns True on exact
    equality or list-membership."""
    if isinstance(row_grantee, str):
        return row_grantee == query
    if isinstance(row_grantee, (list, tuple)):
        return query in row_grantee
    return False


def _bounds_digest(bounds: dict) -> str:
    """SHA-256 of the bounds' canonical JSON. Used as the tamper-evident
    key for the FRANK envelope events — a proposal whose bounds are edited
    out-of-band after propose but before ratify has a different digest,
    which ratify can catch by re-computing.

    Deterministic encoding (same discipline as ``session_signing._message``):
    ``json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)``.
    """
    import hashlib

    payload = json.dumps(
        bounds, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
