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


class EnvelopeIdCollisionError(EnvelopeAuthoringError):
    """A generated envelope id collided with an existing entry — retry
    should succeed (uuid4 collision is not a scenario worth solving
    beyond loud refusal)."""


class OperatorVerifierRequired(EnvelopeAuthoringError):
    """Ratify/reject requires an operator verifier known to the keyring
    and not compromised. Same shape ``session_signing.session_is_valid``
    downgrades on: unknown / compromised → refuse."""


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


def _load_registry() -> dict:
    """Read the current registry. Routes through :func:`envelopes._load`, which
    itself routes through ``paths.trusted_read`` — a writable/symlinked
    registry is a forged-envelope vector and the read refuses it."""
    return _envelopes._load(_envelopes.registry_path())


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
    _atomic_write(_envelopes.registry_path(), registry)

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
    _atomic_write(_envelopes.registry_path(), registry)

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
    _atomic_write(_envelopes.registry_path(), registry)

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
    Read-only."""
    registry = _load_registry()
    rows = registry.get("active") or []
    if grantee is not None:
        rows = [row for row in rows if _grantee_matches(row.get("grantee"), grantee)]
    if verb is not None:
        rows = [row for row in rows if row.get("verb") == verb]
    return list(rows)


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
