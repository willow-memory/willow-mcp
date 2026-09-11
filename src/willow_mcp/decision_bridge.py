"""decision_bridge.py — the propose half of the nestor-propose-bridge gap.

Closes a hole next to the one ``seal_handler.py`` documents: a governance
decision can be *recorded* in SOIL (``store_put`` into
``projects_willow_governance_decisions``) but until now there was no
in-process/MCP path to *propose* it as a draft in the vault's Nestor
database — the only way was shelling out to Nestor's own venv, by hand,
outside any tool the fleet can call. Worse, doing that by hand never
stamped the SOIL record with the resulting ``pair_id``, so
``seal_handler.on_seal``'s ``nestor_pair_id == pair_id`` correlation
(see that module's docstring) had nothing to match: a decision recorded
and a draft proposed separately never converge, and a seal silently
upgrades nothing.

``propose()`` is the missing middle step:

    store_put (record a decision)
      -> decision_propose (this module: draft it in Nestor, stamp the
         SOIL record with the new pair_id)
      -> a human seals the draft in Nestor (out of band — this module
         never signs)
      -> seal_daemon tails the ledger, calls seal_handler.on_seal
      -> on_seal finds the SOIL record by nestor_pair_id and upgrades it

Propose != seal, on purpose. ``nestor.decision.DecisionMemory.propose``
is explicitly "the one write a model may make; it confirms nothing" —
it lands an unsigned draft. This module never seals: sealing requires a
human's own key (``DecisionMemory.seal`` takes a ``seal_sig`` this
process cannot produce), so the sudo invariant this fleet runs on
(a machine may propose, only a human may ratify) holds all the way
through this bridge.

Same soft-seam discipline as ``tool_oracle.py``: Nestor is an OPTIONAL
dependency (the ``nestor`` extra), imported lazily, and its absence
degrades to ``{"error": "nestor_unavailable"}`` rather than an import
failure.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from . import seal_handler
from .db import Store

logger = logging.getLogger(__name__)

#: Same collection seal_handler reads/upgrades — re-exported here so callers
#: (and tests) have one name to import regardless of which module they start
#: from.
GOVERNANCE_COLLECTION = seal_handler.GOVERNANCE_COLLECTION

# ── soft Nestor seam (tool_oracle.py's pattern) ──────────────────────────────
_NESTOR = None
_TRIED = False


def _nestor():
    """(DecisionMemory, SqliteStore, ConflictingDraftError) or None. Imported
    once and cached."""
    global _NESTOR, _TRIED
    if not _TRIED:
        _TRIED = True
        try:
            from nestor.decision import DecisionMemory
            from nestor.sqlite_store import SqliteStore
            from nestor.memory import ConflictingDraftError
            _NESTOR = (DecisionMemory, SqliteStore, ConflictingDraftError)
        except ImportError:
            _NESTOR = None
    return _NESTOR


def available() -> bool:
    """Whether the Nestor engine is installed (propose is live)."""
    return _nestor() is not None


def propose(app_id: str, record_id: str, question: str = "", conclusion: str = "",
            rationale: str = "", origin: str = "", *,
            store: Optional[Store] = None,
            db_path: Optional[Path] = None) -> dict:
    """Propose a SOIL governance record as a draft decision in Nestor.

    Loads ``record_id`` from ``GOVERNANCE_COLLECTION``, and:

      - {"error": "record_not_found"} if it doesn't exist.
      - {"pair_id", "record_id", "status": "already_linked"} without touching
        Nestor if the record already carries a non-empty ``nestor_pair_id``
        (idempotency — a retried propose call must never mint a second draft).
      - {"error": "nestor_unavailable"} if the optional Nestor engine isn't
        installed.
      - {"error": "title_collision", ...} if this record's (question, i.e.
        normalized title) already names a DIFFERENT draft or sealed pair in
        Nestor — see the "one draft per source_text" note below. Never
        stamped, never a raw exception.
      - otherwise, proposes a draft (question/conclusion/rationale/origin
        default from the record's title/ruling/rationale when the argument is
        empty; an explicit argument always overrides), stamps the record's
        ``nestor_pair_id`` with the new draft's id so ``seal_handler.on_seal``
        can later correlate a seal back to this record, and returns
        {"pair_id", "record_id", "status": "draft"}.

    Nestor keys a pair by ``normalize(question)`` within (source_lang,
    target_lang) — one row per distinct question, not per caller. Two SOIL
    records that happen to share a title therefore name the SAME Nestor row,
    and ``DecisionMemory.propose``/``add_pair`` handles that collision two
    different ways depending on what the second call asks for:

      - a DIFFERENT conclusion than the row already holds raises
        ``ConflictingDraftError`` — caught here and turned into a clean
        ``title_collision`` error rather than an uncaught traceback.
      - the SAME conclusion (or a title that already names a SEALED pair
        with a different conclusion, which ``add_pair`` also returns as-is
        rather than raising) hands back the EXISTING row with no exception —
        indistinguishable from success unless the caller checks it. Left
        unchecked, this record would get stamped with a pair_id another SOIL
        record already owns, and ``seal_handler.on_seal`` would only ever
        upgrade whichever record ``store.all`` happens to list first
        (``_find_governance_record`` returns on the first match), leaving
        the other one silently un-sealable forever. Checked here two ways:
        the returned pair's target_text must equal the conclusion this call
        asked for, and its id must not already be some OTHER record's
        ``nestor_pair_id``. Either mismatch is also ``title_collision``, and
        this record is never stamped.

    A ``title_collision`` is the caller's to resolve — typically by passing
    an explicit, disambiguated ``question`` (Nestor's source_text is
    per-question, not per-record, so two truly distinct decisions need
    distinguishable questions to get distinct, independently sealable
    drafts).

    ``store`` / ``db_path`` are injection seams for tests, mirroring
    ``seal_handler.on_seal``'s own ``store=``/``db_path=`` parameters.
    """
    st = store if store is not None else Store()
    gov = st.get(GOVERNANCE_COLLECTION, record_id)
    if gov is None:
        return {"error": "record_not_found"}

    existing_pair_id = gov.get("nestor_pair_id")
    if existing_pair_id:
        logger.info(
            "decision_bridge: record %s already linked to pair_id=%s — "
            "skipping propose", record_id, existing_pair_id,
        )
        return {"pair_id": existing_pair_id, "record_id": record_id,
                "status": "already_linked"}

    parts = _nestor()
    if parts is None:
        return {"error": "nestor_unavailable"}
    DecisionMemory, SqliteStore, ConflictingDraftError = parts

    resolved_db_path = db_path if db_path is not None else seal_handler._nestor_db_path()
    resolved_db_path.parent.mkdir(parents=True, exist_ok=True)
    nestor_store = SqliteStore(str(resolved_db_path))
    dm = DecisionMemory(nestor_store, domain="decision")

    q = question or gov.get("title", "")
    c = conclusion or gov.get("ruling", "")
    r = rationale or gov.get("rationale", "")
    o = origin or f"willow:{app_id}:{record_id}"

    try:
        draft = dm.propose(q, c, rationale=r, origin=o)
    except ConflictingDraftError as e:
        logger.warning(
            "decision_bridge: title collision proposing record %s (question "
            "%r already names a different draft) — %s", record_id, q, e,
        )
        return {"error": "title_collision", "record_id": record_id,
                "detail": str(e)}
    pair_id = draft["id"]

    # A same-conclusion (or already-sealed) collision doesn't raise — add_pair
    # hands back the existing row unchanged. Two independent tells, either one
    # enough to refuse: the row we got back doesn't say what we asked it to,
    # or it already belongs to a different SOIL record.
    if draft.get("target_text") != c:
        logger.warning(
            "decision_bridge: title collision proposing record %s — question "
            "%r already names pair %s with conclusion %r, not ours (%r)",
            record_id, q, pair_id, draft.get("target_text"), c,
        )
        return {"error": "title_collision", "record_id": record_id,
                "pair_id": pair_id,
                "detail": f"question {q!r} already names pair {pair_id} "
                          f"with a different conclusion"}

    other = seal_handler._find_governance_record(st, pair_id)
    if other is not None and other[0] != record_id:
        logger.warning(
            "decision_bridge: title collision proposing record %s — pair %s "
            "already belongs to governance record %s", record_id, pair_id,
            other[0],
        )
        return {"error": "title_collision", "record_id": record_id,
                "pair_id": pair_id,
                "detail": f"pair {pair_id} is already linked to governance "
                          f"record {other[0]!r}"}

    updated = seal_handler._strip_meta(gov)
    updated["nestor_pair_id"] = pair_id
    st.update(GOVERNANCE_COLLECTION, record_id, updated)

    logger.info(
        "decision_bridge: proposed pair_id=%s for governance record %s",
        pair_id, record_id,
    )
    return {"pair_id": pair_id, "record_id": record_id, "status": "draft"}
