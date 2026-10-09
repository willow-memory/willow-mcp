"""willow_mcp/onescript_deposit.py — the pooled set becomes governance drafts.

The one script's ``pooled`` step (see ``onescript_executor``) only READS: the
session's pooled, unsealed ``pass`` proposals as JSON lines. This module is the
write half, kept out of the executor so that module stays pure ("local steps
only, nothing pushed"). For each pooled pair it does exactly what the desk does
by hand (``store_put`` a ``projects_willow_governance_decisions`` record, then
``decision_propose`` it) and nothing more:

* **ProposeOnly.** A draft lands in Nestor; no seal, no ``seal_drain``, no HMAC.
  Only a human's key ratifies. Nothing here imports or calls a seal path.
* **Three states, passed straight through.** ``unreachable`` or ``empty`` from
  the pooled read deposits NOTHING and is returned as read.
* **Idempotent on the pooled ``subject``** (``proposal:<hash>``). The governance
  store has no field index, so the record carries a ``subject`` field and the
  guard is a scan for it (the shape ``seal_handler._find_governance_record``
  uses for ``nestor_pair_id``). A record that already carries the subject is
  REUSED — never re-put — and ``decision_propose`` is itself idempotent per
  record (``already_linked`` once it holds a ``nestor_pair_id``).
* **Ink.** One FRANK ``onescript_deposit`` receipt per act that deposited.
"""
from __future__ import annotations

import json
import re
from typing import Callable, Optional

from . import decision_bridge, onescript_executor

EVENT = "onescript_deposit"
GOVERNANCE_COLLECTION = decision_bridge.GOVERNANCE_COLLECTION

_SUBJECT_RE = re.compile(r"^proposal:[0-9a-f]{16,128}$")
_TITLE_MAX = 200
_BLOB_MAX = 4000


#: The fixed, deposit-controlled first line of every deposited conclusion. The
#: untrusted, model-authored claim never occupies line 1 (F1, Loki 7A2ED3DA):
#: first-line-keyed re-derivations of a privileged scope off a sealed
#: ``target_text`` must never fire from pooled content.
PREAMBLE = "onescript-deposit: pooled unsealed proposal (draft; claim below is model-authored, unverified)"

# Privileged markers read off a sealed pair's target_text (enumerated from
# seed_loader / seal_handler / manifest_grant_executor / trust_owner_verbs /
# net_authority / constitutional). First-line grammars:
_FIRST_LINE_MARKERS = (
    r"boot-correction:",                   # seed_loader._BOOT_CORRECTION_RE, seal_handler._boot_correction_scope
    r"willow-manifest-grant-v1\b",         # manifest_grant_executor.RULING_FORMAT
    r"willow-net-auth-v2",                 # net_authority.BOUND_FORMAT (+ "-lease")
    r"revoke envelope\s",                  # trust_owner_verbs._REVOKE_RE
    r"retire seat\s",                      # trust_owner_verbs._RETIRE_RE
    r"create seat\s",                      # trust_owner_verbs._CREATE_RE
    r"ratify federation server\s",         # trust_owner_verbs._RATIFY_RE
    r"ratify envelope\s",                  # trust_owner_verbs._ENVELOPE_RATIFY_RE
)
# constitutional._AMEND_LINE_RE is MULTILINE: it fires on ANY line of target_text.
_ANY_LINE_MARKERS = (r"syscall-row-amend:",)
_FIRST_LINE_RE = re.compile(r"^\s*(?:" + "|".join(_FIRST_LINE_MARKERS) + ")", re.IGNORECASE)
_ANY_LINE_RE = re.compile(r"^\s*(?:" + "|".join(_ANY_LINE_MARKERS) + ")", re.IGNORECASE | re.MULTILINE)


def privileged_marker(claim: str) -> Optional[str]:
    """The privileged marker a claim opens with (or carries, for any-line
    markers), else None."""
    text = str(claim)
    m = _FIRST_LINE_RE.match(text.lstrip("\r\n")) or _ANY_LINE_RE.search(text)
    return m.group(0).strip() if m else None


def _blob(value) -> str:
    # Always JSON: a bare string with newlines could otherwise start a line of
    # the conclusion with a marker; json.dumps escapes the newlines.
    text = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return text if len(text) <= _BLOB_MAX else text[:_BLOB_MAX] + " [truncated]"


def _record(pair: dict, app_id: str) -> dict:
    """The governance record for one pooled pair: title from the claim, ruling
    (the side a human would seal) = a fixed preamble line, then the labelled
    claim, then its supporting data/cites."""
    claim = str(pair["claim"]).strip()
    title = (claim.splitlines() or [""])[0].strip()[:_TITLE_MAX]
    ruling = (f"{PREAMBLE}\n\nclaim:\n{claim}\n\n"
              f"evidence: {_blob(pair['data'])}\ncites: {_blob(pair['cites'])}")
    return {
        "title": title,
        "ruling": ruling,
        "rationale": f"pooled unsealed pass proposal {pair['subject']} at {pair['path']}; "
                     "drafted by onescript_deposit, ProposeOnly (a human seals).",
        "subject": pair["subject"],
        "path": str(pair["path"]),
        "origin": f"willow:{app_id}:onescript_deposit",
        "source": "onescript_deposit",
    }


def _existing(store, subject: str) -> Optional[tuple[str, dict]]:
    for rec in store.all(GOVERNANCE_COLLECTION):
        if rec.get("subject") == subject:
            return rec.get("_id"), rec
    return None


def deposit(
    app_id: str,
    *,
    project: str = "onescript",
    session: str = "",
    ledger=None,
    store=None,
    read_pool: Optional[Callable[[], dict]] = None,
) -> dict:
    """Read the pooled set and propose each pair as a governance draft."""
    if read_pool is None:
        def read_pool() -> dict:
            return onescript_executor.execute_step(
                app_id, "pooled", {}, project=project, session=session, ledger=ledger)

    pooled = read_pool()
    state = pooled.get("state")
    if state != "populated":
        # unreachable / empty (or a refusal with no state): deposit nothing.
        return {"ok": False, "deposited": [], "count": 0,
                "state": state or "unreachable",
                "reason": pooled.get("reason") or pooled.get("error") or "the pooled read gave no pairs",
                "pooled_receipt_id": pooled.get("receipt_id")}

    pairs = (pooled.get("stdout_json") or {}).get("pooled") or []
    if store is None:
        from .db import Store
        store = Store()

    deposited: list[dict] = []
    for pair in pairs:
        subject = pair.get("subject") if isinstance(pair, dict) else None
        if not isinstance(subject, str) or not _SUBJECT_RE.fullmatch(subject):
            deposited.append({"subject": subject, "record_id": None, "pair_id": None,
                              "status": "error", "error": "subject must be proposal:<hash>"})
            continue
        if not str(pair.get("claim", "")).strip():
            deposited.append({"subject": subject, "record_id": None, "pair_id": None,
                              "status": "error", "error": "empty_claim"})
            continue
        marker = privileged_marker(pair["claim"])
        if marker:
            deposited.append({"subject": subject, "record_id": None, "pair_id": None,
                              "status": "error",
                              "error": f"refused: privileged marker in claim ({marker})"})
            continue
        record = _record(pair, app_id)
        found = _existing(store, subject)
        reused = found is not None
        if reused:
            record_id, stored = found
            if stored.get("ruling") != record["ruling"]:
                deposited.append({"subject": subject, "record_id": record_id, "pair_id": None,
                                  "status": "error", "error": "subject_content_conflict",
                                  "detail": "a record for this subject already holds different "
                                            "claim/data/cites; the later content was not deposited"})
                continue
        else:
            record_id, _action = store.put(GOVERNANCE_COLLECTION, record)
        res = decision_bridge.propose(app_id, record_id, store=store)
        entry = {"subject": subject, "record_id": record_id,
                 "pair_id": res.get("pair_id"),
                 "status": res.get("status") or "error"}
        if res.get("error"):
            entry["error"] = res["error"]
            if res.get("detail"):
                entry["detail"] = res["detail"]
        if reused:
            entry["reused_record"] = True
        deposited.append(entry)

    out = {"ok": True, "deposited": deposited, "count": len(deposited), "state": "populated",
           "pooled_receipt_id": pooled.get("receipt_id")}
    rid = None
    if ledger is not None:
        try:
            rid = ledger.append(project or "onescript", EVENT, {
                "actor": app_id, "session": session, "count": len(deposited),
                "subjects": [d["subject"] for d in deposited],
                "record_ids": [d["record_id"] for d in deposited],
                "pair_ids": [d["pair_id"] for d in deposited],
                "statuses": [d["status"] for d in deposited],
            })
        except Exception as exc:  # noqa: BLE001 — the act happened; the ink failing is reported
            out["receipt_error"] = f"{type(exc).__name__}: {exc}"
    out["receipt_id"] = rid
    return out
