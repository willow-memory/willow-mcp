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


def _blob(value) -> str:
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return text if len(text) <= _BLOB_MAX else text[:_BLOB_MAX] + " [truncated]"


def _record(pair: dict, app_id: str) -> dict:
    """The governance record for one pooled pair: title from the claim, ruling
    (the side a human would seal) = the claim plus its supporting data/cites."""
    claim = str(pair["claim"]).strip()
    title = (claim.splitlines() or [""])[0].strip()[:_TITLE_MAX]
    ruling = f"{claim}\n\nevidence: {_blob(pair['data'])}\ncites: {_blob(pair['cites'])}"
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


def _existing(store, subject: str) -> Optional[str]:
    for rec in store.all(GOVERNANCE_COLLECTION):
        if rec.get("subject") == subject:
            return rec.get("_id")
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
        record_id = _existing(store, subject)
        reused = record_id is not None
        if not reused:
            record_id, _action = store.put(GOVERNANCE_COLLECTION, _record(pair, app_id))
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
