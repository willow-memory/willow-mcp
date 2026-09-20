"""willow_mcp/net_authority.py — egress authority is seal-driven.

Sealed decision ``c8572a92`` (operator, 2026-09-20; SOIL record
``egress-authority-is-seal-driven-2026-09-20``): a Kart task gets network
authority without the operator at a keyboard. Three principals, the same
three the reloader (``e961aff8``) uses:

* **request** — the seat. ``task_submit(allow_net=True)`` with no envelope no
  longer refuses. It mints the task id and nonce, computes the normalized
  task hash, inserts the row as :data:`HELD_STATUS` (a status the worker's
  ``claim_pending`` never selects — ``task_queue.py`` claims ``'pending'``
  only), and proposes ONE Nestor decision pair through the ordinary
  ``decision_bridge`` path. The pair's conclusion binds exactly what
  ``willow-net-auth-v2`` signs — ``task_id, agent, submitted_by, task_hash,
  scope, ttl, nonce`` — and its rationale carries the task text so the human
  reads what they seal. The hash is what the seal signs; the text is what
  the human sees; the two are bound by the hash.
* **confirm** — the operator's seal, in the Nestor UI, with the browser
  verifier key whose private half never leaves the browser.
* **act** — :mod:`net_signer`, a separate process running as the egress
  key's owner. :func:`drain` (one tick, beside ``seal_drain.drain``) finds
  each held row, reads its pair from ``nestor.db``, and hands the signer
  ONLY the sealed bytes (``source_norm``, ``target_text``, ``verifier``,
  ``seal_sig``) plus the bound fields as this side read them off the row.
  The signer re-verifies the seal against the ring's public halves, parses
  the bound fields out of the sealed text, refuses if this side's view
  differs, and signs. The task text never crosses the socket — the protocol
  asserts it.

What this does NOT let any uid-1000 process do: sign. Without a seal the
signer refuses (unsealed / bad signature / bound-field mismatch, each named);
with a seal it signs exactly what the operator sealed and nothing else.

Three states on every step, never collapsed (INVARIANTS §1): a held row is
``waiting`` (no seal yet), ``minted`` (envelope attached, row released to
``pending``), ``refused`` (the signer said no and named the field), or
``unreachable`` (signer socket down, nestor.db unreadable, queue unavailable
— nothing consumed, nothing lied about).

Same shape for a standing lease: a sealed pair whose conclusion binds
``(app_id, ttl_seconds, reason, scope=lease)`` is minted by the same signer
into ``mcp_apps/_net_leases/<app_id>.json`` in ``lease.py``'s own shape.
"""
from __future__ import annotations

import json
import logging
import os
import random
import re
import secrets
import socket
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from . import egress_authorization as ea
from . import seal_handler

logger = logging.getLogger(__name__)

#: The row status a held task carries until its seal is minted. The worker
#: claims ``'pending'`` only (``task_queue.PgTaskQueue.claim_pending``), so a
#: held row is unrunnable by construction, not by a check that could be
#: forgotten.
HELD_STATUS = "held_net_authorization"

#: The status a held row is released to once its envelope is attached.
RELEASED_STATUS = "pending"

#: Version tag on the sealed conclusion line. Bump it if the bound field set
#: ever changes — a signer must refuse a line it does not know how to parse.
BOUND_FORMAT = "willow-net-auth-v2"

#: FRANK events. ``net_authorization_minted`` is the act; a refusal inks too,
#: so a client that never got its envelope can be told apart from a signer
#: that never saw the row.
EVENT_MINTED = "net_authorization_minted"
EVENT_REFUSED = "net_authorization_refused"
EVENT_LEASE_MINTED = "net_lease_minted"

#: The sealed-text field order. FROZEN alongside :data:`BOUND_FORMAT`: the
#: signer parses this line independently of this module's parser and the two
#: must agree byte for byte.
BOUND_FIELDS = ("task_id", "agent", "submitted_by", "task_hash", "scope", "ttl", "nonce")
LEASE_BOUND_FIELDS = ("app_id", "ttl", "reason_sha", "scope")

_TASK_ID_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789"
_BOUND_LINE_RE = re.compile(
    r"^" + re.escape(BOUND_FORMAT) + r"((?: [a-z_]+=[^ ]+)+)$"
)

SOCKET_ENV = "WILLOW_NET_SIGNER_SOCKET"
DEFAULT_SOCKET = "/run/willow-net-signer/sock"

#: SOIL governance records for held tasks are keyed by task id so the drain
#: can find the pair a row is waiting on without a second index.
def record_id_for_task(task_id: str) -> str:
    return f"net-auth-{task_id}"


def record_id_for_lease(app_id: str, nonce: str) -> str:
    return f"net-lease-{app_id}-{nonce[:8]}"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def mint_task_id() -> str:
    return "".join(random.choices(_TASK_ID_ALPHABET, k=8))


def mint_nonce() -> str:
    # 32 bytes -> 43 URL-safe chars: inside egress_authorization's 22..128 rule.
    return secrets.token_urlsafe(32)


# ── the sealed text ────────────────────────────────────────────────────────────

def bound_line(bound: dict) -> str:
    """The ONE line the operator seals for a task. ``bound`` carries every
    :data:`BOUND_FIELDS` key; order is fixed by the tuple, values are the
    row's own. No value may contain a space — task_id, hash, nonce and
    scope cannot; ``agent``/``submitted_by`` are gate-validated identifiers."""
    parts = []
    for key in BOUND_FIELDS:
        value = str(bound[key])
        if " " in value or "\n" in value or "=" in value:
            raise ValueError(f"bound field {key} contains a separator: {value!r}")
        parts.append(f"{key}={value}")
    return BOUND_FORMAT + " " + " ".join(parts)


def parse_bound_line(text: str) -> Optional[dict]:
    """Inverse of :func:`bound_line`; ``None`` for anything that is not
    exactly one well-formed line with exactly the expected keys."""
    line = (text or "").strip()
    m = _BOUND_LINE_RE.match(line)
    if not m:
        return None
    out: dict = {}
    for token in m.group(1).split():
        key, _, value = token.partition("=")
        if key in out:
            return None
        out[key] = value
    if set(out) != set(BOUND_FIELDS):
        return None
    if not ea._TASK_ID_RE.fullmatch(out["task_id"]):
        return None
    if not re.fullmatch(r"[0-9a-f]{64}", out["task_hash"]):
        return None
    if out["scope"] not in ea._VALID_SCOPES:
        return None
    if not out["ttl"].isdigit():
        return None
    if not ea._NONCE_RE.fullmatch(out["nonce"]):
        return None
    return out


def lease_bound_line(bound: dict) -> str:
    parts = []
    for key in LEASE_BOUND_FIELDS:
        value = str(bound[key])
        if " " in value or "\n" in value or "=" in value:
            raise ValueError(f"lease bound field {key} contains a separator")
        parts.append(f"{key}={value}")
    return BOUND_FORMAT + "-lease " + " ".join(parts)


def parse_lease_bound_line(text: str) -> Optional[dict]:
    line = (text or "").strip()
    prefix = BOUND_FORMAT + "-lease "
    if not line.startswith(prefix):
        return None
    out: dict = {}
    for token in line[len(prefix):].split():
        key, _, value = token.partition("=")
        if not key or key in out:
            return None
        out[key] = value
    if set(out) != set(LEASE_BOUND_FIELDS):
        return None
    if not out["ttl"].isdigit() or out["scope"] != "lease":
        return None
    if not re.fullmatch(r"[0-9a-f]{16}", out["reason_sha"]):
        return None
    return out


def question_for_task(bound: dict) -> str:
    """The pair's source_text. Unique per task id, so two held rows never
    collide on Nestor's one-row-per-question key."""
    return (f"Authorize network for Kart task {bound['task_id']} "
            f"({bound['agent']}, submitted by {bound['submitted_by']}, scope {bound['scope']})?")


def question_for_lease(bound: dict) -> str:
    return (f"Grant {bound['app_id']} a standing egress lease for {bound['ttl']}s "
            f"(reason sha {bound['reason_sha']})?")


# ── request: hold the row, propose the pair ───────────────────────────────────

def hold_and_propose(
    *,
    pg,
    fields: dict,
    app_id: str,
    agent: str,
    task: str,
    lane: str,
    scope: str,
    ttl_seconds: int,
    write_param: Callable,
    store=None,
    db_path: Optional[Path] = None,
    propose: Callable = None,
) -> dict:
    """The request half. Inserts the held row, records the governance record,
    proposes the pair. Returns ``{task_id, status, pair_id, seal_this}`` or
    ``{error}`` with the row NOT inserted (the propose runs first so a Nestor
    outage never strands a held row nobody can seal).

    ``fields`` is the confirmed ``tasks`` mapping; ``write_param`` is
    ``server._write_param``; ``propose`` defaults to
    ``decision_bridge.propose`` (injectable for tests).
    """
    from .db import Store

    if scope not in ea._VALID_SCOPES:
        return {"error": f"net_hold_denied: unsupported scope {scope!r}"}
    task_id = mint_task_id()
    nonce = mint_nonce()
    bound = {
        "task_id": task_id, "agent": agent, "submitted_by": app_id,
        "task_hash": ea.normalized_task_hash(task), "scope": scope,
        "ttl": str(int(ttl_seconds)), "nonce": nonce,
    }
    try:
        line = bound_line(bound)
    except ValueError as exc:
        return {"error": f"net_hold_denied: {exc}"}

    st = store if store is not None else Store()
    record_id = record_id_for_task(task_id)
    st.put(seal_handler.GOVERNANCE_COLLECTION, {
        "title": question_for_task(bound),
        "ruling": line,
        "rationale": task,
        "kind": "net-authorization-request",
        "task_id": task_id, "scope": scope, "submitted_by": app_id, "agent": agent,
        "task_hash": bound["task_hash"], "nonce": nonce, "ttl": bound["ttl"],
        "status": "proposed", "proposed_by": app_id, "date": _now().date().isoformat(),
        "under": "c8572a92",
    }, record_id=record_id)

    do_propose = propose
    if do_propose is None:
        from . import decision_bridge
        do_propose = decision_bridge.propose
    proposed = do_propose(app_id, record_id, store=st, db_path=db_path)
    if proposed.get("error"):
        return {"error": f"net_hold_denied: {proposed['error']}",
                "detail": proposed.get("detail", ""), "record_id": record_id}
    pair_id = proposed["pair_id"]

    values = {"task_id": task_id, "task": task, "status": HELD_STATUS, "lane": lane}
    if fields.get("submitted_by", {}).get("column"):
        values["submitted_by"] = app_id
    if fields.get("agent", {}).get("column"):
        values["agent"] = agent
    if not fields.get("status", {}).get("column"):
        return {"error": "schema_unusable: the confirmed tasks mapping has no 'status' column; "
                         "a held row cannot be held"}
    cols = ", ".join(f'"{fields[f]["column"]}"' for f in values)
    placeholders = ", ".join(["%s"] * len(values))
    params = [write_param(fields[f], v) for f, v in values.items()]
    cur = pg.cursor()
    cur.execute(f"INSERT INTO tasks ({cols}) VALUES ({placeholders})", params)  # nosec B608 - cols come from the confirmed schema_profile mapping; values are bound params
    cur.close()
    return {"task_id": task_id, "status": HELD_STATUS, "pair_id": pair_id,
            "record_id": record_id, "seal_this": line,
            "next": "the operator seals the pair in the Nestor UI; the next net_authority "
                    "tick mints the envelope and releases the row to pending"}


def propose_lease(
    *,
    app_id: str,
    ttl_seconds: int,
    reason: str,
    store=None,
    db_path: Optional[Path] = None,
    propose: Callable = None,
) -> dict:
    """The request half for a standing lease: one pair binding
    ``(app_id, ttl, reason_sha, scope=lease)``; the reason text rides in the
    rationale for the human."""
    import hashlib

    from .db import Store
    from . import lease as lease_mod

    if not isinstance(ttl_seconds, int) or ttl_seconds <= 0 or ttl_seconds > lease_mod.MAX_TTL_SECONDS:
        return {"error": f"lease_hold_denied: ttl_seconds must be within 1..{lease_mod.MAX_TTL_SECONDS}"}
    nonce = mint_nonce()
    bound = {"app_id": app_id, "ttl": str(ttl_seconds),
             "reason_sha": hashlib.sha256((reason or "").encode("utf-8")).hexdigest()[:16],
             "scope": "lease"}
    try:
        line = lease_bound_line(bound)
    except ValueError as exc:
        return {"error": f"lease_hold_denied: {exc}"}
    st = store if store is not None else Store()
    record_id = record_id_for_lease(app_id, nonce)
    st.put(seal_handler.GOVERNANCE_COLLECTION, {
        "title": question_for_lease(bound) + f" [{nonce[:8]}]",
        "ruling": line,
        "rationale": reason or "",
        "kind": "net-lease-request",
        "app_id": app_id, "ttl": bound["ttl"], "reason_sha": bound["reason_sha"],
        "status": "proposed", "proposed_by": app_id, "date": _now().date().isoformat(),
        "under": "c8572a92",
    }, record_id=record_id)
    do_propose = propose
    if do_propose is None:
        from . import decision_bridge
        do_propose = decision_bridge.propose
    proposed = do_propose(app_id, record_id, store=st, db_path=db_path)
    if proposed.get("error"):
        return {"error": f"lease_hold_denied: {proposed['error']}", "record_id": record_id}
    return {"status": "proposed", "pair_id": proposed["pair_id"], "record_id": record_id,
            "seal_this": line}


# ── the seal, read from nestor.db ─────────────────────────────────────────────

def read_sealed_pair(pair_id: str, db_path: Path) -> dict:
    """The pair as the sealer wrote it — or three-state why not.

    ``populated`` carries ``source_norm, target_text, verifier, seal_sig``;
    ``empty`` means the pair exists but is not sealed (draft, unsigned,
    superseded — ``why`` names which); ``unreachable`` means nestor.db could
    not be read. ``status='sealed'`` is deliberately NOT enough on its own:
    the signer verifies ``seal_sig`` itself, and this side hands it the
    bytes to do so.
    """
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        return {"state": "unreachable", "cause": f"{type(exc).__name__}: {exc}", "path": str(db_path)}
    try:
        row = conn.execute(
            "SELECT source_norm, target_text, verifier, seal_sig, status, superseded_by "
            "FROM tm_pairs WHERE id = ?", (pair_id,)).fetchone()
    except sqlite3.Error as exc:
        return {"state": "unreachable", "cause": f"{type(exc).__name__}: {exc}", "path": str(db_path)}
    finally:
        conn.close()
    if row is None:
        return {"state": "empty", "why": "pair_absent"}
    source_norm, target_text, verifier, seal_sig, status, superseded_by = row
    if superseded_by:
        return {"state": "empty", "why": "superseded"}
    if status != "sealed":
        return {"state": "empty", "why": f"status={status}"}
    if not seal_sig:
        return {"state": "empty", "why": "unsigned"}
    return {"state": "populated", "source_norm": source_norm, "target_text": target_text,
            "verifier": verifier, "seal_sig": seal_sig}


# ── the signer, over a socket ─────────────────────────────────────────────────

def socket_path() -> Path:
    return Path(os.environ.get(SOCKET_ENV, "").strip() or DEFAULT_SOCKET)


def signer_call(request: dict, *, path: Optional[Path] = None, timeout: float = 10.0) -> dict:
    """One request, one reply, newline-delimited JSON over AF_UNIX. Never
    raises: an unreachable signer is ``{"state": "unreachable", ...}``.

    The protocol assertion the ruling asks for lives here, on the client:
    a request carrying ``task`` (the text) is refused before it is sent.
    """
    if "task" in request or "task_text" in request:
        return {"state": "refused", "reason": "protocol: the task text never crosses the socket"}
    sock_path = Path(path) if path is not None else socket_path()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(str(sock_path))
            s.sendall((json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8"))
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
    except (OSError, socket.timeout) as exc:
        return {"state": "unreachable", "cause": f"{type(exc).__name__}: {exc}", "socket": str(sock_path)}
    try:
        reply = json.loads(buf.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {"state": "unreachable", "cause": "malformed reply", "socket": str(sock_path)}
    if not isinstance(reply, dict) or "state" not in reply:
        return {"state": "unreachable", "cause": "reply carries no state", "socket": str(sock_path)}
    return reply


# ── act: one tick ─────────────────────────────────────────────────────────────

def _held_rows(pg, cols: dict) -> list[dict]:
    """Every held row, as {task_id, task, agent, submitted_by, lane}."""
    want = ["task_id", "task", "agent", "submitted_by", "lane"]
    present = [f for f in want if cols.get(f)]
    select = ", ".join(f'"{cols[f]}"' for f in present)
    cur = pg.cursor()
    cur.execute(
        f'SELECT {select} FROM tasks WHERE "{cols["status"]}" = %s',  # nosec B608 - cols come from the confirmed schema_profile mapping; status is a bound param
        (HELD_STATUS,),
    )
    rows = [dict(zip(present, r)) for r in cur.fetchall()]
    cur.close()
    return rows


def _release(pg, cols: dict, task_id: str, envelope: str) -> bool:
    cur = pg.cursor()
    cur.execute(
        f'UPDATE tasks SET "{cols["network_authorization"]}" = %s, "{cols["status"]}" = %s '  # nosec B608 - cols come from the confirmed schema_profile mapping; values are bound params
        f'WHERE "{cols["task_id"]}" = %s AND "{cols["status"]}" = %s',
        (envelope, RELEASED_STATUS, task_id, HELD_STATUS),
    )
    released = cur.rowcount == 1
    cur.close()
    pg.commit()
    return released


def drain(
    *,
    pg,
    cols: dict,
    ledger=None,
    store=None,
    db_path: Optional[Path] = None,
    call: Callable[[dict], dict] = signer_call,
    max_rows: int = 200,
    now: Optional[datetime] = None,
) -> dict:
    """One tick: for every held row, find its pair, ask the signer, release
    the row. Receipt shape mirrors ``seal_drain.drain``:

    ``state`` is ``unreachable`` (queue/store/nestor.db unavailable — nothing
    consumed), ``empty`` (no held rows), or ``populated`` with ``rows``: one
    entry per held row, each ``waiting`` / ``minted`` / ``refused`` /
    ``unreachable`` with its cause.

    ``cols`` is the confirmed ``tasks`` column mapping (needs ``task_id``,
    ``status``, ``network_authorization``); ``ledger`` a ``GovernanceLedger``
    (None → receipts are reported in the tick receipt only, and the receipt
    says ``inked: false``); ``call`` the signer transport.
    """
    from .db import Store

    receipt: dict = {"event": "net_authority_tick", "at": (now or _now()).isoformat()}
    for needed in ("task_id", "status", "network_authorization"):
        if not cols.get(needed):
            receipt.update(state="unreachable", reason=f"tasks mapping has no {needed} column")
            return receipt
    try:
        held = _held_rows(pg, cols)
    except Exception as exc:  # noqa: BLE001 — queue outage is reported, never raised into the tick
        receipt.update(state="unreachable", reason="queue_unavailable",
                       error=f"{type(exc).__name__}: {exc}")
        return receipt
    if not held:
        receipt.update(state="empty", held=0)
        return receipt

    st = store if store is not None else Store()
    nestor_db = db_path if db_path is not None else seal_handler._nestor_db_path()
    rows_out: list[dict] = []
    counts = {"waiting": 0, "minted": 0, "refused": 0, "unreachable": 0}
    truncated = len(held) > max_rows
    for row in held[:max_rows]:
        task_id = row["task_id"]
        out = {"task_id": task_id}
        gov = st.get(seal_handler.GOVERNANCE_COLLECTION, record_id_for_task(task_id))
        if gov is None or not gov.get("nestor_pair_id"):
            out.update(state="waiting", why="no pair proposed for this row")
            counts["waiting"] += 1
            rows_out.append(out)
            continue
        pair_id = gov["nestor_pair_id"]
        out["pair_id"] = pair_id
        sealed = read_sealed_pair(pair_id, nestor_db)
        if sealed["state"] == "unreachable":
            out.update(state="unreachable", cause=sealed.get("cause"))
            counts["unreachable"] += 1
            rows_out.append(out)
            continue
        if sealed["state"] == "empty":
            out.update(state="waiting", why=sealed.get("why"))
            counts["waiting"] += 1
            rows_out.append(out)
            continue

        # This side's view of what the row is — the signer compares it to
        # what the operator sealed and refuses on any difference.
        bound_view = {
            "task_id": task_id,
            "agent": row.get("agent") or gov.get("agent"),
            "submitted_by": row.get("submitted_by") or gov.get("submitted_by"),
            "task_hash": ea.normalized_task_hash(row.get("task") or ""),
            "scope": gov.get("scope"),
            "ttl": str(gov.get("ttl")),
            "nonce": gov.get("nonce"),
        }
        reply = call({
            "op": "sign_task",
            "seal": {k: sealed[k] for k in ("source_norm", "target_text", "verifier", "seal_sig")},
            "bound": bound_view,
            "pair_id": pair_id,
        })
        state = reply.get("state")
        if state == "unreachable":
            out.update(state="unreachable", cause=reply.get("cause"), socket=reply.get("socket"))
            counts["unreachable"] += 1
        elif state == "refused":
            out.update(state="refused", reason=reply.get("reason"), field=reply.get("field"))
            counts["refused"] += 1
            _ink(ledger, out, EVENT_REFUSED, {
                "task_id": task_id, "pair_id": pair_id, "reason": reply.get("reason"),
                "field": reply.get("field"), "verifier": sealed["verifier"],
            })
        elif state == "minted" and isinstance(reply.get("envelope"), str):
            envelope = reply["envelope"]
            # Last check on this side: the envelope the signer returned must
            # verify for THIS row before it is attached. A signer that signed
            # something else is a refusal, not a release.
            public_key = ea.public_key_path()
            ok, reason, payload = (False, "verification key is not configured", None)
            if public_key is not None:
                ok, reason, payload = ea.verify_envelope(
                    public_key_path=public_key, submitted_by=bound_view["submitted_by"],
                    task_id=task_id, agent=bound_view["agent"], task=row.get("task") or "",
                    envelope=envelope, expected_scope=bound_view["scope"],
                )
            if not ok:
                out.update(state="refused", reason=f"minted envelope does not verify: {reason}",
                           field="envelope")
                counts["refused"] += 1
                _ink(ledger, out, EVENT_REFUSED, {
                    "task_id": task_id, "pair_id": pair_id, "reason": out["reason"]})
            elif not _release(pg, cols, task_id, envelope):
                out.update(state="refused", reason="row is no longer held", field="status")
                counts["refused"] += 1
            else:
                out.update(state="minted", expires_at=payload.get("expires_at"),
                           verifier=sealed["verifier"], released_to=RELEASED_STATUS)
                counts["minted"] += 1
                _ink(ledger, out, EVENT_MINTED, {
                    "task_id": task_id, "pair_id": pair_id, "verifier": sealed["verifier"],
                    "scope": bound_view["scope"], "expires_at": payload.get("expires_at"),
                    "decision": "c8572a92",
                })
        else:
            out.update(state="unreachable", cause=f"signer reply not understood: {state!r}")
            counts["unreachable"] += 1
        rows_out.append(out)

    receipt.update(state="populated", held=len(held), rows=rows_out, counts=counts,
                   truncated=truncated, inked=ledger is not None)
    return receipt


def _ink(ledger, out: dict, event: str, content: dict) -> None:
    if ledger is None:
        out["inked"] = False
        return
    try:
        out["receipt_id"] = ledger.append("fleet", event, content)
        out["inked"] = True
    except Exception as exc:  # noqa: BLE001 — the act happened; a receipt failing is reported, not hidden
        out["inked"] = False
        out["receipt_error"] = f"{type(exc).__name__}: {exc}"


def drain_leases(
    *,
    store=None,
    db_path: Optional[Path] = None,
    ledger=None,
    call: Callable[[dict], dict] = signer_call,
    now: Optional[datetime] = None,
) -> dict:
    """The lease half of the tick: every ``net-lease-request`` governance
    record still ``proposed`` whose pair is sealed goes to the signer, which
    writes the lease file (it owns the lease root on a hardened box) and
    reports ``minted``; the record flips to ``minted`` so it is never sent
    twice."""
    from .db import Store

    st = store if store is not None else Store()
    nestor_db = db_path if db_path is not None else seal_handler._nestor_db_path()
    receipt: dict = {"event": "net_lease_tick", "at": (now or _now()).isoformat()}
    pending = [r for r in st.all(seal_handler.GOVERNANCE_COLLECTION)
               if r.get("kind") == "net-lease-request" and r.get("status") == "proposed"]
    if not pending:
        receipt.update(state="empty", requests=0)
        return receipt
    rows_out = []
    for gov in pending:
        rid = gov.get("_id")
        out = {"record_id": rid, "app_id": gov.get("app_id")}
        pair_id = gov.get("nestor_pair_id")
        if not pair_id:
            out.update(state="waiting", why="no pair proposed")
            rows_out.append(out)
            continue
        sealed = read_sealed_pair(pair_id, nestor_db)
        if sealed["state"] != "populated":
            out.update(state="unreachable" if sealed["state"] == "unreachable" else "waiting",
                       why=sealed.get("why") or sealed.get("cause"))
            rows_out.append(out)
            continue
        reply = call({
            "op": "sign_lease",
            "seal": {k: sealed[k] for k in ("source_norm", "target_text", "verifier", "seal_sig")},
            "bound": {"app_id": gov.get("app_id"), "ttl": str(gov.get("ttl")),
                      "reason_sha": gov.get("reason_sha"), "scope": "lease"},
            "reason": gov.get("rationale") or "",
            "pair_id": pair_id,
        })
        state = reply.get("state")
        if state == "minted":
            updated = seal_handler._strip_meta(gov)
            updated["status"] = "minted"
            updated["lease_path"] = reply.get("path")
            updated["expires_at"] = reply.get("expires_at")
            st.update(seal_handler.GOVERNANCE_COLLECTION, rid, updated)
            out.update(state="minted", path=reply.get("path"), expires_at=reply.get("expires_at"))
            _ink(ledger, out, EVENT_LEASE_MINTED, {
                "app_id": gov.get("app_id"), "pair_id": pair_id, "verifier": sealed["verifier"],
                "expires_at": reply.get("expires_at"), "decision": "c8572a92"})
        elif state == "refused":
            out.update(state="refused", reason=reply.get("reason"), field=reply.get("field"))
        else:
            out.update(state="unreachable", cause=reply.get("cause"))
        rows_out.append(out)
    receipt.update(state="populated", requests=len(pending), rows=rows_out)
    return receipt


def tick(*, ledger=None, call: Callable[[dict], dict] = signer_call) -> dict:
    """Both halves against the live queue and store — what the steward tick
    (or ``python -m willow_mcp.net_authority tick``) runs."""
    from .db import get_pg

    pg = get_pg()
    if pg is None:
        return {"state": "unreachable", "reason": "postgres_unavailable"}
    cols = ea._task_table_columns()
    if cols is None:
        return {"state": "unreachable", "reason": "tasks mapping unconfirmed"}
    # _task_table_columns resolves the gate fields only; the drain also needs
    # the envelope and lane columns, resolved the same way.
    from . import schema_profile as sp

    app_id = os.environ.get("WILLOW_APP_ID", "willow").strip() or "willow"
    mapping = sp.resolve(pg, app_id, "tasks",
                         ["task_id", "task", "status", "agent", "submitted_by", "lane",
                          "network_authorization"])
    if "error" in mapping or not mapping.get("confirmed"):
        return {"state": "unreachable", "reason": "tasks mapping unconfirmed"}
    full_cols = {k: v["column"] for k, v in mapping["fields"].items()}
    if ledger is None:
        try:
            from .governance_ledger import GovernanceLedger
            ledger = GovernanceLedger(pg)
        except Exception:  # noqa: BLE001 — no ledger means receipts are reported, not inked
            ledger = None
    tasks = drain(pg=pg, cols=full_cols, ledger=ledger, call=call)
    leases = drain_leases(ledger=ledger, call=call)
    return {"tasks": tasks, "leases": leases}


def main(argv: Optional[list] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="willow-mcp-net-authority")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("tick", help="one drain of held tasks and lease requests against the signer")
    args = parser.parse_args(argv)
    if args.command == "tick":
        print(json.dumps(tick(), default=str, indent=2))
        return 0
    return 1


if __name__ == "__main__":  # pragma: no cover
    import sys

    sys.exit(main(sys.argv[1:]))
