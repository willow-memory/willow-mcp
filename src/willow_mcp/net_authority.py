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
  ``decision_bridge`` path. The pair's conclusion — the SEALED text — is the
  bound line (``task_id, agent, submitted_by, scope, ttl, nonce``), a rule,
  and the task text itself. No hash anywhere: a hash is the one field a
  human cannot check by eye, and a line whose hash named a text other than
  the one shown beside it was the phishable shape Loki found (7153DC79;
  amending pair 6b305258). What the human reads is inside what they sign.
* **confirm** — the operator's seal, in the Nestor UI, with the browser
  verifier key whose private half never leaves the browser.
* **act** — :mod:`net_signer`, a separate process running as the egress
  key's owner. :func:`drain` (one tick, beside ``seal_drain.drain``) finds
  each held row, reads its pair from ``nestor.db``, and hands the signer the
  sealed bytes (``source_norm``, ``target_text``, ``verifier``, ``seal_sig``,
  ``created_at``) plus this side's view of the identity fields. The signer
  re-verifies the seal against the ring's public halves, splits the sealed
  text, DERIVES the task hash from the body it verified, refuses if the
  identity fields differ, and signs from that hash. No hash, no task text
  and no pair id travel outside the seal — the client refuses to send them
  and the signer refuses to read them — so every binding in the envelope is
  something the operator sealed, never something a caller asserted.

What this does NOT let any uid-1000 process do: sign, or steer what is
signed. Without a seal the signer refuses (unsealed / bad signature /
identity mismatch, each named); with a seal it signs exactly the text the
operator sealed and nothing else. This side then checks the envelope
against the ROW's text (``verify_envelope(task=row.task)``) before release,
so a row whose text differs from the sealed text is refused here.

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

#: The status a held row is moved to when nobody sealed it in time. Terminal
#: for the worker (never claimed), and `_row_blocks_net_authorization`
#: treats a non-pending, non-running row as not runnable either way.
EXPIRED_STATUS = "failed"

#: How long a held row waits for a seal before it is refused as stale
#: (Loki 7153DC79: a held row that never expires is a standing offer). One
#: day: long enough for an operator away from the seal desk, short enough
#: that a request from a session nobody remembers does not sit for a week.
HELD_MAX_AGE_S = 24 * 60 * 60

#: A seal older than this is not honoured for a NEW mint: the operator sealed
#: it for a row that has since been refused as stale, or the seal predates a
#: key rotation the ring cannot express. Same bound as the held row.
SEAL_MAX_AGE_S = HELD_MAX_AGE_S

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
#: No ``task_hash`` here (Loki 7153DC79, amending pair 6b305258): a hash in
#: the line is the one field a human cannot check by eye, and a sealed line
#: whose hash named a different text than the one shown beside it was the
#: phishable shape. The text itself is IN the sealed bytes below the rule;
#: the signer derives the hash from what was sealed and never accepts one.
BOUND_FIELDS = ("task_id", "agent", "submitted_by", "scope", "ttl", "nonce")
LEASE_BOUND_FIELDS = ("app_id", "ttl", "scope")

#: Separates the bound line from the body in the sealed ``target_text``.
#: A line of its own so neither a bound value nor a task line can be
#: mistaken for it: task text is canonicalised (directive lines stripped)
#: and a task containing this exact line is refused at hold time.
SEALED_RULE = "---"

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
    if out["scope"] not in ea._VALID_SCOPES:
        return None
    if not out["ttl"].isdigit():
        return None
    if not ea._NONCE_RE.fullmatch(out["nonce"]):
        return None
    return out


def sealed_text(bound: dict, body: str) -> str:
    """What the operator seals: the bound line, a rule, the body — the task
    text for a task, the reason for a lease. The body is what the human
    reads; being inside the sealed bytes is what makes reading it count."""
    if SEALED_RULE in (body or "").splitlines():
        raise ValueError(f"body contains the sealed rule line {SEALED_RULE!r}")
    return bound_line(bound) + "\n" + SEALED_RULE + "\n" + (body or "")


def split_sealed_text(text: str) -> Optional[tuple[dict, str]]:
    """Inverse of :func:`sealed_text`: ``(bound, body)`` or ``None``. The
    FIRST rule line splits; a body may not contain one, and a text with no
    rule is not a sealed text. Used by the signer on the bytes it verified,
    so the body it hashes is the body the human sealed."""
    lines = (text or "").split("\n")
    try:
        rule_at = lines.index(SEALED_RULE)
    except ValueError:
        return None
    if rule_at != 1:
        return None
    bound = parse_bound_line(lines[0])
    if bound is None:
        return None
    body = "\n".join(lines[2:])
    if SEALED_RULE in body.split("\n"):
        return None
    return bound, body


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
    return out


def sealed_lease_text(bound: dict, reason: str) -> str:
    if SEALED_RULE in (reason or "").splitlines():
        raise ValueError(f"reason contains the sealed rule line {SEALED_RULE!r}")
    return lease_bound_line(bound) + "\n" + SEALED_RULE + "\n" + (reason or "")


def split_sealed_lease_text(text: str) -> Optional[tuple[dict, str]]:
    lines = (text or "").split("\n")
    try:
        rule_at = lines.index(SEALED_RULE)
    except ValueError:
        return None
    if rule_at != 1:
        return None
    bound = parse_lease_bound_line(lines[0])
    if bound is None:
        return None
    reason = "\n".join(lines[2:])
    if SEALED_RULE in reason.split("\n"):
        return None
    return bound, reason


def question_for_task(bound: dict) -> str:
    """The pair's source_text. Unique per task id, so two held rows never
    collide on Nestor's one-row-per-question key."""
    return (f"Authorize network for Kart task {bound['task_id']} "
            f"({bound['agent']}, submitted by {bound['submitted_by']}, scope {bound['scope']})?")


def question_for_lease(bound: dict, nonce: str) -> str:
    return (f"Grant {bound['app_id']} a standing egress lease for {bound['ttl']}s? "
            f"[{nonce[:8]}]")


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
        "scope": scope, "ttl": str(int(ttl_seconds)), "nonce": nonce,
    }
    try:
        # The task text IS the sealed body. No hash anywhere the human
        # cannot check; the signer derives it from the sealed bytes.
        to_seal = sealed_text(bound, task)
    except ValueError as exc:
        return {"error": f"net_hold_denied: {exc}"}

    st = store if store is not None else Store()
    record_id = record_id_for_task(task_id)
    held_at = _now().isoformat()
    st.put(seal_handler.GOVERNANCE_COLLECTION, {
        "title": question_for_task(bound),
        "ruling": to_seal,
        "rationale": (f"Seal only if the task text under the rule is what you mean to "
                      f"authorize for {agent} on behalf of {app_id}. Decision c8572a92 as "
                      f"amended by 6b305258: the text is inside the sealed bytes; the signer "
                      f"hashes what you sealed, never what a caller says you sealed."),
        "kind": "net-authorization-request",
        "task_id": task_id, "scope": scope, "submitted_by": app_id, "agent": agent,
        "nonce": nonce, "ttl": bound["ttl"], "held_at": held_at,
        "status": "proposed", "proposed_by": app_id, "date": held_at[:10],
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
            "record_id": record_id, "seal_this": to_seal,
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
    """The request half for a standing lease: one pair whose sealed text is
    the bound line ``(app_id, ttl, scope=lease)``, the rule, and the reason
    — the reason inside the sealed bytes, same as a task's text."""
    from .db import Store
    from . import lease as lease_mod

    if not isinstance(ttl_seconds, int) or ttl_seconds <= 0 or ttl_seconds > lease_mod.MAX_TTL_SECONDS:
        return {"error": f"lease_hold_denied: ttl_seconds must be within 1..{lease_mod.MAX_TTL_SECONDS}"}
    nonce = mint_nonce()
    bound = {"app_id": app_id, "ttl": str(ttl_seconds), "scope": "lease"}
    try:
        to_seal = sealed_lease_text(bound, reason or "")
    except ValueError as exc:
        return {"error": f"lease_hold_denied: {exc}"}
    st = store if store is not None else Store()
    record_id = record_id_for_lease(app_id, nonce)
    st.put(seal_handler.GOVERNANCE_COLLECTION, {
        "title": question_for_lease(bound, nonce),
        "ruling": to_seal,
        "rationale": "Seal only if the reason under the rule is one you accept for a "
                     "standing lease; the reason is inside the sealed bytes.",
        "kind": "net-lease-request",
        "app_id": app_id, "ttl": bound["ttl"], "nonce": nonce,
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
            "seal_this": to_seal}


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
            "SELECT source_norm, target_text, verifier, seal_sig, status, superseded_by, "
            "created_at FROM tm_pairs WHERE id = ?", (pair_id,)).fetchone()
    except sqlite3.Error as exc:
        return {"state": "unreachable", "cause": f"{type(exc).__name__}: {exc}", "path": str(db_path)}
    finally:
        conn.close()
    if row is None:
        return {"state": "empty", "why": "pair_absent"}
    source_norm, target_text, verifier, seal_sig, status, superseded_by, created_at = row
    if superseded_by:
        return {"state": "empty", "why": "superseded"}
    if status != "sealed":
        return {"state": "empty", "why": f"status={status}"}
    if not seal_sig:
        return {"state": "empty", "why": "unsigned"}
    return {"state": "populated", "source_norm": source_norm, "target_text": target_text,
            "verifier": verifier, "seal_sig": seal_sig, "created_at": created_at}


# ── the signer, over a socket ─────────────────────────────────────────────────

def socket_path() -> Path:
    return Path(os.environ.get(SOCKET_ENV, "").strip() or DEFAULT_SOCKET)


def signer_call(request: dict, *, path: Optional[Path] = None, timeout: float = 10.0) -> dict:
    """One request, one reply, newline-delimited JSON over AF_UNIX. Never
    raises: an unreachable signer is ``{"state": "unreachable", ...}``.

    Protocol assertion, client side: the ONLY body the signer may hash is
    the one inside the sealed bytes. A request that carries a task text, a
    hash, or a pair id OUTSIDE the seal is refused before it is sent — those
    would be caller-supplied facts, and the whole point (Loki 7153DC79) is
    that the signer derives every binding from what the operator sealed.
    """
    for forbidden in ("task", "task_text", "task_hash", "pair_id"):
        if forbidden in request or forbidden in (request.get("bound") or {}):
            return {"state": "refused", "field": forbidden,
                    "reason": f"protocol: {forbidden} outside the sealed bytes is not a fact"}
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


def _parse_iso(value) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt.astimezone(timezone.utc)


def _expire(pg, cols: dict, task_id: str) -> bool:
    cur = pg.cursor()
    cur.execute(
        f'UPDATE tasks SET "{cols["status"]}" = %s '  # nosec B608 - cols come from the confirmed schema_profile mapping; values are bound params
        f'WHERE "{cols["task_id"]}" = %s AND "{cols["status"]}" = %s',
        (EXPIRED_STATUS, task_id, HELD_STATUS),
    )
    expired = cur.rowcount == 1
    cur.close()
    pg.commit()
    return expired


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
    held_max_age_s: int = HELD_MAX_AGE_S,
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
    current = now or _now()
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

        # A held row does not wait forever (Loki 7153DC79): past the cap it
        # is refused with the field named and inked, so a request nobody
        # sealed is a record, not a standing offer.
        held_at = _parse_iso(gov.get("held_at"))
        if held_at is not None and (current - held_at).total_seconds() > held_max_age_s:
            out.update(state="refused", field="age",
                       reason=f"held since {gov.get('held_at')} exceeds {held_max_age_s}s")
            counts["refused"] += 1
            _ink(ledger, out, EVENT_REFUSED, {"task_id": task_id, "pair_id": pair_id,
                                              "reason": out["reason"], "field": "age"})
            _expire(pg, cols, task_id)
            rows_out.append(out)
            continue

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

        # This side's view of the row's identity fields. NO hash and NO
        # pair id travel: the signer derives the hash from the sealed body
        # and names the seal by the digest of the bytes it verified. The
        # row's text is compared to the envelope on THIS side, below, by
        # verify_envelope(task=row.task) against the hash the signer bound.
        bound_view = {
            "task_id": task_id,
            "agent": row.get("agent") or gov.get("agent"),
            "submitted_by": row.get("submitted_by") or gov.get("submitted_by"),
            "scope": gov.get("scope"),
            "ttl": str(gov.get("ttl")),
            "nonce": gov.get("nonce"),
        }
        reply = call({
            "op": "sign_task",
            "seal": {k: sealed[k] for k in ("source_norm", "target_text", "verifier", "seal_sig",
                                            "created_at")},
            "bound": bound_view,
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
                           verifier=sealed["verifier"], released_to=RELEASED_STATUS,
                           seal_digest=payload.get("seal_pair_id"))
                counts["minted"] += 1
                _ink(ledger, out, EVENT_MINTED, {
                    "task_id": task_id, "pair_id": pair_id, "verifier": sealed["verifier"],
                    "scope": bound_view["scope"], "expires_at": payload.get("expires_at"),
                    "seal_digest": payload.get("seal_pair_id"), "decision": "c8572a92",
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
        # The reason is INSIDE the sealed bytes; nothing else about the lease
        # travels except this side's view of the identity fields.
        reply = call({
            "op": "sign_lease",
            "seal": {k: sealed[k] for k in ("source_norm", "target_text", "verifier", "seal_sig",
                                            "created_at")},
            "bound": {"app_id": gov.get("app_id"), "ttl": str(gov.get("ttl")), "scope": "lease"},
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


TICK_FIELDS = ["task_id", "task", "status", "agent", "submitted_by", "lane",
               "network_authorization"]


def combined_state(tasks: dict, leases: dict) -> tuple[str, Optional[str]]:
    """The tick's one state from its two halves. ``populated`` if either
    half had something to show; else ``unreachable`` if either half could
    not look (an empty half beside a blind one is not an empty tick — it is
    a tick that could not tell); else ``empty``. Returns ``(state, reason)``,
    ``reason`` naming the blind half's cause when there is one."""
    states = {tasks.get("state"), leases.get("state")}
    if "populated" in states:
        return "populated", None
    if "unreachable" in states:
        blind = tasks if tasks.get("state") == "unreachable" else leases
        return "unreachable", blind.get("reason") or blind.get("cause")
    return "empty", None


def tick(*, app_id: str = "", ledger=None, call: Callable[[dict], dict] = signer_call,
         max_rows: int = 0, pg=None, store=None, db_path: Optional[Path] = None) -> dict:
    """Both halves against the live queue and store, under one three-state
    envelope — what the ``net_authority_drain`` verb (the steward's tick
    step, the desk by hand) and ``python -m willow_mcp.net_authority tick``
    run. ``app_id`` is whose confirmed ``tasks`` mapping to read (default
    ``$WILLOW_APP_ID`` / ``willow``). ``pg``/``store``/``db_path`` are
    injectable for tests.

    Receipt: ``{event, state, reason?, tasks, leases}``. ``tasks`` is
    :func:`drain`'s receipt, ``leases`` is :func:`drain_leases`'s; each keeps
    its own state, and ``state`` is :func:`combined_state` of the two. When
    the queue or the mapping cannot be reached, ``tasks`` and ``leases`` are
    ``None`` and nothing is consumed.
    """
    receipt: dict = {"event": "net_authority_tick", "at": _now().isoformat()}
    if pg is None:
        from .db import get_pg

        pg = get_pg()
    if pg is None:
        receipt.update(state="unreachable", reason="postgres_unavailable", tasks=None, leases=None)
        return receipt
    from . import schema_profile as sp

    who = (app_id or os.environ.get("WILLOW_APP_ID", "willow")).strip() or "willow"
    mapping = sp.resolve(pg, who, "tasks", TICK_FIELDS)
    if "error" in mapping:
        receipt.update(state="unreachable", reason="tasks_mapping_unresolved",
                       error=mapping["error"], tasks=None, leases=None)
        return receipt
    if not mapping.get("confirmed"):
        receipt.update(state="unreachable", reason="tasks_mapping_unconfirmed", tasks=None, leases=None)
        return receipt
    full_cols = {k: v.get("column") for k, v in mapping["fields"].items()}
    if ledger is None:
        try:
            from .governance_ledger import GovernanceLedger
            ledger = GovernanceLedger(pg)
        except Exception:  # noqa: BLE001 — no ledger means receipts are reported, not inked
            ledger = None
    if store is None:
        from .db import Store

        try:
            store = Store()
        except Exception as exc:  # noqa: BLE001 — a store outage is the receipt's to report
            receipt.update(state="unreachable", reason="store_unavailable",
                           error=f"{type(exc).__name__}: {exc}", tasks=None, leases=None)
            return receipt
    kwargs = {}
    if max_rows and max_rows > 0:
        kwargs["max_rows"] = int(max_rows)
    tasks = drain(pg=pg, cols=full_cols, ledger=ledger, store=store, db_path=db_path, call=call,
                  **kwargs)
    leases = drain_leases(store=store, db_path=db_path, ledger=ledger, call=call)
    state, reason = combined_state(tasks, leases)
    receipt.update(state=state, tasks=tasks, leases=leases)
    if reason:
        receipt["reason"] = reason
    return receipt


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
