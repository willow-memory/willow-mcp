"""willow_mcp/manifest_grant_executor.py — a sealed permission grant lands
through a broker verb, signed, never hand-edited.

Verb 18, ``manifest.grant``, sealed under governance decision ``d5504878``
(operator; pair 10ed2707 is the first grant it executes) — see
``src/willow_mcp/bundle/constitutional/syscall-table.json`` row 18.

Rework (pair ``b74019ac``, amending ``d5504878``): the reloader pattern. The
BROKER NEVER PUBLISHES. This module is split into two halves that never run
in the same process identity:

* :func:`manifest_grant_request` — the broker side. Verifies everything: the
  caller is the orchestrator seat, the envelope bounds, the sealed pair's own
  ed25519 ``seal_sig`` (:func:`net_signer.verify_seal`, against the ring built
  from ``config/verifiers.json`` — never the mutable SOIL record's verifier
  field), the sealed text's grammar (seats/groups bound to what was actually
  SEALED, not to the record), no escalation-class group, and the pre-state
  signature of every target seat's manifest. Only once every one of those
  holds does it write ONE signed request under
  ``$WILLOW_HOME/manifest_grants/pending/<pair_id>.json`` (atomic tmp+rename)
  and only THEN ink the FRANK envelope citation — a request that fails to
  persist durably must never have spent the one-use citation, so the citation
  is minted after the file exists on disk, and the file is removed again if
  citing then fails. The request side signs nothing and needs no gpg-agent at
  all: :mod:`pgp` signature VERIFICATION (``gpg --verify``) needs no agent,
  and this half never calls :func:`pgp.sign_detached`.

* :func:`manifest_grant_apply` — the unit side. A trust-owner ``--user``
  systemd unit (``willow-mcp-manifest-grant.timer`` / ``.service``, same
  shape as :mod:`reloader`'s own installer-never-starts split — see
  ``src/willow_mcp/bundle/deploy/willow-mcp-manifest-grant.{service,timer}.template``)
  drains ``pending/``: RE-verifies the seal and every seat's pre-state fresh
  (a pending request can sit for minutes; nothing about it is trusted twice
  without a re-check), then for each seat applies its groups one at a time
  through ``manifest_admin.set_permission`` + ``publish_signed_pair`` under
  the exclusive ``signed_pair_lock`` — with NO ``privileged_publisher``: this
  process already runs AS the trust owner (the unit's own uid), so the sudo
  bridge that the broker could never clear a controlling tty for
  (``publish_via_trust_owner`` needs one; a systemd unit has none) is not
  needed at all. A failure on seat *n*, group *g* rolls back every group
  already granted to that seat and every seat already granted earlier in the
  same request, through the SAME staged ``set_permission`` path — never a
  bare ``Path.write_text``. The request moves to ``done/`` with per-seat
  receipts, or to ``failed/`` with the rollback list and no receipts
  (FRANK is append-only; a receipt for a grant this same call undid is never
  inked).

:func:`manifest_grant_status` reads whichever of ``pending/`` / ``done/`` /
``failed/`` holds ``<pair_id>.json`` and reports which.

Four preconditions, none of which an agent can satisfy on its own:

1. a Nestor pair that is ``sealed`` (a human verified it) whose ed25519
   ``seal_sig`` verifies against a verifier active in the keyring
   (``config/verifiers.json``) — not merely present, not compromised, not
   revoked. The verifier checked is the SEALED ROW's own ``verifier`` field
   (what the seal signature actually covers), never the mutable SOIL
   record's ``nestor_verifier`` — a record can be edited after the seal
   lands (``seal_handler.on_seal``); the sealed row in ``nestor.db`` cannot;
2. the grant is bound to what was actually SEALED, not merely to the mutable
   SOIL governance record. The record's ``seats``/``groups`` fields are
   read-write long after the seal lands (probe P4); the ``target_text`` in
   Nestor's own ``nestor.db`` is the one artifact the seal signature covers.
   This module parses that text with a strict grammar (:func:`ruling_text` /
   :data:`_RULING_RE`) and refuses (``eseal_mismatch``) when the record
   disagrees with it;
3. no escalation-class group, ever, regardless of seal or envelope — the
   PreToolUse manifest guard's own list restated here so a grant can never
   open the door the guard exists to keep shut. This is EXACTLY the 14-item
   packet list (:data:`ESCALATION_GROUPS`) — not the much broader gate-derived
   set a prior draft used, which refused this verb's own first live pair
   (10ed2707, naming ``grove_read``/``grove_write``, neither of which is
   escalation-class here);
4. the caller is the orchestrator seat itself (``is_orchestrator_app``) —
   this is a narrowing REFUSAL layered on top of the manifest gate that
   already authenticated ``app_id`` (the ``@_guarded`` decorator's PGP-backed
   manifest check), not a privilege source in its own right.

Refusals, each with its own errno, all before any envelope citation:

* ``EPERM`` — caller is not the orchestrator seat, or a named group is on
  the escalation list;
* ``EUNREACH`` — nestor.db cannot be read to bind the grant to what was
  sealed;
* ``ENOENT`` — no governance record for ``pair_id``, or no active
  ``manifest.grant`` envelope governs the caller;
* ``EACCES`` — the pair is not ``status=sealed`` (on the SOIL record OR in
  nestor.db), or its seal does not verify (unknown verifier, compromised,
  revoked, bad signature, stale — see :func:`net_signer.verify_seal`);
* ``EINVAL`` — the governance record's ``seats``/``groups`` fields are
  missing or malformed, or the sealed pair's own text does not match the
  strict grammar this verb requires;
* ``eseal_mismatch`` — the sealed text parses cleanly but names different
  seats/groups than the (mutable) governance record — the record was
  edited after the seal;
* ``EAMBIG`` — more than one active envelope governs the call, or the
  bounds do not cover every named seat/group;
* ``EALREADY`` — a pending (or done/failed) request already exists for this
  ``pair_id`` — one request per sealed pair.

Kart-guard note (Loki probe P6): a positive ``gpg-agent`` socket check in
:func:`_gpg_agent_reachable` is NOT a security boundary — any process that
can create a Unix socket file at the expected path (including one running
inside Kart's own bwrap sandbox) can make the check pass, and a real
gpg-agent answering does not prove ITS private key belongs to the operator.
The actual boundary is that :func:`manifest_grant_apply` runs as a distinct
uid (the trust owner's ``--user`` systemd service), never inside a Kart task
and never as the broker; the socket check is a diagnostic that turns a
cryptic gpg failure into a named one, nothing more. The request side
(:func:`manifest_grant_request`) makes no such check at all — it never signs.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

VERB = "manifest.grant"
EVENT = "manifest_granted"

#: The exact escalation set the PreToolUse manifest guard refuses self-grant
#: of (`hooks/pre_tool_use.py:928-940`, `gate.PERMISSION_GROUPS`). A sealed
#: pair naming any of these is refused here too, regardless of seal or
#: envelope bounds. This is EXACTLY the packet's escalation set — nothing
#: more. A prior draft folded in most of gate's other write/admin groups
#: (store_write, grove_write, task_db, ...); that over-broad list refused
#: the verb's own first live pair (10ed2707, which names grove_write) and
#: was never exercised by a test.
ESCALATION_GROUPS = frozenset({
    "task_net", "integration_net", "web_net", "mcp_federation", "grove_relay",
    "orchestrator", "context", "binding", "full_access",
    "envelope_apply", "envelope_write", "frank_write",
    "governance_propose", "governance_sync",
})

#: The strict grammar a sealed pair's ``target_text`` must match for this
#: verb to bind a grant to it. ONE line; anything after it is free-text
#: rationale, ignored here, the same "bound line, then a body the human
#: reads" split :mod:`net_authority` uses for network authority. Bumped by
#: name if the bound field set ever changes.
RULING_FORMAT = "willow-manifest-grant-v1"
_RULING_RE = re.compile(
    r"^" + re.escape(RULING_FORMAT) + r" seats=(?P<seats>[A-Za-z0-9_,\-]+) "
    r"groups=(?P<groups>[A-Za-z0-9_,\-]+)$"
)


def ruling_text(seats: list[str], groups: list[str]) -> str:
    """The ONE line a governance record's ``ruling`` must be (or start with)
    for a grant to bind to it — what the human seals in Nestor is this text;
    parsing it back out is how a grant is bound to what was actually sealed
    rather than to the mutable SOIL record. Order-preserving, comma-joined;
    no field may contain a comma."""
    for value in (*seats, *groups):
        if "," in value or " " in value:
            raise ValueError(f"seat/group name contains a separator: {value!r}")
    return f"{RULING_FORMAT} seats={','.join(seats)} groups={','.join(groups)}"


def _parse_ruling_text(text: str) -> Optional[dict]:
    """Inverse of :func:`ruling_text`, read from the FIRST line of sealed
    ``target_text``. ``None`` for anything that does not match — a caller
    must never guess seats/groups out of free-form prose. (Pair ``d23a3726``
    is the live example of a pair sealed correctly in this grammar; pair
    ``10ed2707`` — prose, no grammar line — is the example this must refuse,
    naming the grammar in the refusal rather than guessing at the English.)"""
    first_line = (text or "").strip().splitlines()[:1]
    if not first_line:
        return None
    m = _RULING_RE.match(first_line[0].strip())
    if not m:
        return None
    seats = [s for s in m.group("seats").split(",") if s]
    groups = [g for g in m.group("groups").split(",") if g]
    if not seats or not groups:
        return None
    return {"apps": seats, "groups": groups}


def _refuse(errno: str, reason: str, **extra) -> dict:
    return {"ok": False, "error": errno, "reason": reason, **extra}


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _in_kart() -> bool:
    return bool(
        os.environ.get("WILLOW_IN_KART", "").strip()
        or os.environ.get("KART_TASK_ID", "").strip()
    )


def _gpg_agent_reachable() -> bool:
    """A positive gpg-agent socket check — a diagnostic, NOT a security
    boundary (module docstring, Loki probe P6). Used only by
    :func:`manifest_grant_apply`, which signs; :func:`manifest_grant_request`
    never calls this."""
    try:
        result = subprocess.run(
            ["gpgconf", "--list-dirs", "agent-socket"],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    sock = Path(result.stdout.strip())
    try:
        return sock.is_socket()
    except OSError:
        return False


# ── governance record + sealed pair lookups ──────────────────────────────────

def _load_sealed_pair(pair_id: str, *, store=None) -> dict:
    """The governance record naming ``pair_id`` — same lookup
    :func:`seal_handler.on_seal` performs when a seal lands, reused here
    read-only. Returns ``{"ok": False, ...}`` on any miss; never raises."""
    from .db import Store
    from . import seal_handler

    st = store if store is not None else Store()
    match = seal_handler._find_governance_record(st, pair_id)
    if match is None:
        return _refuse(
            "ENOENT",
            f"no governance record for pair_id={pair_id!r} — sealed elsewhere "
            "or not tracked in projects_willow_governance_decisions",
        )
    record_id, record = match
    return {"ok": True, "record_id": record_id, "record": record}


def _seats_and_groups(record: dict) -> dict:
    """``{"apps": [...], "groups": [...]}`` from a governance record's
    ``seats``/``groups`` fields, or an EINVAL refusal."""
    seats = record.get("seats")
    groups = record.get("groups")
    if not isinstance(seats, list) or not seats or not all(isinstance(s, str) and s for s in seats):
        return _refuse("EINVAL", "governance record's 'seats' must be a non-empty list of app_id strings")
    if not isinstance(groups, list) or not groups or not all(isinstance(g, str) and g for g in groups):
        return _refuse("EINVAL", "governance record's 'groups' must be a non-empty list of group-name strings")
    return {"ok": True, "apps": list(seats), "groups": list(groups)}


def _load_sealed_ruling(pair_id: str, *, db_path: Optional[Path] = None) -> dict:
    """The pair's own sealed bytes from ``nestor.db`` — the artifact the
    seal signature covers — three-state, never raises. Reuses
    :func:`net_authority.read_sealed_pair`, which is already generic over
    any sealed decision pair keyed by id, not net-authority-specific."""
    from . import seal_handler
    from .net_authority import read_sealed_pair

    resolved = db_path if db_path is not None else seal_handler._nestor_db_path()
    return read_sealed_pair(pair_id, resolved)


def _ring_from_keyring(kr) -> dict[str, dict]:
    """The verify_seal ring shape (``{name: {key, kind, revoked_at,
    compromised}}``) built from the process's OWN keyring
    (``config/verifiers.json`` via :func:`keyring.get_keyring`) — never from
    :mod:`net_signer`'s separate exported public-only ring file, which
    hard-refuses a keyring holding any private half. The operator's own
    signing entries legitimately carry a private half in this same file;
    verification only ever reads ``.key`` (the public half), never
    ``.private``."""
    return {
        e.name: {"key": e.key, "kind": e.kind, "revoked_at": e.revoked_at, "compromised": e.compromised}
        for e in kr.entries()
    }


def _bind_to_seal(pair_id: str, apps: list[str], groups: list[str], *,
                   db_path: Optional[Path] = None) -> Optional[dict]:
    """Refuse unless the sealed pair's ed25519 signature verifies AND its
    own text names exactly ``apps``/``groups`` (read off the mutable SOIL
    record). Returns a refusal dict, or ``None`` when the grant is bound
    cleanly and the seal is genuine.

    Rework (pair ``b74019ac``): the seal binding used to compare text only,
    never checking ``seal_sig`` at all — a garbage signature on an
    otherwise-well-formed sealed row was granted with a receipt. This now
    calls :func:`net_signer.verify_seal` against a ring built from
    ``config/verifiers.json``, using the SEALED ROW's own ``verifier`` field
    — never the SOIL record's ``nestor_verifier``, which is mutable after
    the seal lands and is not what the signature covers.
    """
    from . import keyring as _keyring
    from . import net_signer

    sealed = _load_sealed_ruling(pair_id, db_path=db_path)
    state = sealed.get("state")
    if state == "unreachable":
        return _refuse(
            "EUNREACH",
            f"nestor.db unreachable ({sealed.get('cause')}) — cannot bind this "
            "grant to what was actually sealed; the SOIL record alone is not enough",
        )
    if state != "populated":
        return _refuse(
            "EACCES",
            f"pair_id={pair_id!r} is not a populated sealed pair in nestor.db "
            f"({sealed.get('why')}) — a governance record marked status=sealed "
            "is not enough on its own; the pair itself must be sealed",
        )

    ring_kr = _keyring.get_keyring()
    if ring_kr is None:
        return _refuse(
            "EACCES",
            "no keyring configured (config/verifiers.json via WILLOW_KEYRING) — "
            "a grant cannot verify a seal without a ring to verify it against",
        )
    ok, reason, field = net_signer.verify_seal(sealed, _ring_from_keyring(ring_kr))
    if not ok:
        return _refuse(
            "EACCES",
            f"sealed pair {pair_id!r} does not verify: {reason} (field={field!r}) — "
            "a garbage or unverifiable seal_sig is refused regardless of what the "
            "SOIL record's own nestor_verifier field claims",
            field=field,
        )

    parsed = _parse_ruling_text(sealed.get("target_text", ""))
    if parsed is None:
        return _refuse(
            "EINVAL",
            f"sealed pair {pair_id!r} text does not match the strict manifest.grant "
            f"grammar ({RULING_FORMAT!r} seats=<a,b> groups=<c,d>, one line, prose "
            "below it) — refusing to guess what was actually sealed",
            sealed_text=sealed.get("target_text"),
        )
    if set(parsed["apps"]) != set(apps) or set(parsed["groups"]) != set(groups):
        return _refuse(
            "eseal_mismatch",
            f"governance record's seats/groups for pair_id={pair_id!r} do not match "
            "what the sealed pair's own text says — the record was edited after the "
            "seal; refusing rather than trusting the mutable record over the seal",
            sealed_apps=parsed["apps"], sealed_groups=parsed["groups"],
            record_apps=apps, record_groups=groups,
        )
    return None


# ── substrings from set_permission's own RuntimeError messages ─────────────

_ESIGN_FINGERPRINT_ABSENT = "WILLOW_PGP_FINGERPRINT is unset"
_ESIGN_PRESTATE = "current manifest signature is not valid"


def _classify_set_permission_error(exc: RuntimeError) -> str:
    msg = str(exc)
    if _ESIGN_FINGERPRINT_ABSENT in msg:
        return "efingerprint_absent"
    if _ESIGN_PRESTATE in msg:
        return "esig_prestate"
    return "esign"


def _seat_pre_state(seat: str, apps_root: Path) -> dict:
    """Pre-state a request records / re-checks for one seat: does the
    manifest exist, does its EXISTING signature (if any) verify, and its
    content/sig digests — refused ``enomanifest`` / ``efingerprint_absent`` /
    ``esig_prestate`` on the spot, never touching anything (probe P1: never
    launder a tampered, currently-denied manifest into a freshly valid one;
    probe P2: never write unsigned over signed)."""
    from . import pgp

    manifest_path = apps_root / seat / "manifest.json"
    if not manifest_path.is_file():
        return {"ok": False, "app_id": seat, "error": "enomanifest",
                "reason": f"no manifest at {manifest_path} — manifest.grant adds "
                          "groups to an existing seat, it does not create one"}
    existing_sig = pgp.read_detached_sig_bytes(manifest_path)
    fingerprint = pgp.expected_fingerprint()
    if existing_sig is not None and not fingerprint:
        return {"ok": False, "app_id": seat, "error": "efingerprint_absent",
                "reason": "manifest already carries a detached signature but "
                          "WILLOW_PGP_FINGERPRINT is unset — refusing to write "
                          "unsigned over signed"}
    if existing_sig is not None:
        ok, detail = pgp.verify_detached(manifest_path, fingerprint=fingerprint)
        if not ok:
            return {"ok": False, "app_id": seat, "error": "esig_prestate",
                    "reason": "existing manifest signature does not verify against "
                              f"WILLOW_PGP_FINGERPRINT; refusing to mutate a tampered "
                              f"manifest ({detail})"}
    manifest_bytes = manifest_path.read_bytes()
    return {
        "ok": True, "app_id": seat,
        "manifest_sha256": _digest(manifest_bytes),
        "sig_sha256": _digest(existing_sig) if existing_sig else None,
    }


# ── the pending/done/failed store ────────────────────────────────────────────

def _grants_root(grants_root: Optional[Path] = None) -> Path:
    if grants_root is not None:
        return Path(grants_root)
    from . import paths
    return paths.willow_home() / "manifest_grants"


def _pending_path(grants_root: Path, pair_id: str) -> Path:
    return grants_root / "pending" / f"{pair_id}.json"


def _write_json_atomic(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    try:
        tmp.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _existing_request_state(grants_root: Path, pair_id: str) -> Optional[str]:
    for state in ("pending", "done", "failed"):
        if (grants_root / state / f"{pair_id}.json").is_file():
            return state
    return None


def manifest_grant_status(pair_id: str, *, grants_root: Optional[Path] = None) -> dict:
    """Three-state (plus not_found) read of one request: ``pending`` (the
    unit has not drained it yet), ``done`` (granted, receipts attached),
    ``failed`` (refused or rolled back at apply time), or ``not_found`` (no
    request was ever made for this ``pair_id``). Read-only, never blocks."""
    root = _grants_root(grants_root)
    state = _existing_request_state(root, pair_id)
    if state is None:
        return {"state": "not_found", "pair_id": pair_id}
    path = root / state / f"{pair_id}.json"
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"state": "unreachable", "pair_id": pair_id, "cause": f"{type(exc).__name__}: {exc}"}
    return {"state": state, "pair_id": pair_id, "path": str(path), **record}


# ── request: the broker side — verify everything, write, then cite ─────────

def manifest_grant_request(
    app_id: str,
    *,
    envelope_id: str,
    pair_id: str,
    project: str = "",
    session: str = "",
    task_id: str = "",
    ledger=None,
    store=None,
    apps_root: Optional[Path] = None,
    db_path: Optional[Path] = None,
    grants_root: Optional[Path] = None,
) -> dict:
    """Verify a sealed Nestor pair against every precondition (module
    docstring), write ONE signed request under
    ``$WILLOW_HOME/manifest_grants/pending/<pair_id>.json``, and only then
    ink the FRANK envelope citation. Never signs, never touches a seat's
    manifest — that is :func:`manifest_grant_apply`'s job, run by a different
    process identity (the trust-owner unit).

    Returns ``{ok: True, state: "requested", pending_path, citation_id,
    envelope_id, pair_id}`` or a refusal dict. ``app_id`` must be the
    orchestrator seat; ``ledger`` is a :class:`GovernanceLedger`;
    ``store``/``apps_root``/``db_path``/``grants_root`` are test seams.
    """
    from .envelopes import EnvelopeAuthority, governing_envelopes
    from .human_session import is_orchestrator_app

    if not is_orchestrator_app(app_id):
        return _refuse(
            "EPERM",
            f"manifest.grant is orchestrator-only; {app_id!r} may not call it "
            "regardless of any envelope — a specialist requesting a group for "
            "itself or a peer routes through the operator, never this verb",
        )

    grants_root_p = _grants_root(grants_root)
    existing = _existing_request_state(grants_root_p, pair_id)
    if existing is not None:
        return _refuse(
            "EALREADY",
            f"a manifest.grant request for pair_id={pair_id!r} already exists "
            f"({existing}) — one request per sealed pair",
            state=existing,
        )

    pair_result = _load_sealed_pair(pair_id, store=store)
    if not pair_result.get("ok"):
        return pair_result
    record = pair_result["record"]
    if record.get("status") != "sealed":
        return _refuse(
            "EACCES",
            f"pair_id={pair_id!r} governance record is status={record.get('status')!r}, "
            "not 'sealed' — a grant only ever executes a human-sealed decision",
        )

    parsed = _seats_and_groups(record)
    if not parsed.get("ok"):
        return parsed
    apps, groups = parsed["apps"], parsed["groups"]

    seal_refusal = _bind_to_seal(pair_id, apps, groups, db_path=db_path)
    if seal_refusal is not None:
        return seal_refusal

    escalating = sorted(set(groups) & ESCALATION_GROUPS)
    if escalating:
        return _refuse(
            "EPERM",
            f"pair_id={pair_id!r} names escalation-class group(s) {escalating!r} — "
            "never grantable through manifest.grant, regardless of seal or "
            "envelope bounds (same list the PreToolUse manifest guard refuses "
            "self-grant of)",
            escalating=escalating,
        )

    if ledger is None:
        return _refuse(
            "EAMBIG",
            "no governance ledger: a grant that cannot be cited is not performed",
        )

    from . import gate as _gate

    root = apps_root if apps_root is not None else _gate._apps_root()
    pre_state: dict[str, dict] = {}
    for seat in apps:
        outcome = _seat_pre_state(seat, root)
        if not outcome.get("ok"):
            return {"ok": False, "error": outcome["error"], "reason": outcome["reason"], "app_id": seat}
        pre_state[seat] = {"manifest_sha256": outcome["manifest_sha256"], "sig_sha256": outcome["sig_sha256"]}

    call_args = {"apps": apps, "groups": groups}
    try:
        rows = governing_envelopes(VERB, app_id)
    except (OSError, ValueError) as exc:
        return _refuse("EAMBIG", f"envelope registry unreadable: {exc}")
    matches = [row["id"] for row in rows]
    if envelope_id:
        if envelope_id not in matches:
            return _refuse(
                "ENOENT", f"envelope {envelope_id!r} does not govern {VERB} for {app_id!r}",
                envelope_ids=matches,
            )
        matches = [envelope_id]
    if not matches:
        return _refuse("ENOENT", f"no active {VERB} envelope governs {app_id!r}")
    if len(matches) > 1:
        return _refuse(
            "EAMBIG", f"multiple active {VERB} envelopes govern {app_id!r} — "
                      f"pass envelope_id to name which one to cite",
            envelope_ids=matches,
        )

    # Everything above holds. Write the request FIRST — durable on disk
    # before a single citation is spent — then cite. If the citation is then
    # refused (bounds, expiry, max_count), the file is removed again: a
    # request nobody may act on is not left sitting in pending/.
    pending_path = _pending_path(grants_root_p, pair_id)
    pending_record = {
        "pair_id": pair_id, "envelope_id": None, "citation_id": None,
        "actor": app_id, "apps": apps, "groups": groups,
        "project": project or "willow-mcp", "session": session,
        "requested_at": _now_iso(), "pre_state": pre_state,
    }
    _write_json_atomic(pending_path, pending_record)

    result = EnvelopeAuthority(ledger).authorize_and_cite(
        matches[0], actor=app_id, verb=VERB, call_args=call_args,
        project=project or "willow-mcp", session=session,
    )
    if not result.get("ok"):
        pending_path.unlink(missing_ok=True)
        errno = result.get("errno", "EAMBIG")
        reason = result.get("reason", "")
        fields = result.get("fields")
        return _refuse(errno, reason, envelope_id=matches[0],
                       citation_id=result.get("citation_id"), fields=fields)

    pending_record["envelope_id"] = matches[0]
    pending_record["citation_id"] = result.get("citation_id")
    _write_json_atomic(pending_path, pending_record)

    return {
        "ok": True, "state": "requested", "pending_path": str(pending_path),
        "pair_id": pair_id, "envelope_id": matches[0],
        "citation_id": result.get("citation_id"), "apps": apps, "groups": groups,
    }


# ── apply: the unit side — re-verify, act, roll back, receipt ──────────────

def _apply_one_seat(app_id: str, groups: list[str], *, apps_root: Path) -> dict:
    """Add ``groups`` to one seat's manifest via
    ``manifest_admin.set_permission`` — NO ``privileged_publisher``: this
    process runs AS the trust owner (the apply unit's own uid), so
    ``publish_signed_pair`` writes the trust root directly under
    ``signed_pair_lock``; there is no sudo bridge to cross."""
    from . import manifest_admin, pgp

    pre = _seat_pre_state(app_id, apps_root)
    if not pre.get("ok"):
        return {"ok": False, "app_id": app_id, "error": pre["error"], "reason": pre["reason"]}

    manifest_path = apps_root / app_id / "manifest.json"
    before_digest = pre["manifest_sha256"]
    current = json.loads(manifest_path.read_text(encoding="utf-8"))
    perms = list(current.get("permissions") or [])
    added = [g for g in groups if g not in perms]
    if not added:
        return {"ok": True, "app_id": app_id, "groups": [], "changed": False,
                "manifest_sha256": before_digest, "manifest_sha256_before": before_digest,
                "unsigned": pre["sig_sha256"] is None}

    granted_now: list[str] = []
    try:
        for g in added:
            manifest_admin.set_permission(app_id, g, True)
            granted_now.append(g)
    except OSError as exc:
        _revoke_groups(app_id, granted_now)
        try:
            owning_uid = manifest_path.stat().st_uid
        except OSError:
            owning_uid = None
        return {"ok": False, "app_id": app_id, "error": "eperm",
                "reason": f"{type(exc).__name__}: {exc}",
                "path": str(manifest_path), "owning_uid": owning_uid}
    except RuntimeError as exc:
        _revoke_groups(app_id, granted_now)
        return {"ok": False, "app_id": app_id, "error": _classify_set_permission_error(exc),
                "reason": str(exc)}
    except Exception as exc:  # noqa: BLE001 — never let an exception escape a citation already inked
        _revoke_groups(app_id, granted_now)
        return {"ok": False, "app_id": app_id, "error": "eunexpected",
                "reason": f"{type(exc).__name__}: {exc}"}

    after_text = manifest_path.read_text(encoding="utf-8")
    after_digest = _digest(after_text.encode("utf-8"))
    sig_after = pgp.read_detached_sig_bytes(manifest_path)
    return {
        "ok": True, "app_id": app_id, "groups": granted_now, "changed": True,
        "manifest_sha256": after_digest, "manifest_sha256_before": before_digest,
        "sig_sha256": _digest(sig_after) if sig_after else "",
        "unsigned": sig_after is None,
    }


def _revoke_groups(app_id: str, groups: list[str]) -> None:
    """Best-effort compensating undo of groups THIS call already granted,
    when a LATER group for the SAME seat fails partway through. Never
    raises: the outer refusal this backs out of is what gets reported."""
    from . import manifest_admin

    for g in reversed(groups):
        try:
            manifest_admin.set_permission(app_id, g, False)
        except Exception:  # noqa: BLE001 — best-effort undo only
            pass


def _rollback_seat(app_id: str, groups: list[str]) -> None:
    """Best-effort undo of a whole seat this call already granted, when a
    LATER seat in the same request fails — through the SAME staged
    ``set_permission`` path a grant used, never a direct byte restore."""
    _revoke_groups(app_id, groups)


def _move(path: Path, dest_dir: Path, record: dict) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / path.name
    _write_json_atomic(dest, record)
    path.unlink(missing_ok=True)
    return dest


def _apply_one(record: dict, path: Path, *, ledger, apps_root: Path,
                db_path: Optional[Path], grants_root: Path) -> dict:
    pair_id = record.get("pair_id")
    apps = record.get("apps") or []
    groups = record.get("groups") or []

    seal_refusal = _bind_to_seal(pair_id, apps, groups, db_path=db_path)
    if seal_refusal is not None:
        _move(path, grants_root / "failed", {**record, "result": seal_refusal})
        return {"pair_id": pair_id, "ok": False, **seal_refusal}

    pre_state = record.get("pre_state") or {}
    for seat in apps:
        seat_now = _seat_pre_state(seat, apps_root)
        if not seat_now.get("ok"):
            out = {"ok": False, "error": seat_now["error"], "reason": seat_now["reason"], "app_id": seat}
            _move(path, grants_root / "failed", {**record, "result": out})
            return {"pair_id": pair_id, **out}
        recorded = pre_state.get(seat) or {}
        if recorded.get("manifest_sha256") and recorded["manifest_sha256"] != seat_now["manifest_sha256"]:
            out = {"ok": False, "error": "edrift", "app_id": seat,
                   "reason": f"{seat}'s manifest changed since the request was made — "
                             "refusing to apply against a moved target"}
            _move(path, grants_root / "failed", {**record, "result": out})
            return {"pair_id": pair_id, **out}

    from . import pgp as _pgp_precheck
    if _pgp_precheck.pgp_enabled() and not _gpg_agent_reachable():
        out = {"ok": False, "error": "EUNREACH",
               "reason": "no reachable gpg-agent socket for the apply unit — diagnostic "
                         "only (module docstring), but nothing can be signed without one"}
        _move(path, grants_root / "failed", {**record, "result": out})
        return {"pair_id": pair_id, **out}

    granted: list[dict] = []
    refused: list[dict] = []
    rollback_stack: list[tuple[str, list[str]]] = []
    pending_receipts: list[tuple[dict, dict]] = []

    for seat in apps:
        outcome = _apply_one_seat(seat, groups, apps_root=apps_root)
        if not outcome.get("ok"):
            refused.append(outcome)
            for undone_app, undone_groups in reversed(rollback_stack):
                _rollback_seat(undone_app, undone_groups)
            out = {
                "ok": False, "error": outcome.get("error", "EAMBIG"),
                "reason": (f"seat {seat!r} refused ({outcome.get('reason')}); rolled back "
                           f"{len(rollback_stack)} already-granted seat(s) in this request"),
                "granted": [], "refused": refused,
                "rolled_back": [a for a, _ in rollback_stack],
            }
            _move(path, grants_root / "failed", {**record, "result": out})
            return {"pair_id": pair_id, **out}

        if outcome.get("changed"):
            rollback_stack.append((seat, outcome.get("groups", [])))
        granted.append({
            "app_id": seat, "groups": outcome.get("groups", []),
            "manifest_sha256": outcome.get("manifest_sha256"),
            "sig_sha256": outcome.get("sig_sha256", ""),
            "unsigned": outcome.get("unsigned", False),
        })
        if not outcome.get("changed"):
            continue
        payload = {
            "actor": record.get("actor"), "app_id": seat, "pair_id": pair_id,
            "envelope_id": record.get("envelope_id"), "citation_id": record.get("citation_id"),
            "groups_added": outcome.get("groups", []),
            "manifest_sha256_before": outcome.get("manifest_sha256_before"),
            "manifest_sha256_after": outcome.get("manifest_sha256"),
            "sig_sha256": outcome.get("sig_sha256", ""),
            "session": record.get("session"),
        }
        pending_receipts.append((granted[-1], payload))

    receipt_ids: list[str] = []
    if ledger is not None:
        for granted_entry, payload in pending_receipts:
            try:
                rec = ledger.append(record.get("project") or "willow-mcp", EVENT, payload)
                receipt_ids.append(rec)
            except Exception as exc:  # noqa: BLE001 — the grant happened; report, never hide
                granted_entry["receipt_error"] = f"{type(exc).__name__}: {exc}"

    out = {"ok": True, "granted": granted, "refused": refused, "receipt_ids": receipt_ids}
    _move(path, grants_root / "done", {**record, "result": out})
    return {"pair_id": pair_id, **out}


def manifest_grant_apply(
    *,
    pair_id: Optional[str] = None,
    ledger=None,
    apps_root: Optional[Path] = None,
    db_path: Optional[Path] = None,
    grants_root: Optional[Path] = None,
) -> dict:
    """The unit side: drain ``pending/`` (or just ``pair_id``, when named),
    re-verifying the seal and every seat's pre-state fresh before acting.
    Runs as the trust owner — no ``privileged_publisher``, no sudo bridge.
    Never raises past this call; a per-request exception is reported and the
    request moved to ``failed/`` rather than left to retry forever silently.
    """
    if _in_kart():
        # Advisory, not the boundary (module docstring): the real boundary is
        # that the apply unit runs as a distinct uid, never inside Kart. This
        # just turns "ran by accident in the wrong place" into a named
        # refusal instead of a confusing sudo/gpg failure three steps later.
        return {"ok": False, "state": "refused", "error": "EUNREACH",
                "reason": "manifest_grant_apply does not run inside Kart — it runs as the "
                          "trust-owner systemd --user unit, a distinct uid from any Kart task",
                "processed": []}
    root = _grants_root(grants_root)
    pending_dir = root / "pending"
    if not pending_dir.is_dir():
        return {"ok": True, "state": "empty", "processed": []}
    if pair_id:
        files = [p for p in [pending_dir / f"{pair_id}.json"] if p.is_file()]
    else:
        files = sorted(pending_dir.glob("*.json"))
    if not files:
        return {"ok": True, "state": "empty", "processed": []}

    from . import gate
    apps_root_p = apps_root if apps_root is not None else gate._apps_root()

    processed: list[dict] = []
    for f in files:
        try:
            record = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            out = {"pair_id": f.stem, "ok": False, "error": "ecorrupt",
                   "reason": f"{type(exc).__name__}: {exc}"}
            try:
                _move(f, root / "failed", {"pair_id": f.stem, "result": out})
            except OSError:
                pass
            processed.append(out)
            continue
        try:
            processed.append(_apply_one(record, f, ledger=ledger, apps_root=apps_root_p,
                                        db_path=db_path, grants_root=root))
        except Exception as exc:  # noqa: BLE001 — never let one bad request wedge the drain
            out = {"pair_id": record.get("pair_id", f.stem), "ok": False, "error": "eunexpected",
                   "reason": f"{type(exc).__name__}: {exc}"}
            try:
                _move(f, root / "failed", {**record, "result": out})
            except OSError:
                pass
            processed.append(out)

    return {"ok": all(r.get("ok") for r in processed), "state": "populated", "processed": processed}
