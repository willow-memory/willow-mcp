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

* :func:`manifest_grant_apply` — the unit side. Rework (pair ``6bd11def``,
  amending ``b74019ac``): this runs as a ``willow-mcp-manifest-grant.timer`` /
  ``.service`` unit installed in the BROKER's own ``--user`` manager, under
  the broker's OWN uid — no ``User=`` line, no trust-owner claim. systemd's
  own manual is explicit that a non-root ``--user`` manager may only run a
  unit as the identity it is already running as (systemd.exec, "the only
  valid setting is the same user the user's service manager is running
  as"); a prior draft's ``User=@TRUST_OWNER@`` line could therefore never
  start at all (217/USER), and "runs as a distinct trust-owner uid" was
  never true of a broker-installed ``--user`` unit regardless of what the
  template said. What this split actually buys, restated honestly: the
  request/apply split is an AUDIT-TRAIL boundary, not a privilege one — see
  the module-level note above :func:`_broker_signing_key_path` (the signing
  note) and :func:`_apply_one`'s own signature/citation checks — named by
  function rather than by line number, since a fixed line range goes stale
  the moment either section grows (a prior version of this note cited
  ``executor:294-321 / 973-976``, which had already drifted to
  ``352-397 / 1122-1128`` by Loki audit 5 and would drift again the moment
  this docstring itself changed). The real privilege boundary on this box is
  that ``config/verifiers.json``, ``env`` and ``manifest_grants/`` (its
  ``broker_signing_key`` included) are ABSENT from Kart's view of
  ``$WILLOW_HOME`` — not merely read-only-bound; only ``nestor.db`` is
  actually a read-only bind there (measured from inside the sandbox, Loki
  audit 5) — and a uid split (gap ``85716b25d9a8``), if the operator ever
  performs one — then, and only then, does
  ``manifest_grant_apply`` running as a distinct identity from the broker
  mean anything. ``manifest_grant_apply`` drains ``pending/``: RE-verifies
  the seal and every seat's pre-state fresh (a pending request can sit for
  minutes; nothing about it is trusted twice without a re-check), then for
  each seat applies its groups one at a time through
  ``manifest_admin.set_permission`` + ``publish_signed_pair`` under
  the exclusive ``signed_pair_lock`` — with NO ``privileged_publisher``: this
  process runs as the broker's own uid, the same uid that already owns the
  trust root on this box, so the sudo bridge that a cross-uid publish would
  need (``publish_via_trust_owner``, which needs a controlling tty the
  broker can never clear) is not needed at all. A failure on seat *n*, group *g* rolls back every group
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
3. no escalation-class group, ever, regardless of seal or envelope — a
   dedicated escalation set for THIS verb (:data:`ESCALATION_GROUPS`,
   exactly the 14-item packet list), never the PreToolUse manifest guard's
   OWN list, which is broader still (``hooks/pre_tool_use.py:928-940``
   names ~37 groups, including ``store_write``/``grove_write``/
   ``task_queue``) and is enforced separately, unchanged, by the guard
   itself. A prior draft folded most of the guard's broader set in here
   too, which refused this verb's own first live pair (10ed2707, naming
   ``grove_read``/``grove_write``, neither of which is escalation-class
   for THIS verb — both are for the guard's, which is why the guard still
   refuses a seat's own self-grant of them regardless of what this verb
   does);
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
The actual boundary :func:`manifest_grant_apply` enforces is narrower than a
prior draft claimed: it refuses to run inside a Kart task at all
(:func:`_in_kart`), and it refuses to run as any uid other than the one that
owns ``apps_root`` (the trust root). On THIS box those two things do not add
up to a distinct-uid guarantee — the broker itself owns ``apps_root``, so
"the uid that owns apps_root" and "the broker's own uid" are the same
uid (gap ``85716b25d9a8``: the actual uid split is not built). The socket
check is a diagnostic that turns a cryptic gpg failure into a named one,
nothing more. The request side (:func:`manifest_grant_request`) makes no
such check at all — it never signs.

Known limits, stated plainly rather than left to be rediscovered (Loki
audit 5):

* CITE-CRASH — a ``pending/`` record with no citation to confirm (its write
  crashed before ``citation_id`` landed, or it was never signed) is refused
  ``eforged`` by :func:`_apply_one`. ``eforged`` is not in
  :data:`RETRYABLE_ERRORS`, so this is terminal by shape: the spent citation
  is not recoverable through any call this module offers, and the operator
  clears the ``failed/`` entry by hand;
* an ``eunexpected`` raised AFTER a seat's manifest was already granted and
  its FRANK receipt already inked (e.g. a crash between the grant and the
  move to ``done/``) retries like any other ``eunexpected`` — but the
  retried apply then finds the seat's manifest has moved since the
  request's ``pre_state`` was recorded, and correctly refuses ``edrift``.
  The request ends up ``failed`` even though the grant is live and
  receipted in FRANK: truthful in FRANK, misleading in
  :func:`manifest_grant_status`;
* MOVE — a request the apply uid cannot move out of ``pending/`` (its
  ``failed/`` destination unwritable, say) can leave a half-state: the
  original stays in ``pending/`` untouched, a copy of the failure lands in
  ``failed/`` on every tick, :func:`manifest_grant_status` still reports
  ``pending`` (``_existing_request_state`` checks ``pending/`` first), and
  a retry refuses ``EALREADY`` rather than requeuing anything;
* :func:`manifest_grant_retry` proceeds with ``ledger=None`` when Postgres
  is unreachable at retry time: the request is requeued to ``pending/``
  with no FRANK ``manifest_grant_retried`` event and ``receipt_id=None`` —
  unlike :func:`manifest_grant_request`, which refuses outright rather than
  proceed unrecorded when Postgres is down;
* :meth:`GovernanceLedger.all_events` — used both by the FRANK
  ``manifest_granted`` replay check above :data:`EVENT` and by
  :func:`_apply_one`'s own citation lookup — fetches every row of the
  event type and filters in Python; O(N) per tick, not indexed by
  ``citation_id`` or ``envelope_id``.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

VERB = "manifest.grant"
EVENT = "manifest_granted"

#: This verb's OWN escalation set — the packet's list, exactly, no more.
#: NOT the same list the PreToolUse manifest guard refuses self-grant of
#: (`hooks/pre_tool_use.py:928-940`, `gate.PERMISSION_GROUPS`), which is
#: broader (~37 groups, including store_write/grove_write/task_queue) and
#: enforced separately by the guard regardless of what this verb grants. A
#: sealed pair naming any of THESE 14 is refused here, regardless of seal
#: or envelope bounds. A prior draft folded in most of the guard's broader
#: set instead; that over-broad list refused the verb's own first live
#: pair (10ed2707, which names grove_write) and was never exercised by a
#: test.
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


#: A lock older than this with no live holder is reclaimed (Loki audit 4,
#: MEDIUM). Ten minutes is well past any real request's lock hold time (the
#: lock spans one `_manifest_grant_request_locked` call — file writes and a
#: single envelope citation, not network I/O) and well short of "a human
#: would notice and intervene first."
_STALE_LOCK_AGE_S = 600.0


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, owned by someone else — never treat as dead
    except OSError:
        return True  # unknown — never treat as dead on ambiguous failure
    return True


def _stale_lock(lock_path: Path, *, max_age_s: float = _STALE_LOCK_AGE_S) -> bool:
    """True only when the lock is provably abandoned AND at least
    ``max_age_s`` old. A lock naming a pid that is still alive, or that is
    simply young, is never reclaimed — ambiguity always resolves to 'leave
    it alone.'

    A legacy body-less lock (the pre-``pid``/``created_at`` format wrote no
    body at all) carries no pid to check; its file mtime is the only signal
    available, so it is treated as stale once that mtime is at least
    ``max_age_s`` old — the same bound a pid-bearing lock is held to. Loki
    audit 5 noted this case was previously never reclaimed at all (no
    deployment has produced one yet, but the format existed before this
    lock body did)."""
    try:
        raw = lock_path.read_text(encoding="utf-8")
        mtime = lock_path.stat().st_mtime
    except OSError:
        return False
    text = raw.strip()
    if not text:
        return (time.time() - mtime) >= max_age_s
    try:
        info = json.loads(text)
        pid = int(info["pid"])
        created_at = info["created_at"]
    except (ValueError, KeyError, TypeError):
        return False
    try:
        created = datetime.fromisoformat(created_at)
    except (TypeError, ValueError):
        return False
    age_s = (datetime.now(timezone.utc) - created).total_seconds()
    if age_s < max_age_s:
        return False
    return not _pid_alive(pid)


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


# ── the broker's own signature over a pending request ───────────────────────
#
# Loki audit 3, finding 2 ("forgeable pending/"): apply used to re-verify only
# the seal and (optionally) pre-state drift — never the escalation set, never
# that the citation it names actually exists in FRANK with outcome=granted,
# never that the file was written by manifest_grant_request at all. Anything
# with $WILLOW_HOME write access (any Kart task, since WILLOW_HOME and
# config/verifiers.json are broker-uid-writable there) could hand-write a
# pending/<pair_id>.json and have it applied.
#
# The fix is a detached ed25519 signature the BROKER holds and the APPLY
# side can verify — not net_signer's key (that key belongs to the egress
# key's owner, a different uid than the broker's and unreachable to it by
# design; sharing it here would break that split) and not pgp.sign_detached
# (the request side deliberately signs nothing with gpg and needs no
# gpg-agent — module docstring). Instead: a dedicated ed25519 keypair
# generated on first use under ``<grants_root>/broker_signing_key`` (0600,
# broker-owned, private half never leaves this process) with its public half
# exported alongside it at ``<grants_root>/broker_public_key.pub`` (0644).
#
# Loki audit 4, HIGH ("signing key adds nothing on this box"): this
# signature is an AUDIT-TRAIL binding, not a privilege boundary, and this
# comment previously overclaimed it as one ("a file this process did not
# write and sign is never actioned" — false on a single-uid box). What it
# actually proves: the pending record was produced by SOME process holding
# ``broker_signing_key`` — nothing more. On this box (no uid split, gap
# ``85716b25d9a8``) that key lives at ``$WILLOW_HOME/manifest_grants/``,
# 0600, owned by uid 1000 — the SAME uid Kart tasks run as, with
# ``$WILLOW_HOME`` read-write. A Kart task can read the private half
# directly (POISON: on an empty ``manifest_grants/`` it can even plant its
# own keypair first, and the broker's next genuine request signs with the
# planted key) and forge a request the broker itself would then sign as
# genuine. The signature therefore verifies "a uid-1000 process wrote this,"
# never "the broker, and only the broker, wrote this" — closing that gap is
# the uid split's job, not this branch's. What this branch DOES close: the
# citation binding below (pair_id in ``call_args``, matched by id — not
# "latest" — never a "latest" lookup, and never a previously-consumed
# citation) so a signed-but-stolen-key forgery still cannot replay a
# citation it does not itself hold.
#
# What is signed: the canonical JSON of exactly ``{pair_id, envelope_id,
# citation_id, apps, groups, pre_state, requested_at}`` — the fields that,
# taken together, ARE the request. A forged file with no ``broker_sig``, or
# one whose signature does not verify against this key, is refused
# ``eforged`` with no grant, before the seal, the escalation set, or
# anything else is even looked at.

def _broker_signing_key_path(grants_root: Path) -> Path:
    return grants_root / "broker_signing_key"


def _broker_public_key_path(grants_root: Path) -> Path:
    return grants_root / "broker_public_key.pub"


def _load_or_create_broker_signing_key(grants_root: Path):
    """The broker's own ed25519 PRIVATE key for signing pending requests —
    generated once, on first request, and reused after. Never touched by
    :func:`manifest_grant_apply`, which only ever reads the public half."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat,
    )

    path = _broker_signing_key_path(grants_root)
    if path.is_file():
        raw = bytes.fromhex(path.read_text(encoding="utf-8").strip())
        return Ed25519PrivateKey.from_private_bytes(raw)
    path.parent.mkdir(parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    tmp = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(raw.hex())
    os.replace(tmp, path)

    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_path = _broker_public_key_path(grants_root)
    pub_tmp = pub_path.with_suffix(pub_path.suffix + f".tmp-{os.getpid()}")
    pub_tmp.write_text(pub.hex(), encoding="utf-8")
    os.chmod(pub_tmp, 0o644)
    os.replace(pub_tmp, pub_path)
    return priv


def _canonical_request_bytes(record: dict) -> bytes:
    """The bytes the broker's signature actually covers. Generalized (pair
    ``1bd6fd29`` amendment) to carry a ``verb``/``target`` pair for the four
    trust-owner verbs added alongside ``manifest.grant`` — but ONLY when
    ``verb`` is present and not ``manifest.grant`` itself, so a
    ``manifest.grant`` record (whether or not it explicitly carries
    ``"verb": "manifest.grant"``) signs the EXACT SAME bytes as before this
    change: a pending file signed before this rework still verifies against
    a broker key generated after it, and vice versa.

    ``sealed_row`` (gap ``035d287206e1``, F1) is covered UNCONDITIONALLY,
    for every verb: it is now the one artifact the apply half trusts in
    place of a fresh nestor.db read, so it must be exactly as tamper-evident
    as ``target``/``apps``/``groups`` already are — an attacker who could
    edit the embedded sealed bytes without invalidating ``broker_sig`` could
    splice in a different, genuinely-signed sealed row (from an unrelated
    pair) that happens to parse to whatever grammar the tampered record's
    own ``target``/``apps``/``groups`` names. A request written before this
    field existed carries no ``sealed_row`` key; ``record.get(...)`` folds
    that in as ``None``, so old and new requests still sign distinguishable,
    self-consistent bytes rather than colliding."""
    payload = {
        "pair_id": record.get("pair_id"),
        "envelope_id": record.get("envelope_id"),
        "citation_id": record.get("citation_id"),
        "apps": record.get("apps"),
        "groups": record.get("groups"),
        "pre_state": record.get("pre_state"),
        "requested_at": record.get("requested_at"),
        "sealed_row": record.get("sealed_row"),
    }
    verb = record.get("verb") or VERB
    if verb != VERB:
        payload["verb"] = verb
        payload["target"] = record.get("target")
        payload["call_args"] = record.get("call_args")
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign_request(record: dict, grants_root: Path) -> str:
    priv = _load_or_create_broker_signing_key(grants_root)
    return priv.sign(_canonical_request_bytes(record)).hex()


def _verify_request_signature(record: dict, grants_root: Path) -> tuple[bool, str]:
    """``(ok, reason)``. ``False`` for anything the broker did not sign:
    no ``broker_sig`` field at all (a hand-written file), a signature that
    does not verify (a forged or corrupted one), or no public key on disk
    yet to verify against (a file dropped before any real request ever
    ran)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    sig_hex = record.get("broker_sig")
    if not sig_hex or not isinstance(sig_hex, str):
        return False, "pending record carries no broker_sig — not written by manifest_grant_request"
    pub_path = _broker_public_key_path(grants_root)
    if not pub_path.is_file():
        return False, f"no broker public key at {pub_path} to verify the signature against"
    try:
        pub_bytes = bytes.fromhex(pub_path.read_text(encoding="utf-8").strip())
        sig_bytes = bytes.fromhex(sig_hex)
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig_bytes, _canonical_request_bytes(record))
    except (ValueError, InvalidSignature):
        return False, "broker_sig does not verify against the broker's public key — forged or corrupted"
    return True, "ok"


#: The fields a sealed row's signature actually covers, and the exact set
#: the REQUEST half now embeds in the pending record so the APPLY half never
#: has to open nestor.db to re-verify (gap `035d287206e1`, F1 — Loki audit
#: B00BD43E, desk decision on 6864961F): nestor.db is a WAL database,
#: and a read-only opener under `ProtectHome=read-only` cannot create the
#: `-shm` sidecar a WAL reader needs. Measured under every permission shape
#: the trust-owner uid can be given (sidecars present-but-unreadable,
#: sidecars absent with a read-only directory, `immutable=1`, a bare ACL on
#: the db file alone) — all four either fail outright or silently hide rows
#: still sitting in the WAL. The remedy Loki names as option (iii): the
#: broker (which CAN read nestor.db) copies the sealed row's own bytes into
#: the signed, broker-``broker_sig``-covered request; the apply half re-runs
#: :func:`net_signer.verify_seal` against those embedded bytes and the
#: public ring — the ed25519 signature is the anchor, not the file it came
#: from. Trade-off named honestly: a pair superseded AFTER request but
#: BEFORE apply is no longer caught at apply time (supersession is checked
#: only by :func:`net_authority.read_sealed_pair`, a nestor.db read, which
#: the request half still performs) — a pending request can sit for
#: minutes, and this narrows (does not remove) that window; the desk chose
#: this over widening ProtectHome or granting the trust owner nestor.db's
#: WAL sidecars.
_SEALED_ROW_FIELDS = ("source_norm", "target_text", "verifier", "seal_sig", "created_at")


def _sealed_row_fields(sealed: dict) -> dict:
    """The exact subset of a ``state: populated`` sealed dict
    (:func:`net_authority.read_sealed_pair`'s own shape) that
    :func:`net_signer.verify_seal` needs and nothing else — stashed onto a
    pending record at request time so the apply half never has to read
    nestor.db to re-derive it."""
    return {k: sealed.get(k) for k in _SEALED_ROW_FIELDS}


def _verify_seal_only(pair_id: str, *, db_path: Optional[Path] = None,
                       sealed_row: Optional[dict] = None) -> tuple[Optional[dict], Optional[dict]]:
    """Refuse unless the sealed pair's ed25519 signature verifies — no
    grammar, no target binding. ``(refusal, sealed)``: exactly one is
    ``None``. Factored out of :func:`_bind_to_seal` (pair ``1bd6fd29``
    amendment) so the four trust-owner verbs added alongside
    ``manifest.grant`` share this half — the seal-state/ring/verify_seal
    checks — while each still parses ITS OWN strict grammar out of
    ``sealed["target_text"]``.

    Rework (pair ``b74019ac``): the seal binding used to compare text only,
    never checking ``seal_sig`` at all — a garbage signature on an
    otherwise-well-formed sealed row was granted with a receipt. This now
    calls :func:`net_signer.verify_seal` against a ring built from
    ``config/verifiers.json``, using the SEALED ROW's own ``verifier`` field
    — never the SOIL record's ``nestor_verifier``, which is mutable after
    the seal lands and is not what the signature covers.

    ``sealed_row`` (gap ``035d287206e1``, F1): when given, this is the
    apply-side call — the sealed bytes the REQUEST half already read from
    nestor.db and embedded (signed) in the pending record, never a fresh
    nestor.db read. ``db_path``/``sealed_row`` are mutually exclusive in
    practice: request-time callers pass ``db_path`` (they CAN read
    nestor.db, and must, to bind the grant to what was actually sealed);
    apply-time callers pass ``sealed_row`` (they never open nestor.db at
    all — see the module-level note above :data:`_SEALED_ROW_FIELDS`).
    """
    from . import keyring as _keyring
    from . import net_signer

    if sealed_row is not None:
        missing = [k for k in _SEALED_ROW_FIELDS if not sealed_row.get(k)]
        if missing:
            return _refuse(
                "eforged",
                f"pending record's embedded sealed_row is missing {missing!r} — not "
                "written by a request half that stashes the sealed bytes (gap "
                "035d287206e1), or corrupted after the fact",
            ), None
        sealed = {"state": "populated", **{k: sealed_row.get(k) for k in _SEALED_ROW_FIELDS}}
    else:
        sealed = _load_sealed_ruling(pair_id, db_path=db_path)
    state = sealed.get("state")
    if state == "unreachable":
        return _refuse(
            "EUNREACH",
            f"nestor.db unreachable ({sealed.get('cause')}) — cannot bind this "
            "grant to what was actually sealed; the SOIL record alone is not enough",
        ), None
    if state != "populated":
        return _refuse(
            "EACCES",
            f"pair_id={pair_id!r} is not a populated sealed pair in nestor.db "
            f"({sealed.get('why')}) — a governance record marked status=sealed "
            "is not enough on its own; the pair itself must be sealed",
        ), None

    ring_kr = _keyring.get_keyring()
    if ring_kr is None:
        return _refuse(
            "EACCES",
            "no keyring configured (config/verifiers.json via WILLOW_KEYRING) — "
            "a grant cannot verify a seal without a ring to verify it against",
        ), None
    # Loki audit 3, finding 1: "a permission grant is not a lease." The
    # default verify_seal age bound (net_authority.SEAL_MAX_AGE_S, 24h) was
    # written for a one-shot net-authority request; a manifest.grant sealed
    # pair is a standing governance decision, and it does not go stale on a
    # calendar just because nobody happened to apply it within a day. The
    # actual revocation path is supersession: _load_sealed_ruling already
    # refuses a pair whose row carries superseded_by (net_authority.
    # read_sealed_pair), and that check runs before verify_seal is reached.
    ok, reason, field = net_signer.verify_seal(sealed, _ring_from_keyring(ring_kr), max_age_s=None)
    if not ok:
        return _refuse(
            "EACCES",
            f"sealed pair {pair_id!r} does not verify: {reason} (field={field!r}) — "
            "a garbage or unverifiable seal_sig is refused regardless of what the "
            "SOIL record's own nestor_verifier field claims",
            field=field,
        ), None
    return None, sealed


def _bind_to_seal(pair_id: str, apps: list[str], groups: list[str], *,
                   db_path: Optional[Path] = None,
                   sealed_row: Optional[dict] = None) -> tuple[Optional[dict], Optional[dict]]:
    """Refuse unless the sealed pair's ed25519 signature verifies AND its
    own text names exactly ``apps``/``groups`` (read off the mutable SOIL
    record). ``(refusal, sealed)``: exactly one is ``None`` — the request
    side needs ``sealed`` back to stash :func:`_sealed_row_fields` of it
    onto the pending record (gap ``035d287206e1``); the apply side passes
    ``sealed_row`` instead of ``db_path`` and never touches nestor.db.
    ``manifest.grant``'s own grammar binder, built on
    :func:`_verify_seal_only`."""
    refusal, sealed = _verify_seal_only(pair_id, db_path=db_path, sealed_row=sealed_row)
    if refusal is not None:
        return refusal, None

    parsed = _parse_ruling_text(sealed.get("target_text", ""))
    if parsed is None:
        return _refuse(
            "EINVAL",
            f"sealed pair {pair_id!r} text does not match the strict manifest.grant "
            f"grammar ({RULING_FORMAT!r} seats=<a,b> groups=<c,d>, one line, prose "
            "below it) — refusing to guess what was actually sealed",
            sealed_text=sealed.get("target_text"),
        ), None
    if set(parsed["apps"]) != set(apps) or set(parsed["groups"]) != set(groups):
        return _refuse(
            "eseal_mismatch",
            f"governance record's seats/groups for pair_id={pair_id!r} do not match "
            "what the sealed pair's own text says — the record was edited after the "
            "seal; refusing rather than trusting the mutable record over the seal",
            sealed_apps=parsed["apps"], sealed_groups=parsed["groups"],
            record_apps=apps, record_groups=groups,
        ), None
    return None, sealed


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
    """tmp-write + fsync(file) + rename + fsync(directory). A rename alone
    is atomic with respect to a crash mid-write, but on most filesystems it
    is NOT durable until the containing directory's own metadata is
    fsync'd — a crash between ``os.replace`` and the next `sync` can lose
    the rename itself, or leave the new name pointing at garbage (Loki
    audit 3, finding 6). Citing an envelope only after this returns is what
    makes "durable on disk before a single citation is spent" (module
    docstring) actually true rather than aspirational."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(record, indent=2, default=str))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        tmp.unlink(missing_ok=True)


def _existing_request_state(grants_root: Path, pair_id: str) -> Optional[str]:
    for state in ("pending", "done", "failed"):
        if (grants_root / state / f"{pair_id}.json").is_file():
            return state
    return None


def _consumed_citation_ids(grants_root: Path) -> set[str]:
    """Every ``citation_id`` a ``done/`` entry already recorded — the
    REPLAY defense (Loki audit 4, HIGH): done/ IS the record of which
    citations were actually consumed, so a request naming one of these ids
    again is refused regardless of how well-formed or well-signed it
    otherwise looks. Read-only, tolerant of a corrupt or unreadable
    individual file (skipped, never raised) — this is a denylist check, not
    the only gate."""
    done_dir = grants_root / "done"
    ids: set[str] = set()
    if not done_dir.is_dir():
        return ids
    for f in done_dir.glob("*.json"):
        try:
            rec = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        cid = rec.get("citation_id")
        if cid:
            ids.add(cid)
    return ids


def manifest_grant_status(pair_id: str, *, grants_root: Optional[Path] = None) -> dict:
    """Three-state (plus not_found) read of one request: ``pending`` (the
    unit has not drained it yet), ``done`` (granted, receipts attached),
    ``failed`` (refused or rolled back at apply time), or ``not_found`` (no
    request was ever made for this ``pair_id``). Read-only, never blocks.

    ``failed`` is terminal for most causes, but not all of them (Loki audit
    4, MEDIUM: a disk hiccup, an unreachable dependency, a race against
    another request, or a corrupt-directory read burned a human-sealed pair
    for a reason that was never the pair's own fault). A pair that failed
    for ``eforged``, ``eseal_mismatch``, an escalation-class group, or
    ``edrift`` failed for a reason a bare retry cannot itself fix — the
    seal is still whatever it was, the drift is still there, the forgery is
    still forged; retrying productively there means re-sealing a fresh
    Nestor pair (a NEW ``pair_id``) once the actual cause is addressed, not
    replaying the same failed request, and :func:`manifest_grant_retry`
    refuses those causes by name. For the narrower, audited set of
    genuinely transient causes (:data:`RETRYABLE_ERRORS`),
    :func:`manifest_grant_retry` moves the same request back to ``pending/``
    unchanged. The one-request-per-pair rule (``EALREADY``) still refuses a
    second attempt at the SAME ``pair_id`` while it is pending or done; a
    failed one that is not on the retryable list still needs the operator's
    `rm $WILLOW_HOME/manifest_grants/failed/<pair_id>.json`.
    """
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


# ── shared lock/cite plumbing, reused by every trust-owner verb ────────────
#
# Pair 1bd6fd29 amendment: four more verbs (envelope.revoke, manifest.retire,
# manifest.create, federation.ratify — trust_owner_verbs.py) share this one
# pending/done/failed queue with manifest.grant, distinguished by the
# record's own "verb" field (defaulting to VERB when absent, so every
# existing pending/done/failed file written before this change still
# parses). The per-pair-id lock dance (stale-lock reclaim included) and the
# write-then-cite-then-sign tail are identical in shape across verbs; they
# are factored here rather than re-derived per verb.

def _run_locked_request(grants_root_p: Path, pair_id: str, body) -> dict:
    """Acquire ``pending/<pair_id>.lock`` (with the same stale-lock reclaim
    :func:`manifest_grant_request` performs), run ``body()``, and always
    release. ``body`` takes no arguments and returns the result dict; on a
    reclaimed stale lock, ``reclaimed_stale_lock: True`` is folded in."""
    lock_dir = grants_root_p / "pending"
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_dir / f"{pair_id}.lock"
    reclaimed_stale_lock = False

    def _acquire() -> int:
        fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.write(fd, json.dumps({"pid": os.getpid(), "created_at": _now_iso()}).encode("utf-8"))
        return fd

    try:
        lock_fd = _acquire()
    except FileExistsError:
        if _stale_lock(lock_path):
            reclaim_path = lock_path.with_name(
                f"{lock_path.name}.reclaimed-{int(time.time() * 1000)}-{os.getpid()}"
            )
            try:
                lock_path.rename(reclaim_path)
            except OSError:
                return _refuse(
                    "EALREADY",
                    f"a request for pair_id={pair_id!r} is already being written by a "
                    "concurrent call — one request per sealed pair",
                )
            try:
                lock_fd = _acquire()
                reclaimed_stale_lock = True
            except FileExistsError:
                return _refuse(
                    "EALREADY",
                    f"a request for pair_id={pair_id!r} is already being written by a "
                    "concurrent call — one request per sealed pair",
                )
        else:
            return _refuse(
                "EALREADY",
                f"a request for pair_id={pair_id!r} is already being written by a "
                "concurrent call — one request per sealed pair",
            )
    os.close(lock_fd)
    try:
        result = body()
        if reclaimed_stale_lock:
            result["reclaimed_stale_lock"] = True
        return result
    finally:
        lock_path.unlink(missing_ok=True)


def _cite_and_persist(pending_path: Path, pending_record: dict, *, ledger,
                       envelope_id: str, app_id: str, call_args: dict,
                       project: str, session: str, pair_id: str,
                       grants_root_p: Path) -> dict:
    """The common tail of every verb's own ``*_request``: resolve the one
    active envelope governing ``pending_record["verb"]`` for ``app_id``,
    write the pending record durably, cite it, sign it, and persist again
    — module docstring's 'write first, cite second, sign last.' On any
    refusal below the durability write, the pending file (if written) is
    removed again so a request nobody may act on is never left in
    ``pending/``."""
    from .envelopes import EnvelopeAuthority, governing_envelopes

    verb = pending_record["verb"]
    try:
        rows = governing_envelopes(verb, app_id)
    except (OSError, ValueError) as exc:
        return _refuse("EAMBIG", f"envelope registry unreadable: {exc}")
    matches = [row["id"] for row in rows]
    if envelope_id:
        if envelope_id not in matches:
            return _refuse(
                "ENOENT", f"envelope {envelope_id!r} does not govern {verb!r} for {app_id!r}",
                envelope_ids=matches,
            )
        matches = [envelope_id]
    if not matches:
        return _refuse("ENOENT", f"no active {verb!r} envelope governs {app_id!r}")
    if len(matches) > 1:
        return _refuse(
            "EAMBIG", f"multiple active {verb!r} envelopes govern {app_id!r} — "
                      f"pass envelope_id to name which one to cite",
            envelope_ids=matches,
        )

    # `call_args` is stashed on the record itself (not just handed to the
    # envelope) so the apply side can re-derive exactly what the citation
    # SHOULD carry without re-deriving verb-specific bounds shapes from
    # `target` — `_verify_pending_signature_and_citation` compares the
    # FRANK citation's own `call_args` against this stashed copy, verb-
    # agnostically.
    pending_record["call_args"] = call_args
    _write_json_atomic(pending_path, pending_record)

    result = EnvelopeAuthority(ledger).authorize_and_cite(
        matches[0], actor=app_id, verb=verb, call_args=call_args,
        project=project or "willow-mcp", session=session, pair_id=pair_id,
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
    pending_record["broker_sig"] = _sign_request(pending_record, grants_root_p)
    _write_json_atomic(pending_path, pending_record)

    return {
        "ok": True, "state": "requested", "pending_path": str(pending_path),
        "pair_id": pair_id, "verb": verb, "envelope_id": matches[0],
        "citation_id": result.get("citation_id"),
    }


def _verify_pending_signature_and_citation(record: dict, *, ledger, grants_root: Path,
                                            applied_event: str) -> Optional[dict]:
    """Apply-side steps shared by every trust-owner verb: the broker's own
    signature over the request (:func:`_verify_request_signature`), and
    confirmation that its ``envelope_id``/``citation_id`` actually exist in
    FRANK as a granted citation for THIS ``pair_id`` and THIS verb's
    ``target`` — never consumed already, either by an existing ``done/``
    entry or by a prior ``applied_event`` FRANK row (the durable record,
    read even when ``done/`` was deleted out from under it — Loki audit 5,
    LIMIT, restated here for every verb rather than just ``manifest.grant``).
    Returns a refusal dict, or ``None`` when both hold."""
    pair_id = record.get("pair_id")
    verb = record.get("verb") or VERB
    sig_ok, sig_reason = _verify_request_signature(record, grants_root)
    if not sig_ok:
        return _refuse("eforged", sig_reason)

    envelope_id = record.get("envelope_id")
    citation_id = record.get("citation_id")
    if not envelope_id or not citation_id:
        return _refuse("eforged", "pending record carries no envelope_id/citation_id to confirm in FRANK")
    if ledger is None:
        return _refuse("EUNREACH", "no FRANK ledger available to confirm the citation against")

    candidates = ledger.all_events("envelope_citation", match={"envelope_id": envelope_id, "outcome": "granted"})
    cited = next((c for c in candidates if c.get("id") == citation_id), None)
    if cited is None or (cited.get("content") or {}).get("verb") != verb:
        return _refuse("eforged",
                        f"FRANK carries no granted {verb!r} envelope_citation matching "
                        f"citation_id={citation_id!r} for pair_id={pair_id!r}")
    cited_args = (cited["content"].get("call_args") or {})
    if cited_args.get("pair_id") != pair_id:
        return _refuse("eforged",
                        "FRANK citation's call_args.pair_id does not match this request's "
                        f"pair_id={pair_id!r} — a citation minted for a different sealed "
                        "pair can never authorize this one, even copied verbatim")
    cited_without_pair = {k: v for k, v in cited_args.items() if k != "pair_id"}
    if cited_without_pair != (record.get("call_args") or {}):
        return _refuse("eforged",
                        "FRANK citation's call_args does not match this request's own "
                        "recorded call_args — the file was edited after the citation was inked")

    consumed = _consumed_citation_ids(grants_root)
    if citation_id in consumed:
        return _refuse("eforged",
                        f"citation_id={citation_id!r} was already consumed by a prior "
                        "done/ grant — a spent citation is never replayable")
    try:
        applied_events = ledger.all_events(applied_event, match={"citation_id": citation_id})
    except Exception as exc:  # noqa: BLE001 — ledger unreachable is refused, never swallowed as "not found"
        return _refuse("EUNREACH",
                        "FRANK ledger unreachable while checking for a prior "
                        f"{applied_event!r} event naming citation_id={citation_id!r}: "
                        f"{type(exc).__name__}: {exc} — refusing rather than treating an "
                        "unreachable ledger as 'not previously consumed'")
    if applied_events:
        return _refuse("eforged",
                        f"citation_id={citation_id!r} already has a FRANK {applied_event!r} "
                        "event recorded — already consumed")
    return None


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
    manifest — that is :func:`manifest_grant_apply`'s job, run as a separate
    call (an audit-trail split, not a privilege boundary on this box — see
    the module docstring's note above :func:`_broker_signing_key_path` and
    :func:`_apply_one`'s own signature/citation checks).

    Returns ``{ok: True, state: "requested", pending_path, citation_id,
    envelope_id, pair_id}`` or a refusal dict. ``app_id`` must be the
    orchestrator seat; ``ledger`` is a :class:`GovernanceLedger`;
    ``store``/``apps_root``/``db_path``/``grants_root`` are test seams.

    An ``O_CREAT|O_EXCL`` lock file (``pending/<pair_id>.lock``) serializes
    this against a CONCURRENT call for the SAME ``pair_id`` (Loki audit 3,
    medium finding: ``_existing_request_state`` and the write it guards had
    no lock between them, so two requests racing the same pair could both
    pass the EALREADY check and both cite — two citations, last file wins).
    A pair already being written by another call refuses ``EALREADY``
    rather than blocking; the lock is released win or lose.
    """
    from .human_session import is_orchestrator_app

    if not is_orchestrator_app(app_id):
        return _refuse(
            "EPERM",
            f"manifest.grant is orchestrator-only; {app_id!r} may not call it "
            "regardless of any envelope — a specialist requesting a group for "
            "itself or a peer routes through the operator, never this verb",
        )

    grants_root_p = _grants_root(grants_root)
    lock_dir = grants_root_p / "pending"
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_dir / f"{pair_id}.lock"
    reclaimed_stale_lock = False

    def _acquire() -> int:
        fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.write(fd, json.dumps({"pid": os.getpid(), "created_at": _now_iso()}).encode("utf-8"))
        return fd

    try:
        lock_fd = _acquire()
    except FileExistsError:
        # Loki audit 4, MEDIUM (stale lock): this box is swap-bound and a
        # hard kill (SIGKILL/OOM) mid-request leaves the lock behind — the
        # `finally: lock_path.unlink()` below never runs. A lock older than
        # 10 minutes whose recorded pid is no longer alive is reclaimed; a
        # live pid, or a lock too young to judge either way, is left alone.
        if _stale_lock(lock_path):
            # Loki audit 5, LIMIT (stale-lock reclaim TOCTOU): unlinking the
            # stale lock by name and then re-creating it left a window where
            # two concurrent reclaimers could each judge the SAME lock
            # stale and both unlink+acquire — the second reclaimer's unlink
            # removes the FIRST reclaimer's freshly created (and perfectly
            # live) lock, not the dead one either of them meant to clear.
            # Renaming the stale lock to a name unique to this attempt
            # first closes it: `rename` is atomic, so only one reclaimer's
            # rename of the SAME original path can succeed. A reclaimer
            # that loses the race sees `FileNotFoundError` (the file it
            # tried to rename is already gone) and falls through to the
            # ordinary EALREADY a contended lock always returns — it never
            # touches the winner's lock file.
            reclaim_path = lock_path.with_name(
                f"{lock_path.name}.reclaimed-{int(time.time() * 1000)}-{os.getpid()}"
            )
            try:
                lock_path.rename(reclaim_path)
            except OSError:
                return _refuse(
                    "EALREADY",
                    f"a manifest.grant request for pair_id={pair_id!r} is already being "
                    "written by a concurrent call — one request per sealed pair",
                )
            try:
                lock_fd = _acquire()
                reclaimed_stale_lock = True
            except FileExistsError:
                return _refuse(
                    "EALREADY",
                    f"a manifest.grant request for pair_id={pair_id!r} is already being "
                    "written by a concurrent call — one request per sealed pair",
                )
        else:
            return _refuse(
                "EALREADY",
                f"a manifest.grant request for pair_id={pair_id!r} is already being "
                "written by a concurrent call — one request per sealed pair",
            )
    os.close(lock_fd)
    try:
        result = _manifest_grant_request_locked(
            app_id, envelope_id=envelope_id, pair_id=pair_id, project=project,
            session=session, task_id=task_id, ledger=ledger, store=store,
            apps_root=apps_root, db_path=db_path, grants_root_p=grants_root_p,
        )
        if reclaimed_stale_lock:
            # A receipt line, not a refusal: the request itself proceeded
            # (or was refused) on its own merits; this only notes that its
            # lock slot had to be reclaimed from a dead holder first.
            result["reclaimed_stale_lock"] = True
        return result
    finally:
        lock_path.unlink(missing_ok=True)


def _manifest_grant_request_locked(
    app_id: str,
    *,
    envelope_id: str,
    pair_id: str,
    project: str,
    session: str,
    task_id: str,
    ledger,
    store,
    apps_root: Optional[Path],
    db_path: Optional[Path],
    grants_root_p: Path,
) -> dict:
    """The body of :func:`manifest_grant_request`, run under its per-pair
    lock. Not called directly outside tests that already hold the lock."""
    from .envelopes import EnvelopeAuthority, governing_envelopes

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

    seal_refusal, sealed = _bind_to_seal(pair_id, apps, groups, db_path=db_path)
    if seal_refusal is not None:
        return seal_refusal

    escalating = sorted(set(groups) & ESCALATION_GROUPS)
    if escalating:
        return _refuse(
            "EPERM",
            f"pair_id={pair_id!r} names escalation-class group(s) {escalating!r} — "
            "never grantable through manifest.grant, regardless of seal or "
            "envelope bounds (the packet's own escalation set, restated in "
            "ESCALATION_GROUPS — narrower than, and not the same list as, "
            "the PreToolUse manifest guard's own broader refusal set)",
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

    # Loki audit 4, HIGH (TWO-PAIRS / REPLAY): pair_id rides in call_args so
    # the citation FRANK records carries it too — apply matches its citation
    # by (envelope_id, pair_id, outcome=granted), never by "whichever is
    # newest for the envelope." bounds-checking (EnvelopeAuthority.check)
    # only ever sees the bounds-relevant subset of call_args; pair_id is
    # folded into the CITATION content separately (authorize_and_cite's
    # pair_id= kwarg below) so it never has to appear in the envelope's own
    # bounds signature.
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
        "pair_id": pair_id, "verb": VERB, "envelope_id": None, "citation_id": None,
        "actor": app_id, "apps": apps, "groups": groups,
        "project": project or "willow-mcp", "session": session,
        "requested_at": _now_iso(), "pre_state": pre_state,
        # Gap 035d287206e1, F1: the sealed row's own bytes, embedded here
        # (and covered by broker_sig below) so the apply half never opens
        # nestor.db — see the note above _SEALED_ROW_FIELDS.
        "sealed_row": _sealed_row_fields(sealed),
    }
    _write_json_atomic(pending_path, pending_record)

    result = EnvelopeAuthority(ledger).authorize_and_cite(
        matches[0], actor=app_id, verb=VERB, call_args=call_args,
        project=project or "willow-mcp", session=session, pair_id=pair_id,
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
    # Signed AFTER the citation is inked, over the fields that make the
    # request what it is (pair_id, envelope_id, citation_id, apps, groups,
    # pre_state, requested_at) — apply verifies this FIRST, before anything
    # else. This proves the file was produced by A process holding
    # ``broker_signing_key`` (Loki audit 3, finding 2); on a single-uid box
    # that is not the same as "the broker, uniquely" (Loki audit 4, HIGH —
    # see the module-level note above the key-loading helpers). The
    # citation binding that follows (pair_id in call_args, matched by id) is
    # what actually stops a signed forgery from being actioned.
    pending_record["broker_sig"] = _sign_request(pending_record, grants_root_p)
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
    process runs as the broker's own uid, the same uid that already owns
    ``apps_root`` on this box, so ``publish_signed_pair`` writes the trust
    root directly under ``signed_pair_lock``; there is no sudo bridge to
    cross. (A uid split, if the operator ever performs one, would need
    ``privileged_publisher`` here — gap ``85716b25d9a8``.)"""
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
        revoke = _revoke_groups(app_id, granted_now)
        try:
            owning_uid = manifest_path.stat().st_uid
        except OSError:
            owning_uid = None
        out = {"ok": False, "app_id": app_id, "error": "eperm",
               "reason": f"{type(exc).__name__}: {exc}",
               "path": str(manifest_path), "owning_uid": owning_uid}
        if revoke["failed"]:
            out["rollback_failed"] = revoke["failed"]
        return out
    except RuntimeError as exc:
        revoke = _revoke_groups(app_id, granted_now)
        out = {"ok": False, "app_id": app_id, "error": _classify_set_permission_error(exc),
               "reason": str(exc)}
        if revoke["failed"]:
            out["rollback_failed"] = revoke["failed"]
        return out
    except Exception as exc:  # noqa: BLE001 — never let an exception escape a citation already inked
        revoke = _revoke_groups(app_id, granted_now)
        out = {"ok": False, "app_id": app_id, "error": "eunexpected",
               "reason": f"{type(exc).__name__}: {exc}"}
        if revoke["failed"]:
            out["rollback_failed"] = revoke["failed"]
        return out

    after_text = manifest_path.read_text(encoding="utf-8")
    after_digest = _digest(after_text.encode("utf-8"))
    sig_after = pgp.read_detached_sig_bytes(manifest_path)
    return {
        "ok": True, "app_id": app_id, "groups": granted_now, "changed": True,
        "manifest_sha256": after_digest, "manifest_sha256_before": before_digest,
        "sig_sha256": _digest(sig_after) if sig_after else "",
        "unsigned": sig_after is None,
    }


def _revoke_groups(app_id: str, groups: list[str]) -> dict:
    """Compensating undo of groups THIS call already granted — for the SAME
    seat (a later group failing) or a LATER seat in the same request
    failing. Never raises, but never swallows either (Loki audit 3,
    finding 4: this used to be a bare ``except Exception: pass``, and a
    rollback that failed was reported as ``rolled_back`` with the seat
    still holding the group). Returns ``{app_id, reverted, failed}``:
    ``reverted`` is what actually came off, ``failed`` is
    ``[{group, reason}, ...]`` for what did not — the caller reports
    ``rollback_failed`` from ``failed``, never folds it into success."""
    from . import manifest_admin

    reverted: list[str] = []
    failed: list[dict] = []
    for g in reversed(groups):
        try:
            manifest_admin.set_permission(app_id, g, False)
            reverted.append(g)
        except Exception as exc:  # noqa: BLE001 — reported via `failed`, never hidden
            failed.append({"group": g, "reason": f"{type(exc).__name__}: {exc}"})
    return {"app_id": app_id, "reverted": reverted, "failed": failed}


def _rollback_seat(app_id: str, groups: list[str]) -> dict:
    """Undo of a whole seat this call already granted, when a LATER seat in
    the same request fails — through the SAME staged ``set_permission``
    path a grant used, never a direct byte restore. See :func:`_revoke_groups`
    for the truthful-reporting contract."""
    return _revoke_groups(app_id, groups)


def _move(path: Path, dest_dir: Path, record: dict) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / path.name
    _write_json_atomic(dest, record)
    path.unlink(missing_ok=True)
    return dest


def _dirs_writable(grants_root: Path) -> tuple[bool, str]:
    """Whether THIS process (the apply unit's uid) can create, write and
    unlink inside every one of ``pending/``, ``done/``, ``failed/``. Checked
    BEFORE granting anything (Loki audit 3, finding 5: a cross-uid box where
    the apply uid could grant a seat's manifest but not unlink the request
    from ``pending/`` used to grant, ink a receipt, and then loop forever
    reporting ``eunexpected`` every tick with the grant already live and the
    file stuck 'pending'). A directory that cannot be created or is not
    writable+traversable by this uid refuses ``eperm_pending`` up front,
    before a single seat's manifest is touched."""
    for name in ("pending", "done", "failed"):
        d = grants_root / name
        try:
            d.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return False, f"cannot create or access {d}: {type(exc).__name__}: {exc}"
        if not os.access(d, os.W_OK | os.X_OK):
            return False, f"{d} is not writable by this process (uid {os.geteuid()})"
    return True, "ok"


def _apply_one(record: dict, path: Path, *, ledger, apps_root: Path,
                db_path: Optional[Path], grants_root: Path) -> dict:
    pair_id = record.get("pair_id")
    apps = record.get("apps") or []
    groups = record.get("groups") or []

    # 0. Can this process even move the request OUT of pending/ once it
    # decides an outcome? Checked before anything is granted — never after
    # (Loki audit 3, finding 5).
    dirs_ok, dirs_reason = _dirs_writable(grants_root)
    if not dirs_ok:
        out = {"ok": False, "error": "eperm_pending", "reason": dirs_reason}
        try:
            _move(path, grants_root / "failed", {**record, "result": out})
        except OSError:
            pass  # even failed/ is unreachable; no grant occurred either way
        return {"pair_id": pair_id, **out}

    def _fail(errno: str, reason: str, **extra) -> dict:
        out = {"ok": False, "error": errno, "reason": reason, **extra}
        _move(path, grants_root / "failed", {**record, "result": out})
        return {"pair_id": pair_id, **out}

    # 1. The broker's own signature over the request, FIRST — before the
    # seal, before the escalation set, before anything else. A file this
    # process did not write and sign is never actioned, regardless of how
    # well-formed it otherwise looks (Loki audit 3, finding 2, FORGE-1/2).
    sig_ok, sig_reason = _verify_request_signature(record, grants_root)
    if not sig_ok:
        return _fail("eforged", sig_reason)

    # 2. The seal — re-verified fresh (a pending request can sit for
    # minutes), but NEVER by opening nestor.db here (gap 035d287206e1, F1):
    # it is a WAL database and a read-only opener under this unit's
    # ProtectHome=read-only cannot create the -shm sidecar a WAL reader
    # needs — measured EUNREACH/edrift-shaped failures under every
    # permission grant tried. The sealed row's own bytes were embedded
    # (and broker-signed) in the pending record at request time; re-verify
    # THOSE against the public ring instead — see the note above
    # _SEALED_ROW_FIELDS. `db_path` is still accepted by this function for
    # the request-side callers that share it; passed nowhere below.
    seal_refusal, _sealed_at_apply = _bind_to_seal(
        pair_id, apps, groups, sealed_row=record.get("sealed_row"))
    if seal_refusal is not None:
        return _fail(seal_refusal["error"], seal_refusal["reason"],
                     **{k: v for k, v in seal_refusal.items() if k not in ("ok", "error", "reason")})

    # 3. The escalation set — re-checked at apply, not just at request. A
    # prior draft re-verified only the seal here; nothing stopped a
    # perfectly-signed request naming an escalation group post-request if
    # request-time enforcement were ever bypassed or the escalation list
    # widened between request and apply.
    escalating = sorted(set(groups) & ESCALATION_GROUPS)
    if escalating:
        return _fail("EPERM",
                      f"pair_id={pair_id!r} names escalation-class group(s) {escalating!r} at "
                      "apply time — refused regardless of what request-time checked",
                      escalating=escalating)

    # 4. The envelope + citation actually exist in FRANK, granted, for this
    # exact pair — never re-derived, never assumed from the file's own say-so
    # (Loki audit 3, finding 2: a hand-written file naming citation_id
    # 'forged' used to apply cleanly).
    envelope_id = record.get("envelope_id")
    citation_id = record.get("citation_id")
    if not envelope_id or not citation_id:
        return _fail("eforged", "pending record carries no envelope_id/citation_id to confirm in FRANK")
    if ledger is None:
        return _fail("EUNREACH", "no FRANK ledger available to confirm the citation against")
    # Loki audit 4, HIGH (TWO-PAIRS): a citation is looked up by ITS OWN id
    # among EVERY granted citation for this envelope — never
    # `latest_event`'s "whichever is newest." Two legitimate requests queued
    # under one envelope used to burn whichever one `latest_event` did not
    # happen to return (on real Postgres, ORDER BY created_at DESC — the
    # OLDER pending request always lost).
    candidates = ledger.all_events("envelope_citation", match={"envelope_id": envelope_id, "outcome": "granted"})
    cited = next((c for c in candidates if c.get("id") == citation_id), None)
    if cited is None or (cited.get("content") or {}).get("verb") != VERB:
        return _fail("eforged",
                      f"FRANK carries no granted {VERB!r} envelope_citation matching "
                      f"citation_id={citation_id!r} for pair_id={pair_id!r}")
    cited_args = (cited["content"].get("call_args") or {})
    # Loki audit 4, HIGH (REPLAY): the citation's OWN pair_id (recorded in
    # call_args at request time) must match THIS record's pair_id. A
    # citation minted for pair A can never authorize pair B, even copied
    # verbatim onto a byte-identical, correctly-signed pending file — the
    # shape of Loki's actual REPLAY probe: a spent citation_id from a done/
    # entry, glued onto a freshly self-sealed pair.
    if cited_args.get("pair_id") != pair_id:
        return _fail("eforged",
                      "FRANK citation's call_args.pair_id does not match this request's "
                      f"pair_id={pair_id!r} — a citation minted for a different sealed "
                      "pair can never authorize this one, even copied verbatim")
    if set(cited_args.get("apps") or []) != set(apps) or set(cited_args.get("groups") or []) != set(groups):
        return _fail("eforged",
                      "FRANK citation's call_args do not match this request's apps/groups — "
                      "the file was edited after the citation was inked")
    # Loki audit 4, HIGH (REPLAY): a citation already spent by an earlier
    # done/ grant must never authorize a second one — even a byte-for-byte
    # copy of a once-valid pending file, dropped back into pending/ after
    # the operator revoked the grant it produced the first time. done/
    # already names the citation_id it consumed; refuse before touching a
    # single seat's manifest.
    consumed = _consumed_citation_ids(grants_root)
    if citation_id in consumed:
        return _fail("eforged",
                      f"citation_id={citation_id!r} was already consumed by a prior "
                      "done/ grant — a spent citation is never replayable, regardless "
                      "of a valid broker_sig or a matching pair_id")
    # Loki audit 5, LIMIT: the check above reads ONLY done/ — a durable
    # record that can be deleted out from under it (REPLAY-3), after which
    # a byte-copy of a granted request is refused only incidentally, by
    # `edrift`, if the manifest it targets happens to have moved. The
    # actual durable record of consumption is FRANK's own `manifest_granted`
    # event, which names `citation_id` and is append-only — done/ is a
    # convenience cache of it, never the other way around. Ask FRANK
    # directly, every time, regardless of what done/ shows. A ledger this
    # process cannot even query is never treated as "found nothing" — that
    # would silently let a replay through on the one occasion the durable
    # record can't be read, which is worse than refusing.
    try:
        granted_events = ledger.all_events(EVENT, match={"citation_id": citation_id})
    except Exception as exc:  # noqa: BLE001 — ledger unreachable is refused, never swallowed as "not found"
        return _fail("EUNREACH",
                      "FRANK ledger unreachable while checking for a prior "
                      f"{EVENT!r} event naming citation_id={citation_id!r}: "
                      f"{type(exc).__name__}: {exc} — refusing rather than treating an "
                      "unreachable ledger as 'not previously consumed'")
    if granted_events:
        return _fail("eforged",
                      f"citation_id={citation_id!r} already has a FRANK {EVENT!r} event "
                      "recorded — already consumed, regardless of whether done/ still "
                      "holds the record it was consumed from")

    # 5. Pre-state is mandatory, not optional (Loki audit 3, finding 2:
    # drift was skipped whenever pre_state was simply absent). A request
    # with no pre-state to check drift against is itself refused, never
    # treated as "nothing to compare."
    pre_state = record.get("pre_state") or {}
    if not pre_state:
        return _fail("eforged", "pre_state is mandatory and absent from this request")
    for seat in apps:
        seat_now = _seat_pre_state(seat, apps_root)
        if not seat_now.get("ok"):
            return _fail(seat_now["error"], seat_now["reason"], app_id=seat)
        recorded = pre_state.get(seat) or {}
        if not recorded.get("manifest_sha256"):
            return _fail("eforged", f"pre_state for {seat!r} is missing or incomplete", app_id=seat)
        if recorded["manifest_sha256"] != seat_now["manifest_sha256"]:
            return _fail("edrift",
                         f"{seat}'s manifest changed since the request was made — "
                         "refusing to apply against a moved target", app_id=seat)

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
            rolled_back: list[str] = []
            rollback_failed: list[dict] = []
            for undone_app, undone_groups in reversed(rollback_stack):
                revoke = _rollback_seat(undone_app, undone_groups)
                if revoke["failed"]:
                    rollback_failed.append({"app_id": undone_app, "still_held": [
                        f["group"] for f in revoke["failed"]], "detail": revoke["failed"]})
                else:
                    rolled_back.append(undone_app)
            reason = (f"seat {seat!r} refused ({outcome.get('reason')}); rolled back "
                      f"{len(rolled_back)} already-granted seat(s) in this request")
            if rollback_failed:
                # Loki audit 3, finding 4 (RBFAIL): a rollback failure is
                # named explicitly, with which seats still hold what — never
                # folded into "rolled back N" as if it had succeeded.
                still = {r["app_id"]: r["still_held"] for r in rollback_failed}
                reason += f"; ROLLBACK FAILED, still held: {still!r}"
            out = {
                "ok": False, "error": outcome.get("error", "EAMBIG"),
                "reason": reason,
                "granted": [], "refused": refused,
                "rolled_back": rolled_back,
            }
            if rollback_failed:
                out["rollback_failed"] = rollback_failed
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
    """The apply side: drain ``pending/`` (or just ``pair_id``, when named),
    re-verifying the seal and every seat's pre-state fresh before acting.
    Runs as a ``willow-mcp-manifest-grant.timer``/``.service`` unit in the
    BROKER's own ``--user`` manager, under the broker's own uid — no
    ``privileged_publisher``, no sudo bridge, no ``User=`` claim (module
    docstring, pair ``6bd11def``). Never raises past this call; a
    per-request exception is reported and the request moved to ``failed/``
    rather than left to retry forever silently.
    """
    if _in_kart():
        # Advisory, not a privilege boundary (module docstring): the actual
        # boundary this refuses on is "never inside a Kart task" — it says
        # nothing about a distinct uid, because on this box there isn't one
        # (gap 85716b25d9a8). This just turns "ran by accident in the wrong
        # place" into a named refusal instead of a confusing sudo/gpg
        # failure three steps later.
        return {"ok": False, "state": "refused", "error": "EUNREACH",
                "reason": "manifest_grant_apply does not run inside Kart — it runs as the "
                          "broker's own systemd --user unit, never a Kart task",
                "processed": []}

    from . import gate
    apps_root_p = apps_root if apps_root is not None else gate._apps_root()

    # Gap 035d287206e1 (2026-09-22): `Path.is_dir()`/`.exists()` swallow
    # EVERY `OSError` — including `PermissionError` — and return `False`,
    # by design (pathlib's own documented behaviour). That means a genuinely
    # UNREADABLE apps_root/grants_root (the trust-owner uid cannot traverse
    # $WILLOW_HOME) used to read EXACTLY like "nothing pending, all done":
    # `{"ok": true, "state": "empty"}`, every tick, forever — the silent
    # false-positive is worse than a crash, because nothing ever surfaces
    # it. Distinguish "genuinely absent" (a real, expected empty-install
    # state) from "present but this uid cannot even stat it" up front, and
    # refuse the second case by name, listing exactly which path failed.
    for candidate in (apps_root_p.parent, apps_root_p):
        try:
            candidate.stat()
        except FileNotFoundError:
            break  # absent, not blocked — the normal "not installed yet" case
        except OSError as exc:
            return {"ok": False, "state": "refused", "error": "EACCES",
                    "reason": f"cannot reach {candidate}: {type(exc).__name__}: {exc}",
                    "unreadable_path": str(candidate), "processed": []}

    # Loki audit 3, finding 3: the unit template carried no User= and this
    # function made no uid check at all, so enabling it under the operator's
    # own session ran it as the broker's uid and got `eperm` on mcp_apps
    # three layers down in a confusing place. Refuse by name, up front: this
    # process must run AS the uid that owns apps_root — on this box, the
    # broker's own uid (no trust-owner separation exists here, pair
    # 6bd11def); after a real uid split this same check would correctly
    # refuse a run under the wrong identity.
    if apps_root_p.is_dir():
        try:
            owning_uid = apps_root_p.stat().st_uid
        except OSError as exc:
            return {"ok": False, "state": "refused", "error": "EUNREACH",
                    "reason": f"cannot stat apps_root {apps_root_p}: {type(exc).__name__}: {exc}",
                    "processed": []}
        if owning_uid != os.geteuid():
            return {"ok": False, "state": "refused", "error": "ewronguser",
                    "reason": f"manifest_grant_apply is running as uid {os.geteuid()} but "
                              f"apps_root {apps_root_p} is owned by uid {owning_uid} — this "
                              "process must run as the uid that owns apps_root, never any other",
                    "apps_root_uid": owning_uid, "running_uid": os.geteuid(),
                    "processed": []}

    root = _grants_root(grants_root)
    pending_dir = root / "pending"
    for candidate in (root.parent, root, pending_dir):
        try:
            candidate.stat()
        except FileNotFoundError:
            break
        except OSError as exc:
            return {"ok": False, "state": "refused", "error": "EACCES",
                    "reason": f"cannot reach {candidate}: {type(exc).__name__}: {exc}",
                    "unreadable_path": str(candidate), "processed": []}
    if not pending_dir.is_dir():
        return {"ok": True, "state": "empty", "processed": []}
    if pair_id:
        files = [p for p in [pending_dir / f"{pair_id}.json"] if p.is_file()]
    else:
        # Gap 035d287206e1, F2 (Loki audit B00BD43E): the stat() probes
        # above catch "cannot TRAVERSE" (needs only x on the parent) but
        # Path.glob() swallows "cannot LIST" (needs r on pending_dir
        # itself) exactly the way is_dir()/exists() do — a traversable but
        # unreadable pending/ (mode 111) used to read as {ok: true, state:
        # "empty"}, exit 0, silently, forever. os.listdir raises on that;
        # glob does not.
        try:
            names = os.listdir(pending_dir)
        except OSError as exc:
            return {"ok": False, "state": "refused", "error": "EACCES",
                    "reason": f"cannot list {pending_dir}: {type(exc).__name__}: {exc}",
                    "unreadable_path": str(pending_dir), "processed": []}
        files = sorted(pending_dir / n for n in names if n.endswith(".json"))
    if not files:
        return {"ok": True, "state": "empty", "processed": []}

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
            verb = record.get("verb") or VERB
            if verb == VERB:
                outcome = _apply_one(record, f, ledger=ledger, apps_root=apps_root_p,
                                      db_path=db_path, grants_root=root)
            else:
                from . import trust_owner_verbs as _tov

                apply_fn = _tov.APPLY_DISPATCH.get(verb)
                if apply_fn is None:
                    out = {"ok": False, "error": "ENOSYS",
                           "reason": f"no apply handler registered for verb {verb!r}"}
                    _move(f, root / "failed", {**record, "result": out})
                    outcome = {"pair_id": record.get("pair_id"), **out}
                else:
                    outcome = apply_fn(record, f, ledger=ledger, apps_root=apps_root_p,
                                        db_path=db_path, grants_root=root)
            processed.append(outcome)
        except Exception as exc:  # noqa: BLE001 — never let one bad request wedge the drain
            out = {"pair_id": record.get("pair_id", f.stem), "ok": False, "error": "eunexpected",
                   "reason": f"{type(exc).__name__}: {exc}"}
            try:
                _move(f, root / "failed", {**record, "result": out})
            except OSError:
                pass
            processed.append(out)

    return {"ok": all(r.get("ok") for r in processed), "state": "populated", "processed": processed}


# ── retry: failed/ is terminal, but not every failure earned it ────────────

RETRY_EVENT = "manifest_grant_retried"

#: Failure causes a bare retry can plausibly fix without re-sealing anything
#: — a disk hiccup, an unreachable dependency, a race against another
#: request, or a `failed`/`done` directory read that came back corrupt.
#: None of these mean the SEAL, the record, or the request itself was ever
#: wrong (Loki audit 4, MEDIUM: `failed/` was terminal by design even for
#: these, and each one burned a human-sealed pair for a cause that was
#: never the pair's own fault).
RETRYABLE_ERRORS = frozenset({"EUNREACH", "ecorrupt", "eunexpected", "eperm_pending"})

#: Failure causes that mean the request itself was wrong, forged, or
#: refused for a standing policy reason — retrying resubmits exactly what
#: was correctly refused. Never retryable, regardless of age or a
#: plausible-sounding excuse.
#:
#: ``estale_presigned`` (pair ``1bd6fd29`` amendment; sealed ``33654f35``,
#: 2026-09-22) is minted OUTSIDE this module entirely — by
#: ``deploy/manifest-grant/install.sh`` step 6b, which withdraws every
#: request already sitting in ``pending/`` before enabling the timer,
#: because step 6 (re-signing every manifest under a fresh fingerprint)
#: just invalidated every such request's recorded ``pre_state`` and the
#: seat set named in it may itself be stale. Written in the exact shape
#: :func:`_move` produces (the original record's fields spread at the top
#: level, plus a ``result`` key) so :func:`manifest_grant_status` and this
#: set both read it with no special-casing — never retryable: the fix is a
#: fresh request under a current sealed pair, not a replay of pre_state
#: that is now definitionally stale.
TERMINAL_ERRORS = frozenset({"eforged", "eseal_mismatch", "EPERM", "edrift", "estale_presigned"})


def manifest_grant_retry(
    app_id: str,
    pair_id: str,
    *,
    ledger=None,
    grants_root: Optional[Path] = None,
    project: str = "",
) -> dict:
    """Orchestrator-only: move ``failed/<pair_id>.json`` back to ``pending/``
    for the apply side to re-drain — but ONLY when the recorded failure
    reason is on :data:`RETRYABLE_ERRORS`. A cause on :data:`TERMINAL_ERRORS`
    (forgery, a seal that no longer matches the record, an escalation-class
    group, or drift) is refused ``EPERM`` naming the original reason:
    retrying those resubmits exactly what was correctly refused the first
    time, and the fix is a fresh sealed pair, not a replay of this one
    (:func:`manifest_grant_status`'s own docstring, before this verb
    existed, argued exactly this for the general case — this verb is the
    narrow, audited exception for causes that are provably not the pair's
    own fault).

    Requeuing strips the prior ``result`` and re-lands the same
    ``pair_id``/``envelope_id``/``citation_id``/``apps``/``groups``/
    ``pre_state``/``broker_sig`` unchanged (nothing here re-signs or
    re-verifies — that is :func:`manifest_grant_apply`'s job on the next
    drain), appends a ``manifest_grant_retried`` FRANK event naming the
    prior error, and refuses ``EALREADY`` if a pending or done request for
    this ``pair_id`` already exists (a fresh request must never race a
    requeued one).
    """
    from .human_session import is_orchestrator_app

    if not is_orchestrator_app(app_id):
        return _refuse(
            "EPERM",
            f"manifest.grant retry is orchestrator-only; {app_id!r} may not call it",
        )

    root = _grants_root(grants_root)
    failed_path = root / "failed" / f"{pair_id}.json"
    if not failed_path.is_file():
        return _refuse("ENOENT", f"no failed manifest.grant request for pair_id={pair_id!r}")
    try:
        record = json.loads(failed_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return _refuse(
            "EUNREACH",
            f"failed/{pair_id}.json is unreadable, so its failure reason cannot be "
            f"judged retryable: {type(exc).__name__}: {exc}",
        )

    prior_result = record.get("result") or {}
    prior_error = prior_result.get("error")
    if prior_error in TERMINAL_ERRORS or prior_result.get("escalating"):
        return _refuse(
            "EPERM",
            f"pair_id={pair_id!r} failed for {prior_error!r}, which is terminal — "
            "not retryable; re-seal a fresh Nestor pair once the actual cause is "
            "addressed, rather than replaying a request that was correctly refused",
            prior_error=prior_error,
        )
    if prior_error not in RETRYABLE_ERRORS:
        return _refuse(
            "EPERM",
            f"pair_id={pair_id!r} failed for {prior_error!r}, which is on neither the "
            "retryable nor the terminal list — refusing rather than guessing it is "
            "safe to resubmit",
            prior_error=prior_error,
        )

    pending_path = _pending_path(root, pair_id)
    if pending_path.is_file() or (root / "done" / f"{pair_id}.json").is_file():
        return _refuse(
            "EALREADY",
            f"pair_id={pair_id!r} already has a pending or done manifest.grant request",
        )

    requeued = {k: v for k, v in record.items() if k != "result"}
    _write_json_atomic(pending_path, requeued)
    failed_path.unlink(missing_ok=True)

    receipt_id = None
    if ledger is not None:
        try:
            receipt_id = ledger.append(project or "willow-mcp", RETRY_EVENT, {
                "actor": app_id, "pair_id": pair_id,
                "envelope_id": requeued.get("envelope_id"),
                "citation_id": requeued.get("citation_id"),
                "prior_error": prior_error,
            })
        except Exception as exc:  # noqa: BLE001 — the requeue happened; report, never hide
            receipt_id = f"receipt_error: {type(exc).__name__}: {exc}"

    return {
        "ok": True, "state": "requeued", "pair_id": pair_id,
        "prior_error": prior_error, "receipt_id": receipt_id,
    }
