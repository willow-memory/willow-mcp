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
# UNIT can verify — not net_signer's key (that key belongs to the egress
# key's owner, uid 994 on a hardened box, a different uid than the broker's
# 1000 and unreachable to it by design; sharing it here would break that
# split) and not pgp.sign_detached (the request side deliberately signs
# nothing with gpg and needs no gpg-agent — module docstring). Instead: a
# dedicated ed25519 keypair generated on first use under
# ``<grants_root>/broker_signing_key`` (0600, broker-owned, private half
# never leaves this process) with its public half exported alongside it at
# ``<grants_root>/broker_public_key.pub`` (0644 — the apply unit, a
# different uid, must be able to read it; provisioning ``manifest_grants/``
# with a mode both uids can traverse is fix 3's job, tracked there). The
# apply unit never needs the private half at all: it only ever verifies.
#
# What is signed (Loki's own spec): the canonical JSON of exactly
# ``{pair_id, envelope_id, citation_id, apps, groups, pre_state,
# requested_at}`` — the fields that, taken together, ARE the request. A
# forged file with no ``broker_sig``, or one whose signature does not
# verify against this key, is refused ``eforged`` with no grant, before the
# seal, the escalation set, or anything else is even looked at.

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
    payload = {
        "pair_id": record.get("pair_id"),
        "envelope_id": record.get("envelope_id"),
        "citation_id": record.get("citation_id"),
        "apps": record.get("apps"),
        "groups": record.get("groups"),
        "pre_state": record.get("pre_state"),
        "requested_at": record.get("requested_at"),
    }
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


def manifest_grant_status(pair_id: str, *, grants_root: Optional[Path] = None) -> dict:
    """Three-state (plus not_found) read of one request: ``pending`` (the
    unit has not drained it yet), ``done`` (granted, receipts attached),
    ``failed`` (refused or rolled back at apply time), or ``not_found`` (no
    request was ever made for this ``pair_id``). Read-only, never blocks.

    ``failed`` is TERMINAL BY DESIGN (Loki audit 3, medium finding —
    weighed against adding a ``manifest_grant_retry`` orchestrator verb,
    and deliberately not built): a pair that failed once (bad seal at
    apply time, drift, escalation, a forged file, a rollback that could
    not complete) failed for a reason that a bare retry cannot itself
    fix — the seal is still whatever it was, the drift is still there, the
    forgery is still forged. Retrying productively means re-sealing a
    fresh Nestor pair (a NEW pair_id) once the actual cause is addressed,
    not replaying the same failed request. The one-request-per-pair rule
    (``EALREADY``) already refuses a second attempt at the SAME pair_id
    whether it is pending, done, or failed; unsticking a failed one is
    the operator's `rm $WILLOW_HOME/manifest_grants/failed/<pair_id>.json`
    — the one keyboard act this verb was not written to remove, since the
    thing to remove is the FILE, not a re-verification this module could
    perform any more usefully the second time than the first.
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
    try:
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return _refuse(
            "EALREADY",
            f"a manifest.grant request for pair_id={pair_id!r} is already being "
            "written by a concurrent call — one request per sealed pair",
        )
    os.close(lock_fd)
    try:
        return _manifest_grant_request_locked(
            app_id, envelope_id=envelope_id, pair_id=pair_id, project=project,
            session=session, task_id=task_id, ledger=ledger, store=store,
            apps_root=apps_root, db_path=db_path, grants_root_p=grants_root_p,
        )
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

    seal_refusal = _bind_to_seal(pair_id, apps, groups, db_path=db_path)
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
    # Signed AFTER the citation is inked, over the fields that make the
    # request what it is (pair_id, envelope_id, citation_id, apps, groups,
    # pre_state, requested_at) — apply verifies this FIRST, before anything
    # else, so a file this process did not write is never actioned
    # (Loki audit 3, finding 2).
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

    # 2. The seal — re-verified fresh (a pending request can sit for minutes).
    seal_refusal = _bind_to_seal(pair_id, apps, groups, db_path=db_path)
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
    latest = ledger.latest_event("envelope_citation", match={"envelope_id": envelope_id, "outcome": "granted"})
    if (latest is None or latest.get("id") != citation_id
            or (latest.get("content") or {}).get("verb") != VERB):
        return _fail("eforged",
                      f"FRANK carries no granted {VERB!r} envelope_citation matching "
                      f"citation_id={citation_id!r} for pair_id={pair_id!r}")
    cited_args = (latest["content"].get("call_args") or {})
    if set(cited_args.get("apps") or []) != set(apps) or set(cited_args.get("groups") or []) != set(groups):
        return _fail("eforged",
                      "FRANK citation's call_args do not match this request's apps/groups — "
                      "the file was edited after the citation was inked")

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

    from . import gate
    apps_root_p = apps_root if apps_root is not None else gate._apps_root()

    # Loki audit 3, finding 3: the unit template carried no User= and this
    # function made no uid check at all, so enabling it under the operator's
    # own session ran it as the broker's uid — the one identity the design
    # says never publishes — and got `eperm` on mcp_apps three layers down
    # in a confusing place. Refuse by name, up front: this process must run
    # AS the uid that owns apps_root (the trust owner), never any other.
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
                              "process must run AS the trust owner, never any other identity",
                    "apps_root_uid": owning_uid, "running_uid": os.geteuid(),
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
