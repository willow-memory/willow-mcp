"""willow_mcp/manifest_grant_executor.py — a sealed permission grant lands
through a broker verb, signed, never hand-edited.

Verb 18, ``manifest.grant``, sealed under governance decision ``d5504878``
(operator; pair 10ed2707 is the first grant it executes) — see
``src/willow_mcp/bundle/constitutional/syscall-table.json`` row 18. Pattern:
:mod:`unit_install_executor` (verb 17, #588) — envelope lookup + bounds
check + preflight + act + receipt.

Rework (Loki audit, session_handoff-2026-09-21-04472e32): the write path now
REUSES :mod:`manifest_admin`'s staged sign-then-publish discipline instead of
re-implementing it. ``manifest_admin.set_permission`` is documented
"Do not wire this into an ``@mcp.tool()``" — the self-grant vector that
warning exists for is a bare, ungated wrapper. Calling it from inside THIS
executor is a different shape: by the time any seat's manifest is touched,
four preconditions this module enforces (sealed pair, known verifier, no
escalation group, envelope bounds) have already refused every path a caller
could use to steer what gets written. ``set_permission`` is reused for
exactly what it already gets right and this module used to duplicate worse:
pre-state signature verification before mutation, refusing to write unsigned
over signed when the fingerprint has gone missing, signing in a tempdir
before the live manifest is ever touched, and publishing through the
exclusive ``signed_pair_lock`` (`publish_signed_pair` / the sudo bridge
`publish_via_trust_owner` when this uid cannot write the trust root itself).

Four preconditions, none of which an agent can satisfy on its own:

1. a Nestor pair that is ``sealed`` (a human verified it), whose verifier is
   active in the keyring (config/verifiers.json) — not merely present, not
   compromised;
2. the grant is bound to what was actually SEALED, not merely to the mutable
   SOIL governance record `seal_handler.on_seal` keeps upgrading in place.
   The record's ``seats``/``groups`` fields are read-write long after the
   seal lands (probe P4); the ``target_text`` in Nestor's own ``nestor.db``
   is the one artifact the seal signature covers. This module parses that
   text with a strict grammar (:func:`ruling_text` / :data:`_RULING_RE`) and
   refuses (``eseal_mismatch``) when the record disagrees with it;
3. no escalation-class group, ever, regardless of seal or envelope — the
   PreToolUse manifest guard's own list restated here so a grant can never
   open the door the guard exists to keep shut;
4. the caller is the orchestrator seat itself (``is_orchestrator_app``) —
   this is a narrowing REFUSAL layered on top of the manifest gate that
   already authenticated ``app_id`` (the ``@_guarded`` decorator's PGP-backed
   manifest check), not a privilege source in its own right.

Refusals, each with its own errno, all before any envelope citation:

* ``EPERM`` — caller is not the orchestrator seat, or a named group is on
  the escalation list;
* ``EUNREACH`` — running inside Kart (no gpg-agent to sign with), or
  nestor.db cannot be read to bind the grant to what was sealed;
* ``ENOENT`` — no governance record for ``pair_id``, or no active
  ``manifest.grant`` envelope governs the caller;
* ``EACCES`` — the pair is not ``status=sealed`` (on the SOIL record OR in
  nestor.db), or its verifier is not known to the keyring / has been
  revoked as compromised;
* ``EINVAL`` — the governance record's ``seats``/``groups`` fields are
  missing or malformed, or the sealed pair's own text does not match the
  strict grammar this verb requires;
* ``eseal_mismatch`` — the sealed text parses cleanly but names different
  seats/groups than the (mutable) governance record — the record was
  edited after the seal;
* ``EAMBIG`` — more than one active envelope governs the call, or the
  bounds do not cover every named seat/group.

Per-seat write: for each group named by the sealed pair, call
``manifest_admin.set_permission(app_id, group, True,
privileged_publisher=manifest_admin.publish_via_trust_owner)``. Before ever
calling it, this module verifies the seat's EXISTING signature (if any) —
a manifest whose current ``.sig`` does not verify is refused
``esig_prestate`` and never touched (probe P1: never launder a tampered,
currently-denied manifest into a freshly valid one). A ``.sig`` present
with no ``WILLOW_PGP_FINGERPRINT`` configured is refused ``efingerprint_absent``
(probe P2: never write unsigned over signed). A trust-root uid mismatch
(`publish_via_trust_owner`'s sudo bridge failing, or `PermissionError` from a
process that cannot write ``mcp_apps`` at all) is caught and reported
``eperm`` with the path and its owning uid, never left to escape after the
envelope citation is inked (probe P5). ``atomic=True`` (default) additionally
rolls back every seat already granted earlier in the SAME call the moment
one seat (or group, within one seat) fails; FRANK receipts for a call that
rolls back are never inked.

Signing runs in the broker process (uid 1000, gpg-agent reachable as a
``--user`` service); a desktop pinentry prompt is fine and expected. Kart
cannot reach that agent socket, so this refuses outright inside Kart — and,
because an env var alone (``WILLOW_IN_KART`` / ``KART_TASK_ID``) is
forgeable by unsetting it, this also requires a live, reachable gpg-agent
socket before it will attempt to sign (probe P6).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Optional

VERB = "manifest.grant"
EVENT = "manifest_granted"

#: The exact escalation set the PreToolUse manifest guard refuses self-grant
#: of (`hooks/pre_tool_use.py:928-940`, `gate.PERMISSION_GROUPS`). A sealed
#: pair naming any of these is refused here too, regardless of seal or
#: envelope bounds. Loki audit (04472e32, finding 2): this list is EXACTLY
#: the packet's escalation set — nothing more. A prior draft folded in most
#: of gate's other write/admin groups (store_write, grove_write, task_db,
#: ...); that over-broad list refused the verb's own first live pair
#: (10ed2707, which names grove_write) and was never exercised by a test.
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
    for :func:`execute_manifest_grant` to bind a grant to it — what the
    human seals in Nestor is this text; parsing it back out is how a grant
    is bound to what was actually sealed rather than to the mutable SOIL
    record. Order-preserving, comma-joined; no field may contain a comma."""
    for value in (*seats, *groups):
        if "," in value or " " in value:
            raise ValueError(f"seat/group name contains a separator: {value!r}")
    return f"{RULING_FORMAT} seats={','.join(seats)} groups={','.join(groups)}"


def _parse_ruling_text(text: str) -> Optional[dict]:
    """Inverse of :func:`ruling_text`, read from the FIRST line of sealed
    ``target_text``. ``None`` for anything that does not match — a caller
    must never guess seats/groups out of free-form prose."""
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
    return {"ok": False, "error": errno, "granted": [], "refused": [], "reason": reason, **extra}


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _in_kart() -> bool:
    return bool(
        os.environ.get("WILLOW_IN_KART", "").strip()
        or os.environ.get("KART_TASK_ID", "").strip()
    )


def _gpg_agent_reachable() -> bool:
    """Positive proof a gpg-agent socket exists, rather than trusting that
    ``WILLOW_IN_KART``/``KART_TASK_ID`` were left set (Loki probe P6: both
    are plain env vars an agent can unset). ``gpgconf`` reports the socket
    path this GNUPGHOME would use; Kart's bwrap sandbox does not forward it
    even when those two env vars happen to be absent. Any failure to run
    the check at all (gpgconf missing, timeout, ...) is treated as
    unreachable — fail closed, the same disposition every signing guard in
    this codebase takes."""
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


def _verifier_active(verifier: str) -> bool:
    """True iff ``verifier`` is registered in the keyring (config/verifiers.json)
    and not compromised — the same operator-verifier check
    :func:`envelope_authoring.ratify` requires before moving a proposal to
    active. Empty or unknown → False."""
    if not verifier:
        return False
    from . import keyring as _keyring

    ring = _keyring.get_keyring()
    if ring is None:
        return False
    return ring.verifying_entry(verifier) is not None


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


def _bind_to_seal(pair_id: str, apps: list[str], groups: list[str], *,
                   db_path: Optional[Path] = None) -> Optional[dict]:
    """Refuse unless ``apps``/``groups`` (read off the mutable SOIL record)
    match what the sealed pair's own text actually says. Returns a refusal
    dict, or ``None`` when the grant is bound cleanly."""
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
    parsed = _parse_ruling_text(sealed.get("target_text", ""))
    if parsed is None:
        return _refuse(
            "EINVAL",
            f"sealed pair {pair_id!r} text does not match the strict manifest.grant "
            f"grammar ({RULING_FORMAT!r} seats=<a,b> groups=<c,d>) — refusing to guess "
            "what was actually sealed",
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


#: Substrings from `manifest_admin.set_permission`'s own RuntimeError
#: messages, mapped to this verb's structured errno. Frozen alongside that
#: function's wording; a change there that drops these substrings should
#: break the corresponding test here, not silently fall through to "esign".
_ESIGN_FINGERPRINT_ABSENT = "WILLOW_PGP_FINGERPRINT is unset"
_ESIGN_PRESTATE = "current manifest signature is not valid"


def _classify_set_permission_error(exc: RuntimeError) -> str:
    msg = str(exc)
    if _ESIGN_FINGERPRINT_ABSENT in msg:
        return "efingerprint_absent"
    if _ESIGN_PRESTATE in msg:
        return "esig_prestate"
    return "esign"


def _revoke_groups(app_id: str, groups: list[str]) -> None:
    """Best-effort compensating undo of groups THIS seat's call already
    granted via ``set_permission``, when a LATER group for the SAME seat
    fails partway through. Never raises: the outer refusal this backs out
    of is what gets reported; a revoke that itself fails is silently
    best-effort, matching `manifest_admin.publish_via_trust_owner`'s own
    "prior manifest and signature were preserved" guarantee (nothing this
    call granted was left durably applied, but a revoke failing here does
    not invent a NEW error to report over the real one)."""
    from . import manifest_admin

    for g in reversed(groups):
        try:
            manifest_admin.set_permission(
                app_id, g, False, privileged_publisher=manifest_admin.publish_via_trust_owner,
            )
        except Exception:  # noqa: BLE001 — best-effort undo only
            pass


def _grant_one_seat(app_id: str, groups: list[str], *, apps_root: Path) -> dict:
    """Add ``groups`` to one seat's manifest via
    ``manifest_admin.set_permission`` — sign-first, staged, published
    through the exclusive ``signed_pair_lock``, never a hand-rolled write.

    Returns ``{"ok": True, ...}`` with before/after digests on success, or
    ``{"ok": False, "error": ..., "reason": ...}``. Never leaves a
    written-but-unsigned manifest on disk, and never mutates a manifest
    whose EXISTING signature does not verify (``esig_prestate``).
    """
    from . import manifest_admin, pgp

    manifest_path = apps_root / app_id / "manifest.json"
    if not manifest_path.is_file():
        return {"ok": False, "app_id": app_id, "error": "enomanifest",
                "reason": f"no manifest at {manifest_path} — manifest.grant adds "
                          "groups to an existing seat, it does not create one"}

    # Pre-state (Loki probe P1): an existing signature must verify BEFORE
    # this call touches anything. A manifest currently denied by a bad
    # signature must stay denied, not get laundered into a fresh valid one
    # by a grant that only cared about the new content.
    existing_sig = pgp.read_detached_sig_bytes(manifest_path)
    fingerprint = pgp.expected_fingerprint()
    if existing_sig is not None and not fingerprint:
        return {"ok": False, "app_id": app_id, "error": "efingerprint_absent",
                "reason": "manifest already carries a detached signature but "
                          "WILLOW_PGP_FINGERPRINT is unset — refusing to write "
                          "unsigned over signed"}
    if existing_sig is not None:
        ok, detail = pgp.verify_detached(manifest_path, fingerprint=fingerprint)
        if not ok:
            return {"ok": False, "app_id": app_id, "error": "esig_prestate",
                    "reason": "existing manifest signature does not verify against "
                              f"WILLOW_PGP_FINGERPRINT; refusing to mutate a tampered "
                              f"manifest ({detail})"}

    try:
        before_text = manifest_path.read_text(encoding="utf-8")
        current = json.loads(before_text)
    except (OSError, ValueError) as exc:
        return {"ok": False, "app_id": app_id, "error": "eunreadable", "reason": str(exc)}
    if not isinstance(current, dict):
        return {"ok": False, "app_id": app_id, "error": "eunreadable",
                "reason": "manifest.json does not contain a JSON object"}
    before_digest = _digest(before_text.encode("utf-8"))
    perms = list(current.get("permissions") or [])
    added = [g for g in groups if g not in perms]
    if not added:
        return {"ok": True, "app_id": app_id, "groups": [], "changed": False,
                "manifest_sha256": before_digest, "manifest_sha256_before": before_digest,
                "unsigned": existing_sig is None}

    granted_now: list[str] = []
    try:
        for g in added:
            manifest_admin.set_permission(
                app_id, g, True, privileged_publisher=manifest_admin.publish_via_trust_owner,
            )
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


def _rollback_seat(app_id: str, apps_root: Path, previous: dict) -> None:
    """Best-effort undo of a seat this call already granted, when a LATER
    seat in the same ``atomic=True`` call fails."""
    from . import pgp

    manifest_path = apps_root / app_id / "manifest.json"
    pgp.restore_signed_content(
        manifest_path, previous.get("previous_text"), previous.get("previous_sig"),
    )


def execute_manifest_grant(
    app_id: str,
    *,
    envelope_id: str,
    pair_id: str,
    project: str = "",
    session: str = "",
    task_id: str = "",
    atomic: bool = True,
    ledger=None,
    store=None,
    apps_root: Optional[Path] = None,
    db_path: Optional[Path] = None,
) -> dict:
    """Grant the seats/groups a sealed Nestor pair names, under the
    ``manifest.grant`` envelope that governs ``app_id`` — or refuse, cite
    the refusal, and stop.

    ``app_id`` must be the orchestrator seat; ``ledger`` is a
    :class:`GovernanceLedger`; ``store`` / ``apps_root`` / ``db_path`` are
    test seams for the SOIL governance-record store, the manifest root, and
    Nestor's own sqlite ledger.
    """
    from . import gate
    from .envelopes import EnvelopeAuthority, governing_envelopes
    from .human_session import is_orchestrator_app

    if not is_orchestrator_app(app_id):
        return _refuse(
            "EPERM",
            f"manifest.grant is orchestrator-only; {app_id!r} may not call it "
            "regardless of any envelope — a specialist requesting a group for "
            "itself or a peer routes through the operator, never this verb",
        )
    if _in_kart():
        return _refuse(
            "EUNREACH",
            "manifest.grant signs in the broker process; gpg-agent is unreachable "
            "inside the Kart bwrap sandbox (same limit as sign-manifest/sign-seed). "
            "Run this from the broker's own process on the host, not from a "
            "queued Kart task.",
        )
    from . import pgp as _pgp_precheck

    # Loki probe P6: WILLOW_IN_KART/KART_TASK_ID are plain env vars an agent
    # can unset to bypass the check above. Signing is only ever attempted
    # when PGP enforcement is on (`pgp.pgp_enabled()`) — unsigned/dev mode
    # never touches gpg at all, so this positive-presence check is scoped to
    # exactly the case where a missing agent would otherwise be discovered
    # only after the citation was already spent.
    if _pgp_precheck.pgp_enabled() and not _gpg_agent_reachable():
        return _refuse(
            "EUNREACH",
            "no reachable gpg-agent socket — this is checked independently of "
            "WILLOW_IN_KART/KART_TASK_ID. Run from a host terminal/broker "
            "process with a live gpg-agent --user service.",
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
    verifier = record.get("nestor_verifier")
    if not _verifier_active(verifier):
        return _refuse(
            "EACCES",
            f"pair_id={pair_id!r} was sealed by verifier {verifier!r}, which is "
            "unknown to the keyring (config/verifiers.json) or has been revoked "
            "as compromised — a grant refuses rather than trust an unverifiable seal",
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

    result = EnvelopeAuthority(ledger).authorize_and_cite(
        matches[0], actor=app_id, verb=VERB, call_args=call_args,
        project=project or "willow-mcp", session=session,
    )
    if not result.get("ok"):
        errno = result.get("errno", "EAMBIG")
        reason = result.get("reason", "")
        fields = result.get("fields")
        return _refuse(errno, reason, envelope_id=matches[0],
                       citation_id=result.get("citation_id"), fields=fields)

    # ── the act ─────────────────────────────────────────────────────────
    root = apps_root if apps_root is not None else gate._apps_root()

    # `manifest_admin`/`gate` both resolve the trust root from
    # WILLOW_MCP_APPS_ROOT/WILLOW_HOME env, not from a parameter (Loki
    # finding 7: `gate.authorized` must verify against the SAME root this
    # call actually wrote to). When a caller injects an explicit
    # `apps_root` (the test seam), align the env for the duration of the
    # act so every helper this section calls — `set_permission`,
    # `gate.authorized` (exercised indirectly via the caller's own
    # follow-up checks) — agrees with it. Restored in `finally`, never
    # leaked past this call.
    _prior_apps_root_env = os.environ.get("WILLOW_MCP_APPS_ROOT")
    if apps_root is not None:
        os.environ["WILLOW_MCP_APPS_ROOT"] = str(root)

    try:
        granted: list[dict] = []
        refused: list[dict] = []
        receipt_ids: list[str] = []
        rollback_stack: list[tuple[str, dict]] = []
        # FRANK is append-only: a receipt cannot be un-inked. Under atomic=True a
        # seat granted earlier in this call can still be rolled back by a LATER
        # seat's refusal, so its receipt is deferred here and only actually
        # written once every seat in the call has cleared — never for a grant
        # this same call went on to undo. atomic=False has no rollback, so its
        # receipts are written immediately (a later seat's refusal cannot retract
        # an earlier seat's already-final grant).
        pending_receipts: list[dict] = []

        from . import pgp

        for seat in apps:
            previous_text = None
            previous_sig = None
            manifest_path = root / seat / "manifest.json"
            if manifest_path.is_file():
                try:
                    previous_text = manifest_path.read_text(encoding="utf-8")
                except OSError:
                    previous_text = None
                previous_sig = pgp.read_detached_sig_bytes(manifest_path)

            try:
                outcome = _grant_one_seat(seat, groups, apps_root=root)
            except Exception as exc:  # noqa: BLE001 — a citation is already inked; never escape
                outcome = {"ok": False, "app_id": seat, "error": "eunexpected",
                           "reason": f"{type(exc).__name__}: {exc}"}
            if not outcome.get("ok"):
                refused.append(outcome)
                if atomic:
                    for undone_app, snapshot in reversed(rollback_stack):
                        _rollback_seat(undone_app, root, snapshot)
                    return {
                        "ok": False, "error": outcome.get("error", "EAMBIG"),
                        "reason": (f"seat {seat!r} refused ({outcome.get('reason')}); "
                                   f"atomic=True rolled back {len(rollback_stack)} "
                                   f"already-granted seat(s) in this call"),
                        "granted": [], "refused": refused,
                        "rolled_back": [a for a, _ in rollback_stack],
                        "envelope_id": matches[0], "citation_id": result.get("citation_id"),
                    }
                continue

            rollback_stack.append((seat, {"previous_text": previous_text, "previous_sig": previous_sig}))
            granted.append({
                "app_id": seat, "groups": outcome.get("groups", []),
                "manifest_sha256": outcome.get("manifest_sha256"),
                "sig_sha256": outcome.get("sig_sha256", ""),
                "unsigned": outcome.get("unsigned", False),
            })
            if not outcome.get("changed"):
                # Nothing to ink: the seat already held every named group. Same
                # no-op-writes-nothing discipline manifest_admin.set_permission
                # follows for an idempotent re-grant.
                continue
            payload = {
                "actor": app_id, "app_id": seat, "pair_id": pair_id,
                "envelope_id": matches[0], "citation_id": result.get("citation_id"),
                "groups_added": outcome.get("groups", []),
                "manifest_sha256_before": outcome.get("manifest_sha256_before"),
                "manifest_sha256_after": outcome.get("manifest_sha256"),
                "sig_sha256": outcome.get("sig_sha256", ""),
                "session": session,
            }
            if atomic:
                pending_receipts.append((granted[-1], payload))
                continue
            try:
                rec = ledger.append(project or "willow-mcp", EVENT, payload)
                receipt_ids.append(rec)
            except Exception as exc:  # noqa: BLE001 — the grant happened; report, never hide
                granted[-1]["receipt_error"] = f"{type(exc).__name__}: {exc}"

        # Every seat cleared (no refusal returned early above): ink the deferred
        # receipts now, for real.
        for granted_entry, payload in pending_receipts:
            try:
                rec = ledger.append(project or "willow-mcp", EVENT, payload)
                receipt_ids.append(rec)
            except Exception as exc:  # noqa: BLE001 — the grant happened; report, never hide
                granted_entry["receipt_error"] = f"{type(exc).__name__}: {exc}"

        return {
            "ok": not refused,
            "granted": granted,
            "refused": refused,
            "receipt_ids": receipt_ids,
            "envelope_id": matches[0],
            "citation_id": result.get("citation_id"),
            "pair_id": pair_id,
        }
    finally:
        if apps_root is not None:
            if _prior_apps_root_env is None:
                os.environ.pop("WILLOW_MCP_APPS_ROOT", None)
            else:
                os.environ["WILLOW_MCP_APPS_ROOT"] = _prior_apps_root_env
