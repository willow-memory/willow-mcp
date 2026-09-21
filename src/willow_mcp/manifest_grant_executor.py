"""willow_mcp/manifest_grant_executor.py — a sealed permission grant lands
through a broker verb, signed, never hand-edited.

Verb 18, ``manifest.grant``, sealed under governance decision ``d5504878``
(operator; pair 10ed2707 is the first grant it executes) — see
``src/willow_mcp/bundle/constitutional/syscall-table.json`` row 18. Pattern:
:mod:`unit_install_executor` (verb 17, #588) — envelope lookup + bounds
check + preflight + act + receipt.

What this verb is NOT: :func:`manifest_admin.set_permission` is the
CLI-only path an operator uses directly and its own docstring says "Do not
wire this into an ``@mcp.tool()``" — writing an app's own manifest from a
tool call is the self-grant vector the sudo invariant forbids. This module
does not call that function. It re-derives the same detach-sign discipline
`server._cmd_sign_manifest` uses (`pgp.sign_detached` / `pgp.verify_detached`
/ `pgp.restore_signed_content`) directly, gated on FOUR preconditions none of
which an agent can satisfy on its own:

1. a Nestor pair that is ``sealed`` (a human verified it), whose verifier is
   active in the keyring (config/verifiers.json) — not merely present, not
   compromised;
2. an active ``manifest.grant`` envelope whose ``apps``/``groups`` bounds
   cover every seat and group the sealed pair names — checked by
   :class:`envelopes.EnvelopeAuthority`, the same fail-closed matcher every
   other enveloped verb uses;
3. no escalation-class group, ever, regardless of seal or envelope — the
   PreToolUse manifest guard's own list (``hooks/pre_tool_use.py``
   ``_SEAT_ESCALATION_REASON``) restated here so a grant can never open the
   door the guard exists to keep shut;
4. the caller is the orchestrator seat itself (``is_orchestrator_app``) —
   this is a narrowing REFUSAL layered on top of the manifest gate that
   already authenticated ``app_id`` (the ``@_guarded`` decorator's PGP-backed
   manifest check), not a privilege source in its own right; see
   ``server.py``'s note above ``human_attestation_create`` for why
   ``is_orchestrator_app`` must never be reintroduced as the ONLY check.

Refusals, each with its own errno, all before any envelope citation:

* ``EPERM`` — caller is not the orchestrator seat, or a named group is on
  the escalation list;
* ``EUNREACH`` — running inside Kart (no gpg-agent to sign with), same
  guard `pgp.signing_blocked` already states;
* ``ENOENT`` — no governance record for ``pair_id``, or no active
  ``manifest.grant`` envelope governs the caller;
* ``EACCES`` — the pair is not ``status=sealed``, or its verifier is not
  known to the keyring / has been revoked as compromised;
* ``EINVAL`` — the governance record's ``seats``/``groups`` fields are
  missing or malformed;
* ``EAMBIG`` — more than one active envelope governs the call, or the
  bounds do not cover every named seat/group.

Per-seat write: read ``$WILLOW_HOME/mcp_apps/<app_id>/manifest.json``,
append the granted groups to ``permissions`` (dedupe, keep order, touch
nothing else), write atomically (tmp + rename, same mode), detach-sign
(``pgp.sign_detached``) when PGP enforcement is on, then verify with the
gate's own check (``gate.authorized``). A sign or verify failure restores
the manifest's previous bytes AND ``.sig`` (`pgp.restore_signed_content`)
and reports ``esign`` for that seat, never leaving a written-but-unsigned
manifest on disk. ``atomic=True`` (default) additionally rolls back every
seat already granted earlier in the SAME call the moment one seat fails.

Signing runs in the broker process (uid 1000, gpg-agent reachable as a
``--user`` service); a desktop pinentry prompt is expected and normal.
Kart cannot reach that agent socket (``WILLOW_IN_KART`` / no agent
forwarded), so this refuses outright inside Kart rather than attempting a
sign that would hang or fail unreachably.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Optional

VERB = "manifest.grant"
EVENT = "manifest_granted"

#: The exact escalation set the PreToolUse manifest guard refuses
#: self-grant of (`hooks/pre_tool_use.py` `_SEAT_ESCALATION_REASON`). A
#: sealed pair naming any of these is refused here too, regardless of seal
#: or envelope bounds — this verb is a disciplined path to the SAME grant
#: surface the guard exists to keep an agent from handing itself.
ESCALATION_GROUPS = frozenset({
    "store_write", "store_all", "knowledge_write", "knowledge_curate",
    "lineage_write", "schema_admin", "nest_write", "gap_write", "gap_promote",
    "gap_purge", "friction_write", "task_db", "task_queue", "dispatch_write",
    "human_loop_write", "frank_write", "envelope_apply", "envelope_write",
    "fork_write", "commitment_write", "code_graph_write", "agent_dispatch",
    "grove_write", "grove_all", "integration_call", "federation_call",
    "markdownai_write", "markdownai_directives", "orchestrator", "context",
    "binding", "tool_oracle_route", "tool_oracle_seal", "governance_propose",
    "governance_sync", "full_access",
    # Capability flags, not permission groups, but just as escalatory as any
    # of the above — a sealed pair naming them is refused for the same
    # reason the guard names them in the same breath.
    "task_net", "integration_net", "web_net", "mcp_federation", "grove_relay",
})


def _refuse(errno: str, reason: str, **extra) -> dict:
    return {"ok": False, "error": errno, "granted": [], "refused": [], "reason": reason, **extra}


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _in_kart() -> bool:
    return bool(
        os.environ.get("WILLOW_IN_KART", "").strip()
        or os.environ.get("KART_TASK_ID", "").strip()
    )


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


def _write_manifest_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = path.stat().st_mode if path.exists() else None
    tmp = path.with_name(path.name + f".tmp-{os.getpid()}")
    try:
        tmp.write_text(text, encoding="utf-8")
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _grant_one_seat(
    app_id: str, groups: list[str], *, apps_root: Path, sign: bool,
) -> dict:
    """Add ``groups`` to one seat's manifest, sign, and verify.

    Returns ``{"ok": True, ...}`` with before/after digests on success, or
    ``{"ok": False, "error": "esign"|"enomanifest"|..., "reason": ...}``.
    Never leaves a written-but-unsigned manifest on disk: any sign or
    verify failure restores the previous bytes AND ``.sig``.
    """
    import json

    from . import gate, pgp

    manifest_path = apps_root / app_id / "manifest.json"
    if not manifest_path.is_file():
        return {"ok": False, "app_id": app_id, "error": "enomanifest",
                "reason": f"no manifest at {manifest_path} — manifest.grant adds "
                          "groups to an existing seat, it does not create one"}
    try:
        previous_text = manifest_path.read_text(encoding="utf-8")
        manifest = json.loads(previous_text)
    except (OSError, ValueError) as exc:
        return {"ok": False, "app_id": app_id, "error": "eunreadable", "reason": str(exc)}
    if not isinstance(manifest, dict):
        return {"ok": False, "app_id": app_id, "error": "eunreadable",
                "reason": "manifest.json does not contain a JSON object"}

    perms = list(manifest.get("permissions") or [])
    added = [g for g in groups if g not in perms]
    if not added:
        digest = _digest(previous_text.encode("utf-8"))
        return {"ok": True, "app_id": app_id, "groups": [], "changed": False,
                "manifest_sha256": digest, "manifest_sha256_before": digest,
                "unsigned": not sign}

    manifest["permissions"] = perms + added
    new_text = json.dumps(manifest, indent=2) + "\n"
    before_digest = _digest(previous_text.encode("utf-8"))
    previous_sig = pgp.read_detached_sig_bytes(manifest_path)
    sig_before_digest = _digest(previous_sig) if previous_sig else ""

    _write_manifest_atomic(manifest_path, new_text)
    after_digest = _digest(new_text.encode("utf-8"))

    if not sign:
        return {"ok": True, "app_id": app_id, "groups": added, "changed": True,
                "manifest_sha256": after_digest, "manifest_sha256_before": before_digest,
                "unsigned": True}

    ok, detail = pgp.sign_detached(manifest_path)
    if not ok:
        pgp.restore_signed_content(manifest_path, previous_text, previous_sig)
        return {"ok": False, "app_id": app_id, "error": "esign",
                "reason": f"sign failed, manifest restored: {detail}"}
    if not gate.authorized(app_id):
        pgp.restore_signed_content(manifest_path, previous_text, previous_sig)
        return {"ok": False, "app_id": app_id, "error": "esign",
                "reason": "signed manifest failed gate.authorized() re-verification, restored"}
    sig_after = pgp.read_detached_sig_bytes(manifest_path)
    return {
        "ok": True, "app_id": app_id, "groups": added, "changed": True,
        "manifest_sha256": after_digest, "manifest_sha256_before": before_digest,
        "sig_sha256": _digest(sig_after) if sig_after else "",
        "sig_sha256_before": sig_before_digest, "unsigned": False,
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
) -> dict:
    """Grant the seats/groups a sealed Nestor pair names, under the
    ``manifest.grant`` envelope that governs ``app_id`` — or refuse, cite
    the refusal, and stop.

    ``app_id`` must be the orchestrator seat; ``ledger`` is a
    :class:`GovernanceLedger`; ``store`` / ``apps_root`` are test seams for
    the SOIL governance-record store and the manifest root.
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
    from . import pgp

    root = apps_root if apps_root is not None else gate._apps_root()
    sign = pgp.pgp_enabled()

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

        outcome = _grant_one_seat(seat, groups, apps_root=root, sign=sign)
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
