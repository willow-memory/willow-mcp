"""willow_mcp/trust_owner_verbs.py — four more trust-owner verbs on
manifest_grant_executor's own queue: ``envelope.revoke``, ``manifest.retire``,
``manifest.create``, ``federation.ratify``.

Sealed pair ``1bd6fd29`` (operator, 2026-09-22): "Setup is the installer's
(root, once, detects rather than asks). Operations are Willow's, executed by
the trust-owner apply half under a sealed pair. The operator's only keyboard
act is the seal." Retiring the Jeles seat (sealed ``ae23d366``) handed the
operator four terminal lines nobody had built the propose→seal→apply half
for; this module is that half, built exactly on the ``manifest.grant``
template (:mod:`manifest_grant_executor`, verb 18, sealed ``d5504878`` /
``b74019ac`` / ``6bd11def``) — read that module's docstring first, every
rule there applies here.

Same two halves, same one queue, four more verbs:

* **Request** (broker, orchestrator-only, signs nothing): one function per
  verb below, each mirroring :func:`manifest_grant_executor.
  manifest_grant_request` — orchestrator check, a strict single-line grammar
  parsed out of the sealed pair's OWN ``target_text`` (never the mutable
  SOIL record), :func:`manifest_grant_executor._verify_seal_only` for the
  seal itself, a verb-specific pre-state check, then ONE signed request
  under ``$WILLOW_HOME/manifest_grants/pending/<pair_id>.json`` via
  :func:`manifest_grant_executor._cite_and_persist` (write, cite, sign — in
  that order), gated on the SAME one-request-per-pair queue as
  ``manifest.grant`` (``verb`` distinguishes the record; the queue itself is
  shared, not duplicated).

* **Apply** (unit, trust owner — never Kart, never an ``@mcp.tool()``): one
  function per verb, registered in :data:`APPLY_DISPATCH` and called from
  :func:`manifest_grant_executor.manifest_grant_apply`'s own drain loop,
  which already refuses to run inside Kart and refuses to run as any uid
  other than the one owning ``apps_root`` — nothing about that changes here.
  Each apply function re-verifies the seal AND the target's pre-state fresh
  (:func:`manifest_grant_executor._verify_pending_signature_and_citation`
  for the broker-signature + FRANK-citation half, common to every verb),
  then performs its own act through the SAME staged/signed paths the rest
  of the fleet already uses for that kind of mutation — never a bare
  ``Path.write_text``, never a hand-rolled JSON dump over a trust-root file.

Every apply function receipts to FRANK as ``<verb>_applied`` (dots become
underscores: ``envelope_revoke_applied`` / ``manifest_retire_applied`` /
``manifest_create_applied`` / ``federation_ratify_applied``), citing the
pair and the FRANK citation that authorized it — the same "grants and
denials get the same ink" contract every other verb in
``bundle/constitutional/syscall-table.json`` carries.

Grammar-scope note, restated once rather than per verb: each ``_parse_*``
function below reads ONLY the first line of the sealed ``target_text``; a
sealed pair whose free-text rationale runs below that line is unaffected —
the grammar line is what binds the grant, everything after it is for the
human reader, exactly as :mod:`manifest_grant_executor`'s own
``RULING_FORMAT`` treats prose after its first line.

Escalation note: none of these four verbs consults
:data:`manifest_grant_executor.ESCALATION_GROUPS` for their OWN target
(there is no "seats"/"groups" pair to escalate for ``envelope.revoke``,
``manifest.retire``, or ``federation.ratify``) EXCEPT ``manifest.create``,
whose sealed ``permissions`` list is checked against that exact set —
never grantable at creation any more than at a later ``manifest.grant``.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

from . import manifest_grant_executor as mgx

# ── envelope.revoke ──────────────────────────────────────────────────────

VERB_REVOKE = "envelope.revoke"
EVENT_REVOKE_APPLIED = "envelope_revoke_applied"

_REVOKE_RE = re.compile(r"^revoke envelope (?P<envelope_id>[A-Za-z0-9_.\-]+): (?P<reason>.+)$")


def _parse_envelope_revoke_text(text: str) -> Optional[dict]:
    first_line = (text or "").strip().splitlines()[:1]
    if not first_line:
        return None
    m = _REVOKE_RE.match(first_line[0].strip())
    if not m:
        return None
    reason = m.group("reason").strip()
    if not reason:
        return None
    return {"envelope_id": m.group("envelope_id"), "reason": reason}


def _envelope_registry() -> dict:
    from . import envelopes
    import json as _json

    try:
        return _json.loads(envelopes.registry_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _envelope_active_row(envelope_id: str) -> Optional[dict]:
    for row in (_envelope_registry().get("active") or []):
        if row.get("id") == envelope_id:
            return row
    return None


def _is_row_revoked(row: dict) -> bool:
    return bool(row.get("revoked") or row.get("status") == "revoked")


def envelope_revoke_request(
    app_id: str,
    *,
    envelope_id: str = "",
    pair_id: str,
    project: str = "",
    session: str = "",
    ledger=None,
    store=None,
    db_path: Optional[Path] = None,
    grants_root: Optional[Path] = None,
) -> dict:
    """Broker side of ``envelope.revoke``. Sealed text:
    ``revoke envelope <envelope_id>: <reason>``. Request pre-state: the
    named envelope exists in ``active[]`` and is not already revoked.
    Orchestrator-only; writes one signed request, cites, never revokes
    anything itself — that is :func:`_apply_envelope_revoke`'s job, run as
    the trust-owner unit."""
    from .human_session import is_orchestrator_app

    if not is_orchestrator_app(app_id):
        return mgx._refuse(
            "EPERM", f"{VERB_REVOKE} is orchestrator-only; {app_id!r} may not call it"
        )

    grants_root_p = mgx._grants_root(grants_root)

    def _body() -> dict:
        existing = mgx._existing_request_state(grants_root_p, pair_id)
        if existing is not None:
            return mgx._refuse(
                "EALREADY",
                f"a {VERB_REVOKE} request for pair_id={pair_id!r} already exists ({existing})",
                state=existing,
            )

        pair_result = mgx._load_sealed_pair(pair_id, store=store)
        if not pair_result.get("ok"):
            return pair_result
        gov_record = pair_result["record"]
        if gov_record.get("status") != "sealed":
            return mgx._refuse(
                "EACCES",
                f"pair_id={pair_id!r} governance record is status={gov_record.get('status')!r}, "
                "not 'sealed'",
            )

        refusal, sealed = mgx._verify_seal_only(pair_id, db_path=db_path)
        if refusal is not None:
            return refusal
        parsed = _parse_envelope_revoke_text(sealed.get("target_text", ""))
        if parsed is None:
            return mgx._refuse(
                "EINVAL",
                f"sealed pair {pair_id!r} text does not match the strict {VERB_REVOKE} "
                "grammar ('revoke envelope <envelope_id>: <reason>', one line)",
                sealed_text=sealed.get("target_text"),
            )

        target_envelope_id = parsed["envelope_id"]
        row = _envelope_active_row(target_envelope_id)
        if row is None:
            return mgx._refuse("ENOENT", f"no active envelope with id={target_envelope_id!r} to revoke")
        if _is_row_revoked(row):
            return mgx._refuse(
                "EACCES",
                f"envelope {target_envelope_id!r} is already revoked "
                f"(at {row.get('revoked_at') or 'unknown time'})",
            )

        if ledger is None:
            return mgx._refuse("EAMBIG", "no governance ledger: a request that cannot be cited is not performed")

        target = {"envelope_id": target_envelope_id, "reason": parsed["reason"]}
        pending_path = mgx._pending_path(grants_root_p, pair_id)
        pending_record = {
            "pair_id": pair_id, "verb": VERB_REVOKE, "envelope_id": None, "citation_id": None,
            "actor": app_id, "target": target,
            "project": project or "willow-mcp", "session": session,
            "requested_at": mgx._now_iso(), "pre_state": {"envelope": {"revoked": False}},
        }
        return mgx._cite_and_persist(
            pending_path, pending_record, ledger=ledger, envelope_id=envelope_id,
            app_id=app_id, call_args={"envelope_ids": [target_envelope_id]},
            project=project, session=session,
            pair_id=pair_id, grants_root_p=grants_root_p,
        )

    return mgx._run_locked_request(grants_root_p, pair_id, _body)


def _apply_envelope_revoke(record: dict, path: Path, *, ledger, apps_root: Path,
                            db_path: Optional[Path], grants_root: Path) -> dict:
    pair_id = record.get("pair_id")
    target = record.get("target") or {}
    envelope_id = target.get("envelope_id")
    reason = target.get("reason")

    def _fail(errno: str, reason_msg: str, **extra) -> dict:
        out = {"ok": False, "error": errno, "reason": reason_msg, **extra}
        mgx._move(path, grants_root / "failed", {**record, "result": out})
        return {"pair_id": pair_id, **out}

    dirs_ok, dirs_reason = mgx._dirs_writable(grants_root)
    if not dirs_ok:
        out = {"ok": False, "error": "eperm_pending", "reason": dirs_reason}
        try:
            mgx._move(path, grants_root / "failed", {**record, "result": out})
        except OSError:
            pass
        return {"pair_id": pair_id, **out}

    citation_refusal = mgx._verify_pending_signature_and_citation(
        record, ledger=ledger, grants_root=grants_root, applied_event=EVENT_REVOKE_APPLIED)
    if citation_refusal is not None:
        return _fail(citation_refusal["error"], citation_refusal["reason"])

    seal_refusal, sealed = mgx._verify_seal_only(pair_id, db_path=db_path)
    if seal_refusal is not None:
        return _fail(seal_refusal["error"], seal_refusal["reason"])
    parsed = _parse_envelope_revoke_text(sealed.get("target_text", ""))
    if parsed is None or parsed["envelope_id"] != envelope_id or parsed["reason"] != reason:
        return _fail("eseal_mismatch", "sealed text no longer matches this request's recorded target")

    row = _envelope_active_row(envelope_id)
    if row is None:
        return _fail("ENOENT", f"no active envelope with id={envelope_id!r} to revoke")
    if _is_row_revoked(row):
        return _fail("edrift", f"envelope {envelope_id!r} was already revoked since the request was made")

    from . import envelopes, envelope_authoring

    verifier = sealed.get("verifier") or ""
    try:
        result = envelope_authoring.revoke(envelope_id, verifier=verifier, reason=reason, ledger=ledger)
    except envelope_authoring.EnvelopeAuthoringError as exc:
        return _fail("eunexpected", f"{type(exc).__name__}: {exc}")
    except OSError as exc:
        return _fail(
            "EACCES",
            f"envelope registry not writable by this process: {type(exc).__name__}: {exc}",
            path=str(envelopes.registry_path()),
        )

    payload = {
        "actor": record.get("actor"), "envelope_id": envelope_id, "pair_id": pair_id,
        "request_envelope_id": record.get("envelope_id"), "citation_id": record.get("citation_id"),
        "reason": reason, "revoked_at": result.get("revoked_at"), "session": record.get("session"),
    }
    receipt_ids: list[str] = []
    try:
        receipt_ids.append(ledger.append(record.get("project") or "willow-mcp", EVENT_REVOKE_APPLIED, payload))
    except Exception:  # noqa: BLE001 — the revoke happened; report, never hide
        pass

    out = {"ok": True, "envelope_id": envelope_id, "revoked_at": result.get("revoked_at"), "receipt_ids": receipt_ids}
    mgx._move(path, grants_root / "done", {**record, "result": out})
    return {"pair_id": pair_id, **out}


# ── manifest.retire ──────────────────────────────────────────────────────

VERB_RETIRE = "manifest.retire"
EVENT_RETIRE_APPLIED = "manifest_retire_applied"

_RETIRE_RE = re.compile(r"^retire seat (?P<app_id>[A-Za-z0-9_\-]+): (?P<reason>.+)$")


def _parse_manifest_retire_text(text: str) -> Optional[dict]:
    first_line = (text or "").strip().splitlines()[:1]
    if not first_line:
        return None
    m = _RETIRE_RE.match(first_line[0].strip())
    if not m:
        return None
    reason = m.group("reason").strip()
    if not reason:
        return None
    return {"app_id": m.group("app_id"), "reason": reason}


def _active_envelopes_for_grantee(app_id: str) -> list[dict]:
    out = []
    for row in (_envelope_registry().get("active") or []):
        if _is_row_revoked(row):
            continue
        grantee = row.get("grantee")
        if grantee == app_id or (isinstance(grantee, list) and app_id in grantee):
            out.append(row)
    return out


def manifest_retire_request(
    app_id: str,
    *,
    envelope_id: str = "",
    pair_id: str,
    project: str = "",
    session: str = "",
    ledger=None,
    store=None,
    apps_root: Optional[Path] = None,
    db_path: Optional[Path] = None,
    grants_root: Optional[Path] = None,
) -> dict:
    """Broker side of ``manifest.retire``. Sealed text:
    ``retire seat <app_id>: <reason>``. Request pre-state:
    ``mcp_apps/<app_id>/manifest.json`` exists and its signature verifies;
    refuses ``EBUSY`` naming any ACTIVE envelope that still grants
    ``app_id`` (sealed ``ae23d366`` ordering: revoke before rm). The
    orchestrator seat itself can never be named."""
    from .human_session import is_orchestrator_app

    if not is_orchestrator_app(app_id):
        return mgx._refuse(
            "EPERM", f"{VERB_RETIRE} is orchestrator-only; {app_id!r} may not call it"
        )

    grants_root_p = mgx._grants_root(grants_root)

    def _body() -> dict:
        existing = mgx._existing_request_state(grants_root_p, pair_id)
        if existing is not None:
            return mgx._refuse(
                "EALREADY",
                f"a {VERB_RETIRE} request for pair_id={pair_id!r} already exists ({existing})",
                state=existing,
            )

        pair_result = mgx._load_sealed_pair(pair_id, store=store)
        if not pair_result.get("ok"):
            return pair_result
        gov_record = pair_result["record"]
        if gov_record.get("status") != "sealed":
            return mgx._refuse(
                "EACCES",
                f"pair_id={pair_id!r} governance record is status={gov_record.get('status')!r}, "
                "not 'sealed'",
            )

        refusal, sealed = mgx._verify_seal_only(pair_id, db_path=db_path)
        if refusal is not None:
            return refusal
        parsed = _parse_manifest_retire_text(sealed.get("target_text", ""))
        if parsed is None:
            return mgx._refuse(
                "EINVAL",
                f"sealed pair {pair_id!r} text does not match the strict {VERB_RETIRE} "
                "grammar ('retire seat <app_id>: <reason>', one line)",
                sealed_text=sealed.get("target_text"),
            )

        target_app_id = parsed["app_id"]
        if is_orchestrator_app(target_app_id):
            return mgx._refuse("EPERM", f"{target_app_id!r} is the orchestrator seat — never retired by this verb")

        root = apps_root if apps_root is not None else _default_apps_root()
        pre = mgx._seat_pre_state(target_app_id, root)
        if not pre.get("ok"):
            return {"ok": False, "error": pre["error"], "reason": pre["reason"], "app_id": target_app_id}

        active = _active_envelopes_for_grantee(target_app_id)
        if active:
            return mgx._refuse(
                "EBUSY",
                f"active envelope(s) still name {target_app_id!r} as grantee — revoke first "
                "(sealed ae23d366 ordering: revoke before rm)",
                envelope_ids=[r.get("id") for r in active],
            )

        if ledger is None:
            return mgx._refuse("EAMBIG", "no governance ledger: a request that cannot be cited is not performed")

        target = {"app_id": target_app_id, "reason": parsed["reason"]}
        pending_path = mgx._pending_path(grants_root_p, pair_id)
        pending_record = {
            "pair_id": pair_id, "verb": VERB_RETIRE, "envelope_id": None, "citation_id": None,
            "actor": app_id, "target": target,
            "project": project or "willow-mcp", "session": session,
            "requested_at": mgx._now_iso(),
            "pre_state": {target_app_id: {"manifest_sha256": pre["manifest_sha256"]}},
        }
        return mgx._cite_and_persist(
            pending_path, pending_record, ledger=ledger, envelope_id=envelope_id,
            app_id=app_id, call_args={"apps": [target_app_id]}, project=project, session=session,
            pair_id=pair_id, grants_root_p=grants_root_p,
        )

    return mgx._run_locked_request(grants_root_p, pair_id, _body)


def _apply_manifest_retire(record: dict, path: Path, *, ledger, apps_root: Path,
                            db_path: Optional[Path], grants_root: Path) -> dict:
    pair_id = record.get("pair_id")
    target = record.get("target") or {}
    app_id = target.get("app_id")
    reason = target.get("reason")

    def _fail(errno: str, reason_msg: str, **extra) -> dict:
        out = {"ok": False, "error": errno, "reason": reason_msg, **extra}
        mgx._move(path, grants_root / "failed", {**record, "result": out})
        return {"pair_id": pair_id, **out}

    dirs_ok, dirs_reason = mgx._dirs_writable(grants_root)
    if not dirs_ok:
        out = {"ok": False, "error": "eperm_pending", "reason": dirs_reason}
        try:
            mgx._move(path, grants_root / "failed", {**record, "result": out})
        except OSError:
            pass
        return {"pair_id": pair_id, **out}

    citation_refusal = mgx._verify_pending_signature_and_citation(
        record, ledger=ledger, grants_root=grants_root, applied_event=EVENT_RETIRE_APPLIED)
    if citation_refusal is not None:
        return _fail(citation_refusal["error"], citation_refusal["reason"])

    seal_refusal, sealed = mgx._verify_seal_only(pair_id, db_path=db_path)
    if seal_refusal is not None:
        return _fail(seal_refusal["error"], seal_refusal["reason"])
    parsed = _parse_manifest_retire_text(sealed.get("target_text", ""))
    if parsed is None or parsed["app_id"] != app_id or parsed["reason"] != reason:
        return _fail("eseal_mismatch", "sealed text no longer matches this request's recorded target")

    from .human_session import is_orchestrator_app

    if is_orchestrator_app(app_id):
        return _fail("EPERM", f"{app_id!r} is the orchestrator seat — never retired by this verb")

    pre = mgx._seat_pre_state(app_id, apps_root)
    if not pre.get("ok"):
        return _fail(pre["error"], pre["reason"], app_id=app_id)
    recorded = (record.get("pre_state") or {}).get(app_id) or {}
    if recorded.get("manifest_sha256") != pre["manifest_sha256"]:
        return _fail("edrift", f"{app_id}'s manifest changed since the request was made")

    active = _active_envelopes_for_grantee(app_id)
    if active:
        return _fail(
            "EBUSY",
            f"active envelope(s) still name {app_id!r} as grantee — revoke first",
            envelope_ids=[r.get("id") for r in active],
        )

    retired_dir = apps_root / "_retired"
    src = apps_root / app_id
    dest = retired_dir / f"{app_id}-{pair_id}"
    try:
        retired_dir.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            return _fail("eunexpected", f"retirement destination {dest} already exists")
        os.rename(src, dest)
    except OSError as exc:
        return _fail("EACCES", f"cannot move {src} to {dest}: {type(exc).__name__}: {exc}", path=str(src))

    payload = {
        "actor": record.get("actor"), "app_id": app_id, "pair_id": pair_id,
        "envelope_id": record.get("envelope_id"), "citation_id": record.get("citation_id"),
        "reason": reason, "retired_to": str(dest), "session": record.get("session"),
    }
    receipt_ids: list[str] = []
    try:
        receipt_ids.append(ledger.append(record.get("project") or "willow-mcp", EVENT_RETIRE_APPLIED, payload))
    except Exception:  # noqa: BLE001 — the move happened; report, never hide
        pass

    out = {"ok": True, "app_id": app_id, "retired_to": str(dest), "receipt_ids": receipt_ids}
    mgx._move(path, grants_root / "done", {**record, "result": out})
    return {"pair_id": pair_id, **out}


# ── manifest.create ──────────────────────────────────────────────────────

VERB_CREATE = "manifest.create"
EVENT_CREATE_APPLIED = "manifest_create_applied"

_CREATE_RE = re.compile(
    r"^create seat (?P<app_id>[A-Za-z0-9_\-]+) "
    r"store_scope \[(?P<store_scope>[^\]]*)\] "
    r"store_write \[(?P<store_write>[^\]]*)\] "
    r"permissions \[(?P<permissions>[^\]]*)\]$"
)


def _parse_list(raw: str) -> list[str]:
    return [p.strip() for p in raw.split(",") if p.strip()]


def _parse_manifest_create_text(text: str) -> Optional[dict]:
    first_line = (text or "").strip().splitlines()[:1]
    if not first_line:
        return None
    m = _CREATE_RE.match(first_line[0].strip())
    if not m:
        return None
    return {
        "app_id": m.group("app_id"),
        "store_scope": _parse_list(m.group("store_scope")),
        "store_write": _parse_list(m.group("store_write")),
        "permissions": _parse_list(m.group("permissions")),
    }


def _default_apps_root() -> Path:
    from . import gate

    return gate._apps_root()


def _validate_seat_name(app_id: str) -> Optional[str]:
    from . import gate

    try:
        gate._validate_app_id(app_id)
    except ValueError as exc:
        return str(exc)
    return None


def manifest_create_request(
    app_id: str,
    *,
    envelope_id: str = "",
    pair_id: str,
    project: str = "",
    session: str = "",
    ledger=None,
    store=None,
    apps_root: Optional[Path] = None,
    db_path: Optional[Path] = None,
    grants_root: Optional[Path] = None,
) -> dict:
    """Broker side of ``manifest.create``. Sealed text:
    ``create seat <app_id> store_scope [a, b] store_write [c] permissions [g1, g2]``
    (each list may be empty, ``[]``). Request pre-state: no
    ``mcp_apps/<app_id>/`` exists yet; no named permission is on
    :data:`manifest_grant_executor.ESCALATION_GROUPS`; ``app_id`` passes the
    same seat-name rule :mod:`gate` already enforces. First live use is the
    Jeles corpus organ (sealed ``ae23d366``): ``create seat jeles-corpus
    store_scope [ask_jeles_corpus, ask_jeles_corpus_gaps] store_write
    [ask_jeles_corpus, ask_jeles_corpus_gaps] permissions []``."""
    from .human_session import is_orchestrator_app

    if not is_orchestrator_app(app_id):
        return mgx._refuse(
            "EPERM", f"{VERB_CREATE} is orchestrator-only; {app_id!r} may not call it"
        )

    grants_root_p = mgx._grants_root(grants_root)

    def _body() -> dict:
        existing = mgx._existing_request_state(grants_root_p, pair_id)
        if existing is not None:
            return mgx._refuse(
                "EALREADY",
                f"a {VERB_CREATE} request for pair_id={pair_id!r} already exists ({existing})",
                state=existing,
            )

        pair_result = mgx._load_sealed_pair(pair_id, store=store)
        if not pair_result.get("ok"):
            return pair_result
        gov_record = pair_result["record"]
        if gov_record.get("status") != "sealed":
            return mgx._refuse(
                "EACCES",
                f"pair_id={pair_id!r} governance record is status={gov_record.get('status')!r}, "
                "not 'sealed'",
            )

        refusal, sealed = mgx._verify_seal_only(pair_id, db_path=db_path)
        if refusal is not None:
            return refusal
        parsed = _parse_manifest_create_text(sealed.get("target_text", ""))
        if parsed is None:
            return mgx._refuse(
                "EINVAL",
                f"sealed pair {pair_id!r} text does not match the strict {VERB_CREATE} grammar",
                sealed_text=sealed.get("target_text"),
            )

        seat_id = parsed["app_id"]
        name_error = _validate_seat_name(seat_id)
        if name_error:
            return mgx._refuse("EINVAL", f"{seat_id!r} is not a valid seat name: {name_error}")
        if is_orchestrator_app(seat_id):
            return mgx._refuse(
                "EPERM",
                f"{seat_id!r} collides case-insensitively with the orchestrator seat — "
                f"{VERB_CREATE} can never name it, the same refusal manifest.retire "
                "already makes the other direction (Loki audit BFCC5C79, F5: "
                "is_orchestrator_app lowercases before comparing, but the seat "
                "namespace is case-sensitive on disk)",
            )

        escalating = sorted(set(parsed["permissions"]) & mgx.ESCALATION_GROUPS)
        if escalating:
            return mgx._refuse(
                "EPERM",
                f"pair_id={pair_id!r} names escalation-class permission(s) {escalating!r} — "
                f"never grantable through {VERB_CREATE}",
                escalating=escalating,
            )

        root = apps_root if apps_root is not None else _default_apps_root()
        if (root / seat_id / "manifest.json").is_file():
            return mgx._refuse("EEXIST", f"a manifest already exists for {seat_id!r} — {VERB_CREATE} only ever creates")

        if ledger is None:
            return mgx._refuse("EAMBIG", "no governance ledger: a request that cannot be cited is not performed")

        target = {
            "app_id": seat_id, "store_scope": parsed["store_scope"],
            "store_write": parsed["store_write"], "permissions": parsed["permissions"],
        }
        pending_path = mgx._pending_path(grants_root_p, pair_id)
        pending_record = {
            "pair_id": pair_id, "verb": VERB_CREATE, "envelope_id": None, "citation_id": None,
            "actor": app_id, "target": target,
            "project": project or "willow-mcp", "session": session,
            "requested_at": mgx._now_iso(), "pre_state": {seat_id: {"exists": False}},
        }
        return mgx._cite_and_persist(
            pending_path, pending_record, ledger=ledger, envelope_id=envelope_id,
            app_id=app_id, call_args={"apps": [seat_id], "groups": parsed["permissions"]},
            project=project, session=session,
            pair_id=pair_id, grants_root_p=grants_root_p,
        )

    return mgx._run_locked_request(grants_root_p, pair_id, _body)


def _apply_manifest_create(record: dict, path: Path, *, ledger, apps_root: Path,
                            db_path: Optional[Path], grants_root: Path) -> dict:
    pair_id = record.get("pair_id")
    target = record.get("target") or {}
    seat_id = target.get("app_id")

    def _fail(errno: str, reason_msg: str, **extra) -> dict:
        out = {"ok": False, "error": errno, "reason": reason_msg, **extra}
        mgx._move(path, grants_root / "failed", {**record, "result": out})
        return {"pair_id": pair_id, **out}

    dirs_ok, dirs_reason = mgx._dirs_writable(grants_root)
    if not dirs_ok:
        out = {"ok": False, "error": "eperm_pending", "reason": dirs_reason}
        try:
            mgx._move(path, grants_root / "failed", {**record, "result": out})
        except OSError:
            pass
        return {"pair_id": pair_id, **out}

    citation_refusal = mgx._verify_pending_signature_and_citation(
        record, ledger=ledger, grants_root=grants_root, applied_event=EVENT_CREATE_APPLIED)
    if citation_refusal is not None:
        return _fail(citation_refusal["error"], citation_refusal["reason"])

    seal_refusal, sealed = mgx._verify_seal_only(pair_id, db_path=db_path)
    if seal_refusal is not None:
        return _fail(seal_refusal["error"], seal_refusal["reason"])
    parsed = _parse_manifest_create_text(sealed.get("target_text", ""))
    if parsed is None or parsed != target:
        return _fail("eseal_mismatch", "sealed text no longer matches this request's recorded target")

    escalating = sorted(set(target.get("permissions") or []) & mgx.ESCALATION_GROUPS)
    if escalating:
        return _fail(
            "EPERM",
            f"pair_id={pair_id!r} names escalation-class permission(s) {escalating!r} at apply time",
            escalating=escalating,
        )

    from .human_session import is_orchestrator_app

    if is_orchestrator_app(seat_id):
        return _fail(
            "EPERM",
            f"{seat_id!r} collides case-insensitively with the orchestrator seat at apply "
            "time — refused regardless of what request-time checked (Loki audit BFCC5C79, F5)",
        )

    if (apps_root / seat_id / "manifest.json").is_file():
        return _fail("edrift", f"a manifest for {seat_id!r} was created since the request was made")

    from . import manifest_admin

    try:
        manifest_admin.create_manifest(
            seat_id,
            store_scope=target.get("store_scope") or [],
            store_write=target.get("store_write") or [],
            permissions=target.get("permissions") or [],
        )
    except FileExistsError as exc:
        return _fail("edrift", str(exc))
    except ValueError as exc:
        return _fail("EINVAL", str(exc))
    except RuntimeError as exc:
        return _fail(mgx._classify_set_permission_error(exc), str(exc))
    except OSError as exc:
        return _fail("EACCES", f"{type(exc).__name__}: {exc}")

    manifest_path = apps_root / seat_id / "manifest.json"
    digest = mgx._digest(manifest_path.read_bytes())
    payload = {
        "actor": record.get("actor"), "app_id": seat_id, "pair_id": pair_id,
        "envelope_id": record.get("envelope_id"), "citation_id": record.get("citation_id"),
        "store_scope": target.get("store_scope") or [], "store_write": target.get("store_write") or [],
        "permissions": target.get("permissions") or [], "manifest_sha256": digest,
        "session": record.get("session"),
    }
    receipt_ids: list[str] = []
    try:
        receipt_ids.append(ledger.append(record.get("project") or "willow-mcp", EVENT_CREATE_APPLIED, payload))
    except Exception:  # noqa: BLE001 — the create happened; report, never hide
        pass

    out = {"ok": True, "app_id": seat_id, "manifest_sha256": digest, "receipt_ids": receipt_ids}
    mgx._move(path, grants_root / "done", {**record, "result": out})
    return {"pair_id": pair_id, **out}


# ── federation.ratify ────────────────────────────────────────────────────

VERB_RATIFY = "federation.ratify"
EVENT_RATIFY_APPLIED = "federation_ratify_applied"

_RATIFY_RE = re.compile(
    r"^ratify federation server (?P<name>\S+) command (?P<command>\S+) cwd (?P<cwd>\S+) "
    r"env_keys \[(?P<env_keys>[^\]]*)\](?: args \[(?P<args>[^\]]*)\])?$"
)
_ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _parse_federation_ratify_text(text: str) -> Optional[dict]:
    first_line = (text or "").strip().splitlines()[:1]
    if not first_line:
        return None
    m = _RATIFY_RE.match(first_line[0].strip())
    if not m:
        return None
    env_keys = _parse_list(m.group("env_keys"))
    if not all(_ENV_KEY_RE.match(k) for k in env_keys):
        return None
    args = _parse_list(m.group("args") or "")
    return {
        "name": m.group("name"), "command": m.group("command"), "cwd": m.group("cwd"),
        "env_keys": env_keys, "args": args,
    }


def federation_ratify_request(
    app_id: str,
    *,
    envelope_id: str = "",
    pair_id: str,
    project: str = "",
    session: str = "",
    ledger=None,
    store=None,
    db_path: Optional[Path] = None,
    grants_root: Optional[Path] = None,
) -> dict:
    """Broker side of ``federation.ratify``. Sealed text:
    ``ratify federation server <name> command <abs path> cwd <abs path>
    env_keys [K1, K2]`` (``args [...]`` optional). Request pre-state: the
    command path exists and is executable; every env key is a bare NAME
    (``^[A-Z][A-Z0-9_]*$``) — values are never in a pair. First live use is
    entry ``8cae3d1dcdf4`` (``jeles-corpus``), env_keys ``WILLOW_HOME,
    WILLOW_STORE_ROOT, JELES_CORPUS_APP_ID, NESTOR_KEYRING,
    WILLOW_MCP_APPS_ROOT`` (``NESTOR_SEAL_KEY`` dropped, ``ae23d366`` clause
    2; ``WILLOW_MCP_APPS_ROOT`` added, install note ``8441E2B9``)."""
    from .human_session import is_orchestrator_app

    if not is_orchestrator_app(app_id):
        return mgx._refuse(
            "EPERM", f"{VERB_RATIFY} is orchestrator-only; {app_id!r} may not call it"
        )

    grants_root_p = mgx._grants_root(grants_root)

    def _body() -> dict:
        existing = mgx._existing_request_state(grants_root_p, pair_id)
        if existing is not None:
            return mgx._refuse(
                "EALREADY",
                f"a {VERB_RATIFY} request for pair_id={pair_id!r} already exists ({existing})",
                state=existing,
            )

        pair_result = mgx._load_sealed_pair(pair_id, store=store)
        if not pair_result.get("ok"):
            return pair_result
        gov_record = pair_result["record"]
        if gov_record.get("status") != "sealed":
            return mgx._refuse(
                "EACCES",
                f"pair_id={pair_id!r} governance record is status={gov_record.get('status')!r}, "
                "not 'sealed'",
            )

        refusal, sealed = mgx._verify_seal_only(pair_id, db_path=db_path)
        if refusal is not None:
            return refusal
        parsed = _parse_federation_ratify_text(sealed.get("target_text", ""))
        if parsed is None:
            return mgx._refuse(
                "EINVAL",
                f"sealed pair {pair_id!r} text does not match the strict {VERB_RATIFY} grammar, "
                "or names an env_key that is not a bare NAME",
                sealed_text=sealed.get("target_text"),
            )

        command_path = Path(parsed["command"])
        if not command_path.is_file() or not os.access(command_path, os.X_OK):
            return mgx._refuse("ENOENT", f"command {parsed['command']!r} does not exist or is not executable")
        if not Path(parsed["cwd"]).is_dir():
            return mgx._refuse("ENOENT", f"cwd {parsed['cwd']!r} does not exist")

        if ledger is None:
            return mgx._refuse("EAMBIG", "no governance ledger: a request that cannot be cited is not performed")

        target = dict(parsed)
        pending_path = mgx._pending_path(grants_root_p, pair_id)
        pending_record = {
            "pair_id": pair_id, "verb": VERB_RATIFY, "envelope_id": None, "citation_id": None,
            "actor": app_id, "target": target,
            "project": project or "willow-mcp", "session": session,
            "requested_at": mgx._now_iso(), "pre_state": {"command": {"exists": True}},
        }
        return mgx._cite_and_persist(
            pending_path, pending_record, ledger=ledger, envelope_id=envelope_id,
            app_id=app_id, call_args={"servers": [parsed["name"]]}, project=project, session=session,
            pair_id=pair_id, grants_root_p=grants_root_p,
        )

    return mgx._run_locked_request(grants_root_p, pair_id, _body)


def _apply_federation_ratify(record: dict, path: Path, *, ledger, apps_root: Path,
                              db_path: Optional[Path], grants_root: Path) -> dict:
    pair_id = record.get("pair_id")
    target = record.get("target") or {}

    def _fail(errno: str, reason_msg: str, **extra) -> dict:
        out = {"ok": False, "error": errno, "reason": reason_msg, **extra}
        mgx._move(path, grants_root / "failed", {**record, "result": out})
        return {"pair_id": pair_id, **out}

    dirs_ok, dirs_reason = mgx._dirs_writable(grants_root)
    if not dirs_ok:
        out = {"ok": False, "error": "eperm_pending", "reason": dirs_reason}
        try:
            mgx._move(path, grants_root / "failed", {**record, "result": out})
        except OSError:
            pass
        return {"pair_id": pair_id, **out}

    citation_refusal = mgx._verify_pending_signature_and_citation(
        record, ledger=ledger, grants_root=grants_root, applied_event=EVENT_RATIFY_APPLIED)
    if citation_refusal is not None:
        return _fail(citation_refusal["error"], citation_refusal["reason"])

    seal_refusal, sealed = mgx._verify_seal_only(pair_id, db_path=db_path)
    if seal_refusal is not None:
        return _fail(seal_refusal["error"], seal_refusal["reason"])
    parsed = _parse_federation_ratify_text(sealed.get("target_text", ""))
    if parsed is None or parsed != target:
        return _fail("eseal_mismatch", "sealed text no longer matches this request's recorded target")

    command_path = Path(target["command"])
    if not command_path.is_file() or not os.access(command_path, os.X_OK):
        return _fail("edrift", f"command {target['command']!r} no longer exists or is not executable")

    from . import mcp_federation

    # Loki audit BFCC5C79, F3: mcp_federation.ratify() reads the CURRENT
    # registry via _read_registry_file() and, when its detached signature no
    # longer verifies (the exact state right after install.sh re-signs every
    # SEAT manifest under a fresh WILLOW_PGP_FINGERPRINT but forgets the
    # federation registry itself), silently treats it as `{}` and starts the
    # merge from empty — ratify() itself ignores that second return value.
    # Refuse here, before ever reaching ratify(), rather than let the first
    # post-fingerprint-change federation.ratify silently drop every other
    # ratified server. install.sh step 6 now re-signs servers.json too (same
    # commit), so this should never fire in the intended sequence; it is the
    # backstop for every other way the registry's signature could go stale.
    _existing_entries, _registry_ok = mcp_federation._read_registry_file()
    if not _registry_ok:
        return _fail(
            "EACCES",
            f"federation registry at {mcp_federation.registry_path()} does not verify "
            "under the current WILLOW_PGP_FINGERPRINT (or is corrupt) — refusing to "
            "ratify from what mcp_federation.ratify() would otherwise silently read as "
            "an empty registry, dropping every other ratified entry",
            path=str(mcp_federation.registry_path()),
        )

    resolved = mcp_federation._resolved_command_path(target["command"])
    server_id = mcp_federation._stable_id(resolved, target["name"])
    spec = mcp_federation.McpServerSpec(
        id=server_id, name=target["name"], command=target["command"],
        args=tuple(target.get("args") or ()), env_keys=tuple(target.get("env_keys") or ()),
        cwd=target.get("cwd"), transport="stdio", source_path="",
    )
    verifier = sealed.get("verifier") or ""
    # mcp_federation.ratify's own docstring: "never call this from an MCP
    # tool." Safe by construction here, not by runtime check: only
    # manifest_grant_apply (CLI `manifest-grant apply` / the trust-owner
    # systemd unit, never wired to @mcp.tool()) ever reaches this function;
    # federation_ratify_request (the @mcp.tool()-wired half) only ever
    # writes a pending record and never imports mcp_federation.ratify.
    assert verifier, "ratify without a verifier would violate mcp_federation.ratify's own precondition"
    try:
        entry = mcp_federation.ratify(spec, ratified_by=verifier, reason=f"pair {pair_id}")
    except ValueError as exc:
        return _fail("EINVAL", str(exc))
    except OSError as exc:
        return _fail(
            "EACCES",
            f"federation registry not writable by this process: {type(exc).__name__}: {exc}",
            path=str(mcp_federation.registry_path()),
        )

    payload = {
        "actor": record.get("actor"), "server_id": server_id, "name": target["name"],
        "pair_id": pair_id, "envelope_id": record.get("envelope_id"),
        "citation_id": record.get("citation_id"), "session": record.get("session"),
    }
    receipt_ids: list[str] = []
    try:
        receipt_ids.append(ledger.append(record.get("project") or "willow-mcp", EVENT_RATIFY_APPLIED, payload))
    except Exception:  # noqa: BLE001 — the ratify happened; report, never hide
        pass

    out = {"ok": True, "server_id": server_id, "name": target["name"], "receipt_ids": receipt_ids,
           "ratified_by": entry.get("ratified_by")}
    mgx._move(path, grants_root / "done", {**record, "result": out})
    return {"pair_id": pair_id, **out}


# ── apply-side dispatch, read by manifest_grant_executor.manifest_grant_apply ──

APPLY_DISPATCH = {
    VERB_REVOKE: _apply_envelope_revoke,
    VERB_RETIRE: _apply_manifest_retire,
    VERB_CREATE: _apply_manifest_create,
    VERB_RATIFY: _apply_federation_ratify,
}
