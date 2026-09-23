"""willow_mcp/trust_owner_verbs.py — five trust-owner verbs on
manifest_grant_executor's own queue: ``envelope.revoke``, ``manifest.retire``,
``manifest.create``, ``federation.ratify``, ``envelope.ratify``.

Sealed pair ``1bd6fd29`` (operator, 2026-09-22): "Setup is the installer's
(root, once, detects rather than asks). Operations are Willow's, executed by
the trust-owner apply half under a sealed pair. The operator's only keyboard
act is the seal." Retiring the Jeles seat (sealed ``ae23d366``) handed the
operator four terminal lines nobody had built the propose→seal→apply half
for; this module is that half, built exactly on the ``manifest.grant``
template (:mod:`manifest_grant_executor`, verb 18, sealed ``d5504878`` /
``b74019ac`` / ``6bd11def``) — read that module's docstring first, every
rule there applies here.

**Amendment (sealed ``9fe5e179`` / gap ``aafad73d4606``):** routine
``envelope.ratify`` is an *envelope click*, not a Nestor knowledge seal.
The desk default is :func:`envelope_ratify_click_request` (and the
``envelope_ratify`` MCP tool's EACCES fall-through): attributed session +
operator words. :func:`envelope_ratify_request` remains the remote /
unattended sealed-pair path only. Manifest/federation/revoke verbs still
use sealed pairs as their human act.

Same two halves, same one queue, five verbs:

* **Request** (broker, orchestrator-only, signs nothing): one function per
  verb below, each mirroring :func:`manifest_grant_executor.
  manifest_grant_request` — orchestrator check, then (for sealed-pair
  verbs) a strict single-line grammar parsed out of the sealed pair's OWN
  ``target_text`` (never the mutable SOIL record) and
  :func:`manifest_grant_executor._verify_seal_only`; for the envelope.ratify
  *click* path, the human act is the attributed session instead. Then ONE
  signed request under ``$WILLOW_HOME/manifest_grants/pending/<pair_id>.json``
  via :func:`manifest_grant_executor._cite_and_persist` (write, cite, sign —
  in that order), gated on the SAME one-request-per-pair queue as
  ``manifest.grant`` (``verb`` distinguishes the record; the queue itself is
  shared, not duplicated).

* **Apply** (unit, trust owner — never Kart, never an ``@mcp.tool()``): one
  function per verb, registered in :data:`APPLY_DISPATCH` and called from
  :func:`manifest_grant_executor.manifest_grant_apply`'s own drain loop,
  which already refuses to run inside Kart and refuses to run as any uid
  other than the one owning ``apps_root`` — nothing about that changes here.
  Each apply function re-verifies the request (broker signature + FRANK
  citation; sealed-pair verbs also re-verify the seal) and the target's
  pre-state fresh, then performs its own act through the SAME staged/signed
  paths the rest of the fleet already uses for that kind of mutation —
  never a bare ``Path.write_text``, never a hand-rolled JSON dump over a
  trust-root file.

Every apply function receipts to FRANK as ``<verb>_applied`` (dots become
underscores: ``envelope_revoke_applied`` / ``manifest_retire_applied`` /
``manifest_create_applied`` / ``federation_ratify_applied``), citing the
pair and the FRANK citation that authorized it — the same "grants and
denials get the same ink" contract every other verb in
``bundle/constitutional/syscall-table.json`` carries. ``envelope.ratify`` is
the one deliberate exception: it inks ``envelope_ratified`` (never
``envelope_ratify_applied``) — the SAME event name
:func:`envelope_authoring.ratify` already inks for the sidecar path, so a
FRANK reader filtering for "what did the operator say yes to" sees an
envelope becoming active identically regardless of which of the two paths
produced it. That event's payload still carries ``citation_id``, so
:func:`manifest_grant_executor._verify_pending_signature_and_citation`'s
own replay guard (which needs SOME event name to check a citation was not
already consumed) works unchanged with no second event to keep in sync.

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
            # Gap 035d287206e1, F1: embed the sealed row's own bytes so the
            # apply half re-verifies the signature without opening
            # nestor.db (a WAL database — see manifest_grant_executor's
            # note above _SEALED_ROW_FIELDS).
            "sealed_row": mgx._sealed_row_fields(sealed),
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

    # Gap 035d287206e1, F1: never opens nestor.db at apply — verifies the
    # sealed row's bytes the request half already embedded (and signed).
    seal_refusal, sealed = mgx._verify_seal_only(pair_id, sealed_row=record.get("sealed_row"))
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
    """Rows a live `EnvelopeAuthority.check()` could still grant against for
    this app_id — the EBUSY predicate manifest.retire refuses on. Loki audit
    54E3DFC0, F8: this used to only check `_is_row_revoked`, broader than the
    gate's own definition of "usable" (`envelopes.usable_active_grants` plus
    `status == 'active'`, unexpired) — a row that is merely archived,
    expired, or otherwise not `status == 'active'` could never be granted by
    the gate yet still blocked a retirement here. Mirrors the gate's own
    filters (not a full `check()` replay — no verb/bounds/actor match is
    meaningful without a specific call to test against)."""
    from datetime import datetime, timezone

    from . import envelopes

    out = []
    now = datetime.now(timezone.utc)
    for row in envelopes.usable_active_grants(_envelope_registry()):
        if _is_row_revoked(row):
            continue
        if row.get("status") != "active":
            continue
        try:
            expiry = envelopes._deadline(row.get("expires_at"))
        except ValueError:
            expiry = None
        if expiry and expiry <= now:
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
            # Gap 035d287206e1, F1 — see note above mgx._SEALED_ROW_FIELDS.
            "sealed_row": mgx._sealed_row_fields(sealed),
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

    # Gap 035d287206e1, F1: never opens nestor.db at apply.
    seal_refusal, sealed = mgx._verify_seal_only(pair_id, sealed_row=record.get("sealed_row"))
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
        # Loki audit 42B3B46F, U2: explicit mode, not left to the calling
        # process's umask -- the same fix _atomic_write needed for the
        # proposals sidecar directory (T2, 367C367A). A freshly-created
        # _retired/ at whatever a permissive umask allows (e.g. 0o775 under
        # 0002) would carry group/other-write bits nothing here intends.
        if not retired_dir.exists():
            retired_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
            os.chmod(retired_dir, 0o755)
        else:
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
    [ask_jeles_corpus, ask_jeles_corpus_gaps] permissions [gap_write]`` —
    corrected, Loki audit 367C367A, T4: the live sealed line grants
    ``gap_write`` (tonight's #619 red needs the organ able to forward gaps);
    an empty permissions list here was documentary drift, not what was
    actually sealed."""
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
        # gate._validate_app_id (above) only checks the id's charset/shape —
        # it carries no reserved-name guard. manifest_admin.create_manifest
        # (apply time) uses paths._validate_app_id instead, which DOES
        # refuse a seat named after a reserved container directory
        # (including `_retired`/`_federation` as of Loki audit 54E3DFC0,
        # F9) — check the same thing here so a doomed request never spends
        # a citation on an apply that was always going to refuse.
        from . import paths as _paths

        try:
            _paths._validate_app_id(seat_id)
        except ValueError as exc:
            return mgx._refuse("EINVAL", f"{seat_id!r} is not a valid seat name: {exc}")
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

        # Loki audit 54E3DFC0, F10: request time only ever checked the
        # escalation subset, never whether each named permission is even
        # KNOWN — manifest_admin.create_manifest's own validate_permission
        # call would refuse EINVAL at apply time regardless, but only after
        # this request had already spent a citation on a doomed apply. Same
        # check, moved earlier.
        from . import manifest_admin as _manifest_admin

        for perm in parsed["permissions"]:
            try:
                _manifest_admin.validate_permission(perm)
            except ValueError as exc:
                return mgx._refuse("EINVAL", str(exc))

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
            # Gap 035d287206e1, F1 — see note above mgx._SEALED_ROW_FIELDS.
            "sealed_row": mgx._sealed_row_fields(sealed),
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

    # Gap 035d287206e1, F1: never opens nestor.db at apply.
    seal_refusal, sealed = mgx._verify_seal_only(pair_id, sealed_row=record.get("sealed_row"))
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
            # Gap 035d287206e1, F1 — see note above mgx._SEALED_ROW_FIELDS.
            "sealed_row": mgx._sealed_row_fields(sealed),
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

    # Gap 035d287206e1, F1: never opens nestor.db at apply.
    seal_refusal, sealed = mgx._verify_seal_only(pair_id, sealed_row=record.get("sealed_row"))
    if seal_refusal is not None:
        return _fail(seal_refusal["error"], seal_refusal["reason"])
    parsed = _parse_federation_ratify_text(sealed.get("target_text", ""))
    if parsed is None or parsed != target:
        return _fail("eseal_mismatch", "sealed text no longer matches this request's recorded target")

    command_path = Path(target["command"])
    if not command_path.is_file() or not os.access(command_path, os.X_OK):
        return _fail("edrift", f"command {target['command']!r} no longer exists or is not executable")

    # Loki audit 54E3DFC0, F10: only `command` was re-checked at apply time;
    # `cwd` (also apply-time-fixed in the target, also named in the sealed
    # text) could vanish between request and apply exactly like `command`
    # can, and mcp_federation would otherwise spawn the server against a
    # working directory that no longer exists.
    cwd_value = target.get("cwd")
    if cwd_value and not Path(cwd_value).is_dir():
        return _fail("edrift", f"cwd {cwd_value!r} no longer exists")

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


# ── envelope.ratify ──────────────────────────────────────────────────────
#
# Gap d3f79320ccb5, measured live 2026-09-22T07:4xZ right after the
# installer ran: the desk's own envelope_ratify -> EACCES, "there is no
# uid on the box that can complete ratify() as written"
# (envelope_authoring._register_writable). Three envelopes were queued
# behind it (two pushes, one pr.open) and every governed act on the desk
# was stopped. Same shape as the other four verbs above, with one twist
# forced by the box's own two-uid split (Loki audits 367C367A T1 / 42B3B46F
# U1): the trust-owner apply half can WRITE the active register but cannot
# READ the broker-owned 0600 proposals sidecar at all, so unlike
# envelope.revoke (which only ever touches the register), this request half
# copies the proposal's FULL row into the signed request at request time —
# the broker CAN read its own sidecar; the apply half then needs only the
# request, never the sidecar.

VERB_ENVELOPE_RATIFY = "envelope.ratify"
EVENT_ENVELOPE_RATIFIED = "envelope_ratified"

#: Pending-record auth for the desk click path (sealed 9fe5e179 / gap
#: aafad73d4606): attributed orchestrator session + operator words — not a
#: Nestor knowledge seal. The sealed-pair path leaves ``auth`` unset /
#: absent and carries ``sealed_row`` instead.
AUTH_SESSION_CLICK = "session_click"


def click_request_id(proposal_id: str) -> str:
    """Stable queue id for a session-click ratify of ``proposal_id``.

    Distinct from Nestor pair UUIDs so the shared ``manifest_grants/``
    queue never collides a click with a sealed-pair request for the same
    proposal. Filename-safe: proposal ids are already ``[A-Za-z0-9_.-]``.
    """
    return f"click-{proposal_id}"

# Loki audit BDC2B0F2, A2 (high, blocking): the grammar used to bind only
# the proposal id and the operator's words -- the proposal ITSELF (verb,
# grantee, bounds, expires_at, max_count, use_count_source) was copied at
# REQUEST time from the broker's own unsigned, broker-writable 0600
# sidecar, and the apply half compared nothing in that copy but `id`.
# Measured: edit the sidecar after propose and the row the request copies
# reads grantee=attacker, bounds={'a': ['*']}, while the sealed text still
# says only `ratify envelope <id>: <words>` -- the apply half would sign
# that row into the register as issued_by=root. The human sealed an id;
# the agent chose the grant. The grammar now carries a DIGEST over the
# proposal's governing fields, computed from the row the operator actually
# saw via envelope_pending_read when the pair was drafted -- the seal now
# covers the grant's CONTENT, not just its name.
_ENVELOPE_RATIFY_RE = re.compile(
    r"^ratify envelope (?P<proposal_id>[A-Za-z0-9_.\-]+) (?P<digest>[0-9a-f]{64}): (?P<words>.+)$"
)

#: The exact field set the digest covers -- everything about a proposal
#: that governs what the ratified envelope actually authorizes.
#: `bounds_digest` (the field FRANK's own `envelope_proposed` event
#: carries) covers only `bounds`; this covers the rest too
#: (expires_at/max_count/use_count_source), which a bounds-only digest
#: would let drift silently (Loki audit BDC2B0F2, A2's own note: "a
#: max_count: 1 -> null edit survives a digest check" against bounds
#: alone).
_DIGEST_FIELDS = ("verb", "verb_id", "grantee", "bounds", "expires_at", "max_count", "use_count_source")


def _proposal_digest(row: dict) -> str:
    """sha256 hex over the canonical JSON of ``row``'s governing fields
    (:data:`_DIGEST_FIELDS`). Computed by the desk when drafting the
    sealed pair (from the row the operator actually saw via
    ``envelope_pending_read``), recomputed here from whatever row travels
    with the request/is copied at apply time — any disagreement means the
    row is not the one that was sealed."""
    import hashlib
    import json as _json

    payload = {k: row.get(k) for k in _DIGEST_FIELDS}
    canonical = _json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _parse_envelope_ratify_text(text: str) -> Optional[dict]:
    first_line = (text or "").strip().splitlines()[:1]
    if not first_line:
        return None
    m = _ENVELOPE_RATIFY_RE.match(first_line[0].strip())
    if not m:
        return None
    words = m.group("words").strip()
    if not words:
        return None
    return {"proposal_id": m.group("proposal_id"), "digest": m.group("digest"), "words": words}


def _envelope_registry_view() -> dict:
    """The merged registry view (``active``/``proposals``/``archived``) —
    the broker's own read, used ONLY at request time (this half runs as
    the broker, which owns the sidecar and can read the register through
    ``trusted_read``'s signature branch). Deferred import: :mod:`envelope_authoring`
    is a heavier import than the rest of this module needs at load time."""
    from . import envelope_authoring as _ea

    return _ea._load_registry()


def _verify_proposal_against_frank(row: dict, *, ledger) -> Optional[dict]:
    """Cross-check ``row`` (the proposal copy travelling inside the signed
    request) against FRANK's own ``envelope_proposed`` event for this id —
    the anchor :func:`envelope_authoring.propose` inks BEFORE any seal
    exists and the broker cannot rewrite after the fact (Loki audit
    BDC2B0F2, A2, second independent anchor alongside the sealed digest).
    Returns a refusal dict on any disagreement or a missing event; ``None``
    when every field checked agrees. Checked at BOTH halves: the request
    half refuses fast when the sidecar was already tampered with before
    the request was even written; the apply half's own check is the one
    that actually holds, since it runs on the copy that travels inside the
    signed, citation-bound request."""
    if ledger is None:
        return mgx._refuse(
            "EUNREACH",
            "no FRANK ledger available to confirm this proposal's own envelope_proposed event",
        )
    proposal_id = row.get("id")
    try:
        events = ledger.all_events("envelope_proposed", match={"envelope_id": proposal_id})
    except Exception as exc:  # noqa: BLE001 — ledger unreachable is refused, never swallowed
        return mgx._refuse(
            "EUNREACH",
            f"FRANK ledger unreachable while checking envelope_proposed for {proposal_id!r}: "
            f"{type(exc).__name__}: {exc}",
        )
    proposed = next((e for e in events if (e.get("content") or {}).get("envelope_id") == proposal_id), None)
    if proposed is None:
        return mgx._refuse(
            "edrift",
            f"no FRANK envelope_proposed event found for proposal {proposal_id!r} — cannot "
            "confirm what the operator actually saw when the pair was sealed",
        )
    from . import envelope_authoring as _ea

    content = proposed.get("content") or {}
    mismatches = []
    if content.get("verb") != row.get("verb"):
        mismatches.append("verb")
    if content.get("verb_id") != row.get("verb_id"):
        mismatches.append("verb_id")
    if content.get("grantee") != row.get("grantee"):
        mismatches.append("grantee")
    if content.get("bounds_digest") != _ea._bounds_digest(row.get("bounds") or {}):
        mismatches.append("bounds")
    if mismatches:
        return mgx._refuse(
            "edrift",
            f"proposal {proposal_id!r}'s copied row disagrees with FRANK's own "
            f"envelope_proposed event on {mismatches!r} — the sidecar may have been "
            "edited after propose",
            fields=mismatches,
        )
    return None


def envelope_ratify_click_request(
    app_id: str,
    *,
    proposal_id: str,
    verifier: str,
    words: str = "ratify",
    envelope_id: str = "",
    project: str = "",
    session: str = "",
    ledger=None,
    grants_root: Optional[Path] = None,
) -> dict:
    """Desk click path for ``envelope.ratify`` (sealed ``9fe5e179`` / gap
    ``aafad73d4606``): an attributed orchestrator session + the operator's
    verbatim words — not a Nestor knowledge seal. Writes one signed request
    carrying a full copy of the proposal row; the trust-owner apply half
    completes the move. Same queue and cite/sign discipline as
    :func:`envelope_ratify_request`; the pending record carries
    ``auth=session_click`` and no ``sealed_row``.

    Digests and FRANK's ``envelope_proposed`` still bind the grant's
    CONTENT (Loki BDC2B0F2 A2) — only the human-act instrument changes
    from memory.seal to the envelope click.
    """
    from .human_session import is_orchestrator_app

    if not is_orchestrator_app(app_id):
        return mgx._refuse(
            "EPERM", f"{VERB_ENVELOPE_RATIFY} is orchestrator-only; {app_id!r} may not call it"
        )
    words = (words or "").strip()
    if not words:
        return mgx._refuse("EINVAL", "words must be the operator's non-empty ratification text")
    verifier = (verifier or "").strip()
    if not verifier:
        return mgx._refuse("EINVAL", "verifier is required for a session-click ratify")
    proposal_id = (proposal_id or "").strip()
    if not proposal_id:
        return mgx._refuse("EINVAL", "proposal_id is required")

    pair_id = click_request_id(proposal_id)
    grants_root_p = mgx._grants_root(grants_root)

    def _body() -> dict:
        existing = mgx._existing_request_state(grants_root_p, pair_id)
        if existing is not None:
            return mgx._refuse(
                "EALREADY",
                f"a {VERB_ENVELOPE_RATIFY} click request for proposal_id={proposal_id!r} "
                f"already exists ({existing})",
                state=existing,
                pair_id=pair_id,
            )

        registry = _envelope_registry_view()
        active_ids = {r.get("id") for r in (registry.get("active") or [])}
        if proposal_id in active_ids:
            return mgx._refuse(
                "EALREADY",
                f"envelope {proposal_id!r} is already active — nothing to ratify",
                envelope_id=proposal_id,
            )

        proposal_row = None
        for row in registry.get("proposals") or []:
            if row.get("id") == proposal_id:
                proposal_row = row
                break
        if proposal_row is None:
            return mgx._refuse(
                "ENOENT", f"no pending proposal with id={proposal_id!r} to ratify"
            )

        if ledger is None:
            return mgx._refuse(
                "EAMBIG", "no governance ledger: a request that cannot be cited is not performed"
            )

        digest = _proposal_digest(proposal_row)
        frank_refusal = _verify_proposal_against_frank(proposal_row, ledger=ledger)
        if frank_refusal is not None:
            return frank_refusal

        target = {
            "proposal_id": proposal_id,
            "digest": digest,
            "words": words,
            "verifier": verifier,
            "proposal": {k: v for k, v in proposal_row.items() if not k.startswith("_")},
        }
        pending_path = mgx._pending_path(grants_root_p, pair_id)
        pending_record = {
            "pair_id": pair_id,
            "verb": VERB_ENVELOPE_RATIFY,
            "auth": AUTH_SESSION_CLICK,
            "envelope_id": None,
            "citation_id": None,
            "actor": app_id,
            "target": target,
            "project": project or "willow-mcp",
            "session": session,
            "requested_at": mgx._now_iso(),
            "pre_state": {"proposal": {"exists": True}, proposal_id: {"active": False}},
            # No sealed_row — the human act is the attributed session click,
            # not a Nestor knowledge seal (9fe5e179 / aafad73d4606).
        }
        return mgx._cite_and_persist(
            pending_path, pending_record, ledger=ledger, envelope_id=envelope_id,
            app_id=app_id, call_args={"proposal_ids": [proposal_id]},
            project=project, session=session,
            pair_id=pair_id, grants_root_p=grants_root_p,
        )

    return mgx._run_locked_request(grants_root_p, pair_id, _body)


def envelope_ratify_request(
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
    """Broker side of ``envelope.ratify`` for the REMOTE / UNATTENDED path
    (gap ``aafad73d4606``): a human-sealed Nestor pair whose ``target_text``
    is ``ratify envelope <proposal_id> <digest>: <words>``. The desk's
    default click is :func:`envelope_ratify_click_request` (and the
    ``envelope_ratify`` MCP tool's EACCES fall-through) — sealed
    ``9fe5e179``: routine authority is an envelope, not a Nestor seal.

    ``<digest>`` is :func:`_proposal_digest` over the proposal's own
    governing fields — the seal binds the grant's CONTENT, not just its
    name (Loki audit BDC2B0F2, A2). Request pre-state: the named proposal
    exists in the broker's own sidecar (readable here — this half runs as
    the broker) and is not already in ``active[]``; the sidecar row's OWN
    digest matches the sealed one, and the row agrees with FRANK's own
    ``envelope_proposed`` event for this id (:func:`_verify_proposal_against_frank`)
    — refused fast here if either disagrees, though the apply half's own
    re-check on the COPIED row (not this read) is the one that actually
    holds. Writes one signed request carrying a full copy of the proposal
    row (option (a) of the packet: the apply half runs as the trust owner
    and cannot read the sidecar at all, so the row travels inside the
    signed request instead); never touches the register itself — that is
    :func:`_apply_envelope_ratify`'s job, run as the trust-owner unit. The
    broker's own next ``envelope_pending_read`` prunes the sidecar's
    now-stale copy once it sees the id active in the register."""
    from .human_session import is_orchestrator_app

    if not is_orchestrator_app(app_id):
        return mgx._refuse(
            "EPERM", f"{VERB_ENVELOPE_RATIFY} is orchestrator-only; {app_id!r} may not call it"
        )

    grants_root_p = mgx._grants_root(grants_root)

    def _body() -> dict:
        existing = mgx._existing_request_state(grants_root_p, pair_id)
        if existing is not None:
            return mgx._refuse(
                "EALREADY",
                f"a {VERB_ENVELOPE_RATIFY} request for pair_id={pair_id!r} already exists ({existing})",
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
        parsed = _parse_envelope_ratify_text(sealed.get("target_text", ""))
        if parsed is None:
            return mgx._refuse(
                "EINVAL",
                f"sealed pair {pair_id!r} text does not match the strict {VERB_ENVELOPE_RATIFY} "
                "grammar ('ratify envelope <proposal_id> <digest>: <the operator's verbatim "
                "words>', one line, digest = sha256 hex over verb/verb_id/grantee/bounds/"
                "expires_at/max_count/use_count_source)",
                sealed_text=sealed.get("target_text"),
            )

        target_proposal_id = parsed["proposal_id"]

        registry = _envelope_registry_view()
        active_ids = {r.get("id") for r in (registry.get("active") or [])}
        if target_proposal_id in active_ids:
            return mgx._refuse(
                "EALREADY",
                f"envelope {target_proposal_id!r} is already active — nothing to ratify",
                envelope_id=target_proposal_id,
            )

        proposal_row = None
        for row in registry.get("proposals") or []:
            if row.get("id") == target_proposal_id:
                proposal_row = row
                break
        if proposal_row is None:
            return mgx._refuse(
                "ENOENT", f"no pending proposal with id={target_proposal_id!r} to ratify"
            )

        if ledger is None:
            return mgx._refuse("EAMBIG", "no governance ledger: a request that cannot be cited is not performed")

        # Loki audit BDC2B0F2, A2: refuse here, fast, if the sidecar row no
        # longer matches what was sealed -- the apply half's own re-check
        # on the COPIED row is the one that actually holds under a race
        # (this read happens before the copy is even made), but there is
        # no reason to let a doomed request spend a citation.
        computed_digest = _proposal_digest(proposal_row)
        if computed_digest != parsed["digest"]:
            return mgx._refuse(
                "eseal_mismatch",
                f"sealed digest does not match proposal {target_proposal_id!r}'s current "
                "governing fields (verb/verb_id/grantee/bounds/expires_at/max_count/"
                "use_count_source) — the sidecar may have been edited since the pair was "
                "sealed; refusing to request a grant the operator never actually sealed",
                expected_digest=parsed["digest"], computed_digest=computed_digest,
            )

        frank_refusal = _verify_proposal_against_frank(proposal_row, ledger=ledger)
        if frank_refusal is not None:
            return frank_refusal

        target = {
            "proposal_id": target_proposal_id,
            "digest": parsed["digest"],
            "words": parsed["words"],
            "proposal": {k: v for k, v in proposal_row.items() if not k.startswith("_")},
        }
        pending_path = mgx._pending_path(grants_root_p, pair_id)
        pending_record = {
            "pair_id": pair_id, "verb": VERB_ENVELOPE_RATIFY, "envelope_id": None, "citation_id": None,
            "actor": app_id, "target": target,
            "project": project or "willow-mcp", "session": session,
            "requested_at": mgx._now_iso(),
            "pre_state": {"proposal": {"exists": True}, target_proposal_id: {"active": False}},
            # Gap 035d287206e1, F1: embed the sealed row's own bytes so the
            # apply half re-verifies the signature without opening
            # nestor.db (a WAL database — see manifest_grant_executor's
            # note above _SEALED_ROW_FIELDS). Loki audit 229BE2C1, R3: the
            # fifth verb, converted alongside the other four rather than
            # left on the old db_path-reading path a clean merge would
            # never warn anyone about.
            "sealed_row": mgx._sealed_row_fields(sealed),
        }
        return mgx._cite_and_persist(
            pending_path, pending_record, ledger=ledger, envelope_id=envelope_id,
            app_id=app_id, call_args={"proposal_ids": [target_proposal_id]},
            project=project, session=session,
            pair_id=pair_id, grants_root_p=grants_root_p,
        )

    return mgx._run_locked_request(grants_root_p, pair_id, _body)


def _apply_envelope_ratify(record: dict, path: Path, *, ledger, apps_root: Path,
                            db_path: Optional[Path], grants_root: Path) -> dict:
    pair_id = record.get("pair_id")
    target = record.get("target") or {}
    proposal_id = target.get("proposal_id")
    words = target.get("words")
    sealed_digest = target.get("digest")
    proposal_row = target.get("proposal") or {}
    is_click = record.get("auth") == AUTH_SESSION_CLICK

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
        record, ledger=ledger, grants_root=grants_root, applied_event=EVENT_ENVELOPE_RATIFIED)
    if citation_refusal is not None:
        return _fail(citation_refusal["error"], citation_refusal["reason"])

    if is_click:
        # Session-click path (9fe5e179 / aafad73d4606): no Nestor seal.
        # Human act was the attributed desk call; broker sig + FRANK
        # citation + content digest bind the grant.
        verifier = (target.get("verifier") or "").strip()
        if not verifier:
            return _fail(
                "eforged",
                "session-click request carries no verifier on target — refusing",
            )
        if not words:
            return _fail("eforged", "session-click request carries empty words")
        if not sealed_digest:
            return _fail("eforged", "session-click request carries no proposal digest")
    else:
        # Gap 035d287206e1, F1: never opens nestor.db at apply — verifies the
        # sealed row's bytes the request half already embedded (and signed).
        seal_refusal, sealed = mgx._verify_seal_only(pair_id, sealed_row=record.get("sealed_row"))
        if seal_refusal is not None:
            return _fail(seal_refusal["error"], seal_refusal["reason"])
        parsed = _parse_envelope_ratify_text(sealed.get("target_text", ""))
        if (
            parsed is None
            or parsed["proposal_id"] != proposal_id
            or parsed["words"] != words
            or parsed["digest"] != sealed_digest
        ):
            return _fail("eseal_mismatch", "sealed text no longer matches this request's recorded target")
        verifier = sealed.get("verifier") or ""

    if not proposal_row or proposal_row.get("id") != proposal_id:
        return _fail("eforged", "request carries no valid copy of the proposal row to ratify")

    # Loki audit BDC2B0F2, A2: the check that actually holds. The row
    # travelling inside this signed, citation-bound request is checked
    # against TWO independent anchors the broker could not have rewritten
    # after the human act landed: (1) the digest bound at request time,
    # recomputed fresh from this copy; (2) FRANK's own envelope_proposed
    # event, inked at propose. Agreement on both is required before this
    # row is ever signed into the register as issued_by=root.
    computed_digest = _proposal_digest(proposal_row)
    if computed_digest != sealed_digest:
        return _fail(
            "eseal_mismatch",
            f"copied proposal row's digest does not match the bound digest for "
            f"{proposal_id!r} — the row disagrees with what was ratified",
            expected_digest=sealed_digest, computed_digest=computed_digest,
        )

    frank_refusal = _verify_proposal_against_frank(proposal_row, ledger=ledger)
    if frank_refusal is not None:
        return _fail(
            frank_refusal["error"], frank_refusal["reason"],
            **{k: v for k, v in frank_refusal.items() if k not in ("ok", "error", "reason")},
        )

    if _envelope_active_row(proposal_id) is not None:
        return _fail("edrift", f"envelope {proposal_id!r} was already ratified since the request was made")

    from . import envelope_authoring, envelopes

    try:
        result = envelope_authoring.ratify_proposal_row(
            proposal_row,
            ratified_by=verifier,
            ratified_via=f"frank ledger entry {record.get('citation_id')}",
            citation_id=record.get("citation_id"),
            ledger=ledger,
        )
    except envelope_authoring.RegisterUnwritableError as exc:
        return _fail("EACCES", str(exc), **exc.detail)
    except envelope_authoring.EnvelopeAuthoringError as exc:
        return _fail("eunexpected", f"{type(exc).__name__}: {exc}")
    except OSError as exc:
        return _fail(
            "EACCES",
            f"envelope registry not writable by this process: {type(exc).__name__}: {exc}",
            path=str(envelopes.registry_path()),
        )

    receipt_ids: list[str] = []
    if result.get("_ledger_record_id"):
        receipt_ids.append(result["_ledger_record_id"])
    out = {
        "ok": True, "envelope_id": proposal_id, "ratified_at": result.get("issued_at"),
        "ratified_by": result.get("ratified_by"), "receipt_ids": receipt_ids,
        "auth": AUTH_SESSION_CLICK if is_click else "sealed_pair",
        "words": words,
    }
    if result.get("_ledger_error"):
        out["receipt_error"] = result["_ledger_error"]
    mgx._move(path, grants_root / "done", {**record, "result": out})
    return {"pair_id": pair_id, **out}


# ── apply-side dispatch, read by manifest_grant_executor.manifest_grant_apply ──

APPLY_DISPATCH = {
    VERB_REVOKE: _apply_envelope_revoke,
    VERB_RETIRE: _apply_manifest_retire,
    VERB_CREATE: _apply_manifest_create,
    VERB_RATIFY: _apply_federation_ratify,
    VERB_ENVELOPE_RATIFY: _apply_envelope_ratify,
}
