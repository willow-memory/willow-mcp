"""willow_mcp/identity_binding.py — bind serve-mode OAuth identities to app_id.

Implements docs/design/schema-adaptation.md §6.2-6.3 (SECURITY_AUDIT.md
L-AUTH-02): a Google/Apple sign-in verifies *who* signed in but, on its own,
grants that person no standing under gate.py. A binding maps
(idp, subject_id) -> app_id. It starts unconfirmed on first sign-in; only
a confirmed binding lets _gate() resolve an authenticated session to real
tool permissions. An authenticated-but-unbound caller is denied, the same as
an unmanifested app_id in stdio mode — fail closed, not fail open.

Confirmation is intentionally NOT exposed as an MCP tool — a remote serve-mode
caller must never be able to confirm their own binding. It is only available
via the local `willow-mcp confirm-binding` CLI subcommand (stdio-only, run by
the operator on the host that owns $WILLOW_HOME).
"""
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("willow_mcp.identity_binding")


def _write_json_atomic(path: Path, record: dict) -> None:
    """Write via a temp file + atomic rename so a crash mid-write can never
    leave a half-written binding file — which load_binding would then either
    fail to parse (fine, treated as absent) or, worse, parse as valid JSON
    with a truncated/wrong 'confirmed' value."""
    tmp = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    tmp.write_text(json.dumps(record, indent=2))
    os.replace(tmp, path)

# Subject/idp values come from a verified IdP (Google tokeninfo / Apple JWT),
# not raw user input, but they still become filesystem path components here —
# refuse anything that isn't a plain token before touching the filesystem.
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.\-:]{1,256}$")


def _bindings_root() -> Path:
    """The binding directory. F1 (Loki, audit of b725667): under a valid
    trust-provisioned marker the `WILLOW_MCP_APPS_ROOT` lever is ignored
    (Q37, `paths.reader_apps_root`); without a marker it is honoured as ever."""
    from . import paths

    root = paths.reader_apps_root() / "_identity_bindings"
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError:
        # A trust-owned directory the caller cannot create into is the hardened
        # shape, not an error for a reader; a write fails on its own below.
        pass
    return root


def _idp_of(record: dict) -> str:
    """The IdP name from a binding record, written before or after the rename.

    Pre-rename records key it `issuer`. The filename never changed — it has
    always been `{idp}__{subject}.json` with the IdP NAME in it — so an old
    record is found at the same path and only its inner key differs. Reading
    both means the rename does not orphan a single confirmed binding.
    """
    return record.get("idp") or record.get("issuer") or ""


def _safe_token(value: str, label: str) -> str:
    if not value or not _TOKEN_RE.match(value):
        raise ValueError(f"unsafe {label} for binding filename: {value!r}")
    return value


def binding_path(idp: str, subject_id: str) -> Path:
    idp = _safe_token(idp, "idp")
    subject_id = _safe_token(subject_id, "subject_id")
    return _bindings_root() / f"{idp}__{subject_id}.json"


def _read_binding(idp: str, subject_id: str) -> "tuple[Optional[dict], str]":
    """`(record_or_None, untrusted_detail)`. `untrusted_detail` is non-empty only
    when a valid trust marker binds this host and the binding's tree (apps
    root, `_identity_bindings/`, the file) is not trust-owner/root-owned, is a
    symlink or was swapped under the read, or the marker is unusable (F1,
    Loki D06A0EF3): the record is then absent, never read."""
    from . import paths

    path = binding_path(idp, subject_id)
    state, pinned, detail = paths.marker_gated_read([path.parent.parent, path.parent], path)
    if state == paths.READ_UNTRUSTED:
        logger.error("identity_binding: %s is not under a trust-owned tree: %s — binding treated as absent (D06A0EF3)",
                     path, detail)
        return None, detail
    if state in (paths.READ_ABSENT, paths.READ_UNREADABLE):
        return None, ""
    if state == paths.READ_OK:
        text = pinned.decode("utf-8", errors="replace")
    else:
        if not path.exists():
            return None, ""
        try:
            text = path.read_text()
        except Exception:
            return None, ""
    try:
        record = json.loads(text)
    except Exception:
        return None, ""
    if isinstance(record, dict) and "idp" not in record and "issuer" in record:
        record["idp"] = record.pop("issuer")
    return record, ""


def load_binding(idp: str, subject_id: str) -> Optional[dict]:
    """Read a binding. A pre-rename record is normalised to the `idp` key here,
    once, so nothing downstream has to know two shapes existed. Under a valid
    trust marker a binding outside a trust-owned tree is absent (see
    `_read_binding`)."""
    return _read_binding(idp, subject_id)[0]


def compute_email_basis(idp: str, email: Optional[str]) -> str:
    """§6.2: 'do we have an email' is not the interesting question — 'how
    much should anything downstream trust it' is. Google's tokeninfo email
    is IdP-asserted on every sign-in. Apple's may be a one-time snapshot
    (present only on the *first* authorization, silently absent after) or a
    private relay address that silently stops forwarding if the user
    revokes it later — either is a materially weaker guarantee than
    Google's, and code written against Google's always-present email will
    silently misbehave the first time it sees one of these."""
    if not email:
        return "unavailable"
    if idp == "apple":
        if email.endswith("@privaterelay.appleid.com"):
            return "relay"
        return "first_auth_only"
    return "asserted"


def _note_email_drift(existing: dict, incoming_email: Optional[str]) -> None:
    """§6.3 step 4: if a bound identity's email changes between sign-ins,
    surface it (like §4's schema_drift) rather than silently accepting it.
    Only 'present and different' counts as drift — Apple's email correctly
    disappearing on a later login (subject_id unchanged, see §6.1) must NOT
    be flagged, since that's expected behavior, not an identity change."""
    stored = existing.get("email")
    if not incoming_email or not stored or incoming_email == stored:
        return
    existing["email_drift"] = True
    existing["email_drift_detected_at"] = datetime.now(timezone.utc).isoformat()
    existing["drift_from_email"] = stored
    existing["drift_to_email"] = incoming_email
    _write_json_atomic(binding_path(_idp_of(existing), existing["subject_id"]), existing)


def propose_binding(idp: str, subject_id: str, email: Optional[str]) -> dict:
    """Create an unconfirmed binding artifact on first sign-in.

    Returns the existing record untouched if one is already on disk — a
    repeat sign-in must never silently overwrite a human's prior decision
    (confirmed or not). It may still be annotated in place with an
    email-drift flag (§6.3 step 4) if the incoming email differs from what
    was stored — that's an audit note, not a decision change.
    """
    existing, untrusted = _read_binding(idp, subject_id)
    if existing is not None:
        _note_email_drift(existing, email)
        return existing
    if untrusted:
        # An untrusted store holds no decisions: do not write into it, and do
        # not clobber what is there. The caller gets an unconfirmed stub, which
        # the gate treats as unbound.
        return {"idp": idp, "subject_id": subject_id, "email": email, "app_id": None,
                "confirmed": False, "untrusted": untrusted}
    now = datetime.now(timezone.utc).isoformat()
    record = {
        "idp": idp,
        "subject_id": subject_id,
        "email": email,
        "email_basis": compute_email_basis(idp, email),
        "verified_at": now,
        "app_id": None,
        "confirmed": False,
        "created_at": now,
    }
    _write_json_atomic(binding_path(idp, subject_id), record)
    return record


def confirm_binding(idp: str, subject_id: str, app_id: str) -> dict:
    """Operator-only: bind a proposed identity to an app_id and confirm it.

    Not reachable from any MCP tool — call only from the local CLI.
    """
    record, untrusted = _read_binding(idp, subject_id)
    if record is None and untrusted:
        raise ValueError(
            f"binding for ({idp}, {subject_id}) is not in a trust-owned tree: {untrusted}"
        )
    if record is None:
        raise ValueError(
            f"no proposed binding for ({idp}, {subject_id}) — "
            "the person must sign in once via the OAuth approval page first"
        )
    record["app_id"] = app_id
    record["confirmed"] = True
    record["confirmed_at"] = datetime.now(timezone.utc).isoformat()
    _write_json_atomic(binding_path(idp, subject_id), record)
    return record


def resolve_app_id(idp: str, subject_id: str) -> Optional[str]:
    """Return the bound app_id only if the binding is confirmed — None (fail closed) otherwise."""
    record = load_binding(idp, subject_id)
    if record and record.get("confirmed") and record.get("app_id"):
        return record["app_id"]
    return None
