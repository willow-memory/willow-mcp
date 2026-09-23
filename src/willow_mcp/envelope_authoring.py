"""willow_mcp.envelope_authoring — propose / ratify / reject / list.

PR5 of the envelope accrual plan. Fills the write-hole in
:mod:`willow_mcp.envelopes`: the registry gate has always been fully shipped
(``EnvelopeAuthority.check``, ``_enveloped_verb_gate``, ``authorize_and_cite``
+ FRANK citations), but until now the ONLY way to add or mutate an entry in
``$WILLOW_HOME/constitutional/pre-approved.json`` was to hand-edit the JSON.
This module makes the ``proposals[]`` slot the constitutional file already
declares (``syscall-table.json:233``: "Agents MAY draft proposals into
``pre-approved.json#proposals``; a proposal has no force until root moves it
to active") an actual runtime surface.

Three primitives, ported straight from Nestor §5.8:

* **propose** = ``memory.add_pair(status="draft")``. An agent writes to
  ``proposals[]`` with no force. Refuses when the calling session isn't
  keyring-attributed — the provenance rail per the plan's Q&A.
* **ratify** = ``memory.seal(...)``. The operator moves a proposal into
  ``active[]``; only the human key can do this (``require_operator_terminal``
  + keyring verifier check).
* **reject** = ``memory.reject_pair(reopen_when=...)``. The "no" is recorded
  with never / not-yet, mirroring the fleet's existing rejection discipline.

Every authoring act appends a FRANK ledger event
(``envelope_proposed`` / ``envelope_ratified`` / ``envelope_rejected``) so
"shapes the operator has said yes to" becomes a queryable ledger walk in
later PRs. Existing ``envelope_citation`` events (uses) are unchanged.

**issued_by="root" preserved.** ``ratify`` writes ``"root"`` when the
operator's verifier passes the keyring check — "root" in willow means "the
human at the terminal with a keyring-registered key," same discipline PR1-4
established for the session-record ``verifier`` field.

**Server verifies, never signs.** Ratify + reject take the operator's
``verifier`` as an arg; the caller (CLI subcommand or MCP tool wrapper) is
responsible for producing it from the local keyring context. This module
does not read the operator's private key material; it only checks that the
supplied verifier exists in the keyring and is not compromised.

**Trusted-read discipline preserved.** Reads go through
:func:`envelopes._load` (which routes through ``paths.trusted_read``); writes
use an atomic rename with prior-content rollback on failure, mirroring the
discipline :func:`sign_session_cli.cmd_sign_session` uses for its sidecar +
sig write.
"""
from __future__ import annotations

import json
import os
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from . import envelopes as _envelopes
from . import human_session as _human_session
from . import keyring as _keyring


# Event types written to the FRANK governance ledger (PR5). Frozen strings —
# every reader that matches them is a wire contract.
FRANK_EVENT_PROPOSED = "envelope_proposed"
FRANK_EVENT_RATIFIED = "envelope_ratified"
FRANK_EVENT_REJECTED = "envelope_rejected"
FRANK_EVENT_REVOKED = "envelope_revoked"


class EnvelopeAuthoringError(Exception):
    """Base class for authoring refusals."""


class UnattributedSessionError(EnvelopeAuthoringError):
    """The calling session is not in the keyring attribution cache. Only
    attributed sessions may propose envelopes — the provenance rail from
    the plan's Q&A: a proposal must always be attributable to the human
    whose work generated the need."""


class UnknownVerbError(EnvelopeAuthoringError):
    """The proposed verb is not in the syscall table."""


class InvalidBoundsSignatureError(EnvelopeAuthoringError):
    """The proposed bounds' keys do not exactly match the verb's declared
    bounds signature. A bounds object that misses a key or carries an extra
    one makes the envelope void, not loosely interpretable (schema §
    envelope_schema.fields.bounds)."""


class ProposalNotFoundError(EnvelopeAuthoringError):
    """No pending proposal with the given id."""


class EnvelopeNotFoundError(EnvelopeAuthoringError):
    """No ACTIVE envelope carries the named id."""


class EnvelopeIdCollisionError(EnvelopeAuthoringError):
    """A generated envelope id collided with an existing entry — retry
    should succeed (uuid4 collision is not a scenario worth solving
    beyond loud refusal)."""


class OperatorVerifierRequired(EnvelopeAuthoringError):
    """Ratify/reject requires an operator verifier known to the keyring
    and not compromised. Same shape ``session_signing.session_is_valid``
    downgrades on: unknown / compromised → refuse."""


class RegistryMismatchError(EnvelopeAuthoringError):
    """``EREGISTRY`` (gap 4c7512c57a7e): the registry this process resolves
    is not the one ``$WILLOW_HOME`` names. An operator act that lands in a
    registry the desk does not read reports "ratified" and changes nothing
    the desk can see — the proposal stays ``proposed`` on the broker and the
    seat ratifies again on the operator's word. Refused before any write;
    ``detail`` names both paths and the env that steered the resolve."""

    def __init__(self, message: str, detail: dict):
        super().__init__(message)
        self.detail = detail


class RegisterUnwritableError(EnvelopeAuthoringError):
    """``EACCES`` (Loki audit 367C367A, T1): this process cannot write the
    active register's own directory. Refused UP FRONT, before the proposal
    is touched or FRANK is inked — ``ratify()`` used to discover this only
    at the register write itself, after the proposal was already deleted
    from the sidecar and ``envelope_ratified`` already appended: the
    proposal was lost and FRANK said something that never happened. On an
    installed box where ``constitutional/`` is trust-owner-owned (sealed
    31f5d3af), the desk's own uid can never write it — and, Loki audit
    42B3B46F, U1: NO uid can, since the trust owner's own uid then fails
    reading the OTHER file this same ratify needs (the broker-owned 0600
    proposals sidecar). Ratifying an envelope is not possible at all until
    a trust-owner ``envelope.ratify`` apply-half verb exists — gap
    ``d3f79320ccb5``, tracked, not built in this packet. ``detail`` names
    the path and the uid that owns it."""

    def __init__(self, message: str, detail: dict):
        super().__init__(message)
        self.detail = detail


# ---------------------------------------------------------------------------
# Registry identity — which file is in effect, and is it the home's own
# ---------------------------------------------------------------------------


def registry_identity(path: Optional[Path] = None) -> dict:
    """``{path, fingerprint, exists, mtime, active, proposals}`` for the
    registry in effect (or ``path``). ``fingerprint`` is the sha256 of the
    ACTIVE register's own file bytes, 16 hex — enough for two readers to
    agree they are looking at the same file, which is the question the desk
    asks when an operator says "ratified" and the queue has not moved.
    Read-only; counts come from a plain ``json.loads`` so a registry the
    trusted-read gate would refuse still gets a fingerprint (the gate's own
    refusal is unchanged elsewhere).

    ``proposals`` (pair 31f5d3af: proposals[] now lives in the broker-owned
    sidecar, :func:`_proposals_path`, never the active register itself) is
    read from that sidecar — a missing sidecar (no proposal ever queued
    yet) counts as zero, not unreadable; only the ACTIVE file's own
    fingerprint/exists/mtime speak to whether the identity check as a whole
    succeeded, since that is the file whose trust root actually matters
    here."""
    import hashlib
    p = path if path is not None else _envelopes.registry_path()
    out: dict[str, Any] = {"path": str(p), "fingerprint": None, "exists": False,
                           "mtime": None, "active": None, "proposals": None}
    try:
        raw = p.read_bytes()
    except OSError:
        return out
    out["exists"] = True
    out["fingerprint"] = hashlib.sha256(raw).hexdigest()[:16]
    try:
        out["mtime"] = (
            datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc)
            .replace(microsecond=0).isoformat().replace("+00:00", "Z")
        )
    except OSError:
        pass
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return out
    if isinstance(doc, dict):
        out["active"] = len(doc.get("active") or [])
        # Legacy pre-split file (never migrated) may still carry proposals
        # inline — read it if present, else fall through to the sidecar.
        out["proposals"] = len(doc.get("proposals") or [])
    prop_path = _proposals_path()
    try:
        prop_raw = prop_path.read_bytes()
        prop_doc = json.loads(prop_raw.decode("utf-8"))
        if isinstance(prop_doc, dict):
            out["proposals"] = len(prop_doc.get("proposals") or [])
    except (OSError, ValueError, UnicodeDecodeError):
        pass
    return out


def _same_file(a: Path, b: Path) -> bool:
    try:
        return os.path.realpath(a) == os.path.realpath(b)
    except OSError:
        return False


def registry_mismatch() -> Optional[dict]:
    """``None`` when the registry in effect is ``$WILLOW_HOME/constitutional/
    pre-approved.json``; otherwise the ``EREGISTRY`` detail: ``resolved``,
    ``expected``, ``steered_by`` (the env var that moved the resolve — or
    the absence of ``WILLOW_HOME``, which lands the implicit ``~/.willow``
    default), and a ``message`` that names all three.

    The home's own registry is the one every reader on the box — the desk,
    the serve broker, ``home_init``'s seed — reads by default. A ratify
    that goes anywhere else is an act the desk cannot see."""
    from . import paths as _paths
    resolved = _envelopes.registry_path()
    home_env = (os.environ.get("WILLOW_HOME") or "").strip()
    try:
        expected: Optional[Path] = _paths.willow_home() / "constitutional" / "pre-approved.json"
    except _paths.RetiredHomeError as exc:
        return {
            "error": "EREGISTRY",
            "resolved": str(resolved),
            "expected": None,
            "steered_by": "WILLOW_HOME unset (implicit ~/.willow default, retired)",
            "message": (
                f"EREGISTRY: registry resolved to {resolved} with WILLOW_HOME unset; "
                f"the implicit home is retired ({exc}). Set WILLOW_HOME to the live "
                "home before ratifying."
            ),
        }
    if expected is not None and _same_file(resolved, expected):
        return None
    if (os.environ.get("WILLOW_ENVELOPE_REGISTRY") or "").strip():
        steered_by = "WILLOW_ENVELOPE_REGISTRY"
    elif (os.environ.get("WILLOW_CHARTER_REPO") or "").strip():
        steered_by = "WILLOW_CHARTER_REPO"
    elif not home_env:
        steered_by = "WILLOW_HOME unset (implicit ~/.willow default)"
    else:
        steered_by = "unknown"
    return {
        "error": "EREGISTRY",
        "resolved": str(resolved),
        "expected": str(expected),
        "steered_by": steered_by,
        "message": (
            f"EREGISTRY: this process resolves the envelope registry to {resolved} "
            f"(steered by {steered_by}), but $WILLOW_HOME names {expected}. An "
            "operator act written to the former is invisible to every reader of "
            "the latter — refused before any write. Unset the steering env or "
            "point WILLOW_HOME at the home whose registry you mean."
        ),
    }


def _refuse_registry_mismatch(act: str) -> None:
    detail = registry_mismatch()
    if detail is not None:
        raise RegistryMismatchError(f"{act} refused — {detail['message']}", detail)


# ---------------------------------------------------------------------------
# Registry read/write helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _proposals_path() -> Path:
    """Rework (Loki audit 54E3DFC0, R1/R2 — the desk's reading of sealed
    ``31f5d3af``): the active register (``pre-approved.json``) and the
    proposal queue are two different trust boundaries, not one file with
    two views, and not even siblings in the SAME directory — a directory
    is one trust root, and ``constitutional/`` (the register's own
    directory) is the TRUST OWNER's, 0755, no ACLs. A broker-owned FILE
    inside a trust-owner-owned DIRECTORY cannot be created, rewritten, or
    unlinked by the broker at all (directory write permission is the
    directory owner's to grant, not the file's). ``proposals[]``/
    ``archived[]`` therefore live in a directory of their OWN
    (:func:`paths.envelope_proposals_path`, a sibling of ``constitutional/``
    — never a file inside it), broker-owned end to end, never signed,
    never requiring trust-owner ownership. The broker writes it directly,
    exactly as it always wrote the combined file before this split."""
    # Anchored to $WILLOW_HOME (paths.envelope_proposals_path), not derived
    # from envelopes.registry_path(): that path can be steered to an
    # ARBITRARY file via WILLOW_ENVELOPE_REGISTRY, with no reliable
    # directory depth to climb back out of -- tried, reverted after it
    # escaped a test's own tmp_path into a directory shared session-wide.
    from . import paths

    return paths.envelope_proposals_path()


def _load_registry() -> dict:
    """Read the current registry as a MERGED VIEW: ``active`` from the
    (now possibly trust-owner-owned, signed) active register
    (:func:`envelopes.registry_path`); ``proposals``/``archived`` from the
    broker-owned sidecar (:func:`_proposals_path`, pair 31f5d3af). Every
    reader below (propose/ratify/reject/list_*) keeps operating on the one
    shape it always has; only this function and its write counterparts
    (:func:`_save_proposals`, :func:`_save_active`) know the file is
    actually split in two. Both read paths routed through
    :func:`envelopes._load`, which itself routes through
    ``paths.trusted_read`` — a writable/symlinked/unsigned-when-required
    source is a forged-envelope vector and the read refuses it."""
    active_doc = _envelopes._load(_envelopes.registry_path())
    proposals_path = _proposals_path()
    proposals_doc = _envelopes._load(proposals_path) if proposals_path.is_file() else {}
    return {
        "active": active_doc.get("active") or [],
        "proposals": proposals_doc.get("proposals") or [],
        "archived": proposals_doc.get("archived") or [],
    }


def _load_active_register() -> dict:
    """Read ONLY the active register's ``active[]`` — via
    :func:`envelopes._load` (``trusted_read``), the same trust rail every
    other reader of the trust-owner-owned register uses — and NEVER the
    broker-owned proposals sidecar. Loki audit BDC2B0F2, A1:
    :func:`_load_registry` opens BOTH files whenever the sidecar exists;
    as the trust owner, that second open is refused before the register
    write it was meant to guard ever happens — :func:`ratify_proposal_row`
    and :func:`revoke` (the two functions this codebase reaches ONLY
    through the trust-owner apply half) call this instead. Neither needs
    anything from the sidecar: ``ratify_proposal_row`` receives its row
    from the caller (the request half already copied it, running as the
    broker, which CAN read the sidecar); ``revoke`` only ever mutates
    ``active[]``. Making the docstrings' "never looks the proposal up
    itself" literally true, not just intended.

    F-A (dispatch 10F9E837, Loki audit 23DE8AA9): a register that does
    not exist AT ALL is treated as ``{"active": []}`` — legitimate
    bootstrap, the same state an empty-but-present register would carry —
    rather than propagating ``paths.trusted_read``'s "source path
    missing" refusal. A truly fresh ``$WILLOW_HOME`` (no register ever
    written) hit this on install's own step 1d seed: ``trusted_read``
    correctly refuses to authenticate content that is not there, but
    there is nothing to authenticate when nothing has been written yet —
    the same bootstrap distinction :func:`_register_writable` already
    makes for a missing DIRECTORY (returns writable/ok rather than
    refusing). Extending it to a missing FILE inside an existing,
    writable (or not-yet-existing) directory is safe: the two real
    callers of this function (the ``envelope.ratify`` trust-owner apply
    half, and install's own seed) both go on to WRITE the register via
    :func:`_save_active`, which creates it correctly owned and signed
    either way — there is no path here where "missing" could be mistaken
    for signed, trustworthy content this process merely failed to read."""
    path = _envelopes.registry_path()
    if not path.exists():
        return {"active": []}
    active_doc = _envelopes._load(path)
    return {"active": active_doc.get("active") or []}


def _save_proposals(registry: dict) -> None:
    """Write ONLY ``proposals[]``/``archived[]`` to the broker-owned
    sidecar (:func:`_proposals_path`) — NEVER touches the active register
    at all. Rework (Loki audit 54E3DFC0, R2): the prior draft's
    ``_save_registry`` rewrote BOTH files on every call, so ``propose()``
    and ``reject()`` — which only ever change the proposal queue —
    silently rewrote the trust-owner-owned active register too; as the
    broker's own uid, that ``os.replace`` succeeded and FLIPPED the
    register's ownership back to the broker, voiding the sealed shape from
    that call on. ``propose``/``reject`` call this and only this."""
    _atomic_write(_proposals_path(), {
        "proposals": registry.get("proposals") or [],
        "archived": registry.get("archived") or [],
    })


def _register_writable() -> tuple[bool, str, dict]:
    """Whether THIS process (this uid) could actually write the active
    register — checked before any write, and before any other mutation
    (proposal removal, FRANK ink) that a caller might be tempted to do
    first. Loki audit 367C367A, T1: ``ratify()`` used to find this out only
    at the register write itself, after the sidecar had already lost the
    proposal and FRANK already carried ``envelope_ratified`` — this call
    lets ``ratify()`` refuse loudly before touching anything. Mirrors
    ``manifest_grant_executor._dirs_writable``'s pre-check shape: a missing
    directory (a never-installed box — whichever uid runs first creates it)
    is not a refusal, only an existing, unwritable one is."""
    path = _envelopes.registry_path()
    d = path.parent
    if not d.exists():
        return True, "ok", {}
    if os.access(d, os.W_OK | os.X_OK):
        return True, "ok", {}
    try:
        import pwd
        owner = pwd.getpwuid(d.stat().st_uid).pw_name
    except (KeyError, OSError):
        owner = str(d.stat().st_uid)
    reason = (
        f"{d} is not writable by this process (uid {os.geteuid()}) — owned "
        f"by {owner!r}. Direct ratify() cannot span both the broker-owned "
        "0600 proposals sidecar and this trust-owner-owned register from one "
        "uid (Loki 367C367A/42B3B46F). Default click (sealed 9fe5e179 / gap "
        "aafad73d4606): from an attributed orchestrator session call "
        "envelope_ratify — the MCP tool queues a session-click request and "
        "the trust-owner apply half completes the move; no Nestor seal. "
        f"Operator terminal click: `sudo -E willow-mcp envelope ratify "
        f"<proposal_id> --verifier NAME` (root spans both files). "
        "Remote/unattended only: envelope_ratify_request with a sealed "
        "Nestor pair. The proposal named here stays in "
        "$WILLOW_HOME/proposals/; nothing was touched by this refusal."
    )
    return False, reason, {"error": "EACCES", "path": str(d), "owner": owner}


def _save_active(registry: dict, *, sign_as: "str | None" = None) -> None:
    """Write ONLY ``active[]`` to the (signed) active register — NEVER
    touches the proposals sidecar. The one write path that mutates the
    trust-owner-owned register: :func:`ratify` (the one broker-side act
    the sealed text names as touching it) and :func:`revoke` (reached only
    through the trust-owner apply half in this codebase,
    :mod:`trust_owner_verbs`, which already runs as the trust-owner uid).
    A write attempted by a process that does not own ``constitutional/``
    raises a plain ``OSError`` here — REFUSED, not silently rescued by
    directory ownership the way the prior draft was; there is no
    special-casing, the write simply fails the way any other-uid write
    into a 0755 directory fails.

    Signing order — **rework, Loki audit BDC2B0F2, A3**: the prior draft
    wrote the register (rename) and signed AFTERWARDS, over the file
    already at its live path. Two defects that shape produced: (1) between
    the content rename and gpg's write of the new ``.sig``, every OTHER
    reader's ``trusted_read`` sees a live register whose signature does
    not yet match — a stale-``.sig`` window on every single write, refused
    ``EUNREACH`` by the fail-closed gate; (2) if signing fails altogether
    (agent down, key gone) the register is left with the NEW ``active[]``
    and the OLD ``.sig`` permanently — unsigned-looking to every reader
    from then on, with no path in this module to repair it (a retry finds
    the id already active and refuses). Mirrors
    :func:`manifest_admin.publish_signed_pair`'s own order instead: sign a
    TMP candidate first, verify nothing about the rename can be observed
    half-done, then rename the ``.sig`` into place BEFORE the content —
    "signature first is fail-closed even for a non-cooperating reader."
    A ``sign_detached`` failure now raises before either rename, leaving
    the prior register and its prior ``.sig`` byte-for-byte untouched.

    Under ``--local-user WILLOW_PGP_FINGERPRINT`` when PGP enforcement is
    on (``pgp.pgp_enabled()``) — Loki audit 367C367A, T3 still holds: this
    does NOT refuse when the fingerprint is unset, it writes the register
    UNSIGNED, the same "unsigned atomic write when PGP is not enforced"
    posture every other write in this codebase takes.

    ``sign_as`` (dispatch FA4F79AC, M1): install.sh's own bootstrap seed
    (``deploy/manifest-grant/seed_envelope_ratify.py``, the ONLY caller
    that passes this) runs at a point in the install sequence where
    ``constitutional/`` is already trust-owner-owned but ``trust.env`` has
    not been published yet — the generated fingerprint is not yet the
    trusted one anywhere else can read, only root's own install.sh knows
    it. Going through ``pgp.pgp_enabled()``/``pgp.expected_fingerprint()``
    there raises :class:`pgp.PgpSourceUnreadable` (missing trust.env on an
    already-provisioned directory) EVERY fresh install, forever — not a
    transient failure a retry clears, a permanent deadlock, because
    trust.env is never written until AFTER this exact write succeeds.
    When ``sign_as`` is given, this signs unconditionally under that
    fingerprint via ``--local-user``, bypassing the trust.env read
    entirely — the caller (root, mid-install, holding the fingerprint it
    just generated/resolved and is about to publish) is vouching for the
    value directly, the same way ``rotate_resign.py`` and
    ``sync_constitutional.py --sign-as`` already sign install-time writes
    under an explicit fingerprint rather than consulting
    ``pgp.expected_fingerprint()``. This is never a fallback available to
    ordinary callers — :func:`ratify_proposal_row`'s only other caller,
    the real ``envelope.ratify`` apply half, never passes it, and still
    goes through the trust.env-backed check exactly as before.

    **``ratify()`` (the sidecar-reading path) is a separate case, Loki
    audit 42B3B46F, U1: no uid on an installed box can complete it at
    all** (:func:`_register_writable` refuses before reaching this
    function). The trust-owner apply half (:mod:`trust_owner_verbs`'s
    ``envelope.ratify``, gap ``d3f79320ccb5``) is the path that actually
    reaches this write there, via :func:`ratify_proposal_row`."""
    from . import pgp

    path = _envelopes.registry_path()
    doc = {"active": registry.get("active") or []}
    if not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        os.chmod(path.parent, 0o755)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)

    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.chmod(tmp, stat.S_IMODE(os.stat(tmp).st_mode) & ~0o022)

    tmp_sig = None
    if sign_as:
        ok, detail = pgp.sign_detached(tmp, local_user=sign_as)
        if not ok:
            tmp.unlink(missing_ok=True)
            raise EnvelopeAuthoringError(
                f"{path} could not be signed under the explicit "
                f"sign_as={sign_as!r} ({detail}) — refused before any "
                "write; the live register and its .sig are untouched"
            )
        tmp_sig = pgp.detached_sig_path(tmp)
    elif pgp.pgp_enabled():
        fingerprint = pgp.expected_fingerprint()
        ok, detail = pgp.sign_detached(tmp, local_user=fingerprint)
        if not ok:
            tmp.unlink(missing_ok=True)
            raise EnvelopeAuthoringError(
                f"{path} could not be signed under WILLOW_PGP_FINGERPRINT "
                f"({detail}) — refused before any write; the live register "
                "and its .sig are untouched"
            )
        tmp_sig = pgp.detached_sig_path(tmp)

    # Signature first is fail-closed even for a non-cooperating reader
    # (manifest_admin.publish_signed_pair's own comment, same shape here):
    # a reader that races in between these two renames sees either the OLD
    # content with the NEW (matching, once both land) or OLD signature —
    # trusted_read's own re-check on each read makes either state refuse
    # cleanly rather than accept a mismatched pair.
    live_sig = pgp.detached_sig_path(path)
    if tmp_sig is not None:
        os.replace(tmp_sig, live_sig)
    os.replace(tmp, path)


def _load_syscall_table() -> dict[int, dict]:
    """Verbs by id."""
    table = _envelopes._load(_envelopes.syscall_path())
    return {
        int(row["id"]): row
        for row in table.get("verbs") or []
        if isinstance(row, dict) and isinstance(row.get("id"), int)
    }


def _atomic_write(path: Path, doc: dict) -> None:
    """Write ``doc`` atomically. Mirrors ``sign_session_cli``'s discipline:
    write to a tmp file, replace atomically, so a mid-flight failure never
    leaves the registry half-written.

    Loki audit 367C367A, T2: ``path.parent.mkdir`` used to take no explicit
    ``mode``, so a freshly-created directory landed at whatever the calling
    process's umask allowed (measured: 0o775 under this box's 0002 umask).
    ``paths.trusted_read`` refuses a group/other-writable PARENT directory
    exactly like it refuses a group/other-writable file — so the very first
    ``propose()`` on a fresh ``$WILLOW_HOME`` (typically
    ``_auto_propose_on_gate_miss`` on the first ungoverned dispatch, well
    before ``install.sh`` ever runs) could brick every later authoring read
    against its own sidecar. ``mkdir`` now sets ``0o755`` explicitly — not
    left to the umask — the same mode ``install.sh`` already uses when it
    creates this directory itself; a pre-existing directory is untouched
    (this only fixes a directory THIS call creates new)."""
    if not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        os.chmod(path.parent, 0o755)  # mkdir's mode is umask-masked too
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    # paths.trusted_read fail-closed refuses a group/other-writable source
    # (mode & 0o022) — the umask-derived mode open() leaves on tmp (typically
    # 664) trips that on the very next read. Strip those bits before the
    # atomic rename so a fresh write never re-triggers the guard it's meant
    # to satisfy.
    os.chmod(tmp, stat.S_IMODE(os.stat(tmp).st_mode) & ~0o022)
    os.replace(tmp, path)


def _find_verb(verb: str, verbs_by_id: dict[int, dict]) -> tuple[int, dict]:
    for vid, row in verbs_by_id.items():
        if row.get("verb") == verb:
            return vid, row
    raise UnknownVerbError(
        f"verb {verb!r} is not in the syscall table (verbs known: "
        f"{sorted(row.get('verb', '?') for row in verbs_by_id.values())})"
    )


def _validate_bounds_signature(verb: str, bounds: dict, verbs_by_id: dict[int, dict]) -> int:
    """Return the verb_id when bounds match the verb's declared signature;
    raise :class:`InvalidBoundsSignatureError` otherwise. Same equality shape
    :meth:`envelopes.EnvelopeAuthority.check` enforces post-ratification —
    catching the mismatch at propose-time so the operator never sees an
    envelope in the queue that will refuse the moment they ratify it."""
    verb_id, spec = _find_verb(verb, verbs_by_id)
    expected = set((spec.get("bounds") or {}).keys())
    # Registry v1.1 hoists metering fields from older verb rows.
    expected -= {"max_count", "expires_at"}
    got = set(bounds.keys())
    if expected != got:
        raise InvalidBoundsSignatureError(
            f"bounds signature mismatch for verb {verb!r}: "
            f"expected keys {sorted(expected)}, got {sorted(got)}. "
            "A bounds object that misses a key or carries an extra one makes "
            "the envelope void, not loosely interpretable."
        )
    return verb_id


def _keyring_verifier_active(verifier: str) -> bool:
    """True iff ``verifier`` is registered in the keyring and not
    compromised. Empty or unknown → False. Same downgrade shape
    :func:`session_signing.session_is_valid` uses: caller gets a bool, the
    refusal decision is upstream."""
    if not verifier:
        return False
    ring = _keyring.get_keyring()
    if ring is None:
        return False
    return ring.verifying_entry(verifier) is not None


# ---------------------------------------------------------------------------
# The five primitives
# ---------------------------------------------------------------------------


def propose(
    *,
    verb: str,
    grantee: str,
    bounds: dict,
    reason: str,
    verifier: str,
    session_id: str,
    expires_at: Optional[str] = None,
    max_count: Optional[int] = None,
    precedent_ids: Optional[Iterable[str]] = None,
    ledger: Optional[Any] = None,
    orchestrator_session_id: Optional[str] = None,
    proposer_app_id: str = "",
) -> dict:
    """Write an envelope proposal into ``pre-approved.json#proposals[]``.

    Attribution-gated: refuses when the calling session is not in
    :data:`human_session._attributed_sessions`. That's the provenance rail
    from the plan — every proposal is tied to the human whose work generated
    the need. Unattributed callers cannot cause a proposal to appear.

    Returns the proposal row as it was written (includes generated ``id``
    and ``proposed_at``). Appends an ``envelope_proposed`` event to the
    FRANK ledger when one is available; ledger-write failure is reported in
    the returned dict but does not roll back the sidecar write (mirrors the
    discipline sign-session uses for its ledger append).

    Deliberately NOT guarded by ``EREGISTRY`` (:func:`registry_mismatch`):
    a proposal has no force wherever it lands, and a specialist's
    auto-propose on a gate miss must be able to queue into whatever registry
    its process resolves — a steered resolve costs nothing here. The guard
    sits on the operator acts (ratify / reject / revoke), where a write to
    the wrong file is a "ratified" the desk cannot see (gap 4c7512c57a7e).
    """
    if _keyring.enabled():
        # Attribution rail is active. Every gate below is inside the
        # keyring-enabled branch — a deployment with no keyring stays on
        # the pre-PR5 shape (which is "hand-edit the JSON," so propose()
        # is not a path they use).
        if not verifier:
            raise UnattributedSessionError(
                "envelope_propose requires a verifier — the human whose "
                "session this proposal is attributed to. Attributed "
                "sessions carry a verifier on their session record; an "
                "unattested willow session cannot propose."
            )
        if not _keyring_verifier_active(verifier):
            raise UnattributedSessionError(
                f"verifier {verifier!r} is unknown to the keyring or has "
                "been revoked as compromised. Propose refuses rather than "
                "letting an untrusted claim into the queue."
            )
        if not session_id or not _human_session.is_session_attributed(session_id):
            raise UnattributedSessionError(
                f"session {session_id!r} is not in the attribution cache. "
                "The proposal must come from a session that carried a "
                "valid signature at session_enter time — see "
                "docs/design/identity-in-session.md (PR4) for the cache "
                "lifecycle."
            )

    verbs_by_id = _load_syscall_table()
    verb_id = _validate_bounds_signature(verb, bounds, verbs_by_id)

    registry = _load_registry()
    proposals = list(registry.get("proposals") or [])
    active = list(registry.get("active") or [])

    proposal_id = f"env-{verb}-{uuid.uuid4().hex[:12]}"
    if any(row.get("id") == proposal_id for row in proposals + active):
        raise EnvelopeIdCollisionError(
            f"generated id {proposal_id!r} already exists — retry"
        )

    # PR7: precedent recall. If the caller didn't supply precedent_ids
    # explicitly, ask envelope_shapes for the top matches against
    # currently-active envelopes for this (verb, grantee, bounds) shape.
    # An import-guarded call — if envelope_shapes ever needs an optional
    # dep this module doesn't want to pull in, propose still works.
    resolved_precedents: list[str]
    if precedent_ids is None:
        try:
            from . import envelope_shapes as _es
            resolved_precedents = _es.top_precedent_ids(
                verb, grantee, bounds
            )
        except Exception:
            # Precedent recall failing must never block propose — the
            # operator can still ratify from scratch. Log to no-op and
            # move on.
            resolved_precedents = []
    else:
        resolved_precedents = list(precedent_ids)

    row = {
        "id": proposal_id,
        "verb_id": verb_id,
        "verb": verb,
        "grantee": grantee,
        "bounds": bounds,
        "issued_by": "",  # unset until ratify — "root" is a keyring-verified act
        "issued_at": "",
        "ratified_via": "",
        "expires_at": expires_at,
        "max_count": max_count,
        "use_count_source": "frank",
        "status": "proposed",
        "notes": reason,
        # Fields added by PR5 for the accrual loop
        "proposed_at": _now_iso(),
        "proposed_by": {
            "verifier": verifier,
            "session_id": session_id,
            "orchestrator_session_id": orchestrator_session_id or session_id,
            "proposer_app_id": proposer_app_id,
        },
        "precedent_ids": resolved_precedents,
    }
    proposals.append(row)
    registry["proposals"] = proposals
    _save_proposals(registry)

    ledger_record_id = None
    ledger_error = None
    if ledger is not None:
        try:
            ledger_record_id = ledger.append(
                proposer_app_id or "willow",
                FRANK_EVENT_PROPOSED,
                {
                    "envelope_id": proposal_id,
                    "verb": verb,
                    "verb_id": verb_id,
                    "grantee": grantee,
                    "bounds_digest": _bounds_digest(bounds),
                    "verifier": verifier,
                    "orchestrator_session_id": orchestrator_session_id or session_id,
                    "proposer_app_id": proposer_app_id,
                    "precedent_ids": row["precedent_ids"],
                    "proposed_at": row["proposed_at"],
                },
            )
        except Exception as exc:  # pragma: no cover — ledger is optional
            ledger_error = str(exc)

    result = dict(row)
    result["_ledger_record_id"] = ledger_record_id
    if ledger_error:
        result["_ledger_error"] = ledger_error
    return result


def ratify(
    proposal_id: str,
    *,
    verifier: str,
    ledger: Optional[Any] = None,
) -> dict:
    """Move a proposal from ``proposals[]`` to ``active[]``. The operator's
    keyring-verified act. ``issued_by`` is stamped as ``"root"`` per schema
    (invariant preserved from the pre-PR5 shape).

    The caller (CLI subcommand or MCP tool) is responsible for wrapping this
    in :func:`human_session.require_operator_terminal` — this module does not
    reach for the tty; a lone unit test that constructs a valid verifier +
    keyring is a legitimate caller.

    Returns the ratified envelope row. Appends ``envelope_ratified`` to the
    FRANK ledger when one is available.

    **Honest state as of Loki audits 367C367A (T1) and 42B3B46F (U1):** once
    ``constitutional/`` is trust-owner-owned (sealed 31f5d3af, an installed
    box), the desk's own uid cannot write the register — this function now
    refuses ``EACCES`` UP FRONT (:func:`_register_writable`,
    :class:`RegisterUnwritableError`) rather than half-executing (inking
    FRANK and deleting the proposal before discovering the register write
    cannot succeed, which is what the prior draft did — measured, not
    theoretical). **On the installed box, ratifying an envelope is not
    possible until ``envelope.ratify`` (gap ``d3f79320ccb5``) lands** — a
    ``sudo -u willow-operator`` invocation is NOT a working alternative
    (measured, 42B3B46F): that uid then fails reading the OTHER file this
    same call needs, the broker-owned 0600 proposals sidecar. Proposals
    queue in ``$WILLOW_HOME/proposals/`` and are not lost while this gap is
    open. Mirroring ``manifest.grant``'s request/apply split for the other
    four verbs is the tracked fix, not built in this packet. The desk's
    ``envelope_ratify`` MCP tool will refuse ``EACCES`` here rather than run
    partway.
    """
    if not _keyring_verifier_active(verifier):
        raise OperatorVerifierRequired(
            f"ratify requires an operator verifier known to the keyring "
            f"and not compromised; got {verifier!r}."
        )
    _refuse_registry_mismatch("ratify")

    # Loki audit 367C367A, T1: refused UP FRONT, before the proposal is
    # touched or FRANK is inked. This used to be discovered only at the
    # register write below, by which point the proposal was already gone
    # from the sidecar and envelope_ratified already appended to FRANK —
    # the proposal was lost and FRANK said something that never happened.
    writable, writable_reason, writable_detail = _register_writable()
    if not writable:
        raise RegisterUnwritableError(writable_reason, writable_detail)

    registry = _load_registry()
    proposals = list(registry.get("proposals") or [])
    active = list(registry.get("active") or [])
    matches = [row for row in proposals if row.get("id") == proposal_id]
    if not matches:
        raise ProposalNotFoundError(
            f"no pending proposal with id {proposal_id!r}"
        )
    proposal = matches[0]

    ratified_at = _now_iso()
    ratified: dict = {
        **{k: v for k, v in proposal.items() if not k.startswith("_")},
        "issued_by": "root",
        "issued_at": ratified_at,
        "status": "active",
        # Loki audit 367C367A, T1: no longer conditioned on whether the
        # FRANK ink below succeeds -- FRANK is now inked AFTER this row is
        # already durably in the register (see the ordering note below), so
        # its outcome cannot be known yet when this row is built. The
        # keyring verifier is provenance enough for the row itself; the
        # FRANK cross-reference lives in the ledger event's own content
        # (envelope_id, ratified_at), not embedded back into the register.
        "ratified_via": f"keyring verifier {verifier}",
    }

    # Rework (Loki audit 54E3DFC0, R2 / 367C367A, T1 / 42B3B46F, U1): ratify
    # is the ONE broker-side act the sealed text names as touching the
    # trust-owner-owned active register at all. On an installed box where
    # constitutional/ is trust-owner-owned, the register write below needs
    # this process to run AS the trust owner for the OS-level write to
    # succeed -- _register_writable() above already refused before anything
    # was touched if that is not the case, so reaching this point means
    # THIS write is expected to succeed. That is not the same as "ratify()
    # as a whole works as the trust owner": running this whole function as
    # the trust owner still fails on the OTHER file it touches, the
    # broker-owned 0600 proposals sidecar (measured, 42B3B46F) -- gap
    # d3f79320ccb5 is the real fix, not a uid change.
    #
    # Order matters (T1's fix): the REGISTER write happens FIRST, while the
    # proposal is still sitting untouched in the sidecar and FRANK is still
    # untouched. Only once that has actually landed does the sidecar lose
    # the proposal; only once BOTH files agree does FRANK get inked. A
    # failure at any step before its own write leaves every earlier state
    # exactly as it was -- there is no window where FRANK says "ratified"
    # and the register disagrees, and no window where the proposal is gone
    # from the sidecar but never made it into the register. The register
    # write signs under WILLOW_PGP_FINGERPRINT via --local-user when PGP is
    # enforced (_save_active -> _maybe_sign), never gpg's ambient default
    # key (R2's other measured defect).
    active.append(ratified)
    _save_active({"active": active})

    proposals = [row for row in proposals if row.get("id") != proposal_id]
    _save_proposals({"proposals": proposals, "archived": registry.get("archived") or []})

    ledger_record_id = None
    ledger_error = None
    if ledger is not None:
        try:
            ledger_record_id = ledger.append(
                "willow",
                FRANK_EVENT_RATIFIED,
                {
                    "envelope_id": proposal_id,
                    "verb": proposal["verb"],
                    "verb_id": proposal["verb_id"],
                    "grantee": proposal["grantee"],
                    "bounds_digest": _bounds_digest(proposal["bounds"]),
                    "verifier": verifier,
                    "ratified_at": ratified_at,
                },
            )
        except Exception as exc:  # pragma: no cover — ledger is optional
            ledger_error = str(exc)

    result = dict(ratified)
    result["_ledger_record_id"] = ledger_record_id
    if ledger_error:
        result["_ledger_error"] = ledger_error
    return result


def ratify_proposal_row(
    row: dict,
    *,
    ratified_by: str,
    ratified_via: str,
    citation_id: Optional[str] = None,
    ledger: Optional[Any] = None,
    sign_as: Optional[str] = None,
) -> dict:
    """Move an ALREADY-KNOWN proposal ROW into ``active[]`` — the
    sidecar-free sibling of :func:`ratify`, built for
    :mod:`trust_owner_verbs`'s ``envelope.ratify`` apply half (gap
    ``d3f79320ccb5``). On an installed box the apply half runs AS the
    trust owner, which can write the register (:func:`_register_writable`
    holds) but cannot read the broker-owned 0600 proposals sidecar at all
    (that function's own docstring, Loki audit 42B3B46F, U1) — so unlike
    :func:`ratify`, this never looks the proposal up itself. The caller
    (the ``envelope.ratify`` request half, running as the broker, which
    CAN read its own sidecar) copies the full row into the signed request
    at request time; this function only ever receives that copy.

    Same register-write discipline as :func:`ratify`: refuses
    :class:`RegisterUnwritableError` up front via
    :func:`_register_writable`, before anything is touched; refuses when
    ``row['id']`` is already in ``active[]`` (the caller re-checks this
    itself too, immediately before calling — the check here is the one
    that actually holds under a race, since it runs right before the
    write it guards); writes ``active[]`` via :func:`_save_active`
    (atomic write + re-sign under ``WILLOW_PGP_FINGERPRINT`` when PGP
    enforcement is on); and appends ``envelope_ratified`` to FRANK — the
    SAME event name :func:`ratify` inks, so a reader filtering FRANK for
    "what did the operator say yes to" sees both paths identically.
    ``citation_id``, when given, rides in the FRANK payload so
    :func:`manifest_grant_executor._verify_pending_signature_and_citation`
    can use this same event as its own replay guard — no second event
    name to keep in sync. Unlike :func:`ratify`, ``ratified_by`` (the
    sealed row's own verifier, read by the caller — this function does
    not touch the keyring) is stamped onto the row as its own field,
    alongside ``ratified_via``; the caller composes ``ratified_via`` (the
    packet's own shape: ``"frank ledger entry <citation_id>"``) rather
    than this function guessing at it.

    F-A (dispatch 10F9E837, Loki audit 23DE8AA9): a TRULY fresh box (no
    ``constitutional/pre-approved.json`` at all yet — nothing has ever
    been written there, not even by a prior seed) used to raise from
    :func:`_load_active_register` itself, before this function's own body
    ever ran — ``envelopes._load`` -> ``paths.trusted_read`` treats a
    missing source path as a hard refusal (correctly, for a file that is
    SUPPOSED to already exist). That refusal is right for every OTHER
    reader of the register, which has no business proceeding if the
    register vanished after having existed — but wrong for install's own
    bootstrap seed, the ONE caller that is establishing the register's
    first row. See :func:`_load_active_register`'s own docstring for the
    fix.

    ``sign_as`` (dispatch FA4F79AC, M1): threaded straight through to
    :func:`_save_active`'s own parameter of the same name — see its
    docstring for who this is for (install.sh's bootstrap seed only) and
    why (the trust.env-backed check deadlocks at that specific point in
    the install sequence). Every other caller passes ``None`` and gets
    exactly the pre-existing ``pgp.pgp_enabled()``-gated behavior."""
    _refuse_registry_mismatch("ratify")
    writable, writable_reason, writable_detail = _register_writable()
    if not writable:
        raise RegisterUnwritableError(writable_reason, writable_detail)

    # Loki audit BDC2B0F2, A1: _load_registry() opens the broker-owned
    # sidecar too whenever it exists -- refused for the trust owner before
    # this write ever happens. Nothing below needs proposals[]/archived[],
    # only active[].
    registry = _load_active_register()
    active = list(registry.get("active") or [])
    proposal_id = row.get("id")
    if any(r.get("id") == proposal_id for r in active):
        raise EnvelopeAuthoringError(
            f"envelope {proposal_id!r} is already active — nothing to ratify"
        )

    ratified_at = _now_iso()
    ratified: dict = {
        **{k: v for k, v in row.items() if not k.startswith("_")},
        "issued_by": "root",
        "issued_at": ratified_at,
        "status": "active",
        "ratified_via": ratified_via,
        "ratified_by": ratified_by,
    }
    active.append(ratified)
    _save_active({"active": active}, sign_as=sign_as)

    ledger_record_id = None
    ledger_error = None
    if ledger is not None:
        try:
            ledger_record_id = ledger.append(
                "willow",
                FRANK_EVENT_RATIFIED,
                {
                    "envelope_id": proposal_id,
                    "verb": row.get("verb"),
                    "verb_id": row.get("verb_id"),
                    "grantee": row.get("grantee"),
                    "bounds_digest": _bounds_digest(row.get("bounds") or {}),
                    "verifier": ratified_by,
                    "ratified_at": ratified_at,
                    "citation_id": citation_id,
                },
            )
        except Exception as exc:  # pragma: no cover — ledger is optional
            ledger_error = str(exc)

    result = dict(ratified)
    result["_ledger_record_id"] = ledger_record_id
    if ledger_error:
        result["_ledger_error"] = ledger_error
    return result


def reject(
    proposal_id: str,
    *,
    reason: str,
    verifier: str,
    reopen_when: str = "",
    ledger: Optional[Any] = None,
) -> dict:
    """Record a "no" on a proposal. Same keyring guard as :func:`ratify`.

    ``reopen_when`` distinguishes NEVER (empty) from NOT YET (non-empty),
    mirroring :func:`nestor.memory.reject_match`'s policy. A reader that
    surfaces rejections should show non-empty ``reopen_when`` as a condition
    to re-check, not a closed door.

    PR11 (envelope-accrual, archived state): the rejected row does not
    vanish — it moves to the registry's ``archived[]`` list with
    ``status="rejected"``, its bounds intact, and the ``reason`` /
    ``reopen_when`` / ``verifier`` fields preserved. This is what lets
    :func:`envelope_shapes.similar_precedents` count "the operator's
    no with a reopen condition" as a precedent alongside their yeses —
    the same signal Nestor's ``reject_match`` surfaces. Registry growth
    is a real long-run cost; compaction is left for a later PR when
    the archived list actually gets large enough to matter.

    Returns ``{proposal_id, verifier, rejected_at, reason, reopen_when}`` and
    appends ``envelope_rejected`` to the FRANK ledger when one is available.
    """
    if not _keyring_verifier_active(verifier):
        raise OperatorVerifierRequired(
            f"reject requires an operator verifier known to the keyring "
            f"and not compromised; got {verifier!r}."
        )
    _refuse_registry_mismatch("reject")

    registry = _load_registry()
    proposals = list(registry.get("proposals") or [])
    matches = [row for row in proposals if row.get("id") == proposal_id]
    if not matches:
        raise ProposalNotFoundError(
            f"no pending proposal with id {proposal_id!r}"
        )
    proposal = matches[0]
    proposals = [row for row in proposals if row.get("id") != proposal_id]

    rejected_at = _now_iso()
    # PR11: archive the rejected row instead of dropping. Bounds + polarity
    # + reopen_when carry into the precedent walk. The operator's decision
    # (yes AND no) is what accrues, not just the ratified subset.
    archived = list(registry.get("archived") or [])
    archived.append({
        **{k: v for k, v in proposal.items() if not k.startswith("_")},
        "status": "rejected",
        "archived_at": rejected_at,
        "rejected_at": rejected_at,
        "reject_reason": reason,
        "reopen_when": reopen_when,
        "rejected_by": verifier,
    })
    registry["proposals"] = proposals
    registry["archived"] = archived
    _save_proposals(registry)

    ledger_record_id = None
    ledger_error = None
    if ledger is not None:
        try:
            ledger_record_id = ledger.append(
                "willow",
                FRANK_EVENT_REJECTED,
                {
                    "proposal_id": proposal_id,
                    "verb": proposal["verb"],
                    "grantee": proposal["grantee"],
                    "bounds_digest": _bounds_digest(proposal["bounds"]),
                    "verifier": verifier,
                    "reason": reason,
                    "reopen_when": reopen_when,
                    "rejected_at": rejected_at,
                },
            )
        except Exception as exc:  # pragma: no cover — ledger is optional
            ledger_error = str(exc)

    result = {
        "proposal_id": proposal_id,
        "verifier": verifier,
        "reason": reason,
        "reopen_when": reopen_when,
        "rejected_at": rejected_at,
        "_ledger_record_id": ledger_record_id,
    }
    if ledger_error:
        result["_ledger_error"] = ledger_error
    return result


def list_active(
    *, grantee: Optional[str] = None, verb: Optional[str] = None
) -> list[dict]:
    """Currently active envelopes, filterable by grantee and/or verb.
    Read-only.

    "Active" means what the GATE means by it: a row in ``active[]`` that is
    not revoked and whose ``status`` is ``"active"`` — the same predicate
    ``envelopes.usable_active_grants`` applies. Membership of ``active[]``
    alone is not enough. A revoked envelope stays in that list on purpose
    (the register keeps the history of what was granted and withdrawn), and
    listing it here reported grants as in force that the gate would refuse —
    the surface an operator reads disagreeing with the surface that enforces.
    Use :func:`list_revoked` to see what was withdrawn."""
    registry = _load_registry()
    rows = [row for row in (registry.get("active") or []) if not _is_revoked(row)]
    if grantee is not None:
        rows = [row for row in rows if _grantee_matches(row.get("grantee"), grantee)]
    if verb is not None:
        rows = [row for row in rows if row.get("verb") == verb]
    return list(rows)


def _is_revoked(row: dict) -> bool:
    """The gate's own predicate (``envelopes.py`` line ~198), one place."""
    return bool(row.get("revoked")) or row.get("status") == "revoked"


def list_revoked(
    *, grantee: Optional[str] = None, verb: Optional[str] = None
) -> list[dict]:
    """Envelopes that were granted and later withdrawn. Read-only.

    These rows stay in ``active[]`` rather than moving to ``archived[]``: an
    envelope that was in force and was withdrawn is a different fact from a
    proposal that was never granted, and the register should be able to say
    which happened."""
    registry = _load_registry()
    rows = [row for row in (registry.get("active") or []) if _is_revoked(row)]
    if grantee is not None:
        rows = [row for row in rows if _grantee_matches(row.get("grantee"), grantee)]
    if verb is not None:
        rows = [row for row in rows if row.get("verb") == verb]
    return list(rows)


def revoke(
    envelope_id: str,
    *,
    verifier: str,
    reason: str,
    ledger=None,
) -> dict:
    """Withdraw an ACTIVE envelope. Operator act, CLI only.

    Until this existed, revocation was a state the system could read and not
    produce: the gate honours ``revoked``/``status == "revoked"``
    (``envelopes.py``), no code path ever set either, and ``envelope reject``
    acts on pending PROPOSALS. Withdrawing a live grant therefore meant
    hand-editing ``constitutional/pre-approved.json`` — the trust root — which
    is the act the envelope programme exists to keep hands off.

    The row is marked in place and KEPT, never deleted: the register's value
    is that it records what was granted AND what was taken back, and a
    disappeared grant cannot be audited. ``bounds`` and ``ratified_via``
    survive intact so the row still scores as a precedent.

    Deliberately NOT an MCP tool, for the same reason ``frank-anchor`` is
    CLI-only: an agent must not be able to withdraw the grants that bound it,
    nor a peer's. Narrowing authority is safer than widening it, but a seat
    that can revoke can also deny — it could strip another agent's dispatch
    grant and stall the fleet. Revocation is an operator act, and the
    keyring check below is what makes "operator" mean something.

    Returns ``{envelope_id, verifier, revoked_at, reason}`` and appends
    ``envelope_revoked`` to FRANK when a ledger is available.
    """
    if not _keyring_verifier_active(verifier):
        raise OperatorVerifierRequired(
            f"revoke requires an operator verifier known to the keyring "
            f"and not compromised; got {verifier!r}."
        )
    if not (reason or "").strip():
        # A withdrawn grant with no stated reason is the thing a later reader
        # cannot act on: they can see the authority is gone and not whether
        # it was redundant, mistaken, or abused.
        raise EnvelopeAuthoringError("revoke requires a reason")
    _refuse_registry_mismatch("revoke")

    # Loki audit BDC2B0F2, A1: same defect as ratify_proposal_row's, and
    # pre-existing since #623 -- _load_registry() opens the broker-owned
    # sidecar too, refused for the trust owner (the only identity that
    # ever reaches this function in this codebase,
    # trust_owner_verbs._apply_envelope_revoke) before this write happens.
    registry = _load_active_register()
    rows = registry.get("active") or []
    matches = [row for row in rows if row.get("id") == envelope_id]
    if not matches:
        raise EnvelopeNotFoundError(f"no envelope with id {envelope_id!r}")
    row = matches[0]
    if _is_revoked(row):
        raise EnvelopeAuthoringError(
            f"envelope {envelope_id!r} is already revoked "
            f"(at {row.get('revoked_at') or 'unknown time'})")

    revoked_at = _now_iso()
    row["status"] = "revoked"
    row["revoked"] = True
    row["revoked_at"] = revoked_at
    row["revoked_by"] = verifier
    row["revoked_reason"] = reason
    # revoke only ever changes active[] -- writes only the register, never
    # the proposals sidecar (Loki audit 54E3DFC0, R2). Reached in this
    # codebase only through the trust-owner apply half
    # (trust_owner_verbs._apply_envelope_revoke), which already runs as
    # the trust-owner uid; a direct CLI call to this function from any
    # other identity fails the same way any other-uid write into a
    # trust-owner-owned directory fails.
    _save_active(registry)

    ledger_record_id = None
    ledger_error = None
    if ledger is not None:
        try:
            ledger_record_id = ledger.append(
                "willow",
                FRANK_EVENT_REVOKED,
                {
                    "envelope_id": envelope_id,
                    "verb": row.get("verb"),
                    "grantee": row.get("grantee"),
                    "bounds_digest": _bounds_digest(row.get("bounds") or {}),
                    "ratified_via": row.get("ratified_via"),
                    "revoked_by": verifier,
                    "revoked_at": revoked_at,
                    "reason": reason,
                },
            )
        except Exception as exc:                      # ledger down != act undone
            ledger_error = str(exc)
    return {
        "envelope_id": envelope_id,
        "verifier": verifier,
        "revoked_at": revoked_at,
        "reason": reason,
        "ledger_record_id": ledger_record_id,
        "ledger_error": ledger_error,
    }


def list_archived(
    *,
    grantee: Optional[str] = None,
    verb: Optional[str] = None,
    status: Optional[str] = None,
) -> list[dict]:
    """Envelope rows the operator has archived — today, rejected
    proposals moved by :func:`reject` (PR11). Filterable by grantee,
    verb, and status. Read-only.

    Bounds and reopen_when carry through so a caller can score archived
    rows as precedents (see :func:`envelope_shapes.similar_precedents`
    with ``include_archived=True``). The ``status`` filter is opt-in —
    absent, all archived rows come back regardless of why they were
    archived (rejected today; superseded / revoked in future PRs)."""
    registry = _load_registry()
    rows = list(registry.get("archived") or [])
    if grantee is not None:
        rows = [row for row in rows if _grantee_matches(row.get("grantee"), grantee)]
    if verb is not None:
        rows = [row for row in rows if row.get("verb") == verb]
    if status is not None:
        rows = [row for row in rows if row.get("status") == status]
    return rows


def _reconcile_pending_against_active(registry: dict) -> dict:
    """Drop any sidecar ``proposals[]`` row whose id is already in the
    register's ``active[]`` — the trust-owner ``envelope.ratify`` apply
    half (:mod:`trust_owner_verbs`) moves a proposal into ``active[]`` but
    can never touch the broker-owned sidecar at all (it cannot even read
    it, let alone write it), so without this the sidecar keeps showing a
    proposal as pending long after it became a real, active grant. Called
    from the broker's own read paths (:func:`list_pending`,
    :func:`envelope_pending_read`'s underlying call) — reading ``active[]``
    here is the same ``trusted_read`` signature-verified branch every other
    reader of the trust-owner-owned register already takes; WRITING the
    trimmed sidecar back is safe because the broker (not the apply half)
    is the one calling this, and the broker owns that file. A write
    failure here (read-only mount, race, whatever) never breaks the read
    itself — the stale rows are filtered out of what this call returns
    regardless of whether the on-disk cleanup could complete."""
    proposals = registry.get("proposals") or []
    active_ids = {row.get("id") for row in (registry.get("active") or [])}
    if not any(row.get("id") in active_ids for row in proposals):
        return registry
    remaining = [row for row in proposals if row.get("id") not in active_ids]
    try:
        _save_proposals({"proposals": remaining, "archived": registry.get("archived") or []})
    except OSError:
        pass
    registry = dict(registry)
    registry["proposals"] = remaining
    return registry


def list_pending(
    *,
    oldest_first: bool = True,
    limit: int = 50,
    include_precedents: bool = True,
) -> list[dict]:
    """Proposals awaiting ratification. Operator's queue view.

    Sorted by ``proposed_at`` (oldest first by default so the operator sees
    the longest-waiting proposals at the top). Bounded by ``limit`` — the
    queue can grow; a paginated read is safer than an unbounded one.

    When ``include_precedents`` is True (the default; PR10), each row gets
    a ``precedents_expanded`` field: for every id in ``precedent_ids``
    that still resolves to a currently-active envelope, the full envelope
    row is inlined so the operator can see WHAT they'd be reaffirming
    without a second lookup. IDs that no longer resolve (envelope was
    revoked, registry was edited by hand) are silently dropped from the
    expansion — the id itself stays in ``precedent_ids`` as tamper
    evidence but the operator's ratify surface reflects only what's
    actually still on record. Empty list on a row with no precedents.
    """
    registry = _load_registry()
    registry = _reconcile_pending_against_active(registry)
    rows = list(registry.get("proposals") or [])
    rows.sort(key=lambda r: r.get("proposed_at") or "", reverse=not oldest_first)
    rows = rows[: max(0, int(limit))]
    if not include_precedents:
        return rows
    # Build one lookup so N pending × M precedents is O(N+M+A) rather than
    # O(N × M × A). Active + archived are small in practice; still worth
    # the loop. Active wins ties (an id present in both — shouldn't happen,
    # but active is the current state, so it's the truth if it does).
    active_by_id = {
        row.get("id"): row for row in (registry.get("active") or [])
        if row.get("id")
    }
    archived_by_id = {
        row.get("id"): row for row in (registry.get("archived") or [])
        if row.get("id") and row.get("id") not in active_by_id
    }
    enriched = []
    for row in rows:
        row = dict(row)
        expanded = []
        for pid in row.get("precedent_ids") or []:
            hit = active_by_id.get(pid)
            if hit is not None:
                expanded.append({**hit, "precedent_status": "active"})
                continue
            hit = archived_by_id.get(pid)
            if hit is not None:
                # PR11: an archived precedent — most often the operator's
                # "no with reopen_when" from a prior session. Same shape,
                # different polarity. The `precedent_status` field is
                # what tells the ratify surface how to render it.
                expanded.append({
                    **hit,
                    "precedent_status": hit.get("status") or "archived",
                })
        row["precedents_expanded"] = expanded
        enriched.append(row)
    return enriched


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _grantee_matches(row_grantee, query: str) -> bool:
    """Loose match: the registry row's grantee can be a string or a list of
    strings; the caller's query is a plain string. Returns True on exact
    equality or list-membership."""
    if isinstance(row_grantee, str):
        return row_grantee == query
    if isinstance(row_grantee, (list, tuple)):
        return query in row_grantee
    return False


def _bounds_digest(bounds: dict) -> str:
    """SHA-256 of the bounds' canonical JSON. Used as the tamper-evident
    key for the FRANK envelope events — a proposal whose bounds are edited
    out-of-band after propose but before ratify has a different digest,
    which ratify can catch by re-computing.

    Deterministic encoding (same discipline as ``session_signing._message``):
    ``json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)``.
    """
    import hashlib

    payload = json.dumps(
        bounds, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
