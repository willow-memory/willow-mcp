"""subject_consent.core — consent for a subject who isn't the owner.

The stdlib-only, egress-free heart of the guardian-consent seam. It answers a
question no other authorization surface in the stack can: *did this person — or a
guardian on their behalf — agree to their data being used this way?*

This is the convergence of a gap that was designed twice and built zero times:
corpus-lens named `owner != subject` its "biggest unshipped gap" and refused to
ship it; the willow-mcp seam doc mapped it; UTETY built a private copy for a
child learner. This module is the one shared primitive all three depend on.

HARD CONSTRAINT — stdlib only, no network, no FFI, no willow-mcp runtime deps.
UTETY runs this on a child's device; corpus-lens is stdlib-only by charter. So
this file imports nothing but the standard library, and `tests/` enforces it.

Everything here is FAIL-CLOSED: absence, unparseability, a broken chain, a
truncated chain, `pending`, or `revoked` all resolve to denied. Mutation
(`grant`/`revoke`) is a library primitive an *operator CLI* calls — an app can
never grant consent on a subject's behalf; enforcing that is the binding's job.

STORAGE IS PLUGGABLE (v0.0.2). The chain logic — hashing, prev-links, and the
head **anchor** that makes tail-truncation detectable (backported from UTETY's
store, audit B4) — lives here, storage-free. Where the rows land is a `Backend`.
The default `FileBackend` writes append-only JSONL + a sibling anchor file; UTETY
plugs a SQLite backend so its consent lives in the one on-device store beside the
learner, atomically. Every public function takes `store`, which may be a
filesystem path (wrapped in a `FileBackend`) or any `Backend` instance.

Provenance: home is THIS repo. Vendored from rudi193-cmd/safe-app-store
``libs/subject-consent`` (MIT; box audit A1) until 2026-09-12, when
safe-app-store was archived (owner decision: never an origin again). Since then
this is the canonical copy: edit it here, under the HARD CONSTRAINT above.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable

# ── vocabulary ────────────────────────────────────────────────────────────────

#: What a subject can consent to. INDEPENDENT permissions, deliberately NOT a
#: ladder: a person-inference that stays local is not "more" than a de-identified
#: KB promotion — they are different uses, so each is granted (and checked)
#: on its own. `person_inference` is the same name as corpus-lens's capability.
SCOPES: tuple[str, ...] = (
    "local_only",        # the subject's data may live on this device
    "process_analysis",  # process/structure may be derived (corpus-lens, Nest counts)
    "kb_promotion",      # de-identified structure may cross into the shared KB
    "person_inference",  # a person-shaped claim about the subject may be made at all
    # The subject's own account may leave the vault ATTRIBUTED — their words,
    # under the name they gave. Deliberately not `kb_promotion`: that scope is
    # de-identified structure crossing into a shared index, and an oral-history
    # desk publishes the opposite ("Names Given Not Chosen" — the naming is the
    # record). Granting one must never imply the other, so it is its own scope.
    # Added for apps/intake-desk, the fourth consumer.
    "testimony_publication",
)

#: How a subject relates to the owner. `self` means owner == subject (the
#: binding may exempt that case; the core does not — it only records grants).
RELATIONS: tuple[str, ...] = ("self", "child", "ward", "household", "other")

# UTETY's exact lifecycle. Anything that is not GRANTED is denied.
PENDING = "pending"
GRANTED = "granted"
REVOKED = "revoked"
_STATUSES = frozenset({PENDING, GRANTED, REVOKED})

_GENESIS = ""  # prev_hash of the first row in a chain


class SubjectConsentError(Exception):
    """Base for this module."""


class DeidentificationError(SubjectConsentError):
    """A boundary crossing could not prove its scrub. Never carries the value."""


class ChainTamperError(SubjectConsentError):
    """A hash chain failed verification (mid-chain edit, or tail truncation)."""


# ── records ───────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Subject:
    """A person the data is about. `id` is opaque and local — never a name on
    the wire. `can_self_consent` is carried but its *policy* (age/capacity) is
    deferred to the binding; the core does not judge it."""
    id: str
    relation_to_owner: str = "other"
    can_self_consent: bool = False


@dataclass(frozen=True)
class Consent:
    """One transition in a subject's consent chain. Tamper-evident: `hash`
    covers the canonical payload AND `prev_hash`, so any edit or truncation
    breaks the links (or the anchor)."""
    subject_id: str
    scope: str
    status: str
    granted_by: str
    at: str            # ISO-8601 UTC
    prev_hash: str
    hash: str

    def payload(self) -> dict:
        """The signed portion — everything but `hash`."""
        return {
            "subject_id": self.subject_id,
            "scope": self.scope,
            "status": self.status,
            "granted_by": self.granted_by,
            "at": self.at,
            "prev_hash": self.prev_hash,
        }


# ── hashing (shared by the consent chain and the disclosure chain) ─────────────

def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _row_hash(payload: dict) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── storage backend (pluggable) ────────────────────────────────────────────────
# The core owns the chain LOGIC; a Backend owns WHERE rows land. There are two
# chains, addressed by a string id: the consent chain (`_CONSENT_CHAIN`) and one
# disclosure chain per subject (`_disclosure_chain(subject_id)` — the subject_id
# is hashed, so an opaque id never leaks into a chain name / filename).

_CONSENT_CHAIN = "consent"


def _disclosure_chain(subject_id: str) -> str:
    safe = hashlib.sha256(subject_id.encode("utf-8")).hexdigest()[:32]
    return f"disclosure/{safe}"


@runtime_checkable
class Backend(Protocol):
    """Where a hash-chained log is stored. Four operations, each per-chain:

      read_rows    — the rows in order, or None if the chain is absent/unreadable
                     (None is "not there", distinct from [] "there and empty").
      append_row   — append one row (the core has already chained + hashed it).
      read_anchor  — the {"hash","count"} head anchor, or None if absent.
      write_anchor — persist the head anchor after an append.

    A backend that can make append_row + write_anchor atomic (e.g. one SQLite
    transaction, as UTETY does) closes the crash window the FileBackend documents.
    """

    def read_rows(self, chain: str) -> list[dict] | None: ...
    def append_row(self, chain: str, row: dict) -> None: ...
    def read_anchor(self, chain: str) -> dict | None: ...
    def write_anchor(self, chain: str, anchor: dict) -> None: ...


class FileBackend:
    """Default backend: append-only hash-chained JSONL + a sibling anchor file.

        <root>/consent.jsonl                     (+ consent.anchor.json)
        <root>/disclosures/<subject_hash>.jsonl  (+ <subject_hash>.anchor.json)

    Append writes the row, then the anchor (atomic tmp+replace). A crash *between*
    the two leaves rows/anchor out of step — which `_verify` reads as tampered and
    FAILS CLOSED (deny), never silently accepts. A backend needing crash atomicity
    should make the pair transactional (that is why the backend is pluggable).

    EMPTIED IS NOT ABSENT. The count anchor detects deleting the *newest* rows.
    It cannot, on its own, detect deleting them ALL: `read_rows() -> None` means
    "no such chain", and absent is legitimately not tampered, so a backend that
    answers None for an emptied chain hands an attacker the strongest attack
    available *and* the simplest — delete every row and the log reads as one that
    never existed. The revocation, the disclosure that names them: gone, quietly.

    The two files are siblings, and that is the evidence. An anchor with no rows
    beside it is positive proof rows were here, so this backend reads that state
    as EMPTIED (`[]`, which `_verify` rejects) and answers `None` only when there
    is genuinely nothing left — neither file. Unreadable rows count as emptied
    too, on the same evidence: ambiguity resolves to tampered, never to absent.
    (marching-arts's SqliteConsentBackend reaches the same conclusion from the
    same argument; its rows and anchor share one store.)

    Consequently an orphaned anchor also BLOCKS `append_row`: without that, the
    next honest grant would start a fresh chain at genesis, overwrite the orphan
    with `count=1`, and leave a store that verifies clean with the deleted
    history gone — the attack laundered by its victim. Recovering deliberately
    means removing the anchor too, which is the operator saying "there is no
    chain here" in the one way that is not also a silent rewrite."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)

    def _base(self, chain: str) -> Path:
        if chain == _CONSENT_CHAIN:
            return self.root / "consent"
        if chain.startswith("disclosure/"):
            return self.root / "disclosures" / chain.split("/", 1)[1]
        raise SubjectConsentError(f"unknown chain: {chain!r}")

    def _rows_path(self, chain: str) -> Path:
        return self._base(chain).with_suffix(".jsonl")

    def _anchor_path(self, chain: str) -> Path:
        return self._base(chain).with_suffix(".anchor.json")

    def _emptied_or_absent(self, chain: str) -> list[dict] | None:
        """No usable rows. `[]` (emptied → tampered) if an anchor survives to
        prove rows were here; `None` (absent → clean) only if nothing does."""
        return [] if self._anchor_path(chain).is_file() else None

    def read_rows(self, chain: str) -> list[dict] | None:
        path = self._rows_path(chain)
        if not path.is_file():
            return self._emptied_or_absent(chain)
        rows: list[dict] = []
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    return self._emptied_or_absent(chain)
                rows.append(obj)
        except Exception:
            return self._emptied_or_absent(chain)
        return rows

    def append_row(self, chain: str, row: dict) -> None:
        path = self._rows_path(chain)
        if not path.is_file() and self._anchor_path(chain).is_file():
            # An anchor with no rows file: the chain was emptied, not absent.
            # Appending here would rebuild it from genesis and destroy the only
            # evidence of that. Refuse — the core refuses broken chains too.
            raise ChainTamperError(
                "refusing to extend a chain whose rows are gone but whose anchor remains"
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    def read_anchor(self, chain: str) -> dict | None:
        path = self._anchor_path(chain)
        if not path.is_file():
            return None
        try:
            obj = json.loads(path.read_text(encoding="utf-8"))
            return obj if isinstance(obj, dict) else None
        except Exception:
            return None

    def write_anchor(self, chain: str, anchor: dict) -> None:
        path = self._anchor_path(chain)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(anchor, sort_keys=True), encoding="utf-8")
        tmp.replace(path)


def _as_backend(store: "Path | str | Backend") -> Backend:
    """A path/str becomes a FileBackend; a Backend is used as-is. This keeps the
    public API a single `store` parameter for both the default and a plugged one."""
    if isinstance(store, Backend):
        return store
    return FileBackend(store)


# ── chain verification (links + the truncation anchor) ─────────────────────────

def _verify(rows: list[dict], anchor: dict | None) -> bool:
    """Two properties, both required:

      1. LINKS — every row's prev_hash equals the prior row's hash, and every
         hash recomputes (a mid-chain edit or delete breaks this).
      2. ANCHOR — the head anchor names the last row's hash and the row count, so
         DELETING THE NEWEST ROWS is detected even though the shorter chain still
         links cleanly (UTETY audit B4). An empty chain must have no anchor; a
         non-empty chain with a missing/mismatched anchor is tampered.
    """
    prev = _GENESIS
    for row in rows:
        h = row.get("hash")
        payload = {k: row.get(k) for k in row if k != "hash"}
        if payload.get("prev_hash") != prev:
            return False
        if not isinstance(h, str) or _row_hash(payload) != h:
            return False
        prev = h
    if not rows:
        return anchor is None
    if not isinstance(anchor, dict):
        return False
    return anchor.get("hash") == rows[-1]["hash"] and anchor.get("count") == len(rows)


def _append(backend: Backend, chain: str, payload: dict) -> str:
    """Append one hash-chained row + advance the anchor. Returns the new head hash.
    Verifies the existing chain first and REFUSES to extend a broken or truncated
    one — a tampered store must not be silently continued.

    THE EMPTIED CHAIN. ``read_rows`` returns None for "absent" and [] for
    "present but empty", and that distinction is the whole defence against the
    complete truncation: delete every row, leave the anchor, and [] beside a
    surviving anchor is positive evidence that rows were here.

    This used to read ``read_rows(chain) or []``, collapsing the two — and since
    [] is falsy the guard below was then skipped, so NO backend could make this
    refuse an emptied chain however carefully it reported one.

    The consequence was worse than a missed detection. ``verify`` did catch the
    wipe, but the next honest append restarted at genesis and overwrote the
    orphaned anchor with ``count=1``, after which the store verified clean and
    the deleted history was gone with nothing left to say so. The detection
    window was real and self-closing: any legitimate write laundered it.

    So: ``is not None``, and an emptied chain fails verification and is refused.
    Genuinely absent still starts at genesis, which is how a first grant works."""
    existing = backend.read_rows(chain)
    if existing is not None and not _verify(existing, backend.read_anchor(chain)):
        raise ChainTamperError("refusing to append to a broken chain")
    existing = existing or []
    prev = existing[-1]["hash"] if existing else _GENESIS
    payload = dict(payload, prev_hash=prev)
    h = _row_hash(payload)
    backend.append_row(chain, dict(payload, hash=h))
    backend.write_anchor(chain, {"hash": h, "count": len(existing) + 1})
    return h


# ── consent: mutation (operator/CLI primitives — never an MCP tool) ────────────

def grant(store: "Path | str | Backend", subject_id: str, scope: str, granted_by: str) -> Consent:
    """Record a GRANTED transition. Raises on an unknown scope or empty grantor
    (a grant with no author is not a grant)."""
    return _transition(store, subject_id, scope, GRANTED, granted_by)


def revoke(store: "Path | str | Backend", subject_id: str, scope: str, revoked_by: str) -> Consent:
    """Record a REVOKED transition. Denies from this moment on, permanently on
    the record."""
    return _transition(store, subject_id, scope, REVOKED, revoked_by)


def _transition(store: "Path | str | Backend", subject_id: str, scope: str, status: str, by: str) -> Consent:
    if scope not in SCOPES:
        raise SubjectConsentError(f"unknown scope: {scope!r}")
    if status not in _STATUSES:
        raise SubjectConsentError(f"unknown status: {status!r}")
    if not (subject_id and subject_id.strip()):
        raise SubjectConsentError("subject_id required")
    if not (by and by.strip()):
        raise SubjectConsentError("granted_by/revoked_by required")
    payload = {
        "subject_id": subject_id,
        "scope": scope,
        "status": status,
        "granted_by": by,
        "at": _now(),
    }
    h = _append(_as_backend(store), _CONSENT_CHAIN, payload)
    return Consent(hash=h, prev_hash="", **payload)  # prev_hash set inside _append; returned value is informational


# ── consent: the gate (read-only, fail-closed) ─────────────────────────────────

def permitted(store: "Path | str | Backend", subject_id: str, scope: str) -> bool:
    """True only when the latest transition for (subject_id, scope) is a
    verified GRANTED. Fail-closed on every other path:

      - store absent                    → False
      - unparseable / broken / truncated → False
      - no record for this pair          → False
      - latest is pending or revoked     → False

    Unknown scope is a programming error, denied but still False. Owner == subject
    is NOT special-cased here; that exemption (if any) belongs to the binding that
    knows who the owner is. This core only knows grants.
    """
    if scope not in SCOPES:
        return False
    backend = _as_backend(store)
    rows = backend.read_rows(_CONSENT_CHAIN)
    if not rows or not _verify(rows, backend.read_anchor(_CONSENT_CHAIN)):
        return False
    latest: dict | None = None
    for row in rows:
        if row.get("subject_id") == subject_id and row.get("scope") == scope:
            latest = row
    return bool(latest) and latest.get("status") == GRANTED


def verify_consent_chain(store: "Path | str | Backend") -> None:
    """Admin/diagnostic path: raise ChainTamperError if the consent chain is
    broken or truncated (the gate silently denies; this one tells you *why*)."""
    backend = _as_backend(store)
    rows = backend.read_rows(_CONSENT_CHAIN)
    if rows is None:
        return  # absent is not tampered
    if not _verify(rows, backend.read_anchor(_CONSENT_CHAIN)):
        raise ChainTamperError("consent chain failed verification")


# ── the de-identify-or-refuse boundary (from UTETY's knowledge.py) ─────────────

def deidentify(text: str, identifiers: list[str]) -> str:
    """Remove each identifier from `text`, then PROVE the scrub or raise.

    The only thing that may cross a sharing boundary about a subject is a
    de-identified derivative, and the scrub is verified or it refuses. If any
    identifier survives (case-insensitive), this raises DeidentificationError —
    and the error NEVER contains the surviving value or the text, exactly like
    UTETY's `deidentify()`. `identified is person; de-identified is process`.

    This removes NAMED identifiers (a subject's name you already hold). It composes
    with — does not replace — a pattern scrubber like UTETY's egress-query
    `deidentify` (email/phone/SSN): different jobs, both fail-closed.
    """
    if not isinstance(text, str):
        raise DeidentificationError("de-identification input was not text")
    out = text
    for ident in identifiers:
        if not ident:
            continue
        # case-insensitive removal without echoing the identifier anywhere
        low = out.lower()
        needle = ident.lower()
        idx = low.find(needle)
        while idx != -1:
            out = out[:idx] + "█" * len(ident) + out[idx + len(ident):]
            low = out.lower()
            idx = low.find(needle)
    # verify: no identifier may survive
    low = out.lower()
    for ident in identifiers:
        if ident and ident.lower() in low:
            raise DeidentificationError(
                "de-identification failed to clean the text"  # value withheld on purpose
            )
    return out


# ── the disclosure chain (per subject — the guardian's readable record) ────────

def record_disclosure(store: "Path | str | Backend", subject_id: str, action: str, detail: str = "") -> str:
    """Append a hash-chained disclosure row: what was done with this subject's
    data. This is the record a guardian can read ("what the tutor discussed with
    your child"). Returns the new head hash."""
    if not (subject_id and subject_id.strip()):
        raise SubjectConsentError("subject_id required")
    payload = {
        "subject_id": subject_id,
        "action": action,
        "detail": detail,
        "at": _now(),
    }
    return _append(_as_backend(store), _disclosure_chain(subject_id), payload)


def read_disclosures(store: "Path | str | Backend", subject_id: str) -> list[dict]:
    """Return the verified disclosure chain for a subject. Raises ChainTamperError
    if the chain is broken OR truncated — a guardian's record that cannot prove its
    own integrity must announce that, not quietly return rows."""
    backend = _as_backend(store)
    chain = _disclosure_chain(subject_id)
    rows = backend.read_rows(chain)
    if rows is None:
        return []
    if not _verify(rows, backend.read_anchor(chain)):
        raise ChainTamperError("disclosure chain failed verification")
    return rows
