"""willow_mcp.attribution_ledger — append-only hash chain of session attestations.

PR4 of the identity-in-session plan. Mirrors :mod:`nestor.ledger`'s shape
(Nestor#2 tamper-evident chain) for a different subject: instead of "which
verifier sealed which pair," this records "which verifier attested which
session, and when." One entry per successful ``willow-mcp sign-session``
call — a re-attestation writes a fresh entry rather than mutating a prior
one, so the whole history of a session's trust-lineage is preserved.

The invariant Nestor's ledger docstring names holds here too: each line's
``prev`` is the SHA-256 of the whole previous line's bytes. A tamper anywhere
in the tail rehashes the next entry's ``prev`` and the walk catches it —
except for the very last line, which nothing follows. :func:`head` returns
the tip so a caller who kept it out-of-band (a CI variable, a monitor)
can close the "newest line is editable" gap via :func:`verify`'s
``expected_head`` parameter.

Genesis is the string ``"genesis"``, same as Nestor. A fresh instance and a
tampered-then-cleared one look the same, which is precisely why an
out-of-band head is needed to distinguish them.

Storage: JSONL at ``paths.attribution_ledger_path()`` (a fixed file under
``sessions_dir()``). Callers use :func:`append` on the write path and
:func:`verify` on read/boot. Nothing mutates a written line.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Optional, Union


class LedgerError(Exception):
    """The ledger is unusable (unreadable, malformed, chain broken)."""


def _default_path() -> Path:
    from . import paths as _paths

    return _paths.attribution_ledger_path()


def _resolve(path: Union[str, Path, None]) -> Path:
    if path is None:
        return _default_path()
    return Path(path)


def head(path: Union[str, Path, None] = None) -> str:
    """SHA-256 of the last line's bytes — the chain's current tip.

    The value the **next** :func:`append` will carry as its ``prev``. Returns
    ``"genesis"`` for an absent or empty ledger, so a fresh instance behaves
    like any other — a caller who did not remember to save the tip cannot tell
    a fresh ledger from one that was cleared without knowing what was there,
    which is why :func:`verify` accepts ``expected_head``.
    """
    p = _resolve(path)
    if not p.exists():
        return "genesis"
    last = ""
    for raw in p.read_text(encoding="utf-8").splitlines():
        if raw.strip():
            last = raw.strip()
    return hashlib.sha256(last.encode("utf-8")).hexdigest() if last else "genesis"


def append(
    session_id: str,
    verifier: str,
    attested_at: str,
    sig_digest: str,
    path: Union[str, Path, None] = None,
) -> str:
    """Append one attestation to the chain. Returns the new head (the SHA-256
    of the line just written).

    ``sig_digest`` is the SHA-256 of the raw hex signature bytes. Storing the
    digest — not the signature itself — keeps the ledger small while binding
    each entry to the exact attestation it records; two identical entries
    would only occur if the same verifier signed the same session at the same
    attested_at with the same sig, which by construction cannot differ.

    Not atomic in the strict sense: two concurrent appends could interleave.
    The ledger's own reader will detect a chain break at the interleaved
    line's ``prev``. In the single-server-process willow-mcp deployment this
    doesn't arise; a note here for anyone porting the module to a
    multi-writer context.
    """
    p = _resolve(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    prev = head(p)
    entry = {
        "kind": "session_attestation",
        "session_id": session_id,
        "verifier": verifier,
        "attested_at": attested_at,
        "sig_digest": sig_digest,
        "prev": prev,
    }
    line = json.dumps(entry, separators=(",", ":"), ensure_ascii=False)
    with open(p, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def verify(
    path: Union[str, Path, None] = None,
    expected_head: Optional[str] = None,
) -> tuple[bool, str]:
    """Walk the chain: line N's ``prev`` must equal SHA-256 of line N-1's
    bytes, rooted at ``"genesis"``. Returns ``(ok, detail)``.

    ``expected_head`` closes the last-line-is-editable gap for a caller who
    kept the tip out of band. Absent it, a walk of an intact chain still
    passes even if the last entry was quietly edited — same property Nestor's
    ledger docstring names, and the same remedy.
    """
    p = _resolve(path)
    if not p.exists():
        if expected_head and expected_head != "genesis":
            return False, (
                f"no ledger at {p}, but head {expected_head[:16]}… was "
                "expected — the trail is missing, not empty"
            )
        return True, "no ledger yet"
    prev = "genesis"
    count = 0
    for i, raw in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception as exc:
            return False, f"line {i}: not valid JSON ({exc})"
        if rec.get("prev") != prev:
            return False, (
                f"broken chain at line {i}: prev={rec.get('prev')!r} "
                f"expected {prev!r}"
            )
        prev = hashlib.sha256(line.encode("utf-8")).hexdigest()
        count += 1
    if expected_head and expected_head != prev:
        return False, (
            f"chain walks clean over {count} entries but its head is "
            f"{prev[:16]}…, not the expected {expected_head[:16]}… — the "
            "last entry was edited, or entries were added or removed"
        )
    return True, f"intact — {count} entries"


def entries(
    session_id: Optional[str] = None,
    path: Union[str, Path, None] = None,
    limit: int = 500,
) -> list[dict]:
    """Ledger entries, oldest first, optionally filtered by ``session_id``.

    Deliberately does NOT verify the chain: a caller investigating a broken
    ledger still needs to see what is in it. Call :func:`verify` for that
    and treat the two answers together. Skips lines that don't parse — the
    ones that do are still evidence, and refusing to show them means the
    audit UI hides content the operator needs to see.
    """
    p = _resolve(path)
    if not p.exists():
        return []
    out: list[dict] = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if session_id is not None and rec.get("session_id") != session_id:
            continue
        out.append(rec)
        if len(out) >= limit:
            break
    return out


def sig_digest_hex(sig_hex: str) -> str:
    """The digest ``append`` records for a given hex signature. Exposed so
    callers can supply exactly what the ledger stores rather than reproducing
    the hash themselves."""
    return hashlib.sha256(sig_hex.encode("utf-8")).hexdigest()
