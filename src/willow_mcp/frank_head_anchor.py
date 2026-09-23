"""The FRANK governance chain's externally-held head anchor (#280).

A hash chain vouches for every row except the newest — nothing about the
chain itself can tell you whether its head is still the head it was
yesterday, because a party that can rewrite the whole table consistently
(``governance_ledger.rechain()``, run over tampered content) produces a
chain that is internally valid and simply wrong. The close, same as
Nestor's ``ledger head`` / ``verify --expect-head``: hold the head
somewhere the party you don't fully trust with Postgres cannot also reach.

Layout::

    $WILLOW_HOME/constitutional/frank_head_anchor.json
        {"head": "<sha256 hex, or null for an empty chain>",
         "count": <int>, "anchored_at": "<UTC iso8601>", "anchored_by": "<str>"}

Same directory and trust contract as ``pre-approved.json`` /
``syscall-table.json`` — ``paths.trusted_read()`` refuses a symlinked,
foreign-owned, or group/other-writable file (or parent dir) before this
module believes anything in it.

Write path is CLI/operator-only (``willow-mcp frank-anchor write``) — no MCP
tool wraps ``write_anchor()``. This mirrors ``agent_registry.py``'s sudo
invariant: an agent may request standing, never mint it. If an MCP tool
could re-anchor, the anchor would only ever agree with whatever the DB
currently says, which is exactly the property it exists to NOT have.

Read path (``read_anchor()``) never raises: a missing file (no anchor
configured — most installs, including every test in this suite, start
here), an unreadable/malformed one, or one that fails the trust check all
degrade to a reported status rather than to a silent "no check happened
here, but let's call it fine." Callers (``frank_verify``, ``rechain()``)
must look at ``status`` before trusting ``head``.
"""
from __future__ import annotations

import json
import logging
import os
import re
import secrets as _secrets
import threading
import time
from pathlib import Path

from . import paths
from . import pgp

logger = logging.getLogger(__name__)

_HEAD_RE = re.compile(r"^[0-9a-f]{64}$")

#: Anchor read/write outcomes. Only "anchored" carries a `head` a caller may
#: trust and compare against. Every other status means "we do not have a
#: usable external anchor right now" — for a different reason each time, all
#: worth telling an operator apart from "the chain is fine."
STATUS_ANCHORED = "anchored"
STATUS_UNANCHORED = "unanchored"      # no file — anchoring was never opted into
STATUS_UNREADABLE = "unreadable"      # file exists but is missing/malformed/corrupt
STATUS_UNTRUSTED = "untrusted"        # file exists but fails the ownership/perms check


def anchor_path() -> Path:
    return paths.frank_head_anchor_path()


def _tmp_suffix() -> str:
    # pid + thread id + random token: two writers cannot collide on one temp
    # path and publish a torn file (mirrors agent_registry.py).
    return f".tmp-{os.getpid()}-{threading.get_ident()}-{_secrets.token_hex(4)}"


def read_anchor() -> dict:
    """Read the externally-held head. Never raises.

    Returns ``{"status": ..., "head": ...}`` and, when ``status ==
    "anchored"``, also ``count``/``anchored_at``/``anchored_by``. ``head`` is
    only meaningful when ``status == "anchored"`` — every other status means
    "there is nothing trustworthy to compare against right now," which a
    caller must treat as *unknown*, not as *matches*.
    """
    p = anchor_path()
    if not p.exists():
        return {"status": STATUS_UNANCHORED, "head": None}
    try:
        paths.trusted_read(p)
    except PermissionError as e:
        logger.warning("frank_head_anchor: refusing untrusted anchor file %s: %s", p, e)
        return {"status": STATUS_UNTRUSTED, "head": None, "error": str(e)}
    except (pgp.PgpFingerprintConflict, pgp.PgpSourceUnreadable) as e:
        # Loki audit A38D41C2, F10: this module's own contract ("never
        # raises") only caught PermissionError, so a conflicting or
        # unreadable trust-config file (both RuntimeError, not
        # PermissionError) escaped it. read_anchor() cannot verify this
        # file's trust-owner signature without knowing which fingerprint to
        # verify against, so it degrades to the same UNTRUSTED status a
        # verification failure gets — "we do not have a usable external
        # anchor right now," never a caller-facing crash.
        logger.warning("frank_head_anchor: cannot verify trust for anchor file %s: %s", p, e)
        return {"status": STATUS_UNTRUSTED, "head": None, "error": str(e)}
    try:
        data = json.loads(p.read_text())
    except (OSError, ValueError) as e:
        logger.warning("frank_head_anchor: unreadable anchor file %s: %s", p, e)
        return {"status": STATUS_UNREADABLE, "head": None, "error": str(e)}
    if not isinstance(data, dict) or "head" not in data:
        logger.warning("frank_head_anchor: malformed anchor file %s", p)
        return {"status": STATUS_UNREADABLE, "head": None, "error": "malformed anchor file"}
    head = data.get("head")
    if head is not None and not (isinstance(head, str) and _HEAD_RE.match(head)):
        logger.warning("frank_head_anchor: non-hex head in anchor file %s", p)
        return {"status": STATUS_UNREADABLE, "head": None, "error": "malformed head value"}
    return {
        "status": STATUS_ANCHORED,
        "head": head,
        "count": data.get("count"),
        "anchored_at": data.get("anchored_at"),
        "anchored_by": data.get("anchored_by"),
    }


def write_anchor(head: str | None, count: int, *, anchored_by: str = "") -> Path:
    """Re-anchor to ``head`` (the CURRENT, operator-confirmed chain head).

    CLI-only — see the module docstring. Not exported through any MCP tool;
    do not add one. Atomic write (temp file + ``os.replace``) at 0600, same
    shape as ``agent_registry.py``'s secret-file writes, so a reader never
    observes a half-written anchor.
    """
    if head is not None and not _HEAD_RE.match(head):
        raise ValueError(f"invalid head (must be 64 lowercase hex chars or None): {head!r}")
    d = paths.constitutional_dir()
    d.mkdir(parents=True, exist_ok=True)
    p = anchor_path()
    data = {
        "head": head,
        "count": count,
        "anchored_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "anchored_by": anchored_by or os.environ.get("USER", "operator"),
    }
    tmp = p.parent / (p.name + _tmp_suffix())
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    try:
        os.chmod(tmp, 0o600)
    except OSError as e:
        logger.warning("frank_head_anchor: could not chmod 0600 %s: %s", tmp, e)
    os.replace(tmp, p)
    return p
