"""tool_oracle.py — Nestor-backed natural-language router over willow's own verbs.

Design: docs/design/nestor-tool-route.md.

Fail-closed by construction: a query is SERVED only when a human-sealed
`surface -> tool` pair clears Nestor's seal threshold; everything else is QUEUED
for a human to seal. It never guesses a verb.

Nestor is an OPTIONAL dependency (the `nestor` extra; an unpublished git dep).
It is imported LAZILY behind `_nestor()` — absent the engine the verbs report
`{"status": "unavailable"}` instead of failing to import, the same soft-seam
discipline used by oakenscrolls' almanac_seam. State is vault-rooted and
gitignored; nothing oracle-side lives in the repo except the shipped catalog.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from .paths import store_root

DOMAIN = "tool"

# ── soft Nestor seam ─────────────────────────────────────────────────────────
_NESTOR = None
_TRIED = False


def _nestor():
    """(EntityResolver, answer, portable, cascade, SqliteStore) or None.

    Imported once and cached. A clean install without the `nestor` extra returns
    None, so the verbs degrade to `unavailable` rather than raising at import.
    """
    global _NESTOR, _TRIED
    if not _TRIED:
        _TRIED = True
        try:
            from nestor import answer, cascade, portable
            from nestor.entity import EntityResolver
            from nestor.sqlite_store import SqliteStore
            _NESTOR = (EntityResolver, answer, portable, cascade, SqliteStore)
        except ImportError:
            _NESTOR = None
    return _NESTOR


def available() -> bool:
    """Whether the Nestor engine is installed (routing is live)."""
    return _nestor() is not None


def _unavailable() -> dict:
    return {"status": "unavailable",
            "detail": "Nestor engine not installed — pip install "
                      "'nestor @ git+https://github.com/Die-Namic-Systems/Nestor@master'"}


# ── paths (vault-rooted, gitignored, per-fleet) ──────────────────────────────
def _oracle_dir() -> Path:
    return store_root() / "tool-oracle"


def _db_path() -> Path:
    return _oracle_dir() / "oracle.db"


def _ledger_path() -> Path:
    return _oracle_dir() / "ledger.jsonl"


def _pending_path() -> Path:
    return _oracle_dir() / "pending.jsonl"


def _bundle_path() -> Path:
    """The shipped, signed catalog. Override with WILLOW_TOOL_ORACLE_BUNDLE."""
    import os
    override = os.environ.get("WILLOW_TOOL_ORACLE_BUNDLE", "").strip()
    if override:
        return Path(override)
    return Path(__file__).parent / "bundle" / "tool_oracle.bundle.json"


def _store():
    parts = _nestor()
    _, _, _, cascade, SqliteStore = parts
    _oracle_dir().mkdir(parents=True, exist_ok=True)
    cascade.set_ledger_path(_ledger_path())
    store = SqliteStore(str(_db_path()))
    store.memory_init()  # idempotent; _ensure_seeded queries before any resolver
    return store


# ── one-time seed from the shipped bundle, verified before trust ─────────────
def _ensure_seeded(store) -> Optional[str]:
    """Import the shipped catalog once. Verify its integrity FIRST and fail
    closed if it was tampered — a redirected verb target must never load
    silently. Returns an error string on a bad bundle, else None."""
    _, _, portable, _, _ = _nestor()
    if store.memory_list(source_lang=DOMAIN, target_lang=DOMAIN, limit=1):
        return None  # already seeded
    bundle_file = _bundle_path()
    if not bundle_file.is_file():
        return None  # no catalog shipped — an empty oracle is taught live
    try:
        bundle = json.loads(bundle_file.read_text())
    except (OSError, json.JSONDecodeError) as e:
        return f"tool-oracle bundle unreadable: {e}"
    ok, detail = portable.verify_bundle(bundle)
    if not ok:
        return f"tool-oracle bundle failed verification: {detail}"
    portable.import_bundle(bundle, store=store, dry_run=False)
    return None


def _record_pending(surface: str, closest: Optional[dict]) -> None:
    """Append an unserved intent to the teach-queue (append-only jsonl)."""
    _oracle_dir().mkdir(parents=True, exist_ok=True)
    with _pending_path().open("a") as fh:
        fh.write(json.dumps({"surface": surface, "at": int(time.time()),
                             "closest": closest}) + "\n")


# ── operations the MCP verbs call ────────────────────────────────────────────
def route(query: str) -> dict:
    """Resolve a natural-language intent to a willow verb, or queue it."""
    if not query or not query.strip():
        return {"status": "error", "detail": "nothing to route"}
    if _nestor() is None:
        return _unavailable()
    _, answer, _, _, _ = _nestor()
    store = _store()
    seed_err = _ensure_seeded(store)
    if seed_err:
        return {"status": "unavailable", "detail": seed_err}
    r = answer.resolve(store, query, domain=DOMAIN)  # appends a ledger passage
    if r.get("verified"):
        return {"status": "served", "tool": r["canonical"],
                "confidence": r.get("confidence"), "threshold": r.get("threshold")}
    top = (r.get("candidates") or [None])[0]
    closest = ({"tool": top["canonical"], "similarity": top["similarity"]}
               if top else None)
    _record_pending(query, closest)
    return {"status": "queued", "tool": None, "threshold": r.get("threshold"),
            "closest": closest,
            "hint": "no sealed phrasing cleared the bar; a human can teach it "
                    "with nestor_tool_seal"}


def seal(surface: str, tool: str, verifier: str) -> dict:
    """Sanction a `surface -> tool` mapping (a signed, ledgered seal)."""
    if not surface.strip() or not tool.strip():
        return {"status": "error", "detail": "seal needs a surface and a tool"}
    if _nestor() is None:
        return _unavailable()
    EntityResolver, _, _, _, _ = _nestor()
    store = _store()
    _ensure_seeded(store)
    EntityResolver(store, domain=DOMAIN).seal(
        surface=surface, canonical=tool, verifier=verifier, origin="tool-oracle")
    return {"status": "sealed", "surface": surface, "tool": tool, "verifier": verifier}


def pending(limit: int = 20) -> list:
    """The teach-queue: recent unserved intents, newest first, deduped by
    surface. Empty when every routed intent has a sealed home."""
    if _nestor() is None:
        return [_unavailable()]
    path = _pending_path()
    if not path.is_file():
        return []
    seen, out = set(), []
    for line in reversed(path.read_text().splitlines()):
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        key = row.get("surface", "")
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
        if len(out) >= limit:
            break
    return out
