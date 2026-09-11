"""willow_mcp.nest.autointake — the SessionStart join: drop a file, it gets
processed, not just staged.

The Nest's drop-folder router (intake.py) ships three manual verbs — scan
stages a review queue, confirm/`nest_intake_file` files one item, skip passes
one — but nothing ever CALLS them. A file the operator drags into
~/Desktop/Nest sits in "pending" forever unless someone remembers to run the
verbs by hand. Operator, 2026-09-11: "the nest still has never been wired up
to process things fully when I drop an item in that folder."

This module is the automatic join, invoked from session_start_hook via
boot_context.build_boot_lines on every session boot. It composes the EXISTING
verbs — it does not reimplement intake or classification:

  1. ``intake.scan()``        — stage anything new (already idempotent: a file
     already in the queue, in any status, is never re-staged).
  2. for every item still ``pending`` — file it (``intake.confirm``, the same
     function ``nest_intake_file`` calls) IFF it (a) classified to a known
     track at full confidence, AND (b) a content sniff for high-signal
     credentials (nest/secrets.py) found nothing. Anything else is LEFT
     pending — never forced through — and reported back so a human can look
     at ``nest_intake_queue``/``nest_intake_flags``.

Idempotent by construction: once an item is filed, ``intake.get_queue``
excludes it (status != "pending"), so a second run touches only items that
are new since the last one. Deterministic — no model, no network call
anywhere in this module.

Scope decision — nest_promote is deliberately NOT wired in here. It promotes
the *content* pipeline (nest_scan's SQLite DB → knowledge base), which is
orthogonal to this filename-based intake queue: making it run automatically
would mean either (a) calling nest_scan first, whose default path uses an
embedding model — a model call does not belong in a deterministic boot hook —
or (b) promoting whatever stale/unrelated DB happens to already exist at the
default path, which has no necessary relationship to the items this hook just
filed. nest_promote stays a manual verb the operator runs when they want Nest
structure pushed to the KB. See docs/NEST.md.

A genuine on-drop trigger needs a filesystem watcher daemon (inotify) running
independently of any chat session — that is a separate build. This hook only
guarantees a dropped file is processed by the *next* session's boot, at the
latest.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..db import Store
from . import intake, secrets

# Mirrors intake._prediction_for: 0.70 for a matched rule, 0.0 for "unknown".
# Anything below this is a classification a human should confirm, not the hook.
CONFIDENCE_FLOOR = 0.70

# A boot hook sniffs for secrets, it does not scan a corpus — cap the read.
_MAX_SNIFF_BYTES = 2_000_000


def _secret_kinds(path: Path) -> list[str]:
    """Best-effort content sniff for high-signal credentials. Returns [] for
    anything unreadable/binary/oversized rather than raising — an unreadable
    file is not evidence of a secret (it falls through to the low-confidence
    branch on its own merits), but a decode failure must never take the boot
    path down."""
    try:
        if not path.is_file() or path.stat().st_size > _MAX_SNIFF_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError, ValueError):
        return []
    return sorted({kind for kind, _ in secrets.find_secrets(text)})


def run(store: Store, app_id: str = "hook",
        folders: list[Path] | None = None) -> dict[str, Any]:
    """Scan the drop zone(s) and auto-file everything that classifies cleanly.

    Never raises: any failure downgrades to ``{"status": "error", ...}`` so a
    Nest problem never breaks session boot. Idempotent — a second call with
    nothing new dropped files nothing further.
    """
    try:
        newly_staged = intake.scan(store, folders=folders)
    except Exception as e:  # pragma: no cover — scan() itself is exception-safe
        return {"status": "error", "error": f"{type(e).__name__}: {e}",
                "newly_staged": 0, "filed": [], "held": []}

    filed: list[dict] = []
    held: list[dict] = []
    try:
        pending = intake.get_queue(store)
    except Exception as e:
        return {"status": "error", "error": f"{type(e).__name__}: {e}",
                "newly_staged": len(newly_staged), "filed": [], "held": []}

    for item in pending:
        prediction = item.get("prediction") or {}
        confidence = float(prediction.get("confidence", 0.0) or 0.0)
        track = item.get("track")
        reasons: list[str] = []
        if not track or track == "unknown" or confidence < CONFIDENCE_FLOOR:
            reasons.append("low_confidence")
        kinds = _secret_kinds(Path(item.get("src", "")))
        if kinds:
            reasons.append("secrets:" + ",".join(kinds))
        if reasons:
            held.append({"id": item["id"], "filename": item.get("filename"),
                         "reason": ";".join(reasons)})
            continue
        try:
            res = intake.confirm(store, item["id"], app_id=app_id)
        except Exception as e:
            held.append({"id": item["id"], "filename": item.get("filename"),
                         "reason": f"confirm_failed:{type(e).__name__}"})
            continue
        if isinstance(res, dict) and res.get("error"):
            held.append({"id": item["id"], "filename": item.get("filename"),
                         "reason": f"confirm_error:{res['error']}"})
        else:
            filed.append(res)

    return {"status": "ok", "newly_staged": len(newly_staged),
            "filed": filed, "held": held}


def boot_line(app_id: str = "hook", folders: list[Path] | None = None,
              store: Store | None = None) -> str | None:
    """One-line SessionStart summary, or None when there is nothing to say
    (no drop dirs present, nothing new, nothing pending). Never raises —
    wraps ``run`` so a Nest problem degrades to a visible one-line note, not
    a broken boot."""
    try:
        store = store or Store()
        result = run(store, app_id=app_id, folders=folders)
    except Exception as e:
        return f"[nest] auto-intake failed ({type(e).__name__}: {e}) — run nest_intake_scan by hand."

    if result.get("status") != "ok":
        return f"[nest] auto-intake error: {result.get('error')} — run nest_intake_scan by hand."

    filed, held = result["filed"], result["held"]
    if not filed and not held:
        return None

    parts = []
    if filed:
        parts.append(f"filed {len(filed)}")
    if held:
        names = ", ".join(str(h.get("filename")) for h in held[:3])
        more = "" if len(held) <= 3 else f" +{len(held) - 3} more"
        parts.append(f"{len(held)} need review ({names}{more})")
    return "[nest] " + "; ".join(parts) + " — see nest_intake_queue / nest_intake_flags."
