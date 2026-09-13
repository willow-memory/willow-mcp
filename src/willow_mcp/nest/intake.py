"""willow_mcp.nest.intake — the live drop-folder router.

"The pigeon sorts your desktop." Watch a drop folder, classify each new file by
FILENAME into a *track* (rules.py), stage a review queue, and — on an explicit
human gate action — move the file to the track's destination. Nothing moves
without a confirm: scan only stages; confirm/skip is the gate.

THE FEEDBACK EDGE (the thing corpus-lens's static classifiers lack). Every gate
action records the classifier's prediction and the human outcome. A mismatch
(the operator filed it somewhere other than predicted) increments a correction
counter keyed by (predicted → outcome, ext); at CORRECTION_FLAG_THRESHOLD a flag
opens proposing a rule delta. The classifier never rewrites its own rules — it
proposes, the human ratifies (applies the delta to $WILLOW_HOME/nest_rules.json,
bumps its version). Adapted from rudi193-cmd/willow-2.0 sap/core/nest_intake.py;
state lives in willow-mcp's SOIL Store, not core.soil/core.intake.

All state-changing functions take the willow-mcp Store; the MCP tools pass the
server's `_store`. Callers are identified by app_id (willow-mcp's identity),
not an agent name.
"""
from __future__ import annotations

import hashlib
import shutil
from datetime import datetime, timezone
from pathlib import Path

from .. import paths
from . import rules

# Overrides of the same (predicted → outcome, ext) pattern before a rule-delta
# flag opens for human ratification.
CORRECTION_FLAG_THRESHOLD = 3

# SOIL collection names — underscore-only (Store rejects slashes).
QUEUE = "nest_intake_queue"
CORRECTIONS = "nest_intake_corrections"
FLAGS = "nest_intake_flags"
FEEDBACK = "nest_intake_feedback"


def default_drop_dirs() -> list[Path]:
    """Where files are dumped. The canonical Desktop Nest plus a home inbox."""
    return [Path.home() / "Desktop" / "Nest", paths.willow_home() / "nest" / "inbox"]


def track_to_dest() -> dict[str, Path]:
    """Track → destination directory. User tracks land under ~/personal; agent
    artifacts under $WILLOW_HOME. Resolved at call time so tests can redirect
    HOME/WILLOW_HOME."""
    home = Path.home()
    wh = paths.willow_home()
    return {
        "journal":         home / "personal" / "journal",
        "legal":           home / "personal" / "legal",
        "financial":       home / "personal" / "financial",
        "knowledge":       home / "personal" / "knowledge",
        "narrative":       home / "personal" / "writing",
        "correspondence":  home / "personal" / "correspondence",
        "photos_personal": home / "personal" / "photos" / "personal",
        "photos_camera":   home / "personal" / "photos" / "camera",
        "screenshots":     home / "personal" / "photos" / "screenshots",
        "specs":           wh / "specs",
        "handoffs":        wh / "handoffs" / "filed",
        # Operator credentials — PEMs / willow-bot.env land here via Nest gate.
        # Same directory credentials.py reads ($WILLOW_HOME/secrets, usually the
        # vault box). Autointake never auto-files this track (secret sniff).
        "secrets":         wh / "secrets",
    }


def _item_id(src: str) -> str:
    # Content-addressing only (dedup key derived from a file path), not a
    # security boundary — usedforsecurity=False silences B324 honestly
    # rather than suppressing it.
    return "itm-" + hashlib.sha1(src.encode(), usedforsecurity=False).hexdigest()[:10]


def _track_for_dest(dest: Path) -> str:
    """Reverse-map a destination path to its track. Unknown dirs → 'custom'."""
    try:
        resolved = dest.resolve()
    except OSError:
        resolved = dest
    for track, root in track_to_dest().items():
        try:
            root_resolved = root.resolve()
        except OSError:
            root_resolved = root
        if resolved == root_resolved or root_resolved in resolved.parents:
            return track
    return "custom"


def _unique_dest(dest_dir: Path, filename: str) -> Path:
    dest = dest_dir / filename
    if not dest.exists():
        return dest
    stem, suffix = Path(filename).stem, Path(filename).suffix
    i = 1
    while dest.exists():
        dest = dest_dir / f"{stem}_{i}{suffix}"
        i += 1
    return dest


def _prediction_for(filename: str, track: str | None, proposed_dest: str | None) -> dict:
    return {
        "track": track or "unknown",
        "dest": proposed_dest,
        "method": "heuristic" if track else "none",
        "confidence": 0.70 if track else 0.0,
        "classifier_version": rules.version(),
    }


# ── scan / queue ─────────────────────────────────────────────────────────────

def scan(store, folders: list[Path] | None = None) -> list[dict]:
    """Scan drop zones, classify new files by filename, stage them. Idempotent:
    a file already staged (any status) is not re-staged. Returns newly staged."""
    folders = folders or default_drop_dirs()
    dests = track_to_dest()
    newly: list[dict] = []
    for nest_dir in folders:
        if not nest_dir.exists() or not nest_dir.is_dir():
            continue
        for f in sorted(nest_dir.iterdir()):
            if not f.is_file() or f.name.startswith("."):
                continue
            src = str(f)
            iid = _item_id(src)
            if store.get(QUEUE, iid) is not None:
                continue  # already staged (pending/confirmed/skipped)
            track = rules.classify(f.name)
            dest_dir = dests.get(track) if track else None
            proposed = str(_unique_dest(dest_dir, f.name)) if dest_dir else None
            item = {
                "id": iid,
                "src": src,
                "filename": f.name,
                "track": track or "unknown",
                "proposed_dest": proposed,
                "prediction": _prediction_for(f.name, track, proposed),
                "status": "pending",
                "staged_at": datetime.now(timezone.utc).isoformat(),
            }
            store.put(QUEUE, item, record_id=iid)
            newly.append(item)
    return newly


def get_queue(store) -> list[dict]:
    return [it for it in store.all(QUEUE) if it.get("status") == "pending"]


def open_flags(store) -> list[dict]:
    return [f for f in store.all(FLAGS) if f.get("flag_state") == "open"]


# ── feedback loop ────────────────────────────────────────────────────────────

def _correction_rule_key(predicted: str, outcome: str, ext: str) -> str:
    # Same as _item_id above: a short grouping key, not a security hash.
    return hashlib.md5(
        f"{predicted}->{outcome}:{ext}".encode(), usedforsecurity=False
    ).hexdigest()[:8]


def _record_correction(store, prediction: dict, outcome_track: str,
                       filename: str) -> None:
    """Count a prediction miss; open a rule-delta flag at threshold. The
    classifier proposes the delta; a human ratifies it."""
    ext = Path(filename).suffix.lower()
    predicted = prediction.get("track", "unknown")
    rule_key = _correction_rule_key(predicted, outcome_track, ext)
    record_id = f"nest-corr-{rule_key}"
    now = datetime.now(timezone.utc).isoformat()

    existing = store.get(CORRECTIONS, record_id)
    if existing:
        record = existing
        record["count"] = int(record.get("count", 1)) + 1
        record["last_seen"] = now
        samples = record.get("sample_filenames", [])
        if filename not in samples:
            record["sample_filenames"] = (samples + [filename])[-5:]
    else:
        record = {
            "id": record_id, "type": "nest_correction", "rule_key": rule_key,
            "predicted_track": predicted, "outcome_track": outcome_track, "ext": ext,
            "classifier_version": prediction.get("classifier_version", ""),
            "sample_filenames": [filename], "count": 1,
            "first_seen": now, "last_seen": now,
        }
    store.put(CORRECTIONS, record, record_id=record_id)

    if int(record["count"]) >= CORRECTION_FLAG_THRESHOLD:
        flag_id = f"flag-nest-{rule_key}"
        if store.get(FLAGS, flag_id) is None:
            samples = ", ".join(record["sample_filenames"][:3])
            store.put(FLAGS, {
                "id": flag_id, "type": "flag", "flag_state": "open",
                "title": (f"Nest classifier overridden {record['count']}×: "
                          f"{predicted} → {outcome_track} on {ext or 'no-ext'} files"),
                "source": "nest_feedback", "rule_key": rule_key,
                "hit_count": int(record["count"]), "sample_reason": f"e.g. {samples}",
                "fix_path": (f"Propose a keyword/rule delta moving this pattern to "
                             f"'{outcome_track}' in the nest rules store "
                             f"({CORRECTIONS} {record_id}); a human ratifies, the delta "
                             f"applies to $WILLOW_HOME/nest_rules.json and bumps its version."),
                "opened_at": now,
            }, record_id=flag_id)


def _write_feedback(store, item: dict, event: str, final_dest: Path | None,
                    app_id: str) -> None:
    """Record a nest/v1 feedback edge for a gate action (best-effort)."""
    prediction = item.get("prediction") or _prediction_for(
        item.get("filename", ""), item.get("track"), item.get("proposed_dest"))
    filename = item["filename"]
    if event == "skip":
        outcome = {"track": None, "dest": None, "matched": None}
    else:
        outcome_track = _track_for_dest(final_dest.parent)
        matched = outcome_track == prediction["track"]
        outcome = {"track": outcome_track, "dest": str(final_dest), "matched": matched}
        if not matched:
            _record_correction(store, prediction, outcome_track, filename)
    store.put(FEEDBACK, {
        "schema": "nest/v1", "event": event, "app_id": app_id,
        "filename": filename, "ext": Path(filename).suffix.lower(),
        "prediction": prediction, "outcome": outcome,
        "at": datetime.now(timezone.utc).isoformat(),
    })


# ── gate actions ─────────────────────────────────────────────────────────────

def confirm(store, item_id: str, override_dest: str | None = None,
            app_id: str = "") -> dict:
    """Move a staged file to its destination (or override_dest) and record the
    outcome. event is 'confirm' when the outcome matches the prediction, else
    'override' (which feeds the correction counter)."""
    item = store.get(QUEUE, item_id)
    if not item:
        return {"error": f"item {item_id} not found"}
    if item.get("status") != "pending":
        return {"error": f"item {item_id} already {item.get('status')}"}

    src = Path(item["src"])
    if not src.exists():
        item["status"] = "error"
        item["error"] = "source file missing"
        store.put(QUEUE, item, record_id=item_id)
        return {"error": f"source file missing: {src}"}

    dest = Path(override_dest).expanduser() if override_dest else (
        Path(item["proposed_dest"]) if item.get("proposed_dest") else None)
    if not dest:
        return {"error": "no destination — track unknown; pass override_dest"}

    dest.parent.mkdir(parents=True, exist_ok=True)
    final_dest = _unique_dest(dest.parent, dest.name)
    shutil.move(str(src), str(final_dest))
    # Credentials land operator-readable only — Nest is the drop path into
    # $WILLOW_HOME/secrets; mode must match what vault-first loaders expect.
    if _track_for_dest(final_dest.parent) == "secrets":
        try:
            final_dest.chmod(0o600)
        except OSError:
            pass

    outcome_track = _track_for_dest(final_dest.parent)
    predicted = (item.get("prediction") or {}).get("track", item.get("track"))
    event = "confirm" if outcome_track == predicted else "override"

    item.update(status="confirmed", event=event, outcome_track=outcome_track,
                final_dest=str(final_dest),
                confirmed_at=datetime.now(timezone.utc).isoformat())
    store.put(QUEUE, item, record_id=item_id)
    _write_feedback(store, item, event, final_dest, app_id)

    return {"status": "confirmed", "event": event, "item_id": item_id,
            "filename": item["filename"], "track": outcome_track,
            "predicted_track": predicted, "moved_to": str(final_dest)}


def skip(store, item_id: str, app_id: str = "") -> dict:
    item = store.get(QUEUE, item_id)
    if not item:
        return {"error": f"item {item_id} not found"}
    if item.get("status") != "pending":
        return {"error": f"item {item_id} already {item.get('status')}"}
    item.update(status="skipped",
                skipped_at=datetime.now(timezone.utc).isoformat())
    store.put(QUEUE, item, record_id=item_id)
    _write_feedback(store, item, "skip", None, app_id)
    return {"status": "skipped", "item_id": item_id, "filename": item["filename"]}
