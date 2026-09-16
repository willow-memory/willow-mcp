"""willow_mcp/constitutional.py — the seal-driven live-table sync.

``home_init.ensure_home_layout()`` seeds ``$WILLOW_HOME/constitutional/
syscall-table.json`` from the package's own bundled copy ONLY when the live
file is missing (``home_init._copy_bundle_file_if_missing``). That is right
for a fresh install and wrong for an upgrade: once a box already has a live
table, a verb the operator ratifies and merges into the shipped bundle table
(``bundle/constitutional/syscall-table.json``) never reaches the running
install's live table on its own — the merge lands in git, the box restarts
on the new code, and the syscall table the process actually reads at
startup is still the one ``willow-mcp-init`` wrote months ago. Verb 15
(``unit.reload``, sealed ``06075e99``) is exactly this case.

This module closes the gap for the one shape a ratified merge produces: the
bundle table gained one or more rows and changed none of the ones the live
table already had. That is applied — atomically, with FRANK ink naming what
changed and the seal that authorized it. Anything else (a modified or
missing existing row) is a refusal, never a merge: this is a sync of an
additive ratification, not a general reconciler, and a live table that has
diverged from the bundle any other way needs the operator's eyes, not code
guessing which side is right.
"""
from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Optional

from . import paths

#: The ``seal <id>`` convention row 15's own ``note`` field established —
#: read back here so a sync's FRANK event can name which governance
#: decision authorized each added verb without re-parsing prose by hand
#: anywhere else.
_SEAL_RE = re.compile(r"\bseal\s+([0-9a-fA-F][0-9a-fA-F-]{5,})")


def _default_bundle_path() -> Path:
    return paths.bundle_dir() / "constitutional" / "syscall-table.json"


def _load(path: Path) -> dict:
    paths.trusted_read(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path.name} must contain an object")
    return data


def _rows_by_id(table: dict) -> dict[int, dict]:
    return {
        row["id"]: row
        for row in table.get("verbs") or []
        if isinstance(row, dict) and isinstance(row.get("id"), int)
    }


def _extract_seal_id(note: str) -> str:
    m = _SEAL_RE.search(note or "")
    return m.group(1) if m else ""


def _atomic_write(path: Path, doc: dict) -> None:
    """Same discipline as ``envelope_authoring._atomic_write`` (gap
    ``6b4b7737c535``): write to a temp file beside the target, strip
    group/other-write bits off whatever the umask left (typically 0644),
    then ``os.replace`` — so ``paths.trusted_read`` never observes a
    half-written or over-permissive table, and a fresh write never
    re-triggers the guard it is meant to satisfy."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.chmod(tmp, stat.S_IMODE(os.stat(tmp).st_mode) & ~0o022)
    os.replace(tmp, path)


def sync_syscall_table_from_bundle(
    *,
    live_path: Optional[Path] = None,
    bundle_path: Optional[Path] = None,
    ledger=None,
    project: str = "fleet",
    actor: str = "willow-mcp",
) -> dict:
    """Apply an additive bundle-vs-live syscall table diff to the live table.

    Reads both tables through ``paths.trusted_read`` — the same trust
    contract every other governance-input read uses — and refuses without
    writing anything unless the bundle is a STRICT superset of the live
    table by row content: every id the live table carries must appear in
    the bundle with byte-identical fields (compared by id AND verb, so a
    row that reused an id under a different verb name is a modification,
    not a match). Under that condition the live table is overwritten with
    the bundle's content and a FRANK ``constitutional_sync`` event is
    appended naming the new verb ids and the seal id read off each new
    row's ``note``.

    Returns one of:

    * ``{"ok": True, "added": [], "reason": "..."}`` — nothing to do: no
      live table yet (home_init's own job), or the tables already agree.
    * ``{"ok": True, "added": [...], "verbs": [...], "seals": {...}, ...}``
      — synced.
    * ``{"ok": False, "refused": True, "reason": "..."}`` — the live table
      is untouched: a live row is missing from the bundle, or a row the
      bundle also carries has different content there.

    Never raises for a missing live table specifically — an install with
    none yet is exactly what ``home_init.ensure_home_layout()`` already
    handles by seeding the bundle wholesale, so this treats that case as
    "nothing to sync," not a refusal. A read that fails for any other
    reason (unreadable, untrusted, malformed) IS reported as a refusal:
    it is the same fail-closed posture ``envelopes._load`` takes on every
    other governance input.
    """
    live_path = live_path or paths.syscall_table_path()
    bundle_path = bundle_path or _default_bundle_path()

    if not live_path.exists():
        return {
            "ok": True, "added": [],
            "reason": "no live table yet — home_init seeds it from the "
                      "bundle on first install",
        }
    if not bundle_path.exists():
        return {"ok": False, "refused": True,
                "reason": f"bundle table missing: {bundle_path}"}

    try:
        live = _load(live_path)
        bundle = _load(bundle_path)
    except (OSError, PermissionError, ValueError) as exc:
        return {"ok": False, "refused": True,
                "reason": f"could not read tables: {exc}"}

    live_rows = _rows_by_id(live)
    bundle_rows = _rows_by_id(bundle)

    missing = sorted(set(live_rows) - set(bundle_rows))
    if missing:
        return {
            "ok": False, "refused": True,
            "reason": f"bundle is missing live row id(s) {missing} — not a "
                      f"strict superset, refusing to touch the live table",
        }

    changed = sorted(
        vid for vid in live_rows if live_rows[vid] != bundle_rows[vid]
    )
    if changed:
        return {
            "ok": False, "refused": True,
            "reason": f"bundle row(s) {changed} differ from the live table's "
                      f"existing content — a modification is not a merge; "
                      f"refusing to touch the live table",
        }

    added = sorted(set(bundle_rows) - set(live_rows))
    if not added:
        return {"ok": True, "added": [], "reason": "live table already matches the bundle"}

    _atomic_write(live_path, bundle)

    verb_names: list[str] = []
    seals: dict[int, str] = {}
    for vid in added:
        row = bundle_rows[vid]
        verb_names.append(row.get("verb", f"id-{vid}"))
        seal_id = _extract_seal_id(row.get("note", ""))
        if seal_id:
            seals[vid] = seal_id

    result: dict = {
        "ok": True, "added": added, "verbs": verb_names, "seals": seals,
        "path": str(live_path),
    }

    if ledger is not None:
        try:
            record_id = ledger.append(project, "constitutional_sync", {
                "actor": actor, "added": added, "verbs": verb_names,
                "seals": seals, "path": str(live_path),
            })
            result["receipt_id"] = record_id
        except Exception as exc:  # noqa: BLE001 — the sync happened; the receipt failing is reported, not hidden
            result["receipt_error"] = f"{type(exc).__name__}: {exc}"

    return result
