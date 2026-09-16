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

"Modified" is judged on a row's STRUCTURAL fields only — ``id``, ``verb``,
``bounds``, ``enforcement``, ``enforced_by``, ``min_ring`` — never ``note``
or ``summary`` (row 16, ``pr.update``, sealed ``783bab4e``). A row's prose
gets corrected in the same PR that adds an unrelated row surprisingly often
(row 15's own lineage note went from a ``PR <#>`` placeholder to ``PR #555``
in the very commit that appended row 16), and a sync that refused on that
diff would hold a real additive ratification hostage to a footnote. A
rewritten bound, ring, or enforcement wall is still a modification and still
refuses — narrative text is the only thing exempted.
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


def _load_bundle(path: Path) -> dict:
    """Read the shipped bundle table plainly.

    The bundle is package code — tracked, reviewed, merged; its trust is git
    history, not filesystem ownership bits. On an editable install the
    checkout can legitimately be group-writable (umask-002 era trees), and on
    a pip install it sits in site-packages where ``trusted_read`` would pass
    by accident, not by design. Running the same strict check on it here was
    the bug: it made this sync refuse on the very artifact it exists to
    apply.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path.name} must contain an object")
    return data


def _load_live(path: Path) -> dict:
    """Read the live table — the file this function writes and the enforcer
    reads. This one stays behind ``paths.trusted_read``: it is a governance
    input an operator (or nothing else) may replace."""
    paths.trusted_read(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path.name} must contain an object")
    return data


def _row_count(rows: Optional[dict[int, dict]]) -> Optional[int]:
    return None if rows is None else len(rows)


def _ink_refusal(
    ledger,
    project: str,
    actor: str,
    *,
    reason: str,
    live_path: Path,
    bundle_path: Path,
    live_rows: Optional[dict[int, dict]] = None,
    bundle_rows: Optional[dict[int, dict]] = None,
) -> Optional[dict]:
    """Every refusal writes FRANK ink when a ledger is given — the operator
    should never again find out about a refused sync by counting rows.
    Returns the receipt fields to fold into the response, or ``None`` when no
    ledger was passed."""
    if ledger is None:
        return None
    content = {
        "actor": actor,
        "reason": reason,
        "live_path": str(live_path),
        "bundle_path": str(bundle_path),
        "live_rows": _row_count(live_rows),
        "bundle_rows": _row_count(bundle_rows),
    }
    try:
        record_id = ledger.append(project, "constitutional_sync_refused", content)
        return {"receipt_id": record_id}
    except Exception as exc:  # noqa: BLE001 — the refusal happened; the receipt failing is reported, not hidden
        return {"receipt_error": f"{type(exc).__name__}: {exc}"}


def _rows_by_id(table: dict) -> dict[int, dict]:
    return {
        row["id"]: row
        for row in table.get("verbs") or []
        if isinstance(row, dict) and isinstance(row.get("id"), int)
    }


#: Fields that decide whether a row was "modified" for the additive-diff
#: check. ``note`` and ``summary`` are narrative — they name a gap, a seal, a
#: PR number, or reword a description — and none of that changes what the
#: row actually grants. Row 16 (``pr.update``, sealed ``783bab4e``): a note
#: fixed up in the same PR that adds a new row must not block the add.
_STRUCTURAL_FIELDS = ("id", "verb", "bounds", "enforcement", "enforced_by", "min_ring")


def _structural(row: dict) -> dict:
    """``row``, narrowed to the fields an additive sync treats as identity —
    everything except ``note``/``summary``. Two rows that differ only in
    prose compare equal here."""
    return {k: row.get(k) for k in _STRUCTURAL_FIELDS}


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

    The live table is read through ``paths.trusted_read`` — the same trust
    contract every other governance-input read uses, since it is the file
    this function writes and the enforcer reads. The bundle table is read
    plainly: it is package code (tracked, reviewed, merged), and its trust
    is git history, not filesystem ownership bits — an editable install's
    group-writable checkout must not make this sync refuse the very
    artifact it exists to apply. The sync refuses without writing anything
    unless the bundle is a STRICT superset of the live table by row
    STRUCTURE: every id the live table carries must appear in the bundle
    with identical ``id``/``verb``/``bounds``/``enforcement``/
    ``enforced_by``/``min_ring`` (compared by id AND verb, so a row that
    reused an id under a different verb name is a modification, not a
    match). ``note`` and ``summary`` are excluded from that comparison —
    see :func:`_structural` — so a row whose prose was corrected in the same
    PR that adds an unrelated row does not block the add. Under that
    condition the live table is overwritten with the bundle's content
    (prose included) and a FRANK ``constitutional_sync`` event is appended
    naming the new verb ids and the seal id read off each new row's
    ``note``.

    Returns one of:

    * ``{"ok": True, "added": [], "reason": "..."}`` — nothing to do: no
      live table yet (home_init's own job), or the tables already agree.
    * ``{"ok": True, "added": [...], "verbs": [...], "seals": {...}, ...}``
      — synced.
    * ``{"ok": False, "refused": True, "reason": "..."}`` — the live table
      is untouched: a live row is missing from the bundle, a row the
      bundle also carries has different content there, the live table
      fails ``trusted_read`` (``reason`` starts with
      ``"live_table_untrusted"``), or either table is missing/unreadable.
      Every refusal shape here writes a FRANK ``constitutional_sync_refused``
      event when a ledger is given, naming the reason and both paths — the
      one honest silence is the "tables already agree" no-op.

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
        reason = f"bundle table missing: {bundle_path}"
        result = {"ok": False, "refused": True, "reason": reason}
        receipt = _ink_refusal(ledger, project, actor, reason=reason,
                                live_path=live_path, bundle_path=bundle_path)
        if receipt:
            result.update(receipt)
        return result

    try:
        live = _load_live(live_path)
    except (OSError, PermissionError, ValueError) as exc:
        reason = f"live_table_untrusted: could not read live table {live_path}: {exc}"
        result = {"ok": False, "refused": True, "reason": reason}
        receipt = _ink_refusal(ledger, project, actor, reason=reason,
                                live_path=live_path, bundle_path=bundle_path)
        if receipt:
            result.update(receipt)
        return result

    try:
        bundle = _load_bundle(bundle_path)
    except (OSError, ValueError) as exc:
        reason = f"could not read bundle table: {exc}"
        result = {"ok": False, "refused": True, "reason": reason}
        receipt = _ink_refusal(ledger, project, actor, reason=reason,
                                live_path=live_path, bundle_path=bundle_path,
                                live_rows=_rows_by_id(live))
        if receipt:
            result.update(receipt)
        return result

    live_rows = _rows_by_id(live)
    bundle_rows = _rows_by_id(bundle)

    missing = sorted(set(live_rows) - set(bundle_rows))
    if missing:
        reason = (f"bundle is missing live row id(s) {missing} — not a "
                  f"strict superset, refusing to touch the live table")
        result = {"ok": False, "refused": True, "reason": reason}
        receipt = _ink_refusal(ledger, project, actor, reason=reason,
                                live_path=live_path, bundle_path=bundle_path,
                                live_rows=live_rows, bundle_rows=bundle_rows)
        if receipt:
            result.update(receipt)
        return result

    changed = sorted(
        vid for vid in live_rows
        if _structural(live_rows[vid]) != _structural(bundle_rows[vid])
    )
    if changed:
        reason = (f"bundle row(s) {changed} differ from the live table's "
                  f"existing content — a modification is not a merge; "
                  f"refusing to touch the live table")
        result = {"ok": False, "refused": True, "reason": reason}
        receipt = _ink_refusal(ledger, project, actor, reason=reason,
                                live_path=live_path, bundle_path=bundle_path,
                                live_rows=live_rows, bundle_rows=bundle_rows)
        if receipt:
            result.update(receipt)
        return result

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
