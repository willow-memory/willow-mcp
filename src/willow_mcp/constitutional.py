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

Gap 82022def338f, ruling A (pair 3445116c): row 18 (``manifest.grant``)
changed only the description strings INSIDE ``bounds`` — still structural
by the rule above, so the additive-only sync above refused it and held
#662's row 25 (``package.upgrade``) hostage behind a row it never touches.
This module now also accepts a SEALED AMENDMENT: a changed row is applied,
not refused, when a ``projects_willow_governance_decisions`` record of
``kind="syscall_row_amend"`` names this exact row id/verb, is
``status="sealed"`` with a ``nestor_pair_id``/``nestor_verifier`` (the same
shape ``seal_handler.on_seal`` writes), independently confirms sealed in
Nestor's own ledger (:func:`net_authority.read_sealed_pair`), and names
``from_sha256``/``to_sha256`` matching this module's own hash of the row's
structural fields exactly. See :func:`diff_changed_rows` (the read-only
preview an operator uses to prepare that record), :func:`_find_amendment`,
and :func:`_confirm_amendment`. An unsealed modification, or a changed row
with no matching decision at all, is refused exactly as before — this is
additive, never a relaxation.

Reachability without a restart: this module has no standing process of its
own — it runs once, at willow-mcp's own startup (``server.py``'s boot
sequence calls :func:`sync_syscall_table_from_bundle` directly, before any
client can connect). There is no cheap way to re-run it on a live broker
without adding a new gated WRITE verb to this very table (a chicken-and-egg
this build does not take on): the next service-manager-driven restart of
the broker unit — an operator-issued ``unit.reload`` (row 15) via
``unit_reload_execute``, or the reloader's own tick (``reloader.run_once``,
which restarts the SAME unit onto a sealed git-pull/env-change receipt) —
is what picks up a sealed amendment or a new additive row. Until one of
those restarts happens, a sealed amendment sits ready but unapplied.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Optional

from . import net_authority, paths, seal_handler
from .db import Store

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


#: A sealed governance decision of this ``kind`` — in the same
#: ``projects_willow_governance_decisions`` SOIL collection ``seal_handler``
#: already upgrades to ``status="sealed"`` on a real Nestor seal — is the
#: ONLY thing that turns a structural row modification from a refusal into
#: an applied amendment. Gap 82022def338f, ruling A (pair 3445116c): row 18
#: (``manifest.grant``) changed only its ``bounds`` description strings, but
#: ``bounds`` is a structural field (:data:`_STRUCTURAL_FIELDS`), so the
#: additive-only sync refused it and held #662's row 25 hostage behind it.
AMENDMENT_KIND = "syscall_row_amend"


def _canonical_json(obj) -> str:
    """Sorted keys, no whitespace — the one serialization every hash in
    this module is computed over, so a hash written into a governance
    decision by hand (or by a different process) still compares equal to
    the one this module computes, byte for byte."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _row_hash(row: dict) -> str:
    """sha256 of the canonical JSON of ``row``'s STRUCTURAL fields only —
    the same narrowing :func:`_structural` uses for the additive-diff check,
    so a hash computed here always means exactly what the sync's own
    modification check means: two rows hash equal iff they'd compare equal
    there."""
    return hashlib.sha256(_canonical_json(_structural(row)).encode("utf-8")).hexdigest()


def diff_changed_rows(*, live_path: Optional[Path] = None,
                       bundle_path: Optional[Path] = None) -> dict:
    """Read-only preview of every row id the live table and the bundle both
    carry but disagree on, structurally — everything an operator needs to
    hand-write a sealed :data:`AMENDMENT_KIND` governance decision: the row
    id, its verb, a field-level diff (old/new per :data:`_STRUCTURAL_FIELDS`
    field that actually differs), and the ``from_sha256``/``to_sha256`` pair
    the sealed decision must name exactly. Never writes anything — not the
    live table, not a governance record, not FRANK ink.

    The desk's path from here: read this, ``store_put`` a
    ``projects_willow_governance_decisions`` record naming ``kind``,
    ``id``, ``verb``, ``from_sha256``, ``to_sha256`` for the row(s) it wants
    to amend, ``decision_propose`` it into Nestor, and the operator seals it
    there. Nothing in this function, or in that path up to the seal itself,
    seals anything.

    Returns ``{"ok": True, "rows": [...]}`` (``rows`` is ``[]`` when the
    tables agree on every shared id) or ``{"ok": False, "reason": ...}`` for
    the same unreadable/missing-table causes
    :func:`sync_syscall_table_from_bundle` itself reports as a refusal.
    """
    live_path = live_path or paths.syscall_table_path()
    bundle_path = bundle_path or _default_bundle_path()

    if not live_path.exists():
        return {"ok": True, "rows": [], "reason": "no live table yet"}
    if not bundle_path.exists():
        return {"ok": False, "reason": f"bundle table missing: {bundle_path}"}
    try:
        live = _load_live(live_path)
    except (OSError, PermissionError, ValueError) as exc:
        return {"ok": False,
                "reason": f"live_table_untrusted: could not read live table {live_path}: {exc}"}
    try:
        bundle = _load_bundle(bundle_path)
    except (OSError, ValueError) as exc:
        return {"ok": False, "reason": f"could not read bundle table: {exc}"}

    live_rows = _rows_by_id(live)
    bundle_rows = _rows_by_id(bundle)

    rows: list[dict] = []
    for vid in sorted(set(live_rows) & set(bundle_rows)):
        lv, bv = live_rows[vid], bundle_rows[vid]
        if _structural(lv) == _structural(bv):
            continue
        field_diff = {}
        for field in _STRUCTURAL_FIELDS:
            lval, bval = lv.get(field), bv.get(field)
            if lval != bval:
                field_diff[field] = {"from": lval, "to": bval}
        rows.append({
            "id": vid,
            "verb": lv.get("verb"),
            "diff": field_diff,
            "from_sha256": _row_hash(lv),
            "to_sha256": _row_hash(bv),
        })
    return {"ok": True, "rows": rows}


def _find_amendment(store: Store, row_id: int, verb: str) -> Optional[dict]:
    """The governance decision naming this row/verb as a
    :data:`AMENDMENT_KIND` amendment, sealed or not — the caller confirms
    sealedness. ``Store`` has no field index (same note as
    ``seal_handler._find_governance_record``), so this is a plain scan; the
    FIRST match wins, which is exactly right for the one row this build
    targets and is a known narrowing if a row ever needs a second,
    disambiguated amendment later."""
    for rec in store.all(seal_handler.GOVERNANCE_COLLECTION):
        if (rec.get("kind") == AMENDMENT_KIND
                and rec.get("id") == row_id
                and rec.get("verb") == verb):
            return rec
    return None


def _confirm_amendment(rec: dict, *, live_row: dict, bundle_row: dict,
                        nestor_db_path: Optional[Path] = None) -> tuple[bool, str]:
    """Whether governance decision ``rec`` actually authorizes
    ``live_row -> bundle_row``. Every guard is checked and named on
    failure, in order:

    1. the decision names this exact ``id``/``verb`` (defense in depth —
       :func:`_find_amendment` already filtered on these, but a caller
       reusing this on a hand-fetched record gets the same check);
    2. the decision is ``status == "sealed"`` with a ``nestor_pair_id`` and
       a ``nestor_verifier`` — the same shape ``seal_handler.on_seal``
       writes, so an unsealed (or never-seen-by-the-watcher) record is
       refused, never trusted on a bare SOIL field;
    3. the named pair independently confirms sealed in Nestor's OWN ledger
       (:func:`net_authority.read_sealed_pair`) — the SOIL record's
       ``status`` string is not the trust boundary by itself, the same
       discipline ``read_sealed_pair``'s own docstring states;
    4. ``from_sha256``/``to_sha256`` on the decision equal this module's own
       hash of the live/bundle row, exactly — a decision naming a different
       hash is refused BY NAME, never silently accepted as "close enough".
    """
    row_id = live_row.get("id")
    verb = live_row.get("verb")

    if rec.get("id") != row_id or rec.get("verb") != verb:
        return False, (
            f"row {row_id}: matching governance decision {rec.get('_id')!r} names "
            f"id={rec.get('id')!r} verb={rec.get('verb')!r}, not "
            f"({row_id!r}, {verb!r}) — refusing")

    if (rec.get("status") != "sealed" or not rec.get("nestor_pair_id")
            or not rec.get("nestor_verifier")):
        return False, (
            f"row {row_id} ({verb}): governance decision {rec.get('_id')!r} is not "
            f"sealed (status={rec.get('status')!r}) — refusing the amendment")

    pair_id = rec["nestor_pair_id"]
    db_path = nestor_db_path if nestor_db_path is not None else seal_handler._nestor_db_path()
    ledger_state = net_authority.read_sealed_pair(pair_id, db_path)
    if ledger_state.get("state") != "populated":
        return False, (
            f"row {row_id} ({verb}): sealed pair {pair_id!r} is not confirmed sealed "
            f"in the Nestor ledger (state={ledger_state.get('state')!r}: "
            f"{ledger_state.get('why') or ledger_state.get('cause') or 'unknown'})")

    from_hash = _row_hash(live_row)
    if rec.get("from_sha256") != from_hash:
        return False, (
            f"row {row_id} ({verb}): governance decision {rec.get('_id')!r} names "
            f"from_sha256={rec.get('from_sha256')!r}, which does not match the live "
            f"row's own hash {from_hash!r} — refused by name")

    to_hash = _row_hash(bundle_row)
    if rec.get("to_sha256") != to_hash:
        return False, (
            f"row {row_id} ({verb}): governance decision {rec.get('_id')!r} names "
            f"to_sha256={rec.get('to_sha256')!r}, which does not match the bundle "
            f"row's own hash {to_hash!r} — refused by name")

    return True, ""


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
    store: Optional[Store] = None,
    nestor_db_path: Optional[Path] = None,
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
    match) — UNLESS a sealed :data:`AMENDMENT_KIND` governance decision
    authorizes that exact row's change (see :func:`_find_amendment` /
    :func:`_confirm_amendment` and the module docstring). ``note`` and
    ``summary`` are excluded from the structural comparison — see
    :func:`_structural` — so a row whose prose was corrected in the same PR
    that adds an unrelated row does not block the add. Under either
    condition the live table is overwritten with the bundle's content
    (prose included) and a FRANK ``constitutional_sync`` event is appended
    naming the new verb ids, the seal id read off each new row's ``note``,
    and any applied amendments.

    Returns one of:

    * ``{"ok": True, "added": [], "reason": "..."}`` — nothing to do: no
      live table yet (home_init's own job), or the tables already agree.
    * ``{"ok": True, "added": [...], "verbs": [...], "seals": {...}, ...}``
      — synced. ``amended`` (a list of ``{id, verb, from_sha256,
      to_sha256, pair_id}``) is present only when at least one changed row
      was applied under a sealed amendment.
    * ``{"ok": False, "refused": True, "reason": "..."}`` — the live table
      is untouched: a live row is missing from the bundle, a row the
      bundle also carries has different content there with no (or no
      valid) sealed amendment, the live table fails ``trusted_read``
      (``reason`` starts with ``"live_table_untrusted"``), or either table
      is missing/unreadable. Every refusal shape here writes a FRANK
      ``constitutional_sync_refused`` event when a ledger is given, naming
      the reason and both paths — the one honest silence is the "tables
      already agree" no-op.

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

    # A changed row is still refused by default — UNLESS a sealed
    # AMENDMENT_KIND governance decision names exactly this row's id/verb
    # and the exact from/to structural hash (gap 82022def338f, ruling A).
    # Every changed row must clear this or the whole sync still refuses;
    # this is additive to the modification refusal, never a replacement
    # for it — an unsealed modification, or a row with no matching
    # decision at all, is refused exactly as before.
    amended: list[dict] = []
    if changed:
        st = store if store is not None else Store()
        unauthorized: list[str] = []
        for vid in changed:
            live_row, bundle_row = live_rows[vid], bundle_rows[vid]
            rec = _find_amendment(st, vid, live_row.get("verb"))
            if rec is None:
                unauthorized.append(
                    f"row {vid} ({live_row.get('verb')}): no sealed "
                    f"{AMENDMENT_KIND} governance decision found")
                continue
            ok, why = _confirm_amendment(
                rec, live_row=live_row, bundle_row=bundle_row,
                nestor_db_path=nestor_db_path)
            if not ok:
                unauthorized.append(why)
                continue
            amended.append({
                "id": vid, "verb": live_row.get("verb"),
                "from_sha256": rec["from_sha256"], "to_sha256": rec["to_sha256"],
                "pair_id": rec["nestor_pair_id"],
            })

        if unauthorized:
            reason = (f"bundle row(s) {changed} differ from the live table's "
                      f"existing content — a modification is not a merge, and "
                      f"not every changed row has a sealed amendment: "
                      + "; ".join(unauthorized))
            result = {"ok": False, "refused": True, "reason": reason}
            receipt = _ink_refusal(ledger, project, actor, reason=reason,
                                    live_path=live_path, bundle_path=bundle_path,
                                    live_rows=live_rows, bundle_rows=bundle_rows)
            if receipt:
                result.update(receipt)
            return result

    added = sorted(set(bundle_rows) - set(live_rows))
    if not added and not amended:
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
    if amended:
        result["amended"] = amended

    if ledger is not None:
        try:
            content = {
                "actor": actor, "added": added, "verbs": verb_names,
                "seals": seals, "path": str(live_path),
            }
            if amended:
                content["amended"] = amended
            record_id = ledger.append(project, "constitutional_sync", content)
            result["receipt_id"] = record_id
        except Exception as exc:  # noqa: BLE001 — the sync happened; the receipt failing is reported, not hidden
            result["receipt_error"] = f"{type(exc).__name__}: {exc}"

    return result
