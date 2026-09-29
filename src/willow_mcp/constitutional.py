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
``kind="syscall_row_amend"`` POINTS (via ``nestor_pair_id``) at a sealed
Nestor pair whose signature VERIFIES against this process's own keyring
(:func:`net_signer.verify_seal`, the same code path
:func:`reloader.find_sealing_decision` uses — Loki audit E79FCAE7 F5), and
whose sealed CONCLUSION carries exactly one ``syscall-row-amend:
id=<int> verb=<verb> from=<64-hex> to=<64-hex>`` line naming this exact
row id/verb and this module's own hash of the row's structural fields,
exactly. The authority is the SEALED TEXT ITSELF — never a SOIL side field
merely asserting an id/verb/hash, which is at most a pointer, checked for
internal consistency but never trusted as a substitute for the seal (Loki
audit 573273BD, F1: the prior build let any sealed pair plus any SOIL
record authorize any row change). See :func:`diff_changed_rows` (the
read-only preview an operator uses to prepare that record — it also emits
the exact line to seal), :func:`_find_amendment_candidates`, and
:func:`_confirm_amendment`. An unsealed modification, or a changed row
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

#: The exact line a sealed CONCLUSION must carry to authorize one row
#: change — parsed here, and emitted by :func:`diff_changed_rows` /
#: :func:`_amend_line` so an operator copies one string into the decision
#: they seal (build item 7). Coupled to :func:`_confirm_amendment`'s parse;
#: keep both in sync.
_AMEND_LINE_RE = re.compile(
    r"^syscall-row-amend:[ \t]*id=(\d+)[ \t]+verb=(\S+)[ \t]+from=([0-9a-fA-F]{64})[ \t]+to=([0-9a-fA-F]{64})[ \t]*\r?$",
    re.MULTILINE | re.ASCII,
)


def _amend_line(row_id: int, verb: str, from_sha256: str, to_sha256: str) -> str:
    """The one string a sealed conclusion must contain, verbatim, to
    authorize ``row_id``/``verb``'s change from ``from_sha256`` to
    ``to_sha256``. The single source of that format — :func:`_AMEND_LINE_RE`
    parses exactly what this emits."""
    return f"syscall-row-amend: id={row_id} verb={verb} from={from_sha256} to={to_sha256}"


def _ring_from_keyring(kr) -> dict[str, dict]:
    """The ``verify_seal`` ring shape (``{name: {key, kind, revoked_at,
    compromised}}``), built from the process's OWN keyring — the same shape
    :func:`reloader._ring_from_keyring` builds, duplicated here (a few
    lines) rather than imported, so this module carries no dependency on a
    file another packet owns."""
    return {
        e.name: {"key": e.key, "kind": e.kind, "revoked_at": e.revoked_at, "compromised": e.compromised}
        for e in kr.entries()
    }


def _canonical_json(obj) -> str:
    """Sorted keys, no whitespace, ``ensure_ascii=True`` (``json.dumps``'
    own default) — the one serialization every hash in this module is
    computed over, so a hash written into a governance decision by hand
    (or by a different process) still compares equal to the one this
    module computes, byte for byte. ``ensure_ascii=True`` is load-bearing,
    not incidental (Loki 573273BD F6): row 18 (``manifest.grant``) carries
    non-ASCII characters in its ``bounds`` description text, and hashing
    the SAME row structure with ``ensure_ascii=False`` produces a DIFFERENT
    sha256. An operator preparing a sealed amendment must copy the hash
    this function actually emits (via :func:`diff_changed_rows`) — never
    recompute it with a different ``json.dumps`` call, and never retype it
    by hand."""
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
    to amend, then ``decision_propose(conclusion=<amend_line>)`` on that
    ``kind=syscall_row_amend`` record — the sealed CONCLUSION itself
    must carry the exact ``amend_line`` this function emits (see
    :func:`_amend_line`), never just the record's own side fields —
    and the operator seals it there. Nothing in this function, or in that path up to the seal itself,
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
        from_sha256 = _row_hash(lv)
        to_sha256 = _row_hash(bv)
        rows.append({
            "id": vid,
            "verb": lv.get("verb"),
            "diff": field_diff,
            "from_sha256": from_sha256,
            "to_sha256": to_sha256,
            # Build item 7: the exact line to put in the sealed decision,
            # so the desk copies one string rather than assembling it by
            # hand from the fields above.
            "amend_line": _amend_line(vid, lv.get("verb"), from_sha256, to_sha256),
        })
    return {"ok": True, "rows": rows}


def _find_amendment_candidates(store: Store) -> list[dict]:
    """Every governance decision of :data:`AMENDMENT_KIND` — the kind
    filter is the ONLY thing that admits a record as a candidate here.
    ``id``/``verb``/``from_sha256``/``to_sha256`` side fields on a record
    are no longer trusted as authority (the sealed text pointed to by
    ``nestor_pair_id`` is), so pre-filtering candidates on them would let a
    stale or wrong-looking record hide a valid one behind it (Loki
    573273BD F4), or let a mutant that dropped the kind check pass
    unnoticed (F3). Every candidate returned here is checked by the
    multi-candidate loop in :func:`sync_syscall_table_from_bundle`;
    ``Store`` has no field index (same note as
    ``seal_handler._find_governance_record``), so this is a plain scan."""
    return [rec for rec in store.all(seal_handler.GOVERNANCE_COLLECTION)
            if rec.get("kind") == AMENDMENT_KIND]


def _confirm_amendment(rec: dict, *, live_row: dict, bundle_row: dict,
                        nestor_db_path: Optional[Path] = None) -> tuple[bool, str]:
    """Whether governance decision ``rec`` actually authorizes
    ``live_row -> bundle_row``. Every guard is checked and named on
    failure, in order:

    1. ``rec`` is kind :data:`AMENDMENT_KIND` (defense in depth — a caller
       gathering candidates via :func:`_find_amendment_candidates` already
       filtered on this) and carries a ``nestor_pair_id`` — the ONLY thing
       an amendment record contributes to its own authority.
    2. the named pair is confirmed sealed in Nestor's OWN ledger
       (:func:`net_authority.read_sealed_pair`) — ``rec["status"]`` and
       ``rec["nestor_verifier"]`` are never consulted; the SOIL record is a
       pointer, not the trust boundary (Loki 573273BD F1).
    3. the sealed bytes VERIFY against this process's own keyring
       (:func:`net_signer.verify_seal`, ``max_age_s=None`` — a governance
       decision does not go stale on a calendar, same as
       :func:`reloader.find_sealing_decision`). No keyring, an unknown
       verifier, or a bad signature all refuse here — the SAME code path
       Loki E79FCAE7 F5 put in ``reloader.py``, reused rather than
       re-implemented.
    4. the sealed CONCLUSION (``target_text``) carries EXACTLY ONE
       ``syscall-row-amend: id=<int> verb=<verb> from=<64hex> to=<64hex>``
       line (:data:`_AMEND_LINE_RE`) — zero lines means this pair
       authorizes no row change; two or more (even naming this row twice,
       or a second row) is refused outright, because one sealed pair
       authorizes exactly one row change, never a set (Loki 573273BD F1,
       probe P3).
    5. that one line's ``id``/``verb`` match ``live_row`` exactly, and its
       ``from``/``to`` match this module's OWN hash of
       ``live_row``/``bundle_row`` exactly — a line naming a different row,
       or different hashes, is refused BY NAME, never accepted as "close
       enough".
    6. ``rec``'s own ``id``/``verb``/``from_sha256``/``to_sha256`` fields,
       when present, agree with what the sealed text itself said — a SOIL
       record that disagrees with its own sealed pair is refused as a
       confusing artifact, even though the sealed text (not these fields)
       is what did the authorizing.

    Every guard through step 5 is checked ONLY from the sealed bytes and
    the keyring — never from ``rec``'s own side fields. That is the fix for
    Loki 573273BD F1: the prior build trusted ``rec["status"] == "sealed"``
    and ``rec["nestor_verifier"]`` as if they were the seal, so a record
    naming any existing sealed pair (or a hand-written row with
    ``seal_sig='x'``) authorized any row change.
    """
    row_id = live_row.get("id")
    verb = live_row.get("verb")

    if rec.get("kind") != AMENDMENT_KIND:
        return False, (
            f"row {row_id} ({verb}): governance decision {rec.get('_id')!r} is kind "
            f"{rec.get('kind')!r}, not {AMENDMENT_KIND!r} — refusing")

    pair_id = rec.get("nestor_pair_id")
    if not pair_id:
        return False, (
            f"row {row_id} ({verb}): governance decision {rec.get('_id')!r} carries no "
            f"nestor_pair_id — refusing")

    db_path = nestor_db_path if nestor_db_path is not None else seal_handler._nestor_db_path()
    pair = net_authority.read_sealed_pair(pair_id, db_path)
    if pair.get("state") != "populated":
        return False, (
            f"row {row_id} ({verb}): sealed pair {pair_id!r} is not confirmed sealed "
            f"in the Nestor ledger (state={pair.get('state')!r}: "
            f"{pair.get('why') or pair.get('cause') or 'unknown'})")

    from . import keyring as _keyring
    from . import net_signer

    try:
        ring_kr = _keyring.get_keyring()
    except _keyring.KeyringError as exc:
        return False, (
            f"row {row_id} ({verb}): WILLOW_KEYRING is configured but could not be "
            f"loaded: {exc} — refusing")
    if ring_kr is None:
        return False, (
            f"row {row_id} ({verb}): no keyring configured (WILLOW_KEYRING) — a seal "
            f"cannot be verified without a ring to verify it against — refusing")
    ring = _ring_from_keyring(ring_kr)

    sealed = {"source_norm": pair.get("source_norm"), "target_text": pair.get("target_text"),
              "verifier": pair.get("verifier"), "seal_sig": pair.get("seal_sig"),
              "created_at": pair.get("created_at")}
    ok, why, field = net_signer.verify_seal(sealed, ring, max_age_s=None)
    if not ok:
        return False, (
            f"row {row_id} ({verb}): sealed pair {pair_id!r} does not verify "
            f"({field}: {why}) — refusing")

    lines = _AMEND_LINE_RE.findall(pair.get("target_text") or "")
    if len(lines) != 1:
        return False, (
            f"row {row_id} ({verb}): sealed pair {pair_id!r}'s conclusion names "
            f"{len(lines)} syscall-row-amend line(s), not exactly one — one sealed "
            f"pair authorizes exactly one row change — refusing")

    amend_id_s, amend_verb, amend_from, amend_to = lines[0]
    amend_id = int(amend_id_s)
    amend_from = amend_from.lower()
    amend_to = amend_to.lower()

    if amend_id != row_id or amend_verb != verb:
        return False, (
            f"row {row_id} ({verb}): sealed pair {pair_id!r}'s syscall-row-amend line "
            f"names id={amend_id} verb={amend_verb!r}, not ({row_id!r}, {verb!r}) — "
            f"refusing")

    from_hash = _row_hash(live_row)
    if amend_from != from_hash:
        return False, (
            f"row {row_id} ({verb}): sealed pair {pair_id!r}'s syscall-row-amend line "
            f"names from={amend_from!r}, which does not match the live row's own hash "
            f"{from_hash!r} — refused by name")

    to_hash = _row_hash(bundle_row)
    if amend_to != to_hash:
        return False, (
            f"row {row_id} ({verb}): sealed pair {pair_id!r}'s syscall-row-amend line "
            f"names to={amend_to!r}, which does not match the bundle row's own hash "
            f"{to_hash!r} — refused by name")

    soil_id = rec.get("id")
    if soil_id is not None:
        if isinstance(soil_id, str) and soil_id.strip().lstrip("-").isdigit():
            soil_id = int(soil_id)
        if not isinstance(soil_id, int):
            return False, (
                f"row {row_id} ({verb}): governance decision {rec.get('_id')!r} carries "
                f"a non-integer id {rec.get('id')!r}, not comparable to the sealed "
                f"text's id={amend_id} — refusing")
        if soil_id != amend_id:
            return False, (
                f"row {row_id} ({verb}): governance decision {rec.get('_id')!r}'s own id "
                f"field ({soil_id!r}) disagrees with its own sealed text's id "
                f"({amend_id}) — refusing")
    if rec.get("verb") is not None and rec.get("verb") != amend_verb:
        return False, (
            f"row {row_id} ({verb}): governance decision {rec.get('_id')!r}'s own verb "
            f"field ({rec.get('verb')!r}) disagrees with its own sealed text's verb "
            f"({amend_verb!r}) — refusing")
    if rec.get("from_sha256") is not None and rec.get("from_sha256") != amend_from:
        return False, (
            f"row {row_id} ({verb}): governance decision {rec.get('_id')!r}'s own "
            f"from_sha256 field ({rec.get('from_sha256')!r}) disagrees with its own "
            f"sealed text's from hash ({amend_from!r}) — refusing")
    if rec.get("to_sha256") is not None and rec.get("to_sha256") != amend_to:
        return False, (
            f"row {row_id} ({verb}): governance decision {rec.get('_id')!r}'s own "
            f"to_sha256 field ({rec.get('to_sha256')!r}) disagrees with its own sealed "
            f"text's to hash ({amend_to!r}) — refusing")

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
    authorizes that exact row's change (see :func:`_find_amendment_candidates` /
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
        try:
            st = store if store is not None else Store()
            candidates = _find_amendment_candidates(st)
        except Exception as exc:  # noqa: BLE001 — a broken governance-decision
            # read must fail the sync CLOSED, same as any other refusal path
            # here: the live table stays untouched and the reason is inked
            # (Loki 573273BD F5 — an exception used to escape this function
            # entirely instead of becoming a named refusal).
            reason = (f"could not read governance decisions to check "
                      f"amendment(s) for row(s) {changed}: "
                      f"{type(exc).__name__}: {exc}")
            result = {"ok": False, "refused": True, "reason": reason}
            receipt = _ink_refusal(ledger, project, actor, reason=reason,
                                    live_path=live_path, bundle_path=bundle_path,
                                    live_rows=live_rows, bundle_rows=bundle_rows)
            if receipt:
                result.update(receipt)
            return result

        unauthorized: list[str] = []
        for vid in changed:
            live_row, bundle_row = live_rows[vid], bundle_rows[vid]
            verb = live_row.get("verb")
            row_reasons: list[str] = []
            confirmed_pair_id = None
            # Every candidate of AMENDMENT_KIND is checked — accept on the
            # first that verifies. A stale or planted record earlier in the
            # list must not shadow a valid one later (Loki 573273BD F4).
            for rec in candidates:
                try:
                    ok, why = _confirm_amendment(
                        rec, live_row=live_row, bundle_row=bundle_row,
                        nestor_db_path=nestor_db_path)
                except Exception as exc:  # noqa: BLE001 — one bad candidate
                    # record must not crash the sync, or block a later valid
                    # one; it is simply not an authorization (Loki 573273BD
                    # F5, the old AttributeError-at-:308 crash).
                    ok, why = False, (
                        f"row {vid} ({verb}): error checking governance "
                        f"decision {rec.get('_id')!r}: {type(exc).__name__}: {exc}")
                if ok:
                    confirmed_pair_id = rec.get("nestor_pair_id")
                    break
                row_reasons.append(why)
            if confirmed_pair_id is None:
                if row_reasons:
                    unauthorized.append("; ".join(row_reasons))
                else:
                    unauthorized.append(
                        f"row {vid} ({verb}): no sealed "
                        f"{AMENDMENT_KIND} governance decision found")
                continue
            amended.append({
                "id": vid, "verb": verb,
                "from_sha256": _row_hash(live_row), "to_sha256": _row_hash(bundle_row),
                "pair_id": confirmed_pair_id,
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
