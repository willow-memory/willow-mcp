"""willow_mcp/schema_profile.py — introspect a host table, map it to canonical
fields, and persist the result as a reviewable artifact.

Implements docs/design/schema-adaptation.md §3.1-§3.4: introspection +
heuristic mapping for the read path (§9 step 2), and confirm() for the
write-path gate (§9 step 3) — a table's mapping must be explicitly
confirmed (optionally with human-supplied column overrides) before any
write tool may use it.

Design principles this module exists to satisfy (see doc §2):
  1. Discover, don't assume — introspect() is the only source of column
     truth; no caller may embed a column name that wasn't confirmed present.
  2. Map to canonical concepts, with visible confidence — every mapped field
     carries a tier (exact / alias / unmapped); never hidden from the caller.
  4. The mapping is an artifact, not a black box — persisted as plain JSON,
     diffable and editable, confirmed mappings win over fresh heuristics.
  5. Every inference is logged implicitly by being written to that artifact
     with a discovered_at timestamp; a dedicated audit log is future work
     (§5, not this pass).
"""
import difflib
import hashlib
import json
import os
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import paths

SCHEMA_VERSION = 1

# Hint tuning (docs/design/schema-adaptation.md §3.2 extension). A data-shape
# HINT for an unmapped field fires only when the candidate column's shape is
# DISCRIMINATING (shared by at most this many columns) AND its name has affinity
# to the field — the 2004-archive test showed that on a freetext-heavy table an
# unguarded "first well-shaped column" hint is confidently wrong (it matched a
# `lang` noise column and reused the accession key for two fields). Silence beats
# a wrong guess. The trap-FLAG (a mapped column whose data is the wrong shape) is
# NOT gated by name affinity — that's how the tasks `cmd_line` rescue works.
_HINT_SHARED_SHAPE_MAX = 2
_HINT_NAME_AFFINITY_MIN = 0.55

# Static-but-extensible alias dictionary (§7 open question, resolved as
# "static built-in list" for the first pass — a per-deployment override file
# is cheap to add later if a host schema needs a name this list doesn't
# anticipate). Ordering matters: propose_mapping takes the FIRST present alias,
# so more-specific legacy names are listed before generic fallbacks (e.g. a
# tasks table's business key `jobno`/`jobid` outranks a bare surrogate `id`).
CANONICAL_ALIASES: dict[str, tuple[str, ...]] = {
    # ── knowledge fields ──
    "source": ("source_type", "origin", "origin_ref"),
    "content": ("content", "body", "text"),
    "tags": ("tags", "labels"),
    # ── task-queue fields — 2000s-era job-scheduler house style ──
    "task_id": ("jobno", "job_no", "jobid", "job_id", "reqid", "req_id", "ticket", "id"),
    "task": ("cmd_line", "cmdline", "command", "cmd", "cmd_text", "script", "action", "payload"),
    "submitted_by": ("submitter", "requestor", "requester", "created_by", "owner",
                     "username", "usr", "user", "author"),
    "network_authorization": (
        "net_authorization",
        "egress_authorization",
        "network_envelope",
        "egress_envelope",
    ),
    "agent": ("worker", "executor", "runner", "processor", "handler"),
    "lane": ("queue_lane", "worker_lane", "priority_lane"),
    "status": ("stat", "state", "job_state", "proc_state", "status_code", "st"),
    "result": ("output", "outblob", "result_text", "response", "stdout", "res", "log"),
    "steps": ("nsteps", "num_steps", "step_count", "step_cnt"),
    "created_at": ("created", "crt_dt", "created_ts", "ins_ts", "insert_ts",
                   "date_created", "queued_at", "submit_time", "ctime"),
    "completed_at": ("fin_dt", "finished_at", "completed", "done_at", "end_time",
                     "finish_time", "mtime"),
    "claim_owner": ("claimed_by", "worker_id", "lock_owner"),
    "claimed_at": ("claim_time", "locked_at", "started_at"),
    "attempts": ("attempt_count", "tries", "retry_count"),
    "max_attempts": ("max_tries", "retry_limit"),
    "retry_at": ("next_attempt_at", "retry_after"),
}

# Column data types that must be cast to text before use in an ILIKE
# predicate — jsonb/json columns don't support the ~~ operator directly.
_TEXT_CAST_TYPES = frozenset({"jsonb", "json"})

_COLLECTION_SAFE_RE = re.compile(r"^[A-Za-z0-9_\-]{1,128}$")


@dataclass(frozen=True)
class ColumnInfo:
    name: str
    data_type: str


def introspect(conn, table: str) -> list[ColumnInfo]:
    """Query information_schema for a table's real columns. Empty list means
    the table doesn't exist (or is empty of columns, which is equivalent for
    our purposes) — callers must treat that as table_not_found, not as
    "every field unmapped."."""
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT column_name, data_type FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = %s "
            "ORDER BY ordinal_position",
            (table,),
        )
        rows = cur.fetchall()
    finally:
        cur.close()
    return [ColumnInfo(name=r[0], data_type=r[1]) for r in rows]


# ── the rings: deployment-wide learned mappings (schema-adaptation.md §7) ────
# Dendrochronology, basically. The 2004-archive test proved static heuristics
# don't transfer across schemas: `subj`->domain, `provenance`->source, `kw`->tags
# have no name or shape tell — the only thing that ever finds them is "someone in
# this deployment confirmed that column->field once." confirm() is a labeled
# example; each one grows a RING. The tree of accumulated rings is keyed by column
# name, deployment-wide, so the next unfamiliar table maps itself from what the
# tree already knows. Rings feed PROPOSALS at high-but-sub-exact confidence (tier
# `rooted`) — a rooted mapping is still witnessed at confirm time, never auto-
# applied (principle 3: writes may not guess; a remembered decision is not an
# unattended one).
#
# The canopy is BOUNDED: an open column-name vocabulary would grow it without
# limit (a churny deployment keeps inventing names), so past the cap we PRUNE by
# LFU with an LRU tie-break — thinnest rings first (least-confirmed), oldest-
# among-ties next — keeping the load-bearing heartwood and letting stale one-off
# names from felled schemas rot away. A logical `tick` (not wall-clock:
# deterministic, restart-stable) dates each ring. Over-pruning only costs a re-
# learn (one cold miss), so the canopy cap is generous by default, env-overridable.
_CANOPY_CAP_DEFAULT = 5000


def _rings_path() -> Path:
    env = os.environ.get("WILLOW_MCP_SCHEMA_RINGS")
    if env:
        return Path(env)
    home = Path(os.environ.get("WILLOW_HOME", Path.home() / ".willow"))
    return home / "schema_rings.json"


def _canopy_cap() -> int:
    try:
        return max(1, int(os.environ.get("WILLOW_MCP_SCHEMA_RINGS_MAX", _CANOPY_CAP_DEFAULT)))
    except ValueError:
        return _CANOPY_CAP_DEFAULT


def _core_sample() -> dict:
    """Drill a core and read the full rings: {"tick": int, "columns": {col:
    {field: {"n","t"}}}}. Normalizes the legacy int shape ({col: {field: count}})
    on read, so an old tree keeps growing and upgrades on the next ring. A
    missing/unreadable tree is a sapling (empty) — rings are an optimization,
    never load-bearing."""
    path = _rings_path()
    empty = {"tick": 0, "columns": {}}
    if not path.exists():
        return empty
    try:
        data = json.loads(path.read_text())
    except Exception:
        return empty
    if not isinstance(data, dict):
        return empty
    raw_cols = data.get("columns", {})
    cols: dict = {}
    for col, fields in (raw_cols.items() if isinstance(raw_cols, dict) else ()):
        norm: dict = {}
        for field, val in (fields.items() if isinstance(fields, dict) else ()):
            if isinstance(val, int):
                norm[field] = {"n": val, "t": 0}
            elif isinstance(val, dict):
                norm[field] = {"n": int(val.get("n", 0)), "t": int(val.get("t", 0))}
        if norm:
            cols[col] = norm
    return {"tick": int(data.get("tick", 0)), "columns": cols}


def read_rings() -> dict:
    """Public view of the tree: {column_name: {field: count}} (ints, dates
    dropped) — the stable contract propose_mapping and callers read."""
    return {col: {f: e["n"] for f, e in fields.items()}
            for col, fields in _core_sample()["columns"].items()}


def girth() -> dict:
    """How big the tree has grown — {columns, pairs, cap, tick}. For diagnostics
    and for asserting the canopy bound holds."""
    core = _core_sample()
    pairs = sum(len(v) for v in core["columns"].values())
    return {"columns": len(core["columns"]), "pairs": pairs,
            "cap": _canopy_cap(), "tick": core["tick"]}


def _prune(cols: dict, cap: int) -> int:
    """Thin the canopy: cut lowest-value (column,field) rings until size <= 90%
    of cap (the 10% hysteresis avoids pruning on every ring near the boundary).
    Cut order: thinnest rings first (fewest confirmations), then oldest. Returns
    the count cut. Mutates `cols` in place, felling any column left ringless."""
    pairs = [(e["n"], e["t"], col, field)
             for col, fields in cols.items() for field, e in fields.items()]
    if len(pairs) <= cap:
        return 0
    target = max(1, int(cap * 0.9))
    pairs.sort()  # ascending by (n, t): thinnest ring, then oldest, first to fall
    cut = 0
    for _n, _t, col, field in pairs[: len(pairs) - target]:
        del cols[col][field]
        if not cols[col]:
            del cols[col]
        cut += 1
    return cut


def grow_ring(fields: dict) -> None:
    """Grow a ring from a CONFIRMED record — persist its non-trivial (column !=
    field) mappings, thickening a per-(column,field) count and dating it. Trivial
    exact self-matches (column name == canonical field) teach nothing and are
    skipped — so confirming the naive `task`->`task` trap grows no ring, only a
    human override to `cmd_line` does. Prunes the canopy after growing so the tree
    stays bounded in an open vocabulary."""
    core = _core_sample()
    cols = core["columns"]
    tick = core["tick"] + 1
    changed = False
    for field, m in fields.items():
        col = m.get("column")
        if not col or col == field:
            continue
        bucket = cols.setdefault(col, {})
        prev = bucket.get(field) or {"n": 0}
        bucket[field] = {"n": prev.get("n", 0) + 1, "t": tick}
        changed = True
    if not changed:
        return
    _prune(cols, _canopy_cap())
    path = _rings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_json_atomic(path, {"format": "growth_rings_v1", "tick": tick, "columns": cols})


def _deepest_root(rings: dict, field: str, by_name: dict, taken: set) -> Optional[str]:
    """The present, not-yet-taken column whose ring for `field` is thickest in
    this deployment, or None. Deterministic: thickest ring wins, column name
    breaks ties."""
    candidates = [
        (counts.get(field, 0), col)
        for col, counts in rings.items()
        if col in by_name and col not in taken and counts.get(field, 0) > 0
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda t: (-t[0], t[1]))
    return candidates[0][1]


def propose_mapping(columns: list[ColumnInfo], canonical_fields: list[str],
                    rings: Optional[dict] = None) -> dict:
    """Heuristic pass: exact name -> rooted (deployment rings) -> known alias ->
    unmapped.

    Returns {field: {"column": str|None, "tier": "exact"|"rooted"|"alias"|
    "unmapped", "confidence": float, "data_type": str|None}}. Pure function of
    its arguments — with `rings=None` (the default) the rooted tier is skipped
    and the result is identical to the original name+alias behaviour, so callers
    that want determinism without deployment state just omit it."""
    by_name = {c.name: c for c in columns}
    rings = rings or {}
    taken: set = set()
    mapping: dict = {}
    for field in canonical_fields:
        if field in by_name:
            col = by_name[field]
            taken.add(col.name)
            mapping[field] = {
                "column": col.name, "tier": "exact",
                "confidence": 1.0, "data_type": col.data_type,
            }
            continue
        rooted = _deepest_root(rings, field, by_name, taken) if rings else None
        if rooted is not None:
            taken.add(rooted)
            mapping[field] = {
                "column": rooted, "tier": "rooted",
                "confidence": 0.95, "data_type": by_name[rooted].data_type,
            }
            continue
        found = None
        for alias in CANONICAL_ALIASES.get(field, ()):
            if alias in by_name and alias not in taken:
                found = by_name[alias]
                break
        if found is not None:
            taken.add(found.name)
            mapping[field] = {
                "column": found.name, "tier": "alias",
                "confidence": 0.9, "data_type": found.data_type,
            }
        else:
            mapping[field] = {
                "column": None, "tier": "unmapped",
                "confidence": 0.0, "data_type": None,
            }
    return mapping


# ── data-shape layer (docs/design/schema-adaptation.md §3.2 extension) ──────
# Name matching alone cannot catch the worst trap: a column that name-matches a
# canonical field but holds the WRONG KIND of data (a `task` column full of job
# CLASSES, not commands). The name-based tiers above always pick an exact name
# match, so an alias can never rescue that case. This layer reads a small sample
# of real values, classifies each column's SHAPE, and — purely advisorily —
# flags mismatches and suggests better-shaped columns. It never mutates the
# mapping or auto-confirms: it makes the proposal louder, the human still
# decides (principle 2: visible confidence; principle 3: writes may not guess).

_INTERPRETERS = frozenset({
    "sh", "bash", "zsh", "ksh", "perl", "python", "python2", "python3", "ruby",
    "php", "node", "java", "awk", "sed", "pwsh", "powershell", "cmd",
})
_SCRIPT_EXT_RE = re.compile(r"\.(pl|sh|py|rb|php|js|exe|bat|ps1|cmd)\b", re.I)
_PATH_FLAG_RE = re.compile(r"/\S+.*\s-{1,2}\w")
_IDENTIFIER_RE = re.compile(r"[A-Za-z]{0,10}[-_]?\d{1,12}$")

# Shapes each canonical field is expected to carry. A column whose sampled shape
# is outside this set (and non-empty) is a mismatch worth flagging.
_EXPECTED_SHAPES: dict[str, frozenset] = {
    "task": frozenset({"command", "freetext", "prose"}),
    "task_id": frozenset({"identifier", "integer"}),
    "status": frozenset({"flag", "enum"}),
    "steps": frozenset({"integer"}),
    "created_at": frozenset({"timestamp"}),
    "completed_at": frozenset({"timestamp"}),
    "agent": frozenset({"enum", "identifier"}),
    "lane": frozenset({"enum", "identifier"}),
    "submitted_by": frozenset({"identifier", "enum", "freetext", "prose"}),
    "network_authorization": frozenset({"freetext", "prose"}),
    "result": frozenset({"freetext", "command", "prose", "reference"}),
    "claim_owner": frozenset({"identifier", "enum", "freetext", "reference"}),
    "claimed_at": frozenset({"timestamp"}),
    "attempts": frozenset({"integer"}),
    "max_attempts": frozenset({"integer"}),
    "retry_at": frozenset({"timestamp"}),
    # knowledge side. `content` is the one field that expects prose but NOT
    # reference — a content column full of citations is the trap, so it flags.
    # Everyone else accepts reference too (permissive), so splitting freetext
    # never creates a NEW false mismatch for them.
    "content": frozenset({"prose", "freetext", "command"}),
    "domain": frozenset({"enum", "identifier"}),
    "source": frozenset({"enum", "identifier", "freetext", "prose", "reference"}),
    "tags": frozenset({"enum", "freetext", "prose"}),
}


def _looks_command(s: str) -> bool:
    s = s.strip()
    if not s:
        return False
    if s[0] in "/.~":
        return True
    head = s.split()[0]
    if head.rsplit("/", 1)[-1] in _INTERPRETERS:
        return True
    if _SCRIPT_EXT_RE.search(s):
        return True
    return bool(_PATH_FLAG_RE.search(s))


# Citation-vs-prose signals — the last trap the earlier passes couldn't see: a
# `content` column holding a bibliographic CITATION (short, structured) while the
# real body prose lives in `abstract`. Both were generic `freetext`, so no
# mismatch fired. These split freetext into `reference` and `prose` when
# confident (else stay `freetext`), which lets `content` expect prose-not-
# reference and finally flag the citation trap.
_YEAR_PAREN = re.compile(r"\(\s*(1[89]\d\d|20\d\d)[a-z]?\s*\)")     # (2001), (1948)
_PAGE_RANGE = re.compile(r"\b\d+\s*[-:]\s*\d+\b")                    # 379-423, 27:379
_VOL_ISSUE = re.compile(r"\b\d+\(\d+\)")                             # 11(3), 13(6)
_CITE_TOKENS = re.compile(
    r"(\bpp?\.|\bvol\.?|\bno\.|\beds?\.|\bet al\.?|\bproc\.|\bOCLC|\bDOI|\bISBN|\bLoC\b|\bCACM\b|\bibid\b)",
    re.I,
)
_FUNC_WORDS = frozenset({
    "the", "of", "and", "that", "with", "for", "to", "a", "in", "is", "as",
    "an", "on", "by", "are", "which", "from", "this", "its", "into",
})


def _looks_reference(s: str) -> bool:
    """Short, structured bibliographic text — two-plus citation tells and not
    long enough to be a body paragraph."""
    if len(s) > 220:
        return False
    hits = sum(bool(rx.search(s)) for rx in (_YEAR_PAREN, _PAGE_RANGE, _VOL_ISSUE, _CITE_TOKENS))
    return hits >= 2


def _looks_prose(s: str) -> bool:
    """Substantial running prose — long, many words, function-word rich, and not
    digit-dense (which would signal a reference/record rather than a paragraph)."""
    if len(s) < 120:
        return False
    toks = re.findall(r"[a-z]+", s.lower())
    if len(toks) < 18:
        return False
    func = sum(1 for t in toks if t in _FUNC_WORDS)
    digit_ratio = sum(c.isdigit() for c in s) / len(s)
    return func >= 3 and digit_ratio < 0.05


def classify_shape(values: list, data_type: Optional[str] = None) -> str:
    """Classify a column's data shape from a sample of its values. One of:
    empty | timestamp | integer | flag | command | enum | identifier | freetext.
    Pure function of its inputs. Type hints win for timestamps/ints; everything
    else is inferred from the string form of the values."""
    dt = (data_type or "").lower()
    if "timestamp" in dt or dt == "date":
        return "timestamp"
    vals = [v for v in values if v is not None]
    if not vals:
        return "empty"
    if dt in ("integer", "bigint", "smallint") or all(
        isinstance(v, int) and not isinstance(v, bool) for v in vals
    ):
        return "integer"
    strs = [str(v).strip() for v in vals if str(v).strip() != ""]
    if not strs:
        return "empty"
    n = len(strs)
    distinct = set(strs)
    if all(len(s) == 1 for s in strs):
        return "flag"
    if sum(1 for s in strs if _looks_command(s)) >= max(1, (n + 1) // 2):
        return "command"
    # identifier before enum: a code like JOB0041 is more specific than a small
    # label set, and low-cardinality samples would otherwise read as enum.
    if all(_IDENTIFIER_RE.match(s) for s in strs):
        return "identifier"
    if len(distinct) <= max(2, n // 2) and all(len(s) <= 16 and " " not in s for s in strs):
        return "enum"
    # freetext, refined into reference/prose only on a clear majority — an
    # ambiguous column stays plain freetext rather than being mislabeled.
    half = max(1, (n + 1) // 2)
    if sum(1 for s in strs if _looks_reference(s)) >= half:
        return "reference"
    if sum(1 for s in strs if _looks_prose(s)) >= half:
        return "prose"
    return "freetext"


def _name_affinity(column: str, field: str) -> float:
    """How name-similar is a column to a canonical field (or any of its static
    aliases)? Max SequenceMatcher ratio over {field} ∪ aliases(field), with a
    substring containment treated as a strong match. Used only to gate HINTS —
    a low-affinity column may still be flagged as a trap replacement, but won't
    be *proposed* for an unmapped field on shape alone."""
    col = column.lower()
    targets = (field.lower(),) + tuple(a.lower() for a in CANONICAL_ALIASES.get(field, ()))
    best = 0.0
    for t in targets:
        if col == t or col in t or t in col:
            return 1.0
        best = max(best, difflib.SequenceMatcher(None, col, t).ratio())
    return best


def _sample_columns(conn, table: str, columns: list, limit: int = 8) -> dict:
    """Return {column_name: [sampled values]} for every column, or {} on error.
    A diagnostic aid — degrades to {} rather than raising."""
    _validate_table(table)
    names = [c.name for c in columns]
    if not names:
        return {}
    limit = max(1, min(int(limit), 25))
    col_sql = ", ".join(f'"{c}"' for c in names)
    cur = conn.cursor()
    try:
        cur.execute(f'SELECT {col_sql} FROM "{table}" LIMIT %s', (limit,))  # nosec B608 - table passed _validate_table()'s [A-Za-z0-9_-]{1,128} allowlist above; col_sql is built from introspected column names, not raw text; limit is a bound param
        rows = cur.fetchall()
    except Exception:  # noqa: BLE001 — advisory sampler must not crash a review
        return {}
    finally:
        cur.close()
    out: dict = {name: [] for name in names}
    for row in rows:
        for name, val in zip(names, row):
            out[name].append(val)
    return out


def promote_rings_over_lying_names(fields: dict, shapes: dict, rings: dict,
                                   by_name: dict, canonical_fields: list[str]) -> list[dict]:
    """Let a learned ring outrank an exact name match the data contradicts.

    `propose_mapping` decides `exact -> rooted -> alias`, and the exact tier
    `continue`s, so a column that merely *shares the field's name* is chosen
    before any ring is consulted. That short-circuit is right almost always and
    catastrophic in exactly one case: the case that grows rings at all.

    A ring only exists because a human once overrode a name match on that
    column pair — `grow_ring` skips trivial `column == field` matches precisely
    because they teach nothing. So the only rings held are corrections, and the
    only situation they could correct is a lying name, which is the situation
    the exact tier discards. Measured 2026-08-28: confirming the `knowledge`
    mapping with `content -> summary` grew that ring, and re-profiling still
    proposed `content -> content`, because a column named `content` exists. The
    correction could never be applied to the case that produced it.

    **Gated on shape, not merely on a ring existing.** The ring store is keyed
    on column names globally rather than per table, so an unconditional
    promotion would let `summary -> content`, learned from one table, hijack a
    correct `content -> content` on any other table carrying both columns —
    a worse defect than the one being fixed. Promotion therefore requires the
    exact column's sampled shape to fall OUTSIDE the field's expected set: the
    name match must be demonstrably wrong here, not merely overridden once
    somewhere else.

    Mutates `fields` in place and returns one record per promotion, for the
    caller to surface. Silent promotion would be its own defect — this changes
    which column a write lands in.
    """
    promotions: list[dict] = []
    if not rings or not shapes:
        return promotions
    taken = {v.get("column") for v in fields.values() if v.get("column")}
    for field in canonical_fields:
        current = fields.get(field, {})
        col = current.get("column")
        if not col or current.get("tier") != "exact":
            continue
        expected = _EXPECTED_SHAPES.get(field)
        if not expected or shapes.get(col) in expected or shapes.get(col) in (None, "empty"):
            continue  # the name match is fine, or the data cannot say
        rooted = _deepest_root(rings, field, by_name, taken - {col})
        if rooted is None or rooted == col or shapes.get(rooted) not in expected:
            continue  # no ring, or the ring points somewhere no better
        fields[field] = {
            "column": rooted, "tier": "rooted",
            "confidence": 0.95, "data_type": by_name[rooted].data_type,
        }
        taken.discard(col)
        taken.add(rooted)
        promotions.append({
            "field": field, "from_column": col, "to_column": rooted,
            "from_shape": shapes.get(col), "to_shape": shapes.get(rooted),
            "reason": (f"exact name match {col!r} holds {shapes.get(col)!r}, outside "
                       f"the expected {sorted(expected)}; a confirmed ring names "
                       f"{rooted!r}, which fits"),
        })
    return promotions


def refine_with_data(conn, table: str, fields: dict, canonical_fields: list[str],
                     columns: Optional[list] = None, limit: int = 8) -> dict:
    """Advisory data-shape pass over a name-based proposal. Returns
    {"shapes": {col: shape}, "suggestions": [...]} WITHOUT changing `fields`.

    A suggestion fires when a field's currently-mapped column is the wrong shape
    (severity "trap" — the name lied) or is unmapped while a well-shaped column
    is free (severity "hint"). Columns already well-placed on another field are
    not poached. This is the pass that catches the `task`-holds-a-job-class trap
    the name tiers sail straight past."""
    if columns is None:
        columns = introspect(conn, table)
    col_types = {c.name: c.data_type for c in columns}
    samples = _sample_columns(conn, table, columns, limit=limit)
    shapes = {c: classify_shape(vals, col_types.get(c)) for c, vals in samples.items()}
    if not shapes:
        return {"shapes": {}, "suggestions": []}

    # Columns that already sit on a field whose expected shape they satisfy —
    # don't suggest stealing these away.
    well_placed = set()
    for f in canonical_fields:
        c = fields.get(f, {}).get("column")
        exp = _EXPECTED_SHAPES.get(f)
        if c and exp and shapes.get(c) in exp:
            well_placed.add(c)

    shape_counts = Counter(shapes.values())
    used: set = set()  # a column proposed for one field is not offered to another
    suggestions = []
    for field in canonical_fields:
        exp = _EXPECTED_SHAPES.get(field)
        if not exp:
            continue
        cur_col = fields.get(field, {}).get("column")
        cur_shape = shapes.get(cur_col) if cur_col else None
        mismatch = cur_col is not None and cur_shape not in exp and cur_shape not in (None, "empty")
        unmapped = cur_col is None
        if not (mismatch or unmapped):
            continue

        # A replacement candidate must fit the expected shape, be free (not
        # well-placed elsewhere, not already proposed), and — the 2004 guard —
        # be DISCRIMINATING: its shape shared by few columns, so "the command-
        # shaped one" is meaningful but "one of six freetext columns" is not.
        candidates = [
            c for c, sh in shapes.items()
            if sh in exp and c != cur_col and c not in well_placed and c not in used
            and shape_counts[sh] <= _HINT_SHARED_SHAPE_MAX
        ]

        if mismatch:
            # The FLAG is always worth emitting — a column whose data is the
            # wrong shape is a finding on its own. A replacement is attached only
            # when a discriminating candidate exists; name affinity is NOT
            # required (this is the `task`->`cmd_line` rescue path).
            best = candidates[0] if candidates else None
            entry = {
                "field": field, "current_column": cur_col,
                "current_tier": fields.get(field, {}).get("tier"),
                "current_shape": cur_shape, "severity": "trap",
                "reason": (
                    f"'{cur_col}' name-matched {field}, but its values look like "
                    f"'{cur_shape}', not {'/'.join(sorted(exp))}"
                    + (f"; '{best}' is '{shapes.get(best)}'-shaped" if best else
                       "; no better-shaped column found — confirm by hand")
                ),
            }
            if best:
                entry["suggested_column"] = best
                entry["suggested_shape"] = shapes.get(best)
                used.add(best)
            suggestions.append(entry)
        else:
            # HINT for an unmapped field: additionally require name affinity, so
            # a shape match alone can't propose an unrelated column. If nothing
            # clears both bars, stay silent (silence beats a wrong guess).
            affine = [c for c in candidates if _name_affinity(c, field) >= _HINT_NAME_AFFINITY_MIN]
            if not affine:
                continue
            best = affine[0]
            used.add(best)
            suggestions.append({
                "field": field, "current_column": None, "current_tier": "unmapped",
                "current_shape": None, "suggested_column": best,
                "suggested_shape": shapes.get(best), "severity": "hint",
                "reason": f"{field} is unmapped; '{best}' is '{shapes.get(best)}'-shaped "
                          f"and name-similar to {field}",
            })
    return {"shapes": shapes, "suggestions": suggestions}


def db_fingerprint(conn) -> str:
    """Stable identifier for 'this database' — host + dbname only, never
    connection-string secrets (user/password), so it's safe to use as a
    filename and to persist in a reviewable artifact."""
    dsn = conn.get_dsn_parameters()
    key = f"{dsn.get('host') or 'local'}:{dsn.get('dbname', '')}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _validate_table(table: str) -> str:
    if not table or not _COLLECTION_SAFE_RE.match(table):
        raise ValueError(f"invalid table name: {table!r}")
    return table


def manifest_digest(app_id: str) -> str:
    """Content digest of the manifest in force for ``app_id``, or ``""``.

    A mapping is a photograph of what an app was permitted to touch when the
    profile was taken. Grants change; nothing re-takes the photograph. Recording
    the manifest's digest alongside the mapping makes that drift *detectable*
    rather than merely true — the same move `provenance.toolchain` makes in
    nestor, and for the same stated reason: a content hash cannot be bumped by
    hand and cannot go stale.

    A digest rather than an mtime on purpose. ``$WILLOW_HOME`` is a git
    checkout, so a clone or a `git checkout` rewrites every mtime and a
    timestamp comparison would go silent or fire on every file at once.
    """
    try:
        path = paths.willow_home() / "mcp_apps" / app_id / "manifest.json"
        return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""
    except Exception:  # noqa: BLE001 — provenance is a courtesy, never an outage
        return ""


def audit_mapping_grants(app_id: str) -> list[str]:
    """Mappings whose manifest changed since they were profiled.

    Returns drift messages, empty when in sync. Messages are unprefixed —
    the caller names the seat, because one agent's mappings are audited under
    whichever project points at it (project ``github`` uses agent ``willow``). Deliberately says nothing about
    WHICH fields a grant should permit: there is no declared table-to-tool
    relation in this package, so any such rule would be a second roster invented
    here and free to drift from the manifests it claims to describe. This
    reports only the fact a reader can act on — *the grant moved after the
    profile was taken; re-profile before confirming.*

    A mapping with no recorded digest predates this check. That is reported as
    its own state rather than folded into either verdict, because "not
    comparable" and "in sync" are different answers and only one of them is
    reassuring.
    """
    issues: list[str] = []
    try:
        root = paths.schema_maps_dir(app_id)
    except Exception:  # noqa: BLE001
        return issues
    if not root.is_dir():
        return issues
    current = manifest_digest(app_id)
    if not current:
        return issues
    for path in sorted(root.glob("*.json")):
        try:
            record = json.loads(path.read_text())
        except Exception:  # noqa: BLE001
            issues.append(f"unreadable schema mapping -> {path}")
            continue
        recorded = str(record.get("manifest_sha256") or "")
        table = record.get("table") or path.stem
        if not recorded:
            issues.append(
                f"schema mapping for {table!r} predates grant tracking "
                f"(no manifest_sha256) - re-profile to establish a baseline")
        elif recorded != current:
            issues.append(
                f"schema mapping for {table!r} was profiled under a "
                f"different manifest ({recorded[:12]} != {current[:12]}) - the "
                f"grant changed since; re-profile before confirming"
                + ("  [and it is already CONFIRMED]" if record.get("confirmed") else ""))
    return issues


def mapping_path(app_id: str, fingerprint: str, table: str) -> Path:
    _validate_table(table)
    # B-50/#238: schema_maps/ lives outside mcp_apps/<app_id>/ specifically
    # so this mkdir can never collide with mcp_apps/ being trust-root-
    # hardened to the operator uid -- see paths.schema_maps_dir's docstring.
    root = paths.schema_maps_dir(app_id)
    root.mkdir(parents=True, exist_ok=True)
    return root / f"{fingerprint}__{table}.json"


def _write_json_atomic(path: Path, record: dict) -> None:
    tmp = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    tmp.write_text(json.dumps(record, indent=2))
    os.replace(tmp, path)


def load_mapping(app_id: str, fingerprint: str, table: str) -> Optional[dict]:
    path = mapping_path(app_id, fingerprint, table)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def save_mapping(app_id: str, fingerprint: str, table: str, record: dict) -> None:
    _write_json_atomic(mapping_path(app_id, fingerprint, table), record)


def resolve(conn, app_id: str, table: str, canonical_fields: list[str]) -> dict:
    """Top-level entry point: discover-or-load a mapping for (db, table).

    Returns the mapping artifact dict, always including "fields", "confirmed",
    and "schema_version". On a table that doesn't exist, returns
    {"error": "table_not_found", "table": table} instead — callers must check
    for "error" before touching "fields".

    A confirmed mapping is re-validated against a fresh introspection every
    call: if any confirmed field's column no longer exists, confirmed is
    downgraded to false and "schema_drift": true is set (doc §4) rather than
    building SQL against columns that may no longer mean what a human
    confirmed them to mean. An unconfirmed mapping is simply recomputed —
    propose_mapping is pure, so this only changes the result when the real
    columns changed, which is exactly when it should.
    """
    columns = introspect(conn, table)
    if not columns:
        return {"error": "table_not_found", "table": table}

    fingerprint = db_fingerprint(conn)
    existing = load_mapping(app_id, fingerprint, table)
    fresh_fields = propose_mapping(columns, canonical_fields, read_rings())

    if existing and existing.get("confirmed"):
        by_name = {c.name for c in columns}
        drifted = any(
            f.get("column") and f["column"] not in by_name
            for f in existing.get("fields", {}).values()
        )
        if drifted:
            existing["confirmed"] = False
            existing["schema_drift"] = True
            existing["fields"] = fresh_fields
            save_mapping(app_id, fingerprint, table, existing)
        return existing

    record = {
        "schema_version": SCHEMA_VERSION,
        "database": fingerprint,
        "table": table,
        "discovered_at": datetime.now(timezone.utc).isoformat(),
        "manifest_sha256": manifest_digest(app_id),
        "confirmed": False,
        "fields": fresh_fields,
    }
    save_mapping(app_id, fingerprint, table, record)
    return record


def _apply_overrides(base_fields: dict, overrides: Optional[dict],
                     by_name: dict, canonical_fields: list[str]) -> tuple[Optional[dict], Optional[dict]]:
    """Apply human column overrides to a base mapping (§3.4). Returns
    (fields, None) on success or (None, error) on a bad override — the error
    lacks a "table" key; the caller adds it. Shared by confirm() and preview()
    so both apply overrides identically. A None col explicitly unmaps a field;
    a non-null col must exist in a fresh introspection or the apply is refused
    (principle 3: writes may not guess)."""
    fields = {f: dict(v) for f, v in base_fields.items()}
    for field, col in (overrides or {}).items():
        if field not in canonical_fields:
            return None, {"error": "unknown_field", "field": field}
        if col is None:
            fields[field] = {"column": None, "tier": "unmapped", "confidence": 0.0, "data_type": None}
        elif col not in by_name:
            return None, {"error": "override_invalid", "field": field, "column": col}
        else:
            fields[field] = {"column": col, "tier": "confirmed_override",
                             "confidence": 1.0, "data_type": by_name[col].data_type}
    return fields, None


def render_sample(conn, table: str, fields: dict, limit: int = 3) -> list[dict]:
    """SELECT up to `limit` real rows, projected through the mapping, so a
    reviewer can see what each canonical field ACTUALLY resolves to. This is
    the evidence a name match alone can't give: a `content` column that is
    really a provenance blob — with the real knowledge in `title`/`summary` —
    reveals itself here. Long values are truncated; a query error is returned
    inline rather than raised (a diagnostic must not crash)."""
    _validate_table(table)
    cols, present = [], []
    for field, m in fields.items():
        col = m.get("column")
        if col:
            cols.append(f'"{col}" AS "{field}"')
            present.append(field)
    if not cols:
        return []
    limit = max(1, min(int(limit), 10))
    cur = conn.cursor()
    try:
        cur.execute(f'SELECT {", ".join(cols)} FROM "{table}" LIMIT %s', (limit,))  # nosec B608 - table passed _validate_table()'s [A-Za-z0-9_-]{1,128} allowlist above; cols come from the confirmed field mapping, not raw text; limit is a bound param
        rows = cur.fetchall()
    except Exception as e:  # noqa: BLE001 — evidence tool must degrade, not raise
        return [{"_sample_error": str(e)[:160]}]
    finally:
        cur.close()
    out = []
    for row in rows:
        rec = {}
        for field, val in zip(present, row):
            if val is None or isinstance(val, (int, float, bool)):
                rec[field] = val
            else:
                s = str(val)
                rec[field] = (s[:200] + "…") if len(s) > 200 else s
        out.append(rec)
    return out


def preview(conn, app_id: str, table: str, canonical_fields: list[str],
            overrides: Optional[dict] = None) -> dict:
    """Dry-run: return the proposed mapping (base heuristic or prior artifact,
    with `overrides` applied in memory) plus a rendered sample row — WITHOUT
    confirming or writing anything. The review step the confirm gate needs:
    look at `sample` before trusting `fields`, because a name match is an
    assertion, not evidence."""
    columns = introspect(conn, table)
    if not columns:
        return {"error": "table_not_found", "table": table}
    by_name = {c.name: c for c in columns}
    fingerprint = db_fingerprint(conn)
    existing = load_mapping(app_id, fingerprint, table)
    base_fields = (existing or {}).get("fields") or propose_mapping(columns, canonical_fields, read_rings())
    fields, err = _apply_overrides(base_fields, overrides, by_name, canonical_fields)
    if err:
        err["table"] = table
        return err
    refined = refine_with_data(conn, table, fields, canonical_fields, columns=columns)
    # Applied only when the caller supplied no override for that field: an
    # explicit override is a human deciding now, and a ring is a human who
    # decided once before. The present one wins.
    promotions = promote_rings_over_lying_names(
        fields, refined["shapes"], read_rings(), by_name,
        [f for f in canonical_fields if f not in (overrides or {})])
    # A suggestion for a field that was just promoted describes the mapping as
    # it stood a moment ago. Leaving it in would report a trap the reader is
    # looking at the fix for, which reads as the fix not having worked.
    if promotions:
        promoted = {p["field"] for p in promotions}
        refined["suggestions"] = [g for g in refined["suggestions"]
                                  if g.get("field") not in promoted]
    return {
        "schema_version": SCHEMA_VERSION,
        "database": fingerprint,
        "table": table,
        "confirmed": False,
        "preview": True,
        "fields": fields,
        "sample": render_sample(conn, table, fields),
        "shapes": refined["shapes"],
        "suggestions": refined["suggestions"],
        "ring_promotions": promotions,
    }


def confirm(
    conn, app_id: str, table: str, canonical_fields: list[str],
    overrides: Optional[dict] = None,
) -> dict:
    """Confirm a table's mapping, unlocking write tools for it (§3.4).

    Starts from whatever's already on disk (preserving any prior human
    corrections), or a fresh heuristic proposal if nothing was ever
    computed. `overrides` lets a human correct individual
    canonical-field -> real-column assignments before confirming — pass
    `{"field": "real_column"}` to point a field at a specific column, or
    `{"field": None}` to explicitly mark it unmapped (DROP). An override
    column must exist in a *fresh* introspection or the whole call is
    refused — a confirmed mapping must never point at a column that isn't
    actually there (doc §2 principle 3: writes may not guess).

    Returns the saved, confirmed mapping record, or {"error":
    "table_not_found"|"unknown_field"|"override_invalid", ...}.
    """
    columns = introspect(conn, table)
    if not columns:
        return {"error": "table_not_found", "table": table}
    by_name = {c.name: c for c in columns}

    fingerprint = db_fingerprint(conn)
    existing = load_mapping(app_id, fingerprint, table)
    base_fields = (existing or {}).get("fields") or propose_mapping(columns, canonical_fields, read_rings())
    fields, err = _apply_overrides(base_fields, overrides, by_name, canonical_fields)
    if err:
        err["table"] = table
        return err

    record = {
        "schema_version": SCHEMA_VERSION,
        "database": fingerprint,
        "table": table,
        "discovered_at": (existing or {}).get("discovered_at") or datetime.now(timezone.utc).isoformat(),
        # Stamped at CONFIRM time, not carried from the profile: confirming is
        # the act that says "this mapping is right for what this app may do",
        # so the grant it was judged against is the one in force now.
        "manifest_sha256": manifest_digest(app_id),
        "confirmed": True,
        "confirmed_at": datetime.now(timezone.utc).isoformat(),
        "fields": fields,
    }
    save_mapping(app_id, fingerprint, table, record)
    # A confirmed mapping is a labeled example — remember its non-trivial
    # column->field pairs deployment-wide so the next unfamiliar table maps
    # itself (the durable generalization lever the 2004 test argued for).
    grow_ring(fields)
    return record


def cast_for_ilike(field_mapping: dict) -> str:
    """Return the column reference to use in an ILIKE predicate, casting to
    text first if the real column is jsonb/json (doc §6.1-style type
    wrinkle, applies to §3 too: knowledge.content is jsonb, not text)."""
    col = field_mapping["column"]
    if field_mapping.get("data_type") in _TEXT_CAST_TYPES:
        return f'"{col}"::text'
    return f'"{col}"'
