"""Load agent_seed_v1 from $WILLOW_HOME/seeds/{agent_id}.json.

AS-3: advisory load on session_enter; pending ratification surfaces gaps.
AS-4: PGP verify when WILLOW_PGP_FINGERPRINT is set; ratified + bad sig → untrusted.

See docs/design/agent-seed.md.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from typing import Any

from .paths import seeds_dir, store_root, willow_home
from . import pgp
from .db import Store

logger = logging.getLogger("willow_mcp.seed_loader")

SEED_FORMAT = "agent_seed_v1"
_AGENT_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


def seed_path(agent_id: str) -> Path | None:
    key = (agent_id or "").strip()
    if not _AGENT_ID_RE.match(key):
        return None
    return seeds_dir() / f"{key}.json"


def load_seed_document(agent_id: str) -> tuple[dict[str, Any] | None, str | None]:
    """Read and validate seed JSON from home. Returns (data, error_reason)."""
    path = seed_path(agent_id)
    if path is None:
        return None, "invalid_agent_id"
    if not path.is_file():
        return None, "no_seed_file"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return None, f"unreadable: {e}"
    if not isinstance(data, dict):
        return None, "seed must be a JSON object"
    if data.get("format") != SEED_FORMAT:
        return None, f"unsupported format: {data.get('format')!r}"
    return data, None


def seed_trusted(loaded: dict[str, Any]) -> bool:
    """True when a ratified seed may promote/mirror (PGP enforced when enabled)."""
    if not loaded.get("present"):
        return False
    if str(loaded.get("ratification_status") or "").lower() != "ratified":
        return False
    trusted = loaded.get("trusted")
    if trusted is not None:
        return bool(trusted)
    return True


def _seed_excerpt(data: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    seed_block = data.get("seed") or {}
    if seed_block.get("instruction"):
        out["instruction"] = seed_block["instruction"]
    persona = data.get("persona") or {}
    if persona.get("character"):
        out["character"] = persona["character"]
    context = data.get("context") or {}
    for key in ("cognitive_style", "correction_pattern", "active_work"):
        if context.get(key):
            out[key] = context[key]
    identity = data.get("identity") or {}
    if identity.get("kind"):
        out["kind"] = identity["kind"]
    return out


def load_agent_seed(agent_id: str, *, include_full: bool = False) -> dict[str, Any]:
    """Load seed file if present. Never raises — returns structured status."""
    data, err = load_seed_document(agent_id)
    if err:
        reason = err
        if err == "invalid_agent_id":
            return {"present": False, "reason": reason}
        if err == "no_seed_file":
            return {"present": False, "reason": reason}
        return {"present": False, "reason": reason}

    assert data is not None
    path = seed_path(agent_id)
    assert path is not None

    rat = (data.get("seed") or {}).get("ratification") or {}
    status = str(rat.get("status") or "pending").lower()
    gaps = list(data.get("gaps") or [])

    advisory = None
    if status == "pending":
        advisory = (
            "Agent seed unratified — boot is advisory only; gaps surfaced; "
            "not eligible for KB canon promotion or SOIL mirror."
        )

    verify: dict[str, Any] | None = None
    trusted: bool | None = None
    if pgp.pgp_enabled():
        if status == "ratified":
            ok, reason = pgp.verify_detached(path)
            verify = {"ok": ok, "reason": reason}
            trusted = ok
            if not ok:
                advisory = (
                    "Ratified seed failed PGP verification — treat as untrusted; "
                    "mirror and KB promotion denied until re-signed."
                )
        elif status == "pending":
            verify = {"ok": None, "reason": "skipped_pending_ratification"}
            trusted = False
        else:
            verify = {"ok": False, "reason": f"unknown ratification status: {status}"}
            trusted = False
    elif status == "ratified":
        trusted = True

    rel = str(path.relative_to(willow_home()))
    block: dict[str, Any] = {
        "present": True,
        "path": rel,
        "format": SEED_FORMAT,
        "ratification_status": status,
        "gaps": gaps,
        "advisory": advisory,
        "excerpt": _seed_excerpt(data),
    }
    if trusted is not None:
        block["trusted"] = trusted
    if verify is not None:
        block["verify"] = verify
    if include_full:
        block["seed"] = data
    return block


_CORPUS_CORRECTIONS = "corpus_corrections"
_CORPUS_PREFERENCES = "corpus_preferences"
_CORPUS_CONFIRMATIONS = "corpus_confirmations"


def _project_repo_name() -> str:
    root = os.environ.get("WILLOW_PROJECT_ROOT", "").strip()
    if root:
        return Path(root).name.lower()
    return Path.cwd().name.lower()


def _projects_root() -> Path:
    """Where Claude Code keeps its per-project state — ``~/.claude/projects``.

    Factored out (rather than inlined in both :func:`memory_dirs` and
    :func:`resolve_own_project`) so a test can monkeypatch discovery and
    own-project resolution against one fake tree instead of two.
    """
    return Path.home() / ".claude" / "projects"


def memory_dirs() -> list[Path]:
    """Every Claude Code project memory dir on this box, not just this repo's.

    Bounded discovery: one listing of ``~/.claude/projects`` plus one
    ``is_dir()`` check on each entry's ``memory/`` subdirectory — never a
    recursive walk. ``memory/`` is the boundary Claude Code itself writes
    inside for a project, so nothing outside it is read. Order is
    deterministic (sorted by project dir name) so seeding is reproducible.

    An empty return means "``~/.claude/projects`` itself is not there" —
    UNREACHABLE, not "no project has memories". Callers must not read an
    empty list from this function as license to retire anything (F1,
    Loki 022800C8): a seat opened with a HOME that doesn't have this tree
    yet must never be read as "every memory everywhere was deleted".
    """
    projects = _projects_root()
    if not projects.is_dir():
        return []
    dirs: list[Path] = []
    for entry in sorted(projects.iterdir()):
        if not entry.is_dir():
            continue
        memory = entry / "memory"
        if memory.is_dir():
            dirs.append(memory)
    return dirs


def _git_root(path: Path) -> Path | None:
    """Nearest ancestor of ``path`` (inclusive) that is a git work tree
    root — presence of a ``.git`` entry (a directory for a normal
    checkout, a file for a worktree). Bounded: at most 64 segments up,
    same bound as the caller's own walk. Read-only ``.exists()`` checks
    only. ``None`` when ``path`` isn't inside any git work tree at all.
    """
    candidate = path
    hops = 0
    while True:
        hops += 1
        if hops > 64:
            return None
        if (candidate / ".git").exists():
            return candidate
        parent = candidate.parent
        if parent == candidate:
            return None
        candidate = parent


def resolve_own_project(project_root: str | None = None) -> dict[str, Any]:
    """Resolve THIS seat's own Claude Code memory dir EXACTLY from its
    resolved project root — never by fuzzy substring (G3, Loki 5C276CEA:
    the old substring match sent a willow-mcp seat to a stale
    ``-github-willow-mcp`` dir and a seat in ``willow-memory/willow`` to a
    completely different repo's (``willow``) notes, while ``seat/heimdallr``
    and any worktree matched nothing and printed no boot line at all —
    silent, not empty).

    ``project_root`` is the seat's resolved project root — ``session_enter``
    already computes this (``enter_result["project"]["root"]``); callers
    thread it through rather than re-deriving it. Falls back to
    ``WILLOW_PROJECT_ROOT`` then ``Path.cwd()`` only when the caller has
    nothing better (a bare script, a test).

    A worktree (``<repo>/worktrees/<name>`` — this fleet's own convention;
    every dispatch brief says ``git worktree add worktrees/<name>``) is
    normalized to its repo path first: the operator's memory of a repo is
    not per-worktree.

    Matching is EXACT, then walks up one path segment at a time when the
    exact path has no memory dir of its own (Loki's own narrative:
    "falling back to the nearest ancestor") — e.g. ``seat/heimdallr`` has
    never been opened as its own Claude Code project, so it falls back to
    its parent, the willows-grove repo root, which has. Claude Code names
    a project directory by taking the absolute path and replacing every
    ``/`` with ``-``; this reproduces that encoding FORWARD only (never
    inverts a slug back to a path, which would be ambiguous for a path
    segment that itself contains a dash).

    K2 (Loki 3C1BB137): that ancestor walk used to be UNBOUNDED, so any
    repo under ``~/github`` with no memory dir of its own (willow-bot,
    kartikeya, corpus-lens, willow-gate, any new checkout) climbed all
    the way out to ``~/github``'s own notes and read them as "own
    project" — the exact cross-project leak G3 was built to close, one
    level up. The walk now never climbs past the repo's own git root
    (:func:`_git_root`; a worktree is already normalized to its repo
    above). A path that isn't inside any git work tree at all gets no
    ancestor fallback whatsoever — exact match only.

    Returns ``{"project_dir": str|None, "repo_name": str, "exact": bool,
    "state": "populated"|"empty"|"unreachable"}``. ``"unreachable"``:
    ``~/.claude/projects`` itself isn't there. ``"empty"``: the tree
    exists but no directory — at the resolved path or any ancestor up to
    the git root — encodes this seat's project. ``"populated"``:
    ``project_dir`` names the match; ``exact`` is ``True`` only when the
    match was the resolved path itself, ``False`` when it took an
    ancestor fallback (so a caller can label a fallback as reading
    another project's notes rather than presenting it as this seat's
    own — see ``boot_context.py``'s "from <repo>'s notes" line).
    """
    projects = _projects_root()
    if not projects.is_dir():
        return {"project_dir": None, "repo_name": "", "exact": False, "state": "unreachable"}

    root = (project_root or os.environ.get("WILLOW_PROJECT_ROOT", "") or str(Path.cwd())).strip()
    if not root:
        return {"project_dir": None, "repo_name": "", "exact": False, "state": "empty"}
    try:
        candidate = Path(root).resolve()
    except OSError:
        return {"project_dir": None, "repo_name": "", "exact": False, "state": "empty"}

    parts = candidate.parts
    if "worktrees" in parts:
        candidate = Path(*parts[: parts.index("worktrees")])

    repo_name = candidate.name
    git_root = _git_root(candidate)

    hops = 0
    exact = True
    while True:
        hops += 1
        if hops > 64:  # bounded — no real filesystem path is this deep
            break
        encoded = str(candidate).replace(os.sep, "-")
        memory = projects / encoded / "memory"
        if memory.is_dir():
            return {"project_dir": encoded, "repo_name": candidate.name,
                     "exact": exact, "state": "populated"}
        if git_root is None or candidate == git_root:
            # Not inside any git work tree at all (no fallback — exact
            # match only), or already at the repo's own root (never
            # climb past it, per K2).
            break
        parent = candidate.parent
        if parent == candidate:
            break
        candidate = parent
        exact = False
    return {"project_dir": None, "repo_name": repo_name, "exact": False, "state": "empty"}


def claude_memory_dir() -> Path | None:
    """Back-compat single-path resolution, built on :func:`resolve_own_project`."""
    resolved = resolve_own_project()
    if resolved["state"] != "populated" or not resolved["project_dir"]:
        return None
    return _projects_root() / resolved["project_dir"] / "memory"


def _corpus_store() -> Store:
    return Store(str(store_root()))


# Frontmatter shape Claude Code memory files use: a leading `---` block of
# flat `key: value` pairs, one nested block (`metadata:`) with the same
# shape indented under it, and (per Loki 022800C8 F7) a top-level scalar
# occasionally written as a YAML block scalar (`description: >` folded, or
# `description: |` literal) rather than a single quoted line. Not a general
# YAML parser — PyYAML is a test-only dependency here (pyproject.toml
# `[test]` extra), and this loader runs on every SessionStart in every
# install, so it stays stdlib-only and handles exactly the shapes these
# files are written in. Anything it can't parse this way is reported by
# name and skipped, never guessed at.
_FRONTMATTER_RE = re.compile(r"\A---[ \t]*\n(.*?)\n---[ \t]*\n(.*)", re.DOTALL)

# The only frontmatter `metadata.type` (or, per F7, a stray top-level
# `type:`) that seeds `corpus_corrections`. Operator ruling
# `boot-corrections-trust-and-scope-2026-09-23`, ruling 2: "its project +
# fleet-wide feedback" — `project`-type notes stay OUT of boot entirely
# (they are mostly point-in-time session state, Loki F2/F5's 194-of-321
# stale-note finding), `user` stays out (cross-project persona/preference,
# not a correction), `reference` stays out (documentation, nothing to act
# on). Only `feedback` — an operator correcting a behavior pattern in the
# moment — seeds here.
_SEED_MEMORY_TYPE = "feedback"

# Frontmatter marker (inside the existing `metadata:` block, alongside
# `type:`) that widens a feedback memory's boot audience from "this seat's
# own project only" to every seat everywhere. Chosen over a new top-level
# key because it sits next to `type:` where an author is already looking,
# needs no new frontmatter section, and reads naturally ("type: feedback" /
# "scope: fleet"). Any other value, or its absence, means "own project
# only" (ruling 2's default).
_FLEET_SCOPE_VALUE = "fleet"


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        inner = value[1:-1]
        if value[0] == '"':
            inner = inner.replace('\\"', '"').replace("\\\\", "\\")
        return inner
    return value


_BLOCK_SCALAR_MARKERS = {">", ">-", ">+", "|", "|-", "|+"}


def _parse_frontmatter_block(block: str) -> dict[str, Any] | None:
    lines = block.splitlines()
    data: dict[str, Any] = {}
    nested: dict[str, Any] | None = None
    i = 0
    n = len(lines)
    while i < n:
        raw_line = lines[i]
        if not raw_line.strip():
            i += 1
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()
        if ":" not in line:
            return None
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if not key:
            return None
        if indent > 0:
            if nested is None:
                return None
            nested[key] = _unquote(value)
            i += 1
            continue
        if value in _BLOCK_SCALAR_MARKERS:
            folded = value[0] == ">"
            i += 1
            block_lines: list[str] = []
            block_indent: int | None = None
            while i < n:
                bl = lines[i]
                if not bl.strip():
                    block_lines.append("")
                    i += 1
                    continue
                bi = len(bl) - len(bl.lstrip(" "))
                if bi == 0:
                    break
                if block_indent is None:
                    block_indent = bi
                if bi < block_indent:
                    break
                block_lines.append(bl[block_indent:].rstrip())
                i += 1
            text = " ".join(s for s in block_lines if s.strip()) if folded \
                else "\n".join(block_lines).strip("\n")
            nested = None
            data[key] = text.strip()
            continue
        nested = None
        if not value:
            nested = {}
            data[key] = nested
        else:
            data[key] = _unquote(value)
        i += 1
    return data


def _first_content_line(body: str, limit: int = 200) -> str:
    for line in body.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("@"):
            return line[:limit]
    return ""


def _content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


def _fs_modified(fpath: Path) -> str:
    """The file system's own mtime, ISO-8601 UTC. G4 (Loki 5C276CEA): a
    memory file's own frontmatter `modified` claim is author-controlled
    (including by an agent), so letting it drive fleet-wide ranking let a
    fabricated future date jump a note to the top of every seat's boot.
    The file system's mtime is not something a memory file's own text can
    assert its way past."""
    try:
        return datetime.fromtimestamp(fpath.stat().st_mtime, tz=timezone.utc).isoformat()
    except OSError:
        return ""


def _legacy_record(fpath: Path, project_dir: str, body: str) -> tuple[str, dict[str, Any]] | None:
    """`feedback_*.md` with no (or unparseable) frontmatter — the original
    behavior, kept so nothing that seeds today stops seeding. Still keyed
    (project_dir, name) — F3/F4 — so a same-named legacy file in two
    projects is two records, not a silent overwrite."""
    rule = _first_content_line(body)
    if not rule:
        return None
    name = fpath.stem
    record_id = f"{project_dir}::{name}"
    return record_id, {
        "project_dir": project_dir,
        "project": project_dir.lstrip("-"),
        "path": str(fpath),
        "name": name,
        "content": rule,
        "source": fpath.name,
        "memory_type": _SEED_MEMORY_TYPE,
        "scope": "own",
        "session_id": "",
        "modified": "",
        "fs_modified": _fs_modified(fpath),
    }


def _memory_record(fpath: Path, project_dir: str) -> tuple[str | None, dict[str, Any] | None, str | None]:
    """Extract (record_id, record, skip_reason) for one memory file.

    ``skip_reason`` is only set when the file looked like it should seed
    but couldn't be read this way — reported by name, never seeded as
    garbage. A file that parses fine but is out of scope (wrong type,
    empty) returns ``(None, None, None)``: nothing to report, nothing to
    seed — and critically, per F1, NOT a signal to retire anything; that
    call belongs to the caller, which knows whether the file is truly gone
    or just out of scope this run.
    """
    is_legacy_name = fpath.name.startswith("feedback_")
    try:
        text = fpath.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return None, None, f"unreadable: {e}"

    m = _FRONTMATTER_RE.match(text)
    if not m:
        if is_legacy_name:
            body = text.split("---", 2)[-1].strip() if "---" in text else text.strip()
            rec = _legacy_record(fpath, project_dir, body)
            return (rec[0], rec[1], None) if rec else (None, None, None)
        return None, None, None

    fm = _parse_frontmatter_block(m.group(1))
    body = m.group(2)
    if fm is None:
        if is_legacy_name:
            rec = _legacy_record(fpath, project_dir, body)
            return (rec[0], rec[1], None) if rec else (None, None, None)
        return None, None, "frontmatter did not parse"

    metadata = fm.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    # F7: a top-level `type:` (not nested under `metadata:`) is a real
    # shape in the wild — fall back to it rather than excluding silently.
    mtype = str(metadata.get("type") or fm.get("type") or "").strip().lower()
    if not mtype and is_legacy_name:
        mtype = _SEED_MEMORY_TYPE
    if mtype != _SEED_MEMORY_TYPE:
        return None, None, None

    name = str(fm.get("name") or "").strip() or fpath.stem
    content = str(fm.get("description") or "").strip() or _first_content_line(body)
    if not content:
        return None, None, None

    scope_raw = str(metadata.get("scope") or fm.get("scope") or "").strip().lower()
    record_id = f"{project_dir}::{name}"
    return record_id, {
        "project_dir": project_dir,
        "project": project_dir.lstrip("-"),
        "path": str(fpath),
        "name": name,
        "content": content[:400],
        "source": fpath.name,
        "memory_type": mtype,
        "scope": _FLEET_SCOPE_VALUE if scope_raw == _FLEET_SCOPE_VALUE else "own",
        "session_id": str(metadata.get("originSessionId") or "").strip(),
        "modified": str(metadata.get("modified") or "").strip(),
        "fs_modified": _fs_modified(fpath),
    }, None


def _retire(store: Store, record_id: str, existing: dict[str, Any]) -> None:
    """Flip a record's own `status` field to "retired" — never
    `Store.delete`. `Store.delete` soft-deletes at the SQLite layer, and
    `Store.put`/`Store.update` never clear that flag by design (db.py's own
    comment: a re-put must not silently undelete a tombstoned id, a
    deliberate anti-forgery property). That makes SQLite-level delete a
    ONE-WAY door — exactly Loki's F1: a file that comes back after being
    briefly absent (or a transient parse error, or a HOME that momentarily
    lacked `~/.claude/projects`) would retire permanently and invisibly.
    A `status` field the seeder itself owns has no such trap: flipping it
    back to "active" on a later run is an ordinary field update, visible
    and reversible, the exact "three states, never collapsed" shape this
    repo's own INVARIANTS.md already commits to elsewhere.
    """
    updated = {k: v for k, v in existing.items() if not k.startswith("_")}
    updated["status"] = "retired"
    updated["updated_at"] = datetime.now(timezone.utc).isoformat()
    store.update(_CORPUS_CORRECTIONS, record_id, updated)


def seed_corpus_corrections() -> int:
    """`feedback`-type operator memory → `corpus_corrections`, across every
    discovered memory dir (:func:`memory_dirs`). Keyed by
    ``(project_dir, frontmatter name-or-stem)`` (F3/F4 — a same-named file
    in two projects is two records) plus a content hash: unchanged content
    is skipped; changed content, or a previously-retired record whose file
    is active again, updates the same record in place (`created_at`
    preserved). A record whose file this run can positively confirm is
    gone (its project's dir WAS listed, and its stored path is not among
    the files found there) is retired via `_retire` (see its docstring for
    why that is a status flip, never `Store.delete`).

    F1 fixes, all load-bearing:
      - Zero dirs discovered at all → UNREACHABLE, not empty. Nothing is
        seeded or retired; the run is a no-op.
      - A file whose frontmatter fails to parse this run is left exactly
        as it was — present on disk, just unreadable this pass, never
        treated as "gone".
      - A project's dir that WAS listed protects every record it didn't
        touch by encoding "this file's path is present" independent of
        whether that file's content changed, was out of scope, or failed
        to parse — retirement only fires for a record whose path is
        provably ABSENT from this run's listing.
    """
    dirs = memory_dirs()
    if not dirs:
        logger.info(
            "seed_corpus_corrections: no memory dirs discovered "
            "(~/.claude/projects missing or unreadable) — unreachable, "
            "not empty; seeding and retirement both skipped this run"
        )
        return 0

    store = _corpus_store()
    seeded = 0
    skipped: list[str] = []
    present_by_project: dict[str, set[str]] = {}

    for memory_dir in dirs:
        project_dir = memory_dir.parent.name
        present_paths = present_by_project.setdefault(project_dir, set())
        for fpath in sorted(memory_dir.glob("*.md")):
            if fpath.name == "MEMORY.md":
                continue
            present_paths.add(str(fpath))
            try:
                record_id, payload, skip_reason = _memory_record(fpath, project_dir)
            except Exception:
                logger.debug("seed_corpus_corrections: failed on %s", fpath, exc_info=True)
                skipped.append(f"{fpath}: unexpected error")
                continue
            if skip_reason:
                skipped.append(f"{fpath}: {skip_reason}")
                continue
            if not record_id or not payload:
                continue
            content_hash = _content_hash(payload["content"])
            existing = store.get(_CORPUS_CORRECTIONS, record_id)
            unchanged_and_active = (
                existing is not None
                and existing.get("content_hash") == content_hash
                and existing.get("status") == "active"
            )
            if unchanged_and_active:
                continue
            now = datetime.now(timezone.utc).isoformat()
            record = dict(payload)
            record["id"] = record_id
            record["content_hash"] = content_hash
            record["created_at"] = (existing or {}).get("created_at") or now
            record["updated_at"] = now
            record["status"] = "active"
            store.put(_CORPUS_CORRECTIONS, record, record_id=record_id)
            seeded += 1

    for existing in store.all(_CORPUS_CORRECTIONS):
        rid = existing.get("_id") or existing.get("id")
        if not rid or existing.get("status") == "retired":
            continue
        project_dir = existing.get("project_dir")
        if not project_dir:
            # F7: a pre-rework row from the old bare-name id scheme. The
            # new (project_dir, name) identity supersedes it permanently —
            # nothing will ever re-seed this exact id again.
            _retire(store, rid, existing)
            continue
        present_paths = present_by_project.get(project_dir)
        if present_paths is None:
            # This project's dir was not among the ones listed this run —
            # unreachable for it specifically, not evidence its files are
            # gone. Leave it alone.
            continue
        if existing.get("path") not in present_paths:
            _retire(store, rid, existing)

    if skipped:
        logger.info(
            "seed_corpus_corrections: %d file(s) reported unparsable: %s",
            len(skipped), "; ".join(skipped),
        )
    return seeded


# ── sealed operator corrections: a signature, not a status string ──────────
#
# G1/G2 (Loki 5C276CEA): the first build of the "operator" lane trusted a
# `projects_willow_governance_decisions` row whose `status` field said
# `"sealed"` and whose `boot_correction` field was truthy — both plain JSON
# values any uid-1000 process, any Kart task (the store root is writable
# there), or the willow seat's own `store_put` (full_access) can set. Loki
# forged exactly that row in a throwaway store and it rendered at boot as
# an "operator" correction. That is F6 again, moved from a memory file to
# a database row.
#
# The fix reads Nestor's OWN database directly (never the SOIL mirror
# `seal_handler.on_seal` writes, which stays a convenience copy, not a
# trust boundary) and verifies the seal's ed25519 signature against the
# fleet's verifier keyring with `net_signer.verify_seal` — the SAME
# verifier `reloader.find_sealing_decision` and
# `manifest_grant_executor`/`manifest_grant_request` already trust for a
# seal; nothing here is a new trust primitive. A row with a forged or
# missing `seal_sig` fails `Ed25519PublicKey.verify` and is refused — there
# is no private key reachable to a uid-1000 process that could fake that.
#
# The `boot-correction: <scope>` marker (G2) lives as the FIRST LINE OF THE
# SEALED TEXT ITSELF (the Nestor pair's `target_text` — what
# `decision_bridge.propose(..., boot_correction=<scope>)` writes into the
# conclusion BEFORE the operator ever seals it), never a side field. A
# signature verifies the exact bytes it was made over; a marker anywhere
# else could be added or removed AFTER the seal by the same uid-1000 write
# path that forged the SOIL row, and the signature would still show green.
# Putting the marker inside the signed bytes makes the tag exactly as
# unforgeable as the seal.

_BOOT_CORRECTION_RE = re.compile(r"\Aboot-correction:[ \t]*(\S+)[ \t]*\r?\n(.*)\Z", re.DOTALL)


def _boot_correction_marker(text: str) -> tuple[str, str] | None:
    """Parse the grammar a sealed pair's text must carry to be read as an
    operator boot correction: a first line ``boot-correction: <scope>``,
    then the correction text. Returns ``(scope, content)`` or ``None``."""
    m = _BOOT_CORRECTION_RE.match(text or "")
    if not m:
        return None
    scope, rest = m.group(1).strip(), m.group(2).strip()
    if not rest:
        return None
    return scope, rest


def _ring_from_keyring(kr) -> dict[str, dict]:
    """The `net_signer.verify_seal` ring shape, built from the process's
    own keyring — the same shape `manifest_grant_executor._ring_from_keyring`
    and `reloader._ring_from_keyring` build, duplicated here rather than
    imported (this codebase's established pattern for this exact helper:
    a few lines, no cross-packet dependency)."""
    return {
        e.name: {"key": e.key, "kind": e.kind, "revoked_at": e.revoked_at, "compromised": e.compromised}
        for e in kr.entries()
    }


def load_sealed_corrections(*, db_path: Path | None = None,
                             ring: dict[str, dict] | None = None) -> dict[str, Any]:
    """Sealed governance decisions eligible as boot 'operator' corrections
    — Nestor-sealed, cryptographically verified, never a trusted string.

    Operator ruling `boot-corrections-trust-and-scope-2026-09-23`, ruling
    1: "sealed = operator; memory = unverified". See the module-level
    comment above this function for the G1/G2 rework this implements.

    A row whose signature does not verify, or whose verifier is not on
    the ring, is never shown and never silently dropped either — it is
    counted (`unverifiable`) and logged best-effort, so a real sealed
    decision with a rotated-out verifier is visible to whoever reads the
    logs without ever reaching a seat's boot labelled "operator". A row
    that doesn't even carry the marker is not a candidate at all — no
    keyring lookup is spent on the (likely many) sealed pairs that are
    ordinary governance decisions, not boot corrections.

    K1 (Loki 3C1BB137): `unverifiable` used to be computed and logged but
    never returned to a caller that renders boot — so a boot whose ONLY
    tagged candidates were forgeries printed "none sealed yet", exactly
    the all-clear an attacker wants. `state` now distinguishes that case
    (`"refused"` — candidates existed, all failed) from genuine emptiness
    (`"empty"` — nothing tagged at all) and from a mix (`"populated"`,
    with `unverifiable` still non-empty alongside `items`). A caller
    (`load_corpus_lanes`/`boot_context.py`) must render `unverifiable`
    whenever it is non-empty, in EITHER state — a refusal is never
    optional detail, never silently folded into "empty".

    `ring` is an injection seam for tests (the same shape
    :func:`_ring_from_keyring` builds) — production always resolves it
    from the process's own keyring when omitted.

    Returns `{"items": [...], "total": N, "state":
    "populated"|"refused"|"empty"|"unreachable", "unverifiable": [...]}`.
    State is never inferred from an empty item list alone: a database or
    keyring read failure is `"unreachable"`; zero tagged candidates at
    all is `"empty"`; one or more tagged candidates that ALL failed
    verification is `"refused"`; at least one verified is `"populated"`
    (`unverifiable` may still be non-empty alongside it).
    """
    from . import seal_handler as _seal_handler

    path = db_path if db_path is not None else _seal_handler._nestor_db_path()

    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        return {"items": [], "total": 0, "state": "unreachable",
                "cause": f"{type(exc).__name__}: {exc}", "unverifiable": []}
    try:
        rows = conn.execute(
            "SELECT id, source_norm, target_text, verifier, seal_sig, created_at "
            "FROM tm_pairs WHERE source_lang = 'decision' AND status = 'sealed' "
            "AND seal_sig != '' AND superseded_by = '' ORDER BY created_at DESC"
        ).fetchall()
    except sqlite3.Error as exc:
        return {"items": [], "total": 0, "state": "unreachable",
                "cause": f"{type(exc).__name__}: {exc}", "unverifiable": []}
    finally:
        conn.close()

    candidates = [r for r in rows if _boot_correction_marker(r[2]) is not None]
    if not candidates:
        return {"items": [], "total": 0, "state": "empty", "unverifiable": []}

    from . import net_signer

    if ring is None:
        from . import keyring as _keyring

        try:
            ring_kr = _keyring.get_keyring()
        except _keyring.KeyringError as exc:
            return {"items": [], "total": 0, "state": "unreachable",
                    "cause": f"keyring unusable: {exc}", "unverifiable": []}
        if ring_kr is None:
            return {"items": [], "total": 0, "state": "unreachable",
                    "cause": "no keyring configured — a seal cannot be verified "
                             "without a ring to verify it against",
                    "unverifiable": []}
        ring = _ring_from_keyring(ring_kr)

    items: list[dict[str, str]] = []
    unverifiable: list[str] = []
    for pair_id, source_norm, target_text, verifier, seal_sig, created_at in candidates:
        sealed = {"source_norm": source_norm, "target_text": target_text,
                  "verifier": verifier, "seal_sig": seal_sig, "created_at": created_at}
        ok, reason, _field = net_signer.verify_seal(sealed, ring, max_age_s=None)
        if not ok:
            unverifiable.append(f"{pair_id} ({verifier!r}): {reason}")
            continue
        marker = _boot_correction_marker(target_text)
        if marker is None:
            continue  # can't happen (filtered into candidates above) — defensive
        scope, content = marker
        items.append({
            "content": content,
            "scope": scope,
            "verifier": verifier,
            "sealed_at": str(created_at or ""),
            "pair_id": pair_id,
        })

    if unverifiable:
        logger.info(
            "load_sealed_corrections: %d marked pair(s) failed verification: %s",
            len(unverifiable), "; ".join(unverifiable),
        )
    items.sort(key=lambda r: r["sealed_at"], reverse=True)
    if items:
        state = "populated"
    elif unverifiable:
        # K1: candidates existed (the marker was there) and EVERY one
        # failed verification — this must never read the same as "nothing
        # was ever tagged" (empty). A boot whose only tagged pairs are
        # forgeries has to say so.
        state = "refused"
    else:
        state = "empty"  # defensive: candidates non-empty implies one of the above
    return {"items": items, "total": len(items), "state": state, "unverifiable": unverifiable}


def load_corpus_lanes(project_root: str | None = None) -> dict[str, Any]:
    """Read operator corpus lanes for SessionStart injection.

    Two distinctly-trusted correction lanes
    (`boot-corrections-trust-and-scope-2026-09-23`):

      - `sealed_corrections` / `sealed_lane_state`: Nestor-sealed,
        signature-verified governance decisions — the only thing labelled
        "operator". See :func:`load_sealed_corrections`. Scoped the same
        way memory notes are: a sealed pair's `boot-correction: fleet`
        marker reaches every seat, anything else is scoped to the
        matching repo name.
      - `memory_notes` / `memory_note_total`: `feedback`-type memory
        files, always labelled unverified, scoped to the seat's own
        project (:func:`resolve_own_project`, EXACT match — G3) plus
        anything explicitly marked `scope: fleet`. Ranked own-project
        first, then by file-system mtime (`fs_modified` — G4, never the
        note's own self-reported `modified` claim) within each group.

    `project_root` is the seat's resolved project root
    (`enter_result["project"]["root"]` from `session_enter`) — defaults to
    `WILLOW_PROJECT_ROOT`/`Path.cwd()` via `resolve_own_project` when
    omitted (a bare script, a test).

    K1 (Loki 3C1BB137): `sealed_unverifiable` is always returned, in
    every `sealed_lane_state`, so a refused seal can never be silently
    dropped. K2: `memory_own_is_fallback` tells a caller when the
    own-project match came from the ancestor fallback rather than an
    exact match, so it can be labelled rather than presented as this
    seat's own project.
    """
    from .session_inject import (
        CONFIRMATION_EXCERPT_CHARS,
        CORRECTION_EXCERPT_CHARS,
        MAX_CORRECTIONS,
        MAX_HUMAN_CONFIRMATIONS,
        MAX_PREFERENCES,
        MAX_SEALED_CORRECTIONS,
        PREFERENCE_EXCERPT_CHARS,
        excerpt_corpus,
    )

    store = _corpus_store()

    own = resolve_own_project(project_root)
    repo_name = own["repo_name"]
    own_project_dir = own["project_dir"] if own["state"] == "populated" else None

    sealed = load_sealed_corrections()
    sealed_in_scope = [
        it for it in sealed["items"]
        if it["scope"] == _FLEET_SCOPE_VALUE or (repo_name and it["scope"] == repo_name)
    ]
    sealed_shown = [
        excerpt_corpus(item["content"], CORRECTION_EXCERPT_CHARS)
        for item in sealed_in_scope[:MAX_SEALED_CORRECTIONS]
    ]

    def _is_own(r: dict[str, Any]) -> bool:
        return bool(own_project_dir) and r.get("project_dir") == own_project_dir

    all_notes = [r for r in store.all(_CORPUS_CORRECTIONS) if r.get("status") == "active"]
    in_scope = [r for r in all_notes if r.get("scope") == _FLEET_SCOPE_VALUE or _is_own(r)]

    # Stable two-pass sort: most-recently-edited (by FILE SYSTEM mtime —
    # G4) first WITHIN a relevance group, own-project group ahead of
    # fleet-wide-from-elsewhere. Sorting by the secondary key first and
    # the primary key last relies on sort stability to compose correctly.
    in_scope.sort(key=lambda r: r.get("fs_modified") or r.get("updated_at") or "", reverse=True)
    in_scope.sort(key=lambda r: 0 if _is_own(r) else 1)

    memory_shown = []
    for r in in_scope[:MAX_CORRECTIONS]:
        label = "fleet" if r.get("scope") == _FLEET_SCOPE_VALUE else r.get("project", "?")
        text = excerpt_corpus(r.get("content", ""), CORRECTION_EXCERPT_CHARS)
        memory_shown.append(f"[unverified:{label}] {text} ({r.get('path', '')})")

    prefs = store.all(_CORPUS_PREFERENCES) or []
    confs = store.all(_CORPUS_CONFIRMATIONS) or []
    prefs.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    confs.sort(key=lambda r: r.get("last_seen", r.get("created_at", "")), reverse=True)
    human_confs = [
        r.get("content", "")
        for r in confs
        if r.get("content") and str(r.get("source", "")).startswith("prompt_submit")
    ]

    return {
        "sealed_corrections": sealed_shown,
        "sealed_correction_total": len(sealed_in_scope),
        "sealed_lane_state": sealed["state"],
        # K1: always carried through, in every state, so a caller can never
        # accidentally drop a refusal on the floor by only checking state.
        "sealed_unverifiable": sealed["unverifiable"],
        "memory_notes": memory_shown,
        "memory_note_total": len(in_scope),
        "memory_own_project_state": own["state"],
        "memory_own_repo_name": repo_name,
        # K2/Watch labeling: True when the own-project match came from the
        # ancestor fallback (e.g. seat/heimdallr resolving to its repo
        # root) rather than an exact match on the seat's own resolved
        # path — a caller must label these notes as belonging to another
        # project, not present them as this seat's own.
        "memory_own_is_fallback": own["state"] == "populated" and not own["exact"],
        "preferences": [
            excerpt_corpus(r.get("content", ""), PREFERENCE_EXCERPT_CHARS)
            for r in prefs[:MAX_PREFERENCES]
            if r.get("content")
        ],
        "preference_total": len(prefs),
        "confirmations": [
            excerpt_corpus(c, CONFIRMATION_EXCERPT_CHARS)
            for c in human_confs[:MAX_HUMAN_CONFIRMATIONS]
        ],
        "confirmation_total": len(human_confs),
    }


def seed_context(agent_id: str, *, destination: str = "session_enter") -> dict[str, Any]:
    """session_enter payload wrapper with exposure slice (AS-8)."""
    from . import exposure as exp

    block: dict[str, Any] = {"agent_seed": load_agent_seed(agent_id)}
    sliced = exp.build_exposure_slice(agent_id, destination=destination)
    if sliced.get("ok"):
        block["agent_seed_exposure"] = {
            "destination": sliced["destination"],
            "preset": sliced["preset"],
            "resolved_from": sliced["resolved_from"],
            "fields": sliced.get("fields"),
            "body": sliced["body"],
        }
    return block
