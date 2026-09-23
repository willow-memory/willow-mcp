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


def memory_dirs() -> list[Path]:
    """Every Claude Code project memory dir on this box, not just this repo's.

    Bounded discovery: one listing of ``~/.claude/projects`` plus one
    ``is_dir()`` check on each entry's ``memory/`` subdirectory — never a
    recursive walk. ``memory/`` is the boundary Claude Code itself writes
    inside for a project, so nothing outside it is read. Order is
    deterministic (sorted by project dir name) so seeding is reproducible.
    """
    projects = Path.home() / ".claude" / "projects"
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


def claude_memory_dir() -> Path | None:
    """Resolve Claude Code project memory dir for the open repo (operator path).

    Kept as the single-project lookup some callers still want; seeding
    itself now reads every project's memory dir via :func:`memory_dirs`.
    """
    repo_name = _project_repo_name()
    for memory in memory_dirs():
        slug = memory.parent.name.lower().lstrip("-")
        if repo_name.replace("-", "") in slug.replace("-", ""):
            return memory
    return None


def _corpus_store() -> Store:
    return Store(str(store_root()))


# Frontmatter shape Claude Code memory files use: a leading `---` block of
# flat `key: value` pairs plus one nested block (`metadata:`) with the same
# shape, indented. Not a general YAML parser — PyYAML is a test-only
# dependency here (pyproject.toml `[test]` extra), and this loader runs on
# every SessionStart in every install, so it stays stdlib-only and handles
# exactly the shape these files are written in. Anything it can't parse this
# way is reported by name and skipped, never guessed at.
_FRONTMATTER_RE = re.compile(r"\A---[ \t]*\n(.*?)\n---[ \t]*\n(.*)", re.DOTALL)

# Which frontmatter `metadata.type` values feed the operator-corrections
# corpus (as opposed to preferences/confirmations, seeded elsewhere).
# `feedback` is the direct case — an operator correcting a behavior pattern
# in the moment, the exact shape the legacy `feedback_*.md` glob targeted.
# `project` is included too: in this repo's memory files (canonical-verifier-
# name.md, port-map-and-signing-origin.md) `project`-typed entries are also
# operator-set facts that supersede a stale belief ("if it drifts back to
# `sean`, every desk open is refused") — the same "don't repeat the mistake"
# job as feedback, just about repo state rather than behavior. `user` is
# left out: it's cross-project persona/preference material, not a correction
# of something that was wrong — it belongs in the preferences lane this
# function doesn't own. `reference` is left out: pure documentation, nothing
# to act differently on. MEMORY.md itself is never a record — it's the
# index, excluded by name below.
_CORRECTION_MEMORY_TYPES = frozenset({"feedback", "project"})


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        inner = value[1:-1]
        if value[0] == '"':
            inner = inner.replace('\\"', '"').replace("\\\\", "\\")
        return inner
    return value


def _parse_frontmatter_block(block: str) -> dict[str, Any] | None:
    data: dict[str, Any] = {}
    nested: dict[str, Any] | None = None
    for raw_line in block.splitlines():
        if not raw_line.strip():
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
        if indent == 0:
            if not value:
                nested = {}
                data[key] = nested
            else:
                nested = None
                data[key] = _unquote(value)
        else:
            if nested is None:
                return None
            nested[key] = _unquote(value)
    return data


def _first_content_line(body: str, limit: int = 200) -> str:
    for line in body.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("@"):
            return line[:limit]
    return ""


def _content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


def _legacy_record(fpath: Path, body: str) -> tuple[str, dict[str, str]] | None:
    """`feedback_*.md` with no (or unparseable) frontmatter — the original
    behavior, kept so nothing that seeds today stops seeding."""
    rule = _first_content_line(body)
    if not rule:
        return None
    return fpath.stem, {"content": rule, "source": fpath.name, "memory_type": "feedback"}


def _memory_record(fpath: Path) -> tuple[str | None, dict[str, str] | None, str | None]:
    """Extract (record_id, record, skip_reason) for one memory file.

    ``skip_reason`` is only set when the file looked like it should seed but
    couldn't be read this way — reported by name, never seeded as garbage.
    A file that parses fine but is out of scope (wrong type, empty) returns
    ``(None, None, None)``: nothing to report, nothing to seed.
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
            rec = _legacy_record(fpath, body)
            return (rec[0], rec[1], None) if rec else (None, None, None)
        return None, None, None

    fm = _parse_frontmatter_block(m.group(1))
    body = m.group(2)
    if fm is None:
        if is_legacy_name:
            rec = _legacy_record(fpath, body)
            return (rec[0], rec[1], None) if rec else (None, None, None)
        return None, None, "frontmatter did not parse"

    metadata = fm.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    mtype = str(metadata.get("type") or "").strip().lower()
    if not mtype and is_legacy_name:
        mtype = "feedback"
    if mtype not in _CORRECTION_MEMORY_TYPES:
        return None, None, None

    record_id = str(fm.get("name") or "").strip() or fpath.stem
    content = str(fm.get("description") or "").strip() or _first_content_line(body)
    if not content:
        return None, None, None
    return record_id, {
        "content": content[:400],
        "source": fpath.name,
        "memory_type": mtype,
    }, None


def seed_corpus_corrections() -> int:
    """Operator memory (frontmatter `type: feedback|project`, plus legacy
    `feedback_*.md`) → `corpus_corrections`, across every discovered memory
    dir (:func:`memory_dirs`). Keyed by frontmatter `name` (path stem for
    legacy files) and a content hash: unchanged content is skipped, changed
    content updates the same record in place (`Store.put` upserts by
    `record_id`), and a record this run no longer sees among this loader's
    own rows is retired (soft-deleted — `Store.delete`, not a hard delete)
    rather than left to serve stale content forever.
    """
    store = _corpus_store()
    seeded = 0
    seen_ids: set[str] = set()
    skipped: list[str] = []

    for memory_dir in memory_dirs():
        for fpath in sorted(memory_dir.glob("*.md")):
            if fpath.name == "MEMORY.md":
                continue
            try:
                record_id, payload, skip_reason = _memory_record(fpath)
            except Exception:
                logger.debug("seed_corpus_corrections: failed on %s", fpath, exc_info=True)
                skipped.append(f"{fpath}: unexpected error")
                continue
            if skip_reason:
                skipped.append(f"{fpath}: {skip_reason}")
                continue
            if not record_id or not payload:
                continue
            seen_ids.add(record_id)
            content_hash = _content_hash(payload["content"])
            existing = store.get(_CORPUS_CORRECTIONS, record_id)
            if existing is not None and existing.get("content_hash") == content_hash:
                continue
            now = datetime.now(timezone.utc).isoformat()
            store.put(
                _CORPUS_CORRECTIONS,
                {
                    "id": record_id,
                    "content": payload["content"],
                    "content_hash": content_hash,
                    "source": payload["source"],
                    "memory_type": payload["memory_type"],
                    "created_at": (existing or {}).get("created_at") or now,
                    "updated_at": now,
                },
                record_id=record_id,
            )
            seeded += 1

    # Retire rows this loader owns (tagged with memory_type) that no file
    # accounted for this run. Untagged rows predate this change or come from
    # a different writer, if any, and are left alone.
    for existing in store.all(_CORPUS_CORRECTIONS):
        rid = existing.get("_id") or existing.get("id")
        if not rid or rid in seen_ids or "memory_type" not in existing:
            continue
        store.delete(_CORPUS_CORRECTIONS, rid)

    if skipped:
        logger.info(
            "seed_corpus_corrections: %d file(s) reported unparsable: %s",
            len(skipped), "; ".join(skipped),
        )
    return seeded


def load_corpus_lanes() -> dict[str, Any]:
    """Read operator corpus lanes for SessionStart injection."""
    from .session_inject import (
        CONFIRMATION_EXCERPT_CHARS,
        CORRECTION_EXCERPT_CHARS,
        MAX_CORRECTIONS,
        MAX_HUMAN_CONFIRMATIONS,
        MAX_PREFERENCES,
        PREFERENCE_EXCERPT_CHARS,
        excerpt_corpus,
    )

    store = _corpus_store()
    corrs = store.all(_CORPUS_CORRECTIONS) or []
    prefs = store.all(_CORPUS_PREFERENCES) or []
    confs = store.all(_CORPUS_CONFIRMATIONS) or []
    corrs.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    prefs.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    confs.sort(key=lambda r: r.get("last_seen", r.get("created_at", "")), reverse=True)
    human_confs = [
        r.get("content", "")
        for r in confs
        if r.get("content") and str(r.get("source", "")).startswith("prompt_submit")
    ]
    return {
        "corrections": [
            excerpt_corpus(r.get("content", ""), CORRECTION_EXCERPT_CHARS)
            for r in corrs[:MAX_CORRECTIONS]
            if r.get("content")
        ],
        "correction_total": len(corrs),
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
