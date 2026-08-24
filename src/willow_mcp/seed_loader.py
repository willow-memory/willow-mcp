"""Load agent_seed_v1 from $WILLOW_HOME/seeds/{agent_id}.json.

AS-3: advisory load on session_enter; pending ratification surfaces gaps.
AS-4: PGP verify when WILLOW_PGP_FINGERPRINT is set; ratified + bad sig → untrusted.

See docs/design/agent-seed.md.
"""

from __future__ import annotations

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


def claude_memory_dir() -> Path | None:
    """Resolve Claude Code project memory dir for the open repo (operator path)."""
    projects = Path.home() / ".claude" / "projects"
    if not projects.is_dir():
        return None
    repo_name = _project_repo_name()
    for entry in sorted(projects.iterdir()):
        if not entry.is_dir():
            continue
        slug = entry.name.lower().lstrip("-")
        if repo_name.replace("-", "") in slug.replace("-", ""):
            memory = entry / "memory"
            if memory.is_dir():
                return memory
    return None


def _corpus_store() -> Store:
    return Store(str(store_root()))


def seed_corpus_corrections() -> int:
    """Idempotent feedback_*.md → corpus_corrections (operator memory dir)."""
    memory_dir = claude_memory_dir()
    if memory_dir is None:
        return 0
    store = _corpus_store()
    seeded = 0
    for fpath in sorted(memory_dir.glob("feedback_*.md")):
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
            body = text.split("---", 2)[-1].strip() if "---" in text else text.strip()
            rule = ""
            for line in body.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("@"):
                    rule = line[:200]
                    break
            if not rule:
                continue
            record_id = fpath.stem
            if store.get(_CORPUS_CORRECTIONS, record_id):
                continue
            store.put(
                _CORPUS_CORRECTIONS,
                {
                    "id": record_id,
                    "content": rule,
                    "source": fpath.name,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                },
                record_id=record_id,
            )
            seeded += 1
        except Exception:
            logger.debug("seed store_put failed for %s", record_id, exc_info=True)
            continue
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
