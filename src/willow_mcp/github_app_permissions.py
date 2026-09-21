"""A missing GitHub App permission files ONE named human_required item.

Gap 4464a63db1a9 (apk/keyboard-act): every App-token verb — ``pr_checks_read``,
``pr_open_execute``, ``pr_update_execute``, ``git_push_execute`` — already
detects when the willows-bot App lacks a permission and refuses with the
exact settings path in prose. The operator learned of the ``actions`` gap on
2026-09-21 from the desk relaying that prose, then granted it in the GitHub
UI. Granting stays the operator's act (the App's permissions are an admin
surface the fleet does not hold); *telling the operator once* is the
fleet's. This module is that telling.

``file_permission_ask`` enqueues a ``human_required`` item of kind
``onboarding`` titled ``GitHub App: grant <permission>:<level> to
willows-bot``, deduped on ``(permission, level)`` while an open item exists —
two verbs hitting the same wall in one tick file one row, not two. Resolving
is the operator's (``human_required_resolve``); a resolved item does not block
a later re-file, because the wall can come back (a new org, a re-install
that dropped the permission).

The dedupe scan reads the newest 200 OPEN ``onboarding`` items (``list_queue``'s
bound); past that a duplicate could file. The live queue holds ~30 open items
in total, so the bound is stated rather than engineered around (Loki
8A23D1AE).

Never raises: the caller is already refusing, and a queue that cannot be
written must not turn a legible refusal into a crash. Every exit is a dict
with ``state``: ``filed`` (new row), ``already`` (open row exists),
``unreachable`` (the queue could not be read or written — ``reason`` names
why).
"""
from __future__ import annotations

from typing import Any, Optional

#: GitHub App settings → Permissions & events → <section> → <permission>. The
#: section is where the operator's click lands; naming it saves the search.
_SECTIONS: dict[str, str] = {
    "actions": "Repository permissions → Actions",
    "checks": "Repository permissions → Checks",
    "contents": "Repository permissions → Contents",
    "pull_requests": "Repository permissions → Pull requests",
    "workflows": "Repository permissions → Workflows",
    "issues": "Repository permissions → Issues",
    "metadata": "Repository permissions → Metadata",
    "members": "Organization permissions → Members",
}

_LEVEL_WORDS = {"read": "Read-only", "write": "Read and write", "admin": "Admin"}

APP_NAME = "willows-bot"
KIND = "onboarding"


def title_for(permission: str, level: str) -> str:
    return f"GitHub App: grant {permission}:{level} to {APP_NAME}"


def settings_path(permission: str, level: str) -> str:
    section = _SECTIONS.get(permission, f"Repository permissions → {permission}")
    word = _LEVEL_WORDS.get(level, level)
    return f"App settings → Permissions & events → {section} → {word}"


def _open_item_for(store, permission: str, level: str) -> Optional[dict]:
    from . import human_loop

    title = title_for(permission, level)
    # list_queue is newest-first and bounded; scan open onboarding items only.
    for item in human_loop.list_queue(store, status="open", kind=KIND, limit=200):
        if item.get("title") == title:
            return item
    return None


def file_permission_ask(
    store,
    *,
    app_id: str,
    verb: str,
    repo: str,
    permission: str,
    level: str = "read",
    current: Optional[str] = None,
) -> dict[str, Any]:
    """File (or find) the one human_required item for a missing App permission.

    ``verb`` names the caller (``pr_checks_read``), ``repo`` the repo it was
    reading, ``permission``/``level`` what the App needs, ``current`` what it
    has (``None`` = absent). Returns ``{state, human_required_id, title}``.
    """
    permission = (permission or "").strip()
    level = (level or "read").strip()
    if not permission:
        return {"state": "unreachable", "reason": "no permission named"}
    if store is None:
        return {"state": "unreachable", "reason": "no store bound — nowhere to file the ask"}
    try:
        existing = _open_item_for(store, permission, level)
    except Exception as exc:  # noqa: BLE001 — a queue that cannot be read is reported, not raised
        return {"state": "unreachable", "reason": f"queue unreadable: {type(exc).__name__}: {exc}"}
    title = title_for(permission, level)
    if existing:
        return {"state": "already", "human_required_id": existing.get("id"), "title": title}

    have = f"{current!r}" if current else "absent"
    summary = (
        f"{verb} on {repo} needs the {APP_NAME} App's `{permission}` permission at "
        f"{level!r} (currently {have}). In GitHub: {settings_path(permission, level)}; "
        f"then approve the updated permissions in each org's Installed GitHub Apps. "
        f"Resolve this item once granted — the verb re-checks the token on every call."
    )
    try:
        from . import human_loop

        row = human_loop.enqueue(
            store, kind=KIND, title=title, summary=summary, priority="normal",
            source_agent=app_id or "", source_ref=f"{verb}:{repo}:{permission}",
        )
    except Exception as exc:  # noqa: BLE001
        return {"state": "unreachable", "reason": f"queue unwritable: {type(exc).__name__}: {exc}"}
    return {"state": "filed", "human_required_id": row.get("id"), "title": title}
