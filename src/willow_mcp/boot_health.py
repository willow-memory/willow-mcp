"""Boot liveness assembly for SessionStart (degraded verdict)."""

from __future__ import annotations

import os
from typing import Any

from .db import get_pg
from .paths import store_root
from . import split_brain


def postgres_status() -> str:
    return "up" if get_pg() else "down"


def boot_verdict(app_id: str) -> dict[str, Any]:
    """Lightweight liveness probe — no MCP gate, safe from hooks."""
    problems: list[str] = []
    store_path = store_root()
    try:
        store_path.mkdir(parents=True, exist_ok=True)
        if not os.access(store_path, os.W_OK):
            problems.append("store path not writable")
    except Exception as exc:
        problems.append(f"store not writable ({exc})")

    if not get_pg():
        problems.append("postgres unreachable")

    verdict = "ok" if not problems else "degraded"
    return {"verdict": verdict, "postgres": postgres_status(), "problems": problems}


def degraded_boot_line(app_id: str) -> str | None:
    block = boot_verdict(app_id)
    if block["verdict"] == "ok":
        return None
    joined = "; ".join(block["problems"]) or "liveness checks failed"
    return f"BOOT DEGRADED — do not act until resolved: {joined}"


def split_brain_boot_line() -> str | None:
    """SessionStart surface for the trust-artifact split-brain check (hook
    spec #4; feedback_eliminate-split-brains). Read-only: delegates entirely
    to `split_brain.scan()`, which only stats candidate paths. Report only —
    never resolves or repairs; returns None when everything is clean."""
    try:
        report = split_brain.scan()
    except Exception as exc:
        return f"SPLIT-BRAIN CHECK COULD NOT RUN: {str(exc)[:160]}"
    if report.get("status") != "warn":
        return None
    divergent = [name for name, a in report.get("artifacts", {}).items()
                 if a.get("status") == "warn"]
    return ("SPLIT-BRAIN — divergent resolvable copies found for: "
            + ", ".join(sorted(divergent))
            + " (report only; see diagnostic_summary().checks.split_brain for candidate paths)")
