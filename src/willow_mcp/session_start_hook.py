"""Supported-client SessionStart bridge to native ``session_enter``."""
from __future__ import annotations

import json
import logging
import os
import sys
import uuid

from .boot_context import build_boot_lines
from .seed_loader import seed_corpus_corrections


def handle(payload: dict) -> dict:
    from .server import session_enter

    source = str(payload.get("source") or "startup")
    try:
        seed_corpus_corrections()
    except Exception:
        logging.getLogger("willow_mcp.session_start_hook").debug(
            "seed_corpus_corrections failed", exc_info=True)

    workspace = (
        payload.get("workspace")
        or payload.get("workspace_root")
        or payload.get("cwd")
        or os.environ.get("WILLOW_PROJECT_ROOT", "")
    )
    session_id = str(
        payload.get("session_id") or payload.get("conversation_id") or uuid.uuid4()
    )
    app_id = os.environ.get("WILLOW_APP_ID", "willow")
    result = session_enter(
        app_id=app_id,
        session_id=session_id,
        project=os.environ.get("WILLOW_HANDOFF_PROJECT", ""),
        workspace=str(workspace or ""),
    )
    boot_lines = build_boot_lines(app_id, session_id, source, result)
    result["boot_context"] = "\n".join(boot_lines)
    return {"additional_context": json.dumps(result, sort_keys=True)}


def main() -> None:
    try:
        payload = json.load(sys.stdin)
        print(json.dumps(handle(payload if isinstance(payload, dict) else {})))
    except Exception as exc:
        message = f"WILLOW session_enter FAILED — orientation did not run: {exc}"
        print(f"[willow.session_start] {message}", file=sys.stderr)
        print(json.dumps({"additional_context": message}))


if __name__ == "__main__":
    main()
