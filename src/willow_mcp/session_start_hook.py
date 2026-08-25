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
    # PR4 of the identity-in-session plan: refuse to enter with an inferred
    # identity. The prior default silently assigned app_id="willow"
    # (orchestrator seat) to any workspace without WILLOW_APP_ID set — the
    # exact anti-pattern nestor.memory._same_verifier codified ("empty is
    # unknown, not a person"). Every existing willow orchestrator workspace
    # must set WILLOW_APP_ID=willow explicitly next to the
    # WILLOW_HUMAN_ORCHESTRATOR flag it already carries; specialist
    # workspaces must set their own app_id or refuse at boot.
    app_id = os.environ.get("WILLOW_APP_ID", "").strip()
    if not app_id:
        message = (
            "WILLOW_APP_ID is not set on this MCP server env. Willow no longer "
            "defaults to 'willow' — an unset value used to silently claim the "
            "orchestrator seat. Set WILLOW_APP_ID=willow (orchestrator "
            "workspace) or WILLOW_APP_ID=<specialist_id> (specialist workspace) "
            "in your MCP config next to WILLOW_HUMAN_ORCHESTRATOR. See "
            "docs/design/human-orchestrator.md wiring checklist item 2."
        )
        logging.getLogger("willow_mcp.session_start_hook").error(message)
        return {"additional_context": f"WILLOW session_enter FAILED — {message}"}
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
