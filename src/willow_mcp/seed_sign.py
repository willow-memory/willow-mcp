"""AS-4: operator-terminal sign-seed — ratify home seed + detached .sig.

Host-side only (not Kart, not an MCP tool). See docs/design/agent-seed.md.
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from . import onescript_clock, pgp
from .paths import willow_home
from .seed_loader import load_seed_document, seed_path


def _utc_now() -> str:
    """In the one script's ``seconds_z`` format, from its one clock (flatten-2 F8:
    "Using the onescript at every path."). ``$ONESCRIPT_NOW`` pins it. With no one
    script reachable this falls back to the carried ``clock_local`` and says so (``onescript_clock.SOURCE``)."""
    return onescript_clock.clock().seconds_z()


def sign_seed(
    agent_id: str,
    *,
    ratifier_agent_id: str = "sean",
    dry_run: bool = False,
) -> dict[str, Any]:
    """Mark seed ratified, write home JSON, detach-sign → .sig."""
    key = (agent_id or "").strip()
    path = seed_path(key)
    if path is None:
        return {"ok": False, "error": "invalid_agent_id", "agent_id": key}

    data, err = load_seed_document(key)
    if err:
        return {"ok": False, "error": err, "agent_id": key, "path": str(path)}

    assert data is not None
    rel = f"seeds/{key}.json"
    sig_rel = f"{rel}.sig"

    seed_block = dict(data.get("seed") or {})
    rat = dict(seed_block.get("ratification") or {})
    rat.update(
        {
            "status": "ratified",
            "ratifier_agent_id": ratifier_agent_id,
            "ratified_at": _utc_now(),
            "sig_path": sig_rel,
        }
    )
    seed_block["ratification"] = rat
    data["seed"] = seed_block

    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "agent_id": key,
            "path": str(path.relative_to(willow_home())),
            "sig_path": sig_rel,
            "ratification": rat,
        }

    try:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    except OSError as e:
        return {"ok": False, "error": f"write failed: {e}", "agent_id": key}

    signed, detail = pgp.sign_detached(path)
    out: dict[str, Any] = {
        "ok": signed,
        "agent_id": key,
        "path": str(path.relative_to(willow_home())),
        "sig_path": sig_rel,
        "ratification": rat,
        "signed": signed,
        "sign_detail": detail,
    }
    if pgp.pgp_enabled():
        ok, reason = pgp.verify_detached(path)
        out["verify"] = {"ok": ok, "reason": reason}
    return out


def sign_seed_cli_main() -> None:
    parser = argparse.ArgumentParser(
        prog="willow-mcp-sign-seed",
        description="Ratify $WILLOW_HOME/seeds/{agent_id}.json and detach-sign (operator terminal)",
    )
    parser.add_argument("agent_id", help="agent id (e.g. hanuman, sean)")
    parser.add_argument(
        "--ratifier",
        default="sean",
        help="ratifier_agent_id written into seed.ratification (default: sean)",
    )
    parser.add_argument("--dry-run", action="store_true", help="report changes without writing")
    args = parser.parse_args()
    print(json.dumps(sign_seed(args.agent_id, ratifier_agent_id=args.ratifier, dry_run=args.dry_run), indent=2))


def main() -> None:
    sign_seed_cli_main()
