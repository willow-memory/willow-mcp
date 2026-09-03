#!/usr/bin/env python3
"""Cross-repo drift-guard: assert a vendored file matches its upstream source.

Companion to the in-repo hash pin in tests/test_stance_friction.py. That pin
catches LOCAL edits to the vendored copy; this catches the OTHER direction —
willow-gate advancing while the vendored copy stays behind. That is exactly how
the stance_friction block went missing (box audit theme ①: a manual copy with
no drift-guard). Run in CI with willow-gate checked out beside this repo.

Usage:
    check_vendor_sync.py <path-to-upstream/friction_floor.py>

Compares the module body (the module docstring onward — everything the header
promises is "byte-for-byte") of the INSTALLED forge.friction_floor — the
scorer's home since forge-play became a dependency; src/willow_mcp/
friction_floor.py only re-exports it — and exits non-zero with a unified diff
on any divergence. If the upstream file is absent (private repo checked out without
a token), it soft-skips with a warning so it never blocks a PR on its own; the
in-repo hash guard still enforces against local edits.
"""
from __future__ import annotations

import difflib
import sys
from pathlib import Path

from vendor_drift import annotate, classify


def vendored_path() -> Path:
    """Where the friction scorer's body lives now: the installed forge-play.

    src/willow_mcp/friction_floor.py is a re-export seam since forge-play
    became a dependency (2026-09-03); the bytes this guard compares against
    willow-gate are the Forge's. Same rule as tests/test_stance_friction.py's
    hash pin, which follows the body the same way."""
    try:
        import forge.friction_floor as home
    except ImportError as e:  # the dependency is declared; its absence is the finding
        raise SystemExit(f"::error title=vendor-sync::forge-play is not installed ({e}); "
                         "pip install -e . first — the scorer's body lives there now") from e
    return Path(home.__file__).resolve()


def body(text: str) -> str:
    """The vendored contract: module docstring (first triple-quote) → EOF."""
    return text[text.index('"""'):]


def main(argv: list) -> int:
    if len(argv) != 2:
        print("usage: check_vendor_sync.py <upstream friction_floor.py>", file=sys.stderr)
        return 2
    upstream = Path(argv[1])
    if not upstream.is_file():
        print(f"::warning title=vendor-sync skipped::{upstream} not found; set "
              "FLEET_RO_TOKEN to enforce the cross-repo check. The in-repo hash "
              "guard (tests/test_stance_friction.py) still ran.")
        return 0
    mine = body(vendored_path().read_text())
    theirs = body(upstream.read_text())
    if mine == theirs:
        print("forge.friction_floor (the scorer's home, re-exported here) is in sync with willow-gate ✓")
        return 0
    verdict = classify(upstream, mine, body)
    sys.stdout.write(annotate(
        "vendor", "forge-play/forge/friction_floor.py (via src/willow_mcp/friction_floor.py)", verdict,
        "Re-sync it in the Forge (forge-play/Forge, forge/friction_floor.py), bump the "
        "forge-play floor here, and update the pinned hash in tests/test_stance_friction.py."))
    sys.stdout.writelines(difflib.unified_diff(
        theirs.splitlines(True), mine.splitlines(True),
        fromfile="willow-gate/friction_floor.py", tofile="forge-play/friction_floor.py"))
    return 1 if verdict.fatal else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
