#!/usr/bin/env python3
"""Cross-repo drift-guard: assert a vendored file matches its upstream source.

Companion to the in-repo hash pin in tests/test_stance_friction.py. That pin
catches LOCAL edits to the vendored copy; this catches the OTHER direction —
willow-gate advancing while the vendored copy stays behind. That is exactly how
the stance_friction block went missing (box audit theme ①: a manual copy with
no drift-guard). Run in CI with willow-gate checked out beside this repo.

Usage:
    check_vendor_sync.py <path-to-upstream/friction_floor.py>

Compares the module body (the module docstring onward — everything the vendor
header promises is "byte-for-byte") and exits non-zero with a unified diff on
any divergence. If the upstream file is absent (private repo checked out without
a token), it soft-skips with a warning so it never blocks a PR on its own; the
in-repo hash guard still enforces against local edits.
"""
from __future__ import annotations

import difflib
import sys
from pathlib import Path

VENDORED = Path(__file__).resolve().parents[1] / "src/willow_mcp/friction_floor.py"


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
    mine = body(VENDORED.read_text())
    theirs = body(upstream.read_text())
    if mine == theirs:
        print("vendored friction_floor.py is in sync with willow-gate ✓")
        return 0
    sys.stdout.write(
        "::error title=vendor drift::src/willow_mcp/friction_floor.py has drifted "
        "from willow-memory/willow-gate. Re-sync it (procedure in "
        "tests/test_stance_friction.py) and update the pinned hash there.\n")
    sys.stdout.writelines(difflib.unified_diff(
        theirs.splitlines(True), mine.splitlines(True),
        fromfile="willow-gate/friction_floor.py", tofile="willow-mcp/friction_floor.py"))
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
