#!/usr/bin/env python3
"""Cross-repo drift-guard: assert the vendored mem_ratify matches upstream.

Companion to the in-repo hash pin in tests/test_mem_ratify.py. That pin catches
LOCAL edits to the vendored copy; this catches the OTHER direction — mem_ratify
advancing in the willow repo while the vendored copy here stays behind. That is
box audit theme ①: a manual copy with no drift-guard is how the stance_friction
block went missing. Same soft-skip posture as scripts/check_vendor_sync.py.

Usage:
    check_mem_ratify_sync.py <path-to-upstream/mem_ratify>

Compares the module body (module docstring onward — everything the vendor header
promises is "byte-for-byte") of each vendored file against its upstream twin and
exits non-zero with a unified diff on any divergence. If the upstream tree is
absent (private repo checked out without a token), it soft-skips with a warning
so it never blocks a PR on its own; the in-repo hash guard still enforces against
local edits.
"""
from __future__ import annotations

import difflib
import sys
from pathlib import Path

VENDORED_DIR = Path(__file__).resolve().parents[1] / "src/willow_mcp/mem_ratify"
# Files whose body must stay byte-for-byte with upstream. The vendored tree may
# add its own pieces (none today); only these are contract-bound.
FILES = ("ratify.py", "__init__.py")


def body(text: str) -> str:
    """The vendored contract: module docstring (first triple-quote) -> EOF."""
    return text[text.index('"""'):]


def main(argv: list) -> int:
    if len(argv) != 2:
        print("usage: check_mem_ratify_sync.py <upstream mem_ratify dir>", file=sys.stderr)
        return 2
    upstream_dir = Path(argv[1])
    if not upstream_dir.is_dir():
        print(f"::warning title=mem_ratify-sync skipped::{upstream_dir} not found; set "
              "FLEET_RO_TOKEN to enforce the cross-repo check. The in-repo hash "
              "guard (tests/test_mem_ratify.py) still ran.")
        return 0

    drift = False
    for name in FILES:
        upstream = upstream_dir / name
        if not upstream.is_file():
            print(f"::warning title=mem_ratify-sync skipped::{upstream} not found; "
                  "skipping this file.")
            continue
        mine = body((VENDORED_DIR / name).read_text())
        theirs = body(upstream.read_text())
        if mine == theirs:
            print(f"vendored mem_ratify/{name} is in sync with willow ✓")
            continue
        drift = True
        sys.stdout.write(
            f"::error title=mem_ratify drift::src/willow_mcp/mem_ratify/{name} has drifted "
            "from willow-memory/Willow. Re-sync it (procedure in tests/test_mem_ratify.py) "
            "and update the pinned hash there.\n")
        sys.stdout.writelines(difflib.unified_diff(
            theirs.splitlines(True), mine.splitlines(True),
            fromfile=f"willow/mem_ratify/{name}", tofile=f"willow-mcp/mem_ratify/{name}"))
    return 1 if drift else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
