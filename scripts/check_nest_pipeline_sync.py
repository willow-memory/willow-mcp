#!/usr/bin/env python3
"""Cross-repo drift-guard: assert the vendored Nest pipeline matches upstream.

Companion to the in-repo hash pin in tests/test_nest_pipeline_vendor.py. That pin
catches LOCAL edits to the vendored copy; this catches the OTHER direction — the
shared pipeline advancing in safe-app-store's canonical ``libs/nest-pipeline``
while the vendored copy here stays behind. That is box audit theme ① / A4: a
manual copy with no drift-guard is how the stance_friction block went missing.
Same soft-skip posture as scripts/check_subject_consent_sync.py.

Usage:
    check_nest_pipeline_sync.py <path-to-upstream/nest_pipeline>

Compares the module body (module docstring onward — everything the vendor header
promises is "byte-for-byte") of each shared file against its upstream twin and
exits non-zero with a unified diff on any divergence. If the upstream tree is
absent (private repo checked out without a token), it soft-skips with a warning
so it never blocks a PR on its own; the in-repo hash guard still enforces against
local edits.
"""
from __future__ import annotations

import difflib
import sys
from pathlib import Path

from vendor_drift import annotate, classify

VENDORED_DIR = Path(__file__).resolve().parents[1] / "src/willow_mcp/nest"
# The shared-core modules whose body must stay byte-for-byte with canonical. The
# vendored tree adds its own pieces (bridge/digest/intake/rules/__init__) that
# are app-specific and NOT contract-bound; only these are.
FILES = ("db.py", "embed.py", "ingest.py", "llm.py", "secrets.py",
         "selflearn.py", "taxonomy.py", "classify.py", "ocr.py")


def body(text: str) -> str:
    """The vendored contract: module docstring (first triple-quote) -> EOF."""
    return text[text.index('"""'):]


def main(argv: list) -> int:
    if len(argv) != 2:
        print("usage: check_nest_pipeline_sync.py <upstream nest_pipeline dir>", file=sys.stderr)
        return 2
    upstream_dir = Path(argv[1])
    if not upstream_dir.is_dir():
        print(f"::warning title=nest-pipeline-sync skipped::{upstream_dir} not found; set "
              "FLEET_RO_TOKEN to enforce the cross-repo check. The in-repo hash "
              "guard (tests/test_nest_pipeline_vendor.py) still ran.")
        return 0

    drift = False
    for name in FILES:
        upstream = upstream_dir / name
        if not upstream.is_file():
            print(f"::warning title=nest-pipeline-sync skipped::{upstream} not found; "
                  "skipping this file.")
            continue
        mine = body((VENDORED_DIR / name).read_text())
        theirs = body(upstream.read_text())
        if mine == theirs:
            print(f"vendored nest/{name} is in sync with safe-app-store ✓")
            continue
        verdict = classify(upstream, mine, body)
        drift = drift or verdict.fatal
        sys.stdout.write(annotate(
            "nest-pipeline", f"src/willow_mcp/nest/{name}", verdict,
            "Re-sync it (procedure in tests/test_nest_pipeline_vendor.py) and "
            "update the pinned hash there."))
        sys.stdout.writelines(difflib.unified_diff(
            theirs.splitlines(True), mine.splitlines(True),
            fromfile=f"safe-app-store/nest_pipeline/{name}",
            tofile=f"willow-mcp/nest/{name}"))
    return 1 if drift else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
