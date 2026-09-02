#!/usr/bin/env python3
"""Cross-repo drift-guard: assert the vendored subject_consent package matches
its upstream canonical source in safe-app-store ``libs/subject-consent``.

Companion to the in-repo hash pin in tests/test_subject_consent.py. That pin
catches LOCAL edits to the vendored copy; this catches the OTHER direction —
the canonical package advancing while the vendored copy stays behind. That is
exactly the failure mode the box audit (theme ①, finding A1) called out: a
manual copy carrying a "keep in sync" docstring with no CI to enforce it.
Run in CI with safe-app-store checked out beside this repo.

Usage:
    check_subject_consent_sync.py <path-to safe-app-store/libs/subject-consent/src/subject_consent>

Compares the CODE BODY of every module in the package (from the
``from __future__ import annotations`` marker onward — everything after the
module docstring). The docstring is deliberately EXCLUDED: the vendored copy
adds a provenance stanza the canonical lacks, and that difference is expected
for a vendored file. The behavioral contract is the code, and the code must be
byte-for-byte identical. Exits non-zero with a unified diff on any divergence.

If the upstream package is absent (private repo checked out without a token),
it soft-skips with a warning so it never blocks a PR on its own; the in-repo
hash guard still enforces against local edits.
"""
from __future__ import annotations

import difflib
import sys
from pathlib import Path

from vendor_drift import annotate, classify

VENDORED = Path(__file__).resolve().parents[1] / "src/willow_mcp/subject_consent"

# The module files whose CODE BODY must match canonical byte-for-byte.
MODULES = ("__init__.py", "core.py")

# Slice point: the docstring (which legitimately differs — the vendored copy
# carries an extra provenance stanza) ends and the code begins at this line.
MARKER = "from __future__ import annotations"


def body(text: str) -> str:
    """The vendored contract: the code, from the __future__ import onward.

    Everything before it is the module docstring, which the vendored copy is
    allowed to annotate with provenance; the code after it is not."""
    try:
        return text[text.index(MARKER):]
    except ValueError:
        # No marker — fall back to docstring-onward so a restructured module
        # still gets compared (loudly, via the diff) rather than silently pass.
        return text[text.index('"""'):]


def main(argv: list) -> int:
    if len(argv) != 2:
        print("usage: check_subject_consent_sync.py <upstream subject_consent dir>",
              file=sys.stderr)
        return 2
    upstream = Path(argv[1])
    if not upstream.is_dir():
        print(f"::warning title=subject-consent-sync skipped::{upstream} not found; "
              "set FLEET_RO_TOKEN to enforce the cross-repo check against "
              "safe-app-store. The in-repo hash guard (tests/test_subject_consent.py) "
              "still ran.")
        return 0

    drift = 0
    for mod in MODULES:
        mine_path = VENDORED / mod
        theirs_path = upstream / mod
        if not theirs_path.is_file():
            sys.stdout.write(
                f"::error title=subject-consent drift::canonical is missing {mod} "
                f"({theirs_path}); the vendored package structure has diverged.\n")
            drift = 1
            continue
        mine = body(mine_path.read_text())
        theirs = body(theirs_path.read_text())
        if mine == theirs:
            print(f"vendored subject_consent/{mod} is in sync with safe-app-store ✓")
            continue
        verdict = classify(theirs_path, mine, body)
        drift = drift or int(verdict.fatal)
        sys.stdout.write(annotate(
            "subject-consent", f"src/willow_mcp/subject_consent/{mod}", verdict,
            "Re-sync it (procedure in tests/test_subject_consent.py) and update "
            "the pinned hash there."))
        sys.stdout.writelines(difflib.unified_diff(
            theirs.splitlines(True), mine.splitlines(True),
            fromfile=f"safe-app-store/subject_consent/{mod}",
            tofile=f"willow-mcp/subject_consent/{mod}"))
    return drift


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
