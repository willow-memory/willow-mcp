#!/usr/bin/env python3
"""deploy/manifest-grant/sync_constitutional.py — the installer's constitutional
bundle sync (sealed `1bd6fd29`; gap `c1395b307421`).

`constitutional/` holds POLICY (`syscall-table.json`) and LIVE STATE
(`pre-approved.json` — the active envelope register; `review_queue.json`;
`frank_head_anchor.json`) in the same directory. The checkout ships seed
copies of some of these files under `src/willow_mcp/bundle/constitutional/`.
Nothing before this script ever copied the checkout's `syscall-table.json`
onto an installed box, so a box can sit indefinitely on a stale table —
measured 2026-09-22: the box was missing row 24 (`envelope.ratify`, shipped
by PR 628), freezing every envelope ratification behind it.

The one thing that must not go wrong: a sync that copies the whole
directory DESTROYS the live register. So this module works from an explicit
ALLOWLIST — an include list, never an exclude list. An exclude list grows
wrong silently the day a new live-state file is added beside the register;
an include list fails loudly the day a name goes missing from the bundle.

This module is plain, dependency-free Python so it is testable directly
(no root, no uid switch, no systemctl) — `sync()` is the whole allowlisted
copy-with-diagnostics act; the trust-owner ownership/signing half stays in
install.sh, exactly like the split() step already there for the register.
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

#: The only files this installer step may ever overwrite in `constitutional/`.
#: Add a name here ONLY when it is policy the checkout ships as a seed copy,
#: never live state. `pre-approved.json` (the active envelope register),
#: `review_queue.json`, and `frank_head_anchor.json` must never be added.
ALLOWLIST = ("syscall-table.json",)


class BundleAbsent(Exception):
    """The checkout's bundle directory does not exist at all."""


class BundleUnreadable(Exception):
    """The checkout's bundle directory exists but cannot be listed/read."""


class AllowlistFileMissing(Exception):
    """An ALLOWLIST entry is not present in the bundle — a hard failure,
    never a silent skip. Raised before any box file is touched."""

    def __init__(self, missing: list[str]):
        self.missing = missing
        super().__init__(f"allowlisted file(s) missing from bundle: {', '.join(missing)}")


def _row_count(path: Path) -> "int | None":
    """Best-effort content size for the before/after report: the length of
    the JSON `verbs` list when present (the syscall table's own shape),
    else the top-level dict/list length, else None for a file that is
    absent or does not parse as JSON."""
    if not path.exists():
        return None
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if isinstance(doc, dict) and isinstance(doc.get("verbs"), list):
        return len(doc["verbs"])
    if isinstance(doc, (list, dict)):
        return len(doc)
    return None


def _describe(path: Path) -> dict:
    if not path.exists():
        return {"exists": False, "count": None, "mtime": None}
    st = path.stat()
    return {
        "exists": True,
        "count": _row_count(path),
        "mtime": datetime.datetime.fromtimestamp(
            st.st_mtime, tz=datetime.timezone.utc
        ).isoformat(),
    }


def check_bundle_available(bundle_dir: Path) -> None:
    """Three-state check, never collapsed: present / absent / unreadable."""
    if not bundle_dir.exists():
        raise BundleAbsent(f"bundle directory absent: {bundle_dir}")
    if not bundle_dir.is_dir():
        raise BundleUnreadable(f"bundle path is not a directory: {bundle_dir}")
    try:
        next(bundle_dir.iterdir(), None)
    except OSError as exc:
        raise BundleUnreadable(f"bundle directory unreadable: {bundle_dir} ({exc})") from exc


def sync(bundle_dir: Path, box_dir: Path) -> dict:
    """Sync `box_dir` from `bundle_dir` under ALLOWLIST.

    Returns a report dict with keys `written`, `unchanged`, `skipped`.
    Raises `BundleAbsent`/`BundleUnreadable` if the bundle cannot be read at
    all, or `AllowlistFileMissing` if an allowlisted name is missing from
    the bundle — in both cases `box_dir` is left completely untouched (no
    mkdir, no write) because these checks run before anything is written.

    Never opens a box file for write unless its name is in ALLOWLIST. A
    bundle file NOT in ALLOWLIST (e.g. the bundle's own seed copy of
    `pre-approved.json`) is reported skipped and the box's copy — if any —
    is left byte-for-byte alone.
    """
    check_bundle_available(bundle_dir)
    bundle_names = {p.name for p in bundle_dir.iterdir()}

    missing = [name for name in ALLOWLIST if name not in bundle_names]
    if missing:
        raise AllowlistFileMissing(missing)

    # Nothing written yet past this point failed — safe to touch box_dir now.
    box_dir.mkdir(parents=True, exist_ok=True)

    report: dict = {"written": [], "unchanged": [], "skipped": []}

    for name in sorted(bundle_names - set(ALLOWLIST)):
        report["skipped"].append({
            "name": name,
            "reason": "not on the sync allowlist — left untouched (live state or unmanaged)",
        })

    for name in ALLOWLIST:
        bundle_file = bundle_dir / name
        box_file = box_dir / name
        before = _describe(box_file)
        bundle_bytes = bundle_file.read_bytes()
        box_bytes = box_file.read_bytes() if box_file.exists() else None
        changed = bundle_bytes != box_bytes
        if changed:
            box_file.write_bytes(bundle_bytes)
        after = _describe(box_file)
        entry = {
            "name": name,
            "before_count": before["count"],
            "before_mtime": before["mtime"],
            "bundle_count": _row_count(bundle_file),
            "after_count": after["count"],
            "changed": changed,
        }
        (report["written"] if changed else report["unchanged"]).append(entry)

    return report


def _print_report(report: dict) -> None:
    for entry in report["written"]:
        print(
            f"  {entry['name']}: box had {entry['before_count']} "
            f"(mtime {entry['before_mtime']}), checkout bundle has "
            f"{entry['bundle_count']} -> wrote, box now has {entry['after_count']}"
        )
    for entry in report["unchanged"]:
        print(
            f"  {entry['name']}: box already matches the checkout bundle "
            f"({entry['after_count']} rows, mtime {entry['before_mtime']}) — no-op"
        )
    for entry in report["skipped"]:
        print(f"  skipped {entry['name']}: {entry['reason']}")


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle_dir", type=Path)
    parser.add_argument("box_dir", type=Path)
    args = parser.parse_args(argv)

    try:
        report = sync(args.bundle_dir, args.box_dir)
    except (BundleAbsent, BundleUnreadable, AllowlistFileMissing) as exc:
        print(f"STOP: {exc}", file=sys.stderr)
        return 2

    _print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
