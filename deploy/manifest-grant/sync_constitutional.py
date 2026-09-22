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

Amendment (dispatch A9BF01A9, amending BD5843FD): the operator's first real
run measured the exact defect this docstring warned about in the abstract —
step 1c wrote a new `syscall-table.json`, step 6 (several steps and real
wall-clock time later) was the ONLY thing that ever signed it, and a
pre-existing gpg bug in step 6 died in between, leaving the box with a
REPLACED-but-UNSIGNED governance file that `paths.trusted_read` correctly
refused outright — locked harder than before the install ever ran.
`sync_and_sign()` closes that window: it signs (and, for an unchanged file,
re-verifies) what `sync()` just wrote, in the SAME act, before this process
does anything else — and if signing or verification fails, it restores the
file's exact previous bytes AND its exact previous `.sig` (or removes both,
if neither existed before), so a signing failure of ANY kind — this gpg
bug, a different one, a dead key, a permissions regression — leaves the box
exactly as it was, never half-applied. `sign_fn`/`verify_fn` are injected
callables so the two-uid gpg boundary itself (root creates the temp fd,
`sudo -u <trust owner>` writes into it — Kart is single-uid and has no
systemctl, so that boundary is not exercisable here, same limit
`sync()`/`install.sh`'s chown/ACL half has always had) stays untested where
it cannot be tested, while the rollback/verify CONTROL FLOW — the part that
was actually missing — is fully covered with fake callables.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Callable

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


class SigningFailed(Exception):
    """Signing or immediate-verification of a just-synced file failed.
    Raised AFTER the file's previous content and previous `.sig` (or their
    absence) have already been restored — the caller never needs to repair
    anything itself."""

    def __init__(self, name: str, reason: str):
        self.name = name
        self.reason = reason
        super().__init__(
            f"signing failed for {name}: {reason} — previous content and "
            "signature restored, box unchanged"
        )


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


def _restore(path: Path, prev_bytes: "bytes | None") -> None:
    """Put `path` back exactly as it was before this run touched it: the
    exact previous bytes, or absent if it was absent."""
    if prev_bytes is None:
        path.unlink(missing_ok=True)
    else:
        path.write_bytes(prev_bytes)


def sync_and_sign(
    bundle_dir: Path,
    box_dir: Path,
    sign_fn: "Callable[[Path], bytes]",
    verify_fn: "Callable[[Path, bytes], bool]",
) -> dict:
    """`sync()`, then sign what it wrote — in the SAME act, before this
    process does anything else — verifying each signature immediately.

    For every ALLOWLIST name `sync()` just changed, this calls
    `sign_fn(path)` (must return the detached-signature bytes, or raise) and
    then `verify_fn(path, sig_bytes)`. A name `sync()` left UNCHANGED is
    still checked: if its existing `.sig` is missing or does not verify
    under `verify_fn`, it is re-signed too — the same "an edited-but-
    unsigned governance file locks the box out" failure mode is just as
    real for a signature that went stale for some OTHER reason (a key
    rotation between runs, a corrupted `.sig`) as it is for a fresh write.

    On any signing/verification failure, the file's previous bytes AND its
    previous `.sig` (captured BEFORE `sync()` runs, since `sync()` writes
    in place) are restored — or both removed, if neither existed before —
    and `SigningFailed` is raised. `sync()`'s own exceptions
    (`BundleAbsent`/`BundleUnreadable`/`AllowlistFileMissing`) propagate
    unchanged; nothing has been signed yet at that point, so there is
    nothing to roll back.

    Returns `sync()`'s report dict plus `signed` (names freshly signed this
    run) and `already_signed` (names whose existing signature verified
    as-is, so nothing was touched).
    """
    # Snapshot BEFORE sync() writes anything — sync() overwrites allowlisted
    # files in place, so this is the only chance to capture the true "before"
    # for rollback.
    pre_bytes: dict[str, "bytes | None"] = {}
    pre_sig: dict[str, "bytes | None"] = {}
    for name in ALLOWLIST:
        box_file = box_dir / name
        pre_bytes[name] = box_file.read_bytes() if box_file.exists() else None
        sig_file = box_dir / f"{name}.sig"
        pre_sig[name] = sig_file.read_bytes() if sig_file.exists() else None

    report = sync(bundle_dir, box_dir)  # raises untouched on its own failures

    report["signed"] = []
    report["already_signed"] = []
    changed_names = {entry["name"] for entry in report["written"]}

    for name in ALLOWLIST:
        box_file = box_dir / name
        if not box_file.exists():
            continue
        sig_file = box_dir / f"{name}.sig"

        needs_sign = name in changed_names
        if not needs_sign:
            existing_sig = sig_file.read_bytes() if sig_file.exists() else None
            if existing_sig is None or not verify_fn(box_file, existing_sig):
                needs_sign = True
        if not needs_sign:
            report["already_signed"].append(name)
            continue

        try:
            sig_bytes = sign_fn(box_file)
            if not verify_fn(box_file, sig_bytes):
                raise RuntimeError("signature did not verify immediately after signing")
        except Exception as exc:
            _restore(box_file, pre_bytes[name])
            _restore(sig_file, pre_sig[name])
            raise SigningFailed(name, str(exc)) from exc

        sig_file.write_bytes(sig_bytes)
        report["signed"].append(name)

    return report


def _make_sign_fn(trust_owner: str, gnupg_home: str, fingerprint: str) -> "Callable[[Path], bytes]":
    """A `sign_fn` for `sync_and_sign()` that shells out to gpg as the
    trust owner, exactly like install.sh's own step 6 loop (338bbdb):
    `--output -` writes the detached signature to gpg's own stdout, so gpg
    (running as the trust owner via `sudo -u`) never opens a path this
    process (root) created — the child uid's permission on any temp path
    never matters, because none is ever handed to it."""

    def sign_fn(path: Path) -> bytes:
        env = {**os.environ, "GNUPGHOME": gnupg_home}
        proc = subprocess.run(
            [
                "sudo", "-u", trust_owner, "gpg", "--batch", "--yes",
                "--detach-sign", "--armor", "--local-user", fingerprint,
                "--output", "-", str(path),
            ],
            env=env, capture_output=True, check=True,
        )
        return proc.stdout

    return sign_fn


def _make_verify_fn(trust_owner: str, gnupg_home: str) -> "Callable[[Path, bytes], bool]":
    """A `verify_fn` for `sync_and_sign()`. The candidate signature is piped
    to gpg's stdin (`--verify - <file>`) rather than written to a path
    first — the same "never hand gpg a path the other uid must open"
    discipline `_make_sign_fn` uses, for the same reason."""

    def verify_fn(path: Path, sig_bytes: bytes) -> bool:
        env = {**os.environ, "GNUPGHOME": gnupg_home}
        proc = subprocess.run(
            ["sudo", "-u", trust_owner, "gpg", "--batch", "--verify", "-", str(path)],
            input=sig_bytes, env=env, capture_output=True,
        )
        return proc.returncode == 0

    return verify_fn


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
    parser.add_argument(
        "--sign-as", dest="sign_as", default=None,
        help="trust-owner username; when given, sync() and sign() run as one act "
             "(sync_and_sign) and the synced/signed files are chowned to this user",
    )
    parser.add_argument("--gnupg-home", dest="gnupg_home", default=None)
    parser.add_argument("--fingerprint", dest="fingerprint", default=None)
    args = parser.parse_args(argv)

    if args.sign_as:
        if not (args.gnupg_home and args.fingerprint):
            print("STOP: --sign-as requires --gnupg-home and --fingerprint", file=sys.stderr)
            return 2
        sign_fn = _make_sign_fn(args.sign_as, args.gnupg_home, args.fingerprint)
        verify_fn = _make_verify_fn(args.sign_as, args.gnupg_home)
        try:
            report = sync_and_sign(args.bundle_dir, args.box_dir, sign_fn, verify_fn)
        except (BundleAbsent, BundleUnreadable, AllowlistFileMissing) as exc:
            print(f"STOP: {exc}", file=sys.stderr)
            return 2
        except SigningFailed as exc:
            print(f"STOP: {exc}", file=sys.stderr)
            return 3

        _print_report(report)
        for name in report["signed"]:
            print(f"  signed and verified {name}.sig")
        for name in report["already_signed"]:
            print(f"  {name}.sig already verifies under the current key — no-op")

        # This script runs as root when install.sh invokes it (like split()'s
        # own chown half) — chown the files it just wrote/signed to the trust
        # owner here, in the same act, rather than a separate install.sh line
        # that could run after an interruption.
        import pwd
        pw = pwd.getpwnam(args.sign_as)
        for name in ALLOWLIST:
            box_file = args.box_dir / name
            if not box_file.exists():
                continue
            os.chown(box_file, pw.pw_uid, pw.pw_gid)
            os.chmod(box_file, 0o644)
            sig_file = args.box_dir / f"{name}.sig"
            if sig_file.exists():
                os.chown(sig_file, pw.pw_uid, pw.pw_gid)
                os.chmod(sig_file, 0o644)
        return 0

    try:
        report = sync(args.bundle_dir, args.box_dir)
    except (BundleAbsent, BundleUnreadable, AllowlistFileMissing) as exc:
        print(f"STOP: {exc}", file=sys.stderr)
        return 2

    _print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
