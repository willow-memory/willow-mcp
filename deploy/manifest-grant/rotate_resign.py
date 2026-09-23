#!/usr/bin/env python3
"""deploy/manifest-grant/rotate_resign.py — re-sign an explicit list of
already-live governance files under a (possibly new) trust-owner key, and
report which fingerprint each one verifies under right now.

Dispatch B291C0C7 ("one signing key, one source of truth"), amending
A9BF01A9: the operator ruled a rotation should touch ONE fingerprint in
ONE place ($WILLOW_HOME/env) and every governance file's signature should
move with it in one atomic act, install.sh's own step 6 resigns seat
manifests + the active register + the federation registry as N independent
gpg calls in a bash loop, no rollback: a failure on file 7 of 12 leaves
1-6 signed under the new key and 7-12 still signed under the old one — a
box that is itself split-brained mid-rotation, exactly the shape this
dispatch exists to close.

``resign_all`` gives that loop the same discipline
``sync_constitutional.sync_and_sign`` already gives syscall-table.json:
snapshot every ``.sig`` this run will touch BEFORE touching any of them,
and on ANY failure restore every one already re-signed this run, not just
the file that failed. Only the ``.sig`` sibling ever changes here — the
content of a governance file is not touched by a re-sign, so there is
nothing to snapshot or restore on the content side.

``check_all`` is the other half of item 5 (B291C0C7): a read-only report
of which fingerprint each governed file's ``.sig`` verifies under, so the
desk can confirm a rotation actually landed everywhere with one call
instead of trusting the rotation script's own exit code.

Dependency-free (no ``willow_mcp`` import), same convention as
``sync_constitutional.py`` — this runs as root (resign) or the operator
(check) before/without the package necessarily being on that interpreter's
path.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Callable


class ResignFailed(Exception):
    def __init__(self, name: str, reason: str):
        self.name = name
        self.reason = reason
        super().__init__(
            f"re-signing failed for {name}: {reason} — every file this run "
            "had already re-signed has been restored to its previous "
            "signature; box unchanged"
        )


def _sig_path(path: Path) -> Path:
    return path.parent / f"{path.name}.sig"


def _restore(sig_path: Path, prev_sig: "bytes | None") -> None:
    if prev_sig is None:
        sig_path.unlink(missing_ok=True)
    else:
        sig_path.write_bytes(prev_sig)


def resign_all(
    files: "list[Path]",
    sign_fn: "Callable[[Path], bytes]",
    verify_fn: "Callable[[Path, bytes], bool]",
) -> dict:
    """Re-sign every path in ``files`` that exists (content untouched —
    only the sibling ``.sig`` changes) under whatever key ``sign_fn`` uses,
    verifying each signature immediately.

    Snapshots every ``.sig`` this run MIGHT touch before touching any of
    them, so a failure on file N rolls back files 1..N-1 as well as N —
    one atomic batch across the whole list, never N independent ones. A
    path that does not exist is reported ``skipped_absent`` and never
    touched — rotate has nothing to re-sign for a manifest that was never
    created.
    """
    existing = [f for f in files if f.is_file()]
    pre_sig: "dict[Path, bytes | None]" = {
        f: (_sig_path(f).read_bytes() if _sig_path(f).is_file() else None)
        for f in existing
    }

    report: dict = {
        "signed": [],
        "skipped_absent": [str(f) for f in files if f not in existing],
    }
    signed_so_far: "list[Path]" = []
    for f in existing:
        try:
            sig_bytes = sign_fn(f)
            if not verify_fn(f, sig_bytes):
                raise RuntimeError("signature did not verify immediately after signing")
        except Exception as exc:
            for done in signed_so_far:
                _restore(_sig_path(done), pre_sig[done])
            raise ResignFailed(str(f), str(exc)) from exc
        _sig_path(f).write_bytes(sig_bytes)
        signed_so_far.append(f)
        report["signed"].append(str(f))
    return report


def _signer_fingerprint(path: Path) -> "str | None":
    """The fingerprint that actually signed `path`, per gpg's own
    machine-readable status output — never assumed from which key this
    process happens to expect."""
    sig = _sig_path(path)
    if not sig.is_file():
        return None
    proc = subprocess.run(
        ["gpg", "--batch", "--verify", "--status-fd=1", str(sig), str(path)],
        capture_output=True, text=True, timeout=10,
    )
    for line in (proc.stdout or "").splitlines():
        if line.startswith("[GNUPG:] VALIDSIG"):
            parts = line.split()
            if len(parts) >= 12:
                return parts[11].upper()
    return None


def check_all(files: "list[Path]", expected_fingerprint: str) -> dict:
    """Read-only: for each path, which fingerprint (if any) its `.sig`
    verifies under right now, and whether that matches
    `expected_fingerprint`. Touches nothing."""
    expected = expected_fingerprint.strip().upper()
    rows = []
    for f in files:
        if not f.is_file():
            rows.append({"path": str(f), "state": "absent"})
            continue
        signer = _signer_fingerprint(f)
        if signer is None:
            rows.append({"path": str(f), "state": "unsigned_or_unverifiable"})
        elif signer == expected:
            rows.append({"path": str(f), "state": "ok", "signer": signer})
        else:
            rows.append({
                "path": str(f), "state": "mismatch",
                "signer": signer, "expected": expected,
            })
    all_ok = all(r["state"] == "ok" for r in rows if r["state"] != "absent")
    return {"files": rows, "all_ok": all_ok, "expected": expected}


def _make_sign_fn(trust_owner: str, gnupg_home: str, fingerprint: str) -> "Callable[[Path], bytes]":
    """Same shape as sync_constitutional._make_sign_fn (338bbdb, 586e050):
    `--output -` so gpg never opens a path the other uid must have
    permission on, and GNUPGHOME rides in the sudo argv (sudo resets the
    environment) rather than this process's own `env=`."""

    def sign_fn(path: Path) -> bytes:
        proc = subprocess.run(
            [
                "sudo", "-u", trust_owner, f"GNUPGHOME={gnupg_home}",
                "gpg", "--batch", "--yes",
                "--detach-sign", "--armor", "--local-user", fingerprint,
                "--output", "-", str(path),
            ],
            capture_output=True, check=True,
        )
        return proc.stdout

    return sign_fn


def _make_verify_fn(trust_owner: str, gnupg_home: str) -> "Callable[[Path, bytes], bool]":
    def verify_fn(path: Path, sig_bytes: bytes) -> bool:
        proc = subprocess.run(
            [
                "sudo", "-u", trust_owner, f"GNUPGHOME={gnupg_home}",
                "gpg", "--batch", "--verify", "-", str(path),
            ],
            input=sig_bytes, capture_output=True,
        )
        return proc.returncode == 0

    return verify_fn


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--check", action="store_true",
                         help="read-only: report which fingerprint each file verifies under")
    parser.add_argument("--sign-as", dest="sign_as", default=None,
                         help="trust-owner username (resign mode only)")
    parser.add_argument("--gnupg-home", dest="gnupg_home", default=None)
    parser.add_argument("--fingerprint", dest="fingerprint", default=None)
    args = parser.parse_args(argv)

    if args.check:
        if not args.fingerprint:
            print("STOP: --check requires --fingerprint", file=sys.stderr)
            return 2
        report = check_all(args.files, args.fingerprint)
        print(json.dumps(report, indent=2, sort_keys=True))
        for row in report["files"]:
            if row["state"] == "absent":
                print(f"  {row['path']}: absent (nothing to check)")
            elif row["state"] == "ok":
                print(f"  {row['path']}: OK — verifies under {row['signer']}")
            elif row["state"] == "unsigned_or_unverifiable":
                print(f"  {row['path']}: NO valid signature found")
            else:
                print(
                    f"  {row['path']}: MISMATCH — signed by {row['signer']}, "
                    f"expected {row['expected']}"
                )
        return 0 if report["all_ok"] else 1

    if not (args.sign_as and args.gnupg_home and args.fingerprint):
        print("STOP: resign mode requires --sign-as, --gnupg-home, --fingerprint",
              file=sys.stderr)
        return 2
    sign_fn = _make_sign_fn(args.sign_as, args.gnupg_home, args.fingerprint)
    verify_fn = _make_verify_fn(args.sign_as, args.gnupg_home)
    try:
        report = resign_all(args.files, sign_fn, verify_fn)
    except ResignFailed as exc:
        print(f"STOP: {exc}", file=sys.stderr)
        return 3
    for name in report["signed"]:
        print(f"  re-signed {name}")
    for name in report["skipped_absent"]:
        print(f"  skipped (absent) {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
