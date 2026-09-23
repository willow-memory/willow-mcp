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

Rework (Loki audit A38D41C2, F7): the first cut rolled back only on a
caught ``Exception``. ``KeyboardInterrupt`` (Ctrl-C) and a delivered
``SIGTERM`` are not ``Exception`` subclasses in Python — either one landing
mid-batch skipped rollback entirely and left the box half-rotated (measured:
Kart probe P8, ``sigs [NEW, NEW, OLD]``). ``resign_all`` now (1) installs a
``SIGTERM`` handler that raises the same way Ctrl-C already does, so both
signals drive the identical rollback path, and (2) catches ``BaseException``
in the per-file loop, not ``Exception`` — the only things that still escape
are ``SystemExit`` calls this module itself never makes and a small set of
truly unrecoverable interpreter states rollback cannot help with anyway.
``.sig`` writes are also no longer a direct ``write_bytes`` (a partial write
on the live path is observable to a concurrent reader mid-write, and is not
atomic against a crash); each write goes to a sibling temp file and
``os.replace``s over the live path, both under the SAME directory flock
``pgp.signed_pair_lock`` uses elsewhere in this codebase — reimplemented
locally here (dependency-free) rather than imported, same convention as
``sync_constitutional.py``. ``verify_fn`` now also checks WHICH key signed,
not merely that ``gpg --verify`` exited 0 — a signature that verifies but
was minted under the wrong key must not be reported as success.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator


class ResignFailed(Exception):
    def __init__(self, name: str, reason: str):
        self.name = name
        self.reason = reason
        super().__init__(
            f"re-signing failed for {name}: {reason} — every file this run "
            "had already re-signed has been restored to its previous "
            "signature; box unchanged"
        )


class _Interrupted(BaseException):
    """Raised by the SIGTERM handler installed in ``resign_all`` so a
    delivered SIGTERM drives the exact same rollback path Ctrl-C
    (``KeyboardInterrupt``) already does — neither is an ``Exception``
    subclass, which is exactly the gap F7 measured."""


def _sig_path(path: Path) -> Path:
    return path.parent / f"{path.name}.sig"


@contextmanager
def _sig_lock(path: Path) -> Iterator[None]:
    """Same directory-flock discipline as ``willow_mcp.pgp.signed_pair_lock``
    — reimplemented locally (dependency-free, matching this module's own
    convention) rather than imported. Locking the CONTAINING directory,
    not the file itself, lets a publisher replace the file (a rename
    cannot replace the inode a lock is held on) while a concurrent reader
    (the broker, mid-verify) waits rather than observing a torn write."""
    import fcntl

    directory = path.parent
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _write_sig_atomic(
    sig_path: Path, sig_bytes: bytes, owner: "tuple[int, int, int] | None" = None
) -> None:
    """Write ``sig_bytes`` to ``sig_path`` via a sibling temp file plus
    ``os.replace`` (atomic on the same filesystem), under ``_sig_lock`` so
    no concurrent reader can observe a partially-written file.

    Loki re-audit 93D0F057, N5: the temp file this process (root) creates
    is root-owned with root's own umask; ``os.replace`` does not carry the
    REPLACED file's ownership/mode forward, so a bare write silently
    turned a trust-owner-owned 0644 ``.sig`` into a root-owned one. Any
    later IN-PLACE re-sign by the trust owner (``gpg -o <path>.sig``,
    e.g. ``mcp_federation.ratify``) would then hit EACCES writing over a
    file it no longer owns. ``owner`` (``(uid, gid, mode)``), when given,
    is applied to the temp file BEFORE the atomic replace, so the live
    path never carries the wrong ownership even transiently."""
    with _sig_lock(sig_path):
        tmp = sig_path.with_name(f"{sig_path.name}.tmp-{os.getpid()}")
        tmp.write_bytes(sig_bytes)
        if owner is not None:
            uid, gid, mode = owner
            os.chown(tmp, uid, gid)
            os.chmod(tmp, mode)
        os.replace(tmp, sig_path)


def _restore(sig_path: Path, prev: "tuple[bytes, int, int, int] | None") -> None:
    """Restore ``sig_path`` to its exact previous bytes AND ownership/mode
    (N5 — same reasoning as ``_write_sig_atomic``: a rollback that
    restores bytes but leaves root ownership behind is only a partial
    undo), or remove it when nothing existed before."""
    with _sig_lock(sig_path):
        if prev is None:
            sig_path.unlink(missing_ok=True)
            return
        prev_bytes, uid, gid, mode = prev
        tmp = sig_path.with_name(f"{sig_path.name}.tmp-{os.getpid()}")
        tmp.write_bytes(prev_bytes)
        os.chown(tmp, uid, gid)
        os.chmod(tmp, mode)
        os.replace(tmp, sig_path)


def _stat_owner(path: Path) -> "tuple[int, int, int]":
    st = path.stat()
    import stat as _stat_module

    return st.st_uid, st.st_gid, _stat_module.S_IMODE(st.st_mode)


@contextmanager
def _sigterm_trap() -> Iterator[None]:
    """Install a SIGTERM handler that raises ``_Interrupted`` for the
    duration of the ``with`` block, restoring whatever handler was there
    before on the way out (there is no reason to keep an unusual SIGTERM
    behavior once the batch this trap exists to protect has finished)."""
    previous = signal.getsignal(signal.SIGTERM)

    def _handler(signum, frame):  # noqa: ANN001 — signal handler signature
        raise _Interrupted(f"received signal {signum}")

    signal.signal(signal.SIGTERM, _handler)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def resign_all(
    files: "list[Path]",
    sign_fn: "Callable[[Path], bytes]",
    verify_fn: "Callable[[Path, bytes], bool]",
    *,
    owner: "tuple[int, int, int] | None" = None,
) -> dict:
    """Re-sign every path in ``files`` that exists (content untouched —
    only the sibling ``.sig`` changes) under whatever key ``sign_fn`` uses,
    verifying each signature immediately.

    Snapshots every ``.sig`` this run MIGHT touch — bytes AND owner/mode
    (N5) — before touching any of them, so a failure on file N rolls back
    files 1..N-1 as well as N, ownership included, not just N — one atomic
    batch across the whole list, never N independent ones. A path that
    does not exist is reported ``skipped_absent`` and never touched —
    rotate has nothing to re-sign for a manifest that was never created.

    ``owner`` (``(uid, gid, mode)``), when given, is applied to every
    FRESHLY-written ``.sig`` (there was no previous ``.sig`` to preserve
    the ownership of) — typically the trust owner's identity at mode
    ``0o644``, matching what every other governance-signed file already
    carries.

    Catches ``BaseException`` (F7) — Ctrl-C and a trapped SIGTERM
    (``_sigterm_trap``, installed for the duration of this call) both
    raise something that is NOT an ``Exception`` subclass, and both must
    still trigger the exact same rollback. The ``try`` now wraps the
    ATOMIC WRITE too (Loki re-audit 93D0F057, F7 residual: an interrupt
    landing in ``_write_sig_atomic`` itself, after signing succeeded but
    before the report was updated, used to escape the ``try`` entirely
    and skip rollback for that one file — measured [NEW, OLD, OLD] instead
    of [OLD, OLD, OLD]).
    """
    existing = [f for f in files if f.is_file()]
    pre_sig: "dict[Path, tuple[bytes, int, int, int] | None]" = {
        f: (
            (_sig_path(f).read_bytes(), *_stat_owner(_sig_path(f)))
            if _sig_path(f).is_file()
            else None
        )
        for f in existing
    }

    report: dict = {
        "signed": [],
        "skipped_absent": [str(f) for f in files if f not in existing],
    }
    signed_so_far: "list[Path]" = []
    with _sigterm_trap():
        for f in existing:
            try:
                sig_bytes = sign_fn(f)
                if not verify_fn(f, sig_bytes):
                    raise RuntimeError(
                        "signature did not verify immediately after signing "
                        "(or verified under the wrong key)"
                    )
                # Preserve the PREVIOUS .sig's own owner/mode when one
                # existed (a re-sign of an already-governed file); only a
                # brand-new .sig (no previous one) falls back to `owner`.
                prev = pre_sig[f]
                write_owner = (prev[1], prev[2], prev[3]) if prev is not None else owner
                _write_sig_atomic(_sig_path(f), sig_bytes, write_owner)
                signed_so_far.append(f)
                report["signed"].append(str(f))
            except BaseException as exc:
                for done in signed_so_far:
                    _restore(_sig_path(done), pre_sig[done])
                # `f` itself may have been PARTIALLY written (an interrupt
                # inside _write_sig_atomic, after the temp file exists but
                # before/around the replace) even though it never made it
                # into signed_so_far -- restore it too, unconditionally.
                _restore(_sig_path(f), pre_sig[f])
                raise ResignFailed(str(f), str(exc)) from exc
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


def check_all(files: "list[Path]", expected_fingerprint: str = "") -> dict:
    """Read-only: for each path, which fingerprint (if any) its `.sig`
    verifies under right now, and whether that matches
    `expected_fingerprint`. Touches nothing.

    Loki re-audit 93D0F057, N4: `--check-signatures` is supposed to be
    the FIRST step of a migration, but it used to require
    `expected_fingerprint` (read from trust.env) — which does not exist
    yet on a box that has never been through this install at all, the
    exact state a first-run check needs to work from. An EMPTY
    `expected_fingerprint` now switches this into REPORT-ONLY mode: each
    row still names which fingerprint (if any) actually signed that file,
    but the per-row state is `"signed"`/`"unsigned_or_unverifiable"`/
    `"absent"` rather than `"ok"`/`"mismatch"` (there is nothing to judge
    against), and `all_ok` is `None` — this mode never fails, it only
    informs."""
    expected = expected_fingerprint.strip().upper()
    rows = []
    for f in files:
        if not f.is_file():
            rows.append({"path": str(f), "state": "absent"})
            continue
        signer = _signer_fingerprint(f)
        if not expected:
            if signer is None:
                rows.append({"path": str(f), "state": "unsigned_or_unverifiable"})
            else:
                rows.append({"path": str(f), "state": "signed", "signer": signer})
            continue
        if signer is None:
            rows.append({"path": str(f), "state": "unsigned_or_unverifiable"})
        elif signer == expected:
            rows.append({"path": str(f), "state": "ok", "signer": signer})
        else:
            rows.append({
                "path": str(f), "state": "mismatch",
                "signer": signer, "expected": expected,
            })
    if not expected:
        return {"files": rows, "all_ok": None, "expected": ""}
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


def _make_verify_fn(
    trust_owner: str, gnupg_home: str, expected_fingerprint: str
) -> "Callable[[Path, bytes], bool]":
    """Rework (Loki audit A38D41C2, F7): the first cut only checked that
    `gpg --verify` exited 0 — a signature that verifies but was minted
    under a DIFFERENT key (a stale gpg-agent cache, a `--local-user`
    typo, a second key sharing the box) would still pass. `--status-fd=1`
    is parsed for `VALIDSIG` the same way `_signer_fingerprint` already
    does for `--check`, and the signer must match `expected_fingerprint`
    — the fingerprint this batch is signing FOR, not whatever `gpg`
    happened to use."""
    expected = expected_fingerprint.strip().upper()

    def verify_fn(path: Path, sig_bytes: bytes) -> bool:
        proc = subprocess.run(
            [
                "sudo", "-u", trust_owner, f"GNUPGHOME={gnupg_home}",
                "gpg", "--batch", "--verify", "--status-fd=1", "-", str(path),
            ],
            input=sig_bytes, capture_output=True,
        )
        if proc.returncode != 0:
            return False
        stdout_text = (proc.stdout or b"").decode("utf-8", errors="replace")
        for line in stdout_text.splitlines():
            if line.startswith("[GNUPG:] VALIDSIG"):
                parts = line.split()
                if len(parts) >= 12 and parts[11].upper() == expected:
                    return True
                return False
        return False

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
        # N4: --check now works with NO --fingerprint at all -- report-only
        # mode, the state check_all() needs to be usable as the FIRST step
        # of a migration, before trust.env (the source --fingerprint would
        # otherwise come from) exists.
        report = check_all(args.files, args.fingerprint or "")
        print(json.dumps(report, indent=2, sort_keys=True))
        for row in report["files"]:
            if row["state"] == "absent":
                print(f"  {row['path']}: absent (nothing to check)")
            elif row["state"] == "signed":
                print(f"  {row['path']}: currently signed by {row['signer']}")
            elif row["state"] == "ok":
                print(f"  {row['path']}: OK — verifies under {row['signer']}")
            elif row["state"] == "unsigned_or_unverifiable":
                print(f"  {row['path']}: NO valid signature found")
            else:
                print(
                    f"  {row['path']}: MISMATCH — signed by {row['signer']}, "
                    f"expected {row['expected']}"
                )
        return 0 if report["all_ok"] is not False else 1

    if not (args.sign_as and args.gnupg_home and args.fingerprint):
        print("STOP: resign mode requires --sign-as, --gnupg-home, --fingerprint",
              file=sys.stderr)
        return 2
    sign_fn = _make_sign_fn(args.sign_as, args.gnupg_home, args.fingerprint)
    verify_fn = _make_verify_fn(args.sign_as, args.gnupg_home, args.fingerprint)
    # N5: a brand-new .sig (no previous one to preserve the owner/mode of)
    # must still land trust-owner-owned, 0o644 -- the same shape every
    # other governance-signed file already has.
    import pwd
    pw = pwd.getpwnam(args.sign_as)
    owner = (pw.pw_uid, pw.pw_gid, 0o644)
    try:
        report = resign_all(args.files, sign_fn, verify_fn, owner=owner)
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
